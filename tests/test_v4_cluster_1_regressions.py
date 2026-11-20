"""V4 regression tests for Visold Cluster 1 Security Audit fixes.

Converted from adversarial PoCs to positive regression tests asserting fixed V4 behavior:
- visold/crypto/ (ecc, keystore, mnemonic, parallel_verify, vrf)
- visold/wallet/ (wallet)
- visold/ledger/ (addressing, transaction, block)
- visold/kernel/ (clock, compat, config, serialization, source_identity, units)
"""

import hashlib
import hmac
import importlib
import json
import os
import stat
import time
from unittest.mock import patch

import pytest

from visold.crypto.ecc import (
    ECPoint,
    G,
    _recover_y_from_compressed,
    ecdsa_keygen,
    ecdsa_verify,
    pub_from_bytes,
    pub_from_hex,
    pub_to_hex,
    sig_from_hex,
    sig_to_hex,
)
from visold.crypto.keystore import (
    _PBKDF2_MIN_ITERS,
    _pkcs7_unpad,
    keystore_decrypt,
    keystore_encrypt,
)
from visold.crypto.mnemonic import (
    _MNEMONIC_WORDS,
    mnemonic_from_priv,
    priv_from_mnemonic,
)
from visold.crypto.parallel_verify import _par_verify_sig
from visold.crypto.vrf import _SECP256K1_P, vrf_prove, vrf_verify
from visold.kernel.clock import NetworkClock
from visold.kernel.compat import Cipher, algorithms, default_backend, modes
from visold.kernel.config import Config
from visold.kernel.serialization import _serialize
from visold.kernel.source_identity import compute_node_logic_hash
from visold.kernel.units import gas_fee_to_sat, to_satoshi
from visold.ledger.addressing import (
    is_canonical_contract_address,
    is_canonical_wallet_address,
)
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.wallet.wallet import Wallet


# ── 1. ECC & VRF ─────────────────────────────────────────────────────────────

def test_v4_off_curve_pub_rejected_by_pub_from_bytes_and_hex():
    """visold/crypto/ecc.py: _cached_pub_coords() rejects off-curve points."""
    # x = 5: (5^3 + 7) = 132 is a quadratic non-residue mod secp256k1 P
    x = 5
    compressed = b"\x02" + x.to_bytes(32, "big")
    with pytest.raises(ValueError, match="not on secp256k1"):
        pub_from_bytes(compressed)
    with pytest.raises(ValueError, match="not on secp256k1"):
        pub_from_hex(compressed.hex())


def test_v4_recover_y_from_compressed_validated():
    """visold/crypto/ecc.py: _recover_y_from_compressed() enforces prefix/len/range/curve checks."""
    with pytest.raises(ValueError, match="33 bytes"):
        _recover_y_from_compressed(b"\x04" + (5).to_bytes(32, "big") + b"\x00" * 32)
    with pytest.raises(ValueError, match="prefix"):
        _recover_y_from_compressed(b"\x04" + (5).to_bytes(32, "big"))
    with pytest.raises(ValueError, match="not on secp256k1"):
        _recover_y_from_compressed(b"\x02" + (5).to_bytes(32, "big"))
    with pytest.raises(ValueError, match="out of range"):
        _recover_y_from_compressed(b"\x02" + ECPoint.P.to_bytes(32, "big"))


def test_v4_ecpoint_eq_and_ecdsa_verify_and_sig_from_hex_malformed():
    """visold/crypto/ecc.py: ECPoint.__eq__, ecdsa_verify, and sig_from_hex handle malformed inputs safely."""
    assert (G == None) is False  # noqa: E711

    with pytest.raises(ValueError):
        sig_from_hex("[true, false]")
    with pytest.raises(ValueError):
        sig_from_hex("[1, 2, 999]")

    _, pub = ecdsa_keygen()
    assert ecdsa_verify(pub, b"\x00" * 32, None) is False  # type: ignore[arg-type]
    assert ecdsa_verify(pub, b"\x00" * 32, (1, 2, 3)) is False  # type: ignore[arg-type]


def test_v4_vrf_rejects_non_canonical_gamma_x_ge_p():
    """visold/crypto/vrf.py: vrf_verify() rejects Gamma with gx == 0 or gx >= P."""
    priv, pub = ecdsa_keygen()
    pub_hex = pub_to_hex(pub)
    proof, beta = vrf_prove(priv, b"test-alpha")
    assert vrf_verify(pub_hex, b"test-alpha", proof, beta) is True

    for bad_gx in (0, _SECP256K1_P, _SECP256K1_P + 1):
        bad_proof = proof[:1] + bad_gx.to_bytes(32, "big") + proof[33:]
        assert vrf_verify(pub_hex, b"test-alpha", bad_proof, beta) is False


# ── 2. Keystore, Mnemonic & Wallet ───────────────────────────────────────────

def test_v4_wallet_load_keystore_and_from_dict_authenticates_pub_hex(tmp_path):
    """visold/wallet/wallet.py: load_keystore() and from_dict() verify pub == priv * G."""
    w1 = Wallet.generate()
    w2 = Wallet.generate()
    ks_path = tmp_path / "ks.json"
    w1.save_keystore(str(ks_path), "StrongPass123!")

    loaded_ok = Wallet.load_keystore(str(ks_path), "StrongPass123!")
    assert loaded_ok.priv == w1.priv
    assert loaded_ok.pub == loaded_ok.priv * G
    assert loaded_ok.address == w1.address

    with open(ks_path, "r") as f:
        ks = json.load(f)
    ks["pub_hex"] = w2.pub_hex
    ks["address"] = w2.address
    with open(ks_path, "w") as f:
        json.dump(ks, f)

    with pytest.raises(ValueError, match="does not match"):
        Wallet.load_keystore(str(ks_path), "StrongPass123!")

    d = w1.to_dict()
    d["pub_hex"] = w2.pub_hex
    with pytest.raises(ValueError, match="does not match"):
        Wallet.from_dict(d)


def test_v4_legacy_cbc_keystore_mac_covers_iv():
    """visold/crypto/keystore.py: legacy AES-256-CBC HMAC covers iv + ct and enforces min PBKDF2 iters."""
    from cryptography.hazmat.primitives import hashes as _h
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = os.urandom(32)
    iv = os.urandom(16)
    password = "pw"
    iters = _PBKDF2_MIN_ITERS

    key = PBKDF2HMAC(
        algorithm=_h.SHA256(), length=32, salt=salt, iterations=iters, backend=default_backend()
    ).derive(password.encode())
    pt = b"0x" + b"a" * 64
    pad_len = 16 - (len(pt) % 16)
    padded = pt + bytes([pad_len] * pad_len)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac.new(key, iv + ct, hashlib.sha256).digest()

    ks_valid = {
        "cipher": "AES-256-CBC",
        "kdf": f"PBKDF2-SHA256-i{iters}",
        "salt": salt.hex(),
        "iv": iv.hex(),
        "ct": ct.hex(),
        "mac": mac.hex(),
    }
    assert keystore_decrypt(ks_valid, password) == pt.decode()

    tampered_iv = bytearray(iv)
    tampered_iv[2] ^= 0x01
    ks_tampered_iv = dict(ks_valid, iv=bytes(tampered_iv).hex())
    with pytest.raises(ValueError, match="Wrong password or corrupted keystore"):
        keystore_decrypt(ks_tampered_iv, password)

    ks_low_iters = dict(ks_valid, kdf="PBKDF2-SHA256-i1000")
    with pytest.raises(ValueError, match="out of bounds"):
        keystore_decrypt(ks_low_iters, password)


def test_v4_keystore_kdf_dispatch_and_pkcs7_unpad_hardened():
    """visold/crypto/keystore.py: kdf=None rejected, unknown KDF rejected, _pkcs7_unpad validates all pad bytes."""
    with pytest.raises(ValueError, match="Invalid PKCS7 padding"):
        _pkcs7_unpad(b"")
    with pytest.raises(ValueError, match="Invalid PKCS7 padding"):
        _pkcs7_unpad(b"\x05")
    with pytest.raises(ValueError, match="Invalid PKCS7 padding"):
        _pkcs7_unpad(b"a" * 15 + b"\x05")

    ks = keystore_encrypt("0x" + "1" * 64, "pw")
    ks["kdf"] = None
    with pytest.raises(ValueError, match="Unsupported or invalid KDF tag"):
        keystore_decrypt(ks, "pw")

    ks2 = keystore_encrypt("0x" + "1" * 64, "pw")
    ks2["kdf"] = "unknown-kdf-i1"
    with pytest.raises(ValueError, match="Unsupported KDF tag"):
        keystore_decrypt(ks2, "pw")


def test_v4_wallet_file_permissions_owner_only(tmp_path):
    """visold/wallet/wallet.py: save() and save_keystore() enforce 0o600 permissions."""
    old_umask = os.umask(0o022)
    try:
        w = Wallet.generate()
        p_plain = tmp_path / "wallet.json"
        p_ks = tmp_path / "ks.json"
        w.save(str(p_plain))
        w.save_keystore(str(p_ks), "pw")
        assert stat.S_IMODE(os.stat(p_plain).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(p_ks).st_mode) == 0o600
    finally:
        os.umask(old_umask)


def _encode_raw_mnemonic(priv_int: int) -> str:
    data = priv_int.to_bytes(32, "big")
    checksum = hashlib.sha256(data).digest()[0]
    bits = int.from_bytes(data + bytes([checksum]), "big")
    words = []
    for i in range(24):
        idx = (bits >> (11 * (23 - i))) & 0x7FF
        words.append(_MNEMONIC_WORDS[idx])
    return " ".join(words)


def test_v4_mnemonic_rejects_out_of_range_scalars():
    """visold/crypto/mnemonic.py & wallet.py: priv=0, priv=N, priv=N+1 are rejected."""
    for bad_priv in (0, ECPoint.N, ECPoint.N + 1):
        with pytest.raises(ValueError, match="range"):
            mnemonic_from_priv(bad_priv)
        raw_phrase = _encode_raw_mnemonic(bad_priv)
        with pytest.raises(ValueError, match="out-of-range"):
            priv_from_mnemonic(raw_phrase)
        with pytest.raises(ValueError, match="out-of-range"):
            Wallet.from_mnemonic(raw_phrase)


# ── 3. Parallel Verification ─────────────────────────────────────────────────

def test_v4_par_verify_sig_enforces_sender_binding():
    """visold/crypto/parallel_verify.py: _par_verify_sig() requires valid sender binding."""
    w = Wallet.generate()
    tx_bad = Transaction(sender="VSD_FAKE_SENDER", receiver=w.address, amount=1.0, fee=0.01)
    sig_bad = w.sign(tx_bad.signing_bytes())
    tx_bad.pub_hex = w.pub_hex
    tx_bad.sig_hex = sig_to_hex(sig_bad)

    assert tx_bad.verify_signature() is False
    assert _par_verify_sig(tx_bad.pub_hex, tx_bad.sig_hex, tx_bad.signing_bytes(), sender=None) is False
    assert _par_verify_sig(tx_bad.pub_hex, tx_bad.sig_hex, tx_bad.signing_bytes(), sender=tx_bad.sender) is False

    tx_ok = Transaction(sender=w.address, receiver=w.address, amount=1.0, fee=0.01)
    tx_ok.sign(w)
    assert _par_verify_sig(tx_ok.pub_hex, tx_ok.sig_hex, tx_ok.signing_bytes(), sender=tx_ok.sender) is True


# ── 4. Addressing, Transaction & Block ───────────────────────────────────────

def test_v4_addressing_lowercase_contract_and_bounded_base58():
    """visold/ledger/addressing.py: uppercase VSDc rejected; oversized VSD* rejected in O(1)."""
    upper_contract = "VSDc" + "AB12CD34EF56" * 3
    lower_contract = "VSDc" + "ab12cd34ef56" * 3
    assert is_canonical_contract_address(upper_contract) is False
    assert is_canonical_contract_address(lower_contract) is True

    t0 = time.perf_counter()
    res = is_canonical_wallet_address("VSD" + "z" * 5000)
    elapsed = time.perf_counter() - t0
    assert res is False
    assert elapsed < 0.05


def test_v4_transaction_validation_and_roundtrip_hardened():
    """visold/ledger/transaction.py: forged tx_id, roundtrip preservation, NaN gas_price/expiry, COINBASE register, TYPE_CALL receiver, overflow."""
    w1 = Wallet.generate()
    w2 = Wallet.generate()

    # 1. Forged tx_id rejected by is_valid()
    tx = Transaction(sender=w1.address, receiver=w2.address, amount=1.0, fee=0.01, nonce=0)
    tx.sign(w1)
    d = tx.to_dict()
    d["tx_id"] = "f" * 64
    tx_forged = Transaction.from_dict(d)
    ok_forged, _ = tx_forged.is_valid()
    assert ok_forged is False

    # 2. from_dict() preserves expiry=0 and version=2
    tx_noexp = Transaction(sender=w1.address, receiver=w2.address, amount=1.0, fee=0.01, timestamp=1000, expiry=0)
    tx_noexp.expiry = 0
    tx_noexp.version = 2
    tx_noexp.sign(w1)
    rt = Transaction.from_dict(tx_noexp.to_dict())
    assert rt.expiry == 0
    assert rt.version == 2
    assert rt.verify_signature() is True

    # 3. NaN gas_price rejected by is_valid()
    tx_nan_gp = Transaction(sender=w1.address, receiver=w2.address, amount=1.0, fee=0.01, gas_price=float("nan"))
    ok_gp, _ = tx_nan_gp.is_valid()
    assert ok_gp is False

    # 4. expiry=float('nan') is expired and rejected by is_valid()
    tx_nan_exp = Transaction(sender=w1.address, receiver=w2.address, amount=1.0, fee=0.01, expiry=float("nan"))  # type: ignore[arg-type]
    tx_nan_exp.sign(w1)
    assert tx_nan_exp.is_expired(reference_time=9_999_999_999) is True
    ok_exp, _ = tx_nan_exp.is_valid(reference_time=9_999_999_999)
    assert ok_exp is False

    # 5. Unsigned COINBASE TYPE_REGISTER rejected by is_valid()
    tx_cb_reg = Transaction(sender="COINBASE", receiver="", amount=10.0, fee=0.0, memo="miner", tx_type=Transaction.TYPE_REGISTER)
    ok_cb, _ = tx_cb_reg.is_valid()
    assert ok_cb is False

    # 6. TYPE_CALL rejects non-VSDc receiver and accepts canonical VSDc contract address
    tx_call_bad = Transaction(
        sender=w1.address, receiver="not_a_contract", amount=0.0, fee=0.0,
        tx_type=Transaction.TYPE_CALL, gas_limit=21000, gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    tx_call_bad.sign(w1)
    ok_call_bad, _ = tx_call_bad.is_valid()
    assert ok_call_bad is False

    tx_call_ok = Transaction(
        sender=w1.address, receiver="VSDc" + "a" * 36, amount=0.0, fee=0.0,
        tx_type=Transaction.TYPE_CALL, gas_limit=21000, gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    tx_call_ok.sign(w1)
    assert tx_call_ok.is_valid() == (True, "OK")

    # 7. Combined amount + gas_fee > 2^63 - 1 rejected by is_valid()
    tx_ovf = Transaction(
        sender=w1.address, receiver="VSDc" + "a" * 36, amount=90_000_000_000.0, fee=0.0,
        tx_type=Transaction.TYPE_CALL, gas_limit=1_000_000, gas_price=90_000.0,
    )
    tx_ovf.sign(w1)
    ok_ovf, _ = tx_ovf.is_valid()
    assert ok_ovf is False


def test_v4_block_from_dict_and_genesis_integrity_check():
    """visold/ledger/block.py: integrity_check() accepts genesis; from_dict() preserves fields and rejects empty block_hash."""
    gen_tx = Transaction(
        sender=Config.GENESIS_TX_SENDER,
        receiver=Config.GENESIS_MINER,
        amount=0.0,
        timestamp=Config.GENESIS_TIMESTAMP,
        nonce=Config.GENESIS_TX_NONCE,
        expiry=Config.GENESIS_TX_EXPIRY,
        memo=Config.GENESIS_TX_MEMO,
    )
    gen_blk = Block(
        index=0,
        prev_hash="0" * 64,
        transactions=[gen_tx],
        miner_address=Config.GENESIS_MINER,
        difficulty=Config.INITIAL_DIFFICULTY,
        timestamp=Config.GENESIS_TIMESTAMP,
        nonce=Config.GENESIS_NONCE,
    )
    assert gen_blk.integrity_check() == (True, "OK")

    d = gen_blk.to_dict()
    d["version"] = 2
    d["timestamp"] = 0
    d["protocol_version"] = 0
    rt = Block.from_dict(d)
    assert rt.version == 2
    assert rt.timestamp == 0
    assert rt.protocol_version == 0
    assert rt.block_hash == gen_blk.block_hash

    d_empty = gen_blk.to_dict()
    d_empty["block_hash"] = ""
    with pytest.raises(ValueError, match="block_hash"):
        Block.from_dict(d_empty)


# ── 5. Kernel ────────────────────────────────────────────────────────────────

def test_v4_kernel_clock_units_serialization_compat_lru_source_identity(tmp_path):
    """visold/kernel/*: clock, units, serialization, compat, source_identity."""
    # Clock ignores implausible future jump and NaN without crashing
    clk = NetworkClock()
    now = int(time.time())
    for _ in range(3):
        clk.record_peer_timestamp(now + 10_000_000, trusted=True)
    assert clk.network_time() <= now + 5

    clk_nan = NetworkClock()
    clk_nan.record_peer_timestamp(now, trusted=True)
    clk_nan.record_peer_timestamp(float("nan"), trusted=True)  # type: ignore[arg-type]
    clk_nan.record_peer_timestamp(float("nan"), trusted=True)  # type: ignore[arg-type]
    assert isinstance(clk_nan.network_time(), int)

    # Units exact Decimal precision & negative gas_units rejection
    assert to_satoshi("100000000.00000001") == 10_000_000_000_000_001
    with pytest.raises(ValueError, match="non-negative"):
        gas_fee_to_sat(-10, 0.00000001)

    # Serialization uses _SafeJSONEncoder (sets -> sorted lists)
    assert _serialize({"s": {1, 2}}) == '{"s": [1, 2]}'

    # Compat _CUDA_AVAILABLE / _OPENCL_AVAILABLE are False when packages absent
    import visold.kernel.compat as compat_mod
    try:
        with patch("importlib.util.find_spec", return_value=None):
            reloaded = importlib.reload(compat_mod)
            assert reloaded._CUDA_AVAILABLE is False
            assert reloaded._OPENCL_AVAILABLE is False
    finally:
        importlib.reload(compat_mod)

    # Source identity returns "unknown" instead of trusting unauthenticated manifest on OSError
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    py_file = pkg / "a.py"
    py_file.write_text("x = 1\n")
    manifest = {
        "algorithm": "visold-package-source-v1",
        "package_source_sha256": "a" * 64,
        "source_file_count": 1,
    }
    (pkg / "_build_identity.json").write_text(json.dumps(manifest))
    with patch("visold.kernel.source_identity.package_source_blob", side_effect=OSError("perm")):
        assert compute_node_logic_hash(str(pkg)) == "unknown"
