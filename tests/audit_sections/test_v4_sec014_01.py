"""V4 regression tests for Section 14: Verifiable Random Function (VRF) Generation and Verification."""

from pathlib import Path
import sys

import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.crypto.ecc import ecdsa_keygen, pub_to_hex, G
from visold.crypto.vrf import (
    vrf_prove,
    vrf_verify,
    _vrf_scalar_mul_G,
    _SECP256K1_N,
)
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction


def test_vrf_prove_verify_roundtrip_and_determinism():
    priv, pub = ecdsa_keygen()
    pub_hex = pub_to_hex(pub)
    alpha = b"block-hash-alpha-001"

    proof1, beta1 = vrf_prove(priv, alpha)
    proof2, beta2 = vrf_prove(priv, alpha)

    assert len(proof1) == 81
    assert len(beta1) == 32
    assert proof1 == proof2
    assert beta1 == beta2
    assert vrf_verify(pub_hex, alpha, proof1, beta1) is True


def test_vrf_domain_separation_and_tamper_rejection():
    priv1, pub1 = ecdsa_keygen()
    priv2, pub2 = ecdsa_keygen()
    pub1_hex = pub_to_hex(pub1)
    pub2_hex = pub_to_hex(pub2)
    alpha = b"test-alpha"

    proof, beta = vrf_prove(priv1, alpha)

    # Wrong alpha
    assert vrf_verify(pub1_hex, b"other-alpha", proof, beta) is False
    # Wrong pubkey
    assert vrf_verify(pub2_hex, alpha, proof, beta) is False
    # Tampered beta
    bad_beta = bytes([beta[0] ^ 0x01]) + beta[1:]
    assert vrf_verify(pub1_hex, alpha, proof, bad_beta) is False
    # Tampered proof (Gamma, c, s)
    for idx in (0, 1, 33, 49, 80):
        bad_proof = bytearray(proof)
        bad_proof[idx] ^= 0x01
        assert vrf_verify(pub1_hex, alpha, bytes(bad_proof), beta) is False


def test_vrf_verify_malformed_inputs_fail_closed():
    priv, pub = ecdsa_keygen()
    pub_hex = pub_to_hex(pub)
    alpha = b"malformed-test"
    proof, beta = vrf_prove(priv, alpha)

    # Empty / wrong lengths
    assert vrf_verify("", alpha, proof, beta) is False
    assert vrf_verify("00" * 33, alpha, proof, beta) is False
    assert vrf_verify(pub_hex, alpha, b"", beta) is False
    assert vrf_verify(pub_hex, alpha, proof[:-1], beta) is False
    assert vrf_verify(pub_hex, alpha, proof + b"\x00", beta) is False
    assert vrf_verify(pub_hex, alpha, proof, b"") is False
    assert vrf_verify(pub_hex, alpha, proof, beta[:-1]) is False

    # Out-of-range s >= N
    bad_s_proof = proof[:49] + _SECP256K1_N.to_bytes(32, "big")
    assert vrf_verify(pub_hex, alpha, bad_s_proof, beta) is False

    # Invalid Gamma prefix
    bad_prefix_proof = b"\x04" + proof[1:]
    assert vrf_verify(pub_hex, alpha, bad_prefix_proof, beta) is False


def test_vrf_scalar_mul_G_parity_with_ecpoint():
    for k in (1, 2, 7, _SECP256K1_N - 1):
        pt1 = _vrf_scalar_mul_G(k)
        pt2 = k * G
        assert pt1 == pt2
    assert _vrf_scalar_mul_G(0).is_inf()
    assert _vrf_scalar_mul_G(_SECP256K1_N).is_inf()


def test_block_vrf_fields_sealed_and_committed_in_hash():
    priv, pub = ecdsa_keygen()
    proof, beta = vrf_prove(priv, b"genesis")
    cb = Transaction.coinbase("VSDtestminer", 50_000_000, 1)
    blk = Block(
        index=1,
        prev_hash="0" * 64,
        transactions=[cb],
        miner_address="VSDtestminer",
        difficulty=1.0,
        timestamp=1700000001,
        vrf_proof=proof.hex(),
        vrf_output=beta.hex(),
    ).seal()

    ok, msg = blk.integrity_check()
    assert ok, msg

    with pytest.raises(AttributeError):
        blk.vrf_proof = "00" * 81
    with pytest.raises(AttributeError):
        blk.vrf_output = "00" * 32

    # Tampering via object.__setattr__ breaks block_hash check
    object.__setattr__(blk, "vrf_output", "ff" * 32)
    ok2, _ = blk.integrity_check()
    assert ok2 is False
