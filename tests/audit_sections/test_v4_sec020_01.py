import hashlib
import json
from pathlib import Path
import sys

import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.crypto.mnemonic import _MNEMONIC_WORDS, priv_from_mnemonic
from visold.crypto.vrf import _SECP256K1_N
from visold.kernel.config import Config
from visold.node.visold_node import UserAccount, VisoldNode
from visold.wallet.hd import derive_wallet_from_secret
from visold.wallet.wallet import Wallet


def _make_mnemonic_from_int(val: int) -> str:
    """Encode an arbitrary 256-bit integer (including 0 or >= N) with a valid checksum."""
    data = val.to_bytes(32, "big")
    checksum = hashlib.sha256(data).digest()[0]
    bits = int.from_bytes(data + bytes([checksum]), "big")
    words = []
    for _ in range(24):
        words.append(_MNEMONIC_WORDS[bits & 0x7FF])
        bits >>= 11
    return " ".join(reversed(words))


class TestSection20FixedRegressions:
    def test_load_keystore_and_from_dict_enforce_pub_priv_binding(self, tmp_path):
        """V4 fix for BUG-20-01: Wallet.load_keystore() and Wallet.from_dict() reject mismatched pub_hex."""
        w_real = Wallet.generate()
        w_attacker = Wallet.generate()
        ks_path = tmp_path / "keystore.json"
        w_real.save_keystore(str(ks_path), "test_machine_secret")

        ks = json.loads(ks_path.read_text())
        ks["pub_hex"] = w_attacker.pub_hex
        ks["address"] = w_attacker.address
        ks_path.write_text(json.dumps(ks))

        with pytest.raises(ValueError, match="does not match"):
            Wallet.load_keystore(str(ks_path), "test_machine_secret")

        d = w_real.to_dict()
        d["pub_hex"] = w_attacker.pub_hex
        with pytest.raises(ValueError, match="does not match"):
            Wallet.from_dict(d)

    def test_load_or_create_wallet_rejects_tampered_keystore_pub_hex(
        self, tmp_path, monkeypatch
    ):
        """V4 fix for BUG-20-01 integration: _load_or_create_wallet() fails closed on tampered keystore pub_hex."""
        ks_file = tmp_path / "keystore.json"
        acct_file = tmp_path / "account.json"
        wallet_file = tmp_path / "wallet.json"
        monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
        monkeypatch.setattr(Config, "KEYSTORE_FILE", str(ks_file))
        monkeypatch.setattr(Config, "WALLET_FILE", str(wallet_file))
        monkeypatch.setattr(UserAccount, "ACCOUNTS_FILE", str(acct_file))

        w_stale = Wallet.generate()
        w_expected = derive_wallet_from_secret(
            "0123456789abcdef0123456789abcdef", "alice#0123456789"
        )

        node_stub = VisoldNode.__new__(VisoldNode)
        machine_secret = node_stub._get_or_create_machine_secret()
        w_stale.save_keystore(str(ks_file), machine_secret)
        ks = json.loads(ks_file.read_text())
        ks["pub_hex"] = w_expected.pub_hex
        ks["address"] = w_expected.address
        ks_file.write_text(json.dumps(ks))

        acct_file.write_text(json.dumps({
            "user_id": "alice#0123456789",
            "wallet_derivation": "v1-hkdf",
            "wallet_addr": w_expected.address,
        }))

        with pytest.raises(SystemExit):
            node_stub._load_or_create_wallet()

    def test_wallet_from_mnemonic_rejects_point_at_infinity(self):
        """V4 fix for BUG-20-02: priv_from_mnemonic() and Wallet.from_mnemonic() reject 0 and _SECP256K1_N."""
        m_zero = _make_mnemonic_from_int(0)
        with pytest.raises(ValueError):
            priv_from_mnemonic(m_zero)
        with pytest.raises(ValueError):
            Wallet.from_mnemonic(m_zero)

        m_n = _make_mnemonic_from_int(_SECP256K1_N)
        with pytest.raises(ValueError):
            priv_from_mnemonic(m_n)
        with pytest.raises(ValueError):
            Wallet.from_mnemonic(m_n)

    def test_user_account_recover_normalizes_uppercase_hex(
        self, tmp_path, monkeypatch
    ):
        """V4 fix for BUG-20-03: UserAccount.recover() normalizes uppercase hex to match register()."""
        ks_file = tmp_path / "keystore.json"
        acct_file = tmp_path / "account.json"
        monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
        monkeypatch.setattr(Config, "KEYSTORE_FILE", str(ks_file))
        monkeypatch.setattr(UserAccount, "ACCOUNTS_FILE", str(acct_file))

        ok, user_id, secret = UserAccount.register("alice")
        assert ok
        orig_addr = json.loads(acct_file.read_text())["wallet_addr"]

        ks_file.unlink()
        acct_file.unlink()

        ok_rec, msg_rec = UserAccount.recover(user_id, secret.upper())
        assert ok_rec, msg_rec
        rec_addr = json.loads(acct_file.read_text())["wallet_addr"]

        assert rec_addr == orig_addr

    def test_user_account_register_guards_overwrite_and_invalid_username(
        self, tmp_path, monkeypatch
    ):
        """V4 fix for BUG-20-04: UserAccount.register() refuses to overwrite existing account and rejects invalid usernames."""
        ks_file = tmp_path / "keystore.json"
        acct_file = tmp_path / "account.json"
        monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
        monkeypatch.setattr(Config, "KEYSTORE_FILE", str(ks_file))
        monkeypatch.setattr(UserAccount, "ACCOUNTS_FILE", str(acct_file))

        ok1, uid1, _ = UserAccount.register("alice")
        assert ok1
        addr1 = json.loads(acct_file.read_text())["wallet_addr"]

        # Calling register() again must fail and preserve existing account
        ok2, _, _ = UserAccount.register("bob")
        assert not ok2
        assert json.loads(acct_file.read_text())["user_id"] == uid1
        assert json.loads(acct_file.read_text())["wallet_addr"] == addr1

        # Invalid username must be rejected by register()
        acct_file.unlink()
        ks_file.unlink()
        ok3, _, _ = UserAccount.register("bad user!")
        assert not ok3

    def test_plaintext_wallet_migration_enforces_v1_hkdf_address_check(
        self, tmp_path, monkeypatch
    ):
        """V4 fix for BUG-20-05: _load_or_create_wallet() refuses to migrate mismatched plaintext wallet over v1-hkdf."""
        ks_file = tmp_path / "keystore.json"
        acct_file = tmp_path / "account.json"
        wallet_file = tmp_path / "wallet.json"
        monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
        monkeypatch.setattr(Config, "KEYSTORE_FILE", str(ks_file))
        monkeypatch.setattr(Config, "WALLET_FILE", str(wallet_file))
        monkeypatch.setattr(UserAccount, "ACCOUNTS_FILE", str(acct_file))

        w_expected = derive_wallet_from_secret(
            "0123456789abcdef0123456789abcdef", "alice#0123456789"
        )
        w_legacy = Wallet.generate()
        w_legacy.save(str(wallet_file))

        acct_file.write_text(json.dumps({
            "user_id": "alice#0123456789",
            "wallet_derivation": "v1-hkdf",
            "wallet_addr": w_expected.address,
        }))

        node_stub = VisoldNode.__new__(VisoldNode)
        with pytest.raises(SystemExit):
            node_stub._load_or_create_wallet()
