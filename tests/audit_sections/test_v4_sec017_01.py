"""
V4 regression tests for Section 17:
Encrypted Keystore Security and Data Integrity.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.crypto.ecc import ecdsa_keygen
from visold.crypto.keystore import (
    _derive_key,
    _pkcs7_pad,
    _pkcs7_unpad,
    keystore_decrypt,
)
from visold.wallet.wallet import Wallet


class TestSection17FixedRegressions:
    def test_load_keystore_rejects_tampered_unauthenticated_pub_hex(self, tmp_path):
        """V4 fix for BUG-17-01: Wallet.load_keystore() verifies pub == priv * G."""
        victim = Wallet.generate()
        attacker = Wallet.generate()
        assert victim.address != attacker.address

        ks_path = tmp_path / "victim_keystore.json"
        victim.save_keystore(str(ks_path), "StrongPassword!123")

        ks_data = json.loads(ks_path.read_text())
        ks_data["pub_hex"] = attacker.pub_hex
        ks_data["address"] = attacker.address
        ks_path.write_text(json.dumps(ks_data))

        with pytest.raises(ValueError, match="does not match"):
            Wallet.load_keystore(str(ks_path), "StrongPassword!123")

    def test_from_dict_and_load_reject_mismatched_pub_hex(self, tmp_path):
        """V4 fix for BUG-17-01 (corollary): Wallet.from_dict() and Wallet.load() verify pub == priv * G."""
        victim = Wallet.generate()
        attacker = Wallet.generate()

        d = victim.to_dict()
        d["pub_hex"] = attacker.pub_hex
        d["address"] = attacker.address

        w_path = tmp_path / "mismatched_wallet.json"
        w_path.write_text(json.dumps(d))

        with pytest.raises(ValueError, match="does not match"):
            Wallet.load(str(w_path))

        with pytest.raises(ValueError, match="does not match"):
            Wallet.from_dict(d)

    def test_cbc_legacy_mac_covers_iv_rejecting_iv_tampering(self):
        """V4 fix for BUG-17-02: AES-256-CBC legacy MAC covers iv + ct, rejecting IV tampering."""
        priv, _ = ecdsa_keygen()
        priv_hex = hex(priv)
        password = "LegacyPassword!99"
        salt = b"\x11" * 32
        iv = bytearray(b"\x22" * 16)
        key = _derive_key(password, salt)

        pt = _pkcs7_pad(priv_hex.encode("utf-8"))
        cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(iv)), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(pt) + enc.finalize()
        mac = hmac.new(key, ct, hashlib.sha256).digest()

        target_char = priv_hex[2]
        flipped_char = "1" if target_char != "1" else "0"
        delta = ord(target_char) ^ ord(flipped_char)
        tampered_iv = bytearray(iv)
        tampered_iv[2] ^= delta

        ks_tampered = {
            "cipher": "AES-256-CBC",
            "kdf": "PBKDF2-SHA256-i260000",
            "salt": salt.hex(),
            "iv": bytes(tampered_iv).hex(),
            "ct": ct.hex(),
            "mac": mac.hex(),
        }

        with pytest.raises(ValueError, match="Wrong password or corrupted keystore"):
            keystore_decrypt(ks_tampered, password)

    def test_pkcs7_unpad_rejects_empty_and_short_data_with_value_error(self):
        """V4 fix for BUG-17-03: _pkcs7_unpad() raises ValueError on empty and short inputs."""
        with pytest.raises(ValueError, match="Invalid PKCS7 padding"):
            _pkcs7_unpad(b"")

        with pytest.raises(ValueError, match="Invalid PKCS7 padding"):
            _pkcs7_unpad(b"\x05")

        with pytest.raises(ValueError, match="Invalid PKCS7 padding"):
            _pkcs7_unpad(b"\x10\x10")

        password = "pw"
        salt = b"\x00" * 32
        iv = b"\x00" * 16
        key = _derive_key(password, salt)
        mac = hmac.new(key, b"", hashlib.sha256).digest()
        ks_empty_ct = {
            "cipher": "AES-256-CBC",
            "kdf": "PBKDF2-SHA256-i260000",
            "salt": salt.hex(),
            "iv": iv.hex(),
            "ct": "",
            "mac": mac.hex(),
        }
        with pytest.raises(ValueError):
            keystore_decrypt(ks_empty_ct, password)

    def test_wallet_save_and_save_keystore_enforce_0600_permissions(self, tmp_path):
        """V4 fix for BUG-17-04: Wallet.save() and Wallet.save_keystore() enforce 0o600 permissions."""
        old_umask = os.umask(0o022)
        try:
            w = Wallet.generate()
            plain_path = tmp_path / "wallet_plain.json"
            ks_path = tmp_path / "wallet_ks.json"

            w.save(str(plain_path))
            w.save_keystore(str(ks_path), "pw123")

            plain_mode = stat.S_IMODE(os.stat(plain_path).st_mode)
            ks_mode = stat.S_IMODE(os.stat(ks_path).st_mode)

            assert plain_mode == 0o600, f"Expected 0o600, got {oct(plain_mode)}"
            assert ks_mode == 0o600, f"Expected 0o600, got {oct(ks_mode)}"
        finally:
            os.umask(old_umask)

    def test_valid_keystore_roundtrip_control(self, tmp_path):
        """Control test: normal save_keystore / load_keystore and tamper detection."""
        w = Wallet.generate()
        ks_path = tmp_path / "valid_ks.json"
        w.save_keystore(str(ks_path), "CorrectHorseBatteryStaple")

        loaded = Wallet.load_keystore(str(ks_path), "CorrectHorseBatteryStaple")
        assert loaded.priv == w.priv
        assert loaded.pub_hex == w.pub_hex
        assert loaded.address == w.address

        with pytest.raises(ValueError):
            Wallet.load_keystore(str(ks_path), "WrongPassword")
