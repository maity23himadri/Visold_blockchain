"""V4 regression tests for Section 18: Password-Based Key Derivation & Argon2 Fallback."""

import importlib.util
from pathlib import Path
import secrets
import sys
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.crypto import keystore
from visold.kernel import compat


class TestSection18FixedRegressions:
    def test_compat_cuda_and_opencl_flags_false_when_missing(self):
        """V4 fix for BUG-18-01: _CUDA_AVAILABLE and _OPENCL_AVAILABLE are False when packages are missing."""
        if importlib.util.find_spec("pycuda") is None:
            assert compat._CUDA_AVAILABLE is False
        if importlib.util.find_spec("pyopencl") is None:
            assert compat._OPENCL_AVAILABLE is False

    def test_keystore_decrypt_none_kdf_raises_value_error(self):
        """V4 fix for BUG-18-02: keystore_decrypt() raises ValueError when kdf is None."""
        with patch.object(keystore, "_ARGON2_AVAILABLE", False):
            ks = keystore.keystore_encrypt("0x" + "ab" * 32, "secret")
        ks["kdf"] = None

        with pytest.raises(ValueError, match="Unsupported or invalid KDF tag"):
            keystore.keystore_decrypt(ks, "secret")

    def test_keystore_decrypt_rejects_unknown_kdf_and_arbitrary_iters(self):
        """V4 fix for BUG-18-03: unknown KDF tags and low-iteration bogus tags are rejected."""
        with patch.object(keystore, "_ARGON2_AVAILABLE", False):
            ks = keystore.keystore_encrypt("0x" + "cd" * 32, "secret")

        ks_unknown = dict(ks)
        ks_unknown["kdf"] = "scrypt-i1"
        with pytest.raises(ValueError, match="Unsupported KDF tag"):
            keystore.keystore_decrypt(ks_unknown, "secret")

        salt = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        weak_key = PBKDF2HMAC(
            algorithm=keystore._hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1,
            backend=keystore.default_backend(),
        ).derive(b"secret")
        enc = Cipher(
            algorithms.AES(weak_key),
            modes.GCM(nonce),
            backend=keystore.default_backend(),
        ).encryptor()
        ct = enc.update(b"0x" + b"ef" * 32) + enc.finalize()
        weak_ks = {
            "cipher": "AES-256-GCM",
            "kdf": "unknown-weak-i1",
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ct": ct.hex(),
            "tag": enc.tag.hex(),
        }
        with pytest.raises(ValueError, match="Unsupported KDF tag"):
            keystore.keystore_decrypt(weak_ks, "secret")

    def test_keystore_decrypt_malformed_argon2id_tag_raises_value_error(self):
        """V4 fix for BUG-18-04: malformed argon2id-* tags raise ValueError instead of silent fallback."""
        def fake_hash_secret_raw(**kwargs):
            return b"\x11" * 32

        class FakeType:
            ID = "ID"

        with (
            patch.object(keystore, "_ARGON2_AVAILABLE", True),
            patch.object(keystore, "hash_secret_raw", fake_hash_secret_raw, create=True),
            patch.object(keystore, "_Argon2Type", FakeType, create=True),
        ):
            ks = keystore.keystore_encrypt("0x" + "12" * 32, "secret")
            ks["kdf"] = "argon2id-malformed-tag"
            with pytest.raises(ValueError, match="Malformed Argon2id KDF tag"):
                keystore.keystore_decrypt(ks, "secret")
