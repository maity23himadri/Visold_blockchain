# ─────────────────────────────────────────────────────────────────────────────
#  Visold (VSD) Blockchain Protocol
#  Copyright (c) 2025 Visold Contributors
#  Licensed under the MIT License.
#
#  The original and canonical source is maintained by the Visold Project.
#  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#  the license agreement.
# ─────────────────────────────────────────────────────────────────────────────
# cython: language_level=3
# cython: boundscheck=True
# cython: wraparound=True
# cython: cdivision=True
# cython: nonecheck=True
# cython: initializedcheck=False
# cython: infer_types=True
# cython: optimize.use_switch=True
# cython: optimize.unpack_method_calls=True
"""visold.crypto.keystore


Defines: keystore_encrypt, keystore_decrypt
Origin: visold_vsd_.py L3545-3549, L10846-10920, L10923-11004
"""

import hashlib
import hmac
import secrets

from visold.kernel.compat import (
    Cipher,
    PBKDF2HMAC,
    _ARGON2_AVAILABLE,
    _hashes,
    algorithms,
    default_backend,
    modes,
)

try:  # optional dependency: name may be undefined, exactly as in the monolith
    from visold.kernel.compat import _Argon2Type
except ImportError:
    pass

try:  # optional dependency: name may be undefined, exactly as in the monolith
    from visold.kernel.compat import hash_secret_raw
except ImportError:
    pass


# Argon2id parameters (RFC 9106 §4 "first recommended option"):
#   time_cost   = 3   passes  (iterations over memory)
#   memory_cost = 65536 KiB  (64 MB — memory-hard, blocks GPU parallelism)
#   parallelism = 4   threads (matches a quad-core mobile CPU)
#   hash_len    = 32  bytes   (256-bit output for AES-256 key material)
_ARGON2_TIME_COST    = 3


_ARGON2_MEMORY_COST  = 65536   # KiB — 64 MB


_ARGON2_PARALLELISM  = 4


_ARGON2_HASH_LEN     = 32


_ARGON2_KDF_TAG      = f"argon2id-t{_ARGON2_TIME_COST}-m{_ARGON2_MEMORY_COST}-p{_ARGON2_PARALLELISM}"

_ARGON2_MIN_TIME_COST   = 1
_ARGON2_MAX_TIME_COST   = 64
_ARGON2_MIN_MEMORY_COST = 8192      # 8 MiB floor
_ARGON2_MAX_MEMORY_COST = 1_048_576 # 1 GiB cap
_ARGON2_MIN_PARALLELISM = 1
_ARGON2_MAX_PARALLELISM = 64

_PBKDF2_DEFAULT_ITERS   = 260_000
_PBKDF2_MIN_ITERS       = 100_000
_PBKDF2_MAX_ITERS       = 10_000_000


# ── 2G. AES-256-CBC encrypted keystore ───────────────────────────────────────
def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from password + salt.

    KDF priority:
      1. Argon2id (argon2-cffi installed) — RFC 9106 memory-hard KDF.
         Parameters: t=3, m=65536 KiB (64 MB), p=4.  Resistant to GPU/ASIC
         brute-force; 64 MB working set eliminates parallelism on commodity
         hardware.
      2. PBKDF2-HMAC-SHA256 (260 000 iterations) — used when argon2-cffi is
         absent (Termux, constrained VMs).  Still 260 000x stronger than bare
         SHA-256 and meets NIST SP 800-132 minimums.

    Both branches produce 32 bytes of uniform key material suitable for AES-256.
    """
    if _ARGON2_AVAILABLE:
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_ARGON2_HASH_LEN,
            type=_Argon2Type.ID,
        )
    # Fallback: PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=_hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=260_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16 != 0:
        raise ValueError("Invalid PKCS7 padding")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16 or pad_len > len(data):
        raise ValueError("Invalid PKCS7 padding")
    # BUG-FIX: original code only checked the last byte for length.  PKCS#7
    # requires ALL padding bytes to equal pad_len.  Skipping this verification
    # silently accepts malformed ciphertext, weakening the MAC-then-pad defence.
    if any(b != pad_len for b in data[-pad_len:]):
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]


def keystore_encrypt(priv_hex: str, password: str, aad: bytes = b"") -> dict:
    """
    Encrypt private key hex with AES-256-GCM (authenticated encryption).
    GCM provides both confidentiality AND integrity — any tampering of the
    ciphertext (or optional AAD) will cause decryption to fail with an
    authentication error.
    Returns a JSON-serialisable dict.
    """
    salt      = secrets.token_bytes(32)
    nonce     = secrets.token_bytes(12)   # 96-bit nonce for GCM
    key       = _derive_key(password, salt)
    plaintext = priv_hex.encode()
    cipher    = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    enc       = cipher.encryptor()
    if aad:
        enc.authenticate_additional_data(aad)
    ct        = enc.update(plaintext) + enc.finalize()
    tag       = enc.tag                  # 128-bit GCM authentication tag
    # Store the exact KDF tag so keystore_decrypt can reproduce the derivation
    # even if the default KDF changes in a future version.
    kdf_tag = _ARGON2_KDF_TAG if _ARGON2_AVAILABLE else "PBKDF2-SHA256-i260000"
    return {
        "cipher":     "AES-256-GCM",
        "kdf":        kdf_tag,
        "salt":       salt.hex(),
        "nonce":      nonce.hex(),
        "ct":         ct.hex(),
        "tag":        tag.hex(),
    }


def keystore_decrypt(ks: dict, password: str, aad: bytes = b"") -> str:
    """
    Decrypt AES-256-GCM keystore.
    Raises ValueError on wrong password or any data tampering.

    Supported KDF tags (stored in ks["kdf"]):
      "argon2id-t*-m*-p*"   — Argon2id (memory-hard, preferred)
      "PBKDF2-SHA256*"       — PBKDF2-HMAC-SHA256 (legacy / constrained device)
      "PBKDF2-SHA256-i*"     — same, iteration count encoded in tag
    Supported cipher modes: AES-256-GCM (current), AES-256-CBC (legacy).
    """
    if not isinstance(ks, dict):
        raise ValueError("Invalid keystore object")
    try:
        salt = bytes.fromhex(ks["salt"])
        ct   = bytes.fromhex(ks["ct"])
    except (KeyError, ValueError, TypeError):
        raise ValueError("Corrupted keystore")
    kdf_tag     = ks.get("kdf", "PBKDF2-SHA256")
    cipher_mode = ks.get("cipher", "AES-256-GCM")

    if not isinstance(kdf_tag, str) or not kdf_tag:
        raise ValueError(f"Unsupported or invalid KDF tag: {kdf_tag!r}")

    # ── KDF dispatch ─────────────────────────────────────────────────────────
    import re as _re
    if kdf_tag.startswith("argon2id-"):
        # Parse stored Argon2id parameters strictly; reject malformed tags.
        m = _re.fullmatch(r'argon2id-t(\d+)-m(\d+)-p(\d+)', kdf_tag)
        if not m:
            raise ValueError(f"Malformed Argon2id KDF tag: {kdf_tag!r}")
        _t, _m, _p = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if not (_ARGON2_MIN_TIME_COST <= _t <= _ARGON2_MAX_TIME_COST):
            raise ValueError(f"Argon2id time_cost out of bounds: {_t}")
        if not (_ARGON2_MIN_PARALLELISM <= _p <= _ARGON2_MAX_PARALLELISM):
            raise ValueError(f"Argon2id parallelism out of bounds: {_p}")
        if not (_ARGON2_MIN_MEMORY_COST <= _m <= _ARGON2_MAX_MEMORY_COST) or _m < 8 * _p:
            raise ValueError(f"Argon2id memory_cost out of bounds: {_m}")
        if not _ARGON2_AVAILABLE:
            raise ValueError(
                "Keystore was created with Argon2id but argon2-cffi is not "
                "installed on this device.  Run: pip install argon2-cffi")
        key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=_t,
            memory_cost=_m,
            parallelism=_p,
            hash_len=_ARGON2_HASH_LEN,
            type=_Argon2Type.ID,
        )
    elif kdf_tag == "PBKDF2-SHA256":
        kdf = PBKDF2HMAC(
            algorithm=_hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_PBKDF2_DEFAULT_ITERS,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode("utf-8"))
    else:
        m = _re.fullmatch(r'PBKDF2-SHA256-i(\d+)', kdf_tag)
        if not m:
            raise ValueError(f"Unsupported KDF tag: {kdf_tag!r}")
        _iters = int(m.group(1))
        if not (_PBKDF2_MIN_ITERS <= _iters <= _PBKDF2_MAX_ITERS):
            raise ValueError(f"PBKDF2 iteration count out of bounds: {_iters}")
        kdf = PBKDF2HMAC(
            algorithm=_hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_iters,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode("utf-8"))

    # ── Cipher dispatch ───────────────────────────────────────────────────────
    if cipher_mode == "AES-256-GCM":
        try:
            nonce = bytes.fromhex(ks["nonce"])
            tag   = bytes.fromhex(ks["tag"])
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag),
                            backend=default_backend())
            dec    = cipher.decryptor()
            if aad:
                dec.authenticate_additional_data(aad)
            pt     = dec.update(ct) + dec.finalize()
            return pt.decode()
        except Exception:
            raise ValueError("Wrong password or corrupted/tampered keystore")

    elif cipher_mode == "AES-256-CBC":
        # Legacy path — migrate on next save
        try:
            iv         = bytes.fromhex(ks["iv"])
            mac_stored = bytes.fromhex(ks["mac"])
        except (KeyError, ValueError, TypeError):
            raise ValueError("Wrong password or corrupted keystore")
        mac_computed = hmac.new(key, iv + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_stored, mac_computed):
            raise ValueError("Wrong password or corrupted keystore")
        try:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # type: ignore[arg-type]
            dec    = cipher.decryptor()
            pt     = dec.update(ct) + dec.finalize()
            return _pkcs7_unpad(pt).decode()
        except Exception:
            raise ValueError("Wrong password or corrupted keystore")

    else:
        raise ValueError(f"Unknown cipher mode: {cipher_mode}")
