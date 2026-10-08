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
"""visold.crypto.ecc


Defines: ECPoint, ecdsa_keygen, ecdsa_sign, ecdsa_verify, pub_to_bytes, pub_from_bytes, pub_to_hex, pub_from_hex ...
Origin: visold_vsd_.py L10364-10403, L10408-10449, L10452-10477, L10480-10484
"""

import hashlib
import json
from functools import lru_cache
from typing import Tuple

from visold.crypto.base58 import b58encode
from visold.kernel.compat import (
    EllipticCurvePublicNumbers,
    SECP256K1,
    _InvalidSignature,
    _ec,
    _hashes,
    decode_dss_signature,
    default_backend,
    derive_private_key,
    encode_dss_signature,
    generate_private_key,
    Prehashed,
)

# Optional high-performance secp256k1 backend.  The mandatory
# cryptography/OpenSSL implementation remains the safe fallback.
try:  # pragma: no cover - availability depends on the deployment image
    from coincurve import PrivateKey as _CoincurvePrivateKey
    from coincurve import PublicKey as _CoincurvePublicKey
    _COINCURVE_AVAILABLE = True
except Exception:  # pragma: no cover - exercised when the optional wheel is absent
    _CoincurvePrivateKey = None
    _CoincurvePublicKey = None
    _COINCURVE_AVAILABLE = False


def _effective_ecdsa_digest(msg_hash: bytes) -> bytes:
    """Return the exact digest historically signed by Visold.

    The legacy API passes a 32-byte SHA-256 digest to cryptography while also
    selecting SHA-256 as the ECDSA hash algorithm, so the actual ECDSA message
    digest is SHA-256(msg_hash).  The accelerated backend receives this already-
    finalized digest with hasher=None, preserving the protocol behavior.
    """
    if not isinstance(msg_hash, (bytes, bytearray, memoryview)):
        raise TypeError("msg_hash must be bytes-like")
    raw = bytes(msg_hash)
    if len(raw) != 32:
        raise ValueError("msg_hash must be exactly 32 bytes")
    return hashlib.sha256(raw).digest()


@lru_cache(maxsize=8192)
def _cached_coincurve_public_key(pub_bytes: bytes):
    """Bounded cache of immutable native public-key objects.

    The size cap is deliberate: consensus validation can receive attacker-
    controlled public keys, so this cache must never grow without bound.
    """
    return _CoincurvePublicKey(pub_bytes)


@lru_cache(maxsize=8192)
def _cached_crypto_public_key(x: int, y: int):
    """Bounded cache of OpenSSL public-key objects for the fallback path."""
    numbers = EllipticCurvePublicNumbers(x, y, SECP256K1())
    return numbers.public_key(default_backend())


@lru_cache(maxsize=8192)
def _cached_pub_coords(pub_hex: str):
    """Cache compressed-key decompression without sharing mutable ECPoint objects."""
    raw = bytes.fromhex(pub_hex)
    if len(raw) != 33:
        raise ValueError("compressed public key must be 33 bytes")
    prefix = raw[0]
    if prefix not in (2, 3):
        raise ValueError("invalid compressed public-key prefix")
    x = int.from_bytes(raw[1:33], "big")
    if not (0 <= x < ECPoint.P):
        raise ValueError("public-key x coordinate out of range")
    p = ECPoint.P
    y = pow((pow(x, 3, p) + 7) % p, (p + 1) // 4, p)
    if (y & 1) != (prefix & 1):
        y = p - y
    return x, y


def _self_test_coincurve() -> bool:
    """Cross-check the optional backend before enabling it.

    This is intentionally a compatibility test, not a security primitive:
    coincurve is never allowed to weaken validation if the test fails.
    """
    if not _COINCURVE_AVAILABLE:
        return False
    try:
        priv = (1).to_bytes(32, "big")
        raw_message = b"Visold secp256k1 backend self-test"
        first_digest = hashlib.sha256(raw_message).digest()
        effective_digest = hashlib.sha256(first_digest).digest()
        key = _CoincurvePrivateKey(priv)
        sig_der = key.sign(effective_digest, hasher=None)
        pub_bytes = key.public_key.format(compressed=True)
        pub = _CoincurvePublicKey(pub_bytes)
        if not pub.verify(sig_der, effective_digest, hasher=None):
            return False
        tampered = bytes([sig_der[0] ^ 1]) + sig_der[1:]
        try:
            tampered_valid = bool(pub.verify(tampered, effective_digest, hasher=None))
        except Exception:
            # An invalid DER/signature must be rejected; an exception is also
            # an acceptable rejection result for the optional backend.
            tampered_valid = False
        if tampered_valid:
            return False
        # Also require the mandatory cryptography/OpenSSL path to accept the
        # libsecp-generated signature under Visold's historical double-SHA flow.
        cp = EllipticCurvePublicNumbers(
            int.from_bytes(pub_bytes[1:33], "big"),
            _recover_y_from_compressed(pub_bytes),
            SECP256K1(),
        ).public_key(default_backend())
        cp.verify(sig_der, first_digest, _ec.ECDSA(_hashes.SHA256()))
        return True
    except Exception:
        return False


def _recover_y_from_compressed(pub_bytes: bytes) -> int:
    prefix = pub_bytes[0]
    x = int.from_bytes(pub_bytes[1:33], "big")
    p = ECPoint.P
    y = pow((pow(x, 3, p) + 7) % p, (p + 1) // 4, p)
    if (y & 1) != (prefix & 1):
        y = p - y
    return y


_COINCURVE_SELFTEST_OK = False


# ── 2B. ECDSA — production path uses `cryptography` library ──────────────────
#
# Mandatory fallback uses the audited cryptography/OpenSSL backend.  The
# optional libsecp256k1 backend is enabled only after a runtime compatibility test.
# Node refuses to start without this library — no weak fallback exists.
#
# ECPoint is kept as a lightweight container for public-key coordinates so the
# rest of the code (address derivation, serialisation) is unchanged.

class ECPoint:
    """Coordinate container for public-key x/y coordinates (SEC format serialisation)."""
    P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    def __init__(self, x, y):
        self.x, self.y = x, y

    def is_inf(self): return self.x is None

    @classmethod
    def inf(cls): o = cls.__new__(cls); o.x = o.y = None; return o

    def __eq__(self, o): return self.x == o.x and self.y == o.y

    def __add__(self, o):
        P = self.P
        if self.is_inf(): return o
        if o.is_inf(): return self
        if self.x == o.x:
            if self.y != o.y: return ECPoint.inf()
            m = (3 * self.x * self.x * pow(2 * self.y, P-2, P)) % P
        else:
            m = ((o.y - self.y) * pow(o.x - self.x, P-2, P)) % P
        x3 = (m*m - self.x - o.x) % P
        y3 = (m*(self.x - x3) - self.y) % P
        return ECPoint(x3, y3)

    def __rmul__(self, k):
        k = k % self.N
        R, Q = ECPoint.inf(), self
        while k:
            if k & 1: R = R + Q
            Q = Q + Q
            k >>= 1
        return R


G = ECPoint(ECPoint.Gx, ECPoint.Gy)

# ECPoint is now defined; run the optional backend compatibility self-test only
# after all curve constants required by it exist.
_COINCURVE_SELFTEST_OK = _self_test_coincurve()


# ── Production ECDSA (cryptography library) ───────────────────────────────────

def _priv_int_to_crypto_key(priv_int: int):
    """Convert integer private key → cryptography EllipticCurvePrivateKey."""
    return derive_private_key(priv_int, SECP256K1(), default_backend())


def _crypto_key_to_pub_point(priv_key) -> ECPoint:
    pn = priv_key.public_key().public_numbers()
    return ECPoint(pn.x, pn.y)


def ecdsa_keygen() -> Tuple[int, ECPoint]:
    """Return (private_key_int, public_key_point) using mandatory cryptography."""
    priv_key = generate_private_key(SECP256K1(), default_backend())
    priv_int = priv_key.private_numbers().private_value
    pub = _crypto_key_to_pub_point(priv_key)
    return priv_int, pub


def ecdsa_sign(priv: int, msg_hash: bytes, _native_private_key=None, _crypto_private_key=None) -> Tuple[int, int]:
    """Return ``(r, s)`` while preserving Visold's historical double-SHA digest.

    The optional Coincurve/libsecp256k1 path is used only after a startup
    compatibility self-test.  The fallback is the existing cryptography path.
    New signatures remain ordinary secp256k1 ECDSA signatures; old signatures
    remain valid because verification accepts the same curve/signature domain.
    """
    digest = _effective_ecdsa_digest(msg_hash)
    if _COINCURVE_SELFTEST_OK:
        try:
            key = _native_private_key
            if key is None:
                raw_priv = int(priv).to_bytes(32, "big")
                key = _CoincurvePrivateKey(raw_priv)
            sig_der = key.sign(digest, hasher=None)
            return decode_dss_signature(sig_der)
        except Exception:
            # Do not silently accept a malformed/unsupported native result.
            # The mandatory implementation remains the authoritative fallback.
            pass

    priv_key = _crypto_private_key or _priv_int_to_crypto_key(priv)
    sig_der = priv_key.sign(digest, _ec.ECDSA(Prehashed(_hashes.SHA256())))
    r, s = decode_dss_signature(sig_der)
    return r, s


def ecdsa_verify(pub: ECPoint, msg_hash: bytes, sig: Tuple[int, int]) -> bool:
    r, s = sig
    N = ECPoint.N
    if not (1 <= r < N and 1 <= s < N):
        return False
    try:
        digest = _effective_ecdsa_digest(msg_hash)
        if _COINCURVE_SELFTEST_OK:
            pub_bytes = pub_to_bytes(pub)
            native_pub = _cached_coincurve_public_key(pub_bytes)
            sig_der = encode_dss_signature(r, s)
            return bool(native_pub.verify(sig_der, digest, hasher=None))

        pub_key = _cached_crypto_public_key(pub.x, pub.y)
        sig_der = encode_dss_signature(r, s)
        pub_key.verify(sig_der, digest, _ec.ECDSA(Prehashed(_hashes.SHA256())))
        return True
    except _InvalidSignature:
        return False
    except Exception:
        return False


# ── 2C. Key serialization ──────────────────────────────────────────────────────
def pub_to_bytes(pub: ECPoint) -> bytes:
    """Compressed 33-byte SEC format."""
    prefix = b'\x02' if pub.y % 2 == 0 else b'\x03'
    return prefix + pub.x.to_bytes(32, 'big')


def pub_from_bytes(data: bytes) -> ECPoint:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("public key must be bytes-like")
    raw = bytes(data)
    if len(raw) != 33:
        raise ValueError("compressed public key must be 33 bytes")
    x, y = _cached_pub_coords(raw.hex())
    return ECPoint(x, y)


def pub_to_hex(pub: ECPoint) -> str:
    return pub_to_bytes(pub).hex()


def pub_from_hex(h: str) -> ECPoint:
    return pub_from_bytes(bytes.fromhex(h))


def sig_to_hex(sig: Tuple[int,int]) -> str:
    return json.dumps([sig[0], sig[1]])


def sig_from_hex(s: str) -> Tuple[int,int]:
    arr = json.loads(s)
    return (arr[0], arr[1])


# ── 2D. Wallet address derivation ─────────────────────────────────────────────
def pub_to_address(pub: ECPoint) -> str:
    pub_bytes = pub_to_bytes(pub)
    h = hashlib.sha256(pub_bytes).digest()
    r = hashlib.new('sha256', h).digest()           # double sha256
    return 'VSD' + b58encode(r[:20])
