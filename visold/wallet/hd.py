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
"""visold.wallet.hd


Defines: derive_wallet_priv, derive_wallet_from_secret
Origin: visold_vsd_.py L11242-11243, L11246-11248, L11251-11261, L11264-11292, L11295-11302
"""

import hashlib
import hmac

from visold.crypto.ecc import G
from visold.crypto.vrf import _SECP256K1_N
from visold.wallet.wallet import Wallet


# ─────────────────────────────────────────────────────────────────────────────
# DETERMINISTIC WALLET DERIVATION FROM (secret, user_id)            v1-hkdf
# ─────────────────────────────────────────────────────────────────────────────
# Used by UserAccount.register() and .recover() so that the same (secret,
# user_id) pair always produces the SAME secp256k1 private key on any device.
# This is what makes cross-device recovery actually restore the user's funds.
#
# Construction:
#     IKM  = secret.encode()                       # 32 hex chars = 16 bytes
#     salt = sha256(b"VSD-WALLET-DERIV-V1-SALT")   # fixed protocol salt
#     info = b"VSD-WALLET-V1:" + user_id.encode()  # binds wallet to user_id
#     PRK  = HMAC-SHA256(salt, IKM)
#     OKM  = HKDF-Expand(PRK, info, 32 bytes)
#     priv = (int.from_bytes(OKM, 'big') % (N-1)) + 1
#
# Why this construction:
#   • HKDF (RFC 5869) is the standard KDF for deriving cryptographic keys
#     from input keying material with context binding.
#   • Domain-separated by user_id so two accounts that ever happen to share
#     the same 32-hex secret still derive different wallets.
#   • % (N-1) + 1 guarantees priv ∈ [1, N-1] which is the valid range for
#     secp256k1 scalars (priv == 0 is invalid; priv >= N would wrap).
#   • Constant 32-byte output makes the bias negligible (~2^-256).
#
# Backward compatibility:
#   • account.json files written by code BEFORE this change have no
#     "wallet_derivation" key.  Those are LEGACY accounts whose wallets
#     are random and CANNOT be recovered cross-device — they remain
#     readable on the original device via the existing keystore.
#   • New accounts (register or recover paths after this change) write
#     "wallet_derivation": "v1-hkdf" so future recover/load paths know
#     they can deterministically rebuild the wallet from the secret.
# ─────────────────────────────────────────────────────────────────────────────
_WALLET_DERIV_VERSION = "v1-hkdf"


_WALLET_DERIV_SALT    = hashlib.sha256(b"VSD-WALLET-DERIV-V1-SALT").digest()


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract using HMAC-SHA256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand using HMAC-SHA256."""
    out = b""
    t   = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]),
                     hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def derive_wallet_priv(secret: str, user_id: str) -> int:
    """Deterministically derive a secp256k1 private key int from
    (secret, user_id).  Same inputs ALWAYS produce the same output on
    every device — this is what makes cross-device account recovery
    actually restore the user's funds.

    Inputs:
      secret  — the 32 hex-char secret returned by UserAccount.register()
      user_id — the canonical USERNAME#xxxxxxxxxx form

    Output:
      An integer priv in [1, N-1] suitable for secp256k1 ECDSA.

    Raises ValueError if either input is empty or whitespace.
    """
    s = (secret or "").strip()
    u = (user_id or "").strip()
    if not s:
        raise ValueError("secret must not be empty")
    if not u:
        raise ValueError("user_id must not be empty")
    ikm  = s.encode("utf-8")
    info = b"VSD-WALLET-V1:" + u.encode("utf-8")
    prk  = _hkdf_extract(_WALLET_DERIV_SALT, ikm)
    okm  = _hkdf_expand(prk, info, 32)
    raw  = int.from_bytes(okm, "big")
    # Map into [1, N-1] uniformly (negligible bias for 256-bit input)
    priv = (raw % (_SECP256K1_N - 1)) + 1
    return priv


def derive_wallet_from_secret(secret: str, user_id: str) -> 'Wallet':
    """Build a fully-formed Wallet from (secret, user_id) using the
    canonical v1-hkdf derivation.  Convenience wrapper used by
    UserAccount.register / .recover and the CLI's address-preview.
    """
    priv = derive_wallet_priv(secret, user_id)
    pub  = priv * G
    return Wallet(priv, pub)
