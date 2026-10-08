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
"""visold.crypto.base58

Original section: SECTION 2: CRYPTOGRAPHIC PRIMITIVES

Defines: b58encode, b58decode
Origin: visold_vsd_.py L10328-10354
"""




# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2: CRYPTOGRAPHIC PRIMITIVES
# ─────────────────────────────────────────────────────────────────────────────

# ── 2A. Base58 ────────────────────────────────────────────────────────────────
B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, rem = divmod(n, 58)
        result.append(B58_ALPHABET[rem:rem+1])
    pad = len(data) - len(data.lstrip(b'\x00'))
    return (B58_ALPHABET[0:1] * pad + b''.join(reversed(result))).decode()


def b58decode(s: str) -> bytes:
    n = 0
    for c in s.encode():
        # BUG-FIX: B58_ALPHABET.index(c) raises ValueError with a raw bytes
        # repr on invalid input (e.g. 'O', '0', 'I', 'l').  Guard explicitly
        # so callers get a readable, actionable error message.
        if c not in B58_ALPHABET:
            raise ValueError(
                f"Invalid Base58 character: {chr(c)!r} (ordinal {c})")
        n = n * 58 + B58_ALPHABET.index(c)
    result = []
    while n > 0:
        result.append(n & 0xff)
        n >>= 8
    pad = len(s) - len(s.lstrip(chr(B58_ALPHABET[0])))
    return b'\x00' * pad + bytes(reversed(result))
