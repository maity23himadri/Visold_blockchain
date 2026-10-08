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
"""visold.crypto.hashing


Defines: sha256, sha256d, hash_obj
Origin: visold_vsd_.py L10771-10781, L10842-10843
"""

import hashlib
import json


# ── 2F. SHA-256 helpers ───────────────────────────────────────────────────────
def sha256(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of data.
    BUG-FIX: name 'sha256' is ambiguous — this returns a hex STRING, not bytes.
    Use sha256d() when you need raw bytes (double-SHA-256 → bytes).
    The function is kept as sha256() for wire-protocol / DB compatibility,
    but all internal callers that need bytes must call hashlib.sha256(...).digest()
    directly or use sha256d() instead."""
    return hashlib.sha256(data).hexdigest()


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash_obj(obj) -> str:
    return sha256(json.dumps(obj, sort_keys=True, default=str).encode())
