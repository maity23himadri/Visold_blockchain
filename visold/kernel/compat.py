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
"""visold.kernel.compat

Original section: END SECTION UDP-TRANSPORT

Origin: visold_vsd_.py L2885-2890, L2911-2922, L3389-3393, L3398-3402, L3406-3410, L3413-3418, L3425-3430, L3435-3440, L3448-3483, L3489-3524, L3534-3538
"""

import os
import sys
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# END SECTION UDP-TRANSPORT
# ─────────────────────────────────────────────────────────────────────────────

# ── Optional NTP library (soft dependency for hardened clock) ─────────────────
try:
    import ntplib as _ntplib
    _NTPLIB_AVAILABLE = True
except ImportError:
    _ntplib = None  # type: ignore
    _NTPLIB_AVAILABLE = False


# ═════════════════════════════════════════════════════════════════════════════
# v7.1.0 STORAGE SUBSYSTEM (PostgreSQL + RocksDB + Redis)
# ─────────────────────────────────────────────────────────────────────────────
# Replaces the SQLite single-writer bottleneck (Bug 1 in v7.0.1.0 header).
# Strategy:
#   • PostgreSQL ....... user accounts, balances, transactions metadata,
#                        peers, validators, mempool cold store.
#   • RocksDB .......... block bodies, headers, hash-index, tx locators,
#                        account state trie, merkle nodes, contract code+slots.
#   • Redis ............ hot cache: tip block, height, recent balances,
#                        live mempool (sorted-set by fee), pub/sub of new blocks.
#   • SQLite (aux) ..... retained ONLY for a handful of ad-hoc external
#                        raw-SQL callers (reputation_extended, peer_capabilities).
#                        No consensus or block data ever touches it.
#
# Enabled when env VISOLD_STORAGE=pgx (default) and all required Python deps
# are installed.  The PGX RocksDB layer supports either the legacy
# ``python-rocksdb`` binding or the maintained ``rocksdict`` binding.
# ``rocksdict`` is the preferred path on modern Linux distributions because
# the legacy binding is tied to older RocksDB APIs.
#
#     pip install rocksdict asyncpg redis msgpack
#     # or, where a compatible legacy binding is available:
#     pip install python-rocksdb asyncpg redis msgpack
#
# Fallback: VISOLD_STORAGE=sqlite — legacy single-file DB.
# ═════════════════════════════════════════════════════════════════════════════
_PGX_IMPORT_ERROR: Optional[str] = None
_rocksdb = None
_rocksdict = None
_asyncpg = None
_redis = None
_msgpack = None


def _import_pgx_deps() -> None:
    global _rocksdb, _rocksdict, _asyncpg, _redis, _msgpack, _PGX_IMPORT_ERROR
    errors = []
    try:
        import rocksdb as _r  # type: ignore
        _rocksdb = _r
    except Exception as exc:
        errors.append(f"rocksdb={exc!r}")
    try:
        import rocksdict as _rd  # type: ignore
        _rocksdict = _rd
    except Exception as exc:
        errors.append(f"rocksdict={exc!r}")
    try:
        import asyncpg as _a  # type: ignore
        _asyncpg = _a
    except Exception as exc:
        errors.append(f"asyncpg={exc!r}")
    try:
        import redis as _rds  # type: ignore
        _redis = _rds
    except Exception as exc:
        errors.append(f"redis={exc!r}")
    try:
        import msgpack as _mp  # type: ignore
        _msgpack = _mp
    except Exception as exc:
        errors.append(f"msgpack={exc!r}")

    rocks_ok = _rocksdb is not None or _rocksdict is not None
    required_ok = rocks_ok and _asyncpg is not None and _redis is not None and _msgpack is not None
    if not required_ok:
        _PGX_IMPORT_ERROR = "; ".join(errors) or "required PGX dependencies are unavailable"


_import_pgx_deps()
_PGX_AVAILABLE = (_rocksdb is not None or _rocksdict is not None) and _asyncpg is not None and _redis is not None and _msgpack is not None

# Preserve the distinction between an explicit backend request and automatic
# backend selection.  An explicit VISOLD_STORAGE=pgx request must never be
# silently downgraded to SQLite.
_STORAGE_BACKEND_REQUESTED = os.environ.get("VISOLD_STORAGE")
_STORAGE_BACKEND = _STORAGE_BACKEND_REQUESTED or ("pgx" if _PGX_AVAILABLE else "sqlite")


# ── Optional high-performance compression (zstandard) ─────────────────────────
try:
    import zstandard as _zstd_mod
    _ZSTD_AVAILABLE = True
except ImportError:
    _ZSTD_AVAILABLE = False


# ── Optional LevelDB support (pip install plyvel) ─────────────────────────────
# Used for high-performance block storage when the chain grows to millions of
# blocks and SQLite becomes a read/write bottleneck.
try:
    import plyvel as _plyvel
    _LEVELDB_AVAILABLE = True
except ImportError:
    _LEVELDB_AVAILABLE = False


# ── Optional RocksDB support ─────────────────────────────────────────────────
# ``_ROCKSDB_AVAILABLE`` intentionally means the legacy python-rocksdb API is
# available because visold.storage.block_database.py still targets that API.
# The PGX backend separately supports ``rocksdict`` through _ROCKSDICT_AVAILABLE.
_ROCKSDB_AVAILABLE = _rocksdb is not None
_ROCKSDICT_AVAILABLE = _rocksdict is not None


# ── Optional: numpy (required for GPU mining batches) ─────────────────────────
try:
    import numpy as _np
    _NUMPY_AVAILABLE = True
except ImportError:
    _np = None  # type: ignore[assignment]
    _NUMPY_AVAILABLE = False


# ── Optional: CUDA GPU mining (pip install pycuda) ────────────────────────────
# pycuda is NOT imported at module load — importing it calls cuInit() which
# would crash on machines without an NVIDIA driver.  Instead we detect whether
# the package is installed here and perform the full driver init lazily inside
# ParallelMiner.initialize() only when GPU mining is actually requested.
try:
    import importlib.util as _il_util
    _il_util.find_spec("pycuda")
    _CUDA_AVAILABLE = True
except Exception:
    _CUDA_AVAILABLE = False


# ── Optional: OpenCL GPU mining (pip install pyopencl) ───────────────────────
# BUG-FIX: _il may be undefined if the CUDA try-block above raised an exception
# before `import importlib as _il` succeeded. Re-import here unconditionally.
try:
    import importlib.util as _il_util
    _il_util.find_spec("pyopencl")
    _OPENCL_AVAILABLE = True
except Exception:
    _OPENCL_AVAILABLE = False


# ── Cython: pure-Python-mode shim ─────────────────────────────────────────────
# When the file is compiled with Cython, `import cython` gives real C-level
# type objects and decorators that the compiler understands.
# When run as plain Python (not compiled), we provide a lightweight no-op shim
# so every @cython.ccall / @cython.locals / cython.ulonglong reference is valid
# Python without any behaviour change.
try:
    import cython as cython
    _CYTHON_COMPILED: bool = cython.compiled  # True only in .so / .pyd builds
except ImportError:
    class _CythonShim:                        # pragma: no cover
        """No-op stand-in for the cython module when Cython is not installed."""
        compiled   = False
        # C integer / float type aliases — resolve to Python builtins at runtime
        ulonglong  = int     # unsigned long long  (64-bit)
        longlong   = int     # long long           (64-bit signed)
        uint       = int     # unsigned int        (32-bit)
        ulong      = int     # unsigned long       (platform-width)
        Py_ssize_t = int     # ssize_t             (pointer-width signed)
        double     = float
        bint       = bool

        # Decorators — all pass-through at runtime; Cython uses them at compile time
        @staticmethod
        def cfunc(f):            return f
        @staticmethod
        def ccall(f):            return f
        @staticmethod
        def nogil(f):            return f
        @staticmethod
        def inline(f):           return f
        @staticmethod
        def locals(**_kw):       return lambda f: f
        @staticmethod
        def wraparound(_val):    return lambda f: f  # per-function override
        @staticmethod
        def cast(_typ, val):     return val
        @staticmethod
        def declare(*_a, **_kw): pass

    cython = _CythonShim()
    _CYTHON_COMPILED = False


# ─────────────────────────────────────────────────────────────────────────────
# MANDATORY: audited cryptography library (pip install cryptography)
#            Node will refuse to start if this library is absent.
# ─────────────────────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256K1, EllipticCurvePrivateKey, EllipticCurvePublicKey,
        ECDH, generate_private_key, derive_private_key,
        EllipticCurvePublicNumbers, EllipticCurvePrivateNumbers
    )
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature, encode_dss_signature, Prehashed
    )
    from cryptography.hazmat.primitives import hashes as _hashes, serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    # TLS certificate generation (x509) — uses the same already-required library
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID as _NameOID
    _CRYPTO_LIB = True
except ImportError:
    # ── PRODUCTION HARD STOP ─────────────────────────────────────────────────
    # The `cryptography` library is a mandatory runtime dependency.
    # Running without it would fall back to trivially-broken XOR "encryption",
    # exposing every private key on the network.  We refuse to start instead.
    print(
        "\n╔══════════════════════════════════════════════════════════════╗\n"
        "║  FATAL: Required cryptographic library is not installed.     ║\n"
        "║                                                              ║\n"
        "║  Run:  pip install cryptography                              ║\n"
        "║                                                              ║\n"
        "║  Visold will NOT start without this library.  Operating      ║\n"
        "║  in 'low-security mode' is not acceptable for a financial    ║\n"
        "║  application — all private keys would be trivially exposed.  ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n"
    )
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# OPTIONAL: Argon2id KDF (pip install argon2-cffi)
# Preferred KDF for keystore and account-credential derivation when available.
# Gracefully degrades to PBKDF2-HMAC-SHA256 (260 000 iterations) if absent,
# so the node runs on constrained devices (Termux, low-RAM VMs) without
# modification.  Argon2id is memory-hard (64 MB default) and resistant to
# GPU/ASIC brute-force attacks far beyond what PBKDF2 can achieve.
# ─────────────────────────────────────────────────────────────────────────────
try:
    from argon2.low_level import hash_secret_raw, Type as _Argon2Type
    _ARGON2_AVAILABLE = True
except ImportError:
    _ARGON2_AVAILABLE = False
