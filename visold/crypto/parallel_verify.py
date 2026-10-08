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
"""visold.crypto.parallel_verify

Original section: SECTION 1E3: STATE ENGINE — Single-Writer, Event-Driven State Machine

Origin: visold_vsd_.py L6757-6771, L6774-6795, L6801
"""

import hashlib
import threading
import concurrent.futures as _futures
import multiprocessing as _mp
from typing import Optional

from visold.crypto.ecc import ecdsa_verify, pub_from_hex, pub_to_address, sig_from_hex
from visold.kernel.logging_setup import log


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1E3: STATE ENGINE — Single-Writer, Event-Driven State Machine
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# TPS-OPT-1 — PARALLEL SIGNATURE VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────
# ECDSA signature verification is the single most CPU-intensive step in block
# validation.  Each tx.verify_signature() is independent of every other, making
# it embarrassingly parallel.  We maintain a lazily-initialised ProcessPool
# (one per node lifetime) sized to os.cpu_count() and fan out all non-coinbase
# verifications in a single map() call.
#
# The worker function (_par_verify_sig) lives at module level so it is
# pickle-safe for ProcessPoolExecutor.  It accepts only primitive types
# (strings + bytes) to minimise serialisation cost.
#
# Security: IDENTICAL checks to Transaction.verify_signature() — no logic
# change, only execution topology.  A single False result short-circuits the
# whole batch and rejects the block.
# ─────────────────────────────────────────────────────────────────────────────
_SIG_POOL: Optional[_futures.ProcessPoolExecutor] = None


_SIG_POOL_LOCK = threading.Lock()


def _get_sig_pool() -> _futures.ProcessPoolExecutor:
    """Lazily create and cache the process pool for signature verification."""
    global _SIG_POOL
    if _SIG_POOL is None:
        with _SIG_POOL_LOCK:
            if _SIG_POOL is None:
                n = max(2, (_mp.cpu_count() or 4))
                _SIG_POOL = _futures.ProcessPoolExecutor(
                    max_workers=n)
                log.info("SigPool: started %d workers for parallel "
                         "signature verification", n)
    return _SIG_POOL


def _par_verify_sig(pub_hex: str, sig_hex: str,
                    signing_bytes: bytes,
                    sender: Optional[str] = None,
                    legacy_signing_bytes: Optional[bytes] = None) -> bool:
    """Standalone worker — verifies one ECDSA signature.

    Must be a module-level function (picklable).  Re-imports are cached by the
    child-process interpreter, so the overhead is paid only once per worker.

    SENDER-BINDING FIX: when ``sender`` is supplied, the address derived from
    ``pub_hex`` must equal it — exactly the check Transaction.verify_signature()
    performs — so the parallel path can never accept a tx that the sequential
    path would reject.
    """
    try:
        pub = pub_from_hex(pub_hex)
        if sender is not None and pub_to_address(pub) != sender:
            return False
        sig = sig_from_hex(sig_hex)
        h = hashlib.sha256(signing_bytes).digest()
        if ecdsa_verify(pub, h, sig):
            return True
        if legacy_signing_bytes is not None:
            legacy_h = hashlib.sha256(legacy_signing_bytes).digest()
            return ecdsa_verify(pub, legacy_h, sig)
        return False
    except Exception:
        return False


# Threshold: when a block has fewer non-coinbase txs than this, the overhead
# of cross-process dispatch exceeds the parallelism gain — fall back to
# sequential verification.  Empirically tuned: 4 txs ≈ break-even on most HW.
_PAR_SIG_THRESHOLD = 4


def _par_verify_sig_batch(items) -> int:
    """Verify a batch of signatures inside one worker process.

    Returns the zero-based index of the first invalid item, or ``-1`` when
    every item passes.  The per-transaction verifier above is deliberately
    reused unchanged so this optimization changes only execution topology:
    there is no alternate consensus rule hidden in the batch path.

    The batch boundary removes one ProcessPool submission/result round-trip per
    transaction while preserving fail-closed behavior.  An invalid item still
    causes the worker to stop immediately at that item; a valid block requires
    every item in every batch to pass.
    """
    for index, item in enumerate(items):
        if not _par_verify_sig(*item):
            return index
    return -1
