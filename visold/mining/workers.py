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
"""visold.mining.workers

Original section: SECTION 14A: PARALLEL MINING ENGINE  (CPU multi-thread + GPU CUDA / OpenCL)

Origin: visold_vsd_.py L38545-38582, L38587-38729, L38737-38794
"""

import threading

from visold.kernel.compat import cython


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 14A: PARALLEL MINING ENGINE  (CPU multi-thread + GPU CUDA / OpenCL)
# ─────────────────────────────────────────────────────────────────────────────
#
# Backend priority (auto-detected at first mine() call):
#
#   1. CUDA   — NVIDIA GPUs via pycuda.   pip install pycuda
#               Thousands of SHA-256 evaluations per GPU warp in parallel.
#               Enable:  VISOLD_MINING_GPU=1   (VISOLD_GPU_DEVICE=N for device)
#
#   2. OpenCL — AMD / Intel / NVIDIA via pyopencl.  pip install pyopencl
#               Same parallel SHA-256 approach; cross-vendor support.
#
#   3. CPU threads — always available, zero extra dependencies.
#               hashlib.sha256() releases Python's GIL during the C-level
#               hash computation, so N threads truly run in parallel on
#               N CPU cores.   Default: all logical cores (os.cpu_count()).
#               Override: VISOLD_MINING_THREADS=N
#
# NOTE ON GPU HASH FUNCTION
# ─────────────────────────
# The canonical block hash is SHA-256( JSON.dumps(header, sort_keys=True) ).
# GPU kernels use SHA-256 of a compact 136-byte binary header to avoid
# JSON parsing on device.  When the GPU signals a candidate nonce the CPU
# re-checks it with the canonical JSON hash before accepting the block.
# At low-medium difficulty (network bootstrap) almost every candidate passes;
# at high difficulty the GPU still finds binary-valid candidates very quickly,
# and the JSON re-check rarely rejects more than a handful.
# ─────────────────────────────────────────────────────────────────────────────

# ── Cython-optimised mining template builder ──────────────────────────────────

def _build_mine_template(header_base: dict) -> str:
    """
    Pre-render the block header JSON into a Python format string with two %d
    placeholders — one for nonce, one for timestamp.

    This eliminates json.dumps(dict) + str(nonce).encode() from the inner
    mining loop entirely.  Only a format-string substitution and
    hashlib.sha256() remain — the two cheapest possible operations.

    Called once per candidate block (not per nonce).

    Returns a str like:
      '{"difficulty":2.0,...,"nonce":%d,...,"timestamp":%d,...}'

    The inner loop then does:
      raw = (fmt % (nonce, local_ts)).encode('ascii')
    which is equivalent to — but 4-6× faster than:
      raw = json.dumps({**header_base, 'nonce': nonce,
                        'timestamp': local_ts}, sort_keys=True).encode()
    """
    import json as _j

    # Unique sentinels — large integers that cannot appear in any other header
    # field (hashes are hex strings, addresses start with 'VSD', etc.)
    _SN = 7_777_777_777_777_777_776   # nonce placeholder
    _ST = 7_777_777_777_777_777_775   # timestamp placeholder

    h = dict(header_base)
    h['nonce']     = _SN
    h['timestamp'] = _ST
    full = _j.dumps(h, sort_keys=True, default=str)

    sn, st = str(_SN), str(_ST)
    ni = full.index(sn)
    ti = full.index(st, ni + len(sn))

    # Replace both sentinels with %d — preserves exact key order and spacing
    return full[:ni] + '%d' + full[ni + len(sn):ti] + '%d' + full[ti + len(st):]


# ── Cython-typed inner mining worker (replaces _cpu_mine_thread) ──────────────

@cython.ccall
@cython.wraparound(False)
@cython.locals(
    nonce    = cython.ulonglong,
    step_c   = cython.ulonglong,
    local_ts = cython.ulonglong,
    min_c    = cython.ulonglong,
    tick     = cython.Py_ssize_t,
)
def _cy_mine_worker(fmt_template: str,
                    target_bytes: bytes,
                    initial_ts:   cython.ulonglong,
                    nonce_start:  cython.ulonglong,
                    nonce_step:   cython.ulonglong,
                    min_iters:    cython.ulonglong,
                    result:       list,
                    result_lock,
                    stop_flag,
                    max_hps_per_thread: float = 0.0,
                    throttle_batch:     int   = 0) -> None:
    """
    Cython-optimised inner mining loop.  Three concrete speedups over the old
    _cpu_mine_thread when compiled with Cython:

    1. Pre-serialised JSON template
       fmt_template % (nonce, ts)  replaces  json.dumps(dict, sort_keys=True)
       Eliminates Python dict allocation + JSON encoder overhead every nonce.

    2. Raw bytes target comparison
       digest_raw <= target_bytes  (C memcmp, 32 bytes)
       replaces  int(hexdigest, 16) <= target  (hex parse + 256-bit bigint cmp)
       Uses .digest() instead of .hexdigest() — one less hex encoding step.

    3. C-typed local variables via @cython.locals
       When compiled: nonce / step_c / local_ts / tick / min_c are machine-word
       unsigned long long / ssize_t C variables — zero Python object overhead,
       zero refcount updates, zero heap allocation per loop iteration.

    hashlib.sha256() releases Python's GIL during its C SHA-256 computation,
    so N threads calling this function simultaneously achieve true N-core
    parallelism regardless of whether Cython is compiled or not.

    Hashrate throttle (v7.6.0):
    ───────────────────────────
    When max_hps_per_thread > 0 and throttle_batch > 0, the worker hashes
    `throttle_batch` nonces and then sleeps the remainder of the time slice
    needed to keep its rate at most `max_hps_per_thread` hashes/second.  The
    sleep is computed from the wall-clock interval the batch actually took,
    so the average rate self-corrects against system jitter.

    Throttle is disabled (zero overhead) when either parameter is 0.  This
    preserves the legacy hot-path performance bit-for-bit when
    Config.HASHRATE_OPTIMIZATION_ENABLED is False.

    The throttle is LOCAL ONLY — it does not change which nonces are tried
    or what hash is produced for any given nonce, so it does not affect
    consensus or block validation in any way.
    """
    import hashlib as _hl, time as _t

    REFRESH  = 50_000          # re-read wall-clock every 50 k hashes
    nonce    = nonce_start
    step_c   = nonce_step
    local_ts = initial_ts
    min_c    = min_iters
    tick     = 0

    # Throttle setup — only active when both knobs are positive.
    #
    # Algorithm (v7.6.1 — fixes two leaks present in v7.6.0):
    #   1. The clock starts BEFORE the first hash, so the very first batch
    #      cannot escape unthrottled (which previously let a lucky early
    #      solve produce 2-second blocks even with a tight cap).
    #   2. The sleep duration is NOT capped at 0.5 s.  We instead use
    #      stop_flag.wait(timeout=...) which is fully responsive to
    #      shutdown signals while honouring whatever sleep duration the
    #      math demands.  Capping at 0.5 s leaked ~10-30% of throttle
    #      enforcement when the requested rate was very low relative to
    #      hardware speed.
    _throttle_active = (max_hps_per_thread > 0.0 and throttle_batch > 0)
    _batch_count     = 0
    _batch_started   = _t.time() if _throttle_active else 0.0
    _batch_target_secs = (float(throttle_batch) / max_hps_per_thread
                           if _throttle_active else 0.0)

    while not stop_flag.is_set():

        # ── Timestamp refresh (only advance forward, never regress MTP) ───
        if tick >= REFRESH:
            new_ts = cython.cast(cython.ulonglong, int(_t.time()))
            if new_ts > local_ts:
                local_ts = new_ts
            tick = 0

        # ── Hash  (GIL is released inside hashlib's C implementation) ────
        raw        = (fmt_template % (nonce, local_ts)).encode('ascii')
        digest_raw = _hl.sha256(raw).digest()     # 32 raw bytes — no hex step

        # ── Target check: bytes comparison == big-endian bigint comparison ─
        if digest_raw <= target_bytes and nonce >= min_c:
            with result_lock:
                if not result:                    # first thread to find wins
                    result.append((int(nonce), digest_raw.hex(), int(local_ts)))
                    stop_flag.set()
            return

        nonce += step_c
        tick  += 1

        # ── v7.6.0 Per-thread hashrate throttle ─────────────────────────
        # Pace ourselves so that this thread averages no more than
        # max_hps_per_thread hashes/second over each `throttle_batch`-sized
        # window.  Inactive when either knob is 0.
        #
        # v7.6.1 fix — sleep is no longer capped at 0.5 s.  We use
        # stop_flag.wait(timeout=_sleep_for) which is fully responsive to
        # shutdown signals (returns immediately when the flag is set), so
        # there is no need to cap the sleep duration.  The previous 0.5 s
        # cap silently leaked enforcement when very low rates were
        # requested relative to hardware speed.
        #
        # v7.6.2 — When stop_flag.wait() returns True (flag was set), it
        # could mean EITHER (a) shutdown OR (b) another worker found a
        # winning hash.  In case (b) we want to exit immediately too.
        # Either way, returning is correct.
        if _throttle_active:
            _batch_count += 1
            if _batch_count >= throttle_batch:
                _now = _t.time()
                _elapsed = _now - _batch_started
                if _elapsed < _batch_target_secs:
                    _sleep_for = _batch_target_secs - _elapsed
                    if _sleep_for > 0.0:
                        # stop_flag.wait returns True if the flag was set
                        # during the sleep — caller exits cleanly on the
                        # next loop iteration.  Fully responsive shutdown.
                        if hasattr(stop_flag, "wait"):
                            if stop_flag.wait(timeout=_sleep_for):
                                return
                        else:
                            _t.sleep(_sleep_for)
                _batch_count   = 0
                _batch_started = _t.time()


# ── Legacy single-thread worker (kept for fallback / testing) ─────────────────
# ── Module-level CPU thread worker ────────────────────────────────────────────
# Must be at module level (not a method) so it is easily referenceable, even
# though threading (not multiprocessing) is used here.

def _cpu_mine_thread(header_base: dict,
                     nonce_start: int,
                     nonce_step: int,
                     target: int,
                     min_iters: int,
                     result: list,
                     result_lock: threading.Lock,
                     stop_flag: threading.Event) -> None:
    """
    Single CPU mining thread — covers the nonce sub-range
        nonce_start, nonce_start+nonce_step, nonce_start+2*nonce_step, …

    hashlib.sha256() releases Python's GIL during its C-level computation.
    N threads running this function simultaneously therefore achieve genuine
    N-core parallelism without multiprocessing overhead.

    Args
    ────
    header_base  Block header dict with nonce field absent (worker sets it).
    nonce_start  First nonce for this thread.
    nonce_step   Stride (= total number of worker threads).
    target       256-bit integer PoW target.  Valid: int(hash,16) <= target.
    min_iters    Minimum nonces before a solution is accepted (anti-trivial).
    result       Shared list; winner appends (nonce, hex_hash, timestamp).
    result_lock  Mutex protecting the result list.
    stop_flag    threading.Event; set by winner or externally by MiningEngine.
    """
    import hashlib as _hl, json as _json, time as _t

    REFRESH = 50_000          # re-read wall-clock every 50 k hashes

    h        = dict(header_base)      # per-thread copy — no shared writes
    nonce    = nonce_start
    local_ts = h['timestamp']         # MTP-safe floor; only advance forward
    tick     = 0

    while not stop_flag.is_set():
        # ── Advance timestamp (never regress below MTP floor) ─────────────
        if tick >= REFRESH:
            new_ts = int(_t.time())
            if new_ts > local_ts:
                local_ts = new_ts
            tick = 0

        h['nonce']     = nonce
        h['timestamp'] = local_ts
        raw    = _json.dumps(h, sort_keys=True, default=str).encode()
        digest = _hl.sha256(raw).hexdigest()   # ← GIL released in C layer

        if int(digest, 16) <= target and nonce >= min_iters:
            with result_lock:
                if not result:                 # first thread to find a solution
                    result.append((nonce, digest, local_ts))
                    stop_flag.set()
            return

        nonce += nonce_step
        tick  += 1
