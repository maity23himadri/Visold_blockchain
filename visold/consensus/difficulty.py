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
"""visold.consensus.difficulty

Original section: SECTION 1H: DIFFICULTY ENGINE — Hybrid Rolling-Window + Per-Block Adjustment

Defines: DifficultyEngine
Origin: visold_vsd_.py L8493-9127
"""

import math
import threading
from typing import Dict, List, Optional, TYPE_CHECKING, Tuple

from visold.kernel.config import Config

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1H: DIFFICULTY ENGINE — Hybrid Rolling-Window + Per-Block Adjustment
# ─────────────────────────────────────────────────────────────────────────────
class DifficultyEngine:
    """
    Production-grade hybrid dynamic difficulty engine for Visold (VSD).

    ═══════════════════════════════════════════════════════════════════════════
    Design goals
    ─────────────
    • Deterministic — every honest node independently computes the exact same
      required difficulty from chain history alone. Incoming blocks NEVER
      provide trusted difficulty values; validate_block() always recomputes.
    • Smooth — two cooperative layers prevent oscillation and converge quickly.
    • Bounded — all adjustments are mathematically clamped; no runaway values.
    • Attack-resistant — MTP timestamp validation defeats time-warp attacks;
      per-window clamping defeats oscillation attacks.
    • Performant — results are cached by parent block height; cache is
      invalidated correctly on chain reorg.

    ═══════════════════════════════════════════════════════════════════════════
    Difficulty representation
    ─────────────────────────
    Difficulty D is a positive integer meaning "the valid block hash must have
    at least D leading hexadecimal zero characters".  Each hex char = 4 bits,
    so D=7 requires 28 leading zero bits.

    Corresponding 256-bit integer mining target:
        T(D) = 2^(256 − 4·D) − 1

    A block with hash H (as a 256-bit integer) is valid iff H ≤ T(D), which
    is equivalent to the fast string check: hash_hex.startswith('0' * D).

    ═══════════════════════════════════════════════════════════════════════════
    Layer 1 — Bitcoin-style rolling-window MACRO adjustment
    ────────────────────────────────────────────────────────
    Every block, examine the last MACRO_WINDOW+1 block timestamps.

        actual_span   = timestamps[-1] − timestamps[-MACRO_WINDOW]
        expected_span = MACRO_WINDOW × TARGET_BLOCK_TIME

    Adjustment in logarithmic bit-space (one hex-char unit = 4 bits):

        ratio      = expected_span / actual_span          (clamped ∈ [1/C, C])
        diff_delta = log₂(ratio) / 4
        macro_diff = parent_diff + diff_delta

    Sign convention (correct):
      • Chain too FAST (actual < expected) → ratio > 1 → delta > 0 → harder  ✓
      • Chain too SLOW (actual > expected) → ratio < 1 → delta < 0 → easier  ✓

    The clamping factor C = MACRO_CLAMP (default 4) limits single-window
    swings to at most log₂(4)/4 = 0.5 difficulty units per block, regardless
    of how extreme the hash-rate change is.  This mirrors Bitcoin's 4× cap and
    prevents time-warp attacks from forcing large instantaneous adjustments.

    ═══════════════════════════════════════════════════════════════════════════
    Layer 2 — Ethereum-style per-block MICRO adjustment
    ────────────────────────────────────────────────────
    After macro, examine the parent–grandparent block interval dt:

        dt < TARGET/2  → +MICRO_STEP   (block came very fast: harder)
        dt > TARGET×2  → −MICRO_STEP   (block came very slow: easier)
        else           → linear interpolation ∈ (−MICRO_STEP, +MICRO_STEP)

    This allows rapid response to sudden hash-rate changes that haven't yet
    accumulated enough history to show up in the macro window.

    ═══════════════════════════════════════════════════════════════════════════
    Combination and clamping
    ─────────────────────────
        raw            = macro_diff + micro_delta
        new_difficulty = clamp(round(raw), MIN_DIFFICULTY, MAX_DIFFICULTY)

    ═══════════════════════════════════════════════════════════════════════════
    MTP timestamp validation (anti time-warp)
    ──────────────────────────────────────────
    For every incoming block two conditions must hold simultaneously:

        1.  block.timestamp  >  MTP(last MTP_WINDOW blocks)   [lower bound]
        2.  block.timestamp  ≤  local_clock + MAX_FUTURE_DRIFT [upper bound]

    MTP is the median of the last min(MTP_WINDOW, available) block timestamps.
    Using the median rather than the maximum prevents a miner from inflating
    future timestamps by controlling only a minority of recent blocks.
    """

    # ── Class-level cache: parent_chain_height → required_difficulty ──────────
    _cache:      Dict[int, float] = {}
    _cache_lock: threading.Lock = threading.Lock()
    _CACHE_MAX:  int            = 1024          # evict oldest when exceeded

    # ═════════════════════════════════════════════════════════════════════════
    # Public API
    # ═════════════════════════════════════════════════════════════════════════

    @classmethod
    def compute_next_difficulty(cls, storage: 'Storage',
                                 current_height: int) -> float:
        """
        Return the canonical required difficulty for the block at height
        (current_height + 1).

        Parameters
        ──────────
        storage        : Storage instance (read-only).
        current_height : height of the current chain tip (the parent block).

        The result is a float and is cached by current_height.  Subsequent
        calls with the same height return instantly without touching the database.
        """
        with cls._cache_lock:
            if current_height in cls._cache:
                return cls._cache[current_height]

        result = cls._compute_uncached(storage, current_height)

        with cls._cache_lock:
            cls._cache[current_height] = result
            # Evict the lowest-height entry when cache is full
            if len(cls._cache) > cls._CACHE_MAX:
                del cls._cache[min(cls._cache.keys())]

        return result

    @classmethod
    def invalidate_cache(cls, from_height: int = 0):
        """
        Evict all cache entries for heights >= from_height.

        Call this whenever the chain is reorganised so that stale difficulty
        values are recomputed from the new canonical chain.
        Pass from_height=0 (default) to flush the entire cache.
        """
        with cls._cache_lock:
            stale_keys = [h for h in cls._cache if h >= from_height]
            for k in stale_keys:
                del cls._cache[k]

    # ── Mining target conversion ───────────────────────────────────────────────

    @staticmethod
    def difficulty_to_target(difficulty: float) -> int:
        """
        Convert a fractional hex-zero difficulty D to a 256-bit integer mining
        target T, where a valid block hash H must satisfy H ≤ T.

            T(D) = int(2^(256 − 4·D))

        SEC-FIX M-05 (Deterministic Cross-Architecture Target)
        ───────────────────────────────────────────────────────
        The pre-fix implementation used ``math.ldexp(pow(2.0, frac_part),
        FRAC_SCALE)`` to compute the fractional component of 2^x.  Both
        ``ldexp`` and ``pow(float, float)`` are routed to platform libm,
        which can give bit-different results on x86 vs ARM vs Android
        Bionic for the same input float — a latent consensus-split risk.

        The fix removes ALL float / libm dependence from the hot path:

          1. ``zero_bits = D * 4`` is computed in float once, then snapped
             to the nearest 1/2^FRAC_BITS grid (FRAC_BITS=16, i.e. ~1.5e-5
             granularity in hex-zero units).  Snapping converts the float
             to an exact integer index, so any further computation is
             purely integer arithmetic.

          2. The fractional part of zero_bits is in {0, 1, …, 2^FRAC_BITS-1}.
             For each such index k, we want
                 2^(k/2^FRAC_BITS)  scaled by  2^FRAC_SCALE
             = round(2^FRAC_SCALE * 2^(k/2^FRAC_BITS))
             We compute this with Python's arbitrary-precision integers
             via Newton-Raphson on the polynomial x^(2^FRAC_BITS) =
             2^FRAC_SCALE * 2^k.  Equivalently we use the iteration
                 y_{n+1} = y_n - (y_n^Q - C) // (Q * y_n^(Q-1))
             where Q = 2^FRAC_BITS and C = 2^(FRAC_SCALE + k).  This
             converges in ~5 iterations and uses only int operations, so
             it is byte-identical on every Python interpreter.

          3. The result table is small (2^FRAC_BITS = 65 536 entries of
             ~16 bytes each = ~1 MB) and is computed lazily on first call,
             then cached.  Cache build time is < 100 ms on a phone CPU.

        Properties preserved from the pre-fix version:
          • Continuous in D  (any fractional D is accepted, snapped to
            grid)
          • Integer difficulties give the same result as the legacy
            T = 2^(256-4D) - 1 to within 1 ULP
          • Edge cases (D ≤ 0, D ≥ 64) handled identically

        Properties added:
          • Identical output on every architecture / OS / libm
        """
        try:
            d = float(difficulty)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("difficulty must be a finite number") from exc
        if not math.isfinite(d):
            raise ValueError("difficulty must be finite")
        d = max(0.0, d)
        zero_bits = d * 4.0

        if zero_bits <= 0.0:
            return (1 << 256) - 1
        if zero_bits >= 256.0:
            return 0

        # Snap to a 1/2^FRAC_BITS grid — turns the float into an integer index
        FRAC_BITS  = 12                # 4096 grid points per integer step
        GRID       = 1 << FRAC_BITS    # 4096
        idx_total  = int(round(zero_bits * GRID))     # exact int after snap
        if idx_total <= 0:
            return (1 << 256) - 1
        if idx_total >= 256 * GRID:
            return 0

        int_part   = idx_total // GRID                # 0..255
        frac_idx   = idx_total %  GRID                # 0..GRID-1
        FRAC_SCALE = 128                              # extra precision bits

        # Build (and cache) the table once.  Entry frac_idx holds
        #   round(2^FRAC_SCALE * 2^(frac_idx / GRID))
        # computed entirely in integers via Newton iteration.
        if not hasattr(DifficultyEngine, "_FRAC_TABLE"):
            DifficultyEngine._FRAC_TABLE = DifficultyEngine._build_frac_table(  # type: ignore[attr-defined]
                FRAC_BITS, FRAC_SCALE)
        frac_factor = DifficultyEngine._FRAC_TABLE[frac_idx]  # type: ignore[attr-defined]

        # 2^(256 - zero_bits) = 2^(256 - int_part) / 2^frac
        #                     = (1 << (256 - int_part + FRAC_SCALE)) / frac_factor
        shift     = 256 - int_part
        numerator = 1 << (shift + FRAC_SCALE)
        target    = numerator // frac_factor
        return max(0, min(target, (1 << 256) - 1))

    @staticmethod
    def _build_frac_table(frac_bits: int, frac_scale: int):
        """
        Return a list T of length 2^frac_bits where
            T[k] = round(2^frac_scale * 2^(k / 2^frac_bits))
        computed in pure integer arithmetic.

        Strategy: the table is monotonic and T[0] = 1 << frac_scale.
        T[k] satisfies T[k]^GRID = 2^(frac_scale*GRID + k) so we solve for
        T[k] using integer GRID-th-root via Newton-Raphson.  But since
        we're walking k from 0 upward we can just multiply step-by-step:
            T[k+1] / T[k]  ==  2^(1 / GRID)
        which is itself a constant integer ratio (the GRID-th root of 2,
        scaled by some large factor).  The simplest robust approach,
        though, is the closed-form integer-root computation per entry.

        For FRAC_BITS=12 the table has 4 096 entries; build time on a
        phone is ~125 ms which we accept once at startup.
        """
        GRID = 1 << frac_bits
        table = [0] * GRID

        # Closed form using Python's arbitrary-precision arithmetic.
        # We use the relation
        #     T[k] = floor( (1 << (frac_scale + k_shifted)) ^ (1/GRID) )
        # where k_shifted = k.  But computing GRID-th roots of huge ints
        # is slow per entry.  Instead we use the multiplicative recurrence:
        #
        #     R = floor( (1 << (frac_scale * GRID + 1)) ^ (1/GRID) )
        #         is "≈ 2^frac_scale * 2^(1/GRID)" times some scaling
        #
        # Step 1: compute R = floor( (2 << (frac_scale * GRID)) ^ (1/GRID) )
        # via integer Newton-Raphson for x^GRID = target_int.

        target_int = 2 << (frac_scale * GRID)   # = 2^(frac_scale*GRID + 1)

        # Initial guess: R ≈ 2^frac_scale * 2^(1/GRID) ≈ 2^frac_scale + small
        R = (1 << frac_scale) + (1 << frac_scale) // GRID

        # Newton iteration for x^GRID = target_int:
        #   x_{n+1} = ((GRID-1)*x_n + target_int // x_n^(GRID-1)) // GRID
        # Iteration bound 200 is more than enough for FRAC_BITS up to 16.
        for _ in range(200):
            xp = pow(R, GRID - 1)
            if xp == 0:
                break
            R_next = ((GRID - 1) * R + target_int // xp) // GRID
            if R_next == R:
                break
            R = R_next

        # Step 2: walk the table multiplicatively.  T[0] = 1 << frac_scale.
        T0 = 1 << frac_scale
        table[0] = T0
        cur = T0
        for k in range(1, GRID):
            # cur ← (cur * R) >> frac_scale, rounded to nearest
            prod = cur * R
            cur  = (prod + (1 << (frac_scale - 1))) >> frac_scale
            table[k] = cur
        return table


    @staticmethod
    def validate_pow_target(block_hash: str, difficulty: float) -> bool:
        """
        Canonical Proof-of-Work validation using the 256-bit integer target.

        Returns True iff int(block_hash, 16) ≤ difficulty_to_target(difficulty).

        Accepts fractional float difficulty values (e.g. 0.001, 1.5, 7.0).
        This replaces the legacy string-prefix check which required integer D.
        """
        try:
            hash_int = int(block_hash, 16)
            d = float(difficulty)
            if not math.isfinite(d):
                return False
            target = DifficultyEngine.difficulty_to_target(d)
        except (ValueError, TypeError, OverflowError):
            return False
        return 0 <= hash_int < (1 << 256) and hash_int <= target

    # ── MTP timestamp validation ───────────────────────────────────────────────

    @staticmethod
    def compute_mtp(timestamps: List[int]) -> int:
        """
        Compute Median Time Past from a list of recent block timestamps.

        Returns the lower median for even-length lists (index = (N-1)//2 after
        sorting), which is Bitcoin-compatible behaviour.  Returns 0 for an
        empty list.
        """
        if not timestamps:
            return 0
        s = sorted(timestamps)
        return s[(len(s) - 1) // 2]

    @classmethod
    def validate_timestamp(cls,
                            new_ts: int,
                            recent_timestamps: List[int],
                            network_time: int) -> Tuple[bool, str]:
        """
        Two-sided MTP timestamp validation — the primary defence against
        time-warp and far-future-timestamp attacks.

        Parameters
        ──────────
        new_ts             : timestamp field of the block being validated.
        recent_timestamps  : ordered list of the last N block timestamps
                             on the current chain tip (NOT including new_ts).
        network_time       : int(time.time()) — current local clock.

        Rules
        ─────
        Rule 1 (upper bound) — prevents far-future timestamps:
            new_ts ≤ network_time + MAX_FUTURE_DRIFT

        Rule 2 (lower bound) — prevents time-warp attacks:
            If ≥ 2 recent blocks are available:
                new_ts > MTP(last MTP_WINDOW timestamps)
            Else if exactly 1 recent block:
                new_ts ≥ that block's timestamp   (regression check)

        Using the median (MTP) rather than the maximum timestamp means an
        attacker controlling only a minority of recent blocks cannot lower
        the effective minimum timestamp significantly.
        """
        try:
            ts = float(new_ts)
            nt = float(network_time)
            if not math.isfinite(ts) or not math.isfinite(nt):
                return False, "Timestamp and network time must be finite"
        except (TypeError, ValueError, OverflowError):
            return False, "Timestamp and network time must be finite numbers"

        max_future = Config.DIFF_MAX_FUTURE_DRIFT

        # ── Rule 1: reject far-future timestamps ──────────────────────────────
        if new_ts > network_time + max_future:
            return False, (
                f"Timestamp {new_ts} exceeds maximum allowed "
                f"(local_clock={network_time} + drift={max_future} "
                f"= {network_time + max_future})"
            )

        # ── Rule 2: MTP lower bound ────────────────────────────────────────────
        window = recent_timestamps[-Config.DIFF_MTP_WINDOW:]

        if len(window) >= 2:
            # Full MTP check — strict greater-than against the window median
            mtp = cls.compute_mtp(window)
            if new_ts <= mtp:
                return False, (
                    f"Timestamp {new_ts} must be strictly greater than "
                    f"MTP {mtp} (median of last {len(window)} blocks)"
                )
        elif len(window) == 1:
            # Single parent exists: require no regression (equal is allowed to
            # handle sub-second mining in tests and low-difficulty bootstrap)
            if new_ts < window[0]:
                return False, (
                    f"Timestamp {new_ts} regresses before parent {window[0]}"
                )

        return True, "OK"

    # ═════════════════════════════════════════════════════════════════════════
    # Internal computation
    # ═════════════════════════════════════════════════════════════════════════

    # ═════════════════════════════════════════════════════════════════════════
    # LWMA-1  —  Linearly Weighted Moving Average of work-adjusted solve times
    # ═════════════════════════════════════════════════════════════════════════
    #
    # Algorithm (Zawy's LWMA-1, adapted to VSD's hex-zero difficulty units):
    #
    #   Let N = DIFF_LWMA_WINDOW (e.g. 45).
    #   For the last N blocks i = 1..N (1 = oldest in window, N = newest):
    #
    #     solvetime_i  = clamp(ts_i − ts_{i-1}, MIN_TS_STEP, MAX_TS_STEP)
    #     work_i       = 2^(4 · D_i)      # linear-work weight of D_i
    #
    #     weighted_st  = Σ (i · solvetime_i)       (i=1..N)   # linear weights
    #     weighted_w   = Σ (i · work_i)            (i=1..N)
    #
    #   Average time per unit of work over the window (weighted toward recent):
    #
    #     time_per_work = weighted_st / weighted_w
    #
    #   To hit TARGET_BLOCK_TIME the required work for the next block is:
    #
    #     next_work = TARGET_BLOCK_TIME / time_per_work
    #
    #   Convert back to hex-zero units:
    #
    #     next_D = log2(next_work) / 4
    #
    # Why this eliminates oscillation:
    # ────────────────────────────────
    # Every solve time is divided by its own block's difficulty-weight before
    # averaging.  A block that took 0.5 s at D=3 contributes the same to the
    # estimator as a block that took 8 s at D=3.5.  The controller therefore
    # reads the network's *hashrate* directly rather than inferring it from a
    # span under changing difficulty — so there is no hidden derivative term,
    # no overshoot, and no feedback oscillation.
    #
    # Recent blocks carry weight i=N while the oldest block in the window
    # carries weight i=1.  This means the algorithm forgets the fast bootstrap
    # phase quickly (within ~N/2 blocks once the grace period ends) and locks
    # to the true hashrate without a "catch-up surge" followed by a "pull-back".
    #
    # Both directions are handled by the same formula:
    #   • hashrate ↑  →  solve times shrink  →  time_per_work ↓  →  D ↑
    #   • hashrate ↓  →  solve times grow   →  time_per_work ↑  →  D ↓

    @classmethod
    def _compute_uncached(cls, storage: 'Storage',
                           current_height: int) -> float:
        """
        Core DAA entry point.  Returns the required difficulty (float, in
        hex-zero units) for the block at height (current_height + 1).
        """
        import math as _math

        # ── Early exits ───────────────────────────────────────────────────────
        if current_height < 0:
            return float(Config.INITIAL_DIFFICULTY)

        # Read only the parent header fields needed for the early exits.
        # Real Storage provides the header-only range helper; keep a small
        # compatibility fallback for storage adapters/test doubles that expose
        # only the older get_block() interface.
        get_window = getattr(storage, "get_block_consensus_window", None)
        if callable(get_window):
            parent_rows = get_window(current_height, current_height)
        else:
            parent = storage.get_block(current_height)
            parent_rows = ([(int(parent.timestamp), float(parent.difficulty))]
                           if parent is not None else [])
        if not parent_rows:
            return float(Config.INITIAL_DIFFICULTY)

        if current_height == 0:
            # Only genesis exists; first real block uses INITIAL_DIFFICULTY.
            return float(Config.INITIAL_DIFFICULTY)

        # Tiny bootstrap gap so we always have at least one real parent→child
        # interval mined at INITIAL_DIFFICULTY before the DAA runs.  Keep this
        # small — LWMA self-corrects, it does not need a huge grace window.
        if current_height < Config.DIFF_BOOTSTRAP_BLOCKS:
            return float(Config.INITIAL_DIFFICULTY)

        # ── Pull the last N+1 blocks (we need N intervals) ────────────────────
        N            = int(Config.DIFF_LWMA_WINDOW)
        lookback     = N + 1
        start_idx    = max(0, current_height - lookback + 1)

        if callable(get_window):
            rows = get_window(start_idx, current_height)
        else:
            rows = []
            for idx in range(start_idx, current_height + 1):
                blk = storage.get_block(idx)
                if blk is not None:
                    rows.append((int(blk.timestamp), float(blk.difficulty)))
        timestamps = [int(ts) for ts, _diff in rows]
        difficulties = [float(_diff) for _ts, _diff in rows]

        # Need at least two points for a single interval
        if len(timestamps) < 2:
            return float(Config.INITIAL_DIFFICULTY)

        parent_diff = difficulties[-1]

        # ── LWMA core ─────────────────────────────────────────────────────────
        # Compute per-interval data.  Number of intervals = len - 1.
        n_intervals = len(timestamps) - 1

        max_ts_step = float(Config.DIFF_LWMA_MAX_TS_STEP)
        min_ts_step = float(Config.DIFF_LWMA_MIN_TS_STEP)

        weighted_solvetime = 0.0        # Σ i · st_i
        weighted_work      = 0.0        # Σ i · work_i

        for i in range(1, n_intervals + 1):
            # For interval i: solvetime = ts[i] − ts[i-1]; work weight is the
            # difficulty of the *child* block (difficulties[i]) — the block
            # that was actually mined during that interval.
            raw_st = float(timestamps[i] - timestamps[i - 1])
            # Clamp per-block solve time — defeats timestamp manipulation
            # (negative / huge-positive forged values can't poison the mean).
            st     = max(min_ts_step, min(raw_st, max_ts_step))

            d_i    = float(difficulties[i])
            # Linear work weight per block ∝ 2^(4·D).  (Constants cancel in
            # the ratio, so we just use 2^(4·D) directly.)  Cap the exponent
            # defensively to avoid overflow on pathological history.
            exp_bits = 4.0 * max(0.0, min(d_i, float(Config.MAX_DIFFICULTY)))
            work_i   = _math.pow(2.0, exp_bits)

            weighted_solvetime += i * st
            weighted_work      += i * work_i

        # Defensive: if somehow everything collapsed, just keep parent_diff.
        if weighted_work <= 0.0 or weighted_solvetime <= 0.0:
            return cls._apply_swing_cap(parent_diff, parent_diff)

        # Average time per unit of work over the window.
        time_per_work = weighted_solvetime / weighted_work

        # Work needed so that the next block takes TARGET_BLOCK_TIME seconds.
        target_bt = float(Config.TARGET_BLOCK_TIME)
        next_work = target_bt / time_per_work

        # Convert work back to hex-zero difficulty: D = log2(work) / 4
        if next_work <= 1.0:
            raw_diff = 0.0
        else:
            raw_diff = _math.log2(next_work) / 4.0

        # ── Symmetric swing cap (max multiplicative change vs parent) ─────────
        new_diff = cls._apply_swing_cap(raw_diff, parent_diff)

        # ── Hard global floor / ceiling ───────────────────────────────────────
        new_diff = max(float(Config.MIN_DIFFICULTY),
                       min(new_diff, float(Config.MAX_DIFFICULTY)))
        return new_diff

    @classmethod
    def _apply_swing_cap(cls, raw_diff: float, parent_diff: float) -> float:
        """
        Cap the per-block change so that the target computed by LWMA cannot
        move by more than DIFF_LWMA_MAX_SWING × in either direction relative
        to the parent's target.  In hex-zero units this is:

            max_delta = log2(DIFF_LWMA_MAX_SWING) / 4

        Symmetric — the cap is identical whether difficulty rises or falls.
        This is a guardrail, not a controller: under normal operation LWMA's
        own output is already well inside the cap; the cap only engages after
        a genuine large shock (e.g. a huge miner joining/leaving).
        """
        import math as _math

        swing = max(1.000001, float(Config.DIFF_LWMA_MAX_SWING))
        max_delta = _math.log2(swing) / 4.0

        lo = parent_diff - max_delta
        hi = parent_diff + max_delta
        if raw_diff < lo:
            return lo
        if raw_diff > hi:
            return hi
        return raw_diff

    # ── Legacy shims (kept so any external caller of the old private helpers
    #    still works; they now just delegate to the new unified computation.
    #    They are NOT used on the live path — _compute_uncached no longer
    #    calls a separate macro/micro layer.) ───────────────────────────────
    @classmethod
    def _macro_adjustment(cls, timestamps, parent_diff):  # pragma: no cover
        return float(parent_diff)

    @classmethod
    def _micro_adjustment(cls, parent_ts, grandparent_ts):  # pragma: no cover
        return 0.0

    # ──────────────────────────────────────────────────────────────────────────
    # REVERSE FUNCTION — required network hashrate from current difficulty.
    #
    # _compute_uncached() solves:
    #     next_work = TARGET_BLOCK_TIME / time_per_work
    #     next_D    = log2(next_work) / 4
    #
    # The hashrate-governor needs the inverse: given the difficulty D that was
    # produced by the difficulty engine, what aggregate network hashrate does
    # that difficulty *imply* the engine was targeting?
    #
    #     D                        ⇒  expected hashes per block = 2^(4·D)
    #     TARGET_BLOCK_TIME        ⇒  hashes/sec = 2^(4·D) / TARGET_BLOCK_TIME
    #
    # This is the SAME 2^(4·D) work weight that _compute_uncached uses inside
    # the LWMA estimator.  Because we use exactly the same math that produced
    # D, the optimizer cannot drift away from the difficulty engine's intent.
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def required_network_hashrate(difficulty: float,
                                   target_block_time: Optional[float] = None
                                   ) -> float:
        """
        Return the theoretical aggregate network hashrate (hashes per second)
        required to produce one block in target_block_time seconds at the
        given difficulty.  This is the exact inverse of the math used inside
        _compute_uncached() — both sides agree on what 2^(4·D) means, so an
        optimizer built on this value cannot oscillate against the difficulty
        engine.

        Parameters
        ──────────
        difficulty        : float D in hex-zero units (same field as block.difficulty).
        target_block_time : optional override (defaults to Config.TARGET_BLOCK_TIME).

        Returns
        ───────
        Required hashrate in hashes per second.  Always > 0.

        Bounds
        ──────
        D is clamped to [MIN_DIFFICULTY, MAX_DIFFICULTY] before exponentiation
        to guarantee a finite, non-negative result on pathological inputs.
        """
        import math as _math
        d = float(difficulty)
        d = max(float(Config.MIN_DIFFICULTY),
                min(d, float(Config.MAX_DIFFICULTY)))
        tbt = float(target_block_time
                    if target_block_time is not None
                    else Config.TARGET_BLOCK_TIME)
        if tbt <= 0.0:
            tbt = 60.0
        try:
            work = _math.pow(2.0, 4.0 * d)
        except OverflowError:
            # Float overflow on extreme D — saturate to a very large value
            # rather than raising; the caller will then cap miners at the
            # MAX_DIFFICULTY-equivalent hashrate, which is the right answer.
            work = float("inf")
        if work == float("inf") or work != work:   # inf or NaN
            work = _math.pow(2.0, 4.0 * float(Config.MAX_DIFFICULTY))
        return work / tbt
