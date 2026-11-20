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
"""visold.kernel.clock


Defines: NetworkClock
Origin: visold_vsd_.py L5671-5883, L5887
"""

import math
import threading
import time
from collections import deque
from typing import Optional

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics


# ─────────────────────────────────────────────────────────────────────────────
# FIX 8 — TIME / SYNCHRONIZATION CONSISTENCY MODEL
# ─────────────────────────────────────────────────────────────────────────────
class NetworkClock:
    """
    Network-adjusted clock that tracks observed block timestamps from peers
    to detect and compensate for local clock skew.

    Design
    ──────
    A node whose local clock runs ahead will mine blocks with future timestamps,
    causing them to be rejected by peers enforcing the MTP upper bound.  A node
    whose clock runs behind will produce blocks that appear older than the MTP
    lower bound, also causing rejections.

    This class maintains a sliding window of recent block timestamps observed
    from the network (both locally mined and received from peers).  It computes
    the median of those timestamps to form a "network time" estimate that is
    robust to outliers (up to 49% of recent blocks can have wrong timestamps
    without affecting the median).

    The network time is used in two places:
      1. As the `network_time` argument to DifficultyEngine.validate_timestamp()
         instead of raw time.time() — this makes MTP validation more robust
         under clock skew.
      2. To emit periodic drift warnings if the local clock diverges from the
         network median by more than Config.CLOCK_MAX_DRIFT_SECS.

    Thread safety: all methods are protected by a single lock.
    """

    def __init__(self):
        self._lock    = threading.Lock()
        self._samples: deque = deque(maxlen=Config.CLOCK_PEER_SAMPLE_SIZE)
        self._last_update: float = 0.0

    @staticmethod
    def _sanitize_timestamp(ts) -> Optional[int]:
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            return None
        if not math.isfinite(ts):
            return None
        ts_int = int(ts)
        if ts_int <= 0:
            return None
        return ts_int

    def record_block_timestamp(self, ts: int):
        """Record a block timestamp observed from the network or locally mined."""
        clean_ts = self._sanitize_timestamp(ts)
        if clean_ts is None:
            return
        with self._lock:
            self._samples.append(clean_ts)
        self._maybe_log_drift()

    def record_peer_timestamp(self, ts: int, trusted: bool = True):
        """VSD-M07 FIX: Record a peer-advertised timestamp.
        Only TRUST_LEVEL_HIGH peer timestamps are admitted to the clock sample.
        TRUST_LEVEL_LOW peers are excluded to prevent time-warp attacks."""
        if not trusted:
            return  # drop untrusted peer timestamps silently
        clean_ts = self._sanitize_timestamp(ts)
        if clean_ts is None:
            return
        with self._lock:
            self._samples.append(clean_ts)
        self._maybe_log_drift()

    def reset(self):
        """Clear recorded timestamp samples (e.g. on chain reset or tests)."""
        with self._lock:
            self._samples.clear()
            self._last_update = 0.0

    def network_time(self) -> int:
        """
        Return the best available estimate of current network time.

        BUG-FIX (sync-fix-7): The old logic used `latest_ts` (the most
        recently recorded BLOCK timestamp) as the network reference and
        returned it as 'now' when local_ts - latest_ts > DIFF_MAX_FUTURE_DRIFT.
        This is wrong in two scenarios that are both normal and common:

          Scenario A — fresh node syncing historical blocks:
            A peer sends blocks mined 9 hours ago.  apply_block feeds each
            block's timestamp into _samples.  latest_ts is now 9 hours in
            the past.  local_ts - latest_ts = 32833 > 7200 → old code
            returned latest_ts (9 hours ago) as 'now', making every
            subsequent timestamp validation and mining use a stale clock.
            Warning fires on EVERY block apply, flooding the log.

          Scenario B — chain idle for hours between mining sessions:
            Same outcome.  Local clock is correct; block timestamps are old.
            The 'ahead of network' warning is a false positive.

        Root cause: block timestamps are set AT MINE TIME.  They are
        always in the past relative to the current wall clock.  Using
        latest_ts as a proxy for 'current network time' only makes sense
        when blocks are arriving continuously (< a few minutes old).
        When the newest sample is old, the sample is stale and should
        be ignored — not used to override the local clock.

        Correct behaviour:
          - Always return local wall clock (time.time()) as 'now'.
          - Only warn/correct when the newest block timestamp is AHEAD
            of local time (genuine future-drift attack or a clock running
            behind) AND the sample is fresh (newest block < 2*MAX_DRIFT old).
          - Never substitute a stale block timestamp for the local clock.
        """
        with self._lock:
            samples = list(self._samples)
        local_ts = int(time.time())
        if len(samples) < 3:
            return local_ts
        # AUDIT-FIX-J2: previously used samples[-1] (the single
        # most-recently-appended entry) both for staleness and as the
        # actual network-time reference. Two distinct problems:
        #   (1) deque append order isn't guaranteed to match timestamp
        #       order — e.g. across a reorg a just-applied block can have
        #       an earlier timestamp than one already sitting in the
        #       deque — so "last appended" wasn't reliably "most recent".
        #   (2) the class docstring above and Config's own
        #       CLOCK_MAX_DRIFT_SECS / CLOCK_PEER_SAMPLE_SIZE comments
        #       describe a MEDIAN-based estimate specifically so a single
        #       sample being wrong can't move the result — but no median
        #       was ever computed, so one sample fully determined the
        #       corrected time fed into DifficultyEngine.validate_timestamp().
        # Fixed: max(samples) (a real value comparison, not append order)
        # for staleness, and a median for the correction reference.
        #
        # That median deliberately covers only the 3 most recent samples
        # (by value), not the full CLOCK_PEER_SAMPLE_SIZE=16 window.
        # Verified numerically before choosing this: at this chain's
        # TARGET_BLOCK_TIME=60s, a median over the full 16-sample window
        # sits ~450-500s in the past relative to the newest sample purely
        # from the window's own time-span — completely swamping
        # CLOCK_MAX_DRIFT_SECS=30 and making the correction effectively
        # unreachable even for a genuine, sustained clock skew. A
        # median-of-3 keeps that inherent bias to ~1 block interval
        # (~60s) — same order of magnitude as the documented 30s
        # threshold — while still requiring 2 of the 3 most recent
        # samples to agree, so a single outlier still can't unilaterally
        # control the result.
        import statistics
        max_allowed_ts = local_ts + Config.DIFF_MAX_FUTURE_DRIFT
        plausible = [s for s in samples if s <= max_allowed_ts]
        if len(plausible) < 3:
            return local_ts

        newest_ts = max(plausible)
        # If the newest block timestamp is itself very old (chain was idle
        # or we just replayed historical blocks), the sample window is
        # stale and tells us nothing about current network time.
        sample_age = local_ts - newest_ts
        if sample_age > Config.DIFF_MAX_FUTURE_DRIFT:
            # Stale sample — local clock is authoritative.  Do NOT warn;
            # this is expected during sync and after idle periods.
            return local_ts
        # Fresh sample window: check if local clock is BEHIND the network,
        # using the median of the most recent few samples so a single
        # outlier can't unilaterally trigger a correction.
        recent = sorted(plausible)[-3:]
        median_ts = int(statistics.median(recent))
        drift = local_ts - median_ts
        if drift < -Config.CLOCK_MAX_DRIFT_SECS:
            max_adj = int(getattr(
                Config, "CLOCK_MAX_FUTURE_ADJUSTMENT",
                Config.DIFF_MAX_FUTURE_DRIFT // 2,
            ))
            cap_ts = min(max_allowed_ts, local_ts + max_adj)
            corrected = min(median_ts + 1, cap_ts)
            log.warning(
                f"[NetworkClock] Local clock is {-drift}s behind network "
                f"(local={local_ts}, median_sample={median_ts}) "
                f"— correcting to {corrected}.")
            return corrected
        # Normal case: local clock is fine.
        return local_ts

    def _maybe_log_drift(self):
        """
        Periodically log a warning if the local clock diverges from network time.

        SKEW DETECTION LOGIC
        ────────────────────
        Block timestamps are set at mine/receive time, so the sample window
        always lags behind wall-clock time by up to (CLOCK_PEER_SAMPLE_SIZE ×
        block_interval) seconds on a slow chain.  Comparing the median of
        historical block timestamps directly against time.time() produces a
        false positive on every single-node chain.

        Correct approach: use the MOST RECENT block timestamp as the reference
        (it was set seconds ago), compare it against local time now.  A genuine
        clock skew means the most recent block's timestamp is significantly ahead
        of or behind the local clock — not that old blocks are old.

        We still keep a secondary median-staleness guard: if the newest sample
        is itself older than CLOCK_UPDATE_INTERVAL × 2, the chain has stalled
        and we skip the skew check entirely (different problem, not a clock bug).
        """
        now = time.time()
        with self._lock:
            if now - self._last_update < Config.CLOCK_UPDATE_INTERVAL:
                return
            self._last_update = now
            samples = list(self._samples)
        if len(samples) < 3:
            return
        local_ts = int(now)
        plausible = [s for s in samples if s <= local_ts + Config.DIFF_MAX_FUTURE_DRIFT]
        if len(plausible) < 3:
            return
        newest_ts = max(plausible)
        sample_age = local_ts - newest_ts
        if sample_age > Config.DIFF_MAX_FUTURE_DRIFT or sample_age < 0:
            metrics.set_gauge("clock_drift_secs", 0.0)  # stale or future — no meaningful drift
            return
        drift = sample_age
        metrics.set_gauge("clock_drift_secs", float(drift))
        if drift > Config.CLOCK_MAX_DRIFT_SECS:
            log.warning(
                f"CLOCK SKEW DETECTED: local clock diverges from most recent "
                f"block timestamp by {drift}s "
                f"(local={local_ts}, last_block_ts={newest_ts}). "
                f"This may cause block timestamp rejections and difficulty "
                f"miscalculation.  Check your system clock (NTP sync recommended).")
            metrics.inc("clock_skew_warnings")


# Global singleton network clock
network_clock = NetworkClock()
