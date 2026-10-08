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
"""visold.network.udp.latency


Defines: LatencyTracker
Origin: visold_vsd_.py L2468-2547
"""

import threading
import time
from typing import Dict, List, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# v7.5.0-OPT LatencyTracker — Network-Aware Block Sizing
#
# Maintains a lightweight moving average of Round-Trip Times (RTT) across all
# connected UDP peers.  The underlying per-session SRTT values are computed
# inside _UDPWindow._update_rtt() following RFC 6298 (Jacobson/Karels); this
# tracker simply aggregates them into a single network-wide "slow/fast" signal
# that the consensus layer can consult when deciding the next block size.
#
# IMPORTANT — scope of this tracker:
#   • Purely ADVISORY.  It never alters consensus rules.
#   • Does NOT touch TARGET_BLOCK_TIME (60 s — fixed).
#   • Does NOT touch difficulty adjustment (handled by DifficultyEngine).
#   • Only influences the non-consensus MAX block-byte cap used when building
#     the next candidate, so a slow network produces smaller blocks that still
#     propagate within the 60-second window.
# ─────────────────────────────────────────────────────────────────────────────
class LatencyTracker:
    """
    Thread-safe network-wide RTT aggregator.

    The instantaneous SRTT (smoothed RTT) reported by each UDPSession's
    _UDPWindow is fed into this tracker via ``record_peer_rtt(addr, srtt)``.
    Callers query ``avg_rtt()`` to obtain the current network-wide mean.

    Rationale for a dedicated class (rather than just reading _srtt inline):
      • Encapsulates the aggregation policy (mean of per-peer SRTTs, with
        stale entries evicted).
      • Makes the "network is slow" signal testable in isolation.
      • Allows future upgrades (p95, EMA, etc.) without touching callers.
    """

    # Stale entries: a peer whose SRTT hasn't been refreshed for this many
    # seconds is dropped from the mean.  Keeps the signal responsive after
    # peer churn without adding per-sample TTL machinery.
    STALE_SECS = 120.0

    def __init__(self):
        self._lock   = threading.Lock()
        # addr (ip, port) -> (srtt_seconds, last_update_monotonic)
        self._peers: Dict[tuple, Tuple[float, float]] = {}

    def record_peer_rtt(self, addr: tuple, srtt: float) -> None:
        """Record (or refresh) the SRTT measurement for one peer.

        ``srtt`` is in seconds.  Non-positive or NaN values are ignored so a
        half-initialised window cannot poison the mean.
        """
        try:
            s = float(srtt)
        except (TypeError, ValueError):
            return
        if not (s > 0.0) or s != s:   # NaN check (NaN != NaN)
            return
        # Cap obviously-insane values (>60s RTT is pathological — a satellite
        # link is ~600 ms, a terrestrial slow link ~1-2 s).  Prevents one bad
        # peer from dragging the mean off a cliff.
        if s > 60.0:
            s = 60.0
        now = time.monotonic()
        with self._lock:
            self._peers[addr] = (s, now)

    def drop_peer(self, addr: tuple) -> None:
        """Remove a peer's contribution (called on disconnect)."""
        with self._lock:
            self._peers.pop(addr, None)

    def avg_rtt(self) -> float:
        """Return the mean fresh SRTT across peers in seconds.

        Returns 0.0 when no measurements are available — callers interpret
        0.0 as "no signal" and fall back to their normal sizing policy.
        """
        now = time.monotonic()
        cutoff = now - self.STALE_SECS
        vals: List[float] = []
        with self._lock:
            # Evict stale and collect fresh in one pass.
            dead = []
            for addr, (s, ts) in self._peers.items():
                if ts < cutoff:
                    dead.append(addr)
                else:
                    vals.append(s)
            for addr in dead:
                self._peers.pop(addr, None)
        if not vals:
            return 0.0
        return sum(vals) / len(vals)

    def peer_count(self) -> int:
        """Number of peers with a fresh measurement (for diagnostics)."""
        now = time.monotonic()
        cutoff = now - self.STALE_SECS
        with self._lock:
            return sum(1 for _, ts in self._peers.values() if ts >= cutoff)
