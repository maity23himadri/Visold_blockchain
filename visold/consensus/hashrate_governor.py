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
"""visold.consensus.hashrate_governor

Original section: SECTION 1H-EXT — HASHRATE GOVERNOR (Optimized vs Actual Hashrate)

Defines: HashrateGovernor
Origin: visold_vsd_.py L9163-9512
"""

import threading
import time
from typing import Dict, List, Tuple

from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1H-EXT — HASHRATE GOVERNOR (Optimized vs Actual Hashrate)
#
# The HashrateGovernor maintains:
#   1. An estimate of local unthrottled hash throughput, measured from worker
#      hashes / active compute time (intentional governor sleeps are excluded).
#   2. Fresh authenticated miner-origin rate reports received directly or
#      through mesh gossip, with sender sequence replay protection.
#
# required_network_hashrate(D) remains the aggregate rate implied by difficulty
# and target block time. The local cap follows the requested policy:
#   • unmeasured startup -> temporarily unthrottled calibration;
#   • local actual < required -> cap at local actual (do not throttle a weak
#     device that cannot reach the target itself);
#   • otherwise C_i = H_actual_local × share_i / Σ share_j, with the result
#     floored to H_required and never above this node's actual capacity.
# Peer reports are direct-neighbour observations, NOT a network-wide census.
#
# IMPORTANT — CONSENSUS SAFETY:
# This class is a LOCAL ADVISOR ONLY.  It influences the local miner's hash
# rate (via short sleeps in the mining loop) but it does NOT touch:
#   • Block validation or PoW target computation
#   • Difficulty calculation (DifficultyEngine.compute_next_difficulty)
#   • Block timestamp, state_root, merkle_root, or any header field
#   • Reward distribution math (_distribute_rewards)
# Even if two nodes disagree about the cap (e.g. one runs an old version
# without the governor), every block they produce is still mutually
# validatable.  The cap is a courtesy throttle, not a consensus rule.
# ═════════════════════════════════════════════════════════════════════════════

class HashrateGovernor:
    """
    Compute this miner's local hashrate cap from its own measured H_actual
    and its weighted share among the currently observed miners. Each node
    computes its local cap independently; the sum of local caps is not
    guaranteed to equal the difficulty-derived network target.

    Thread safety: a single instance is owned by MiningEngine.  All public
    methods take an internal lock so reports from the network message loop
    and queries from the mining loop can run concurrently.
    """

    def __init__(self):
        self._lock                  = threading.Lock()
        self._peer_rates: Dict[str, Tuple[float, float]] = {}
        # peer_id -> (measured_unthrottled_hps, local_receive_time)
        # Sender metadata is kept separately so the legacy rate tuple remains
        # compatible with existing diagnostics/audit code.
        self._peer_report_meta: Dict[str, Tuple[float, int]] = {}

        # Local measurement state
        self._local_actual_hashrate = 0.0
        self._local_last_update     = 0.0

        # Cached cap from the most recent advise() call — exposed to status().
        self._last_required_total   = 0.0
        self._last_local_cap        = float("inf")

    # ─────────────────────────────────────────────────────────────────────
    # Inputs from the local mining loop
    # ─────────────────────────────────────────────────────────────────────
    def update_local_actual_hashrate(self, hps: float) -> None:
        """Record the latest estimate of unthrottled local hash throughput.

        This estimate is measured while the worker is actively hashing and
        excludes governor sleep time.  Negative or non-finite values are
        ignored; zero is reserved for the not-yet-calibrated state.
        """
        try:
            v = float(hps)
        except (TypeError, ValueError):
            return
        if v < 0.0 or v != v or v in (float("inf"), float("-inf")):
            return
        with self._lock:
            self._local_actual_hashrate = v
            self._local_last_update     = time.time()

    def get_local_actual_hashrate(self) -> float:
        with self._lock:
            return self._local_actual_hashrate

    def reset_local_measurement(self) -> None:
        """Reset only local calibration when a new mining session starts.

        Fresh peer reports stay cached until their own signed timestamps decay
        or expire; a previous session's local capacity must not be reused.
        """
        with self._lock:
            self._local_actual_hashrate = 0.0
            self._local_last_update = 0.0
            self._last_local_cap = float("inf")
            self._last_required_total = 0.0

    # ─────────────────────────────────────────────────────────────────────
    # Inputs from the network (gossip)
    # ─────────────────────────────────────────────────────────────────────
    def record_peer_hashrate(self, peer_id: str, hps: float,
                             reported_ts=None, sequence=None) -> bool:
        """Store a peer's measured-rate report with replay/staleness guards.

        Signed miner-origin reports carry a timestamp verified by the network
        layer; for sequenced reports the timestamp and sequence are preserved
        so relaying cannot make an old measurement fresh again. Legacy direct
        reports without a sequence remain supported and use local receive time
        for freshness when no origin timestamp metadata is available.
        """
        if not isinstance(peer_id, str) or not peer_id:
            return False
        try:
            v = float(hps)
        except (TypeError, ValueError):
            return False
        if v < 0.0 or v != v or v == float("inf") or v == float("-inf"):
            return False
        # Sanity cap — refuse absurd values (anti-spoofing).  2^48 H/s is
        # well above any plausible single-node hashrate but still finite.
        if v > (1 << 48):
            return False

        now = time.time()
        parsed_ts = None
        parsed_seq = None
        if reported_ts is not None:
            try:
                parsed_ts = float(reported_ts)
            except (TypeError, ValueError):
                return False
            if parsed_ts != parsed_ts or parsed_ts in (float("inf"), float("-inf")):
                return False
            # Allow modest mobile-device clock skew while rejecting reports
            # that are clearly replayed/stale or far in the future. Signed
            # reports are aged from this origin timestamp so relaying cannot
            # refresh an old measurement; legacy reports without a timestamp
            # fall back to local receive time.
            max_skew = max(float(Config.HASHRATE_PEER_TTL), 300.0)
            if abs(now - parsed_ts) > max_skew:
                return False
        if sequence is not None:
            if isinstance(sequence, bool):
                return False
            try:
                parsed_seq = int(sequence)
            except (TypeError, ValueError, OverflowError):
                return False
            if parsed_seq < 0 or str(parsed_seq) != str(sequence).strip():
                return False

        with self._lock:
            previous = self._peer_report_meta.get(peer_id)
            if parsed_seq is not None and previous is not None:
                previous_ts, previous_seq = previous
                if parsed_seq <= previous_seq:
                    return False
                # Signed rate reports are generated at the configured report
                # cadence. A higher sequence with an unchanged/backward wall
                # timestamp is not a fresh measurement and must not refresh it.
                if parsed_ts is not None and parsed_ts <= previous_ts:
                    return False
            self._peer_rates[peer_id] = (v, now)
            if parsed_seq is not None:
                self._peer_report_meta[peer_id] = (
                    parsed_ts if parsed_ts is not None else now, parsed_seq)
            elif parsed_ts is not None:
                # Legacy direct reports have no sequence number. Refresh their
                # origin timestamp without erasing a newer-version anti-replay
                # watermark. Never move that timestamp backwards.
                if previous is None:
                    self._peer_report_meta[peer_id] = (parsed_ts, -1)
                elif parsed_ts > previous[0]:
                    self._peer_report_meta[peer_id] = (parsed_ts, previous[1])
        return True

    def forget_peer(self, peer_id: str) -> None:
        """Drop a peer's cached hashrate and anti-replay state on disconnect."""
        with self._lock:
            self._peer_rates.pop(peer_id, None)
            self._peer_report_meta.pop(peer_id, None)

    # ─────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────
    def _live_peer_rates(self) -> List[float]:
        """Return a list of currently-effective peer hashrates with
        decay-on-silence applied.  Caller must hold _lock.

        v7.6.4 — A peer's claimed hashrate is no longer used at face value
        for the entire TTL window.  Instead the value decays linearly to
        zero between HASHRATE_FRESH_SECS and HASHRATE_FRESH_SECS +
        HASHRATE_DECAY_SECS, then is dropped entirely.  This means a
        miner that pauses or hangs while still TCP-connected stops
        contributing to the network's claimed hashrate within ~90 s
        (default config) instead of 5 minutes, while normal report
        jitter (one missed 5 s interval) sees no change.

        Algorithm per peer:
            age = now - last_report_ts
            age ≤ FRESH               → effective = reported
            FRESH < age ≤ FRESH+DECAY → effective = reported × (1 - (age-FRESH)/DECAY)
            age > FRESH+DECAY         → drop the entry from the registry

        Note: TTL (HASHRATE_PEER_TTL) is preserved as an outer safety net
        in case FRESH+DECAY is misconfigured to a very small value; the
        registry also drops anything older than TTL.
        """
        now            = time.time()
        fresh_secs     = float(Config.HASHRATE_FRESH_SECS)
        decay_secs     = max(1e-3, float(Config.HASHRATE_DECAY_SECS))
        max_age_secs = min(float(Config.HASHRATE_PEER_TTL), fresh_secs + decay_secs)

        live: List[float] = []
        stale: List[str] = []
        for pid, (rate, receive_ts) in self._peer_rates.items():
            metadata = self._peer_report_meta.get(pid)
            # A signed report may be relayed several hops after it was issued.
            # Expiry is therefore based on the origin's signed timestamp, not
            # on the most recent relay's receive time. Legacy reports without
            # an origin timestamp still use local receive time.
            origin_ts = metadata[0] if metadata is not None else receive_ts
            age = max(0.0, now - origin_ts)  # tolerate bounded future clock skew
            if age > max_age_secs:
                stale.append(pid)
                continue
            if age <= fresh_secs:
                effective = rate
            else:
                decay_age = age - fresh_secs
                effective = (0.0 if decay_age >= decay_secs else
                             rate * (1.0 - decay_age / decay_secs))
            if effective > 0.0:
                live.append(effective)
        for pid in stale:
            self._peer_rates.pop(pid, None)
            self._peer_report_meta.pop(pid, None)
        return live

    @staticmethod
    def _share_of(actual: float, exponent: float) -> float:
        """Return actual^exponent with safe handling of zero/negative inputs.
        Used for the per-miner share-weight that produces 'almost-equal'
        opportunity.  α=1 → pure proportional; α=0 → perfectly equal;
        α=0.5 → sqrt-weighted (default)."""
        if actual <= 0.0:
            return 0.0
        try:
            return float(actual) ** float(exponent)
        except (OverflowError, ValueError):
            return 0.0

    # ─────────────────────────────────────────────────────────────────────
    # Public: compute the local cap
    # ─────────────────────────────────────────────────────────────────────
    def advise(self, current_difficulty: float) -> Tuple[float, float, dict]:
        """Return (local_cap_hps, required_network_hps, diagnostics).

        Policy requested for the adaptive governor:
          * Until this node has a measured raw rate, run the first calibration
            attempt unthrottled. Never derive a cap from a fake zero rate or
            substitute another miner's rate for this node's hardware.
          * If local measured capacity is below the difficulty-derived target,
            cap at that local capacity (do not throttle a miner that cannot
            reach the target by itself).
          * Otherwise use THIS miner's local measured H_actual as the formula
            multiplier, with square-root/proportional weighting configured by
            HASHRATE_SHARE_EXPONENT. Peer reports supply the weighting terms,
            not the formula numerator. If the calculated local cap is below the
            required network rate, floor it at required_network_hps, per the
            requested rule. Finally, never set a cap above this node's own
            measured capacity.

        Peer reports form an OBSERVED mesh view of other miners, not a guaranteed
        network-wide census. It can be incomplete, and signatures authenticate
        the claimant, not physical hashrate truth. This class is advisory and
        does not alter consensus validation or the canonical difficulty calculation.
        """
        required_total = DifficultyEngine.required_network_hashrate(
            current_difficulty)
        if not Config.HASHRATE_OPTIMIZATION_ENABLED:
            with self._lock:
                self._last_required_total = required_total
                self._last_local_cap = float("inf")
            return float("inf"), required_total, {
                "enabled": False,
                "measurement_ready": self.get_local_actual_hashrate() > 0.0,
                "required_total_hps": required_total,
                "allowed_local_hps": float("inf"),
            }

        with self._lock:
            local_actual = self._local_actual_hashrate
            peer_rates = self._live_peer_rates()

        # Startup safety: no valid local raw-rate sample yet. Use no throttle
        # for calibration, report the UI as "measuring", and avoid making the
        # local cap depend on a peer's hardware rate.
        if local_actual <= 0.0:
            with self._lock:
                self._last_required_total = required_total
                self._last_local_cap = float("inf")
            return float("inf"), required_total, {
                "enabled": True,
                "measurement_ready": False,
                "required_total_hps": required_total,
                "observed_actual_total_hps": sum(peer_rates),
                "allowed_local_hps": float("inf"),
                "local_actual_hps": 0.0,
                "peers_reporting": len(peer_rates),
                "mode": "startup_calibration",
                "redistributed": False,
            }

        alpha = float(Config.HASHRATE_SHARE_EXPONENT)
        actual_total = local_actual + sum(peer_rates)

        # The user's low-cap guard is per local miner: a device whose own
        # measured capacity is below the network target is never throttled.
        if local_actual < required_total:
            cap = local_actual
            mode = "local_below_required"
            calculated_cap = local_actual
            local_share = 1.0
        else:
            actuals = [local_actual] + peer_rates
            shares = [self._share_of(rate, alpha) for rate in actuals]
            total_share = sum(shares)
            local_share = (shares[0] / total_share) if total_share > 0.0 else 1.0
            # Per the requested rule, replace H_required in C_i with THIS
            # miner's measured H_actual. Peer rates define the share denominator;
            # they do not become the numerator for this node's local cap.
            calculated_cap = (local_actual * local_share
                              * float(Config.HASHRATE_HEADROOM_FACTOR))
            cap = max(required_total, calculated_cap)
            # A cap cannot create hardware capacity. local_actual >= required
            # in this branch, so this clamp does not violate the required floor.
            cap = min(local_actual, cap)
            mode = "weighted_local_actual"

        with self._lock:
            self._last_required_total = required_total
            self._last_local_cap = cap

        debug = {
            "enabled": True,
            "measurement_ready": True,
            "required_total_hps": required_total,
            "observed_actual_total_hps": actual_total,
            "allowed_local_hps": cap,
            "calculated_cap_before_floor_hps": calculated_cap,
            "local_actual_hps": local_actual,
            "local_share": local_share,
            "peers_reporting": len(peer_rates),
            "share_exponent": alpha,
            "mode": mode,
            "redistributed": False,
        }
        return cap, required_total, debug

    def status_snapshot(self) -> dict:
        """Return a snapshot for CLI / RPC display.  Cheap; safe to call often.

        Peer count uses the original report timestamp and the effective decay
        window, so relaying a report does not extend its useful lifetime. The
        map can include authenticated miner origins learned through mesh gossip;
        it is an observed view, not a guaranteed complete network census.
        """
        with self._lock:
            now = time.time()
            visible_age = min(float(Config.HASHRATE_PEER_TTL),
                              float(Config.HASHRATE_FRESH_SECS)
                              + float(Config.HASHRATE_DECAY_SECS))
            peer_count = sum(
                1 for pid, (_, receive_ts) in self._peer_rates.items()
                if now - max(0.0, self._peer_report_meta.get(pid, (receive_ts, -1))[0])
                < visible_age)
            return {
                "local_actual_hps":   self._local_actual_hashrate,
                "measurement_ready":  self._local_actual_hashrate > 0.0,
                "optimization_enabled": bool(Config.HASHRATE_OPTIMIZATION_ENABLED),
                "allowed_local_hps":  self._last_local_cap,
                "required_total_hps": self._last_required_total,
                "live_peer_reports":  peer_count,
            }
