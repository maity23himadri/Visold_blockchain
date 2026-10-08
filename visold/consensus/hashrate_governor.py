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
# The HashrateGovernor maintains two pieces of state per node:
#   1. Local actual hashrate — measured in real time from the mining loop.
#      This is the "honest" rate the hardware can produce when unthrottled.
#   2. A registry of recently-reported peer hashrates (peer_id → (rate, ts)).
#      Built from MSG_HASHRATE_REPORT gossip messages.
#
# From those it computes:
#   • required_network_hashrate(D) — the inverse-difficulty answer to "how
#     many H/s does the network need to mine each block in 60 s?"
#   • allowed_local_hashrate()    — this node's individual cap.  The math is:
#         total_actual = my_actual + Σ peer_actual
#         my_share     = my_actual^α   (where α = HASHRATE_SHARE_EXPONENT)
#         total_share  = my_share + Σ peer_actual^α
#         my_cap       = required_total · my_share / total_share
#     With α = 0.5 (sqrt) every miner gets "almost the same" opportunity:
#     a 10× faster miner gets ~3.16× the cap, not 10×.  The LOCAL_FLOOR
#     guarantees a minimum cap so a brand-new miner is never zeroed out.
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
    Compute per-miner hashrate caps that keep the aggregate network rate
    aligned with the inverse-difficulty target so blocks land near the
    TARGET_BLOCK_TIME ± TARGET_BLOCK_TIME_TOLERANCE band.

    Thread safety: a single instance is owned by MiningEngine.  All public
    methods take an internal lock so reports from the network message loop
    and queries from the mining loop can run concurrently.
    """

    def __init__(self):
        self._lock                  = threading.Lock()
        self._peer_rates: Dict[str, Tuple[float, float]] = {}
        # peer_id -> (actual_hashrate_hps, last_seen_unix_ts)

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
        """Called by MiningEngine.status / _mine_one to record the most
        recent measured rate.  Negative or non-finite values are ignored."""
        try:
            v = float(hps)
        except (TypeError, ValueError):
            return
        if v < 0.0 or v != v:   # NaN check
            return
        with self._lock:
            self._local_actual_hashrate = v
            self._local_last_update     = time.time()

    def get_local_actual_hashrate(self) -> float:
        with self._lock:
            return self._local_actual_hashrate

    # ─────────────────────────────────────────────────────────────────────
    # Inputs from the network (gossip)
    # ─────────────────────────────────────────────────────────────────────
    def record_peer_hashrate(self, peer_id: str, hps: float) -> None:
        """Called from the network message handler when a MSG_HASHRATE_REPORT
        arrives.  Stores under the peer_id, replacing any previous report."""
        if not isinstance(peer_id, str) or not peer_id:
            return
        try:
            v = float(hps)
        except (TypeError, ValueError):
            return
        if v < 0.0 or v != v:
            return
        # Sanity cap — refuse absurd values (anti-spoofing).  2^48 H/s is
        # well above any plausible single-node hashrate but still finite.
        if v > (1 << 48):
            return
        with self._lock:
            self._peer_rates[peer_id] = (v, time.time())

    def forget_peer(self, peer_id: str) -> None:
        """Drop a peer's cached hashrate (e.g. when it disconnects)."""
        with self._lock:
            self._peer_rates.pop(peer_id, None)

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
        ttl_cutoff     = now - float(Config.HASHRATE_PEER_TTL)
        decay_cutoff   = now - (fresh_secs + decay_secs)
        # Use the more aggressive of the two cut-offs for eviction.  Decay
        # cutoff is normally tighter (90 s vs 300 s); TTL is the safety net.
        evict_cutoff   = max(ttl_cutoff, decay_cutoff)

        live: List[float] = []
        stale: List[str] = []
        for pid, (rate, ts) in self._peer_rates.items():
            if ts < evict_cutoff:
                stale.append(pid)
                continue
            age = now - ts
            if age <= fresh_secs:
                effective = rate
            else:
                # Linear decay over decay_secs; clamped to [0, rate].
                decay_age = age - fresh_secs
                if decay_age >= decay_secs:
                    # Fully decayed but not yet evicted (within TTL safety
                    # net but past decay window).  Treat as zero contribution.
                    effective = 0.0
                else:
                    effective = rate * (1.0 - decay_age / decay_secs)
            if effective > 0.0:
                live.append(effective)
        for pid in stale:
            self._peer_rates.pop(pid, None)
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
        """
        Return (allowed_local_hashrate, required_network_hashrate, debug_info).

        allowed_local_hashrate     — H/s; the cap to apply to the local miner.
                                     float('inf') if optimization is disabled.
        required_network_hashrate  — H/s; the inverse-difficulty target.
        debug_info                 — dict for logging / status display.

        Algorithm — water-filling with sqrt weighting:
        ──────────────────────────────────────────────
        We have a total "budget" of H_required hashes/second that the network
        should produce per block to hit TARGET_BLOCK_TIME.  We need to allocate
        this budget across all miners (self + peers).

        Step 1 — Compute "ideal" shares from the sqrt-weighted formula:
                 share_i = actual_i ^ HASHRATE_SHARE_EXPONENT
                 ideal_i = H_required × share_i / Σ share_j

        Step 2 — Water-filling redistribution:
                 If ideal_i > actual_i, the miner cannot consume that many
                 hashes — it would have to invent hardware power it does
                 not have.  Cap it at actual_i and redistribute the surplus
                 to the remaining miners (those with ideal_j ≤ actual_j),
                 weighted by their remaining share.  Iterate until either
                 every miner is at-or-below its actual rate OR the pool is
                 fully distributed.

        This guarantees:
            Σ caps == min(H_required, Σ actual_rates)

        i.e. the caps sum exactly to the required network hashrate when the
        network has enough total capacity, and otherwise to the full network
        capacity (with no waste).  This is the property the user specifically
        asked for: "total hashrate ke calculated hashrate e rakhbe".

        Behaviour when optimization is disabled (Config.HASHRATE_OPTIMIZATION_ENABLED
        is False): allowed = +inf, so the throttle becomes a no-op.

        Behaviour when no peers have reported yet (e.g. just-started network):
        the local miner receives the FULL required network hashrate as its
        cap.  This means a solo bootstrap miner will mine roughly on schedule
        without waiting for peer-rate reports.

        Behaviour when local actual rate has not been measured yet (first few
        seconds of mining): the local miner is given an EQUAL share rather
        than zero, so the very first block is not delayed indefinitely.
        """
        if not Config.HASHRATE_OPTIMIZATION_ENABLED:
            req = DifficultyEngine.required_network_hashrate(current_difficulty)
            return float("inf"), req, {
                "enabled": False,
                "required_total_hps": req,
                "allowed_local_hps":  float("inf"),
            }

        required_total = DifficultyEngine.required_network_hashrate(
            current_difficulty)
        # Apply a small headroom so transient variance doesn't push solve
        # time past the upper tolerance.  This is INSIDE the budget — caps
        # still sum to (required × headroom), not above.
        budget = required_total * float(Config.HASHRATE_HEADROOM_FACTOR)

        with self._lock:
            local_actual = self._local_actual_hashrate
            peer_rates   = self._live_peer_rates()

        # ── Edge case: no peer reports yet (solo bootstrap) ────────────────
        # Give the local miner the full budget — but never exceed its own
        # actual hardware rate (a cap above actual is meaningless and
        # confuses operators who see "Optimized > Actual" in the panel).
        # When solo the cap is effectively a floor of `min(budget, actual)`,
        # which means: run as fast as you can, up to the network target.
        if not peer_rates:
            cap = budget
            if local_actual > 0.0 and cap > local_actual:
                cap = local_actual
            with self._lock:
                self._last_required_total = required_total
                self._last_local_cap      = cap
            return cap, required_total, {
                "enabled":            True,
                "required_total_hps": required_total,
                "budget_hps":         budget,
                "allowed_local_hps":  cap,
                "local_actual_hps":   local_actual,
                "peers_reporting":    0,
                "share_exponent":     float(Config.HASHRATE_SHARE_EXPONENT),
                "redistributed":      False,
            }

        alpha = float(Config.HASHRATE_SHARE_EXPONENT)

        # ── Build the participant list: index 0 is "self", 1..N are peers
        # actuals[0]   = local_actual
        # actuals[1..] = peer_rates
        actuals = [local_actual] + list(peer_rates)

        # If our local rate is unmeasured, give ourselves an equal share so
        # the first-block-timing is not pathologically slow.  We use the
        # MEDIAN of peer rates (robust to one outlier) as a placeholder so
        # the share weights below are well-defined.
        if local_actual <= 0.0 and peer_rates:
            sorted_peers = sorted(peer_rates)
            median_peer  = sorted_peers[len(sorted_peers) // 2]
            actuals[0]   = max(median_peer, float(Config.HASHRATE_MIN_FLOOR))

        # ── Step 1: ideal shares from sqrt weighting ───────────────────────
        shares = [self._share_of(a, alpha) for a in actuals]
        total_share = sum(shares)
        if total_share <= 0.0:
            # All actuals are zero — split equally
            n_total = len(actuals)
            ideal = [budget / n_total for _ in actuals]
        else:
            ideal = [budget * (s / total_share) for s in shares]

        # ── Step 2: water-filling iterative redistribution ────────────────
        # Cap any miner whose ideal share exceeds their actual rate; spread
        # the surplus to the others.  Loop until either no more capping is
        # needed, or every miner is capped (network is hashrate-starved).
        caps = list(ideal)
        # Track who is "saturated" (capped at their actual rate).
        saturated = [False] * len(actuals)
        redistributed = False

        for _iter in range(len(actuals) + 1):   # at most N iterations
            # Find miners exceeding their actual rate
            surplus = 0.0
            newly_saturated = False
            for i, a in enumerate(actuals):
                if saturated[i]:
                    continue
                if a > 0.0 and caps[i] > a:
                    surplus += (caps[i] - a)
                    caps[i] = a
                    saturated[i] = True
                    newly_saturated = True
                    redistributed = True
            if not newly_saturated or surplus <= 0.0:
                break

            # Redistribute surplus to non-saturated miners weighted by
            # their original share.  If everyone is saturated, the surplus
            # is wasted (correct: network has no more capacity to absorb).
            unsaturated_share = sum(shares[i] for i in range(len(actuals))
                                     if not saturated[i])
            if unsaturated_share <= 0.0:
                break
            for i in range(len(actuals)):
                if saturated[i]:
                    continue
                caps[i] += surplus * (shares[i] / unsaturated_share)

        my_cap = caps[0]

        # Hard floor so a brand-new low-rate miner is never starved out.
        floor = float(Config.HASHRATE_MIN_FLOOR)
        if my_cap < floor:
            my_cap = floor

        # Final clamp — never exceed our actual rate (we cannot use more
        # than what the hardware produces; anything above is meaningless).
        if local_actual > 0.0 and my_cap > local_actual:
            my_cap = local_actual

        with self._lock:
            self._last_required_total = required_total
            self._last_local_cap      = my_cap

        debug = {
            "enabled":            True,
            "required_total_hps": required_total,
            "budget_hps":         budget,
            "allowed_local_hps":  my_cap,
            "local_actual_hps":   local_actual,
            "peers_reporting":    len(peer_rates),
            "share_exponent":     alpha,
            "redistributed":      redistributed,
        }
        return my_cap, required_total, debug

    def status_snapshot(self) -> dict:
        """Return a snapshot for CLI / RPC display.  Cheap; safe to call often.

        v7.6.4 — peer count uses the decay window (FRESH + DECAY) instead
        of the raw TTL, so the panel only reports peers whose claims are
        still partially or fully effective in the cap calculation.  A
        peer that has fallen silent for >90 s (default config) is no
        longer counted, even though its entry may linger in the registry
        until TTL eviction.
        """
        with self._lock:
            decay_cutoff = time.time() - (
                float(Config.HASHRATE_FRESH_SECS)
                + float(Config.HASHRATE_DECAY_SECS))
            peer_count = sum(
                1 for _, (_, ts) in self._peer_rates.items()
                if ts >= decay_cutoff)
            return {
                "local_actual_hps":   self._local_actual_hashrate,
                "allowed_local_hps":  self._last_local_cap,
                "required_total_hps": self._last_required_total,
                "live_peer_reports":  peer_count,
            }
