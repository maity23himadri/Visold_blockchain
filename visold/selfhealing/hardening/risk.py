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
"""visold.selfhealing.hardening.risk


Defines: RiskScore, SignalRecord, MultiSignalConfirmationWindow, AnomalyFrequencyTracker, EconomicImpactSimulator, RollbackPreview, RollbackAbuseGuard, RiskScoringEngine ...
Origin: visold_vsd_.py L53353-53396, L53401-53410, L53413-53546, L53551-53597, L53602-53716, L53721-53735, L53738-53796, L53804-53911, L53916-53951
"""

import math
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# SHBS PRODUCTION HARDENING PATCH v2.0.0
# Upgraded architecture: multi-signal confirmation, continuous risk scoring,
# economic gating, staged response, rollback dry-run + abuse guard.
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RiskScore:
    """
    Continuous risk score in [0, 100].

    PSEUDOCODE — risk_score():
        raw = (
            w_confidence  * (confidence * 100)       +
            w_zscore      * min(abs(z_score) * 10, 40) +
            w_attacker_ev * ev_normalized              +
            w_frequency   * freq_penalty
        )
        score = clamp(raw, 0, 100)

    Thresholds:
        0–30   → OBSERVE    (log only, no action)
        30–60  → SOFT       (rate-limit, alert)
        60–80  → RESTRICTED (temporary isolation, freeze with auto-expiry)
        80–100 → CRITICAL   (governance-controlled intervention)
    """
    value: float                    # [0.0, 100.0]
    confidence_contrib: float       # raw contribution from confidence
    zscore_contrib: float           # raw contribution from z-score magnitude
    ev_contrib: float               # raw contribution from attacker expected value
    freq_contrib: float             # raw contribution from historical anomaly freq
    components: Dict[str, float] = field(default_factory=dict)

    OBSERVE    = 30.0
    SOFT       = 60.0
    RESTRICTED = 80.0
    CRITICAL   = 100.0  # theoretical ceiling

    @property
    def tier(self) -> str:
        if self.value < self.OBSERVE:
            return "OBSERVE"
        if self.value < self.SOFT:
            return "SOFT"
        if self.value < self.RESTRICTED:
            return "RESTRICTED"
        return "CRITICAL"

    def __repr__(self):
        return f"RiskScore({self.value:.1f}/{self.tier})"


# ── A2. Signal Confirmation Window ────────────────────────────────────────────

@dataclass
class SignalRecord:
    """One confirmed anomaly signal stored in the confirmation buffer."""
    kind: str                   # AnomalyKind.value
    source: str                 # "rule" | "stat" | "pattern"
    confidence: float
    z_score: float
    affected_addr: Optional[str]
    detected_at: float          # unix ts
    block_height: Optional[int]


class MultiSignalConfirmationWindow:
    """
    Require N independent signals within T seconds before escalating to
    RESTRICTED or CRITICAL tier.

    PSEUDOCODE — confirm(signal):
        1. Append signal to per-(kind, addr) deque.
        2. Evict signals older than WINDOW_SECS.
        3. Count signals by source — count only one per unique source.
           (prevents a single broken detector from flooding N signals)
        4. If unique_source_count >= MIN_SIGNALS_FOR_TIER[tier]:
           → return ConfirmationResult(confirmed=True, signals=list)
        5. Else:
           → return ConfirmationResult(confirmed=False, pending=N-count)

    Attack resistance:
        - Adversary who controls one detector gets at most 1 credit.
        - To spam anomalies from all 3 sources requires compromising all 3,
          which is architecturally much harder than injecting one rule hit.

    FAILURE CASE (documented):
        If two detectors share a bug (e.g., both read a corrupted ring buffer),
        their signals correlate and the multi-source requirement is bypassed.
        Mitigation: each detector reads from an independent data path.
    """

    MIN_SIGNALS_RESTRICTED = 2   # at least 2 independent sources
    MIN_SIGNALS_CRITICAL   = 3   # all 3 sources must agree
    WINDOW_SECS            = 120 # signals expire after 2 minutes
    # Temporal persistence: anomaly must appear across at least N blocks
    MIN_BLOCKS_RESTRICTED  = 2
    MIN_BLOCKS_CRITICAL    = 3

    def __init__(self):
        # (kind, addr) → deque[SignalRecord]
        self._windows: Dict[Tuple[str, str], deque] = defaultdict(
            lambda: deque(maxlen=50))
        self._lock = threading.Lock()

    def add_signal(self, report) -> None:
        """Feed an AnomalyReport into the confirmation window."""
        rec = SignalRecord(
            kind=report.kind.value,
            source=report.source,
            confidence=report.confidence,
            z_score=report.z_score,
            affected_addr=report.affected_addr,
            detected_at=report.detected_at,
            block_height=report.block_height,
        )
        key = (report.kind.value, report.affected_addr or "")
        with self._lock:
            self._windows[key].append(rec)

    def check(self, report, required_tier: str,
              exempt_source_diversity: bool = False) -> Tuple[bool, int, int]:
        """
        Returns (confirmed, unique_sources_seen, unique_blocks_seen).
        confirmed=True only if both source diversity AND block span thresholds
        are met for the requested tier.

        AUDIT-FIX-M1: `exempt_source_diversity` — pass True for anomaly
        kinds that RiskScoringEngine.KIND_FLOORS guarantees always reach
        RESTRICTED/CRITICAL (double_sign, supply_inflation, etc). Every
        AnomalyKind in this system has a fixed, architecturally-limited set
        of possible detector `source` values (at most 2 of the 3 types, and
        most kinds only ever have 1) — so the source-diversity requirement
        below was structurally unsatisfiable for those kinds, silently
        capping automated response at SOFT regardless of confidence. The
        block-span (temporal persistence) requirement still applies even
        when exempted, since that dimension is genuinely satisfiable.
        """
        key = (report.kind.value, report.affected_addr or "")
        now = time.time()
        cutoff = now - self.WINDOW_SECS

        with self._lock:
            buf = self._windows[key]
            # Evict stale signals
            while buf and buf[0].detected_at < cutoff:
                buf.popleft()
            recent = list(buf)

        unique_sources = {r.source for r in recent}
        unique_blocks  = {r.block_height for r in recent
                          if r.block_height is not None}

        min_signals = (
            self.MIN_SIGNALS_CRITICAL
            if required_tier == "CRITICAL"
            else self.MIN_SIGNALS_RESTRICTED
        )
        min_blocks = (
            self.MIN_BLOCKS_CRITICAL
            if required_tier == "CRITICAL"
            else self.MIN_BLOCKS_RESTRICTED
        )

        if exempt_source_diversity:
            confirmed = len(unique_blocks) >= min_blocks
        else:
            confirmed = (
                len(unique_sources) >= min_signals
                and len(unique_blocks) >= min_blocks
            )
        return confirmed, len(unique_sources), len(unique_blocks)

    def aggregate_confidence(self, report) -> float:
        """
        Aggregate confidence across all recent signals for this (kind, addr).
        Uses a dampened mean — newer signals weighted higher via recency factor.

        PSEUDOCODE:
            scores = []
            for signal in recent_window:
                age_factor = exp(-0.01 * (now - signal.detected_at))
                scores.append(signal.confidence * age_factor)
            return mean(scores) if scores else report.confidence
        """
        key = (report.kind.value, report.affected_addr or "")
        now = time.time()
        with self._lock:
            recent = list(self._windows[key])

        if not recent:
            return report.confidence

        weighted = []
        for r in recent:
            age_secs = max(0.0, now - r.detected_at)
            decay = math.exp(-0.01 * age_secs)  # half-life ~70s
            weighted.append(r.confidence * decay)

        return min(1.0, statistics.mean(weighted)) if weighted else report.confidence


# ── A3. Historical Anomaly Frequency Tracker ──────────────────────────────────

class AnomalyFrequencyTracker:
    """
    Tracks how often each AnomalyKind fires per address over a rolling window.
    Used to increase risk score for repeat offenders and dampen score for
    addresses with no prior anomaly history (reducing false positive penalty).

    PERFORMANCE: O(1) amortised push, O(window) query.
    At 1000 TPS with 1% anomaly rate = 10 events/s → 3600 events/hour.
    Per-address deque maxlen=200 keeps memory bounded.

    ATTACK RESISTANCE:
    Adversary flooding anomaly events to inflate a target's frequency score
    is blocked by the ADE deduplication window (30s per kind/addr).
    """
    WINDOW_SECS = 3600  # 1 hour rolling frequency window

    def __init__(self):
        # (kind_str, addr_str) → deque[float (ts)]
        self._history: Dict[Tuple[str, str], deque] = defaultdict(
            lambda: deque(maxlen=200))
        self._lock = threading.Lock()

    def record(self, kind_str: str, addr: str) -> None:
        key = (kind_str, addr or "")
        with self._lock:
            self._history[key].append(time.time())

    def frequency_per_hour(self, kind_str: str, addr: str) -> float:
        """Return anomaly events per hour in the rolling window."""
        key = (kind_str, addr or "")
        cutoff = time.time() - self.WINDOW_SECS
        with self._lock:
            buf = self._history[key]
            count = sum(1 for ts in buf if ts >= cutoff)
        # Normalise to events/hour
        return count  # already a 1h window

    def penalty_score(self, kind_str: str, addr: str) -> float:
        """
        Returns a [0, 20] additive penalty for the risk score based on
        repeat anomaly frequency. Caps at 20 to prevent domination.
        """
        freq = self.frequency_per_hour(kind_str, addr)
        # log scale: 1 event → 0, 10 events → ~5, 100 events → ~10, 1000 → ~15
        if freq <= 0:
            return 0.0
        return min(20.0, 5.0 * math.log10(freq + 1))


# ── A4. Economic Impact Simulator ─────────────────────────────────────────────

class EconomicImpactSimulator:
    """
    Before executing RESTRICTED or CRITICAL actions, simulate three economic
    outcomes to gate the decision on net expected value.

    PSEUDOCODE — simulate(report, action_cost_vsd):
        attacker_profit  = estimate_attack_profit(kind, evidence)
        validator_reward = estimate_validator_incentive(validators, depth)
        user_disruption  = estimate_user_impact(frozen_addr, tps, freeze_secs)
        intervention_cost = action_cost_vsd + user_disruption

        if expected_damage > intervention_cost:
            → act
        else:
            → downgrade to SOFT tier or OBSERVE

    FAILURE CASE:
        If storage is unavailable during simulation, we fall back to the
        pre-computed attacker_ev from GameTheoryModel (conservative upper bound).
        This means we may over-act in degraded state — acceptable trade-off
        vs. under-acting during an active attack.

    ATTACK RESISTANCE:
        Adversary who can influence supply estimates to make intervention_cost
        appear high can suppress responses. Counter: use cached supply values
        with a max staleness of 300 blocks rather than live reads.
    """

    # Default costs for each action type in VSD
    ACTION_COSTS: Dict[str, float] = {
        "rate_limit":      0.5,       # negligible
        "freeze_account":  50.0,      # user loses access × duration
        "freeze_contract": 200.0,     # contract TVL × downtime fraction
        "freeze_chain":    10_000.0,  # full chain halt — very expensive
        "rollback":        500.0,     # coordination + replay overhead
        "slash_validator": 100.0,     # governance overhead
    }

    # Conservative TPS assumption when live TPS unavailable
    DEFAULT_TPS = 50.0

    def __init__(self, storage_ref, blockchain_ref):
        self._storage = storage_ref
        self._blockchain = blockchain_ref
        self._supply_cache: Tuple[float, float] = (0.0, 0.0)  # (value, ts)
        self._supply_ttl = 300.0  # seconds

    def simulate(
        self,
        attacker_ev: float,
        action_tags: List[str],
        affected_addr: Optional[str],
        freeze_duration_secs: float = 600.0,
    ) -> Tuple[bool, float, float, str]:
        """
        Returns:
            (should_act: bool,
             expected_damage: float,
             intervention_cost: float,
             rationale: str)
        """
        # --- Expected damage from attack ---
        expected_damage = attacker_ev  # from GameTheoryModel (conservative)

        # --- Intervention cost ---
        base_cost = sum(
            self.ACTION_COSTS.get(tag, 1.0)
            for tag in action_tags
        )

        # User disruption: estimate blocked TPS × duration × avg tx value
        user_disruption = 0.0
        if affected_addr and any(t in action_tags
                                 for t in ("freeze_account", "freeze_contract")):
            try:
                tps = self._live_tps()
                avg_tx_vsd = 10.0  # heuristic; replace with on-chain avg
                # Assume ~5% of TPS flows through the frozen addr
                disruption_tps = tps * 0.05
                user_disruption = disruption_tps * freeze_duration_secs * avg_tx_vsd
            except Exception:
                user_disruption = 100.0  # safe fallback

        intervention_cost = base_cost + user_disruption

        should_act = expected_damage > intervention_cost
        rationale = (
            f"damage={expected_damage:.2f} VSD  "
            f"cost={intervention_cost:.2f} VSD  "
            f"user_disruption={user_disruption:.2f} VSD  "
            f"base_action_cost={base_cost:.2f} VSD  "
            f"→ {'ACT' if should_act else 'HOLD'}"
        )
        return should_act, expected_damage, intervention_cost, rationale

    def _live_tps(self) -> float:
        """Best-effort TPS read without blocking."""
        try:
            return float(
                getattr(self._blockchain, "current_tps", lambda: self.DEFAULT_TPS)()
            )
        except Exception:
            return self.DEFAULT_TPS

    def _supply(self) -> float:
        now = time.time()
        cached_val, cached_ts = self._supply_cache
        if now - cached_ts < self._supply_ttl and cached_val > 0:
            return cached_val
        try:
            val = float(self._storage.get_total_supply())
            self._supply_cache = (val, now)
            return val
        except Exception:
            return 21_000_000.0


# ── A5. Rollback Dry-Run Preview ──────────────────────────────────────────────

@dataclass
class RollbackPreview:
    """
    Output of a dry-run rollback simulation.
    Shows which accounts/balances would be affected WITHOUT committing.
    """
    target_height: int
    current_tip: int
    rollback_depth: int
    affected_addresses: Set[str]
    flagged_tx_count: int
    safe_tx_count: int
    estimated_balance_changes: Dict[str, float]  # addr → delta VSD
    preview_ok: bool
    reason: str


class RollbackAbuseGuard:
    """
    Prevents rollback abuse: repeated rollback proposals exhausting resources,
    or an attacker proposing rollbacks to a pre-attack state to erase slashing.

    ATTACK: adversary controls >1/3 validators (below BFT threshold).
    They propose rollback at every block, consuming validator bandwidth.
    Counter: rate-limit proposals to MAX_PROPOSALS_PER_HOUR.

    ATTACK: adversary proposes rollback to height H-1000 to erase competitor
    slashing evidence. Counter: MAX_DEPTH_BLOCKS prevents deep rollbacks.

    FAILURE CASE:
        If the legitimate response truly requires a deep rollback (rare but
        possible in a complex MEV attack spanning many blocks), the depth cap
        blocks recovery. Mitigation: governance can call emergency_deep_rollback()
        with an offline multi-sig after human review.
    """
    MAX_PROPOSALS_PER_HOUR = 3
    MAX_DEPTH_BLOCKS        = 20    # dynamic, see compute_max_depth()
    PROPOSAL_WINDOW_SECS    = 3600

    def __init__(self):
        self._proposals: deque = deque(maxlen=100)
        self._lock = threading.Lock()

    def record_proposal(self) -> None:
        with self._lock:
            self._proposals.append(time.time())

    def is_rate_limited(self) -> Tuple[bool, str]:
        """Returns (limited: bool, reason: str)."""
        cutoff = time.time() - self.PROPOSAL_WINDOW_SECS
        with self._lock:
            recent = [ts for ts in self._proposals if ts >= cutoff]
        if len(recent) >= self.MAX_PROPOSALS_PER_HOUR:
            return True, (
                f"Rollback rate limit: {len(recent)} proposals in last hour "
                f"(max {self.MAX_PROPOSALS_PER_HOUR})")
        return False, "ok"

    def compute_max_depth(self, risk_score: float, snapshot_max: int) -> int:
        """
        Dynamic depth cap: higher risk score allows deeper rollback.
        Prevents surface-level rollbacks missing the attack root while also
        preventing abuse through unlimited depth.

            0–60  → max 5 blocks   (minor incident)
            60–80 → max 10 blocks
            80–90 → max 20 blocks
            90+   → max snapshot_max blocks (hard ceiling)
        """
        if risk_score >= 90:
            return snapshot_max
        if risk_score >= 80:
            return 20
        if risk_score >= 60:
            return 10
        return 5


# ─────────────────────────────────────────────────────────────────────────────
# SECTION B: UPGRADED RISK SCORING (replaces DecisionEngine._classify +
#             FalsePositiveSuppressor)
# ─────────────────────────────────────────────────────────────────────────────

class RiskScoringEngine:
    """
    Continuous risk score [0–100] replacing the LOW/MEDIUM/HIGH/CRITICAL enum.

    ALGORITHM PSEUDOCODE:
    ─────────────────────
    risk_score(report, attacker_ev, agg_confidence, freq_penalty) →
        # 1. Confidence component [0, 30]
        c_score = agg_confidence * 30

        # 2. Z-score magnitude component [0, 25]
        #    Each additional σ above 3 adds 5 points; capped at 25
        z_score = clamp((abs(z) - 3.0) * 5.0, 0, 25)  IF z > 3 ELSE 0

        # 3. Attacker EV component [0, 25]
        #    Logarithmic: 10 VSD → ~3pts, 100 VSD → ~6pts, 100k VSD → ~15pts
        ev_score = min(25, log10(max(attacker_ev, 1)) * 3.5)

        # 4. Historical frequency penalty [0, 20]
        freq_score = freq_penalty  (from AnomalyFrequencyTracker)

        raw = c_score + z_score + ev_score + freq_score

        # 5. Per-kind floor: some anomaly kinds have a minimum score
        raw = max(raw, KIND_FLOORS.get(kind, 0))

        return clamp(raw, 0, 100)

    WEIGHTS RATIONALE:
        Confidence dominates (30pts) because it is the most direct evidence
        signal. EV and z-score are secondary — they scale the severity of a
        confirmed signal. Frequency adds recidivist penalty without dominating.

    FAILURE CASE:
        If BaselineTracker has not warmed up (< 200 samples), z-score = 0.
        A real attack in the warm-up window scores lower than it should.
        Mitigation: KIND_FLOORS ensure rule-based anomalies (DOUBLE_SIGN,
        SUPPLY_INFLATION) get high scores regardless of z-score.
    """

    # Minimum score floors by anomaly kind — ensures critical anomalies
    # cannot be washed out by low z-score or EV during warm-up.
    KIND_FLOORS = {
        "double_sign":       85.0,  # cryptographic proof → always critical
        "supply_inflation":  80.0,  # invariant violation → always critical
        "reentrancy_pattern": 55.0, # execution-layer attack
        "fund_drain":        40.0,  # financial attack
        "validator_collusion": 35.0,
        "selfish_mining":    40.0,
    }

    # Weights must sum to 100 — documented for auditability
    W_CONFIDENCE = 30.0
    W_ZSCORE     = 25.0
    W_EV         = 25.0
    W_FREQUENCY  = 20.0

    def compute(
        self,
        report,
        attacker_ev: float,
        agg_confidence: float,
        freq_penalty: float,
    ) -> RiskScore:
        z = abs(report.z_score)

        # Component 1: Confidence [0, 30]
        c_score = agg_confidence * self.W_CONFIDENCE

        # Component 2: Z-score magnitude [0, 25]
        # Only counts above z=3.0 (below is background noise)
        if z > 3.0:
            z_score = min(self.W_ZSCORE, (z - 3.0) * 5.0)
        else:
            z_score = 0.0

        # Component 3: Attacker EV, log-scaled [0, 25]
        if attacker_ev > 0:
            ev_score = min(self.W_EV, math.log10(max(attacker_ev, 1.0)) * 3.5)
        else:
            ev_score = 0.0

        # Component 4: Historical frequency [0, 20]
        freq_score = min(self.W_FREQUENCY, freq_penalty)

        raw = c_score + z_score + ev_score + freq_score

        # Apply kind-specific floor
        kind_str = report.kind.value
        raw = max(raw, self.KIND_FLOORS.get(kind_str, 0.0))

        # Clamp to [0, 100]
        final = min(100.0, max(0.0, raw))

        return RiskScore(
            value=final,
            confidence_contrib=c_score,
            zscore_contrib=z_score,
            ev_contrib=ev_score,
            freq_contrib=freq_score,
            components={
                "confidence": c_score,
                "zscore": z_score,
                "attacker_ev": ev_score,
                "frequency": freq_score,
                "kind_floor": self.KIND_FLOORS.get(kind_str, 0.0),
            },
        )


# ── Updated SeverityDecision that carries RiskScore alongside legacy fields ──

@dataclass
class HardenedDecision:
    """
    Extended decision record. Carries both legacy severity (for backward
    compat with existing logging) AND the new continuous risk score.
    """
    report: Any                     # AnomalyReport (original type)
    risk_score: RiskScore
    action_stage: str               # "OBSERVE" | "SOFT" | "RESTRICTED" | "CRITICAL"
    action_tags: List[str]
    attacker_ev: float
    validator_ev: float
    rationale: str
    suppress: bool = False
    economic_simulation: Optional[str] = None  # rationale from EconomicImpactSimulator
    confirmation_status: Optional[str] = None  # multi-signal confirmation result
    # AUDIT-FIX-M4: when set, _initiate_governance_rollback() uses this
    # height directly instead of deriving a depth from action_stage via
    # ROLLBACK_DEPTH. Only operator-initiated proposals (submit_rollback_
    # proposal, which has a real human-specified depth) set this; normal
    # anomaly-driven decisions leave it None and keep the existing
    # severity-based lookup.
    explicit_rollback_target_height: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "risk_score": round(self.risk_score.value, 2),
            "tier": self.action_stage,
            "action_tags": self.action_tags,
            "attacker_ev": round(self.attacker_ev, 4),
            "rationale": self.rationale,
            "suppress": self.suppress,
            "econ_sim": self.economic_simulation,
            "confirmation": self.confirmation_status,
            "score_components": self.risk_score.components,
        }
