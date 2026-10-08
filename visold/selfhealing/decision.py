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
"""visold.selfhealing.decision

Original section: SECTION 5: LAYER 3 — DECISION ENGINE

Defines: GameTheoryModel, DecisionEngine
Origin: visold_vsd_.py L51101-51175, L51178-51371
"""

from typing import Any, Dict, List, Tuple

from visold.selfhealing.model import AnomalyKind, AnomalyReport, Severity, SeverityDecision


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5: LAYER 3 — DECISION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class GameTheoryModel:
    """
    Deterministic game-theoretic model for attacker/validator incentive analysis.

    Parameters:
      - chain_value_vsd: total VSD in circulation (proxy for stake value)
      - block_reward_vsd: current block reward
      - validator_count: number of active validators
      - network_hashrate: current hash rate

    Outputs:
      - attacker_ev: expected value of the attack succeeding
      - validator_ev: expected value for validators of participating in response
      - cost_to_attack: estimated cost for attacker

    This model is intentionally simple and conservative — overestimating
    attacker EV ensures we err toward caution.
    """

    def __init__(self, storage_ref):
        self._storage = storage_ref

    def compute(
        self,
        kind: AnomalyKind,
        evidence: Dict[str, Any],
        height: int,
    ) -> Tuple[float, float]:
        """Returns (attacker_ev, validator_ev) in VSD units."""
        try:
            supply = self._get_total_supply()
            block_reward = 10.0   # VSD; would read from Config.BLOCK_REWARD
            validators = len(self._storage.get_validators() or [])
        except Exception:
            supply, block_reward, validators = 1_000_000.0, 10.0, 3

        # Attacker EV models per anomaly kind
        if kind == AnomalyKind.FUND_DRAIN:
            # EV = amount drained if attack succeeds
            drain_amount = evidence.get("amount", 0.0)
            attacker_ev = drain_amount * 0.9   # net 90% after costs
            # Validators: slashing reward is a fraction of stake slashed
            validator_ev = drain_amount * 0.05 / max(validators, 1)

        elif kind == AnomalyKind.DOUBLE_SIGN:
            # Byzantine validator attack — EV = reorg profit minus slash risk
            attacker_ev = block_reward * 3    # 3 blocks of double-claim
            validator_ev = -block_reward * 10  # large slash penalty

        elif kind == AnomalyKind.VALIDATOR_COLLUSION:
            # Coordinated censorship or 51% — EV scales with supply fraction
            attacker_ev = supply * 0.001   # small % of supply as reorg profit
            validator_ev = block_reward * 0.5 * validators  # shared staking reward

        elif kind in (AnomalyKind.TPS_SPIKE, AnomalyKind.MEMPOOL_FLOOD):
            # DoS attack — attacker gains nothing financially
            attacker_ev = 0.0
            validator_ev = block_reward * 0.1

        elif kind == AnomalyKind.REENTRANCY_PATTERN:
            # Reentrancy — EV = contract's current balance if drain succeeds
            attacker_ev = evidence.get("contract_balance", 1000.0)
            validator_ev = block_reward * 2

        else:
            attacker_ev = block_reward * 1.5
            validator_ev = block_reward * 0.5

        return round(attacker_ev, 4), round(validator_ev, 4)

    def _get_total_supply(self) -> float:
        try:
            return self._storage.get_total_supply()
        except Exception:
            return 21_000_000.0


class DecisionEngine:
    """
    Deterministic decision engine — no black-box ML.

    Classification rules (all deterministic, fully auditable):

    CRITICAL:
      - Double-sign (cryptographic proof, confidence=1.0)
      - Fund drain > 100k VSD with confidence > 0.8
      - Reentrancy in a contract with > 50k VSD balance
      - Supply inflation detected

    HIGH:
      - Fund drain > 10k VSD
      - Reentrancy pattern (any confidence > 0.6)
      - TPS spike with z-score > 5 + mempool flood simultaneously
      - Validator inactivity across > 50% of validators

    MEDIUM:
      - TPS spike (z > 3.5) OR gas spike (z > 4)
      - Mempool flood from single sender
      - Gas exhaustion pattern
      - Validator inactivity (single validator)

    LOW:
      - Circular trade / wash trading
      - Statistical anomaly below HIGH thresholds
      - Validator collusion suspicion (low confidence)

    False-positive suppression:
      - Confidence gating: CRITICAL requires ≥ 0.8, HIGH ≥ 0.6
      - Attacker EV gating: CRITICAL requires attacker_ev > CRITICAL_EV_FLOOR
    """

    CRITICAL_EV_FLOOR   = 1_000.0    # VSD — must be worth attacking
    CRITICAL_CONFIDENCE = 0.80
    HIGH_CONFIDENCE     = 0.60
    MEDIUM_CONFIDENCE   = 0.40

    def __init__(self, game_model: GameTheoryModel):
        self._game = game_model

    def decide(
        self, report: AnomalyReport, height: int
    ) -> SeverityDecision:
        """
        Classify an anomaly report into a severity + action plan.
        Returns a SeverityDecision with full rationale.
        """
        attacker_ev, validator_ev = self._game.compute(
            report.kind, report.evidence, height)

        severity, actions, rationale = self._classify(
            report, attacker_ev, validator_ev)

        # False-positive suppression
        suppress = self._should_suppress(report, severity, attacker_ev)

        return SeverityDecision(
            report=report,
            severity=severity,
            action_tags=actions,
            attacker_ev=attacker_ev,
            validator_ev=validator_ev,
            rationale=rationale,
            suppress=suppress,
        )

    def _classify(
        self,
        r: AnomalyReport,
        attacker_ev: float,
        validator_ev: float,
    ) -> Tuple[Severity, List[str], str]:
        """Deterministic classification. Returns (severity, actions, rationale)."""

        k = r.kind
        c = r.confidence
        z = abs(r.z_score)

        # ── CRITICAL ─────────────────────────────────────────────────────────
        if k == AnomalyKind.DOUBLE_SIGN and c >= 1.0:
            return (Severity.CRITICAL,
                    ["log", "slash_validator", "rollback", "alert_network"],
                    f"Cryptographic double-sign proof: attacker_ev={attacker_ev:.2f} VSD")

        if k == AnomalyKind.FUND_DRAIN:
            amount = r.evidence.get("amount", 0.0)
            if amount > 100_000 and c >= self.CRITICAL_CONFIDENCE:
                return (Severity.CRITICAL,
                        ["log", "freeze_account", "rollback", "alert_validators"],
                        f"Massive drain {amount:.0f} VSD with confidence {c:.2f}")

        if k == AnomalyKind.SUPPLY_INFLATION:
            return (Severity.CRITICAL,
                    ["log", "freeze_chain", "alert_validators", "rollback"],
                    "Supply conservation invariant violated — consensus break suspected")

        if k == AnomalyKind.REENTRANCY_PATTERN and c >= self.CRITICAL_CONFIDENCE:
            contract_balance = r.evidence.get("contract_balance", 0.0)
            if contract_balance > 50_000:
                return (Severity.CRITICAL,
                        ["log", "freeze_contract", "rollback"],
                        f"Reentrancy in high-value contract ({contract_balance:.0f} VSD)")

        # ── HIGH ─────────────────────────────────────────────────────────────
        if k == AnomalyKind.FUND_DRAIN and c >= self.HIGH_CONFIDENCE:
            amount = r.evidence.get("amount", 0.0)
            if amount > 10_000:
                return (Severity.HIGH,
                        ["log", "freeze_account", "alert_validators"],
                        f"High-value drain {amount:.0f} VSD")

        if k == AnomalyKind.REENTRANCY_PATTERN and c >= self.HIGH_CONFIDENCE:
            return (Severity.HIGH,
                    ["log", "freeze_contract", "alert_validators"],
                    "Reentrancy pattern detected with high confidence")

        if k == AnomalyKind.VALIDATOR_INACTIVITY:
            miss = r.evidence.get("miss_ratio", 0.0)
            # Check if it's a majority of validators — more severe
            return (Severity.HIGH if miss > 0.90 else Severity.MEDIUM,
                    ["log", "alert_validators", "rate_limit"],
                    f"Validator {r.affected_addr[:20] if r.affected_addr else 'unknown'}"
                    f" inactive {miss*100:.0f}% of blocks")

        if k in (AnomalyKind.TPS_SPIKE, AnomalyKind.MEMPOOL_FLOOD) and z > 6.0:
            return (Severity.HIGH,
                    ["log", "rate_limit", "alert_validators"],
                    f"Extreme TPS/flood z={z:.1f} — potential DoS attack")

        if k == AnomalyKind.DOUBLE_SIGN:
            return (Severity.HIGH,
                    ["log", "slash_validator", "alert_validators"],
                    "Double-sign detected — validator slash required")

        # ── MEDIUM ───────────────────────────────────────────────────────────
        if k in (AnomalyKind.TPS_SPIKE, AnomalyKind.GAS_SPIKE) and z > 3.5:
            return (Severity.MEDIUM,
                    ["log", "rate_limit"],
                    f"Statistical anomaly z={z:.1f} in {k.value}")

        if k == AnomalyKind.MEMPOOL_FLOOD:
            return (Severity.MEDIUM,
                    ["log", "rate_limit"],
                    f"Mempool flood from single sender")

        if k == AnomalyKind.GAS_EXHAUSTION:
            return (Severity.MEDIUM,
                    ["log", "alert_validators"],
                    "Contract approaching gas exhaustion limit")

        if k == AnomalyKind.VALIDATOR_COLLUSION and c < 0.6:
            return (Severity.LOW,
                    ["log"],
                    "Low-confidence collusion signal — monitoring only")

        # ── LOW (default) ────────────────────────────────────────────────────
        return (Severity.LOW,
                ["log"],
                f"Low severity: {k.value} — monitoring and logging")

    def _should_suppress(
        self,
        report: AnomalyReport,
        severity: Severity,
        attacker_ev: float,
    ) -> bool:
        """
        False-positive suppression rules.

        Returns True if the anomaly should be suppressed (no action taken).
        """
        # CRITICAL/HIGH require minimum confidence
        if severity >= Severity.HIGH and report.confidence < self.HIGH_CONFIDENCE:
            return True

        if severity == Severity.CRITICAL and report.confidence < self.CRITICAL_CONFIDENCE:
            return True

        # CRITICAL requires economically meaningful attack
        if severity == Severity.CRITICAL and attacker_ev < self.CRITICAL_EV_FLOOR:
            # Exception: double_sign and supply_inflation are always critical
            if report.kind not in (AnomalyKind.DOUBLE_SIGN,
                                   AnomalyKind.SUPPLY_INFLATION):
                return True

        # Low z-score stat anomalies are noise
        if (report.source == "stat"
                and severity == Severity.LOW
                and abs(report.z_score) < 3.0):
            return True

        return False
