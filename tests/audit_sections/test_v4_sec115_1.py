"""
V4 regression tests for Section 115:
Self-Healing Decisions, Orchestration and Intervention Safety.
"""

import time
from types import SimpleNamespace
from unittest.mock import MagicMock

from visold.selfhealing.hardening.patches import (
    apply_hardening_patch,
    patch_rollback_executor,
)
from visold.selfhealing.hardening.risk import HardenedDecision, RiskScore
from visold.selfhealing.model import AnomalyKind, AnomalyReport, Severity, SeverityDecision
from visold.selfhealing.orchestrator import SelfHealingSystem


class _DummyStorage:
    def __init__(self, validators=None, supply_vsd=21_000_000.0):
        self._validators = validators if validators is not None else [
            {"address": "VSD_VAL_1", "slashed": False},
            {"address": "VSD_VAL_2", "slashed": False},
            {"address": "VSD_VAL_3", "slashed": False},
        ]
        self._supply_vsd = supply_vsd

    def get_validators(self):
        return list(self._validators)

    def get_total_supply(self):
        return self._supply_vsd

    def get_total_supply_sat(self):
        return int(self._supply_vsd * 100_000_000)

    def get_block(self, height):
        return None

    def get_balance(self, addr):
        return 0.0

    def get_vvm_receipts_for_block(self, height):
        return []

    def slash_validator(self, addr):
        return True

    def _conn(self):
        raise RuntimeError("no sqlite in dummy storage")


class _DummyBlockchain:
    def __init__(self, tip=100, tps=50.0):
        self._tip = tip
        self._tps = tps

    def height(self):
        return self._tip

    def current_tps(self):
        return self._tps


class _DummyStateEngine:
    def __init__(self):
        self._circuit_breaker = MagicMock()
        self._circuit_breaker.is_open = False

    def _handle_new_tx(self, payload, source_peer):
        return True, "ok"


class _DummyP2P:
    def __init__(self):
        self.gossiped = []

    def _gossip(self, payload, exclude=None):
        self.gossiped.append(payload)


def _make_shbs(tip=100, tps=50.0, validators=None):
    storage = _DummyStorage(validators=validators)
    blockchain = _DummyBlockchain(tip=tip, tps=tps)
    se = _DummyStateEngine()
    p2p = _DummyP2P()
    shbs = SelfHealingSystem(blockchain, storage, se, p2p)
    components = apply_hardening_patch(shbs)
    shbs.start()
    return shbs, components, se, p2p


def test_hardened_decide_preserves_critical_for_double_sign():
    """
    After multi-signal confirmation across 3 blocks, DOUBLE_SIGN remains CRITICAL
    with slash_validator and freeze_account action tags.
    """
    shbs, _, _, _ = _make_shbs(tip=100, tps=50.0)
    val_addr = "VSD_VAL_1"

    decisions = []
    for h in (98, 99, 100):
        report = AnomalyReport(
            kind=AnomalyKind.DOUBLE_SIGN,
            detected_at=time.time(),
            description=f"Double-sign at height {h}",
            evidence={"addr": val_addr, "height": h, "hash_a": "aa", "hash_b": "bb"},
            source="rule",
            confidence=1.0,
            affected_addr=val_addr,
            block_height=h,
        )
        decisions.append(shbs.decision_eng.decide(report, h))

    final = decisions[-1]
    assert final.risk_score.tier == "CRITICAL"
    assert "Confirmed CRITICAL" in (final.confirmation_status or "")
    assert final.action_stage == "CRITICAL"
    assert "slash_validator" in final.action_tags
    assert "freeze_account" in final.action_tags


def test_hardened_decide_preserves_critical_for_supply_inflation():
    """
    After multi-signal confirmation across 3 blocks, SUPPLY_INFLATION remains CRITICAL
    with freeze_chain action tag.
    """
    shbs, _, _, _ = _make_shbs(tip=150, tps=50.0)

    decisions = []
    for h in (50, 100, 150):
        report = AnomalyReport(
            kind=AnomalyKind.SUPPLY_INFLATION,
            detected_at=time.time(),
            description=f"Supply inflation at height {h}",
            evidence={"delta_sat": 1_000_000_000_000},
            source="rule",
            confidence=0.95,
            affected_addr=None,
            block_height=h,
        )
        decisions.append(shbs.decision_eng.decide(report, h))

    final = decisions[-1]
    assert final.risk_score.tier == "CRITICAL"
    assert "Confirmed CRITICAL" in (final.confirmation_status or "")
    assert final.action_stage == "CRITICAL"
    assert "freeze_chain" in final.action_tags


def test_unfreeze_sets_refreeze_cooldown_and_manual_unfreeze_clears_ratelimit():
    """
    (a) SelfHealingSystem.unfreeze() records manual unfreeze so R4 refreeze cooldown
        strips freeze_account for 60s.
    (b) manual_unfreeze() also clears rate_limiter._limited.
    """
    shbs, _, _, _ = _make_shbs()
    addr = "VSD_USER_ABC"

    shbs.freeze_reg.freeze(addr, 600)
    shbs.rate_limiter.limit(addr)
    assert shbs.freeze_reg.is_frozen(addr)

    # (a) Call shbs.unfreeze()
    ok, _ = shbs.unfreeze(addr)
    assert ok
    assert not shbs.freeze_reg.is_frozen(addr)

    # Immediately dispatch a RESTRICTED freeze_account decision: R4 strips freeze_account
    report = AnomalyReport(
        kind=AnomalyKind.FUND_DRAIN,
        detected_at=time.time(),
        description="drain",
        evidence={"amount": 50000.0},
        source="rule",
        confidence=0.9,
        affected_addr=addr,
        block_height=100,
    )
    dec = HardenedDecision(
        report=report,
        risk_score=RiskScore(70.0, 27.0, 0.0, 16.0, 0.0),
        action_stage="RESTRICTED",
        action_tags=["log", "freeze_account"],
        attacker_ev=45000.0,
        validator_ev=10.0,
        rationale="test",
    )
    shbs.hal.execute(dec)
    assert not shbs.freeze_reg.is_frozen(addr)

    # (b) Call shbs.manual_unfreeze() while rate-limited
    shbs.rate_limiter.limit(addr)
    res = shbs.manual_unfreeze(addr)
    assert res["ok"] is True
    assert not shbs.freeze_reg.is_frozen(addr)
    assert addr not in shbs.rate_limiter._limited


def test_ade_observe_block_records_signal_window_and_freq_tracker_once():
    """
    1 anomaly in 1 block is recorded exactly once in freq_tracker and signal_window.
    """
    shbs, components, _, _ = _make_shbs(tip=100)
    addr = "VSD_SPAMMER_1"
    report = AnomalyReport(
        kind=AnomalyKind.MEMPOOL_FLOOD,
        detected_at=time.time(),
        description="flood",
        evidence={"sender": addr, "tx_count": 100},
        source="rule",
        confidence=0.85,
        affected_addr=addr,
        block_height=100,
    )
    shbs.tx_monitor.observe_block = lambda block: [report]
    shbs.gas_monitor.observe_block = lambda block: []
    shbs.validator_mon.observe_block = lambda block: []
    shbs.reentrancy_det.observe_block = lambda block: []
    shbs.stat_detector.detect = lambda h: []

    block = SimpleNamespace(index=100, transactions=[], timestamp=time.time())
    shbs.on_block_applied(block)

    freq_tracker = components["freq_tracker"]
    signal_window = components["signal_window"]
    assert freq_tracker.frequency_per_hour("mempool_flood", addr) == 1
    assert len(signal_window._windows[("mempool_flood", addr)]) == 1


def test_execute_rollback_passes_risk_score_preserving_depth_15():
    """
    HealingActionLayer._execute_rollback() forwards risk_score=95.0 so depth=15
    rolls back to target_height=85 rather than capping to 5.
    """
    shbs, _, _, _ = _make_shbs(tip=100, validators=[])  # solo node auto-approves

    seen_targets = []

    def _fake_orig_execute(target_height, flagged_addresses, replay_safe=True):
        seen_targets.append(target_height)
        return True, f"rolled back to {target_height}"

    shbs.rollback_exec.execute = _fake_orig_execute
    patch_rollback_executor(
        shbs.rollback_exec,
        shbs._v2_abuse_guard,
        shbs._v2_signal_window,
    )
    shbs._storage.get_block = lambda h: {"transactions": []}
    shbs.rollback_exec._snapshots.store(
        SimpleNamespace(height=95, state_root="root95")
    )
    shbs.rollback_exec._snapshots.store(
        SimpleNamespace(height=85, state_root="root85")
    )
    shbs._blockchain.state_root = lambda: "root95"

    res = shbs.submit_rollback_proposal(depth=15, reason="deep exploit", risk_score=95.0)
    assert res["ok"] is True
    assert res["target_height"] == 85
    assert seen_targets == [85]


def test_safe_action_validator_handles_legacy_severity_decision():
    """
    SafeActionValidator.validate_and_filter() handles legacy SeverityDecision
    without raising AttributeError on missing action_stage.
    """
    shbs, _, _, _ = _make_shbs()
    report = AnomalyReport(
        kind=AnomalyKind.MEMPOOL_FLOOD,
        detected_at=time.time(),
        description="flood",
        evidence={},
        source="rule",
        confidence=0.85,
        affected_addr="VSD_1",
        block_height=100,
    )
    legacy = SeverityDecision(
        report=report,
        severity=Severity.MEDIUM,
        action_tags=["log", "rate_limit"],
        attacker_ev=0.0,
        validator_ev=1.0,
        rationale="legacy",
    )
    shbs.hal.execute(legacy)
    assert "VSD_1" in shbs.rate_limiter._limited
