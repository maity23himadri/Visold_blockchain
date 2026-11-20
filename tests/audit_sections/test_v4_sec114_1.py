"""
Section 114 V4 Regression Tests: Self-Healing Detection Models, Confidence and False Positives.

Targets:
  - visold/selfhealing/model.py
  - visold/selfhealing/detection.py
  - visold/selfhealing/decision.py
  - visold/selfhealing/hardening/risk.py
"""

import time
from types import SimpleNamespace
from unittest.mock import MagicMock

from visold.selfhealing.decision import DecisionEngine, GameTheoryModel
from visold.selfhealing.detection import AnomalyDetectionEngine, StatisticalDetector
from visold.selfhealing.hardening.risk import (
    MultiSignalConfirmationWindow,
    RiskScoringEngine,
)
from visold.selfhealing.model import (
    AnomalyKind,
    AnomalyReport,
    BaselineTracker,
    Severity,
)
from visold.selfhealing.monitors import (
    GasMonitor,
    MonitorBus,
    ReentrancyPatternDetector,
    TransactionMonitor,
    ValidatorMonitor,
)
from visold.selfhealing.orchestrator import SelfHealingSystem


def _make_storage():
    storage = MagicMock()
    storage.get_validators.return_value = [{"address": "val1", "slashed": False}]
    storage.get_total_supply.return_value = 21_000_000.0
    storage.mempool_size.return_value = 0
    storage.get_balance.return_value = 1000.0
    storage.get_block.return_value = None
    storage.get_vvm_receipts_for_block.return_value = []
    storage.get_healing_actions.return_value = []
    return storage


def test_dedup_preserves_distinct_sources_for_multi_signal_confirmation():
    """
    AnomalyDetectionEngine._dedup() preserves distinct sources (rule and stat)
    so MultiSignalConfirmationWindow sees 2 independent sources.
    """
    bus = MonitorBus()
    storage = _make_storage()
    blockchain = MagicMock()
    blockchain.current_tps.return_value = 50.0

    tx_mon = TransactionMonitor(bus, storage, blockchain)
    gas_mon = GasMonitor(bus, storage)
    val_mon = ValidatorMonitor(storage, blockchain)
    reen_det = ReentrancyPatternDetector(storage)
    stat_det = StatisticalDetector(bus)

    # Warm up 'tps' baseline around 10.0 TPS with small variance
    tps_baseline = bus.get_baseline("tps")
    for i in range(BaselineTracker.BASELINE_WINDOW):
        tps_baseline.update(10.0 + (i % 3) * 0.5)
    assert tps_baseline.is_warmed

    ade = AnomalyDetectionEngine(
        bus=bus,
        tx_monitor=tx_mon,
        gas_monitor=gas_mon,
        validator_monitor=val_mon,
        reentrancy_detector=reen_det,
        stat_detector=stat_det,
    )

    signal_window = MultiSignalConfirmationWindow()
    ade.add_listener(signal_window.add_signal)

    # Block with 2500 txs over 1s -> tps=2500 > TPS_HARD_LIMIT (200) AND huge z-score
    now = time.time()
    storage.get_block.return_value = {"timestamp": now - 1.0}
    txs = [SimpleNamespace(sender="", amount=0.0, gas_limit=21000) for _ in range(2500)]
    block = SimpleNamespace(index=10, timestamp=now, transactions=txs, validator_sigs=[])

    # Confirm both detectors independently detect TPS_SPIKE
    rule_reports = tx_mon.observe_block(block)
    stat_reports = stat_det.detect(10)
    assert any(r.kind == AnomalyKind.TPS_SPIKE and r.source == "rule" for r in rule_reports)
    assert any(r.kind == AnomalyKind.TPS_SPIKE and r.source == "stat" for r in stat_reports)

    # Run ADE observe_block: both rule and stat reports are preserved
    filtered = ade.observe_block(block)
    tps_reports = [r for r in filtered if r.kind == AnomalyKind.TPS_SPIKE]
    assert len(tps_reports) == 2
    assert {r.source for r in tps_reports} == {"rule", "stat"}

    _, unique_sources, _ = signal_window.check(
        tps_reports[0], required_tier="RESTRICTED", exempt_source_diversity=False
    )
    assert unique_sources == 2


def test_aggregate_confidence_evicts_expired_signals():
    """
    MultiSignalConfirmationWindow.aggregate_confidence() evicts signals older than
    WINDOW_SECS (120s) so expired signals do not dilute fresh high-confidence attacks.
    """
    window = MultiSignalConfirmationWindow()
    now = time.time()

    # Add 5 old low-tier signals from 20 minutes ago (well past WINDOW_SECS=120)
    for i in range(5):
        old_report = AnomalyReport(
            kind=AnomalyKind.TPS_SPIKE,
            detected_at=now - 1200.0 + i,
            description="old spike",
            evidence={},
            source="stat",
            confidence=0.60,
            block_height=100 + i,
            z_score=3.6,
        )
        window.add_signal(old_report)

    # Now a fresh, high-confidence attack signal arrives
    fresh_report = AnomalyReport(
        kind=AnomalyKind.TPS_SPIKE,
        detected_at=now,
        description="fresh critical spike",
        evidence={},
        source="stat",
        confidence=0.95,
        block_height=200,
        z_score=10.0,
    )
    window.add_signal(fresh_report)

    agg = window.aggregate_confidence(fresh_report)
    assert agg >= 0.90, f"Expected expired signals to be evicted, got {agg}"

    risk_engine = RiskScoringEngine()
    low_z_fresh = AnomalyReport(
        kind=AnomalyKind.TPS_SPIKE,
        detected_at=now,
        description="fresh moderate z spike",
        evidence={},
        source="stat",
        confidence=0.95,
        block_height=201,
        z_score=3.6,
    )
    risk = risk_engine.compute(low_z_fresh, attacker_ev=0.0, agg_confidence=agg, freq_penalty=0.0)
    assert agg >= 0.35
    assert risk.tier != "OBSERVE"


def test_statistical_detector_ignores_traffic_drop():
    """
    StatisticalDetector.detect() does not fire TPS_SPIKE on sharp traffic drops
    (e.g., an empty block after steady 100 TPS).
    """
    bus = MonitorBus()
    tps_buf = bus.register_buffer("tps", 3600)
    tps_base = bus.get_baseline("tps")

    # Warm baseline with steady ~100 TPS
    for i in range(BaselineTracker.BASELINE_WINDOW):
        val = 100.0 + (i % 5) * 2.0
        tps_buf.push(val)
        tps_base.update(val)
    assert tps_base.is_warmed

    # Now traffic drops to 0.0 (an empty block)
    tps_buf.push(0.0)
    det = StatisticalDetector(bus)
    anomalies = det.detect(height=201)

    assert anomalies == []


def test_decision_engine_classifies_rule_tps_spike_during_warmup():
    """
    DecisionEngine._classify() classifies a rule-based TPS_HARD_LIMIT violation
    during baseline warm-up (z_score=0.0) as at least Severity.MEDIUM with rate_limit.
    """
    storage = _make_storage()
    de = DecisionEngine(GameTheoryModel(storage))

    report = AnomalyReport(
        kind=AnomalyKind.TPS_SPIKE,
        detected_at=time.time(),
        description="TPS 1000.0 exceeds hard limit 200",
        evidence={"tps": 1000.0, "limit": 200},
        source="rule",
        confidence=0.95,
        block_height=5,
        z_score=0.0,  # baseline not yet warmed
    )

    decision = de.decide(report, height=5)
    assert decision.severity >= Severity.MEDIUM
    assert "rate_limit" in decision.action_tags


def test_self_healing_system_warms_statistical_detector_baselines():
    """
    SelfHealingSystem warms StatisticalDetector baselines as normal blocks are applied.
    """
    storage = _make_storage()
    blockchain = MagicMock()
    state_engine = MagicMock()
    p2p = MagicMock()

    shbs = SelfHealingSystem(blockchain, storage, state_engine, p2p)
    shbs.start()

    now = time.time()
    # Feed 250 normal blocks (> BASELINE_WINDOW=200)
    for h in range(1, 251):
        storage.get_block.return_value = {"timestamp": now + h - 1}
        txs = [SimpleNamespace(sender="", amount=0.0, gas_limit=21000) for _ in range(10)]
        blk = SimpleNamespace(index=h, timestamp=now + h, transactions=txs, validator_sigs=[])
        shbs.on_block_applied(blk)

    tps_tracker = shbs.bus.get_baseline("tps")
    assert tps_tracker is not None
    assert tps_tracker.is_warmed is True
    assert tps_tracker._samples >= BaselineTracker.BASELINE_WINDOW
