"""V4 regression tests for Section 113: Self-Healing Monitors & Runtime Anomaly Detection."""

import time
from types import SimpleNamespace
from unittest.mock import MagicMock

from visold.ledger.block import Block
from visold.selfhealing.hardening.risk import MultiSignalConfirmationWindow
from visold.selfhealing.model import AnomalyKind
from visold.selfhealing.monitors import (
    MonitorBus,
    ReentrancyPatternDetector,
    TransactionMonitor,
)


class _DummyTx:
    def __init__(self, sender: str, amount: float = 1.0, gas_limit: int = 21000, tx_id: str = "tx1"):
        self.sender = sender
        self.amount = amount
        self.gas_limit = gas_limit
        self.tx_id = tx_id


def test_tx_monitor_get_prev_ts_works_on_block_object_detects_tps_spike():
    """
    TransactionMonitor._get_prev_ts() reads timestamp from Block objects,
    so a 250-tx block arriving 1s after the previous block triggers TPS_SPIKE.
    """
    now = int(time.time())
    prev_block = Block(
        index=9,
        prev_hash="0" * 64,
        transactions=[],
        miner_address="VSD_miner",
        difficulty=1,
        timestamp=now - 1,
    )
    curr_block = SimpleNamespace(
        index=10,
        timestamp=float(now),
        transactions=[_DummyTx(f"VSD_sender_{i}") for i in range(250)],
    )

    storage = MagicMock()
    storage.get_block.return_value = prev_block
    storage.mempool_size.return_value = 0
    storage.get_balance.return_value = 1000.0

    bus = MonitorBus()
    tx_mon = TransactionMonitor(bus, storage, blockchain_ref=None)
    anomalies = tx_mon.observe_block(curr_block)

    tps_spikes = [a for a in anomalies if a.kind == AnomalyKind.TPS_SPIKE]
    assert len(tps_spikes) == 1
    assert bus.get_buffer("tps").latest >= 200.0


def test_tx_monitor_get_prev_ts_no_false_positive_on_historical_blocks():
    """
    Replaying/syncing historical blocks 60s apart with 250 txs (~4.17 TPS)
    does not fire a false-positive TPS_SPIKE.
    """
    hist_ts = time.time() - 3600  # 1 hour in the past
    prev_block = Block(
        index=9,
        prev_hash="0" * 64,
        transactions=[],
        miner_address="VSD_miner",
        difficulty=1,
        timestamp=int(hist_ts - 60),
    )
    curr_block = SimpleNamespace(
        index=10,
        timestamp=hist_ts,
        transactions=[_DummyTx(f"VSD_sender_{i}") for i in range(250)],
    )

    storage = MagicMock()
    storage.get_block.return_value = prev_block
    storage.mempool_size.return_value = 0
    storage.get_balance.return_value = 1000.0

    bus = MonitorBus()
    tx_mon = TransactionMonitor(bus, storage, blockchain_ref=None)
    anomalies = tx_mon.observe_block(curr_block)

    tps_spikes = [a for a in anomalies if a.kind == AnomalyKind.TPS_SPIKE]
    assert tps_spikes == []


def test_tx_monitor_fund_drain_detects_100_percent_drain_post_block():
    """
    A 100% account drain leaving post-block balance == 0.0 is still detected as FUND_DRAIN.
    """
    block = SimpleNamespace(
        index=15,
        timestamp=time.time(),
        transactions=[_DummyTx("VSD_victim", amount=1000.0, tx_id="drain_tx")],
    )

    storage = MagicMock()
    storage.get_block.return_value = None
    storage.mempool_size.return_value = 0
    storage.get_balance.return_value = 0.0  # post-block balance after 100% drain

    bus = MonitorBus()
    tx_mon = TransactionMonitor(bus, storage, blockchain_ref=None)
    anomalies = tx_mon.observe_block(block)

    drains = [a for a in anomalies if a.kind == AnomalyKind.FUND_DRAIN]
    assert len(drains) == 1


def test_tx_monitor_fund_drain_no_false_positive_on_25_percent_transfer():
    """
    Sending 250 VSD from 1000 VSD (25% < 30% threshold, leaving 750 VSD post-block)
    does not trigger a false-positive FUND_DRAIN.
    """
    block = SimpleNamespace(
        index=16,
        timestamp=time.time(),
        transactions=[_DummyTx("VSD_normal_user", amount=250.0, tx_id="normal_tx")],
    )

    storage = MagicMock()
    storage.get_block.return_value = None
    storage.mempool_size.return_value = 0
    storage.get_balance.return_value = 750.0  # 1000 - 250 post-block

    bus = MonitorBus()
    tx_mon = TransactionMonitor(bus, storage, blockchain_ref=None)
    anomalies = tx_mon.observe_block(block)

    drains = [a for a in anomalies if a.kind == AnomalyKind.FUND_DRAIN]
    assert drains == []


def test_reentrancy_detector_continues_emitting_across_blocks():
    """
    ReentrancyPatternDetector continues emitting on subsequent blocks so
    MultiSignalConfirmationWindow can confirm across MIN_BLOCKS_RESTRICTED=2.
    """
    receipt = {
        "contract_addr": "VSD_contract_vuln",
        "tx_id": "tx_reen_1",
        "logs": [
            {"topics": ["CALL"]},
            {"topics": ["SSTORE"]},
        ],
        "storage_delta": {"slot0": 1},
    }
    storage = MagicMock()
    storage.get_vvm_receipts_for_block.return_value = [receipt]

    det = ReentrancyPatternDetector(storage)
    window = MultiSignalConfirmationWindow()

    # Block 100: first attack detected
    a1 = det.observe_block(SimpleNamespace(index=100))
    assert len(a1) == 1
    window.add_signal(a1[0])

    # Block 101: second attack on the same contract is also detected
    a2 = det.observe_block(SimpleNamespace(index=101))
    assert len(a2) == 1
    window.add_signal(a2[0])

    confirmed, unique_sources, unique_blocks = window.check(
        a2[0], "RESTRICTED", exempt_source_diversity=True
    )
    assert confirmed is True
    assert unique_sources == 1
    assert unique_blocks == 2
