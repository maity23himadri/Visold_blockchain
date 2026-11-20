"""V4 regression tests for Section 47: Hashrate Measurement & Session Lifecycle."""

import time
from types import SimpleNamespace

import pytest

from visold.consensus.hashrate_governor import HashrateGovernor
from visold.mining.engine import MiningEngine
from visold.mining.parallel_miner import ParallelMiner


def _make_engine(network=None):
    blockchain = SimpleNamespace(
        get_difficulty=lambda: 1.0,
        height=lambda: 0,
        latest_block=lambda: None,
        storage=SimpleNamespace(get_block=lambda idx: None),
    )
    consensus = SimpleNamespace()
    wallet = SimpleNamespace(address="VSD_TEST_ADDR", priv=b"\x01" * 32)
    storage = SimpleNamespace(get_role=lambda addr: {"role": "producer"})
    engine = MiningEngine(blockchain, consensus, network, wallet, storage)
    return engine


def test_session_mean_hashrate_resets_on_mining_restart():
    """V4: MiningEngine.start() resets hashes_done so prior-session hashes
    do not inflate session_mean_hashrate or network.hashrate on restart.
    """
    network = SimpleNamespace(peers={}, wallet=None, node_id="node-1", hashrate=0.0)
    engine = _make_engine(network=network)

    engine.start_time = time.time() - 100.0
    engine.hashes_done = 500_000

    engine._mine_loop = lambda: None
    engine._prewarm_loop = lambda: None
    engine._hashrate_report_loop = lambda: None

    ok, msg = engine.start()
    assert ok, msg
    try:
        st = engine.status()
        assert engine.hashes_done == 0
        assert network.hashrate == 0.0
        assert float(st["session_mean_hashrate"].split()[0]) == 0.0
    finally:
        engine.stop()


def test_mining_engine_status_succeeds_when_network_is_none():
    """V4: MiningEngine.status() safely handles network=None."""
    engine = _make_engine(network=None)
    st = engine.status()
    assert isinstance(st, dict)
    assert st["running"] is False


def test_parallel_miner_raw_hashrate_rejects_non_finite_and_resets():
    pm = ParallelMiner()
    assert pm.get_raw_hashrate() == 0.0
    pm._publish_raw_hashrate(1200.0)
    assert pm.get_raw_hashrate() == pytest.approx(1200.0)
    for bad in (0.0, -50.0, float("nan"), float("inf"), float("-inf"), "not-a-num"):
        pm._publish_raw_hashrate(bad)
        assert pm.get_raw_hashrate() == pytest.approx(1200.0)
    pm.reset_raw_hashrate()
    assert pm.get_raw_hashrate() == 0.0


def test_governor_local_measurement_lifecycle():
    gov = HashrateGovernor()
    assert gov.get_local_actual_hashrate() == 0.0
    gov.update_local_actual_hashrate(2500.0)
    assert gov.get_local_actual_hashrate() == pytest.approx(2500.0)
    for bad in (-1.0, float("nan"), float("inf"), float("-inf"), "bad"):
        gov.update_local_actual_hashrate(bad)
        assert gov.get_local_actual_hashrate() == pytest.approx(2500.0)
    gov.reset_local_measurement()
    assert gov.get_local_actual_hashrate() == 0.0
