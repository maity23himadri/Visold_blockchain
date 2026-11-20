"""V4 regression tests for Section 41 (Session 04): Mining Engine Lifecycle."""

import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from visold.kernel.config import Config
from visold.mining.engine import MiningEngine


def _make_minimal_engine(network=None, local_height=10):
    storage = MagicMock()
    storage.get_role.return_value = None
    storage.get_block.return_value = None

    blockchain = MagicMock()
    blockchain.height.return_value = local_height
    blockchain.get_difficulty.return_value = 1.0
    tip = SimpleNamespace(index=local_height, block_hash="a" * 64)
    blockchain.latest_block.return_value = tip

    consensus = MagicMock()
    candidate = SimpleNamespace(
        index=local_height + 1,
        prev_hash="a" * 64,
        block_hash="b" * 64,
        difficulty=1.0,
        nonce=0,
        timestamp=int(time.time()),
        _sealed=True,
    )
    consensus.build_candidate_block.return_value = candidate

    wallet = MagicMock()
    wallet.address = "VSD_TEST_ADDR"
    wallet.priv = b"\x01" * 32

    engine = MiningEngine(
        blockchain=blockchain,
        consensus=consensus,
        network=network,
        wallet=wallet,
        storage=storage,
        state_engine=None,
    )
    return engine, blockchain, consensus


def test_pause_interrupts_active_mining():
    """V4: MiningEngine.pause() signals the active ParallelMiner.mine() stop_event
    so in-flight PoW hashing aborts promptly.
    """
    network = SimpleNamespace(peers={}, wallet=MagicMock(), node_id="n1", hashrate=0.0)
    engine, _, _ = _make_minimal_engine(network=network)

    mine_entered = threading.Event()
    mine_saw_stop_evt = threading.Event()
    mine_completed_uninterrupted = threading.Event()

    def fake_mine(block, stop_event=None, max_hps=0.0, max_hps_provider=None):
        mine_entered.set()
        if stop_event is not None and stop_event.wait(timeout=1.5):
            mine_saw_stop_evt.set()
            return False
        mine_completed_uninterrupted.set()
        return False

    engine._parallel.mine = fake_mine
    import visold.mining.engine as eng_mod

    orig_vrf = eng_mod.vrf_prove
    eng_mod.vrf_prove = lambda priv, alpha: (b"\x02" * 32, b"\x03" * 32)
    try:
        ok, _ = engine.start()
        assert ok is True
        assert mine_entered.wait(timeout=3.0), "Mining loop did not enter _parallel.mine()"

        p_ok, _ = engine.pause()
        assert p_ok is True
        assert engine._paused is True

        assert mine_saw_stop_evt.wait(timeout=2.0), (
            "Expected pause() to set stop_event and abort in-flight ParallelMiner.mine()"
        )
        assert not mine_completed_uninterrupted.is_set()
    finally:
        engine.stop()
        eng_mod.vrf_prove = orig_vrf


def test_stop_returns_promptly_during_pre_mine_sync_check(monkeypatch):
    """V4: MiningSafetyGuard.pre_mine_sync_check() uses stop_event.wait(probe)
    so MiningEngine.stop() wakes it immediately and completes cleanly.
    """
    monkeypatch.setattr(Config, "MINING_SAFETY_ENABLED", True)
    monkeypatch.setattr(Config, "MINING_SYNC_REQUIRED_BEFORE_MINE", True)
    monkeypatch.setattr(Config, "MINING_SYNC_PROBE_INTERVAL", 5.5)
    monkeypatch.setattr(Config, "MINING_SYNC_MAX_WAIT", 60.0)

    peer = SimpleNamespace(connected=True, verified_chain_height=20, advertised_chain_height=20)
    network = SimpleNamespace(peers={"p1": peer}, wallet=MagicMock(), node_id="n1", hashrate=0.0)
    engine, _, _ = _make_minimal_engine(network=network, local_height=10)

    entered_wait = threading.Event()
    orig_pre_mine = engine._safety_guard.pre_mine_sync_check

    def wrapped_pre_mine(stop_event):
        threading.Timer(0.05, entered_wait.set).start()
        return orig_pre_mine(stop_event)

    engine._safety_guard.pre_mine_sync_check = wrapped_pre_mine

    ok, _ = engine.start()
    assert ok is True
    assert entered_wait.wait(timeout=3.0)

    t0 = time.monotonic()
    stop_ok, _stop_msg = engine.stop()
    elapsed = time.monotonic() - t0
    assert stop_ok is True
    assert elapsed < 2.5


def test_status_succeeds_when_network_is_none():
    """V4: MiningEngine.status() works cleanly when network=None."""
    engine, _, _ = _make_minimal_engine(network=None)
    st = engine.status()
    assert isinstance(st, dict)
    assert st["running"] is False
