"""V4 regression tests for Audit Section 006: Global Event Sequencing & Event Dispatch."""

import concurrent.futures as _futures
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

from visold.kernel.events import Event, EventType
from visold.state.engine import StateEngine


def _make_block(index: int, block_hash: str, prev_hash: str, miner: str = "VSDminer"):
    return SimpleNamespace(
        index=index,
        block_hash=block_hash,
        prev_hash=prev_hash,
        miner_address=miner,
        validator_sigs=[],
        timestamp=1_700_000_000 + index,
        difficulty=1.0,
        transactions=[],
        to_dict=lambda: {
            "index": index,
            "block_hash": block_hash,
            "prev_hash": prev_hash,
            "miner_address": miner,
            "validator_sigs": [],
            "timestamp": 1_700_000_000 + index,
            "difficulty": 1.0,
            "transactions": [],
        },
        validate_pow=lambda: True,
    )


def _make_engine():
    storage = MagicMock()
    storage.get_block.return_value = None
    storage.get_block_hash.return_value = None
    storage.get_block_by_hash.return_value = None
    storage.get_meta.return_value = None

    blockchain = MagicMock()
    blockchain._highest_finalized_height = 0
    blockchain.height.return_value = 5
    blockchain.mempool = MagicMock()
    blockchain.mempool.add.return_value = (True, "ok")
    blockchain.mempool.size.return_value = 0

    governance = MagicMock()
    governance.shadow_validate.return_value = []

    engine = StateEngine(blockchain, governance, storage)
    return engine, blockchain, governance, storage


def test_same_height_fork_win_runs_relay_bft_and_shbs():
    """Winning same-height fork in _handle_new_block triggers relay, receipts, BFT vote, and SHBS."""
    engine, blockchain, governance, storage = _make_engine()
    network = MagicMock()
    network.peers = {"peer_other": SimpleNamespace(connected=True)}
    engine.set_network(network)

    consensus = MagicMock()
    shbs = MagicMock()
    shbs._running = True
    engine._node_ref = SimpleNamespace(consensus=consensus, shbs=shbs)

    parent = _make_block(4, "hash_4", "hash_3")
    old_tip = _make_block(5, "hash_5_old", "hash_4")
    winning_fork = _make_block(5, "hash_5_win", "hash_4")

    canon = {"5": old_tip}

    def get_block(idx):
        if idx == 4:
            return parent
        if idx == 5:
            return canon["5"]
        return None

    def get_block_hash(idx):
        b = get_block(idx)
        return b.block_hash if b else None

    def accept_chain(blocks):
        canon["5"] = winning_fork
        return True, "Reorged to heavier fork"

    storage.get_block.side_effect = get_block
    storage.get_block_hash.side_effect = get_block_hash
    blockchain.accept_chain.side_effect = accept_chain

    ok, _msg = engine._handle_new_block({"block": winning_fork}, "peer_src")
    assert ok is True
    governance.on_block_applied.assert_called_once_with(winning_fork)

    network.broadcast_block.assert_called_once_with(winning_fork, exclude="peer_src")
    network.publish_receipts_for_block.assert_called_once_with(winning_fork)
    consensus.validate_and_finalize.assert_called_once_with(winning_fork)
    shbs.on_block_applied.assert_called_once_with(winning_fork)


def test_same_height_fork_invalid_block_returns_false():
    """Invalid same-height fork candidate returns ok=False from _handle_new_block."""
    engine, blockchain, _governance, storage = _make_engine()
    parent = _make_block(4, "hash_4", "hash_3")
    old_tip = _make_block(5, "hash_5_old", "hash_4")
    bad_fork = _make_block(5, "hash_5_bad", "hash_4")

    storage.get_block.side_effect = lambda idx: parent if idx == 4 else (old_tip if idx == 5 else None)
    storage.get_block_hash.side_effect = lambda idx: "hash_4" if idx == 4 else ("hash_5_old" if idx == 5 else None)
    blockchain.accept_chain.return_value = (False, "Invalid PoW on block #5")

    ok, msg = engine._handle_new_block({"block": bad_fork}, "peer_bad")
    assert ok is False
    assert "Invalid PoW" in msg


def test_state_engine_run_does_not_starve_timer_under_continuous_events():
    """_handle_timer() still fires periodically even when events arrive continuously."""
    engine, _blockchain, _governance, _storage = _make_engine()
    timer_calls = []
    engine._handle_timer = lambda: timer_calls.append(time.monotonic())

    engine.start()
    try:
        for _ in range(11):
            engine.post(Event(EventType.NEW_TX, {"tx": None}))
            time.sleep(0.2)
        assert len(timer_calls) >= 1
    finally:
        engine.stop()


def test_drain_orphans_for_preserves_orphan_source_peer(monkeypatch):
    """_drain_orphans_for passes the orphan's stored source_peer rather than the parent's peer."""
    engine, _blockchain, _governance, _storage = _make_engine()
    child = _make_block(6, "hash_6", "hash_5")
    child_dict = child.to_dict()

    assert engine._stash_orphan(child, child_dict, source_peer="peer_A") is True

    seen_calls = []

    def fake_handle_new_block(payload, source_peer, _drain=True):
        seen_calls.append((payload["block"]["block_hash"], source_peer, _drain))
        return False, "stop"

    monkeypatch.setattr(engine, "_handle_new_block", fake_handle_new_block)
    engine._drain_orphans_for("hash_5", source_peer="peer_B")

    assert seen_calls == [("hash_6", "peer_A", False)]


def test_state_engine_stop_drains_queued_events():
    """stop() drains already-queued events before shutting down."""
    engine, blockchain, _governance, _storage = _make_engine()
    gate = threading.Event()
    started = threading.Event()

    def blocking_add(tx):
        if tx == "blocker":
            started.set()
            gate.wait(timeout=5.0)
        return True, "ok"

    blockchain.mempool.add.side_effect = blocking_add

    engine.start()
    try:
        engine.post(Event(EventType.NEW_TX, {"tx": "blocker"}))
        assert started.wait(timeout=2.0)

        f1 = _futures.Future()
        f2 = _futures.Future()
        engine.post(Event(EventType.NEW_TX, {"tx": "queued_1"}, future=f1))
        engine.post(Event(EventType.NEW_TX, {"tx": "queued_2"}, future=f2))

        threading.Timer(0.05, gate.set).start()
        engine.stop()

        assert f1.done()
        assert f2.done()
    finally:
        gate.set()
        if engine._running:
            engine.stop()


def test_pending_validator_sig_ttl_expires_without_refresh(monkeypatch):
    """_drain_pending_validator_sigs does not refresh created_at when re-queueing, so TTL expires."""
    engine, _blockchain, _governance, _storage = _make_engine()
    now = [1000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])

    payload = {"block_hash": "missing_hash", "validator": "VSDval", "sig": "aa", "pub_hex": "bb"}
    engine._queue_pending_validator_sig(payload, "peer_1")

    now[0] += 25.0
    engine._drain_pending_validator_sigs()

    now[0] += 10.0
    engine._drain_pending_validator_sigs()

    assert len(engine._pending_validator_sigs) == 0
