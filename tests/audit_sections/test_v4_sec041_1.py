"""V4 regression tests for Section 41 (Session 03): Mining Engine Initialization and Shutdown Lifecycle."""

import threading
import time

import pytest

from visold.mining.engine import MiningEngine
from visold.resilience.panic_breaker import PanicCircuitBreaker


class _FakeStorage:
    def __init__(self, role=None):
        self._role = role

    def get_role(self, address):
        return self._role

    def get_block(self, height):
        return None


class _FakeWallet:
    address = "VSD" + "ab" * 20
    priv = 123456789


class _FakeBlockchain:
    def __init__(self):
        self.storage = _FakeStorage()
        self.applied = []

    def latest_block(self):
        return None

    def height(self):
        return 0

    def get_difficulty(self):
        return 1.0

    def apply_block(self, block):
        self.applied.append(block)
        return True, "ok"


class _FakeConsensus:
    def __init__(self):
        self.finalized = []

    def build_candidate_block(self, addr, proof_hex, beta_hex):
        return _FakeBlock()

    def validate_and_finalize(self, block):
        self.finalized.append(block)


class _FakeNetwork:
    def __init__(self):
        self.peers = {}
        self.hashrate = 0.0
        self.broadcasted = []

    def broadcast_block(self, block):
        self.broadcasted.append(block)


class _FakeBlock:
    def __init__(self):
        self.index = 1
        self.prev_hash = "0" * 64
        self.block_hash = "ab" * 32
        self.difficulty = 1.0
        self.nonce = 42
        self.timestamp = int(time.time())
        self._sealed = False

    def seal(self):
        self._sealed = True


def _make_engine(network=None, state_engine=None, role=None):
    storage = _FakeStorage(role=role)
    bc = _FakeBlockchain()
    bc.storage = storage
    consensus = _FakeConsensus()
    wallet = _FakeWallet()
    return MiningEngine(
        blockchain=bc,
        consensus=consensus,
        network=network,
        wallet=wallet,
        storage=storage,
        state_engine=state_engine,
    )


def test_pause_aborts_inflight_mining_and_prevents_block_submission(monkeypatch):
    """V4: pause() signals the work stop event, aborting in-flight _parallel.mine()
    and preventing block sealing/submission while paused.
    """
    net = _FakeNetwork()
    engine = _make_engine(network=net, state_engine=None)

    mine_entered = threading.Event()
    allow_solve = threading.Event()
    stop_was_set_during_mine = []

    def fake_mine(block, stop_event=None, max_hps=0.0, max_hps_provider=None):
        mine_entered.set()
        assert allow_solve.wait(timeout=5.0)
        was_stopped = bool(stop_event and stop_event.is_set())
        stop_was_set_during_mine.append(was_stopped)
        if was_stopped:
            return False
        block.nonce = 7
        return True

    monkeypatch.setattr(engine._parallel, "mine", fake_mine)
    monkeypatch.setattr("visold.mining.engine.vrf_prove", lambda priv, alpha: (b"\x01", b"\x02"))
    monkeypatch.setattr(engine._safety_guard, "pre_mine_sync_check", lambda evt: (True, "already synced"))

    engine._running = True
    engine._paused = False
    engine.start_time = time.time()

    worker = threading.Thread(target=engine._mine_one, daemon=True)
    worker.start()

    assert mine_entered.wait(timeout=5.0), "Mining did not enter _parallel.mine()"

    ok, msg = engine.pause()
    assert ok is True and "paused" in msg.lower()
    assert engine.status()["paused"] is True

    allow_solve.set()
    worker.join(timeout=5.0)
    assert not worker.is_alive()

    assert stop_was_set_during_mine == [True]
    assert len(engine.blockchain.applied) == 0
    assert len(net.broadcasted) == 0
    assert engine.blocks_found == 0


def test_panic_circuit_breaker_pause_stops_inflight_mining(monkeypatch):
    """V4: PanicCircuitBreaker._trip() calls mining.pause(), which aborts
    in-flight _mine_one() so no block is applied.
    """
    net = _FakeNetwork()
    engine = _make_engine(network=net, state_engine=None)
    breaker = PanicCircuitBreaker(mining_engine=engine, state_engine=None)

    mine_entered = threading.Event()
    allow_solve = threading.Event()

    def fake_mine(block, stop_event=None, max_hps=0.0, max_hps_provider=None):
        mine_entered.set()
        assert allow_solve.wait(timeout=5.0)
        return not (stop_event and stop_event.is_set())

    monkeypatch.setattr(engine._parallel, "mine", fake_mine)
    monkeypatch.setattr("visold.mining.engine.vrf_prove", lambda priv, alpha: (b"\x01", b"\x02"))
    monkeypatch.setattr(engine._safety_guard, "pre_mine_sync_check", lambda evt: (True, "already synced"))

    engine._running = True
    engine.start_time = time.time()
    worker = threading.Thread(target=engine._mine_one, daemon=True)
    worker.start()

    assert mine_entered.wait(timeout=5.0)
    breaker._trip("test critical violation")
    assert breaker.is_open is True
    assert engine._paused is True

    allow_solve.set()
    worker.join(timeout=5.0)

    assert len(engine.blockchain.applied) == 0


def test_status_succeeds_when_network_is_none():
    """V4: MiningEngine.status() safely handles network=None without AttributeError."""
    engine = _make_engine(network=None)
    st = engine.status()
    assert isinstance(st, dict)
    assert st["running"] is False


def test_submit_mined_block_succeeds_when_network_is_none():
    """V4: _submit_mined_block() with state_engine=None and network=None
    applies and finalizes the block without crashing on broadcast_block.
    """
    engine = _make_engine(network=None, state_engine=None)
    blk = _FakeBlock()
    ok = engine._submit_mined_block(blk)
    assert ok is True
    assert len(engine.blockchain.applied) == 1
    assert len(engine.consensus.finalized) == 1


def test_investor_role_cannot_start_mining():
    """Verified invariant: investor role is refused on start()."""
    net = _FakeNetwork()
    engine = _make_engine(network=net, role={"role": "investor"})
    ok, msg = engine.start()
    assert ok is False
    assert "investor" in msg.lower()
    assert engine._running is False
