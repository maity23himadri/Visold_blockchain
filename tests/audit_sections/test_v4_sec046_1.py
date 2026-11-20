"""V4 regression tests for Section 46: Cooperative Mining Yield, Cancellation, and Resource Management."""

import threading
import time
from types import SimpleNamespace

from visold.consensus.mining_safety import MiningSafetyGuard
from visold.kernel.config import Config
from visold.mining.engine import MiningEngine


class _DummyBlockchain:
    def __init__(self, height=0):
        self._height = height
        self.storage = SimpleNamespace(get_block=lambda idx: None)

    def height(self):
        return self._height

    def latest_block(self):
        return SimpleNamespace(index=self._height, block_hash="0" * 64, timestamp=1_700_000_000)

    def get_difficulty(self):
        return 1.0

    def apply_block(self, block):
        return True, "applied"


class _DummyBlock:
    def __init__(self, index=1):
        self.index = index
        self.nonce = 0
        self.block_hash = "ab" * 32
        self.timestamp = 1_700_000_001
        self.difficulty = 1.0
        self.prev_hash = "0" * 64
        self._sealed = False

    def seal(self):
        self._sealed = True


def _make_engine(monkeypatch):
    bc = _DummyBlockchain(height=0)
    consensus = SimpleNamespace(
        build_candidate_block=lambda addr, vp, vb: _DummyBlock(1),
        validate_and_finalize=lambda blk: None,
    )
    network = SimpleNamespace(peers={}, hashrate=0.0, broadcast_block=lambda blk: None)
    wallet = SimpleNamespace(address="VSD" + "ab" * 20, priv=b"\x01" * 32)
    storage = SimpleNamespace(get_role=lambda addr: None)

    monkeypatch.setattr("visold.mining.engine.vrf_prove", lambda priv, alpha: (b"\x01" * 32, b"\x02" * 32))
    engine = MiningEngine(bc, consensus, network, wallet, storage, state_engine=None)
    return engine


def test_pause_cancels_inflight_mining_and_prevents_block_submission(monkeypatch):
    """V4: pause() signals stop_event to abort in-flight _parallel.mine() and
    prevents _mine_one() from sealing or submitting a block.
    """
    engine = _make_engine(monkeypatch)
    engine._running = True

    mine_entered = threading.Event()
    mine_stop_observed = threading.Event()
    submitted_blocks = []

    def fake_mine(block, stop_event=None, max_hps=0.0, max_hps_provider=None):
        mine_entered.set()
        if stop_event is not None and stop_event.wait(timeout=1.5):
            mine_stop_observed.set()
            return False
        block.nonce = 42
        block.block_hash = "cd" * 32
        return True

    monkeypatch.setattr(engine._parallel, "mine", fake_mine)
    monkeypatch.setattr(engine, "_submit_mined_block", lambda blk: submitted_blocks.append(blk) or True)
    monkeypatch.setattr(Config, "MINING_SAFETY_ENABLED", False)

    t = threading.Thread(target=engine._mine_one, daemon=True)
    t.start()
    assert mine_entered.wait(timeout=2.0)

    ok, _msg = engine.pause()
    assert ok is True
    assert engine._paused is True

    t.join(timeout=2.0)
    assert not t.is_alive()

    assert mine_stop_observed.is_set()
    assert len(submitted_blocks) == 0


def test_pre_mine_sync_check_wakes_immediately_on_stop_event(monkeypatch):
    """V4: MiningSafetyGuard.pre_mine_sync_check() uses stop_event.wait(probe)
    so stop_evt.set() wakes it promptly without waiting the full probe interval.
    """
    bc = _DummyBlockchain(height=0)
    guard = MiningSafetyGuard(bc, best_peer_height_fn=lambda: 100)

    monkeypatch.setattr(Config, "MINING_SAFETY_ENABLED", True)
    monkeypatch.setattr(Config, "MINING_SYNC_REQUIRED_BEFORE_MINE", True)
    monkeypatch.setattr(Config, "MINING_SYNC_HEIGHT_TOLERANCE", 3)
    monkeypatch.setattr(Config, "MINING_SYNC_PROBE_INTERVAL", 2.0)
    monkeypatch.setattr(Config, "MINING_SYNC_MAX_WAIT", 60.0)

    stop_evt = threading.Event()
    result_box = []

    def run_check():
        t0 = time.monotonic()
        res = guard.pre_mine_sync_check(stop_evt)
        result_box.append((res, time.monotonic() - t0))

    t = threading.Thread(target=run_check, daemon=True)
    t.start()
    time.sleep(0.1)
    stop_evt.set()
    t.join(timeout=5.0)
    assert not t.is_alive()

    (proceed, reason), elapsed = result_box[0]
    assert proceed is False
    assert reason == "stop event"
    assert elapsed < 1.0
