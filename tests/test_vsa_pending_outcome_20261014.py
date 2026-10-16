"""Regression tests for audit finding VSA-23.

A StateEngine timeout means the outcome is unknown: the queued MINE_RESULT keeps
running.  The miner must report it as pending, reconcile the eventual result once,
never broadcast or retry on the strength of a timeout, and keep genuine rejections
distinguishable from timeouts.
"""

from __future__ import annotations

import concurrent.futures as cf
import threading
from types import SimpleNamespace

import visold.mining.engine as mining_engine
from visold.kernel.events import Event, EventType
from visold.mining.engine import MiningEngine
from visold.state.engine import StateEngine


class _Log:
    """Stand-in for the module logger that records (level, message) pairs."""

    def __init__(self):
        self.lines = []

    def warning(self, msg):
        self.lines.append(("warning", msg))

    def info(self, msg):
        self.lines.append(("info", msg))

    def error(self, msg):
        self.lines.append(("error", msg))

    def texts(self, level=None):
        return [m for lv, m in self.lines if level is None or lv == level]


class _FakeStateEngine:
    def __init__(self, result):
        self._result = result
        self.timeouts = []

    def post_sync_detailed(self, event, timeout=None):
        self.timeouts.append(timeout)
        return self._result


class _FakeNetwork:
    def __init__(self):
        self.broadcasts = []

    def broadcast_block(self, block, *args, **kwargs):
        self.broadcasts.append(block.block_hash)


def _miner(result, network):
    miner = object.__new__(MiningEngine)
    miner._state_engine = _FakeStateEngine(result)
    miner.network = network
    miner.consensus = None
    miner.blockchain = None
    wakes = []
    miner.wake_prewarm = lambda: wakes.append(1)
    miner._wakes = wakes
    return miner


def _block(index, digest):
    return SimpleNamespace(index=index, block_hash=digest * 32)


# ── StateEngine: timeout is pending, rejection is done ──────────────────────

def test_state_engine_timeout_is_pending_and_the_queued_event_still_completes(monkeypatch):
    engine = object.__new__(StateEngine)
    engine._running = True
    release = threading.Event()

    def post(event, timeout=None):
        def handle():
            release.wait(5)
            event.future.set_result((True, "applied"))

        threading.Thread(target=handle, daemon=True).start()
        return True

    monkeypatch.setattr(engine, "post", post)
    status, ok, msg, fut = engine.post_sync_detailed(
        Event(EventType.MINE_RESULT, {}), timeout=0.05)

    assert status == "pending", (status, ok, msg)
    assert ok is False and fut is not None
    assert not fut.done(), "a timed-out wait must not look like a completed event"
    release.set()
    assert fut.result(timeout=5) == (True, "applied")


def test_state_engine_rejection_is_reported_as_done_not_pending(monkeypatch):
    engine = object.__new__(StateEngine)
    engine._running = True

    def post(event, timeout=None):
        event.future.set_result((False, "invalid block"))
        return True

    monkeypatch.setattr(engine, "post", post)
    status, ok, msg, _fut = engine.post_sync_detailed(
        Event(EventType.MINE_RESULT, {}), timeout=1.0)

    assert (status, ok, msg) == ("done", False, "invalid block")


def test_post_sync_keeps_its_boolean_contract_for_existing_callers(monkeypatch):
    engine = object.__new__(StateEngine)
    engine._running = True
    release = threading.Event()

    def post(event, timeout=None):
        def handle():
            release.wait(5)
            event.future.set_result((True, "late"))

        threading.Thread(target=handle, daemon=True).start()
        return True

    monkeypatch.setattr(engine, "post", post)
    ok, msg = engine.post_sync(Event(EventType.MINE_RESULT, {}), timeout=0.05)
    release.set()

    assert ok is False and "timeout" in msg


# ── Miner: pending is not a failure; late result is reconciled once ─────────

def test_mining_reports_a_timeout_as_pending_and_reconciles_the_late_result_once(monkeypatch):
    log = _Log()
    monkeypatch.setattr(mining_engine, "log", log)
    block = _block(7, "ab")
    future = cf.Future()
    network = _FakeNetwork()
    miner = _miner(("pending", False, "StateEngine timeout", future), network)

    assert miner._submit_mined_block(block) is None, "a timeout must return pending (None)"
    assert not any("Block apply failed" in t for t in log.texts()), log.lines
    assert any("pending" in t for t in log.texts("warning")), log.lines
    assert network.broadcasts == [], "nothing is broadcast before the outcome is known"

    future.set_result((True, "applied"))   # the queued event completes later
    late = log.texts("info")
    assert len(late) == 1 and "applied" in late[0], log.lines
    assert network.broadcasts == [block.block_hash], "late success is backed up by a broadcast"
    assert miner._wakes == [1], "late success wakes the prewarm loop"


def test_mining_reports_a_late_rejection_once_and_never_as_applied(monkeypatch):
    log = _Log()
    monkeypatch.setattr(mining_engine, "log", log)
    block = _block(9, "ef")
    future = cf.Future()
    network = _FakeNetwork()
    miner = _miner(("pending", False, "StateEngine timeout", future), network)

    assert miner._submit_mined_block(block) is None
    future.set_result((False, "rolled back: invalid state root"))

    rejected = [t for t in log.texts("warning") if "rejected" in t]
    assert len(rejected) == 1 and "rolled back" in rejected[0], log.lines
    assert network.broadcasts == []
    assert miner._wakes == []
    assert log.texts("info") == []


def test_mining_reports_a_genuine_rejection_as_a_failure_not_pending(monkeypatch):
    log = _Log()
    monkeypatch.setattr(mining_engine, "log", log)
    network = _FakeNetwork()
    miner = _miner(("done", False, "invalid block", None), network)

    assert miner._submit_mined_block(_block(8, "cd")) is False
    assert any("Block apply failed: invalid block" in t for t in log.texts("warning")), log.lines
    assert not any("pending" in t for t in log.texts()), log.lines
    assert network.broadcasts == []


def test_mining_applied_block_is_backed_up_and_not_treated_as_pending(monkeypatch):
    log = _Log()
    monkeypatch.setattr(mining_engine, "log", log)
    network = _FakeNetwork()
    block = _block(10, "12")
    miner = _miner(("done", True, "OK", None), network)

    assert miner._submit_mined_block(block) is True
    assert network.broadcasts == [block.block_hash]
    assert not any("Block apply failed" in t for t in log.texts()), log.lines
