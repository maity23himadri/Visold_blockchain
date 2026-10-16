"""Regression tests for audit finding VSA-31: the mining start/stop lifecycle.

start() and stop() run for real.  The mining, prewarm and hashrate loops are replaced
with quick stand-ins so the lifecycle logic can be exercised without real mining.
"""

from __future__ import annotations

import threading
import time

from visold.mining.engine import MiningEngine


class _Storage:
    def get_role(self, address):
        return None


class _Wallet:
    address = "VSD" + "ab" * 20


def _engine() -> MiningEngine:
    m = object.__new__(MiningEngine)
    m.storage = _Storage()
    m.wallet = _Wallet()
    m._running = False
    m._paused = False
    m._lifecycle_lock = threading.Lock()
    m._stop_evt = threading.Event()
    m._prewarm_stop = threading.Event()
    m._prewarm_wake = threading.Event()
    m._hr_report_stop = threading.Event()
    m._thread = None
    m._prewarm_thread = None
    m._hr_report_thread = None
    m.start_time = 0.0
    return m


def _quiet_loops(m: MiningEngine, monkeypatch) -> None:
    def mine_loop():
        while m._running:
            time.sleep(0.01)

    def prewarm_loop():
        while not m._prewarm_stop.is_set():
            m._prewarm_wake.wait(0.05)

    def hashrate_loop():
        while not m._hr_report_stop.is_set():
            time.sleep(0.01)

    monkeypatch.setattr(m, "_mine_loop", mine_loop)
    monkeypatch.setattr(m, "_prewarm_loop", prewarm_loop)
    monkeypatch.setattr(m, "_hashrate_report_loop", hashrate_loop)


def test_start_refuses_while_a_previous_mining_loop_is_still_alive(monkeypatch):
    m = _engine()
    _quiet_loops(m, monkeypatch)
    release = threading.Event()
    stuck = threading.Thread(target=release.wait, args=(10,), daemon=True)
    stuck.start()
    m._thread = stuck
    try:
        ok, msg = m.start()
        assert ok is False and "still stopping" in msg, msg
        assert m._thread is stuck, "start() replaced a thread that is still alive"
        assert m._running is False, (
            "the shared running flag was re-enabled under a live loop (VSA-31)")
    finally:
        release.set()
        stuck.join(5)


def test_stop_does_not_report_success_while_a_mining_loop_is_still_alive(monkeypatch):
    m = _engine()
    _quiet_loops(m, monkeypatch)
    release = threading.Event()
    stuck = threading.Thread(target=release.wait, args=(15,), daemon=True)
    stuck.start()
    m._thread = stuck
    m._running = True
    try:
        ok, msg = m.stop()
        assert ok is False and "still stopping" in msg, (
            f"stop() reported {msg!r} while the mining loop was still running (VSA-31)")
    finally:
        release.set()
        stuck.join(5)


def test_normal_stop_then_start_cycles_still_work(monkeypatch):
    m = _engine()
    _quiet_loops(m, monkeypatch)
    assert m.start() == (True, "Mining started")
    assert m.stop() == (True, "Mining stopped")
    assert m.start() == (True, "Mining started")
    assert m.stop() == (True, "Mining stopped")
