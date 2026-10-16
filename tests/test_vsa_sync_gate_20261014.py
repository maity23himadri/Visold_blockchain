"""Regression tests for audit finding VSA-30 (mining sync gate)."""

from __future__ import annotations

import threading
import time

from visold.consensus.mining_safety import MiningSafetyGuard
from visold.kernel.config import Config


class _Chain:
    def __init__(self, height):
        self._height = height

    def height(self):
        return self._height


def _configure(monkeypatch):
    monkeypatch.setattr(Config, "MINING_SAFETY_ENABLED", True)
    monkeypatch.setattr(Config, "MINING_SYNC_REQUIRED_BEFORE_MINE", True)
    monkeypatch.setattr(Config, "MINING_SYNC_HEIGHT_TOLERANCE", 1)
    monkeypatch.setattr(Config, "MINING_SYNC_MAX_WAIT", 0.4)
    monkeypatch.setattr(Config, "MINING_SYNC_PROBE_INTERVAL", 0.05)


def test_unverified_high_peer_height_is_withheld_after_the_cap(monkeypatch):
    _configure(monkeypatch)
    chain = _Chain(5)
    guard = MiningSafetyGuard(chain, best_peer_height_fn=lambda: 20)

    proceed, why = guard.pre_mine_sync_check(threading.Event())

    assert proceed is False, f"mining proceeded on an unverified tip (VSA-30): {why}"
    assert guard.sync_stalled is True


def test_unchanged_stalled_episode_does_not_repeat_the_full_wait(monkeypatch):
    _configure(monkeypatch)
    chain = _Chain(5)
    guard = MiningSafetyGuard(chain, best_peer_height_fn=lambda: 20)
    stop = threading.Event()

    first_started = time.time()
    guard.pre_mine_sync_check(stop)
    first_elapsed = time.time() - first_started

    second_started = time.time()
    proceed, why = guard.pre_mine_sync_check(stop)
    second_elapsed = time.time() - second_started

    assert first_elapsed >= 0.35, "the first episode must wait the full cap"
    assert proceed is False
    assert second_elapsed < 0.2, (
        f"an unchanged stalled episode repeated the full {Config.MINING_SYNC_MAX_WAIT}s wait "
        f"(took {second_elapsed:.2f}s, reason {why!r}) (VSA-30)")


def test_convergence_during_the_wait_still_resumes_mining(monkeypatch):
    _configure(monkeypatch)
    state = {"height": 5}

    class _Advancing:
        def height(self):
            state["height"] += 1
            return state["height"]

    guard = MiningSafetyGuard(_Advancing(), best_peer_height_fn=lambda: 12)

    proceed, why = guard.pre_mine_sync_check(threading.Event())

    assert proceed is True and why == "synced", (proceed, why)
    assert getattr(guard, "sync_stalled", False) is False


def test_a_changed_peer_claim_starts_a_new_episode_with_a_full_wait(monkeypatch):
    _configure(monkeypatch)
    claim = {"height": 20}
    chain = _Chain(5)
    guard = MiningSafetyGuard(chain, best_peer_height_fn=lambda: claim["height"])
    stop = threading.Event()
    guard.pre_mine_sync_check(stop)

    claim["height"] = 30
    started = time.time()
    proceed, why = guard.pre_mine_sync_check(stop)
    elapsed = time.time() - started

    assert proceed is False
    assert elapsed >= 0.35, f"a new claim must start a new episode (took {elapsed:.2f}s)"


def test_recovery_during_the_retry_window_resumes_mining_at_once(monkeypatch):
    _configure(monkeypatch)
    chain = _Chain(5)
    guard = MiningSafetyGuard(chain, best_peer_height_fn=lambda: 20)
    stop = threading.Event()
    assert guard.pre_mine_sync_check(stop)[0] is False

    chain._height = 19   # the node catches up within tolerance of the peer claim
    started = time.time()
    proceed, why = guard.pre_mine_sync_check(stop)
    elapsed = time.time() - started

    assert proceed is True and why in ("synced", "already synced"), (proceed, why)
    assert getattr(guard, "sync_stalled", False) is False
    assert elapsed < 0.2, f"recovery waited for the retry window (took {elapsed:.2f}s)"
