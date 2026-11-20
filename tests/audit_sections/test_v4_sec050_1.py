"""V4 regression tests for Section 50: Rate Defection Detection and Mining Lifecycle Security."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from visold.consensus.mining_safety import MiningSafetyGuard
from visold.consensus.rate_defection import RateDefectionAuditor
from visold.kernel.config import Config
from visold.storage.storage import Storage


def _configure_rate_audit(monkeypatch, *, auto_slash: bool = True):
    monkeypatch.setattr(Config, "RATE_AUDIT_WINDOW", 10)
    monkeypatch.setattr(Config, "RATE_AUDIT_CADENCE", 5)
    monkeypatch.setattr(Config, "RATE_AUDIT_THRESHOLD", 2.0)
    monkeypatch.setattr(Config, "RATE_AUDIT_CONSECUTIVE", 1)
    monkeypatch.setattr(Config, "RATE_AUDIT_MIN_SHARE", 0.03)
    monkeypatch.setattr(Config, "RATE_AUDIT_VERIFY_TOLERANCE", 0.10)
    monkeypatch.setattr(Config, "AUTO_SLASH_RATE_DEFECTION", auto_slash)
    monkeypatch.setattr(Config, "RATE_SLASH_SCHEDULE", [0.05, 0.25, 0.75])


def test_storage_has_slash_with_rate_and_escalating_slashes_apply(tmp_path, monkeypatch):
    """V4: Storage implements slash_with_rate() and repeated rate-defection
    offenses apply escalating stake reductions.
    """
    _configure_rate_audit(monkeypatch, auto_slash=True)
    storage = Storage(str(tmp_path / "visold.db"))
    assert hasattr(storage, "slash_with_rate")

    storage.set_role("M", "investor", 100.0)
    storage.get_block = lambda idx: SimpleNamespace(index=idx, miner_address="M")

    auditor = RateDefectionAuditor(storage, None)
    caps = {"M": 1.0, "OTHER": 3.0}

    ev1 = {"miner": "M", "window_start": 1, "window_end": 10, "ratio": 4.0, "consecutive": 1}
    ok1, reason1 = auditor.handle_received_evidence(ev1, caps)
    assert ok1 is True and reason1 == "slashed"
    role_after_1 = storage.get_role("M")
    stake_after_1 = role_after_1["stake"]
    assert stake_after_1 == pytest.approx(95.0)

    ev2 = {"miner": "M", "window_start": 11, "window_end": 20, "ratio": 4.0, "consecutive": 1}
    ok2, reason2 = auditor.handle_received_evidence(ev2, caps)
    assert ok2 is True and reason2 == "slashed"
    assert auditor.offense_count("M") == 2
    assert storage.get_role("M")["stake"] < stake_after_1


def test_observe_only_mode_does_not_carry_over_offenses_into_enforced_ban(monkeypatch):
    """V4: Offenses recorded in observe-only mode (AUTO_SLASH_RATE_DEFECTION=False)
    do not carry over to immediately trigger a 100% ban when enforcement is enabled.
    """
    _configure_rate_audit(monkeypatch, auto_slash=False)

    blocks = {h: SimpleNamespace(index=h, miner_address="M") for h in range(1, 51)}
    slashes = []
    storage = SimpleNamespace(
        get_block=lambda h: blocks.get(h),
        slash_with_rate=lambda m, pct: slashes.append((m, pct)),
    )
    auditor = RateDefectionAuditor(storage, None)
    caps = {"M": 1.0, "OTHER": 3.0}

    for idx in range(3):
        ev = {
            "miner": "M",
            "window_start": idx * 10 + 1,
            "window_end": (idx + 1) * 10,
            "ratio": 4.0,
            "consecutive": 1,
        }
        ok, reason = auditor.handle_received_evidence(ev, caps)
        assert ok is True and reason == "observed"
    assert slashes == []

    monkeypatch.setattr(Config, "AUTO_SLASH_RATE_DEFECTION", True)
    ev4 = {"miner": "M", "window_start": 31, "window_end": 40, "ratio": 4.0, "consecutive": 1}
    ok4, reason4 = auditor.handle_received_evidence(ev4, caps)
    assert ok4 is True and reason4 == "slashed"
    assert slashes == [("M", 0.05)]
    assert auditor.is_banned("M") is False


def test_mining_safety_pre_mine_sync_check_wakes_promptly_on_stop_event(monkeypatch):
    """V4: pre_mine_sync_check() uses stop_event.wait(probe) so it returns
    promptly when stop_event is set.
    """
    monkeypatch.setattr(Config, "MINING_SAFETY_ENABLED", True)
    monkeypatch.setattr(Config, "MINING_SYNC_REQUIRED_BEFORE_MINE", True)
    monkeypatch.setattr(Config, "MINING_SYNC_HEIGHT_TOLERANCE", 2)
    monkeypatch.setattr(Config, "MINING_SYNC_MAX_WAIT", 5.0)
    monkeypatch.setattr(Config, "MINING_SYNC_PROBE_INTERVAL", 0.5)
    monkeypatch.setattr(Config, "MINING_FAR_BEHIND_THRESHOLD", 100)

    chain = SimpleNamespace(height=lambda: 1)
    guard = MiningSafetyGuard(chain, best_peer_height_fn=lambda: 10)
    stop_event = threading.Event()

    timer = threading.Timer(0.05, stop_event.set)
    timer.start()
    t0 = time.monotonic()
    proceed, reason = guard.pre_mine_sync_check(stop_event)
    elapsed = time.monotonic() - t0
    timer.join()

    assert proceed is False
    assert reason == "stop event"
    assert elapsed < 0.35
