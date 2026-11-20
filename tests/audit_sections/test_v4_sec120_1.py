"""Section 120 V4 Regression Tests: Testing Architecture, Pytest Regression, Fault Injection."""

import pytest

from visold.kernel.config import Config
from visold.kernel.events import EventType
from visold.resilience.hardened_core import (
    _HardenedSystemMode,
    _hc_panic_cb,
)
from visold.testing import hardened_verification as hv_mod
from visold.testing import suite as suite_mod


def test_hardened_verification_clears_corruption_timestamps():
    """
    HardenedVerificationSuite.run() clears _hc_panic_cb._corruption_timestamps,
    so a single subsequent corruption event transitions to READ_ONLY rather than SAFE_SHUTDOWN.
    """
    with _hc_panic_cb._mode_lock:
        _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
        _hc_panic_cb._corruption_count = 0
        _hc_panic_cb._corruption_timestamps.clear()
        _hc_panic_cb._subsystems.clear()

    try:
        ok = hv_mod.HardenedVerificationSuite().run()
        assert ok is True

        assert len(_hc_panic_cb._corruption_timestamps) == 0
        assert _hc_panic_cb.mode == _HardenedSystemMode.NORMAL

        # Trigger ONE real corruption-level failure after the suite finishes.
        _hc_panic_cb.record_failure(
            "post_suite_subsystem",
            RuntimeError("single real corruption"),
            corruption_level=True,
        )
        assert _hc_panic_cb.mode == _HardenedSystemMode.READ_ONLY
        assert _hc_panic_cb._corruption_count == 1
    finally:
        with _hc_panic_cb._mode_lock:
            _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
            _hc_panic_cb._corruption_count = 0
            _hc_panic_cb._corruption_timestamps.clear()
            _hc_panic_cb._subsystems.clear()


def test_suite_state_engine_insufficient_balance_not_tautological(monkeypatch):
    """
    TestSuite.run_all() section [13] fails when StateEngine falsely accepts
    an unfunded transaction instead of passing via a tautology.
    """
    class _BrokenStateEngine:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def stop(self):
            pass

        def post_sync(self, event):
            return True, "accepted into mempool"

    monkeypatch.setattr(suite_mod, "StateEngine", _BrokenStateEngine)

    ts = suite_mod.TestSuite()
    ok = ts.run_all()
    assert ok is False
    assert ts._failed == 1


def test_suite_state_engine_posts_mine_result_and_restores_config_on_error(monkeypatch):
    """
    TestSuite.run_all() section [13] posts EventType.MINE_RESULT to StateEngine
    and restores Config.MIN_DIFFICULTY / Config.INITIAL_DIFFICULTY in try/finally on error.
    """
    posted_events = []

    class _SpyStateEngine:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def stop(self):
            pass

        def post_sync(self, event):
            posted_events.append(event.etype)
            return True, "ok"

    monkeypatch.setattr(suite_mod, "StateEngine", _SpyStateEngine)

    orig_min = Config.MIN_DIFFICULTY
    orig_init = Config.INITIAL_DIFFICULTY

    ts = suite_mod.TestSuite()
    ts.run_all()
    assert EventType.MINE_RESULT in posted_events

    class _FailingConsensusEngine:
        def __init__(self, *args, **kwargs):
            pass

        def build_candidate_block(self, addr):
            class _BoomBlock:
                difficulty = 1

                def mine(self):
                    raise RuntimeError("simulated mining failure")

            return _BoomBlock()

    monkeypatch.setattr(suite_mod, "ConsensusEngine", _FailingConsensusEngine)
    try:
        with pytest.raises(RuntimeError, match="simulated mining failure"):
            suite_mod.TestSuite().run_all()
        assert Config.MIN_DIFFICULTY == orig_min
        assert Config.INITIAL_DIFFICULTY == orig_init
    finally:
        Config.MIN_DIFFICULTY = orig_min
        Config.INITIAL_DIFFICULTY = orig_init
