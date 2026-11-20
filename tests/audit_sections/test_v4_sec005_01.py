"""V4 regression tests for Audit Section 005: Timekeeping, Clock Bounds & Timestamps."""

import time

import pytest

from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.clock import NetworkClock
from visold.resilience.hardened_core import (
    SystemInvariantGate,
    TimestampAnomalyError,
    _NTPClock,
)


def test_network_clock_clamps_unbounded_future_jump():
    """Far-future peer timestamps in NetworkClock are clamped rather than pushing network_time() arbitrarily far."""
    clk = NetworkClock()
    now = int(time.time())
    far_future = now + 10_000_000

    clk.record_peer_timestamp(now, trusted=True)
    clk.record_peer_timestamp(far_future, trusted=True)
    clk.record_peer_timestamp(far_future, trusted=True)

    nt = clk.network_time()
    assert nt < far_future


def test_network_clock_ignores_nan_timestamp():
    """Recording NaN timestamps does not crash NetworkClock.network_time()."""
    clk = NetworkClock()
    now = int(time.time())
    clk.record_block_timestamp(now)
    clk.record_block_timestamp(float("nan"))
    clk.record_block_timestamp(float("nan"))

    nt = clk.network_time()
    assert isinstance(nt, (int, float))
    assert nt > 0


def test_difficulty_validate_timestamp_rejects_negative_when_no_recent():
    """DifficultyEngine.validate_timestamp rejects negative timestamps even when recent_timestamps is empty."""
    ok, msg = DifficultyEngine.validate_timestamp(
        new_ts=-1000,
        recent_timestamps=[],
        network_time=1700000000,
    )
    assert ok is False
    assert "positive" in msg.lower()


def test_system_invariant_gate_nan_raises_timestamp_anomaly_error():
    """SystemInvariantGate.assert_timestamp_valid(NaN) raises TimestampAnomalyError."""
    with pytest.raises(TimestampAnomalyError):
        SystemInvariantGate.assert_timestamp_valid(float("nan"), context="test")


def test_ntp_clock_restart_re_enables_alive():
    """_NTPClock.start() re-enables _alive=True after stop()."""
    ntp = _NTPClock()
    ntp.stop()
    assert ntp._alive is False
    ntp._client = None
    ntp.start()
    try:
        assert ntp._alive is True
    finally:
        ntp.stop()
