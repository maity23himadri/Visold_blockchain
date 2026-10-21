"""Regression checks for the one-minute reconnect cadence."""
from pathlib import Path

from visold.kernel.config import Config


def test_reconnect_interval_base_is_one_minute():
    assert Config.RECONNECT_INTERVAL == 60


def test_sync_heartbeat_runs_each_reconnect_pass_not_every_other_pass():
    source = (Path(__file__).parents[1] / "visold" / "network" / "p2p.py").read_text()
    start = source.index("    def _reconnect_loop(self):")
    end = source.index("    def _peer_decay_loop(self):", start)
    body = source[start:end]
    assert "_sync_tick" not in body
    assert "# Chain sync heartbeat" in body
    assert "if selected is not None:" in body
