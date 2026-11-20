"""V4 regression tests for Audit Section 009: Logging, Notifications, Metrics & Info Leakage."""

import json
import logging
from pathlib import Path

import pytest

from visold.cli.input_diagnostics import InputDiagnostics
from visold.kernel.logging_setup import _QueueHandler
from visold.kernel.metrics import MetricsCollector
from visold.kernel.notifications import (
    _notify_buf,
    _notify_buf_lock,
    _push_block_notif,
    _push_sync_request_notif,
)
from visold.network.message_logger import P2PMessageLogger


def _read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_input_diagnostics_secret_does_not_leak_length_via_read_calls(tmp_path):
    """Secret input diagnostics suppress bytes_read, read_calls, and periodic 8-call activity buckets."""
    diag = InputDiagnostics(tmp_path / "secret_len.log")
    read_id = diag.begin_read("secret")

    secret = b"MySuperSecret123!\r"
    for ch in secret:
        diag.bytes_received(read_id, bytes([ch]))
    diag.heartbeat(read_id)
    diag.finish_read(read_id, "ok")

    records = _read_jsonl(diag.path)
    finished = next(r for r in records if r["event"] == "input_read_finished")
    hb = next(r for r in records if r["event"] == "input_wait_heartbeat")
    activity_events = [r for r in records if r["event"] == "secret_input_activity"]

    assert "bytes_read" not in finished
    assert "read_calls" not in finished
    assert "read_calls" not in hb
    # Only emitted once on Enter (\r), not every 8th keystroke
    assert len(activity_events) == 1
    assert activity_events[0].get("enter_like") is True


def test_metrics_prometheus_type_suffix_median_and_input_validation():
    """Counter # TYPE includes _total, quantile=0.5 emits median, and invalid increments/bools are rejected."""
    mc = MetricsCollector()
    mc.inc("blocks_applied", 5.0)
    for t in [1.0, 1.0, 1.0, 1.0, 100.0]:
        mc.record_block_time(t)

    text = mc.render_prometheus()
    lines = text.splitlines()

    assert "# TYPE visold_blocks_applied_total counter" in lines
    assert "visold_blocks_applied_total 5.0" in lines
    assert "# TYPE visold_blocks_applied counter" not in lines
    assert 'visold_block_time_seconds{quantile="0.5"} 1.000' in lines

    with pytest.raises(ValueError):
        mc.inc("blocks_applied", -10.0)
    with pytest.raises(TypeError):
        mc.set_gauge("bad_bool", True)


def test_p2p_message_logger_sanitizes_control_chars_and_redacts_case_insensitively(caplog):
    """P2PMessageLogger sanitizes newlines/ANSI from msg['type'] and redacts sensitive keys case-insensitively."""

    class DummyPeer:
        peer_id = "peer1234567890"
        host = "127.0.0.1"
        port = 9000

    was_enabled = P2PMessageLogger.is_enabled()
    P2PMessageLogger.enable(verbose=True)
    try:
        with caplog.at_level(logging.INFO, logger="VISOLD"):
            P2PMessageLogger.log_in(
                DummyPeer(),
                {
                    "type": "PING\n[P2P] FORGED_LOG \x1b[2J",
                    "Signature": "deadbeef_secret_sig_1234",
                    "Private_Key": "0xsupersecretprivkey",
                },
                128,
            )
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "PING\n[P2P] FORGED_LOG \x1b[2J" not in joined
        assert "deadbeef_secret_sig_1234" not in joined
        assert "0xsupersecretprivkey" not in joined
        assert "<redacted>" in joined
    finally:
        if not was_enabled:
            P2PMessageLogger.disable()


def test_notifications_and_queue_handler_strip_newlines_and_ansi():
    """_push_block_notif, _push_sync_request_notif, and _QueueHandler strip newlines and ANSI escapes."""
    with _notify_buf_lock:
        _notify_buf.clear()

    _push_block_notif(1, "miner\n\x1b[2J", source="network")
    _push_sync_request_notif("peer\r\n\x1b[31m", 0, 10, 5)

    handler = _QueueHandler()
    record = logging.LogRecord(
        name="VISOLD",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello\n\x1b[2Jworld",
        args=(),
        exc_info=None,
    )
    handler.emit(record)

    with _notify_buf_lock:
        entries = list(_notify_buf)

    assert len(entries) == 3
    for entry in entries:
        assert "\n" not in entry
        assert "\r" not in entry
        assert "\x1b" not in entry
