"""Diagnostics must be bounded and must never persist terminal input text."""
import json
from pathlib import Path

from visold.cli.input_diagnostics import InputDiagnostics


def _records(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_input_diagnostics_never_log_actual_line_text(tmp_path):
    diag = InputDiagnostics(tmp_path / "input.log")
    read_id = diag.begin_read("line")
    diag.bytes_received(read_id, b"private-user-text\r")
    diag.event("enter_detected", read_id=read_id, delimiter="CR")
    diag.finish_read(read_id, "ok")

    content = diag.path.read_text(encoding="utf-8")
    assert "private-user-text" not in content
    names = [record["event"] for record in _records(diag.path)]
    assert "input_bytes_received" in names
    assert "enter_detected" in names
    assert "input_read_finished" in names


def test_secret_diagnostics_do_not_record_secret_or_length(tmp_path):
    diag = InputDiagnostics(tmp_path / "secret.log")
    read_id = diag.begin_read("secret")
    diag.bytes_received(read_id, b"super-secret-value\r")
    diag.finish_read(read_id, "ok")

    records = _records(diag.path)
    content = diag.path.read_text(encoding="utf-8")
    assert "super-secret-value" not in content
    finished = next(record for record in records if record["event"] == "input_read_finished")
    assert "bytes_read" not in finished


def test_diagnostic_log_rotates_with_bounded_size(tmp_path):
    diag = InputDiagnostics(tmp_path / "bounded.log")
    payload = "x" * 200
    for index in range(1800):
        diag.event("synthetic_test_event", index=index, payload=payload)

    assert diag.path.stat().st_size <= 256 * 1024
    rotated = diag.path.with_name(diag.path.name + ".1")
    assert rotated.exists()
    assert rotated.stat().st_size <= 256 * 1024


def test_tty_reader_logs_enter_metadata_without_recording_line(tmp_path, monkeypatch):
    import os
    import pty

    from visold.cli.interactive import CLI
    import visold.cli.interactive as interactive_module

    diag = InputDiagnostics(tmp_path / "tty.log")
    monkeypatch.setattr(interactive_module, "INPUT_DIAG", diag)
    cli = CLI()
    master_fd, slave_fd = pty.openpty()
    try:
        os.set_blocking(slave_fd, False)
        cli._prepare_raw_tty_input(slave_fd)
        probe = b"harmless-probe-934\r"
        os.write(master_fd, probe)
        read_id = diag.begin_read("line")
        result = cli._read_tty_line(slave_fd, echo_input=False, diag_read_id=read_id)
        diag.finish_read(read_id, "ok")
        assert result == "harmless-probe-934"
        content = diag.path.read_text(encoding="utf-8")
        assert "harmless-probe-934" not in content
        assert '"event":"enter_detected"' in content
        assert '"delimiter":"CR"' in content
    finally:
        os.close(master_fd)
        os.close(slave_fd)


def test_watchdog_captures_stack_for_a_stalled_ui_activity(tmp_path, monkeypatch):
    import time
    import visold.cli.input_diagnostics as diagnostics_module

    monkeypatch.setattr(diagnostics_module, "_WATCHDOG_INTERVAL", 0.01)
    monkeypatch.setattr(diagnostics_module, "_STACK_DUMP_AFTER", 0.0)
    monkeypatch.setattr(diagnostics_module, "_STACK_DUMP_REPEAT", 60.0)
    diag = InputDiagnostics(tmp_path / "watchdog.log")
    activity_id = diag.begin_activity("synthetic_stalled_menu_dispatch")
    try:
        deadline = time.monotonic() + 2.0
        snapshots = []
        while time.monotonic() < deadline:
            snapshots = [
                record for record in _records(diag.path)
                if record["event"] == "ui_activity_watchdog_stack_snapshot"
            ]
            if snapshots:
                break
            time.sleep(0.01)
        assert snapshots, "watchdog should capture a prolonged UI activity"
        assert "stacks" in snapshots[0]
        assert snapshots[0]["kind"] == "synthetic_stalled_menu_dispatch"
    finally:
        diag.finish_activity(activity_id, "test_finished")


def test_termios_mode_repair_is_idempotent_with_integer_vmin_vtime(tmp_path, monkeypatch):
    """Android's termios binding may return VMIN/VTIME as ints, not bytes."""
    import copy
    import os
    import pty
    import termios

    import visold.cli.interactive as interactive_module
    from visold.cli.interactive import CLI

    diag = InputDiagnostics(tmp_path / "termios-types.log")
    monkeypatch.setattr(interactive_module, "INPUT_DIAG", diag)

    master_fd, slave_fd = pty.openpty()
    real_attrs = termios.tcgetattr(slave_fd)
    attrs_state = {"attrs": copy.deepcopy(real_attrs)}

    def as_integer_cc(value):
        return value[0] if isinstance(value, (bytes, bytearray)) else value

    attrs_state["attrs"][6][termios.VMIN] = as_integer_cc(real_attrs[6][termios.VMIN])
    attrs_state["attrs"][6][termios.VTIME] = as_integer_cc(real_attrs[6][termios.VTIME])
    set_calls = []

    def fake_tcgetattr(fd):
        assert fd == slave_fd
        return copy.deepcopy(attrs_state["attrs"])

    def fake_tcsetattr(fd, when, attrs):
        assert fd == slave_fd
        set_calls.append(copy.deepcopy(attrs))
        attrs_state["attrs"] = copy.deepcopy(attrs)

    monkeypatch.setattr(termios, "tcgetattr", fake_tcgetattr)
    monkeypatch.setattr(termios, "tcsetattr", fake_tcsetattr)
    cli = CLI()
    try:
        # First call changes canonical mode into raw mode.
        cli._prepare_raw_tty_input(slave_fd)
        assert len(set_calls) == 1
        assert isinstance(attrs_state["attrs"][6][termios.VMIN], int)
        assert isinstance(attrs_state["attrs"][6][termios.VTIME], int)

        # A stable raw mode must not be re-applied on every 250 ms poll.
        cli._prepare_raw_tty_input(slave_fd)
        cli._prepare_raw_tty_input(slave_fd)
        assert len(set_calls) == 1

        # If an external terminal reset restores canonical mode, repair once.
        attrs_state["attrs"][0] |= termios.ICRNL
        attrs_state["attrs"][3] |= termios.ICANON | termios.ECHO
        cli._prepare_raw_tty_input(slave_fd)
        assert len(set_calls) == 2
        assert not attrs_state["attrs"][3] & termios.ICANON
        assert not attrs_state["attrs"][3] & termios.ECHO

        # Restoration uses the same native VMIN/VTIME representation.
        cli._restore_tty_line_mode(slave_fd)
        assert isinstance(attrs_state["attrs"][6][termios.VMIN], int)
        assert isinstance(attrs_state["attrs"][6][termios.VTIME], int)
        assert attrs_state["attrs"][3] & termios.ICANON
        assert attrs_state["attrs"][3] & termios.ECHO
    finally:
        os.close(master_fd)
        os.close(slave_fd)


def test_fd_diagnostics_include_terminal_identity_without_input_contents():
    import os
    import pty

    import visold.cli.interactive as interactive_module

    master_fd, slave_fd = pty.openpty()
    try:
        details = interactive_module._input_fd_diagnostics(slave_fd)
        assert details["isatty"] is True
        assert details["stat_dev"] >= 0
        assert details["stat_ino"] >= 0
        assert details["stat_rdev"] >= 0
        assert "foreground_pgrp" in details or "foreground_pgrp_error" in details
        assert "session_id" in details or "process_group_error" in details
        assert "winsize" in details or "winsize_error" in details
        serialized = repr(details)
        assert "private-user-text" not in serialized
    finally:
        os.close(master_fd)
        os.close(slave_fd)
