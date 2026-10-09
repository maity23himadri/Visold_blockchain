"""Regression tests for terminal input/render synchronization and worker lifecycle."""
import io
import sys
import threading

from visold.cli.interactive import CLI


class _FakeThread:
    """Controllable thread stand-in for deterministic lifecycle tests."""

    def __init__(self, *, target, daemon, name):
        self.target = target
        self.daemon = daemon
        self.name = name
        self.alive = False

    def start(self):
        self.alive = True

    def join(self, timeout=None):
        # Simulate a worker that does not exit before the join timeout.
        return None

    def is_alive(self):
        return self.alive


def test_menu_uses_shared_canonical_line_reader(monkeypatch):
    cli = CLI()
    cli._ansi_ok = lambda: False
    cli._full_render = lambda: None
    cli._enter_alt_screen = lambda: None
    cli._leave_alt_screen = lambda: None
    seen = []
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO("test\n"))
    monkeypatch.setattr(sys, "stdout", output)

    def dispatch(choice):
        assert choice == "test"
        cli._running = False

    cli._dispatch = dispatch
    cli._main_loop()

    assert "  › " in output.getvalue()
    assert cli._refresh_stop.is_set()
    assert not cli._ui_lock.locked()


def test_refresh_thread_timeout_does_not_allow_overlapping_workers(monkeypatch):
    cli = CLI()
    created = []

    def fake_thread(**kwargs):
        thread = _FakeThread(**kwargs)
        created.append(thread)
        return thread

    monkeypatch.setattr("visold.cli.interactive.threading.Thread", fake_thread)

    cli._start_refresh_thread()
    old_thread = cli._refresh_thread
    assert old_thread is created[0]
    assert old_thread.is_alive()

    cli._stop_refresh_thread()
    assert cli._refresh_stop.is_set()
    assert cli._refresh_thread is old_thread  # timed-out worker remains tracked

    cli._start_refresh_thread()
    assert len(created) == 1  # no overlapping generation
    assert cli._refresh_stop.is_set()  # old worker's stop signal was not cleared

    old_thread.alive = False
    cli._start_refresh_thread()
    assert len(created) == 2
    assert cli._refresh_thread is created[1]
    assert not cli._refresh_stop.is_set()


def test_stopped_refresh_worker_does_not_write_after_input(monkeypatch):
    cli = CLI()
    ready_to_write = threading.Event()

    class Mining:
        @staticmethod
        def status():
            return {"hashrate": "0 H/s", "running": False}

    class Storage:
        @staticmethod
        def get_balance(_address):
            return 0.0

    class Roles:
        @staticmethod
        def get_my_role():
            return None

    class Network:
        @staticmethod
        def active_peer_count():
            return []

    class Mempool:
        @staticmethod
        def size():
            return 0

    class Blockchain:
        mempool = Mempool()

        @staticmethod
        def get_difficulty():
            return 1.0

        @staticmethod
        def height():
            return 0

    class Wallet:
        address = "test-address"

    class Node:
        mining = Mining()
        storage = Storage()
        roles = Roles()
        network = Network()
        blockchain = Blockchain()
        wallet = Wallet()

    cli.node = Node()
    cli._ansi_ok = lambda: True
    cli._layout = {"W": 80, "notif_n": 0, "pa_n": 0}
    cli._up_balance = 1
    cli._up_height = 2
    cli._up_peers = 3
    cli._up_mining = 4
    cli._up_role = 5
    cli._up_notif = []
    cli._up_pa = []
    original_live_line = cli._live_line

    def signal_before_lock(*args, **kwargs):
        result = original_live_line(*args, **kwargs)
        ready_to_write.set()
        return result

    cli._live_line = signal_before_lock
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)

    cli._ui_lock.acquire()
    worker = threading.Thread(target=cli._redraw_live, kwargs={"update_stats": True})
    worker.start()
    try:
        assert ready_to_write.wait(2.0)
        cli._refresh_stop.set()
    finally:
        cli._ui_lock.release()
    worker.join(timeout=2.0)

    assert not worker.is_alive()
    assert stream.getvalue() == ""


def test_resize_redraw_is_abandoned_if_menu_input_is_active(monkeypatch):
    cli = CLI()
    resize_check_reached = threading.Event()
    renders = []
    term_size_calls = 0

    def term_size():
        nonlocal term_size_calls
        term_size_calls += 1
        if term_size_calls >= 2:
            resize_check_reached.set()
        return (80, 24)

    cli._term_size = term_size
    cli._ansi_ok = lambda: True
    cli._resize_pending = True
    cli._full_render = lambda: renders.append("rendered")

    # Model input() holding the UI lock while the app returns to the foreground
    # and the refresh worker notices a terminal resize.
    cli._ui_lock.acquire()
    worker = threading.Thread(target=cli._refresh_loop)
    worker.start()
    try:
        assert resize_check_reached.wait(2.5)
        cli._refresh_stop.set()
    finally:
        cli._ui_lock.release()
    worker.join(timeout=2.0)

    assert not worker.is_alive()
    assert renders == []


def test_line_reader_recovers_a_raw_pty_and_handles_cr_enter(monkeypatch):
    """Model a resumed Android PTY whose line-discipline flags are stale."""
    import os
    import pty
    import termios
    import threading

    master_fd, slave_fd = pty.openpty()
    input_stream = os.fdopen(os.dup(slave_fd), "r", buffering=1)
    prompt_written = threading.Event()
    result = []
    errors = []

    class _PromptStream(io.StringIO):
        def write(self, value):
            written = super().write(value)
            prompt_written.set()
            return written

    output_stream = _PromptStream()
    try:
        # Simulate a stale raw/no-echo mode such as a damaged terminal state.
        attrs = termios.tcgetattr(slave_fd)
        attrs[0] &= ~termios.ICRNL
        attrs[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)
        termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
        monkeypatch.setattr(sys, "stdin", input_stream)
        monkeypatch.setattr(sys, "stdout", output_stream)

        cli = CLI()

        def read_line():
            try:
                result.append(cli._read_input("Choice: "))
            except BaseException as exc:  # surface worker failures in test thread
                errors.append(exc)

        worker = threading.Thread(target=read_line, daemon=True)
        worker.start()
        assert prompt_written.wait(2.0)
        os.write(master_fd, b"2\r")  # Android terminal Enter commonly sends CR.
        worker.join(timeout=2.0)

        assert not worker.is_alive(), "line read remained blocked after CR Enter"
        assert errors == []
        assert result == ["2"]
        repaired = termios.tcgetattr(slave_fd)
        assert repaired[0] & termios.ICRNL
        assert repaired[3] & termios.ICANON
        assert repaired[3] & termios.ECHO
        assert repaired[3] & termios.ISIG
    finally:
        try:
            input_stream.close()
        except Exception:
            pass
        os.close(master_fd)
        os.close(slave_fd)


def test_no_builtin_input_calls_remain_in_cli_methods():
    """All ordinary CLI prompts must use the shared robust line reader."""
    import ast
    from pathlib import Path
    import visold.cli.interactive as interactive_module

    tree = ast.parse(Path(interactive_module.__file__).read_text())
    native_input_calls = [
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "input"
    ]
    assert native_input_calls == []


def test_secret_reader_recovers_on_tty_without_echoing_secret(monkeypatch):
    """Hidden prompts use resume-safe input and never echo the secret itself."""
    import os
    import pty
    import termios
    import threading
    import time

    master_fd, slave_fd = pty.openpty()
    input_stream = os.fdopen(os.dup(slave_fd), "r", buffering=1)
    output = io.StringIO()
    prompt_written = threading.Event()
    result = []
    errors = []

    class _PromptStream(io.StringIO):
        def write(self, value):
            written = super().write(value)
            prompt_written.set()
            return written

    output = _PromptStream()
    try:
        attrs = termios.tcgetattr(slave_fd)
        attrs[0] &= ~termios.ICRNL
        attrs[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)
        termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
        monkeypatch.setattr(sys, "stdin", input_stream)
        monkeypatch.setattr(sys, "stdout", output)
        cli = CLI()

        def read_secret():
            try:
                result.append(cli._read_secret("Secret: "))
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=read_secret, daemon=True)
        worker.start()
        assert prompt_written.wait(2.0)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            current = termios.tcgetattr(slave_fd)
            if not (current[3] & termios.ICANON) and not (current[3] & termios.ECHO):
                break
            time.sleep(0.01)
        else:
            raise AssertionError("secret reader did not enter no-echo TTY mode")

        os.write(master_fd, b"secret-key\r")
        worker.join(timeout=3.0)
        assert not worker.is_alive()
        assert errors == []
        assert result == ["secret-key"]
        assert "Secret: " in output.getvalue()
        assert "secret-key" not in output.getvalue()
        restored = termios.tcgetattr(slave_fd)
        assert restored[3] & termios.ICANON
        assert restored[3] & termios.ECHO
    finally:
        try:
            input_stream.close()
        except Exception:
            pass
        os.close(master_fd)
        os.close(slave_fd)

def test_line_reader_recovers_when_pty_mode_changes_during_blocked_read(monkeypatch):
    """Model Android changing PTY flags after the CLI has begun waiting."""
    import os
    import pty
    import termios
    import threading
    import time

    master_fd, slave_fd = pty.openpty()
    input_stream = os.fdopen(os.dup(slave_fd), "r", buffering=1)
    prompt_written = threading.Event()
    result = []
    errors = []

    class _PromptStream(io.StringIO):
        def write(self, value):
            written = super().write(value)
            prompt_written.set()
            return written

    output_stream = _PromptStream()
    try:
        monkeypatch.setattr(sys, "stdin", input_stream)
        monkeypatch.setattr(sys, "stdout", output_stream)
        cli = CLI()

        def read_line():
            try:
                result.append(cli._read_input("Press Enter: "))
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=read_line, daemon=True)
        worker.start()
        assert prompt_written.wait(2.0)

        # Wait until the new reader has put the PTY into byte-readable mode.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            attrs = termios.tcgetattr(slave_fd)
            if not (attrs[3] & termios.ICANON) and not (attrs[3] & termios.ECHO):
                break
            time.sleep(0.01)
        else:
            raise AssertionError("reader did not enter resilient TTY mode")

        # Simulate the terminal app changing the line discipline while the read
        # is already waiting: canonical+echo, with CR no longer translated.
        attrs = termios.tcgetattr(slave_fd)
        attrs[0] &= ~termios.ICRNL
        attrs[0] &= ~termios.IGNCR
        attrs[3] |= termios.ICANON | termios.ECHO
        termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
        os.write(master_fd, b"resume-test\r")

        worker.join(timeout=3.0)
        assert not worker.is_alive(), "reader remained blocked after mid-read PTY change"
        assert errors == []
        assert result == ["resume-test"]
        restored = termios.tcgetattr(slave_fd)
        assert restored[0] & termios.ICRNL
        assert restored[3] & termios.ICANON
        assert restored[3] & termios.ECHO
    finally:
        try:
            input_stream.close()
        except Exception:
            pass
        os.close(master_fd)
        os.close(slave_fd)


def test_tty_reader_preserves_blank_enter_and_backspace_utf8(monkeypatch):
    """Blank Enter stays distinct from EOF; line editing handles UTF-8 text."""
    import os
    import pty
    import threading

    master_fd, slave_fd = pty.openpty()
    input_stream = os.fdopen(os.dup(slave_fd), "r", buffering=1)
    try:
        monkeypatch.setattr(sys, "stdin", input_stream)
        output = io.StringIO()
        monkeypatch.setattr(sys, "stdout", output)
        cli = CLI()

        # Blank Enter should return an empty string, not raise EOFError.
        first_written = threading.Event()
        original_write = output.write
        def signal_write(value):
            result = original_write(value)
            first_written.set()
            return result
        monkeypatch.setattr(output, "write", signal_write)
        result = []
        t = threading.Thread(target=lambda: result.append(cli._read_input("Prompt: ")), daemon=True)
        t.start()
        assert first_written.wait(2.0)
        os.write(master_fd, b"\r")
        t.join(timeout=2.0)
        assert not t.is_alive()
        assert result == [""]

        # Non-ASCII input and DEL backspace should edit the current line.
        second_written = threading.Event()
        def signal_write2(value):
            result_value = original_write(value)
            second_written.set()
            return result_value
        monkeypatch.setattr(output, "write", signal_write2)
        result2 = []
        t2 = threading.Thread(target=lambda: result2.append(cli._read_input("Prompt 2: ")), daemon=True)
        t2.start()
        assert second_written.wait(2.0)
        os.write(master_fd, "caféx".encode("utf-8") + b"\x7f\r")
        t2.join(timeout=2.0)
        assert not t2.is_alive()
        assert result2 == ["café"]
    finally:
        input_stream.close()
        os.close(master_fd)
        os.close(slave_fd)


def test_tty_reader_preserves_pasted_lines_after_first_enter(monkeypatch):
    """Lines read in one PTY chunk are queued for the next prompt, not lost."""
    import os
    import pty
    import threading

    master_fd, slave_fd = pty.openpty()
    input_stream = os.fdopen(os.dup(slave_fd), "r", buffering=1)
    try:
        monkeypatch.setattr(sys, "stdin", input_stream)
        monkeypatch.setattr(sys, "stdout", io.StringIO())
        cli = CLI()
        prompt_written = threading.Event()
        original_prepare = cli._prepare_raw_tty_input
        def mark_prepare(fd):
            original_prepare(fd)
            prompt_written.set()
        cli._prepare_raw_tty_input = mark_prepare
        os.write(master_fd, b"first\rsecond\r")
        # The new reader can consume the already-pending first line immediately.
        first = cli._read_input("First: ")
        second = cli._read_input("Second: ")
        assert first == "first"
        assert second == "second"
    finally:
        input_stream.close()
        os.close(master_fd)
        os.close(slave_fd)


def test_line_reader_does_not_block_if_termios_changes_between_select_and_read(monkeypatch):
    """A post-select mode change must produce EAGAIN, not a stuck blocking read."""
    import os
    import pty
    import termios
    import threading
    import time
    import visold.cli.interactive as interactive_module

    master_fd, slave_fd = pty.openpty()
    input_stream = os.fdopen(os.dup(slave_fd), "r", buffering=1)
    prompt_written = threading.Event()
    mode_flip = threading.Event()
    result = []
    errors = []

    class _PromptStream(io.StringIO):
        def write(self, value):
            written = super().write(value)
            prompt_written.set()
            return written

    original_read = os.read
    target_fd = input_stream.fileno()
    flipped = False

    def flip_mode_on_read(fd, size):
        nonlocal flipped
        if fd == target_fd and not flipped:
            flipped = True
            attrs = termios.tcgetattr(slave_fd)
            attrs[0] &= ~termios.ICRNL
            attrs[0] &= ~termios.IGNCR
            attrs[3] |= termios.ICANON | termios.ECHO
            termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
            mode_flip.set()
        return original_read(fd, size)

    try:
        monkeypatch.setattr(sys, "stdin", input_stream)
        monkeypatch.setattr(sys, "stdout", _PromptStream())
        monkeypatch.setattr(interactive_module.os, "read", flip_mode_on_read)
        cli = CLI()

        def read_line():
            try:
                result.append(cli._read_input("Prompt: "))
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=read_line, daemon=True)
        worker.start()
        assert prompt_written.wait(2.0)
        # First partial input wakes select while the terminal is raw. The read
        # wrapper then changes the terminal to canonical mode immediately before
        # os.read; a blocking descriptor would risk hanging here until Enter.
        os.write(master_fd, b"resume-race")
        assert mode_flip.wait(2.0)

        def send_enter_after_recovery():
            time.sleep(0.15)
            os.write(master_fd, b"\r")

        sender = threading.Thread(target=send_enter_after_recovery, daemon=True)
        sender.start()
        worker.join(timeout=3.0)
        sender.join(timeout=1.0)

        assert not worker.is_alive(), "reader blocked across the select/read termios race"
        assert errors == []
        assert result == ["resume-race"]
    finally:
        try:
            input_stream.close()
        except Exception:
            pass
        os.close(master_fd)
        os.close(slave_fd)
