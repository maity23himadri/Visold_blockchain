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


def test_menu_input_holds_lock_used_by_live_renderer(monkeypatch):
    cli = CLI()
    cli._ansi_ok = lambda: False
    cli._full_render = lambda: None
    cli._enter_alt_screen = lambda: None
    cli._leave_alt_screen = lambda: None
    seen = []

    def fake_input(prompt):
        assert cli._ui_lock.locked()
        seen.append(prompt)
        return "test"

    def dispatch(choice):
        assert choice == "test"
        cli._running = False

    monkeypatch.setattr("builtins.input", fake_input)
    cli._dispatch = dispatch

    cli._main_loop()

    assert len(seen) == 1
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
