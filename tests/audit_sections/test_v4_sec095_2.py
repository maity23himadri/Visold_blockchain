import concurrent.futures as _futures
import threading
import time
from unittest.mock import MagicMock

from visold.kernel.events import Event, EventType
from visold.state.engine import StateEngine


def _make_engine():
    blockchain = MagicMock()
    blockchain._highest_finalized_height = 0
    blockchain.height.return_value = 0
    governance = MagicMock()
    storage = MagicMock()
    return StateEngine(blockchain=blockchain, governance=governance, storage=storage)


def test_stop_drains_queued_events_and_resolves_post_sync_futures():
    """
    Fixed: StateEngine.stop() drains already-queued events before exiting _run(),
    resolving post_sync_detailed() futures cleanly.
    """
    engine = _make_engine()
    in_e0 = threading.Event()
    release_e0 = threading.Event()
    handled = []

    def fake_handle(event):
        if event.payload.get("tag") == "e0":
            in_e0.set()
            release_e0.wait(timeout=5.0)
        handled.append(event.payload.get("tag"))
        return True, "ok"

    engine._handle = fake_handle
    engine.start()
    try:
        assert engine.post(Event(EventType.NEW_TX, {"tag": "e0"}))
        assert in_e0.wait(timeout=2.0)

        sync_result = {}

        def call_sync():
            sync_result["res"] = engine.post_sync_detailed(
                Event(EventType.NEW_TX, {"tag": "e1"}), timeout=2.0
            )

        caller = threading.Thread(target=call_sync)
        caller.start()

        deadline = time.monotonic() + 2.0
        while engine._queue.qsize() < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert engine._queue.qsize() >= 1

        def do_stop():
            release_e0.set()
            engine.stop()

        stopper = threading.Thread(target=do_stop)
        stopper.start()
        stopper.join(timeout=5.0)
        caller.join(timeout=5.0)

        assert not engine._thread.is_alive()
        assert "e0" in handled
        assert "e1" in handled
        status, ok, _msg, fut = sync_result["res"]
        assert status == "done"
        assert ok is True
        assert fut is not None and fut.done()
    finally:
        release_e0.set()
        if engine._running:
            engine.stop()


def test_stop_and_stopped_dispatch_direct_preserves_single_writer():
    """
    Fixed: Calling post_sync_detailed() concurrently with stop() preserves
    single-writer execution without concurrent _handle() calls.
    """
    engine = _make_engine()
    in_e0 = threading.Event()
    release_e0 = threading.Event()

    lock = threading.Lock()
    active_writers = 0
    max_concurrent_writers = 0

    def fake_handle(event):
        nonlocal active_writers, max_concurrent_writers
        tag = event.payload.get("tag")
        with lock:
            active_writers += 1
            max_concurrent_writers = max(max_concurrent_writers, active_writers)
        try:
            if tag == "e0":
                in_e0.set()
                release_e0.wait(timeout=5.0)
            else:
                time.sleep(0.05)
            return True, "ok"
        finally:
            with lock:
                active_writers -= 1

    engine._handle = fake_handle
    engine.start()
    try:
        assert engine.post(Event(EventType.NEW_TX, {"tag": "e0"}))
        assert in_e0.wait(timeout=2.0)

        stopper = threading.Thread(target=engine.stop)
        stopper.start()
        time.sleep(0.05)

        caller_res = {}

        def call_e1():
            caller_res["res"] = engine.post_sync_detailed(
                Event(EventType.NEW_TX, {"tag": "e1"}), timeout=2.0
            )

        caller = threading.Thread(target=call_e1)
        caller.start()
        time.sleep(0.05)
        release_e0.set()

        stopper.join(timeout=5.0)
        caller.join(timeout=5.0)

        assert max_concurrent_writers == 1
        assert caller_res["res"][0] in ("done", "not_queued")
    finally:
        release_e0.set()


def test_double_start_is_idempotent_single_writer_thread():
    """
    Fixed: StateEngine.start() is idempotent when the writer thread is already alive.
    """
    engine = _make_engine()
    lock = threading.Lock()
    active_writers = 0
    max_concurrent_writers = 0

    def fake_handle(event):
        nonlocal active_writers, max_concurrent_writers
        with lock:
            active_writers += 1
            max_concurrent_writers = max(max_concurrent_writers, active_writers)
        try:
            time.sleep(0.05)
            return True, "ok"
        finally:
            with lock:
                active_writers -= 1

    engine._handle = fake_handle
    engine.start()
    t1 = engine._thread
    engine.start()
    t2 = engine._thread
    try:
        assert t1 is t2
        assert t1.is_alive()

        f1 = _futures.Future()
        f2 = _futures.Future()
        engine.post(Event(EventType.NEW_TX, {"tag": "a"}, future=f1))
        engine.post(Event(EventType.NEW_TX, {"tag": "b"}, future=f2))

        assert f1.result(timeout=3.0) == (True, "ok")
        assert f2.result(timeout=3.0) == (True, "ok")
        assert max_concurrent_writers == 1
    finally:
        engine.stop()
