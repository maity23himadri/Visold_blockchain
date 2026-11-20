import os
import tempfile
import threading
import time

from visold.kernel.events import Event, EventType
from visold.state.batch_proxy import _StorageBatchProxy
from visold.state.engine import StateEngine
from visold.resilience.hardened_core import ImmediateAbort, InvariantViolation
from visold.storage.storage import Storage


class _DummyMempool:
    def __init__(self, on_add=None):
        self._lock = threading.RLock()
        self._pending_tx_ids = set()
        self._on_add = on_add

    def add(self, tx):
        if self._on_add is not None:
            return self._on_add(tx)
        return True, "ok"

    def size(self):
        return 0

    def _purge_expired(self):
        pass

    def get_top(self, n):
        return []


class _DummyBlockchain:
    def __init__(self, on_add=None):
        self.mempool = _DummyMempool(on_add=on_add)
        self._highest_finalized_height = 0

    def height(self):
        return 0


class _DummyGovernance:
    def set_finality_source(self, fn):
        pass

    def on_block_applied(self, block):
        pass

    def shadow_validate(self, block):
        return []


class _DummyStorage:
    def get_meta(self, key):
        return None

    def get_block_hash(self, height):
        return None

    def get_block(self, height):
        return None

    def get_block_by_hash(self, h):
        return None

    def record_block_apply_result(self, height, ok):
        pass

    def prune_old_data(self, height):
        pass


class _DummyTx:
    def __init__(self, tx_id="tx1"):
        self.tx_id = tx_id
        self.sender = "VSD_test_sender"

    def to_dict(self):
        return {"tx_id": self.tx_id, "sender": self.sender}


def test_v4_stop_drains_queued_events_and_resolves_post_sync_future():
    """
    Fixed: StateEngine.stop() drains queued events before exiting _run(),
    resolving pending post_sync_detailed futures cleanly.
    """
    in_first = threading.Event()
    release_first = threading.Event()
    processed = []

    def on_add(tx):
        processed.append(tx.tx_id)
        if tx.tx_id == "tx_1":
            in_first.set()
            release_first.wait(timeout=5.0)
        return True, f"added {tx.tx_id}"

    engine = StateEngine(_DummyBlockchain(on_add=on_add), _DummyGovernance(), _DummyStorage())
    engine.start()

    try:
        assert engine.post(Event(EventType.NEW_TX, {"tx": _DummyTx("tx_1")}))
        assert in_first.wait(timeout=3.0), "Engine did not start processing tx_1"

        sync_result = {}

        def call_post_sync():
            sync_result["res"] = engine.post_sync_detailed(
                Event(EventType.NEW_TX, {"tx": _DummyTx("tx_2")}),
                timeout=2.0,
            )

        t = threading.Thread(target=call_post_sync, daemon=True)
        t.start()

        deadline = time.monotonic() + 2.0
        while engine._queue.qsize() < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert engine._queue.qsize() >= 1, "tx_2 was not queued"

        stop_thread = threading.Thread(target=engine.stop, daemon=True)
        stop_thread.start()
        time.sleep(0.05)
        release_first.set()

        stop_thread.join(timeout=5.0)
        t.join(timeout=5.0)

        assert not engine._thread.is_alive(), "StateEngine thread should have exited"
        status, ok, msg, fut = sync_result["res"]

        assert "tx_2" in processed, "Expected tx_2 to be drained before stop()"
        assert status == "done", f"Expected 'done', got {status!r}"
        assert ok is True
        assert fut is not None and fut.done()
    finally:
        release_first.set()
        if engine._thread and engine._thread.is_alive():
            engine.stop()


def test_v4_post_sync_during_stop_preserves_single_writer():
    """
    Fixed: Calling post_sync_detailed() while StateEngine.stop() is in progress
    never runs _handle() concurrently with the engine thread.
    """
    in_first = threading.Event()
    release_first = threading.Event()
    lock = threading.Lock()
    active_count = 0
    max_concurrent = 0

    def on_add(tx):
        nonlocal active_count, max_concurrent
        with lock:
            active_count += 1
            if active_count > max_concurrent:
                max_concurrent = active_count
        try:
            if tx.tx_id == "tx_inflight":
                in_first.set()
                release_first.wait(timeout=5.0)
            else:
                time.sleep(0.05)
            return True, f"added {tx.tx_id}"
        finally:
            with lock:
                active_count -= 1

    engine = StateEngine(_DummyBlockchain(on_add=on_add), _DummyGovernance(), _DummyStorage())
    engine.start()

    try:
        assert engine.post(Event(EventType.NEW_TX, {"tx": _DummyTx("tx_inflight")}))
        assert in_first.wait(timeout=3.0), "Engine did not enter _handle()"

        stop_thread = threading.Thread(target=engine.stop, daemon=True)
        stop_thread.start()
        time.sleep(0.05)

        sync_result = {}

        def call_concurrent():
            sync_result["res"] = engine.post_sync_detailed(
                Event(EventType.NEW_TX, {"tx": _DummyTx("tx_concurrent")}),
                timeout=3.0,
            )

        caller = threading.Thread(target=call_concurrent, daemon=True)
        caller.start()
        time.sleep(0.05)
        release_first.set()

        stop_thread.join(timeout=5.0)
        caller.join(timeout=5.0)

        status, ok, _msg, _fut = sync_result["res"]
        assert status in ("done", "not_queued")
        assert max_concurrent == 1, (
            f"Expected single-writer _handle() execution during stop(), got max_concurrent={max_concurrent}"
        )
    finally:
        release_first.set()
        if engine._thread and engine._thread.is_alive():
            engine.stop()


def test_core_state_engine_and_batch_proxy_invariants():
    """Verify normal StateEngine single-writer execution and _StorageBatchProxy buffering/flush/restore."""
    seen = []

    def on_add(tx):
        seen.append((tx.tx_id, threading.current_thread().name))
        return True, "ok"

    engine = StateEngine(_DummyBlockchain(on_add=on_add), _DummyGovernance(), _DummyStorage())
    engine.start()
    try:
        for i in range(5):
            status, ok, _msg, fut = engine.post_sync_detailed(
                Event(EventType.NEW_TX, {"tx": _DummyTx(f"tx_{i}")}), timeout=5.0
            )
            assert status in ("done", "not_queued") and fut is not None and fut.done()
        assert len(seen) == 5
        assert all(tname == "state-engine" for _, tname in seen)
    finally:
        engine.stop()

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_visold.db")
        storage = Storage(db_path=db_path)
        try:
            storage.set_balance("addr_a", 100_000_000)
            proxy = _StorageBatchProxy(storage)

            assert proxy.get_balance_sat("addr_a") == 100_000_000
            assert proxy.get_balance_sat("addr_new") == 0

            assert proxy.debit_sat("addr_a", 25_000_000) is True
            proxy.credit_sat("addr_new", 25_000_000)
            assert proxy.get_balance_sat("addr_a") == 75_000_000
            assert proxy.get_balance_sat("addr_new") == 25_000_000
            assert storage.get_balance_sat("addr_a") == 100_000_000
            assert storage.get_balance_sat("addr_new") == 0

            try:
                proxy.credit_sat("addr_a", -1)
                assert False, "Negative credit_sat must raise ValueError"
            except (ValueError, InvariantViolation, ImmediateAbort):
                pass
            assert proxy.debit_sat("addr_a", -1) is False

            proxy.flush()
            assert storage.get_balance_sat("addr_a") == 75_000_000
            assert storage.get_balance_sat("addr_new") == 25_000_000

            proxy.restore_all_touched()
            assert storage.get_balance_sat("addr_a") == 100_000_000
            assert storage.get_balance_sat("addr_new") == 0
        finally:
            storage.close()
