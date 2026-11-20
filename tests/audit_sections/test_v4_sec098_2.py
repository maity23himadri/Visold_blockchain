import asyncio
import threading
import types

import pytest

from visold.storage import backends
from visold.storage.storage import Storage


class _FakePoolFailOnAcquire:
    async def acquire(self):
        raise ConnectionError("simulated pool acquire failure")

    async def release(self, conn):
        pass


class _FakeTxFailOnStart:
    async def start(self):
        raise RuntimeError("simulated tx.start failure")

    async def rollback(self):
        pass

    async def commit(self):
        pass


class _FakeConnFailOnTxStart:
    def transaction(self):
        return _FakeTxFailOnStart()


class _FakePoolFailOnTxStart:
    def __init__(self):
        self.acquired = 0
        self.released = 0

    async def acquire(self):
        self.acquired += 1
        return _FakeConnFailOnTxStart()

    async def release(self, conn):
        self.released += 1


class _FakePgRunner:
    def __init__(self, pool):
        self._pool = pool

    def run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _make_pgx_storage_stub(pool):
    s = Storage.__new__(Storage)
    s._pgx_enabled = True
    s._commit_lock = threading.RLock()
    s._pgx_block_local = threading.local()
    s._pg = _FakePgRunner(pool)
    s._pgx_canonical_tip = -1
    s._pgx_canonical_tip_hash = ""
    return s


def test_pgx_atomic_block_releases_commit_lock_on_acquire_failure():
    """Fixed: pgx_atomic_block() releases _commit_lock when _pool.acquire() fails."""
    s = _make_pgx_storage_stub(_FakePoolFailOnAcquire())

    with pytest.raises(ConnectionError, match="simulated pool acquire failure"):
        with s.pgx_atomic_block():
            pass

    acquired_by_other_thread = threading.Event()

    def _try_acquire():
        if s._commit_lock.acquire(timeout=0.5):
            acquired_by_other_thread.set()
            s._commit_lock.release()

    t = threading.Thread(target=_try_acquire)
    t.start()
    t.join(timeout=1.0)
    assert acquired_by_other_thread.is_set(), (
        "Expected _commit_lock to be released when _start() fails"
    )


def test_pgx_atomic_block_releases_conn_and_lock_on_tx_start_failure():
    """Fixed: If _pool.acquire() succeeds and tx.start() raises, both _commit_lock
    and the acquired PG connection are released."""
    pool = _FakePoolFailOnTxStart()
    s = _make_pgx_storage_stub(pool)

    with pytest.raises(RuntimeError, match="simulated tx.start failure"):
        with s.pgx_atomic_block():
            pass

    assert pool.acquired == 1
    assert pool.released == 1

    acquired_by_other_thread = threading.Event()

    def _try_acquire():
        if s._commit_lock.acquire(timeout=0.5):
            acquired_by_other_thread.set()
            s._commit_lock.release()

    t = threading.Thread(target=_try_acquire)
    t.start()
    t.join(timeout=1.0)
    assert acquired_by_other_thread.is_set()


def test_rocksdict_commit_single_write_with_write_options(monkeypatch):
    """Fixed: When rocksdict exposes WriteOptions and Rdict.write(batch, wo) without
    Rdict.set_write_options(), _RocksBlockStore.commit() writes once with WriteOptions."""

    class _FakeWriteOptions:
        def __init__(self):
            self.sync = False
            self.disable_wal = False

    class _FakeWriteBatch:
        def __init__(self, raw_mode=True):
            self.raw_mode = raw_mode
            self.ops = []

        def put(self, k, v, cf=None):
            self.ops.append(("put", k, v, cf))

    class _FakeRdictNoSetWriteOptions:
        def __init__(self):
            self.write_calls = []
            self.flushed = 0

        def write(self, batch, write_options=None):
            self.write_calls.append((batch, write_options))

        def flush_wal(self, sync=True):
            self.flushed += 1

    fake_rocksdict = types.SimpleNamespace(
        WriteOptions=_FakeWriteOptions,
        WriteBatch=_FakeWriteBatch,
    )
    monkeypatch.setattr(backends, "_rocksdict", fake_rocksdict)

    store = backends._RocksBlockStore.__new__(backends._RocksBlockStore)
    store._write_lock = threading.RLock()
    store._impl = "rocksdict"
    store._db = _FakeRdictNoSetWriteOptions()

    batch = store.new_batch()
    batch.put((None, b"k1"), b"v1")
    store.commit(batch, sync=True)

    assert len(store._db.write_calls) == 1
    assert store._db.write_calls[0][1] is not None
    assert store._db.write_calls[0][1].sync is True
