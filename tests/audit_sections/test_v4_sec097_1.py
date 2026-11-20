"""Section 97 V4 Regression Tests: Storage Batch Proxy Atomicity and Error Handling."""

import asyncio
import sqlite3
import threading
from unittest.mock import MagicMock

import pytest

from visold.state.batch_proxy import _StorageBatchProxy
from visold.storage.storage import Storage


class _FakeAsyncPool:
    def __init__(self, acquire_exc=None, start_exc=None, commit_exc=None):
        self.acquire_exc = acquire_exc
        self.start_exc = start_exc
        self.commit_exc = commit_exc
        self.acquire_calls = 0
        self.release_calls = []
        self.rollback_calls = 0
        self.conn = _FakeAsyncConn(self)

    async def acquire(self):
        self.acquire_calls += 1
        if self.acquire_exc is not None:
            raise self.acquire_exc
        return self.conn

    async def release(self, conn):
        self.release_calls.append(conn)


class _FakeAsyncTx:
    def __init__(self, pool):
        self.pool = pool

    async def start(self):
        if self.pool.start_exc is not None:
            raise self.pool.start_exc

    async def commit(self):
        if self.pool.commit_exc is not None:
            raise self.pool.commit_exc

    async def rollback(self):
        self.pool.rollback_calls += 1


class _FakeAsyncConn:
    def __init__(self, pool):
        self.pool = pool

    def transaction(self):
        return _FakeAsyncTx(self.pool)


class _FakePgRunner:
    def __init__(self, pool):
        self._pool = pool

    def run(self, coro):
        return asyncio.run(coro)


def _make_pgx_storage_stub(pool):
    st = object.__new__(Storage)
    st._pgx_enabled = True
    st._commit_lock = threading.Lock()
    st._pgx_block_local = threading.local()
    st._pg = _FakePgRunner(pool)
    st._pgx_canonical_tip = 0
    st._pgx_canonical_tip_hash = "0" * 64
    st._pgx_restore_rocks_changes = MagicMock()
    st._pgx_resolve_commit_outcome = MagicMock(return_value=False)
    return st


def test_v4_pgx_atomic_block_releases_commit_lock_on_acquire_failure():
    """Fixed: If _pool.acquire() raises in pgx_atomic_block(), _commit_lock is released."""
    pool = _FakeAsyncPool(acquire_exc=RuntimeError("pool exhausted"))
    st = _make_pgx_storage_stub(pool)

    with pytest.raises(RuntimeError, match="pool exhausted"):
        with st.pgx_atomic_block():
            pass

    acquired = st._commit_lock.acquire(blocking=False)
    assert acquired is True, "Expected _commit_lock to be released after _pool.acquire() failure"
    st._commit_lock.release()


def test_v4_pgx_atomic_block_releases_commit_lock_and_conn_on_tx_start_failure():
    """Fixed: If tx.start() raises after _pool.acquire(), both _commit_lock and conn are released."""
    pool = _FakeAsyncPool(start_exc=RuntimeError("tx.start failed"))
    st = _make_pgx_storage_stub(pool)

    with pytest.raises(RuntimeError, match="tx.start failed"):
        with st.pgx_atomic_block():
            pass

    acquired = st._commit_lock.acquire(blocking=False)
    assert acquired is True, "Expected _commit_lock to be released after tx.start() failure"
    st._commit_lock.release()
    assert pool.acquire_calls == 1
    assert len(pool.release_calls) == 1, "Expected acquired connection to be released"


def test_v4_pgx_atomic_block_single_release_on_commit_failure():
    """Fixed: On ambiguous/failed tx.commit(), conn is released once and not rolled back after release."""
    pool = _FakeAsyncPool(commit_exc=RuntimeError("commit lost"))
    st = _make_pgx_storage_stub(pool)

    with pytest.raises(RuntimeError, match="commit lost"):
        with st.pgx_atomic_block() as state:
            state["commit"] = True
            state["pending_tip"] = (1, "a" * 64)

    assert len(pool.release_calls) == 1, f"Expected single release of conn, got {len(pool.release_calls)}"
    assert pool.rollback_calls == 0, "Expected no tx.rollback() after conn release"


def test_v4_remove_contract_re_raises_inside_sqlite_atomic_block(tmp_path):
    """Fixed: remove_contract() propagates failure inside begin_sqlite_atomic_block()
    so the atomic block rolls back cleanly without partial deletes."""
    db_path = str(tmp_path / "visold_test.db")
    st = Storage(db_path=db_path)
    try:
        addr = "V" + "1" * 39
        code_hash = "ab" * 32
        c = st._conn()
        c.execute(
            "INSERT INTO contract_accounts (address, code_hash, storage_root, destroyed) VALUES (?, ?, ?, 0)",
            (addr, code_hash, "cd" * 32),
        )
        c.execute(
            "INSERT INTO contract_storage (contract_addr, slot_key, slot_value) VALUES (?, ?, ?)",
            (addr, "slot1", "val1"),
        )
        c.commit()

        c.execute(
            """CREATE TRIGGER fail_contract_account_delete
               BEFORE DELETE ON contract_accounts
               BEGIN
                   SELECT RAISE(ABORT, 'injected delete failure');
               END;"""
        )
        c.commit()

        st.begin_sqlite_atomic_block()
        with pytest.raises(sqlite3.IntegrityError, match="injected delete failure"):
            st.remove_contract(addr)
        st.rollback_sqlite_atomic_block()

        acct_row = st._conn().execute(
            "SELECT address FROM contract_accounts WHERE address=?", (addr,)
        ).fetchone()
        stor_row = st._conn().execute(
            "SELECT slot_value FROM contract_storage WHERE contract_addr=?", (addr,)
        ).fetchone()
        assert acct_row is not None, "contract_accounts row should still exist after rollback"
        assert stor_row is not None, "contract_storage row should still exist after rollback"
    finally:
        st.close()


def test_batch_proxy_flush_and_sqlite_atomic_rollback(tmp_path):
    """Sanity check: _StorageBatchProxy buffers writes, flushes cleanly, and SQLite atomic rollback undoes them."""
    db_path = str(tmp_path / "visold_proxy.db")
    st = Storage(db_path=db_path)
    try:
        addr_a = "V" + "a" * 39
        addr_b = "V" + "b" * 39
        st.set_balance(addr_a, 1_000_000_000)

        st.begin_sqlite_atomic_block()
        proxy = _StorageBatchProxy(st)
        assert proxy.debit_sat(addr_a, 250_000_000) is True
        proxy.credit_sat(addr_b, 250_000_000)
        proxy.set_nonce(addr_a, 1)
        assert st.get_balance_sat(addr_a) == 1_000_000_000
        assert st.get_balance_sat(addr_b) == 0

        proxy.flush()
        assert st.get_balance_sat(addr_a) == 750_000_000
        assert st.get_balance_sat(addr_b) == 250_000_000
        assert st.get_nonce(addr_a) == 1

        st.rollback_sqlite_atomic_block()
        assert st.get_balance_sat(addr_a) == 1_000_000_000
        assert st.get_balance_sat(addr_b) == 0
        assert st.get_nonce(addr_a) == 0
    finally:
        st.close()
