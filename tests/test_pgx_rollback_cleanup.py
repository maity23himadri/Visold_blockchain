"""Regression tests for PGX canonical rollback cleanup.

These tests intentionally use a reduced PGX auxiliary SQLite schema: the aux
store is a shadow/raw-SQL compatibility store and does not own canonical VVM
receipts.  The regression protects against reintroducing cross-backend receipt
cleanup or making an aux shadow failure abort canonical rollback.
"""
from __future__ import annotations

import asyncio
import sqlite3
import threading

from visold.storage.storage import Storage


class _AsyncContext:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakePGConnection:
    def transaction(self):
        return _AsyncContext(object())

    async def execute(self, _sql, *_args):
        return "DELETE 1"

    async def executemany(self, _sql, _args):
        return None


class _FakePGPool:
    def __init__(self):
        self.connection = _FakePGConnection()

    def acquire(self):
        return _AsyncContext(self.connection)


class _FakePG:
    def __init__(self):
        self._pool = _FakePGPool()

    def run(self, coro):
        return asyncio.run(coro)


class _FakeBatch:
    pass


class _FakeRocks:
    def __init__(self):
        self.committed = False
        self.operations = []

    def get_block(self, height):
        if height == 1:
            return {
                "block_hash": "h1",
                "transactions": [{"tx_id": "tx1"}],
            }
        if height == 0:
            return {"block_hash": "h0", "transactions": []}
        return None

    def tip_height(self):
        return 1

    def new_batch(self):
        return _FakeBatch()

    def delete_block(self, _batch, height, bhash):
        self.operations.append(("delete_block", height, bhash))

    def delete_tx_loc(self, _batch, tx_id):
        self.operations.append(("delete_tx_loc", tx_id))

    def put_meta(self, _batch, name, value):
        self.operations.append(("put_meta", name, value))

    def delete_meta(self, _batch, name):
        self.operations.append(("delete_meta", name))

    def commit(self, _batch, sync=True):
        assert sync is True
        self.committed = True


class _FakeCache:
    def __init__(self):
        self.tip_updates = []
        self.cleared = False

    def set_tip(self, height, bhash, publish=True):
        self.tip_updates.append((height, bhash, publish))

    def clear_tip(self):
        self.cleared = True


def _make_pgx_storage(conn):
    st = Storage.__new__(Storage)
    st._pgx_enabled = True
    st._rocks = _FakeRocks()
    st._pg = _FakePG()
    st._cache = _FakeCache()
    st._commit_lock = threading.RLock()
    st._aux_lock = threading.Lock()
    st.rebuild_name_claims_from_transactions = lambda _height: None
    st._conn = lambda: conn
    return st


def _aux_shadow_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE transactions (tx_id TEXT PRIMARY KEY, block_idx INTEGER)")
    conn.execute("CREATE TABLE blocks (idx INTEGER PRIMARY KEY, block_hash TEXT)")
    conn.execute("CREATE TABLE node_meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("INSERT INTO transactions VALUES ('tx1', 1)")
    conn.execute("INSERT INTO blocks VALUES (1, 'h1')")
    conn.execute("INSERT INTO node_meta VALUES ('block_apply:1', 'ok')")
    conn.commit()
    return conn


def test_pgx_delete_block_does_not_require_aux_vvm_receipts_table():
    conn = _aux_shadow_db()
    st = _make_pgx_storage(conn)

    assert st.delete_block(1, rollback_tx_ids=["tx1"]) is True
    assert st._rocks.committed is True
    assert st._cache.tip_updates == [(0, "h0", False)]

    assert conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM node_meta").fetchone()[0] == 0


def test_pgx_delete_block_aux_shadow_failure_is_nonfatal():
    class _BrokenAux:
        def execute(self, *_args, **_kwargs):
            raise sqlite3.OperationalError("aux unavailable")

        def commit(self):
            raise AssertionError("commit must not be reached")

        def rollback(self):
            self.rolled_back = True

    st = _make_pgx_storage(_BrokenAux())

    assert st.delete_block(1, rollback_tx_ids=["tx1"]) is True
    assert st._rocks.committed is True
    assert st._cache.tip_updates == [(0, "h0", False)]
