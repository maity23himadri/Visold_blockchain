"""Section 98 Audit Tests: Storage Backend Compatibility & DB Transaction Integrity."""

import asyncio
import copy
import sqlite3
import sys
import threading
from pathlib import Path

import pytest


from visold.ledger.block import Block
from visold.storage.backends import _META_CHAIN_TIP, _META_TIP_HASH, _u64
from visold.storage.sqlite_serialized import (
    _SerializedSQLiteConnection,
    _SQLiteConnectionTransactionBusy,
)
from visold.storage.storage import Storage


class _InMemoryRocks:
    """Minimal faithful in-memory stand-in for _RocksBlockStore."""

    def __init__(self):
        self._blocks = {}
        self._headers = {}
        self._hash_idx = {}
        self._tx_locs = {}
        self._meta = {}

    def new_batch(self):
        return []

    def put_block(self, batch, height, block_dict, header_dict, bhash):
        batch.append(("put_block", height, copy.deepcopy(block_dict), copy.deepcopy(header_dict), bhash))

    def delete_block(self, batch, height, bhash):
        batch.append(("delete_block", height, bhash))

    def put_tx_loc(self, batch, txid, height, tx_index):
        batch.append(("put_tx_loc", txid, height, tx_index))

    def delete_tx_loc(self, batch, txid):
        batch.append(("delete_tx_loc", txid))

    def put_meta(self, batch, name, value_bytes):
        batch.append(("put_meta", name, bytes(value_bytes)))

    def delete_meta(self, batch, name):
        batch.append(("delete_meta", name))

    def commit(self, batch, sync=True):
        for op in batch:
            kind = op[0]
            if kind == "put_block":
                _, h, bdict, hdict, bhash = op
                self._blocks[h] = bdict
                self._headers[h] = hdict
                self._hash_idx[bhash] = h
            elif kind == "delete_block":
                _, h, bhash = op
                self._blocks.pop(h, None)
                self._headers.pop(h, None)
                if bhash:
                    self._hash_idx.pop(bhash, None)
            elif kind == "put_tx_loc":
                _, txid, h, idx = op
                self._tx_locs[txid] = (h, idx)
            elif kind == "delete_tx_loc":
                _, txid = op
                self._tx_locs.pop(txid, None)
            elif kind == "put_meta":
                _, name, val = op
                self._meta[name] = val
            elif kind == "delete_meta":
                _, name = op
                self._meta.pop(name, None)

    def get_block(self, height):
        blk = self._blocks.get(height)
        return copy.deepcopy(blk) if blk is not None else None

    def get_header(self, height):
        hdr = self._headers.get(height)
        return copy.deepcopy(hdr) if hdr is not None else None

    def get_meta(self, name):
        return self._meta.get(name)

    def tip_height(self):
        v = self.get_meta(_META_CHAIN_TIP)
        return int.from_bytes(v, "big") if v else -1

    def iter_heights_desc(self, n: int):
        tip = self.tip_height()
        if tip < 0:
            return []
        return list(range(max(0, tip - n + 1), tip + 1))

    def close(self):
        pass


class _FakePgTx:
    def __init__(self, conn):
        self._conn = conn
        self._snapshot = None

    async def start(self):
        self._snapshot = copy.deepcopy(self._conn.db.tables)

    async def commit(self):
        self._snapshot = None

    async def rollback(self):
        if self._snapshot is not None:
            self._conn.db.tables = self._snapshot
            self._snapshot = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if exc_type is not None:
            await self.rollback()
        else:
            await self.commit()


class _FakePgConn:
    def __init__(self, db):
        self.db = db

    def transaction(self):
        return _FakePgTx(self)

    async def execute(self, sql, *args):
        s = " ".join(sql.split())
        if s.startswith("INSERT INTO node_meta"):
            key, val = args[0], args[1]
            if "DO NOTHING" in s and key in self.db.tables["node_meta"]:
                return "INSERT 0 0"
            self.db.tables["node_meta"][key] = val
            return "INSERT 0 1"
        if s.startswith("DELETE FROM node_meta WHERE key=$1"):
            self.db.tables["node_meta"].pop(args[0], None)
            return "DELETE 1"
        if s.startswith("DELETE FROM transactions WHERE block_idx=$1"):
            h = args[0]
            self.db.tables["transactions"] = {
                k: v for k, v in self.db.tables["transactions"].items() if v["block_idx"] != h
            }
            return "DELETE"
        if s.startswith("DELETE FROM tx_replay_guard WHERE tx_id=$1"):
            self.db.tables["tx_replay_guard"].pop(args[0], None)
            return "DELETE"
        if s.startswith("DELETE FROM vvm_receipts WHERE block_idx=$1"):
            return "DELETE"
        return "OK"

    async def executemany(self, sql, rows):
        for r in rows:
            if "INSERT INTO transactions" in sql:
                self.db.tables["transactions"][r[0]] = {"block_idx": r[1]}
            elif "INSERT INTO tx_replay_guard" in sql:
                self.db.tables["tx_replay_guard"][r[0]] = True
            elif "DELETE FROM tx_replay_guard" in sql:
                self.db.tables["tx_replay_guard"].pop(r[0], None)

    async def fetchrow(self, sql, *args):
        s = " ".join(sql.split())
        if "FROM node_meta WHERE key=$1" in s:
            key = args[0]
            if key in self.db.tables["node_meta"]:
                return {"value": self.db.tables["node_meta"][key]}
            return None
        return None

    async def fetch(self, sql, *args):
        return []


class _FakePgPoolCtx:
    def __init__(self, pool):
        self._pool = pool
        self._conn = None

    async def __aenter__(self):
        self._conn = await self._pool.acquire()
        return self._conn

    async def __aexit__(self, exc_type, exc, tb):
        await self._pool.release(self._conn)


class _FakePgPool:
    def __init__(self, db):
        self._db = db

    def acquire(self):
        class _AwaitableCtx:
            def __init__(self, pool):
                self._pool = pool
                self._ctx = _FakePgPoolCtx(pool)

            def __await__(self):
                async def _acq():
                    return _FakePgConn(self._pool._db)
                return _acq().__await__()

            async def __aenter__(self):
                return await self._ctx.__aenter__()

            async def __aexit__(self, exc_type, exc, tb):
                return await self._ctx.__aexit__(exc_type, exc, tb)

        return _AwaitableCtx(self)

    async def release(self, conn):
        pass


class _FakePgStateDB:
    def __init__(self):
        self.tables = {
            "node_meta": {},
            "transactions": {},
            "tx_replay_guard": {},
        }
        self._pool = _FakePgPool(self)

    def run(self, coro):
        return asyncio.run(coro)

    def close(self):
        pass


class _FakeRedis:
    def set_tip(self, height, bhash, publish=True):
        pass

    def clear_tip(self):
        pass

    def mempool_remove(self, tx_ids):
        pass


def _make_pgx_storage(tmp_path: Path, rocks: _InMemoryRocks, pg: _FakePgStateDB) -> Storage:
    st = Storage.__new__(Storage)
    st.db_path = str(tmp_path / "visold.db")
    st._shared_conn = None
    st._conn_create_lock = threading.Lock()
    st._sqlite_api_lock = threading.RLock()
    st._wal_lock = threading.Lock()
    st._write_count = 0
    st._commit_lock = threading.RLock()
    st._aux_lock = threading.Lock()
    st._pgx_block_local = threading.local()
    st._pgx_canonical_tip = -1
    st._pgx_canonical_tip_hash = ""
    st._backend = "pgx"
    st._pgx_enabled = True
    st._rocks = rocks
    st._pg = pg
    st._cache = _FakeRedis()
    st._aux_path = str(tmp_path / "visold.db.aux")
    st._init_aux_schema()
    return st


def _make_block(index: int, prev_hash: str, bhash: str) -> Block:
    return Block(
        index=index,
        prev_hash=prev_hash,
        timestamp=1700000000 + index,
        transactions=[],
        miner_address="VSD_miner",
        difficulty=1.0,
        nonce=index,
        block_hash=bhash,
        merkle_root="0" * 64,
        state_root="0" * 64,
    )


def test_bug1_init_pgx_canonical_state_leaves_stale_rocks_tip_meta_after_orphan_cleanup(tmp_path):
    """_init_pgx_canonical_state deletes uncommitted RocksDB blocks above PG canonical_tip,
    but never rewinds or deletes _META_CHAIN_TIP / _META_TIP_HASH in RocksDB."""
    rocks = _InMemoryRocks()
    pg = _FakePgStateDB()
    st = _make_pgx_storage(tmp_path, rocks, pg)
    try:
        b0 = _make_block(0, "0" * 64, "hash0")
        b1 = _make_block(1, "hash0", "hash1")
        st.save_block(b0)
        st.save_block(b1)

        # Simulate crash between RocksDB commit and PG commit for block 2
        b2 = _make_block(2, "hash1", "hash2")
        batch = rocks.new_batch()
        rocks.put_block(batch, 2, b2.to_dict(), {"idx": 2, "block_hash": "hash2"}, "hash2")
        rocks.put_meta(batch, _META_CHAIN_TIP, _u64(2))
        rocks.put_meta(batch, _META_TIP_HASH, b"hash2")
        rocks.commit(batch, sync=True)

        st._init_pgx_canonical_state()

        assert rocks.get_block(2) is None
        assert rocks.tip_height() == 1
        assert rocks.get_meta(_META_TIP_HASH) == b"hash1"
        assert 2 not in rocks.iter_heights_desc(5)
    finally:
        st.close()


def test_bug1b_init_pgx_canonical_state_leaves_stale_rocks_tip_meta_when_canonical_tip_is_minus_one(tmp_path):
    """When crash happens during genesis (canonical_tip = -1), _init_pgx_canonical_state
    deletes block 0 but leaves _META_CHAIN_TIP = 0 and _META_TIP_HASH = b'hash0'."""
    rocks = _InMemoryRocks()
    pg = _FakePgStateDB()
    pg.tables["node_meta"]["canonical_tip_height"] = "-1"
    pg.tables["node_meta"]["canonical_tip_hash"] = ""
    st = _make_pgx_storage(tmp_path, rocks, pg)
    try:
        b0 = _make_block(0, "0" * 64, "hash0")
        batch = rocks.new_batch()
        rocks.put_block(batch, 0, b0.to_dict(), {"idx": 0, "block_hash": "hash0"}, "hash0")
        rocks.put_meta(batch, _META_CHAIN_TIP, _u64(0))
        rocks.put_meta(batch, _META_TIP_HASH, b"hash0")
        rocks.commit(batch, sync=True)

        st._init_pgx_canonical_state()

        assert rocks.get_block(0) is None
        assert rocks.tip_height() == -1
        assert rocks.get_meta(_META_TIP_HASH) is None
    finally:
        st.close()


def test_bug2_delete_block_pgx_never_rewinds_pg_canonical_tip_breaking_chain_height_and_restart(tmp_path):
    """Storage.delete_block() in PGX mode rewinds RocksDB tip metadata to idx-1,
    but never updates PG node_meta['canonical_tip_height'/'canonical_tip_hash'] or
    self._pgx_canonical_tip, causing chain_height() to lie and restart to refuse to boot."""
    rocks = _InMemoryRocks()
    pg = _FakePgStateDB()
    st = _make_pgx_storage(tmp_path, rocks, pg)
    try:
        st._init_pgx_canonical_state()
        b0 = _make_block(0, "0" * 64, "hash0")
        b1 = _make_block(1, "hash0", "hash1")
        st.save_block(b0)
        st.save_block(b1)
        assert st.chain_height() == 1
        assert rocks.tip_height() == 1

        assert st.delete_block(1, rollback_tx_ids=[]) is True

        assert rocks.tip_height() == 0
        assert st.chain_height() == 0
        assert pg.tables["node_meta"]["canonical_tip_height"] == "0"
        assert pg.tables["node_meta"]["canonical_tip_hash"] == "hash0"

        st._init_pgx_canonical_state()
        assert st.chain_height() == 0
    finally:
        st.close()


def test_verify_serialized_sqlite_atomic_and_resolve_commit_outcome(tmp_path):
    """Sanity verification for _SerializedSQLiteConnection atomic lifecycle and _pgx_resolve_commit_outcome."""
    raw = sqlite3.connect(":memory:", check_same_thread=False)
    lock = threading.RLock()
    conn = _SerializedSQLiteConnection(raw, lock)
    conn.execute("CREATE TABLE t (k TEXT PRIMARY KEY)")
    conn.commit()

    # Implicit transaction triggers _SQLiteConnectionTransactionBusy on begin_atomic
    conn.execute("INSERT INTO t (k) VALUES ('a')")
    with pytest.raises(_SQLiteConnectionTransactionBusy):
        conn.begin_atomic()
    conn.commit()

    conn.begin_atomic()
    assert conn.atomic_active() is True
    conn.execute("INSERT INTO t (k) VALUES ('b')")
    conn.commit()  # suppressed while atomic
    conn.rollback_atomic()
    assert conn.atomic_active() is False
    rows = conn.execute("SELECT k FROM t").fetchall()
    assert [r[0] for r in rows] == ["a"]
    conn.close()

    # Verify _pgx_resolve_commit_outcome checks both height and hash
    rocks = _InMemoryRocks()
    pg = _FakePgStateDB()
    st = _make_pgx_storage(tmp_path, rocks, pg)
    try:
        pg.tables["node_meta"]["canonical_tip_height"] = "5"
        pg.tables["node_meta"]["canonical_tip_hash"] = "h5"
        assert st._pgx_resolve_commit_outcome(5, "h5") is True
        assert st._pgx_resolve_commit_outcome(5, "other") is False
        assert st._pgx_resolve_commit_outcome(6, "h5") is False
    finally:
        st.close()
