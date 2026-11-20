import json
import os
import sys
import tempfile
import unittest.mock as mock

import pytest

from visold.ledger.block import Block
from visold.storage.backends import (
    _META_CHAIN_TIP,
    _META_TIP_HASH,
    _P_BLOCK,
    _P_BLOCKHASH,
    _P_HEADER,
    _P_TX,
    _u32,
    _u64,
)
from visold.storage.block_database import BlockDatabase
from visold.storage.storage import Storage


def _make_block(index: int, prev_hash: str, nonce: int = 0) -> Block:
    blk = Block(
        index=index,
        prev_hash=prev_hash,
        timestamp=1700000000 + index * 10,
        transactions=[],
        miner_address="VSD1testminer",
        difficulty=1.0,
        nonce=nonce,
    )
    blk.block_hash = blk.compute_hash()
    return blk


# ── Faithful in-memory LevelDB double for BlockDatabase ──────────────────────

class _FakeLevelDBBatch:
    def __init__(self, store: dict):
        self._store = store
        self._ops = []

    def put(self, key: bytes, value: bytes):
        self._ops.append(("put", key, value))

    def delete(self, key: bytes):
        self._ops.append(("delete", key, None))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            for op, k, v in self._ops:
                if op == "put":
                    self._store[k] = v
                else:
                    self._store.pop(k, None)
        return False


class _FakeLevelDB:
    def __init__(self):
        self._store: dict[bytes, bytes] = {}

    def get(self, key: bytes):
        return self._store.get(key)

    def write_batch(self):
        return _FakeLevelDBBatch(self._store)

    def close(self):
        pass


def _make_memory_block_db() -> BlockDatabase:
    db = BlockDatabase.__new__(BlockDatabase)
    db._backend = "leveldb"
    db._path = ":memory:"
    db._db = _FakeLevelDB()
    db._lock = __import__("threading").Lock()
    db._enabled = True
    return db


# ── Faithful in-memory PGX doubles for Storage ───────────────────────────────

class _FakeRocksBatch:
    def __init__(self):
        self.ops = []

    def put(self, cf_key, value: bytes):
        self.ops.append(("put", cf_key, value))

    def delete(self, cf_key):
        self.ops.append(("delete", cf_key, None))


class _FakeRocksStore:
    def __init__(self):
        self._data = {"default": {}, "blocks": {}, "state": {}}

    def new_batch(self):
        return _FakeRocksBatch()

    def commit(self, batch, sync: bool = True):
        for op, (cf, key), val in batch.ops:
            if op == "put":
                self._data[cf][key] = val
            else:
                self._data[cf].pop(key, None)

    def put_block(self, batch, height, block_dict, header_dict, bhash):
        batch.put(("blocks", _P_BLOCK + _u64(height)), json.dumps(block_dict).encode())
        batch.put(("blocks", _P_HEADER + _u64(height)), json.dumps(header_dict).encode())
        batch.put(("blocks", _P_BLOCKHASH + bhash.encode("ascii")), height.to_bytes(8, "big"))

    def get_block(self, height):
        v = self._data["blocks"].get(_P_BLOCK + _u64(height))
        return json.loads(v.decode()) if v else None

    def get_header(self, height):
        v = self._data["blocks"].get(_P_HEADER + _u64(height))
        return json.loads(v.decode()) if v else None

    def get_block_by_hash(self, bhash):
        v = self._data["blocks"].get(_P_BLOCKHASH + bhash.encode("ascii"))
        return self.get_block(int.from_bytes(v, "big")) if v else None

    def delete_block(self, batch, height, bhash):
        batch.delete(("blocks", _P_BLOCK + _u64(height)))
        batch.delete(("blocks", _P_HEADER + _u64(height)))
        if bhash:
            batch.delete(("blocks", _P_BLOCKHASH + bhash.encode("ascii")))

    def put_tx_loc(self, batch, txid, height, tx_index):
        batch.put(("blocks", _P_TX + txid.encode("ascii")), _u64(height) + _u32(tx_index))

    def delete_tx_loc(self, batch, txid):
        batch.delete(("blocks", _P_TX + txid.encode("ascii")))

    def put_meta(self, batch, name, value_bytes):
        batch.put(("default", b"M:" + name.encode("utf-8")), value_bytes)

    def delete_meta(self, batch, name):
        batch.delete(("default", b"M:" + name.encode("utf-8")))

    def get_meta(self, name):
        return self._data["default"].get(b"M:" + name.encode("utf-8"))

    def tip_height(self) -> int:
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
        self._snap = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if exc_type is not None:
            await self.rollback()
        else:
            await self.commit()
        return False

    async def start(self):
        self._snap = dict(self._conn._db.node_meta)

    async def commit(self):
        self._snap = None

    async def rollback(self):
        if self._snap is not None:
            self._conn._db.node_meta = self._snap
            self._snap = None


class _FakePgConn:
    def __init__(self, db):
        self._db = db

    def transaction(self):
        return _FakePgTx(self)

    async def execute(self, sql: str, *args):
        if "INSERT INTO node_meta" in sql:
            self._db.node_meta[args[0]] = args[1]
        elif "DELETE FROM node_meta WHERE key=$1" in sql:
            self._db.node_meta.pop(args[0], None)

    async def executemany(self, sql: str, rows):
        pass

    async def fetch(self, sql: str, *args):
        return []

    async def fetchrow(self, sql: str, *args):
        if "SELECT value FROM node_meta WHERE key=$1" in sql:
            key = args[0]
            if key in self._db.node_meta:
                return {"value": self._db.node_meta[key]}
        return None


class _FakePoolCtx:
    def __init__(self, db):
        self._db = db

    async def _get(self):
        return _FakePgConn(self._db)

    def __await__(self):
        return self._get().__await__()

    async def __aenter__(self):
        return _FakePgConn(self._db)

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakePgPool:
    def __init__(self, db):
        self._db = db

    def acquire(self):
        return _FakePoolCtx(self._db)

    async def release(self, conn):
        pass

    def acquire_ctx(self):
        return _FakePoolCtx(self._db)


class _FakePgStateDB:
    def __init__(self):
        self.node_meta: dict[str, str] = {}
        self._pool = _FakePgPool(self)

    def run(self, coro):
        import asyncio
        return asyncio.run(coro)

    def close(self):
        pass


class _FakeRedisCache:
    def __init__(self):
        self.r = None
        self.height = None
        self.tip_hash = None

    def set_tip(self, height, bhash, publish: bool = True):
        self.height = height
        self.tip_hash = bhash

    def clear_tip(self):
        self.height = None
        self.tip_hash = None

    def mempool_remove(self, tx_ids):
        pass


def _make_pgx_storage(tmpdir: str) -> Storage:
    db_path = os.path.join(tmpdir, "visold.db")
    with mock.patch("visold.storage.storage._STORAGE_BACKEND", "sqlite"):
        st = Storage(db_path)
    st._rocks = _FakeRocksStore()
    st._pg = _FakePgStateDB()
    st._cache = _FakeRedisCache()
    st._pgx_enabled = True
    st._backend = "pgx"
    st._init_pgx_canonical_state()
    return st


# ── Confirmed Bug Tests ──────────────────────────────────────────────────────

def test_pgx_delete_block_fails_to_rewind_canonical_tip_breaks_reorg_and_restart():
    """
    Finding 1: Storage.delete_block() in PGX mode rewinds RocksDB _META_CHAIN_TIP
    and Redis tip, but NEVER updates node_meta.canonical_tip_height/hash in PG
    or self._pgx_canonical_tip in memory.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        st = _make_pgx_storage(tmpdir)
        b0 = _make_block(0, "0" * 64)
        b1 = _make_block(1, b0.block_hash)
        b2 = _make_block(2, b1.block_hash)
        st.save_block(b0)
        st.save_block(b1)
        st.save_block(b2)

        assert st.chain_height() == 2
        assert st._pg.node_meta["canonical_tip_height"] == "2"

        # Roll back 2 blocks (2-block reorg back to height 0)
        assert st.delete_block(2, rollback_tx_ids=[]) is True
        assert st.delete_block(1, rollback_tx_ids=[]) is True

        assert st._rocks.tip_height() == 0
        assert st.chain_height() == 0
        assert st._pg.node_meta["canonical_tip_height"] == "0"

        alt_b1 = _make_block(1, b0.block_hash, nonce=42)
        st.save_block(alt_b1)
        assert st.chain_height() == 1

        st._init_pgx_canonical_state()
        assert st.chain_height() == 1

        st.close()


def test_init_pgx_canonical_state_leaves_stale_rocks_tip_after_uncommitted_cleanup():
    """
    Finding 2: Storage._init_pgx_canonical_state() deletes uncommitted RocksDB
    blocks above canonical_tip, but never rewinds RocksDB _META_CHAIN_TIP /
    _META_TIP_HASH.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        st = _make_pgx_storage(tmpdir)
        b0 = _make_block(0, "0" * 64)
        b1 = _make_block(1, b0.block_hash)
        st.save_block(b0)
        st.save_block(b1)
        assert st._pg.node_meta["canonical_tip_height"] == "1"

        # Simulate crash after RocksDB committed block 2, before PG committed
        b2 = _make_block(2, b1.block_hash)
        batch = st._rocks.new_batch()
        st._rocks.put_block(batch, 2, b2.to_dict(), {"idx": 2, "block_hash": b2.block_hash}, b2.block_hash)
        st._rocks.put_meta(batch, _META_CHAIN_TIP, _u64(2))
        st._rocks.put_meta(batch, _META_TIP_HASH, b2.block_hash.encode("ascii"))
        st._rocks.commit(batch, sync=True)
        assert st._rocks.tip_height() == 2

        st._init_pgx_canonical_state()
        assert st._rocks.get_block(2) is None
        assert st._rocks.tip_height() == 1
        assert st._rocks.get_meta(_META_TIP_HASH) == b1.block_hash.encode("ascii")

        assert st.delete_block(1, rollback_tx_ids=[]) is True
        assert st._rocks.tip_height() == 0
        st.close()


def test_sqlite_block_db_get_last_n_blocks_exposes_uncommitted_orphan_kv_block():
    """
    Finding 3: Storage.get_last_n_blocks() delegates to BlockDatabase.get_last_n_blocks()
    without checking the SQLite canonical durability barrier, exposing uncommitted
    orphan KV blocks.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "visold.db")
        with mock.patch("visold.storage.storage._STORAGE_BACKEND", "sqlite"):
            st = Storage(db_path)
        st._block_db = _make_memory_block_db()

        b0 = _make_block(0, "0" * 64)
        b1 = _make_block(1, b0.block_hash)
        st.save_block(b0)
        st.save_block(b1)

        # Simulate crash after BlockDatabase.put_block(b2) before SQLite commit
        b2 = _make_block(2, b1.block_hash)
        assert st._block_db.put_block(b2) is True

        # chain_height() and get_block(2) respect the SQLite canonical barrier
        assert st.chain_height() == 1
        assert st.get_block(2) is None

        # get_last_n_blocks(3) leaks the uncommitted orphan block 2
        last_blocks = st.get_last_n_blocks(3)
        assert [b.index for b in last_blocks] == [0, 1]
        assert last_blocks[-1].block_hash == b1.block_hash
        st.close()


def test_block_database_put_block_leaves_stale_hash_index_on_height_overwrite():
    """
    Finding 4: BlockDatabase.put_block() does not remove the previous h:<old_hash>
    secondary index when overwriting an existing height, so get_block_by_hash(old_hash)
    returns the new block with a mismatched hash.
    """
    db = _make_memory_block_db()
    b0 = _make_block(0, "0" * 64)
    b1_a = _make_block(1, b0.block_hash, nonce=1)
    b1_b = _make_block(1, b0.block_hash, nonce=2)
    assert b1_a.block_hash != b1_b.block_hash

    assert db.put_block(b0) is True
    assert db.put_block(b1_a) is True
    assert db.put_block(b1_b) is True

    resolved = db.get_block_by_hash(b1_a.block_hash)
    assert resolved is None
