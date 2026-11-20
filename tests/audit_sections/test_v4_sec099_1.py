import json
import sqlite3
import struct
import threading
import pytest


from visold.ledger.block import Block
from visold.storage.backends import _PG_SCHEMA_SQL, _k_block, _k_header
from visold.storage.block_database import BlockDatabase
from visold.storage.storage import Storage




class _InMemoryWriteBatch:
    def __init__(self, store: dict):
        self._store = store
        self._ops = []


    def __enter__(self):
        return self


    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            for op, k, v in self._ops:
                if op == "put":
                    self._store[k] = v
                elif op == "delete":
                    self._store.pop(k, None)
        return False


    def put(self, key: bytes, value: bytes):
        self._ops.append(("put", key, value))


    def delete(self, key: bytes):
        self._ops.append(("delete", key, None))




class _InMemoryLevelDB:
    def __init__(self):
        self.data = {}


    def get(self, key: bytes):
        return self.data.get(key)


    def write_batch(self):
        return _InMemoryWriteBatch(self.data)




def _make_block(index: int, prev_hash: str, bhash: str, ts: int = 1000) -> Block:
    return Block(
        index=index,
        transactions=[],
        timestamp=ts + index,
        prev_hash=prev_hash,
        nonce=index + 1,
        difficulty=1.0,
        block_hash=bhash,
        merkle_root="0" * 64,
        state_root="0" * 64,
        miner_address="VSD_MINER",
    )




def _make_inmemory_block_db() -> BlockDatabase:
    db = BlockDatabase.__new__(BlockDatabase)
    db._backend = "leveldb"
    db._path = ":memory:"
    db._db = _InMemoryLevelDB()
    db._lock = threading.Lock()
    db._enabled = True
    return db




def _make_sqlite_storage(tmp_path) -> Storage:
    db_path = str(tmp_path / "visold_test.db")
    st = Storage(db_path=db_path)
    return st




def test_bug1_get_block_timestamps_pgx_queries_nonexistent_blocks_table(tmp_path):
    """Section 99: Storage.get_block_timestamps() in PGX mode queries `blocks`
    table in PostgreSQL, which does not exist in _PG_SCHEMA_SQL (blocks/headers
    live in RocksDB, as used by get_block_consensus_window())."""
    st = _make_sqlite_storage(tmp_path)


    # Set up an in-memory SQLite DB mimicking PostgreSQL's actual schema
    # (_PG_SCHEMA_SQL has no `blocks` table).
    pg_sim = sqlite3.connect(":memory:")
    pg_sim.row_factory = sqlite3.Row
    pg_sim.execute("CREATE TABLE accounts (address TEXT PRIMARY KEY, balance_sat BIGINT)")


    class _FakeRocks:
        def __init__(self):
            self.headers = {
                0: {"idx": 0, "timestamp": 1000, "difficulty": 1.0},
                1: {"idx": 1, "timestamp": 1010, "difficulty": 1.0},
            }


        def get_header(self, idx: int):
            _ = _k_header(idx)
            return self.headers.get(idx)


    st._pgx_enabled = True
    st._rocks = _FakeRocks()
    st._pgx_canonical_tip = 1


    def _fake_pg_fetch(sql, *params):
        sql_sqlite = sql.replace("$1", "?").replace("$2", "?")
        return pg_sim.execute(sql_sqlite, params).fetchall()


    st._pg_fetch = _fake_pg_fetch


    # Verify _PG_SCHEMA_SQL indeed has no `blocks` table
    assert "CREATE TABLE IF NOT EXISTS blocks" not in _PG_SCHEMA_SQL


    # Sibling header-only method works in PGX mode because it reads RocksDB
    assert st.get_block_consensus_window(0, 1) == [(1000, 1.0), (1010, 1.0)]


    assert st.get_block_timestamps(0, 1) == [1000, 1010]




def test_bug2a_get_last_n_blocks_exposes_uncommitted_kv_orphan_blocks(tmp_path):
    """Section 99: Storage.get_last_n_blocks() in BlockDatabase mode bypasses
    the SQLite canonical durability barrier and returns uncommitted KV orphans."""
    st = _make_sqlite_storage(tmp_path)
    st._block_db = _make_inmemory_block_db()


    b0 = _make_block(0, "0" * 64, "h0", ts=1000)
    b1 = _make_block(1, "h0", "h1", ts=1010)
    b2_orphan = _make_block(2, "h1", "h2_orphan", ts=1020)


    st.save_block(b0)
    st.save_block(b1)


    # Simulate crash/rollback after KV put_block(b2_orphan) but before SQLite commit
    assert st._block_db.put_block(b2_orphan) is True


    # SQLite canonical barrier holds for chain_height, get_block, get_block_hash
    assert st.chain_height() == 1
    assert st.get_block(2) is None
    assert st.get_block_hash(2) is None


    # BUG: get_last_n_blocks(1) reads directly from _block_db and returns the orphan!
    last_one = st.get_last_n_blocks(1)
    assert len(last_one) == 1
    assert last_one[0].index == 1
    assert last_one[0].block_hash == "h1"




def test_bug2b_get_last_n_blocks_negative_n_returns_all_blocks_in_sqlite_mode(tmp_path):
    """Section 99: Storage.get_last_n_blocks(-1) in SQLite mode passes -1 to
    SQL `LIMIT ?`, which SQLite interprets as unlimited, returning all blocks."""
    st = _make_sqlite_storage(tmp_path)
    st._block_db._enabled = False


    st.save_block(_make_block(0, "0" * 64, "h0"))
    st.save_block(_make_block(1, "h0", "h1"))
    st.save_block(_make_block(2, "h1", "h2"))


    # Expected: [] (just like PGX mode clamps n = max(0, int(n))).
    # Actual: returns all 3 blocks!
    res = st.get_last_n_blocks(-1)
    assert res == []




def test_bug3_block_database_get_block_by_hash_returns_wrong_block_on_stale_index():
    """Section 99: BlockDatabase.get_block_by_hash() does not verify that the
    fetched block's block_hash matches the requested hash; overwriting a height
    leaves stale h:<old_hash> -> height pointing to the new block."""
    db = _make_inmemory_block_db()
    b1_old = _make_block(1, "h0", "hash_old")
    b1_new = _make_block(1, "h0", "hash_new")


    assert db.put_block(b1_old) is True
    assert db.put_block(b1_new) is True


    # Looking up the replaced hash returns b1_new instead of None!
    fetched = db.get_block_by_hash("hash_old")
    assert fetched is None




def test_bug4_pgx_get_block_and_consensus_window_crash_on_negative_height(tmp_path):
    """Section 99: In PGX mode, Storage.get_block(-1) and
    Storage.get_block_consensus_window(-1, 0) pass negative height to RocksDB
    _u64() (struct.pack('>Q', -1)), raising struct.error instead of returning
    None / clamping to >= 0."""
    st = _make_sqlite_storage(tmp_path)


    class _StrictRocks:
        def get_block(self, idx: int):
            _ = _k_block(idx)
            return None


        def get_header(self, idx: int):
            _ = _k_header(idx)
            return None


    st._pgx_enabled = True
    st._rocks = _StrictRocks()
    st._pgx_canonical_tip = 5


    assert st.get_block(-1) is None
    assert st.get_block_consensus_window(-1, 0) == []