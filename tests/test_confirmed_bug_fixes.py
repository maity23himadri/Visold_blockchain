from __future__ import annotations

import os
import tempfile

from visold.consensus.slashing import SlashingEvidenceProtocol
from visold.crypto.ecc import sig_to_hex
from visold.crypto.hashing import hash_obj
from visold.rollup.l2_state import Layer2State
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op
from visold.wallet.wallet import Wallet


class _Tx:
    gas_price = 0.0
    tx_id = "a" * 64


def test_l2_rollback_preserves_bridge_mutation_after_last_batch():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "l2.db"))
        l2 = Layer2State(st)
        user = Wallet.generate().address
        assert l2.L2_deposit(user, 100, l1_height=10, l1_block_hash="h10")[0]
        root10 = l2.root()
        # A second bridge mutation occurs after the last rollup checkpoint.
        assert l2.L2_deposit(user, 50, l1_height=11, l1_block_hash="h11")[0]
        assert l2.get_balance_sat(user) == 150
        ok, _ = l2.rollback_to_height(11)
        assert ok
        assert l2.get_balance_sat(user) == 150
        assert l2.root() != root10


def test_l2_persistence_failure_does_not_acknowledge_mutation():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "l2.db")
        st = Storage(path)
        l2 = Layer2State(st)
        user = Wallet.generate().address
        original = st.set_meta_batch

        def fail(_values):
            raise OSError("simulated durable-storage failure")

        st.set_meta_batch = fail
        try:
            try:
                l2.L2_deposit(user, 123, l1_height=1, l1_block_hash="h1")
            except OSError:
                pass
            else:
                raise AssertionError("deposit acknowledged a failed persistence")
            assert l2.get_balance_sat(user) == 0
        finally:
            st.set_meta_batch = original
        # The old durable state remains authoritative after a restart.
        l2_restarted = Layer2State(st)
        assert l2_restarted.get_balance_sat(user) == 0


def test_repeated_create_same_execution_site_gets_distinct_addresses():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "vm.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        parent = "VSDc" + "33" * 18
        from visold.vm.assembler import VVMAssembler

        source = """
PUSH1 0
PUSH1 0
MSTORE8
PUSH1 2
PUSH1 1
SSTORE
.loop:
JUMPDEST
PUSH1 1
PUSH1 0
PUSH1 0
CREATE
POP
PUSH1 1
PUSH1 1
SLOAD
SUB
PUSH1 1
SSTORE
PUSH1 1
SLOAD
ISZERO
JUMPI .exit
JUMP .loop
.exit:
JUMPDEST
STOP
"""
        assembled = VVMAssembler().assemble(source)
        assert assembled.ok, assembled.errors
        code = assembled.bytecode
        from visold.crypto.hashing import sha256
        code_hash = sha256(code)
        st.save_contract_code(code_hash, code)
        st.save_contract(parent, code_hash, wallet.address, 1)

        result = vm.call(
            caller=wallet.address, contract=parent, calldata=b"", call_value=0,
            gas_limit=2_000_000, block_ctx=None, tx=_Tx())
        assert result.success, result.revert_reason
        addresses = [d["address"] for d in result.pending_deployments]
        assert len(addresses) == 2
        assert len(set(addresses)) == 2


def test_v2_slash_evidence_verifies_without_local_vote_history():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "slash.db"))
        # A real Blockchain object is only required by the protocol constructor;
        # verification itself uses the storage and can run against an inert stub.
        class _BC: pass
        protocol = SlashingEvidenceProtocol(st, _BC())
        wallet = Wallet.generate()
        h1 = {"version": 1, "protocol_version": 1, "index": 7,
              "prev_hash": "1" * 64, "timestamp": 1, "miner": "m1",
              "difficulty": 1.0, "nonce": 1, "merkle_root": "a" * 64,
              "state_root": "b" * 64, "vrf_proof": "", "vrf_output": ""}
        h2 = dict(h1, nonce=2, merkle_root="c" * 64)
        bh1 = hash_obj(h1)
        bh2 = hash_obj(h2)
        s1 = sig_to_hex(wallet.sign(bh1.encode()))
        s2 = sig_to_hex(wallet.sign(bh2.encode()))
        evidence = protocol.build_evidence(
            wallet.address, wallet.pub_hex, bh1, s1, bh2, s2, 7, "submitter",
            block_header_a=h1, block_header_b=h2)
        assert protocol.verify_evidence(evidence) == (True, "OK")
        assert st.get_validator_votes_at_height(7) == []


def test_vvm_difficulty_opcode_encodes_fractional_difficulty_as_uint256():
    """0x44 must not pass a Python float into the integer-only VM stack."""
    from types import SimpleNamespace

    from visold.vm.frame import _VMFrame

    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "difficulty.db"))
        vm = VVMEngine(st)
        frame = _VMFrame(
            code=bytes([Op.DIFFICULTY, Op.STOP]),
            calldata=b"",
            caller="",
            address="",
            origin="",
            call_value=0,
            gas_limit=100,
            storage_ref=st,
            block_ctx=SimpleNamespace(difficulty=5.15),
        )
        vm._execute(frame)
        assert not frame.reverted
        assert frame.stack == [5_150_000]


def test_external_kv_block_is_hidden_when_sqlite_atomic_commit_rolls_back():
    """A KV block written before SQLite commit must not become canonical."""
    class FakeKV:
        enabled = True

        def __init__(self):
            self.blocks = {}

        def put_block(self, block):
            self.blocks[int(block.index)] = block.to_dict()

        def get_block_by_height(self, height):
            return self.blocks.get(int(height))

        def get_block_by_hash(self, bhash):
            for d in self.blocks.values():
                if d.get("block_hash") == bhash:
                    return d
            return None

        def chain_height(self):
            return max(self.blocks, default=-1)

        def delete_block(self, height):
            self.blocks.pop(int(height), None)
            return True

    from visold.ledger.block import Block

    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "kv.db"))
        kv = FakeKV()
        st._block_db = kv
        block = Block(
            index=0,
            prev_hash="0" * 64,
            transactions=[],
            miner_address="miner",
            difficulty=1.0,
            timestamp=1,
        )
        st.begin_sqlite_atomic_block()
        try:
            st._save_block_sqlite(block)
        finally:
            st.rollback_sqlite_atomic_block()

        assert 0 in kv.blocks
        assert st.chain_height() == -1
        assert st.get_block(0) is None
        assert st.get_block_by_hash(block.block_hash) is None


def test_pgx_block_transaction_uses_one_connection_and_rolls_back_rocks_write():
    """PGX save+rollback must use the active SQL connection and undo RocksDB."""
    import asyncio
    import threading
    from types import SimpleNamespace

    from visold.ledger.block import Block
    from visold.storage.storage import Storage

    class FakeTx:
        def __init__(self):
            self.started = False
            self.committed = False
            self.rolled_back = False

        async def start(self):
            self.started = True

        async def commit(self):
            self.committed = True

        async def rollback(self):
            self.rolled_back = True

    class FakeConn:
        def __init__(self):
            self.calls = []
            self.tx = FakeTx()

        def transaction(self):
            return self.tx

        async def execute(self, sql, *args):
            self.calls.append(("execute", sql, args))
            return "OK"

        async def fetch(self, sql, *args):
            self.calls.append(("fetch", sql, args))
            return []

        async def fetchrow(self, sql, *args):
            self.calls.append(("fetchrow", sql, args))
            return None

        async def executemany(self, sql, args):
            self.calls.append(("executemany", sql, args))

    class FakePool:
        def __init__(self, conn):
            self.conn = conn
            self.acquires = 0
            self.releases = 0

        async def acquire(self):
            self.acquires += 1
            return self.conn

        async def release(self, conn):
            assert conn is self.conn
            self.releases += 1

    class FakePg:
        def __init__(self, conn):
            self._pool = FakePool(conn)

        def run(self, coro):
            return asyncio.run(coro)

    class FakeBatch:
        pass

    class FakeRocks:
        def __init__(self):
            self.blocks = {}
            self.meta = {}

        def new_batch(self):
            return FakeBatch()

        def put_block(self, batch, height, block_dict, header, bhash):
            self.blocks[int(height)] = dict(block_dict)

        def put_tx_loc(self, batch, txid, height, tx_index):
            pass

        def put_meta(self, batch, key, value):
            self.meta[key] = value

        def commit(self, batch, sync=True):
            pass

        def get_block(self, height):
            return self.blocks.get(int(height))

        def get_header(self, height):
            d = self.blocks.get(int(height))
            return d

        def get_meta(self, key):
            return self.meta.get(key)

        def delete_block(self, batch, height, bhash):
            self.blocks.pop(int(height), None)

        def delete_tx_loc(self, batch, txid):
            pass

        def delete_meta(self, batch, key):
            self.meta.pop(key, None)

    conn = FakeConn()
    st = Storage.__new__(Storage)
    st._pgx_enabled = True
    st._pg = FakePg(conn)
    st._rocks = FakeRocks()
    st._cache = SimpleNamespace(set_tip=lambda *a, **k: None,
                                 mempool_remove=lambda *a, **k: None,
                                 cache_balance=lambda *a, **k: None)
    st._commit_lock = threading.RLock()
    st._pgx_block_local = threading.local()
    st._pgx_canonical_tip = -1
    st._pgx_canonical_tip_hash = ""
    st._mirror_block_to_aux = lambda block: None

    block = Block(
        index=0,
        prev_hash="0" * 64,
        transactions=[],
        miner_address="miner",
        difficulty=1.0,
        timestamp=1,
    )

    with st.pgx_atomic_block() as tx:
        st._pg_exec("SELECT 1")
        st._save_block_pgx(block, tx)
        # Deliberately abort after the RocksDB durability step.
        assert st._rocks.blocks[0]["block_hash"] == block.block_hash
        assert any(call[0] == "execute" for call in conn.calls)

    assert conn.tx.started
    assert conn.tx.rolled_back
    assert not conn.tx.committed
    assert 0 not in st._rocks.blocks
    assert st._pgx_canonical_tip == -1
    assert st._pgx_block_local.conn is None
    assert st._pg._pool.releases == 1


def test_external_kv_recovery_removes_orphan_genesis_and_fails_closed_on_missing_canonical():
    """Startup reconciliation must remove KV-only blocks and reject missing bodies."""
    from visold.ledger.block import Block

    class FakeKV:
        enabled = True

        def __init__(self):
            self.blocks = {}

        def put_block(self, block):
            self.blocks[int(block.index)] = block.to_dict()

        def get_block_by_height(self, height):
            return self.blocks.get(int(height))

        def get_block_by_hash(self, bhash):
            for d in self.blocks.values():
                if d.get("block_hash") == bhash:
                    return d
            return None

        def chain_height(self):
            return max(self.blocks, default=-1)

        def delete_block(self, height):
            self.blocks.pop(int(height), None)
            return True

    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "reconcile.db"))
        kv = FakeKV()
        st._block_db = kv
        genesis = Block(
            index=0, prev_hash="0" * 64, transactions=[],
            miner_address="miner", difficulty=1.0, timestamp=1,
        )
        kv.put_block(genesis)
        st._reconcile_external_block_db()
        assert kv.chain_height() == -1

        # A durable SQLite canonical row without a matching KV body is not
        # recoverable at startup; fail closed rather than running incomplete.
        c = st._conn()
        c.execute(
            """INSERT INTO blocks
               (idx,block_hash,timestamp,miner,difficulty,nonce,merkle_root,state_root,finalized,data_json)\n               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (0, genesis.block_hash, 1, "miner", 1.0, 0, "", "", 0, ""),
        )
        c.commit()
        try:
            st._reconcile_external_block_db()
        except RuntimeError as exc:
            assert "ahead of external block DB" in str(exc)
        else:
            raise AssertionError("missing canonical KV body was not rejected")


def test_block_database_delete_genesis_clears_empty_tip():
    """Deleting height zero must leave an empty KV database at height -1."""
    import threading
    from visold.storage.block_database import BlockDatabase

    class Batch:
        def __init__(self, db):
            self.db = db
            self.ops = []
        def put(self, key, value):
            self.ops.append(("put", key, value))
        def delete(self, key):
            self.ops.append(("delete", key, None))
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                for op, key, value in self.ops:
                    if op == "put":
                        self.db.data[key] = value
                    else:
                        self.db.data.pop(key, None)

    class FakeLevelDB:
        def __init__(self):
            self.data = {}
        def get(self, key):
            return self.data.get(key)
        def write_batch(self):
            return Batch(self)

    st = BlockDatabase.__new__(BlockDatabase)
    st._backend = "leveldb"
    st._path = ""
    st._db = FakeLevelDB()
    st._enabled = True
    st._lock = threading.Lock()

    from visold.ledger.block import Block
    block = Block(
        index=0, prev_hash="0" * 64, transactions=[],
        miner_address="miner", difficulty=1.0, timestamp=1,
    )
    st._db.data[st._height_key(0)] = __import__("json").dumps(block.to_dict()).encode()
    st._db.data[st._hash_key(block.block_hash)] = st._encode_height(0)
    st._db.data[b"tip"] = st._encode_height(0)

    assert st.delete_block(0)
    assert st.chain_height() == -1
    assert st._db.get(st._height_key(0)) is None
    assert st._db.get(b"tip") is None

    # Deleting a non-tip block must not rewind a higher canonical tip.
    block1 = Block(
        index=1, prev_hash=block.block_hash, transactions=[],
        miner_address="miner", difficulty=1.0, timestamp=2,
    )
    st._db.data[st._height_key(0)] = __import__("json").dumps(block.to_dict()).encode()
    st._db.data[st._hash_key(block.block_hash)] = st._encode_height(0)
    st._db.data[st._height_key(1)] = __import__("json").dumps(block1.to_dict()).encode()
    st._db.data[st._hash_key(block1.block_hash)] = st._encode_height(1)
    st._db.data[b"tip"] = st._encode_height(1)
    assert st.delete_block(0)
    assert st.chain_height() == 1
    assert st._db.get(st._height_key(0)) is None
    assert st._db.get(st._height_key(1)) is not None
