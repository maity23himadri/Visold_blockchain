"""Positive V4 regression tests for Visold Cluster 4 (Mempool, State, Storage).

Converted from V3 adversarial tests to assert the fixed V4 behavior.
All tests are non-destructive and operate on temporary directories / mock PGX handles.
"""

import asyncio
import concurrent.futures as _futures
import json
import sqlite3
import threading
import time

import pytest

from visold.kernel.config import Config
from visold.kernel.events import Event, EventType
from visold.kernel.units import VSD_GLOBAL_MARKET, to_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.state.batch_proxy import _StorageBatchProxy
from visold.state.engine import StateEngine
from visold.storage.block_database import BlockDatabase
from visold.storage.rolling_window_pruner import RollingWindowPruner
from visold.storage.snapshot import StateSnapshotEngine
from visold.storage.state_pruner import StatePruner
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_storage(tmp_path, name="node.db"):
    return Storage(str(tmp_path / name))


def _make_wallet():
    return Wallet.generate()


def _signed_transfer(wallet, receiver, amount=1.0, fee=0.01, nonce=0, expiry=None):
    if expiry is None:
        expiry = int(time.time()) + 3600
    tx = Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount=amount,
        fee=fee,
        nonce=nonce,
        expiry=expiry,
    )
    tx.sign(wallet)
    return tx


def test_v4_01_mempool_rejects_unauthenticated_coinbase(tmp_path):
    st = _make_storage(tmp_path)
    pool = Mempool(st)
    w = _make_wallet()

    forged_cb = Transaction(
        sender="COINBASE",
        receiver=w.address,
        amount=50.0,
        fee=0.0,
        nonce=0,
        expiry=0,
    )
    ok, msg = pool.add(forged_cb)
    assert ok is False, f"Expected forged COINBASE to be rejected, got: {msg}"
    assert "COINBASE" in msg
    assert forged_cb.tx_id not in [t.tx_id for t in pool.get_top(10)]
    st.close()


def test_v4_02_mempool_rejects_forged_tx_id(tmp_path):
    st = _make_storage(tmp_path)
    pool = Mempool(st)
    alice = _make_wallet()
    bob = _make_wallet()
    st.set_balance(alice.address, to_satoshi(100.0))

    honest = _signed_transfer(alice, bob.address, amount=10.0, fee=0.1, nonce=0)
    spoofed_dict = honest.to_dict()
    spoofed_dict["tx_id"] = "deadbeef" * 8
    spoofed = Transaction.from_dict(spoofed_dict)

    ok, msg = pool.add(spoofed)
    assert ok is False, f"Expected spoofed tx_id to be rejected, got: {msg}"
    assert "tx_id" in msg

    # Honest tx with same nonce=0 is NOT blocked by the rejected spoofed tx
    ok2, msg2 = pool.add(honest)
    assert ok2 is True, f"Expected honest tx to be admitted, got: {msg2}"
    st.close()


def test_v4_03_vvm_rejects_negative_fee_and_fake_high_fee_priority_hijack(tmp_path):
    st = _make_storage(tmp_path)
    pool = Mempool(st)
    alice = _make_wallet()
    bob = _make_wallet()
    st.set_balance(alice.address, to_satoshi(100000.0))
    st.set_balance(bob.address, to_satoshi(1000.0))

    neg_fee_call = Transaction(
        sender=alice.address,
        receiver="VSDc" + "1" * 36,
        amount=0.0,
        fee=-1.0,
        nonce=0,
        expiry=int(time.time()) + 3600,
        tx_type=Transaction.TYPE_CALL,
        gas_limit=100,
        gas_price=Config.VVM_MIN_GAS_PRICE,
        data="00",
    )
    neg_fee_call.sign(alice)
    valid_ok, valid_msg = neg_fee_call.is_valid()
    assert valid_ok is False, f"Expected negative fee VVM tx to fail is_valid, got {valid_msg}"
    assert "negative" in valid_msg.lower()

    fake_high_fee_call = Transaction(
        sender=alice.address,
        receiver="VSDc" + "1" * 36,
        amount=0.0,
        fee=10000.0,
        nonce=0,
        expiry=int(time.time()) + 3600,
        tx_type=Transaction.TYPE_CALL,
        gas_limit=100,
        gas_price=Config.VVM_MIN_GAS_PRICE,
        data="00",
    )
    fake_high_fee_call.sign(alice)

    real_transfer = _signed_transfer(bob, alice.address, amount=10.0, fee=0.1, nonce=0)
    assert pool.add(real_transfer)[0] is True

    # VVM tx whose tx.fee exceeds its gas budget (gas_limit * gas_price) is rejected
    ok_fake, msg_fake = pool.add(fake_high_fee_call)
    assert ok_fake is False, f"Expected fake high-fee VVM tx to be rejected, got: {msg_fake}"
    assert "gas budget" in msg_fake.lower()

    top = pool.get_top(2)
    assert len(top) == 1
    assert top[0].tx_id == real_transfer.tx_id
    st.close()


def test_v4_04_mempool_rejects_zero_balance_transfer_flood(tmp_path):
    st = _make_storage(tmp_path)
    pool = Mempool(st)
    zero_bal_attacker = _make_wallet()
    honest_sender = _make_wallet()
    receiver = _make_wallet()

    st.set_balance(honest_sender.address, to_satoshi(100.0))
    assert st.get_balance_sat(zero_bal_attacker.address) == 0

    honest_tx = _signed_transfer(honest_sender, receiver.address, amount=10.0, fee=0.1, nonce=0)
    assert pool.add(honest_tx)[0] is True

    # Zero-balance attacker's high-fee unmineable transfer is rejected at admission
    spam_tx = _signed_transfer(zero_bal_attacker, receiver.address, amount=5000.0, fee=50.0, nonce=0)
    ok, msg = pool.add(spam_tx)
    assert ok is False, f"Expected 0-balance transfer to be rejected, got: {msg}"
    assert "Insufficient spendable balance" in msg

    top = pool.get_top(1)
    assert top[0].tx_id == honest_tx.tx_id
    st.close()


def test_v4_05_mempool_enforces_replay_guard_and_nonce_for_market_tx(tmp_path):
    st = _make_storage(tmp_path)
    pool = Mempool(st)
    alice = _make_wallet()
    bob = _make_wallet()
    st.set_balance(alice.address, to_satoshi(100.0))

    # 1) Add normal tx first at nonce=0
    norm_tx = _signed_transfer(alice, bob.address, amount=1.0, fee=0.01, nonce=0)
    assert pool.add(norm_tx)[0] is True
    assert 0 in pool._pending_nonces[alice.address]

    # 2) Pruned VSD_GLOBAL_MARKET tx present only in tx_replay_guard is rejected
    mkt_tx = _signed_transfer(alice, VSD_GLOBAL_MARKET, amount=1.0, fee=0.01, nonce=0)
    st.record_applied_tx_id(mkt_tx.tx_id)
    assert st.tx_exists(mkt_tx.tx_id) is False
    assert st.replay_guard_exists(mkt_tx.tx_id) is True
    ok_replay, _ = pool.add(mkt_tx)
    assert ok_replay is False

    # 3) VSD_GLOBAL_MARKET tx cannot share nonce=0 with pending norm_tx
    mkt_tx2 = _signed_transfer(alice, VSD_GLOBAL_MARKET, amount=2.0, fee=0.02, nonce=0)
    ok_mkt2, msg_mkt2 = pool.add(mkt_tx2)
    assert ok_mkt2 is False
    assert "Nonce mismatch" in msg_mkt2
    assert 0 in pool._pending_nonces[alice.address]

    conflicting_tx = _signed_transfer(alice, bob.address, amount=2.0, fee=0.02, nonce=0)
    assert pool.add(conflicting_tx)[0] is False
    st.close()


def test_v4_06_mempool_heap_remove_unknown_preserves_size_and_evicts_expired_at_cap(tmp_path, monkeypatch):
    st = _make_storage(tmp_path)
    pool = Mempool(st)
    alice = _make_wallet()
    bob = _make_wallet()
    charlie = _make_wallet()
    st.set_balance(alice.address, to_satoshi(100.0))
    st.set_balance(bob.address, to_satoshi(100.0))

    tx0 = _signed_transfer(alice, bob.address, amount=1.0, fee=0.01, nonce=0)
    assert pool.add(tx0)[0] is True
    assert pool._heap.size() == 1

    # Clearing unknown tx_ids does not corrupt heap size
    pool.clear_confirmed(["nonexistent_coinbase_tx", "nonexistent_peer_tx"])
    assert pool._heap.size() == 1
    assert len(pool._heap.get_all_live()) == 1

    # Expired-at-cap DoS is prevented: expired entries are evicted so fresh tx fits
    monkeypatch.setattr(Config, "MEMPOOL_MAX", 2)
    expired_tx = _signed_transfer(
        alice, bob.address, amount=1.0, fee=0.01, nonce=1, expiry=int(time.time()) + 2
    )
    assert pool.add(expired_tx)[0] is True
    expired_tx.expiry = int(time.time()) - 10
    pool.storage.mempool_remove(expired_tx.tx_id)
    pool.storage.mempool_add(expired_tx)

    fresh_tx = _signed_transfer(bob, charlie.address, amount=1.0, fee=0.01, nonce=0)
    ok, msg = pool.add(fresh_tx)
    assert ok is True, f"Expected expired tx eviction at cap, got: {msg}"
    st.close()


def test_v4_07_state_engine_stop_resolves_future_and_preserves_single_writer(tmp_path):
    st = _make_storage(tmp_path)
    entered_first = threading.Event()
    release_first = threading.Event()
    active_writers = 0
    max_writers = 0
    wlock = threading.Lock()

    class DummyBC:
        mempool = Mempool(st)
        _highest_finalized_height = 0
        def height(self): return 0

    class DummyGov:
        def set_finality_source(self, fn): pass

    eng = StateEngine(DummyBC(), DummyGov(), st)

    def fake_handle(event):
        nonlocal active_writers, max_writers
        with wlock:
            active_writers += 1
            max_writers = max(max_writers, active_writers)
        if event.payload.get("block_me"):
            entered_first.set()
            release_first.wait(timeout=3.0)
        with wlock:
            active_writers -= 1
        return True, "ok"

    eng._handle = fake_handle
    eng.start()
    eng.post(Event(EventType.TIMER, {"block_me": True}))
    assert entered_first.wait(timeout=2.0)

    e2 = Event(EventType.TIMER, {"queued": True})
    fut = _futures.Future()
    e2.future = fut
    eng.post(e2)

    stop_thread = threading.Thread(target=eng.stop)
    stop_thread.start()
    time.sleep(0.05)

    # New sync submissions while stopping are rejected without violating single-writer
    status, ok, _msg, _ = eng.post_sync_detailed(Event(EventType.TIMER, {"concurrent": True}))
    assert status == "not_queued" and ok is False

    release_first.set()
    stop_thread.join(timeout=3.0)

    assert max_writers == 1, f"Expected single-writer invariant (max_writers=1), got {max_writers}"
    assert fut.done() is True, "Expected queued event future to be resolved on stop()"
    st.close()


def test_v4_08_state_engine_orphan_does_not_record_fail_marker(tmp_path):
    st = _make_storage(tmp_path)

    class DummyBC:
        mempool = Mempool(st)
        _highest_finalized_height = 0
        def height(self): return 0
        def apply_block(self, block):
            return False, "Previous block not found"

    class DummyGov:
        def set_finality_source(self, fn): pass
        def shadow_validate(self, block): return []

    eng = StateEngine(DummyBC(), DummyGov(), st)
    orphan = Block(
        index=1,
        prev_hash="0" * 64,
        transactions=[],
        miner_address="VSD1test",
        difficulty=Config.MIN_DIFFICULTY,
        nonce=0,
    )
    orphan.mine()

    ok, msg = eng._handle_new_block({"block": orphan.to_dict()}, "peer1")
    assert ok is False
    assert "Stashed as orphan" in msg
    assert st.get_meta("block_apply:1") is None
    st.close()


def test_v4_09_batch_proxy_restore_channel_journal_and_flush_sqlite_error(tmp_path):
    st = _make_storage(tmp_path)
    proxy = _StorageBatchProxy(st)

    proxy.restore_state_channel_journal({"accounts": {"alice": (100, 0, 0, True)}})
    row = st._conn().execute("SELECT * FROM state_channels WHERE channel_id='accounts'").fetchone()
    assert row is None, "Expected bogus channel_id='accounts' row not to be persisted"

    with pytest.raises(ValueError):
        st._flush_block_batch({"alice": 500}, {"alice": "not_an_int"}, {})
    assert st._conn()._conn.in_transaction is False
    st.close()


def test_v4_10_remove_contract_atomic_rollback_inside_atomic_block(tmp_path):
    st = _make_storage(tmp_path)
    c = st._conn()
    c.execute(
        "INSERT INTO contract_accounts (address, code_hash, storage_root, nonce, creator, created_at) "
        "VALUES ('VSDc1', 'abc', '', 0, 'creator', 1)"
    )
    c.execute(
        "INSERT INTO contract_storage (contract_addr, slot_key, slot_value) VALUES ('VSDc1', 'k1', '123')"
    )
    c.commit()

    c.execute(
        "CREATE TRIGGER fail_contract_del BEFORE DELETE ON contract_accounts "
        "BEGIN SELECT RAISE(ABORT, 'simulated failure'); END;"
    )
    c.commit()

    st.begin_sqlite_atomic_block()
    with pytest.raises(sqlite3.IntegrityError, match="simulated failure"):
        st.remove_contract("VSDc1")
    st.commit_sqlite_atomic_block()

    # Savepoint rolled back cleanly so neither table was partially deleted
    assert c.execute("SELECT * FROM contract_storage WHERE contract_addr='VSDc1'").fetchone() is not None
    assert c.execute("SELECT * FROM contract_accounts WHERE address='VSDc1'").fetchone() is not None
    st.close()


def test_v4_11_pgx_atomic_releases_lock_on_error_and_get_block_timestamps(tmp_path):
    st = _make_storage(tmp_path)
    st._pgx_enabled = True

    class FailingPool:
        async def acquire(self):
            raise RuntimeError("pool exhausted")

    class DummyPg:
        _pool = FailingPool()
        def run(self, coro):
            return asyncio.run(coro)
        def close(self):
            pass

    st._pg = DummyPg()
    with pytest.raises(RuntimeError, match="pool exhausted"):
        with st.pgx_atomic_block():
            pass

    # Verify _commit_lock is NOT leaked when _pool.acquire() fails
    other_acquired = []
    def _try_acq():
        got = st._commit_lock.acquire(blocking=False)
        if got:
            st._commit_lock.release()
        other_acquired.append(got)
    t = threading.Thread(target=_try_acq)
    t.start()
    t.join(timeout=2.0)
    assert other_acquired == [True], "Expected _commit_lock to be released on _pool.acquire() failure"

    # get_block_timestamps reads PGX RocksDB headers rather than querying a Postgres 'blocks' table
    class DummyRocks:
        def get_header(self, idx):
            return {"timestamp": 1000 + idx}

    queries = []
    st._pg_fetch = lambda sql, *args: (queries.append(sql), [])[1]
    st._rocks = DummyRocks()
    st._pgx_canonical_tip = 1
    ts = st.get_block_timestamps(0, 1)
    assert ts == [1000, 1001]
    assert not any("FROM blocks" in q for q in queries)
    st._pgx_enabled = False
    st.close()


def test_v4_12_block_database_cleans_stale_hash_index_and_get_last_n_blocks_negative(tmp_path):
    bdb = BlockDatabase("sqlite", str(tmp_path / "kv"))
    store = {}

    class FakeKV:
        def get(self, k): return store.get(k)
        def write_batch(self):
            class WB:
                def __enter__(self): return self
                def __exit__(self, *a): pass
                def put(self, k, v): store[k] = v
                def delete(self, k): store.pop(k, None)
            return WB()

    bdb._backend = "leveldb"
    bdb._db = FakeKV()
    bdb._enabled = True

    b1 = Block(index=1, prev_hash="0" * 64, transactions=[], miner_address="VSD1", difficulty=1.0)
    b1.block_hash = "hash_a"
    b2 = Block(index=1, prev_hash="0" * 64, transactions=[], miner_address="VSD1", difficulty=1.0)
    b2.block_hash = "hash_b"

    bdb.put_block(b1)
    bdb.put_block(b2)
    assert bdb.get_block_by_hash("hash_a") is None
    got = bdb.get_block_by_hash("hash_b")
    assert got is not None and got["block_hash"] == "hash_b"

    st = _make_storage(tmp_path)
    g = Block(index=0, prev_hash="0" * 64, transactions=[], miner_address="VSD1", difficulty=1.0)
    g.block_hash = "g_hash"
    st.save_block(g)
    assert st.get_last_n_blocks(-1) == []
    st.close()


def test_v4_13_pruner_reconcile_watermark_and_state_pruner_progress(tmp_path, monkeypatch):
    st = _make_storage(tmp_path)
    g = Block(index=0, prev_hash="0" * 64, transactions=[], miner_address="VSD1", difficulty=1.0)
    g.block_hash = "g0"
    st.save_block(g)
    b1 = Block(index=1, prev_hash="g0", transactions=[], miner_address="VSD1", difficulty=1.0)
    b1.block_hash = "b1"
    b1_dict = b1.to_dict()
    b1_dict["pruned"] = True
    st._conn().execute(
        "INSERT INTO blocks (idx, block_hash, prev_hash, timestamp, miner, difficulty, nonce, merkle_root, state_root, finalized, data_json) "
        "VALUES (1, 'b1', 'g0', 0, '', 1.0, 0, '', '', 0, ?)",
        (json.dumps(b1_dict),),
    )
    st._conn().commit()

    pruner = RollingWindowPruner(st)
    pruner.reconcile_after_bootstrap(1)
    assert st.get_meta("rolling_pruned_until") == "2"

    monkeypatch.setattr(Config, "STATE_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "STATE_PRUNE_KEEP_SNAPSHOTS", 600)
    monkeypatch.setattr(Config, "STATE_PRUNE_INTERVAL", 1)
    sp = StatePruner(st, None)
    c = st._conn()
    c.execute("INSERT INTO node_meta (key, value) VALUES ('state_snapshot:200', 'root200')")
    c.executemany(
        "INSERT INTO node_meta (key, value) VALUES (?, 'root')",
        [(f"state_snapshot:{h}",) for h in range(10000, 10500)],
    )
    c.commit()
    pruned = sp.maybe_prune(10500)
    assert pruned >= 1
    assert st.get_meta("state_snapshot:200") is None
    st.close()


def test_v4_14_storage_prune_old_data_prunes_oldest_signals(tmp_path, monkeypatch):
    st = _make_storage(tmp_path)
    monkeypatch.setattr(st, "PRUNE_BATCH_SIZE", 10)
    monkeypatch.setattr(Config, "FORK_SIGNAL_WINDOW", 5)
    monkeypatch.setattr(st, "PRUNE_META_SIGNAL_KEEP", 10)

    c = st._conn()
    c.execute("INSERT INTO node_meta (key, value) VALUES ('proto_sig:20', '1')")
    c.executemany(
        "INSERT INTO node_meta (key, value) VALUES (?, '1')",
        [(f"proto_sig:{h}",) for h in range(10000, 10010)],
    )
    c.commit()

    res = st.prune_old_data(10010)
    assert res.get("node_meta_signals", 0) >= 1
    assert st.get_meta("proto_sig:20") is None
    st.close()


def test_v4_15_snapshot_get_chunk_negative_index_returns_none(tmp_path):
    st = _make_storage(tmp_path)
    eng = StateSnapshotEngine(st)
    blob = b"A" * 100
    st.set_meta("snap:10", blob.hex())

    assert eng.get_chunk(10, -1) is None
    eng._chunk_size = lambda: 10
    assert eng.get_chunk(10, -2) is None
    st.close()
