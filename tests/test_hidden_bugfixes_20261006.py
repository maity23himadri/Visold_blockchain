from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import patch

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.state.batch_proxy import _StorageBatchProxy
from visold.vm.frame import _VMFrame
from visold.vm.engine import VVMEngine
from visold.crypto.hashing import sha256
from visold.wallet.wallet import Wallet


def _chain(td: str):
    st = Storage(os.path.join(td, "hidden_bugfix.db"))
    return st, Blockchain(st)


def _channel_code(counterparty: str, deposit_sat: int = 100, revert: bool = True) -> bytes:
    dummy = object.__new__(_VMFrame)
    counterparty_word = dummy._addr_to_int(counterparty).to_bytes(32, "big")
    code = bytearray([0x60, 10, 0x61, (deposit_sat >> 8) & 0xFF, deposit_sat & 0xFF,
                      0x7F])
    code.extend(counterparty_word)
    code.append(0xFB)  # CHAN_OPEN
    if revert:
        code.extend([0x60, 0, 0x60, 0, 0xFD])  # REVERT
    else:
        code.append(0x00)  # STOP
    return bytes(code)


def _install_contract(st: Storage, addr: str, runtime: bytes, creator: str) -> None:
    code_hash = sha256(runtime)
    st.save_contract_code(code_hash, runtime)
    st.save_contract(addr, code_hash, creator, 0)


def test_chan_open_revert_restores_channel_and_deposit_balance():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        caller = Wallet.generate()
        counterparty = Wallet.generate()
        st.credit_sat(caller.address, 1_000_000)

        contract = "VSDc" + "11" * 18
        runtime = _channel_code(counterparty.address, 100, revert=True)
        _install_contract(st, contract, runtime, caller.address)

        ctx = Block(
            index=1, prev_hash=bc.latest_block().block_hash, transactions=[],
            miner_address=caller.address, difficulty=bc.get_difficulty(),
            timestamp=bc.latest_block().timestamp + 1,
        )
        tx = Transaction(
            sender=caller.address, receiver=contract, amount=0.0, fee=0.0,
            nonce=0, tx_type=Transaction.TYPE_CALL, data="",
            gas_limit=100_000, gas_price=0.0, expiry=2_000_000_000,
        )

        before = st.get_balance_sat(caller.address)
        result = VVMEngine(st).call(
            caller=caller.address, contract=contract, calldata=b"",
            call_value=0, gas_limit=100_000, block_ctx=ctx, tx=tx,
        )

        assert result.success is False
        assert st.get_balance_sat(caller.address) == before
        assert st.get_open_channel_between(
            caller.address, counterparty.address, contract) is None


def test_chan_open_revert_restores_batch_proxy_balance_overlay():
    """A reverted channel mutation must not survive the apply_block batch proxy."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        caller = Wallet.generate()
        counterparty = Wallet.generate()
        st.credit_sat(caller.address, 1_000)
        contract = "VSDc" + "12" * 18
        _install_contract(st, contract, _channel_code(counterparty.address, 100, revert=True), caller.address)
        tx = Transaction(
            sender=caller.address, receiver=contract, amount=0.0, fee=0.0,
            nonce=0, tx_type=Transaction.TYPE_CALL, data="",
            gas_limit=100_000, gas_price=0.0, expiry=2_000_000_000,
        )
        ctx = Block(
            index=1, prev_hash=bc.latest_block().block_hash, transactions=[],
            miner_address=caller.address, difficulty=bc.get_difficulty(),
            timestamp=bc.latest_block().timestamp + 1,
        )
        proxy = _StorageBatchProxy(st)
        result = VVMEngine(proxy).call(
            caller=caller.address, contract=contract, calldata=b"",
            call_value=0, gas_limit=100_000, block_ctx=ctx, tx=tx,
        )
        assert result.success is False
        assert proxy.get_balance_sat(caller.address) == 1_000
        assert st.get_balance_sat(caller.address) == 1_000
        assert st.get_open_channel_between(
            caller.address, counterparty.address, contract) is None


def test_dry_run_state_root_is_side_effect_free_for_channel_open():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        caller = Wallet.generate()
        counterparty = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(caller.address, 2_000_000_000)

        contract = "VSDc" + "22" * 18
        runtime = _channel_code(counterparty.address, 100, revert=False)
        _install_contract(st, contract, runtime, caller.address)

        tx = Transaction(
            sender=caller.address, receiver=contract, amount=0.0, fee=0.0,
            nonce=0, tx_type=Transaction.TYPE_CALL, data="",
            gas_limit=100_000, gas_price=0.0, expiry=2_000_000_000,
        )
        cb = Transaction.coinbase(miner.address, bc.compute_reward(1), 1)

        before_root = st.compute_state_root()
        before_balance = st.get_balance_sat(caller.address)
        assert st.get_open_channel_between(caller.address, counterparty.address, contract) is None

        _ = bc.dry_run_state_root(
            [cb, tx], miner.address, 1,
            timestamp=bc.latest_block().timestamp + 1,
            difficulty=bc.get_difficulty(),
        )

        assert st.compute_state_root() == before_root
        assert st.get_balance_sat(caller.address) == before_balance
        assert st.get_open_channel_between(caller.address, counterparty.address, contract) is None


def test_dry_run_uses_current_candidate_block_number_and_matches_apply():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        sender = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(sender.address, 2_000_000_000)

        contract = "VSDc" + "33" * 18
        runtime = bytes.fromhex("4360005500")  # NUMBER; PUSH1 0; SSTORE; STOP
        _install_contract(st, contract, runtime, sender.address)

        tx = Transaction(
            sender=sender.address, receiver=contract, amount=0.0, fee=0.0,
            nonce=0, tx_type=Transaction.TYPE_CALL, data="",
            gas_limit=100_000, gas_price=0.0, expiry=2_000_000_000,
        )
        height = 1
        timestamp = bc.latest_block().timestamp + 1
        difficulty = bc.get_difficulty()
        cb = Transaction.coinbase(miner.address, bc.compute_reward(height), height)
        txs = [cb, tx]

        dry_root = bc.dry_run_state_root(
            txs, miner.address, height,
            timestamp=timestamp, difficulty=difficulty,
        )

        block = Block(
            index=height,
            prev_hash=bc.latest_block().block_hash,
            transactions=txs,
            miner_address=miner.address,
            difficulty=difficulty,
            timestamp=timestamp,
            state_root=dry_root,
        )
        with patch.object(bc, "validate_block", return_value=(True, "OK")):
            ok, msg = bc.apply_block(block)
        assert ok, msg
        assert st.compute_state_root() == dry_root
        assert st.sload(contract, "0x0") == height


def test_rollback_rejects_targets_below_pruned_watermark_without_mutation():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        st.set_meta("rolling_pruned_until", "5")
        with patch.object(bc, "height", return_value=10), \
             patch.object(st, "get_block", side_effect=AssertionError("must fail before block lookup")):
            ok, msg = bc.rollback(3)
        assert not ok
        assert "below the rolling-prune watermark 5" in msg


def test_canonical_prune_helper_delegates_to_kv_backend_before_aux_delete():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "prune_helper.db"))

        class DummyBlockDB:
            enabled = True
            def __init__(self):
                self.calls = []
            def get_block_by_height(self, idx):
                return {"index": idx, "block_hash": "a" * 64,
                        "transactions": [{"tx_id": "must-not-survive"}]}
            def prune_block(self, idx, slim):
                self.calls.append((idx, dict(slim)))
                return True

        dummy = DummyBlockDB()
        st._block_db = dummy
        header = {
            "index": 7,
            "block_hash": "a" * 64,
            "prev_hash": "b" * 64,
            "timestamp": 123,
            "difficulty": 5.15,
            "nonce": 42,
            "merkle_root": "c" * 64,
            "state_root": "d" * 64,
            "vrf_proof": "proof",
            "vrf_output": "output",
            "protocol_version": Config.PROTOCOL_VERSION,
            "transactions": [{"tx_id": "must-not-survive"}],
        }
        assert st.prune_block_body(7, header) is True
        assert len(dummy.calls) == 1
        idx, slim = dummy.calls[0]
        assert idx == 7
        assert slim["transactions"] == []
        assert slim["block_hash"] == header["block_hash"]
        assert slim["vrf_proof"] == "proof"
        assert slim["vrf_output"] == "output"


def _pruner_fake_storage(block, *, pgx=False, kv=False, prune_ok=True):
    import sqlite3

    class FakeBlock:
        def __init__(self, data):
            self._data = dict(data)
        def to_dict(self):
            return dict(self._data)

    class DummyKV:
        enabled = kv

    class FakeStorage:
        def __init__(self):
            self._pgx_enabled = pgx
            self._block_db = DummyKV()
            self.conn = sqlite3.connect(":memory:")
            self.conn.row_factory = sqlite3.Row
            self.conn.execute(
                "CREATE TABLE blocks (idx INTEGER PRIMARY KEY, data_json TEXT)"
            )
            self.conn.execute(
                "CREATE TABLE transactions (tx_id TEXT PRIMARY KEY, block_idx INTEGER)"
            )
            self.blocks = {int(block["index"]): FakeBlock(block)}
            self.pg_deleted = []
            self.prune_ok = prune_ok
            self.prune_calls = []
            self.meta = {}
            self.conn.execute(
                "INSERT INTO blocks(idx,data_json) VALUES (?,?)",
                (block["index"], json.dumps(block)),
            )
            for tx in block.get("transactions", []):
                self.conn.execute(
                    "INSERT INTO transactions(tx_id,block_idx) VALUES (?,?)",
                    (tx["tx_id"], block["index"]),
                )
            self.conn.commit()

        def _conn(self):
            return self.conn
        def get_meta(self, key):
            return self.meta.get(key)
        def set_meta(self, key, value):
            self.meta[key] = str(value)
        def get_block(self, idx):
            return self.blocks.get(int(idx))
        def prune_block_body(self, idx, header, tx_ids=None):
            self.prune_calls.append((int(idx), dict(header), list(tx_ids or ())))
            if not self.prune_ok:
                return False
            d = dict(header)
            d["transactions"] = []
            d["pruned"] = True
            self.blocks[int(idx)] = FakeBlock(d)
            return True
        def _pg_exec(self, sql, idx):
            assert "DELETE FROM transactions" in sql
            self.pg_deleted.append(int(idx))
            return "DELETE 1"

    st = FakeStorage()
    return st


def _sample_prune_block(height=0):
    return {
        "version": 1,
        "protocol_version": Config.PROTOCOL_VERSION,
        "index": height,
        "prev_hash": "b" * 64,
        "timestamp": 123,
        "miner_address": "VSD" + "1" * 30,
        "difficulty": 5.15,
        "nonce": 42,
        "vrf_proof": "proof",
        "vrf_output": "output",
        "merkle_root": "c" * 64,
        "state_root": "d" * 64,
        "block_hash": "a" * 64,
        "finalized": False,
        "validator_sigs": [],
        "transactions": [
            {"tx_id": "critical-tx", "sender": "s", "receiver": "r",
             "amount": 200.0, "fee": 0.0, "timestamp": 123,
             "tx_type": "transfer", "memo": ""}
        ],
    }


def test_rolling_pruner_sqlite_path_compacts_body_and_advances_watermark():
    from visold.storage.rolling_window_pruner import RollingWindowPruner

    st = _pruner_fake_storage(_sample_prune_block(0), pgx=False, kv=False)
    pruner = RollingWindowPruner(st)
    with patch.object(Config, "ROLLING_PRUNE_WINDOW", 1), \
         patch.object(Config, "ROLLING_PRUNE_BATCH", 10):
        assert pruner._run_prune_pass(2) == 1
    row = st.conn.execute("SELECT data_json FROM blocks WHERE idx=0").fetchone()
    slim = json.loads(row["data_json"])
    assert slim["transactions"] == []
    assert slim["vrf_proof"] == "proof"
    assert st.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == 0
    assert st.conn.execute("SELECT COUNT(*) FROM block_headers").fetchone()[0] == 1
    assert st.meta["rolling_pruned_until"] == "1"


def test_rolling_pruner_kv_failure_retains_transaction_projection_and_watermark():
    from visold.storage.rolling_window_pruner import RollingWindowPruner

    st = _pruner_fake_storage(_sample_prune_block(0), pgx=False, kv=True, prune_ok=False)
    pruner = RollingWindowPruner(st)
    with patch.object(Config, "ROLLING_PRUNE_WINDOW", 1), \
         patch.object(Config, "ROLLING_PRUNE_BATCH", 10):
        assert pruner._run_prune_pass(2) == 0
    assert st.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == 1
    assert "rolling_pruned_until" not in st.meta
    assert len(st.prune_calls) == 1


def test_rolling_pruner_kv_path_uses_canonical_body_not_empty_aux_shadow():
    from visold.storage.rolling_window_pruner import RollingWindowPruner

    st = _pruner_fake_storage(_sample_prune_block(0), pgx=False, kv=True, prune_ok=True)
    st.conn.execute("UPDATE blocks SET data_json='' WHERE idx=0")
    st.conn.commit()
    pruner = RollingWindowPruner(st)
    with patch.object(Config, "ROLLING_PRUNE_WINDOW", 1), \
         patch.object(Config, "ROLLING_PRUNE_BATCH", 10):
        assert pruner._run_prune_pass(2) == 1
    assert st.prune_calls
    assert st.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == 0
    assert st.meta["rolling_pruned_until"] == "1"


def test_rolling_pruner_pgx_path_deletes_canonical_pg_transactions_after_compaction():
    from visold.storage.rolling_window_pruner import RollingWindowPruner

    st = _pruner_fake_storage(_sample_prune_block(0), pgx=True, kv=False, prune_ok=True)
    pruner = RollingWindowPruner(st)
    with patch.object(Config, "ROLLING_PRUNE_WINDOW", 1), \
         patch.object(Config, "ROLLING_PRUNE_BATCH", 10):
        assert pruner._run_prune_pass(2) == 1
    assert st.prune_calls
    assert st.pg_deleted == [0]
    assert st.meta["rolling_pruned_until"] == "1"



def test_apply_block_reverted_channel_open_does_not_leak_into_batch_overlay():
    """Exercise the real apply_block path where balances are batch-buffered."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        caller = Wallet.generate()
        counterparty = Wallet.generate()
        receiver = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(caller.address, 1_000)
        contract = "VSDc" + "55" * 18
        _install_contract(
            st, contract, _channel_code(counterparty.address, 100, revert=True),
            caller.address)

        transfer = Transaction(
            sender=caller.address, receiver=receiver.address, amount=0.000001,
            fee=0.0, nonce=0, tx_type=Transaction.TYPE_TRANSFER, data="",
            gas_limit=0, gas_price=0.0, expiry=2_000_000_000,
        )
        call = Transaction(
            sender=caller.address, receiver=contract, amount=0.0, fee=0.0,
            nonce=1, tx_type=Transaction.TYPE_CALL, data="",
            gas_limit=100_000, gas_price=0.0, expiry=2_000_000_000,
        )
        height = 1
        timestamp = bc.latest_block().timestamp + 1
        difficulty = bc.get_difficulty()
        txs = [Transaction.coinbase(miner.address, bc.compute_reward(height), height),
               transfer, call]
        dry_root = bc.dry_run_state_root(
            txs, miner.address, height, timestamp=timestamp, difficulty=difficulty)
        block = Block(
            index=height, prev_hash=bc.latest_block().block_hash, transactions=txs,
            miner_address=miner.address, difficulty=difficulty,
            timestamp=timestamp, state_root=dry_root,
        )
        with patch.object(bc, "validate_block", return_value=(True, "OK")):
            ok, msg = bc.apply_block(block)
        assert ok, msg
        assert st.get_balance_sat(caller.address) == 899
        assert st.get_balance_sat(receiver.address) == 100
        assert st.get_open_channel_between(
            caller.address, counterparty.address, contract) is None
        assert st.compute_state_root() == dry_root


def test_block_failure_after_successful_channel_open_rolls_back_channel_and_balance():
    """Whole-block failure must undo direct channel rows without reintroducing in-block account state."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        caller = Wallet.generate()
        counterparty = Wallet.generate()
        bad_sender = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(caller.address, 1_000)
        contract = "VSDc" + "66" * 18
        _install_contract(
            st, contract, _channel_code(counterparty.address, 100, revert=False),
            caller.address)

        call = Transaction(
            sender=caller.address, receiver=contract, amount=0.0, fee=0.0,
            nonce=0, tx_type=Transaction.TYPE_CALL, data="",
            gas_limit=100_000, gas_price=0.0, expiry=2_000_000_000,
        )
        bad_transfer = Transaction(
            sender=bad_sender.address, receiver=caller.address, amount=0.000001,
            fee=0.0, nonce=0, tx_type=Transaction.TYPE_TRANSFER, data="",
            gas_limit=0, gas_price=0.0, expiry=2_000_000_000,
        )
        height = 1
        block = Block(
            index=height, prev_hash=bc.latest_block().block_hash,
            transactions=[
                Transaction.coinbase(miner.address, bc.compute_reward(height), height),
                call, bad_transfer,
            ],
            miner_address=miner.address, difficulty=bc.get_difficulty(),
            timestamp=bc.latest_block().timestamp + 1, state_root="",
        )
        before = st.compute_state_root()
        with patch.object(bc, "validate_block", return_value=(True, "OK")):
            ok, _msg = bc.apply_block(block)
        assert ok is False
        assert st.compute_state_root() == before
        assert st.get_balance_sat(caller.address) == 1_000
        assert st.get_open_channel_between(
            caller.address, counterparty.address, contract) is None


def test_successful_channel_open_rollback_restores_balance_and_removes_channel():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        caller = Wallet.generate()
        counterparty = Wallet.generate()
        st.credit_sat(caller.address, 1_000)
        contract = "VSDc" + "44" * 18
        _install_contract(st, contract, _channel_code(counterparty.address, 100, revert=False), caller.address)
        tx = Transaction(
            sender=caller.address, receiver=contract, amount=0.0, fee=0.0,
            nonce=0, tx_type=Transaction.TYPE_CALL, data="",
            gas_limit=100_000, gas_price=0.0, expiry=2_000_000_000,
        )
        ctx = Block(
            index=1, prev_hash=bc.latest_block().block_hash, transactions=[],
            miner_address=caller.address, difficulty=bc.get_difficulty(),
            timestamp=bc.latest_block().timestamp + 1,
        )
        before = st.get_balance_sat(caller.address)
        fee, success, undo = bc._apply_vvm_tx(tx, ctx)
        assert success is True
        assert fee == 0
        assert st.get_balance_sat(caller.address) == before - 100
        assert st.get_open_channel_between(caller.address, counterparty.address, contract) is not None
        bc._undo_vvm_block_effects([undo])
        assert st.get_balance_sat(caller.address) == before
        assert st.get_open_channel_between(caller.address, counterparty.address, contract) is None

def test_pgx_prune_removes_canonical_tx_location_atomically():
    class FakeBatch:
        pass

    class FakeRocks:
        def __init__(self):
            self.ops = []
            self.committed = False

        def get_block(self, idx):
            if idx == 7:
                return {"block_hash": "h7", "transactions": [{"tx_id": "tx7"}]}
            return None

        def new_batch(self):
            return FakeBatch()

        def delete_tx_loc(self, batch, txid):
            self.ops.append(("delete_tx_loc", txid, batch))

        def put_block(self, batch, idx, block_dict, header, bhash):
            self.ops.append(("put_block", idx, block_dict, header, bhash, batch))

        def commit(self, batch, sync=True):
            assert sync is True
            assert all(op[-1] is batch for op in self.ops)
            self.committed = True

    st = Storage.__new__(Storage)
    st._pgx_enabled = True
    st._rocks = FakeRocks()
    st._block_db = type("KV", (), {"enabled": False})()

    assert st.prune_block_body(7, {"index": 7, "block_hash": "h7"}, tx_ids=["tx7"])
    assert [op[0:2] for op in st._rocks.ops] == [
        ("delete_tx_loc", "tx7"),
        ("put_block", 7),
    ]
    assert st._rocks.committed


def test_pgx_tx_exists_ignores_stale_location_after_prune():
    class FakeRocks:
        def get_tx_loc(self, tx_id):
            return (7, 0) if tx_id == "stale" else (8, 0)

        def get_block(self, height):
            if height == 7:
                return {"transactions": [], "pruned": True}
            if height == 8:
                return {"transactions": [{"tx_id": "live"}]}
            return None

    class FakePG: 
        def __init__(self, rows=None):
            self.rows = rows

    st = Storage.__new__(Storage)
    st._pgx_enabled = True
    st._rocks = FakeRocks()
    st._pg = FakePG()
    st._pg_fetchrow = lambda _sql, _txid: None

    assert st.tx_exists("stale") is False
    assert st.tx_exists("live") is True


def test_pgx_prune_can_derive_tx_ids_without_caller_supplied_list():
    class Batch:
        pass

    class Rocks:
        def __init__(self):
            self.deleted = []
            self.committed = False

        def get_block(self, idx):
            return {"block_hash": "h8", "transactions": [{"tx_id": "tx8"}]}

        def new_batch(self):
            return Batch()

        def delete_tx_loc(self, batch, txid):
            self.deleted.append((txid, batch))

        def put_block(self, *args):
            self.put_args = args

        def commit(self, batch, sync=True):
            self.committed = sync

    st = Storage.__new__(Storage)
    st._pgx_enabled = True
    st._rocks = Rocks()
    st._block_db = type("KV", (), {"enabled": False})()

    assert st.prune_block_body(8, {"index": 8, "block_hash": "h8"})
    assert [x[0] for x in st._rocks.deleted] == ["tx8"]
    assert st._rocks.committed is True


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
