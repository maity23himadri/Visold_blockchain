"""V4 regression tests for Section 78 (Session 06): Event Index Ordering, Cleanup, and Idempotency."""

import os
import tempfile
import time
import unittest

from visold.chain.blockchain import Blockchain
from visold.wallet.wallet import Wallet
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.vm.naming import derive_contract_address


def _make_runtime_two_logs_bytecode(topic_a: int, topic_b: int) -> bytes:
    return bytes([
        0x60, topic_a & 0xFF,
        0x60, 0x00,
        0x60, 0x00,
        0xA1,
        0x60, topic_b & 0xFF,
        0x60, 0x00,
        0x60, 0x00,
        0xA1,
        0x00,
    ])


def _make_init_bytecode(runtime_code: bytes) -> bytes:
    n = len(runtime_code)
    assert n <= 255
    prefix = bytes([
        0x60, n,
        0x60, 12,
        0x60, 0,
        0x39,
        0x60, n,
        0x60, 0,
        0xF3,
    ])
    return prefix + runtime_code


class TestAuditSection78EventIndex(unittest.TestCase):
    def _setup_chain(self):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        db_path = os.path.join(tmpdir.name, "visold_test.db")
        storage = Storage(db_path=db_path)
        bc = Blockchain(storage=storage)

        w_miner = Wallet.generate()
        w_sender = Wallet.generate()
        storage.credit_sat(w_sender.address, 10_000_000_000)

        runtime = _make_runtime_two_logs_bytecode(0x11, 0x22)
        init_code = _make_init_bytecode(runtime)
        deploy_tx = Transaction(
            sender=w_sender.address,
            receiver="",
            amount=0.0,
            fee=0.0,
            nonce=0,
            tx_type=Transaction.TYPE_DEPLOY,
            data=init_code.hex(),
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        deploy_tx.sign(w_sender)
        contract_addr = derive_contract_address(
            w_sender.address, deploy_tx.nonce, deploy_tx.tx_id
        )

        prev0 = storage.get_block(0)
        blk1 = Block(
            index=1,
            prev_hash=prev0.block_hash,
            transactions=[deploy_tx],
            miner_address=w_miner.address,
            difficulty=1,
            timestamp=int(time.time()) + 1,
        )
        orig_val = bc.validate_block
        bc.validate_block = lambda _b: (True, "TEST-BYPASS")
        try:
            blk1.state_root = bc.dry_run_state_root(
                [deploy_tx], w_miner.address, 1
            )
            ok, msg = bc.apply_block(blk1)
        finally:
            bc.validate_block = orig_val
        self.assertTrue(ok, f"Deploy block failed: {msg}")
        self.assertIsNotNone(storage.get_contract(contract_addr))
        return storage, bc, w_miner, w_sender, contract_addr

    def test_multi_tx_block_events_preserve_tx_execution_order(self):
        """Multi-tx block events are ordered by tx execution order, not interleaved."""
        storage, bc, w_miner, w_sender, contract_addr = self._setup_chain()

        tx1 = Transaction(
            sender=w_sender.address,
            receiver=contract_addr,
            amount=0.0,
            fee=0.0,
            nonce=1,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        tx1.sign(w_sender)

        tx2 = Transaction(
            sender=w_sender.address,
            receiver=contract_addr,
            amount=0.0,
            fee=0.0,
            nonce=2,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        tx2.sign(w_sender)

        prev1 = storage.get_block(1)
        blk2 = Block(
            index=2,
            prev_hash=prev1.block_hash,
            transactions=[tx1, tx2],
            miner_address=w_miner.address,
            difficulty=1,
            timestamp=int(time.time()) + 2,
        )
        orig_val = bc.validate_block
        bc.validate_block = lambda _b: (True, "TEST-BYPASS")
        try:
            blk2.state_root = bc.dry_run_state_root(
                [tx1, tx2], w_miner.address, 2
            )
            ok, msg = bc.apply_block(blk2)
        finally:
            bc.validate_block = orig_val
        self.assertTrue(ok, f"Block 2 failed: {msg}")

        events = bc.get_contract_events(contract_addr, from_block=2, to_block=2)
        self.assertEqual(len(events), 4)

        actual_tx_order = [e["tx_id"] for e in events]
        expected_tx_order = [tx1.tx_id, tx1.tx_id, tx2.tx_id, tx2.tx_id]
        self.assertEqual(actual_tx_order, expected_tx_order)

    def test_rejected_block_cleans_up_events_on_undo(self):
        """_undo_vvm_block_effects() removes events from rejected blocks."""
        storage, bc, w_miner, w_sender, contract_addr = self._setup_chain()

        call_tx = Transaction(
            sender=w_sender.address,
            receiver=contract_addr,
            amount=0.0,
            fee=0.0,
            nonce=1,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        call_tx.sign(w_sender)

        failing_tx = Transaction(
            sender=Wallet.generate().address,
            receiver=w_miner.address,
            amount=1.0,
            fee=0.0,
            nonce=0,
            tx_type=Transaction.TYPE_TRANSFER,
        )

        prev1 = storage.get_block(1)
        bad_blk2 = Block(
            index=2,
            prev_hash=prev1.block_hash,
            transactions=[call_tx, failing_tx],
            miner_address=w_miner.address,
            difficulty=1,
            timestamp=int(time.time()) + 2,
        )

        orig_val = bc.validate_block
        bc.validate_block = lambda _b: (True, "TEST-BYPASS")
        try:
            ok, _ = bc._apply_block_unwrapped(bad_blk2)
        finally:
            bc.validate_block = orig_val

        self.assertFalse(ok, "Block 2 must be rejected due to failing_tx")
        self.assertEqual(bc.height(), 1, "Chain height must remain 1")

        self.assertEqual(
            bc.get_contract_events(contract_addr, from_block=2, to_block=2), []
        )
        self.assertEqual(
            bc.get_events_by_topic("0x11", from_block=2, to_block=2), []
        )

    def test_index_logs_idempotent_no_duplicate_events(self):
        """ContractEventIndex.index_logs() is idempotent and deduplicates by tx_id/log_index."""
        storage, bc, w_miner, w_sender, contract_addr = self._setup_chain()

        logs = [
            {"address": contract_addr, "topics": ["0x11"], "data": "aa"},
        ]
        bc._event_index.index_logs(
            tx_id="tx_dup_test_01",
            block_idx=1,
            contract_addr=contract_addr,
            logs=logs,
        )
        bc._event_index.index_logs(
            tx_id="tx_dup_test_01",
            block_idx=1,
            contract_addr=contract_addr,
            logs=logs,
        )

        events = bc.get_contract_events(contract_addr, from_block=1, to_block=1)
        dup_events = [e for e in events if e["tx_id"] == "tx_dup_test_01"]
        self.assertEqual(len(dup_events), 1)
