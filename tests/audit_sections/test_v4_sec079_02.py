"""V4 regression tests for Section 79 (Session 06): Contract Storage and CREATE2 Lifecycle."""

import os
import tempfile
import unittest

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.vm.opcodes import Op
from visold.wallet.wallet import Wallet


def _make_runtime_return_init(runtime_code: bytes) -> bytes:
    code = bytearray()
    for i, b in enumerate(runtime_code):
        code.extend([Op.PUSH1, b, Op.PUSH1, i, Op.MSTORE8])
    code.extend([Op.PUSH1, len(runtime_code), Op.PUSH1, 0, Op.RETURN])
    return bytes(code)


class TestAuditSection79(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmpdir.name, "test_v3_s79.db")
        self.storage = Storage(db_path=self.db_path)
        self.bc = Blockchain(storage=self.storage)
        self.wallet = Wallet.generate()
        self.sender = self.wallet.address
        self.storage.credit_sat(self.sender, 100_000 * Config.SATOSHI_PER_VSD)
        self.miner = Wallet.generate().address

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        self._tmpdir.cleanup()

    def _mine_and_apply(self, txs):
        tip = self.bc.latest_block()
        height = tip.index + 1
        diff = self.bc.get_difficulty()
        ts = max(tip.timestamp + 1, 1_700_000_000 + height)
        state_root = self.bc.dry_run_state_root(
            txs, self.miner, height,
            difficulty=diff, timestamp=ts,
        )
        cb = Transaction.coinbase(self.miner, self.bc.compute_reward(height), height)
        blk = Block(
            index=height,
            prev_hash=tip.block_hash,
            transactions=[cb] + list(txs),
            miner_address=self.miner,
            difficulty=diff,
            timestamp=ts,
            state_root=state_root,
        )
        blk.mine()
        ok, reason = self.bc.apply_block(blk)
        self.assertTrue(ok, f"apply_block failed at height {height}: {reason}")
        return blk

    def test_rollback_preserves_nonzero_storage_tag_and_state_root(self):
        """Unfixed in V4: rollback wipes non-zero storage tag on overwritten slot; see remaining_071_080.md."""
        runtime = bytes([
            Op.PUSH1, 99,
            Op.PUSH1, 5,
            Op.TYPESET,
            Op.PUSH1, 0,
            Op.SSTORE,
            Op.STOP,
        ])
        init_prefix = bytes([
            Op.PUSH1, 42,
            Op.PUSH1, 3,
            Op.TYPESET,
            Op.PUSH1, 0,
            Op.SSTORE,
        ])
        init_code = init_prefix + _make_runtime_return_init(runtime)

        tx1 = Transaction(
            sender=self.sender,
            receiver="",
            amount=0.0,
            nonce=0,
            tx_type=Transaction.TYPE_DEPLOY,
            data=init_code.hex(),
            gas_limit=500_000,
            gas_price=0.0001,
        )
        tx1.sign(self.wallet)
        self._mine_and_apply([tx1])

        receipt1 = self.storage.get_vvm_receipt(tx1.tx_id)
        self.assertIsNotNone(receipt1)
        self.assertTrue(receipt1["success"])
        c_addr = receipt1["contract_addr"]

        self.assertEqual(self.storage.sload(c_addr, "0x0"), 42)
        self.assertEqual(self.storage.get_storage_tag(c_addr, "0x0"), 3)
        state_root_b1 = self.storage.compute_state_root()
        c_root_b1 = self.storage.get_contract(c_addr)["storage_root"]

        tx2 = Transaction(
            sender=self.sender,
            receiver=c_addr,
            amount=0.0,
            nonce=1,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=500_000,
            gas_price=0.0001,
        )
        tx2.sign(self.wallet)
        self._mine_and_apply([tx2])

        self.assertEqual(self.storage.sload(c_addr, "0x0"), 99)
        self.assertEqual(self.storage.get_storage_tag(c_addr, "0x0"), 5)

        self.assertTrue(self.bc.rollback(1))

        self.assertEqual(self.storage.sload(c_addr, "0x0"), 42)
        self.assertEqual(self.storage.get_storage_tag(c_addr, "0x0"), 3)
        self.assertEqual(self.storage.get_contract(c_addr)["storage_root"], c_root_b1)
        self.assertEqual(self.storage.compute_state_root(), state_root_b1)

    def test_create2_after_selfdestruct_rejected_without_locking_funds(self):
        """CREATE2 to a previously destroyed address is rejected without transferring funds."""
        child_init = _make_runtime_return_init(bytes([Op.CALLER, Op.SELFDESTRUCT]))

        f_runtime = bytearray()
        for i, b in enumerate(child_init):
            f_runtime.extend([Op.PUSH1, b, Op.PUSH1, i, Op.MSTORE8])
        f_runtime.extend([
            Op.PUSH1, 1,
            Op.PUSH1, len(child_init),
            Op.PUSH1, 0,
            Op.PUSH2, 0x03, 0xe8,
            Op.CREATE2,
            Op.PUSH1, 0,
            Op.SSTORE,
            Op.STOP,
        ])
        f_init = _make_runtime_return_init(bytes(f_runtime))

        tx1 = Transaction(
            sender=self.sender,
            receiver="",
            amount=1.0,
            nonce=0,
            tx_type=Transaction.TYPE_DEPLOY,
            data=f_init.hex(),
            gas_limit=500_000,
            gas_price=0.0001,
        )
        tx1.sign(self.wallet)
        self._mine_and_apply([tx1])
        f_addr = self.storage.get_vvm_receipt(tx1.tx_id)["contract_addr"]

        tx2 = Transaction(
            sender=self.sender,
            receiver=f_addr,
            amount=0.0,
            nonce=1,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=500_000,
            gas_price=0.0001,
        )
        tx2.sign(self.wallet)
        self._mine_and_apply([tx2])
        r2 = self.storage.get_vvm_receipt(tx2.tx_id)
        self.assertTrue(r2["success"])
        deployed_list = r2["storage_delta"].get("__deployed_contracts__", [])
        self.assertEqual(len(deployed_list), 1)
        c2_addr = deployed_list[0]
        self.assertIsNotNone(self.storage.get_contract(c2_addr))
        self.assertEqual(self.storage.get_balance_sat(c2_addr), 1000)

        tx3 = Transaction(
            sender=self.sender,
            receiver=c2_addr,
            amount=0.0,
            nonce=2,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=500_000,
            gas_price=0.0001,
        )
        tx3.sign(self.wallet)
        self._mine_and_apply([tx3])
        self.assertTrue(self.storage.get_vvm_receipt(tx3.tx_id)["success"])
        self.assertIsNone(self.storage.get_contract(c2_addr))
        self.assertEqual(self.storage.get_balance_sat(c2_addr), 0)

        f_bal_before = self.storage.get_balance_sat(f_addr)

        tx4 = Transaction(
            sender=self.sender,
            receiver=f_addr,
            amount=0.0,
            nonce=3,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=500_000,
            gas_price=0.0001,
        )
        tx4.sign(self.wallet)
        tip3 = self.bc.latest_block()
        blk4_stub = Block(
            index=4,
            prev_hash=tip3.block_hash,
            transactions=[tx4],
            miner_address=self.miner,
            difficulty=self.bc.get_difficulty(),
            timestamp=tip3.timestamp + 1,
        )
        _, vvm_ok, _ = self.bc._apply_vvm_tx(tx4, blk4_stub)
        self.assertTrue(vvm_ok)
        r4 = self.storage.get_vvm_receipt(tx4.tx_id)
        self.assertTrue(r4["success"])

        self.assertNotIn(c2_addr, r4["storage_delta"].get("__deployed_contracts__", []))
        self.assertEqual(self.storage.get_balance_sat(f_addr), f_bal_before)
        self.assertEqual(self.storage.get_balance_sat(c2_addr), 0)
        self.assertIsNone(self.storage.get_contract(c2_addr))
