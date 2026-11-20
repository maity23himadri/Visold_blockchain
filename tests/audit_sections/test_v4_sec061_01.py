import os
import shutil
import sys
import tempfile
import time
import unittest

V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if V4_ROOT not in sys.path:
    sys.path.insert(0, V4_ROOT)

from visold.chain.blockchain import Blockchain
from visold.chain.roles import RoleManager
from visold.kernel.config import Config
from visold.kernel.units import from_satoshi, to_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


class _MempoolStateEngineStub:
    def __init__(self, mempool):
        self.mempool = mempool
        self.submitted = []

    def post_sync(self, evt):
        tx = Transaction.from_dict(evt.payload["tx"])
        self.submitted.append(tx)
        return self.mempool.add(tx)


class TestV4Section61RoleManagement(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmpdir.name, "test_visold.db")
        self.storage = Storage(self.db_path)
        self.chain = Blockchain(self.storage)
        self.alice = Wallet.generate()
        self.bob = Wallet.generate()

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        self._tmpdir.cleanup()

    def test_same_block_cross_role_reentry_enforces_min_investor_stake(self):
        """
        V4 Regression (Bug 1):
        Clearing a 'miner' role with REGISTER('none') and immediately registering
        as 'investor' in the same block with 1 satoshi must NOT bypass MIN_INVESTOR_STAKE.
        """
        self.storage.credit_sat(self.alice.address, to_satoshi(20.0))
        self.storage.set_role(self.alice.address, "miner", 10.0)

        now = int(time.time())
        min_fee_vsd = from_satoshi(int(getattr(Config, "MIN_TX_FEE_SAT", 1000)))
        tx_unreg = Transaction(
            sender=self.alice.address,
            receiver="",
            amount=0.0,
            fee=min_fee_vsd,
            memo="none",
            nonce=0,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_REGISTER,
        )
        tx_unreg.sign(self.alice)

        tx_inv = Transaction(
            sender=self.alice.address,
            receiver="",
            amount=0.00000001,
            fee=0.0,
            memo="investor",
            nonce=1,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_REGISTER,
        )
        tx_inv.sign(self.alice)

        locked, err, offending = self.chain._compute_block_stake_locks(
            [tx_unreg, tx_inv], block_index=1
        )
        self.assertIsNotNone(err, "Expected minimum-stake rejection on cross-role re-entry")
        self.assertEqual(offending.sender, self.alice.address)

        coinbase = Transaction(
            sender="COINBASE",
            receiver=self.bob.address,
            amount=10.0,
            fee=0.0,
            memo="coinbase",
            nonce=0,
            tx_type=Transaction.TYPE_TRANSFER,
        )
        tip = self.storage.get_block(self.storage.chain_height())
        dry_db = os.path.join(self._tmpdir.name, "dry.db")
        self.storage._conn().commit()
        self.storage._conn().execute("PRAGMA wal_checkpoint(TRUNCATE)")
        shutil.copy2(self.db_path, dry_db)
        dry_st = Storage(dry_db)
        fee_sat = int(getattr(Config, "MIN_TX_FEE_SAT", 1000))
        dry_chain = Blockchain(dry_st)
        dry_st.debit_sat(self.alice.address, fee_sat)
        dummy = Block(
            index=tip.index + 1,
            timestamp=max(now, tip.timestamp + 1),
            transactions=[coinbase, tx_unreg, tx_inv],
            prev_hash=tip.block_hash,
            difficulty=tip.difficulty,
            miner_address=self.bob.address,
            state_root="",
        )
        dry_chain._distribute_rewards(dummy, fee_sat)
        expected_root = dry_st.compute_state_root()
        dry_st.close()

        block = Block(
            index=tip.index + 1,
            timestamp=max(now, tip.timestamp + 1),
            transactions=[coinbase, tx_unreg, tx_inv],
            prev_hash=tip.block_hash,
            difficulty=tip.difficulty,
            miner_address=self.bob.address,
            state_root=expected_root,
        )
        block.mine()
        ok, msg = self.chain.apply_block(block)
        self.assertFalse(ok, f"apply_block should reject cross-role min-stake bypass: {msg}")
        role_row = self.storage.get_role(self.alice.address)
        self.assertIsNotNone(role_row)
        self.assertEqual(role_row["role"], "miner")

    def test_role_manager_handles_blockchain_none_gracefully(self):
        """
        V4 Regression (Bug 2):
        RoleManager.unstake(), register_miner(), and register_investor() must
        return (False, msg) gracefully when blockchain=None instead of raising AttributeError.
        """
        self.storage.credit_sat(self.alice.address, to_satoshi(500.0))
        self.storage.set_role(self.alice.address, "miner", 10.0)
        rm = RoleManager(self.storage, self.alice, blockchain=None, state_engine=None)

        ok_u, msg_u = rm.unstake()
        self.assertFalse(ok_u)
        self.assertIn("not wired", msg_u)

        ok_m, msg_m = rm.register_miner(10.0)
        self.assertFalse(ok_m)
        self.assertIn("not wired", msg_m)

        self.storage.set_role(self.alice.address, "none", 0.0)
        ok_i, msg_i = rm.register_investor(200.0)
        self.assertFalse(ok_i)
        self.assertIn("not wired", msg_i)

    def test_role_manager_accounts_for_pending_transfer_in_preflight(self):
        """
        V4 Regression (Bug 3):
        RoleManager.register_miner() must include pending transfer outflow in
        spendable_sat preflight and reject locally without submitting to mempool.
        """
        self.storage.credit_sat(self.alice.address, to_satoshi(25.0))
        now = int(time.time())
        xfer = Transaction(
            sender=self.alice.address,
            receiver=self.bob.address,
            amount=20.0,
            fee=round(20.0 * Config.TX_FEE_RATE, 8),
            nonce=0,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_TRANSFER,
        )
        xfer.sign(self.alice)
        ok_m, msg_m = self.chain.mempool.add(xfer)
        self.assertTrue(ok_m, f"Setup transfer rejected: {msg_m}")

        stub = _MempoolStateEngineStub(self.chain.mempool)
        rm = RoleManager(self.storage, self.alice, blockchain=self.chain, state_engine=stub)

        ok_r, msg_r = rm.register_miner(10.0)
        self.assertFalse(ok_r)
        self.assertEqual(len(stub.submitted), 0, f"Preflight should have blocked submission: {msg_r}")
        self.assertFalse(
            msg_r.startswith("REGISTER tx rejected:"),
            f"Expected local preflight rejection, got mempool rejection: {msg_r}",
        )


if __name__ == "__main__":
    unittest.main()
