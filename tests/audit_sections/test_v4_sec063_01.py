"""Section 63 V4 Regression — Stake Accounting, Deposits, Withdrawals and Stake Locking."""

import os
import sys
import tempfile
import unittest

V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if V4_ROOT not in sys.path:
    sys.path.insert(0, V4_ROOT)

from visold.chain.blockchain import Blockchain
from visold.chain.roles import RoleManager
from visold.kernel.config import Config
from visold.kernel.units import to_satoshi
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


class _StubStateEngine:
    """Minimal synchronous state_engine stub routing NEW_TX directly to mempool."""

    def __init__(self, mempool):
        self.mempool = mempool

    def post_sync(self, event):
        tx = Transaction.from_dict(event.payload["tx"])
        return self.mempool.add(tx)


def _new_chain(tmpdir: str):
    db_path = os.path.join(tmpdir, "visold.db")
    storage = Storage(db_path=db_path)
    bc = Blockchain(storage)
    return storage, bc


def _new_wallet(tmpdir: str, name: str) -> Wallet:
    return Wallet.generate()


class TestV4Section63StakeAccounting(unittest.TestCase):
    def test_compute_block_stake_locks_consistent_for_slashed_validator(self):
        """V4 Regression (Bug 1): Slashed validator's stake lock must be consistent
        whether or not they include a no-op TYPE_REGISTER in the same block."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage, bc = _new_chain(tmpdir)
            val = _new_wallet(tmpdir, "val")
            recv = _new_wallet(tmpdir, "recv")

            storage.credit_sat(val.address, to_satoshi(1000.0))
            storage.set_role(val.address, "investor", 500.0)
            self.assertTrue(storage.slash(val.address))
            role_row = storage.get_role(val.address)
            self.assertEqual(role_row["slashed"], 1)
            self.assertGreater(role_row["stake"], 0.0)

            xfer = Transaction(
                sender=val.address,
                receiver=recv.address,
                amount=600.0,
                fee=6.0,
                nonce=0,
                tx_type=Transaction.TYPE_TRANSFER,
            )
            xfer.sign(val)
            locked_a, err_a, _ = bc._compute_block_stake_locks([xfer], block_index=1)
            self.assertIsNone(err_a)
            self.assertEqual(locked_a.get(val.address, 0), to_satoshi(role_row["stake"]))

            reg = Transaction(
                sender=val.address,
                receiver="",
                amount=10.0,
                fee=0.1,
                memo="investor",
                nonce=1,
                tx_type=Transaction.TYPE_REGISTER,
            )
            reg.sign(val)
            locked_b, err_b, _ = bc._compute_block_stake_locks([xfer, reg], block_index=1)
            self.assertIsNone(err_b)
            self.assertEqual(locked_b.get(val.address, 0), locked_a.get(val.address, 0))

    def test_same_block_reentry_enforces_minimum_stake_on_role_switch(self):
        """V4 Regression (Bug 2): _compute_block_stake_locks() must enforce
        MIN_INVESTOR_STAKE when a miner unregisters and re-registers as investor
        in the same block."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage, bc = _new_chain(tmpdir)
            user = _new_wallet(tmpdir, "user")

            storage.credit_sat(user.address, to_satoshi(1000.0))
            storage.set_role(user.address, "miner", 10.0)

            unreg = Transaction(
                sender=user.address,
                receiver="",
                amount=0.0,
                fee=float(Config.MIN_TX_FEE_SAT) / Config.SATOSHI_PER_VSD,
                memo="none",
                nonce=0,
                tx_type=Transaction.TYPE_REGISTER,
            )
            unreg.sign(user)

            reg_inv = Transaction(
                sender=user.address,
                receiver="",
                amount=1.0,
                fee=0.01,
                memo="investor",
                nonce=1,
                tx_type=Transaction.TYPE_REGISTER,
            )
            reg_inv.sign(user)

            locked, err, offending = bc._compute_block_stake_locks(
                [unreg, reg_inv], block_index=1
            )
            self.assertIsNotNone(err)
            self.assertEqual(offending.sender, user.address)

    def test_role_manager_accounts_for_pending_xfer_sat_in_preflight(self):
        """V4 Regression (Bug 3): RoleManager.register_investor() must reject locally
        when pending transfer outflow leaves insufficient spendable balance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage, bc = _new_chain(tmpdir)
            user = _new_wallet(tmpdir, "user")
            recv = _new_wallet(tmpdir, "recv")

            storage.credit_sat(user.address, to_satoshi(1000.0))

            xfer = Transaction(
                sender=user.address,
                receiver=recv.address,
                amount=900.0,
                fee=9.0,
                nonce=0,
                tx_type=Transaction.TYPE_TRANSFER,
            )
            xfer.sign(user)
            ok, msg = bc.mempool.add(xfer)
            self.assertTrue(ok, msg)

            rm = RoleManager(storage, user, blockchain=bc, state_engine=_StubStateEngine(bc.mempool))
            ok_reg, msg_reg = rm.register_investor(200.0)
            self.assertFalse(ok_reg)
            self.assertNotIn("REGISTER tx rejected:", msg_reg)

    def test_mempool_rejects_transfers_spending_locked_stake(self):
        """V4 Regression (Bug 4): Mempool.add() must reject TYPE_TRANSFER transactions
        that spend locked stake."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage, bc = _new_chain(tmpdir)
            inv = _new_wallet(tmpdir, "inv")
            recv = _new_wallet(tmpdir, "recv")

            storage.credit_sat(inv.address, to_satoshi(500.0))
            storage.set_role(inv.address, "investor", 450.0)

            xfer = Transaction(
                sender=inv.address,
                receiver=recv.address,
                amount=400.0,
                fee=4.0,
                nonce=0,
                tx_type=Transaction.TYPE_TRANSFER,
            )
            xfer.sign(inv)
            ok, msg = bc.mempool.add(xfer)
            self.assertFalse(ok, f"Expected mempool rejection for spending locked stake, got: {msg}")


if __name__ == "__main__":
    unittest.main()
