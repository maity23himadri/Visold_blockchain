import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if V4_ROOT not in sys.path:
    sys.path.insert(0, V4_ROOT)

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.chain.roles import RoleManager
from visold.crypto.ecc import sig_to_hex
from visold.kernel.config import Config
from visold.kernel.events import EventType
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.selfhealing.decision import AnomalyKind, GameTheoryModel
from visold.selfhealing.monitors import ValidatorMonitor
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


class _SyncStateEngine:
    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain
        self.submitted = []

    def post_sync(self, event):
        if event.etype == EventType.NEW_TX:
            tx = Transaction.from_dict(event.payload["tx"])
            self.submitted.append(tx)
            return self.blockchain.mempool.add(tx)
        return False, "unsupported"


def _mine_block(bc: Blockchain, miner_addr: str, txs=None, timestamp=None) -> Block:
    latest = bc.latest_block()
    height = (latest.index + 1) if latest else 0
    prev_hash = latest.block_hash if latest else "0" * 64
    diff = bc.get_difficulty()
    ts = timestamp if timestamp is not None else max(int(time.time()), (latest.timestamp + 1) if latest else 1)

    tx_list = list(txs or [])
    cb = Transaction.coinbase(miner_addr, bc.compute_reward(height), height)
    all_txs = [cb] + tx_list
    state_root = bc.dry_run_state_root(
        transactions=all_txs,
        miner_address=miner_addr,
        height=height,
        timestamp=ts,
        difficulty=diff,
    )
    blk = Block(
        index=height,
        prev_hash=prev_hash,
        transactions=all_txs,
        miner_address=miner_addr,
        difficulty=diff,
        timestamp=ts,
        state_root=state_root,
    )
    blk.mine()
    return blk


class TestV4Section62Eligibility(unittest.TestCase):
    def test_get_validators_works_on_genesis_only_chain(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(os.path.join(tmpdir, "chain.db"))
            bc = Blockchain(storage)
            self.assertEqual(bc.height(), 0)

            vals = storage.get_validators()
            self.assertIsInstance(vals, list)

            genesis = storage.get_block(0)
            mon = ValidatorMonitor(storage, bc)
            mon.observe_block(genesis)

            ev = GameTheoryModel(storage)
            res = ev.compute(AnomalyKind.DOUBLE_SIGN, {}, 0)
            self.assertIsNotNone(res)

    def test_depth_finality_uses_pre_block_roles_and_requires_nonzero_stake(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(os.path.join(tmpdir, "chain.db"))
            bc = Blockchain(storage)
            w_miner = Wallet.generate()
            w_v1 = Wallet.generate()
            w_v2 = Wallet.generate()
            w_v3 = Wallet.generate()

            with patch.object(Config, "INITIAL_DIFFICULTY", 0.25), \
                 patch.object(Config, "MIN_DIFFICULTY", 0.25), \
                 patch.object(Config, "BOOTSTRAP_POW_FINALITY_DEPTH", 5), \
                 patch.object(Config, "POW_FINALITY_DEPTH", 2), \
                 patch.object(Config, "MIN_VALIDATORS_FOR_BFT", 3):

                for _ in range(3):
                    b = _mine_block(bc, w_miner.address)
                    ok, msg = bc.apply_block(b)
                    self.assertTrue(ok, msg)

                storage.credit(w_v1.address, 500.0)
                storage.credit(w_v2.address, 500.0)
                storage.credit(w_v3.address, 500.0)
                storage.set_role(w_v1.address, "investor", 250.0)
                storage.set_role(w_v2.address, "investor", 250.0)

                while bc.height() < 6:
                    b = _mine_block(bc, w_miner.address)
                    ok, msg = bc.apply_block(b)
                    self.assertTrue(ok, msg)

                self.assertTrue(storage.get_block(1).finalized)
                self.assertFalse(storage.get_block(2).finalized)

                # At height 7, v3 submits REGISTER("investor", 250.0).
                # Pre-block validator count is 2 (< 3), so block 7 is STILL in
                # PoW-bootstrap mode (v3 only activates at block 8), and block 2
                # (7 - 5 = 2) should be finalized under bootstrap depth.
                reg_v3 = Transaction(
                    sender=w_v3.address,
                    receiver="",
                    amount=250.0,
                    fee=2.5,
                    memo="investor",
                    nonce=storage.get_nonce(w_v3.address),
                    tx_type=Transaction.TYPE_REGISTER,
                )
                reg_v3.sign(w_v3)
                b7 = _mine_block(bc, w_miner.address, txs=[reg_v3])
                ok, msg = bc.apply_block(b7)
                self.assertTrue(ok, msg)

                ce = ConsensusEngine(bc, w_v1)
                ce.finalize_applied_block(b7)
                self.assertFalse(b7.finalized)
                self.assertTrue(storage.get_block(2).finalized)

                # Part B: 3 investors with 0.0 stake each must NOT count as active BFT validators
                storage.set_role(w_v1.address, "investor", 0.0)
                storage.set_role(w_v2.address, "investor", 0.0)
                storage.set_role(w_v3.address, "investor", 0.0)

                b8 = _mine_block(bc, w_miner.address)
                ok, msg = bc.apply_block(b8)
                self.assertTrue(ok, msg)
                self.assertTrue(storage.get_block(3).finalized)

    def test_role_manager_rejects_slashed_address_in_preflight(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(os.path.join(tmpdir, "chain.db"))
            bc = Blockchain(storage)
            se = _SyncStateEngine(bc)
            w = Wallet.generate()
            storage.credit(w.address, 500.0)
            storage.set_role(w.address, "investor", 250.0)
            self.assertTrue(storage.slash(w.address))
            storage.set_role(w.address, "none", 0.0)
            self.assertTrue(bool(storage.get_role(w.address)["slashed"]))

            rm = RoleManager(storage, w, blockchain=bc, state_engine=se)
            ok, msg = rm.register_investor(250.0)
            self.assertFalse(ok, f"Expected preflight rejection for slashed address, got: {msg}")
            self.assertEqual(len(se.submitted), 0)

    def test_accept_chain_rejects_deep_reorg_past_bft_finalized_block_after_investors_exit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_a = Storage(os.path.join(tmpdir, "a.db"))
            storage_b = Storage(os.path.join(tmpdir, "b.db"))
            bc_a = Blockchain(storage_a)
            bc_b = Blockchain(storage_b)

            v1, v2, v3 = Wallet.generate(), Wallet.generate(), Wallet.generate()
            miner_b = Wallet.generate()

            with patch.object(Config, "INITIAL_DIFFICULTY", 0.25), \
                 patch.object(Config, "MIN_DIFFICULTY", 0.25), \
                 patch.object(Config, "MIN_VALIDATORS_FOR_BFT", 3), \
                 patch.object(Config, "BOOTSTRAP_POW_FINALITY_DEPTH", 50), \
                 patch.object(Config, "POW_FINALITY_DEPTH", 50), \
                 patch.object(Config, "MIN_INVESTOR_STAKE", 500_000_000):

                for v in (v1, v2, v3):
                    b = _mine_block(bc_a, v.address)
                    ok, msg = bc_a.apply_block(b)
                    self.assertTrue(ok, msg)

                reg_txs = []
                for v in (v1, v2, v3):
                    t = Transaction(
                        sender=v.address,
                        receiver="",
                        amount=5.0,
                        fee=0.05,
                        memo="investor",
                        nonce=storage_a.get_nonce(v.address),
                        tx_type=Transaction.TYPE_REGISTER,
                    )
                    t.sign(v)
                    reg_txs.append(t)
                b_reg = _mine_block(bc_a, v1.address, txs=reg_txs)
                ok, msg = bc_a.apply_block(b_reg)
                self.assertTrue(ok, msg)

                b_fin = _mine_block(bc_a, v1.address)
                ok, msg = bc_a.apply_block(b_fin)
                self.assertTrue(ok, msg)
                for v in (v1, v2, v3):
                    sig_hex = sig_to_hex(v.sign(b_fin.block_hash.encode()))
                    self.assertTrue(bc_a.add_validator_sig(b_fin.block_hash, v.address, sig_hex, v.pub_hex))
                fin_height = b_fin.index
                self.assertTrue(storage_a.get_block(fin_height).finalized)
                fin_hash = b_fin.block_hash

                unreg_txs = []
                for v in (v1, v2, v3):
                    t = Transaction(
                        sender=v.address,
                        receiver="",
                        amount=0.0,
                        fee=float(Config.MIN_TX_FEE_SAT) / 100_000_000,
                        memo="none",
                        nonce=storage_a.get_nonce(v.address),
                        tx_type=Transaction.TYPE_REGISTER,
                    )
                    t.sign(v)
                    unreg_txs.append(t)
                b_unreg = _mine_block(bc_a, v1.address, txs=unreg_txs)
                ok, msg = bc_a.apply_block(b_unreg)
                self.assertTrue(ok, msg)
                self.assertEqual(storage_a.get_all_by_role("investor"), [])

                fork_blocks = [storage_b.get_block(0)]
                target_len = bc_a.height() + 3
                for _ in range(target_len):
                    blk = _mine_block(bc_b, miner_b.address)
                    ok, msg = bc_b.apply_block(blk)
                    self.assertTrue(ok, msg)
                    fork_blocks.append(storage_b.get_block(bc_b.height()))

                accepted, msg = bc_a.accept_chain(fork_blocks)
                self.assertFalse(accepted, f"Reorg past BFT-finalized block should be rejected: {msg}")
                self.assertEqual(storage_a.get_block(fin_height).block_hash, fin_hash)


if __name__ == "__main__":
    unittest.main()
