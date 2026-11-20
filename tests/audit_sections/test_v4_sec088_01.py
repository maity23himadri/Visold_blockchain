"""Section 88 V4 Regression Tests: Sequencer Ordering, Liveness, and Censorship Resistance."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.chain.blockchain import Blockchain
from visold.chain.sequencer import Sequencer
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = Config.SATOSHI_PER_VSD
FAR = 2_000_000_000


def _make_chain(td: str, name: str = "audit88.db"):
    st = Storage(os.path.join(td, name))
    bc = Blockchain(st)
    bc._rolling_pruner.prune_async = lambda h: None
    return st, bc


def _transfer(st: Storage, sender: Wallet, receiver: str, amount_vsd: float,
              nonce=None) -> Transaction:
    tx = Transaction(
        sender=sender.address,
        receiver=receiver,
        amount=amount_vsd,
        fee=round(amount_vsd * Config.TX_FEE_RATE, 8),
        nonce=st.get_nonce(sender.address) if nonce is None else nonce,
        expiry=FAR,
    )
    tx.sign(sender)
    return tx


def _build_block(bc: Blockchain, miner: Wallet, txs: list) -> Block:
    height = bc.height() + 1
    cb = Transaction.coinbase(miner.address, bc.compute_reward_sat(height) / SAT, height)
    root = bc.dry_run_state_root([cb] + list(txs), miner.address, height)
    blk = Block(
        index=height,
        prev_hash=bc.latest_block().block_hash,
        transactions=[cb] + list(txs),
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        state_root=root,
    )
    assert blk.mine()
    return blk


class TestV4Section88(unittest.TestCase):
    def setUp(self):
        self._prev_disable = logging.root.manager.disable
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(self._prev_disable)

    def test_future_timestamp_head_does_not_stall_should_seal(self):
        """V4 fix: Far-future txs are rejected at admission, and a within-drift
        future-dated L2 tx at _pending[0] does not prevent _should_seal() from
        returning True when subsequent valid txs exceed MAX_AGE."""
        with tempfile.TemporaryDirectory() as td:
            st, bc = _make_chain(td)
            miner, attacker, user, other, seqw = (Wallet.generate() for _ in range(5))
            st.credit_sat(user.address, 10 * SAT)
            ok, msg = bc.apply_block(_build_block(
                bc, miner, [_transfer(st, user, L2_BRIDGE_ADDRESS, 2.0)]))
            self.assertTrue(ok, msg)

            seq = Sequencer(bc.layer2, seqw, bc)
            seq._running = True

            now = int(time.time())
            far_future_tx = attacker.sign_l2_tx(
                other.address, amount_sat=1000, nonce=0,
                timestamp=now + 365 * 86400,
            )
            ok_far, msg_far = seq.add_l2_tx(far_future_tx)
            self.assertFalse(ok_far)
            self.assertIn("future", msg_far)

            near_future_tx = attacker.sign_l2_tx(
                other.address, amount_sat=1000, nonce=0,
                timestamp=now + 120,
            )
            ok_att, msg_att = seq.add_l2_tx(near_future_tx)
            self.assertTrue(ok_att, msg_att)

            legit_tx = user.sign_l2_tx(
                other.address, amount_sat=int(0.5 * SAT), nonce=0,
                timestamp=now - (Config.L2_BATCH_MAX_AGE_SECS + 60),
            )
            ok_legit, msg_legit = seq.add_l2_tx(legit_tx)
            self.assertTrue(ok_legit, msg_legit)

            self.assertTrue(seq._should_seal())
            self.assertEqual(len(seq._pending), 2)

    def test_next_batch_id_syncs_after_external_commit(self):
        """V4 fix: When another sequencer commits batch_id=0 on-chain, our
        sequencer syncs _next_batch_id and seals batch_id=1 cleanly."""
        with tempfile.TemporaryDirectory() as td:
            st, bc = _make_chain(td)
            miner, user, other, seq1_w, seq2_w = (Wallet.generate() for _ in range(5))
            st.credit_sat(user.address, 10 * SAT)
            st.credit_sat(seq1_w.address, 1 * SAT)
            st.credit_sat(seq2_w.address, 1 * SAT)
            ok, msg = bc.apply_block(_build_block(
                bc, miner, [_transfer(st, user, L2_BRIDGE_ADDRESS, 5.0)]))
            self.assertTrue(ok, msg)

            seq1 = Sequencer(bc.layer2, seq1_w, bc)
            seq1._running = True
            seq1._next_batch_id = max(0, int(bc.layer2._last_batch_id) + 1)

            seq2 = Sequencer(bc.layer2, seq2_w, bc)
            seq2._running = True
            seq2._next_batch_id = max(0, int(bc.layer2._last_batch_id) + 1)

            tx0 = user.sign_l2_tx(other.address, amount_sat=1 * SAT, nonce=0,
                                  timestamp=int(time.time()))
            self.assertTrue(seq2.add_l2_tx(tx0)[0])
            l1_tx0, bid0, app0 = seq2._seal_one()
            self.assertEqual(bid0, 0)
            seq2._finalize_seal(bid0, app0)
            ok_b0, msg_b0 = bc.apply_block(_build_block(bc, miner, [l1_tx0]))
            self.assertTrue(ok_b0, msg_b0)
            self.assertEqual(bc.layer2._last_batch_id, 0)

            tx1 = user.sign_l2_tx(other.address, amount_sat=1 * SAT, nonce=1,
                                  timestamp=int(time.time()))
            self.assertTrue(seq1.add_l2_tx(tx1)[0])
            sealed1 = seq1._seal_one()
            self.assertIsNotNone(sealed1)
            l1_tx1, bid1, app1 = sealed1
            self.assertEqual(bid1, 1)
            seq1._finalize_seal(bid1, app1)

            ok_b1, msg_b1 = bc.apply_block(_build_block(bc, miner, [l1_tx1]))
            self.assertTrue(ok_b1, msg_b1)
            self.assertEqual(bc.layer2.get_balance_sat(other.address), 2 * SAT)

    def test_no_premature_eviction_while_prior_batch_unmined(self):
        """V4 fix: A valid nonce=1 tx is NOT prematurely evicted while batch 0
        (nonce=0) is still unmined, and seals once batch 0 is mined."""
        with tempfile.TemporaryDirectory() as td:
            st, bc = _make_chain(td)
            miner, user, other, seqw = (Wallet.generate() for _ in range(4))
            st.credit_sat(user.address, 10 * SAT)
            st.credit_sat(seqw.address, 1 * SAT)
            ok, msg = bc.apply_block(_build_block(
                bc, miner, [_transfer(st, user, L2_BRIDGE_ADDRESS, 5.0)]))
            self.assertTrue(ok, msg)

            seq = Sequencer(bc.layer2, seqw, bc)
            seq._running = True

            now = int(time.time())
            tx0 = user.sign_l2_tx(other.address, amount_sat=1 * SAT, nonce=0,
                                  timestamp=now - 60)
            self.assertTrue(seq.add_l2_tx(tx0)[0])
            l1_tx0, bid0, app0 = seq._seal_one()
            seq._finalize_seal(bid0, app0)

            tx1 = user.sign_l2_tx(other.address, amount_sat=1 * SAT, nonce=1,
                                  timestamp=now - 60)
            self.assertTrue(seq.add_l2_tx(tx1)[0])
            self.assertTrue(seq._should_seal())

            for _ in range(seq._max_seal_attempts):
                res = seq._seal_one()
                self.assertIsNone(res)

            self.assertEqual(len(seq._pending), 1)
            self.assertEqual(seq._pending[0].l2_tx_id, tx1.l2_tx_id)

            ok_b0, msg_b0 = bc.apply_block(_build_block(bc, miner, [l1_tx0]))
            self.assertTrue(ok_b0, msg_b0)
            self.assertEqual(bc.layer2.get_nonce(user.address), 1)

            sealed1 = seq._seal_one()
            self.assertIsNotNone(sealed1)
            l1_tx1, bid1, app1 = sealed1
            self.assertEqual(bid1, 1)
            self.assertEqual([t.l2_tx_id for t in app1], [tx1.l2_tx_id])
            seq._finalize_seal(bid1, app1)
            self.assertEqual(len(seq._pending), 0)


if __name__ == "__main__":
    unittest.main()
