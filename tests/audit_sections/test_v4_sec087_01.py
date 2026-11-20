"""Section 87 V4 Regression Tests: L2 Ledger Synchronization and Replay Protection."""

import hashlib
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
from visold.crypto.ecc import ecdsa_sign, sig_to_hex
from visold.kernel.units import to_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.rollup.batches import RollupSubmission
from visold.rollup.compact_codec import l2_sig_compact
from visold.rollup.l2_state import L2Transaction, Layer2State
from visold.rollup import ledger_sync
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _sign_l2_tx(wallet: Wallet, receiver: str, amount_sat: int, nonce: int,
                 timestamp: int = 0) -> L2Transaction:
    ts = int(timestamp) if timestamp else int(time.time())
    unsigned = L2Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount_sat=amount_sat,
        nonce=nonce,
        timestamp=ts,
    )
    digest = hashlib.sha256(unsigned.signing_bytes()).digest()
    r, s = ecdsa_sign(wallet.priv, digest)
    sig_hex = l2_sig_compact(sig_to_hex((r, s)))
    return L2Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount_sat=amount_sat,
        nonce=nonce,
        timestamp=ts,
        sig=sig_hex,
        pub=wallet.pub_hex,
    )


class TestV4Section87(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "visold_test.db")
        self.storage = Storage(self.db_path)

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        self._tmp.cleanup()

    def test_l2_state_persist_and_restore(self):
        """Layer2State persists tree, history, last_batch_id, and first_height atomically."""
        w1 = Wallet.generate()
        w2 = Wallet.generate()
        l2 = Layer2State(self.storage)
        ok, msg = l2.L2_deposit(w1.address, 500_000, l1_height=1, l1_block_hash="h1")
        self.assertTrue(ok, msg)

        tx0 = _sign_l2_tx(w1, w2.address, 100_000, nonce=0)
        ok, msg = l2.apply_l2_tx(tx0)
        self.assertTrue(ok, msg)
        new_root = l2.root()
        ok, msg = l2.commit_batch(0, new_root, l1_height=2, l1_block_hash="h2")
        self.assertTrue(ok, msg)

        l2_reloaded = Layer2State(self.storage)
        self.assertEqual(l2_reloaded.root(), new_root)
        self.assertEqual(l2_reloaded.get_balance_sat(w1.address), 400_000)
        self.assertEqual(l2_reloaded.get_balance_sat(w2.address), 100_000)
        self.assertEqual(l2_reloaded.get_nonce(w1.address), 1)
        self.assertEqual(l2_reloaded._last_batch_id, 0)
        self.assertEqual(l2_reloaded._history_first_height, 1)

    def test_l2_replay_protection_nonce_and_batch_id(self):
        """L2Transaction nonce replay and Layer2State batch_id replay are both rejected."""
        w1 = Wallet.generate()
        w2 = Wallet.generate()
        l2 = Layer2State(self.storage)
        l2.L2_deposit(w1.address, 500_000, l1_height=1, l1_block_hash="h1")

        tx0 = _sign_l2_tx(w1, w2.address, 100_000, nonce=0)
        ok, _ = l2.apply_l2_tx(tx0)
        self.assertTrue(ok)

        ok_replay, msg_replay = l2.apply_l2_tx(tx0)
        self.assertFalse(ok_replay)
        self.assertIn("nonce mismatch", msg_replay)

        root1 = l2.root()
        ok_c, _ = l2.commit_batch(0, root1, l1_height=2, l1_block_hash="h2")
        self.assertTrue(ok_c)

        ok_c_replay, msg_c_replay = l2.commit_batch(0, root1, l1_height=3, l1_block_hash="h3")
        self.assertFalse(ok_c_replay)
        self.assertIn("not strictly greater", msg_c_replay)

    def test_storage_replay_guard_survives_pruning_and_clears_on_rollback(self):
        """tx_replay_guard persists across record/check and clears only on rollback."""
        tx_id = "a" * 64
        self.assertFalse(self.storage.replay_guard_exists(tx_id))
        self.storage.record_applied_tx_id(tx_id)
        self.assertTrue(self.storage.replay_guard_exists(tx_id))
        self.assertIn(tx_id, self.storage.existing_tx_ids([tx_id]))

        self.storage.delete_block(999, rollback_tx_ids=[tx_id])
        self.assertFalse(self.storage.replay_guard_exists(tx_id))

    def test_skipped_rollup_not_indexed_by_sync_local_ledger(self):
        """V4 fix: sync_local_ledger / _ledger_collect_entries does NOT index L2 txs
        from a skipped TYPE_ROLLUP that was rejected by _apply_rollup_tx()."""
        chain = Blockchain(self.storage)
        w1 = Wallet.generate()
        w2 = Wallet.generate()

        self.storage.credit_sat(w1.address, to_satoshi(10.0))
        tip = chain.latest_block()

        l2tx = _sign_l2_tx(w1, w2.address, 100_000, nonce=0)
        stale_prev_root = "f" * 64
        fake_new_root = "e" * 64
        sub = RollupSubmission(
            batch_id=0,
            previous_l2_root=stale_prev_root,
            new_l2_root=fake_new_root,
            zk_proof=b"\x01" * 32,
            compressed_data=RollupSubmission.compress_batch([l2tx]),
            backend="simulated",
            backend_security="test",
        )
        rollup_tx = Transaction(
            sender=w1.address,
            receiver=w1.address,
            amount=0.0,
            fee=0.0,
            tx_type=Transaction.TYPE_ROLLUP,
            data=sub.to_json(),
            nonce=0,
            expiry=int(time.time()) + 3600,
        )
        rollup_tx.sign(w1)

        block = Block(
            index=tip.index + 1,
            prev_hash=tip.block_hash,
            transactions=[rollup_tx],
            miner_address=w1.address,
            difficulty=1,
            nonce=0,
            timestamp=int(time.time()),
        )
        ok_r, msg_r = chain._apply_rollup_tx(rollup_tx, block)
        self.assertFalse(ok_r)
        self.assertIn("stale rollup", msg_r)

        self.assertEqual(chain.layer2.get_balance_sat(w2.address), 0)
        self.assertEqual(chain.layer2._last_batch_id, -1)

        ledger_path = os.path.join(self._tmp.name, "vsd_personal_ledger.json")
        orig_path = ledger_sync._LOCAL_LEDGER_PATH
        try:
            ledger_sync._LOCAL_LEDGER_PATH = ledger_path
            entries = ledger_sync._ledger_collect_entries(
                block, w2.address, skipped_rollup_tx_ids=[rollup_tx.tx_id]
            )
            self.assertEqual(len(entries), 0)
        finally:
            ledger_sync._LOCAL_LEDGER_PATH = orig_path


if __name__ == "__main__":
    unittest.main()
