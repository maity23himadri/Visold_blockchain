import json
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
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.rollup.batches import RollupSubmission
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, L2Transaction, Layer2State
from visold.rollup import ledger_sync
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_l2_tx(sender_wallet: Wallet, receiver_addr: str, amount_sat: int,
                nonce: int, timestamp: int = 0) -> L2Transaction:
    return sender_wallet.sign_l2_tx(receiver_addr, amount_sat, nonce, timestamp)


class TestV4Section87_2(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "test_visold.db")
        self.storage = Storage(self.db_path)

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        self.tmpdir.cleanup()

    def test_l2_tx_replay_and_batch_id_monotonicity_across_restart(self):
        """Verify L2Transaction nonce replay protection and commit_batch monotonicity
        survive _persist() -> _try_restore_from_storage()."""
        w1 = Wallet.generate()
        w2 = Wallet.generate()

        l2 = Layer2State(self.storage)
        ok, msg = l2.L2_deposit(w1.address, 10_000, l1_height=1, l1_block_hash="a" * 64)
        self.assertTrue(ok, msg)

        l2tx = _make_l2_tx(w1, w2.address, 2_500, nonce=0)
        ok_a, msg_a = l2.apply_l2_tx(l2tx)
        self.assertTrue(ok_a, msg_a)

        ok_rep, msg_rep = l2.apply_l2_tx(l2tx)
        self.assertFalse(ok_rep)
        self.assertIn("nonce mismatch", msg_rep)

        new_root = l2.root()
        ok_c, msg_c = l2.commit_batch(0, new_root, l1_height=2, l1_block_hash="b" * 64)
        self.assertTrue(ok_c, msg_c)

        l2_restarted = Layer2State(self.storage)
        self.assertEqual(l2_restarted.root(), new_root)
        self.assertEqual(l2_restarted.get_balance_sat(w1.address), 7_500)
        self.assertEqual(l2_restarted.get_balance_sat(w2.address), 2_500)
        self.assertEqual(l2_restarted.get_nonce(w1.address), 1)

        ok_c2, msg_c2 = l2_restarted.commit_batch(0, new_root, l1_height=3, l1_block_hash="c" * 64)
        self.assertFalse(ok_c2)
        self.assertIn("not strictly greater", msg_c2)

        ok_rep2, msg_rep2 = l2_restarted.apply_l2_tx(l2tx)
        self.assertFalse(ok_rep2)
        self.assertIn("nonce mismatch", msg_rep2)

    def test_l2_rollback_and_l1_replay_guard(self):
        """Verify Layer2State.rollback_to_height and Storage replay_guard_exists."""
        w1 = Wallet.generate()
        l2 = Layer2State(self.storage)
        l2.L2_deposit(w1.address, 5_000, l1_height=1, l1_block_hash="1" * 64)
        l2.L2_deposit(w1.address, 3_000, l1_height=2, l1_block_hash="2" * 64)

        can_rb, _ = l2.can_rollback_to_height(1)
        self.assertTrue(can_rb)
        ok_rb, _ = l2.rollback_to_height(1)
        self.assertTrue(ok_rb)
        self.assertEqual(l2.get_balance_sat(w1.address), 5_000)

        tx_id = "deadbeef" * 8
        self.assertFalse(self.storage.replay_guard_exists(tx_id))
        self.storage.record_applied_tx_id(tx_id)
        self.assertTrue(self.storage.replay_guard_exists(tx_id))

    def test_ledger_sync_skips_rejected_rollup_l2_txs(self):
        """V4 fix: sync_local_ledger() does NOT index L2 transactions from a
        TYPE_ROLLUP tx that was rejected by _apply_rollup_tx()."""
        orig_ledger_path = ledger_sync._LOCAL_LEDGER_PATH
        orig_env_owner = os.environ.get("VSD_LEDGER_OWNER")
        ledger_file = os.path.join(self.tmpdir.name, "vsd_personal_ledger.json")
        try:
            ledger_sync._LOCAL_LEDGER_PATH = ledger_file
            bc = Blockchain(self.storage)
            owner = Wallet.generate()
            other = Wallet.generate()
            miner = Wallet.generate()

            os.environ["VSD_LEDGER_OWNER"] = owner.address

            l2tx = _make_l2_tx(owner, other.address, 1_000, nonce=0)
            blob = RollupSubmission.compress_batch([l2tx])
            stale_prev_root = "f" * 64
            fake_new_root = "e" * 64
            sub = RollupSubmission(
                batch_id=0,
                previous_l2_root=stale_prev_root,
                new_l2_root=fake_new_root,
                zk_proof=b"\x00" * 32,
                compressed_data=blob,
                backend="simulated",
                backend_security="dev",
            )

            rollup_tx = Transaction(
                sender=owner.address,
                receiver=L2_BRIDGE_ADDRESS,
                amount=0.0,
                fee=0.0,
                nonce=0,
                tx_type=Transaction.TYPE_ROLLUP,
                data=sub.to_json(),
                expiry=int(time.time()) + 3600,
            )
            rollup_tx.sign(owner)

            latest = bc.latest_block()
            next_idx = latest.index + 1
            reward = bc.compute_reward(next_idx)
            coinbase = Transaction.coinbase(miner.address, reward, next_idx)
            txs = [coinbase, rollup_tx]

            ts = max(int(time.time()), latest.timestamp + 1)
            diff = bc.get_difficulty()
            state_root = bc.dry_run_state_root(txs, miner.address, next_idx, timestamp=ts, difficulty=diff)
            blk = Block(
                index=next_idx,
                prev_hash=latest.block_hash,
                transactions=txs,
                timestamp=ts,
                difficulty=diff,
                miner_address=miner.address,
                state_root=state_root,
            )
            blk.mine()

            ok_apply, msg_apply = bc.apply_block(blk)
            self.assertTrue(ok_apply, f"apply_block failed: {msg_apply}")

            self.assertEqual(bc.layer2.get_balance_sat(other.address), 0)
            self.assertEqual(bc.layer2.get_nonce(owner.address), 0)
            self.assertEqual(bc.layer2._last_batch_id, -1)

            # Give daemon thread a brief window if any, then verify skipped L2 tx is NOT archived
            time.sleep(0.3)
            if os.path.exists(ledger_file):
                with open(ledger_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                l2_entries = [
                    e for e in data.get("entries", [])
                    if e.get("Type") == "L2" and e.get("Tx_Hash") == l2tx.l2_tx_id
                ]
                self.assertEqual(len(l2_entries), 0)
        finally:
            ledger_sync._LOCAL_LEDGER_PATH = orig_ledger_path
            if orig_env_owner is None:
                os.environ.pop("VSD_LEDGER_OWNER", None)
            else:
                os.environ["VSD_LEDGER_OWNER"] = orig_env_owner


if __name__ == "__main__":
    unittest.main()
