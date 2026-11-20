import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.chain.blockchain import Blockchain
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.bootstrap_sync import _extract_commitment, verify_bootstrap_header_chain
from visold.rollup.batches import RollupSubmission
from visold.rollup.l2_state import L2StateTree, L2Transaction, Layer2State
from visold.rollup.proofs import ProofRegistry
from visold.storage.rolling_window_pruner import RollingWindowPruner
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


class TestV4Section86(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "test_86.db")
        self.storage = Storage(self.db_path)
        self.bc = Blockchain(self.storage)

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        self.tmpdir.cleanup()

    def test_l2_state_tree_root_determinism_and_peek(self):
        t1 = L2StateTree()
        t2 = L2StateTree()
        self.assertEqual(t1.root(), sha256(b"L2-EMPTY"))

        w1 = Wallet.generate()
        w2 = Wallet.generate()
        t1.credit(w1.address, 500)
        t1.credit(w2.address, 1000)

        t2.credit(w2.address, 1000)
        t2.credit(w1.address, 500)
        self.assertEqual(t1.root(), t2.root())

        root_before = t1.root()
        w3 = Wallet.generate()
        self.assertIsNone(t1.peek(w3.address))
        self.assertEqual(t1.root(), root_before)

    def test_commit_batch_rejects_root_mismatch_and_non_monotonic_batch_id(self):
        l2 = self.bc.layer2
        w1 = Wallet.generate()
        l2.L2_deposit(w1.address, 1000, l1_height=1, l1_block_hash="a" * 64)
        cur_root = l2.root()

        ok, msg = l2.commit_batch(0, "0" * 64, 1, "a" * 64)
        self.assertFalse(ok)
        self.assertIn("mismatch", msg)

        ok, msg = l2.commit_batch(0, cur_root, 1, "a" * 64)
        self.assertTrue(ok, msg)

        ok, msg = l2.commit_batch(0, cur_root, 2, "b" * 64)
        self.assertFalse(ok)
        self.assertIn("strictly greater", msg)

    def test_apply_rollup_tx_rejects_tampered_root_and_preserves_l2_state(self):
        w1 = Wallet.generate()
        w2 = Wallet.generate()
        self.bc.layer2.L2_deposit(w1.address, 10_000, l1_height=1, l1_block_hash="1" * 64)
        prev_root = self.bc.layer2.root()

        l2tx = w1.sign_l2_tx(w2.address, 2_500, 0)
        compressed = RollupSubmission.compress_batch([l2tx])
        batch_h = RollupSubmission.batch_hash(compressed)

        scratch = L2StateTree()
        scratch.restore(self.bc.layer2._tree.snapshot())
        scratch.debit(w1.address, 2_500)
        scratch.credit(w2.address, 2_500)
        scratch.bump_nonce(w1.address)
        valid_new_root = scratch.root()

        backend = ProofRegistry.get_configured()
        wrong_new_root = "f" * 64
        proof = backend.prove(prev_root, wrong_new_root, batch_h)
        sub = RollupSubmission(
            batch_id=1,
            previous_l2_root=prev_root,
            new_l2_root=wrong_new_root,
            zk_proof=proof,
            compressed_data=compressed,
            backend=backend.name(),
            backend_security=backend.security(),
        )
        l1_tx = Transaction(
            sender=w1.address,
            receiver=w1.address,
            amount=0.0,
            fee=0.0,
            nonce=0,
            tx_type=Transaction.TYPE_ROLLUP,
            data=sub.to_json(),
        )
        l1_tx.sign(w1)
        blk = Block(
            index=1,
            prev_hash=self.bc.get_block(0).block_hash,
            transactions=[l1_tx],
            miner_address=w1.address,
            difficulty=self.bc.get_difficulty(),
        )
        ok, msg = self.bc._apply_rollup_tx(l1_tx, blk)
        self.assertFalse(ok)
        self.assertIn("new_root mismatch", msg)
        self.assertEqual(self.bc.layer2.root(), prev_root)
        self.assertEqual(self.bc.layer2.get_balance_sat(w1.address), 10_000)
        self.assertEqual(self.bc.layer2.get_balance_sat(w2.address), 0)

        valid_proof = backend.prove(prev_root, valid_new_root, batch_h)
        sub_ok = RollupSubmission(
            batch_id=1,
            previous_l2_root=prev_root,
            new_l2_root=valid_new_root,
            zk_proof=valid_proof,
            compressed_data=compressed,
            backend=backend.name(),
            backend_security=backend.security(),
        )
        l1_tx_ok = Transaction(
            sender=w1.address,
            receiver=w1.address,
            amount=0.0,
            fee=0.0,
            nonce=0,
            tx_type=Transaction.TYPE_ROLLUP,
            data=sub_ok.to_json(),
        )
        l1_tx_ok.sign(w1)
        ok, msg = self.bc._apply_rollup_tx(l1_tx_ok, blk)
        self.assertTrue(ok, msg)
        self.assertEqual(self.bc.layer2.root(), valid_new_root)

    def test_block_header_state_root_and_bootstrap_commitment_integrity(self):
        genesis = self.bc.get_block(0)
        miner = Wallet.generate()
        diff1 = self.bc.get_difficulty()
        cb1 = Transaction.coinbase(miner.address, 50.0, 1)
        blk1 = Block(
            index=1,
            prev_hash=genesis.block_hash,
            transactions=[cb1],
            miner_address=miner.address,
            difficulty=diff1,
            timestamp=genesis.timestamp + 10,
            state_root="11" * 32,
        )
        blk1.mine()
        blk1.seal()

        digest = "ab" * 32
        cb2 = Transaction.coinbase(miner.address, 50.0, 2, bootstrap_snapshot=(1, digest))
        blk2 = Block(
            index=2,
            prev_hash=blk1.block_hash,
            transactions=[cb2],
            miner_address=miner.address,
            difficulty=diff1,
            timestamp=blk1.timestamp + 10,
            state_root="12" * 32,
        )
        blk2.mine()
        blk2.seal()

        ok, why = blk2.integrity_check()
        self.assertTrue(ok, why)

        d2 = blk2.to_dict()
        proof = RollingWindowPruner._merkle_proof_for_index([cb2.tx_id], 0, 2)
        pruned_dict = dict(d2)
        pruned_dict["transactions"] = []
        pruned_dict["pruned"] = True
        pruned_dict["bootstrap_commitment"] = {
            "snapshot_height": 1,
            "digest": digest,
            "coinbase": cb2.to_dict(),
            "merkle_proof": proof,
        }
        extracted, why = _extract_commitment(pruned_dict, 1)
        self.assertEqual(extracted, digest, why)

        tampered = json.loads(json.dumps(pruned_dict))
        tampered["bootstrap_commitment"]["coinbase"]["memo"] = f"coinbase:2|{Config.BOOTSTRAP_COMMITMENT_TAG}:1:{'cd'*32}"
        extracted_bad, why_bad = _extract_commitment(tampered, 1)
        self.assertIsNone(extracted_bad)
        self.assertIn("tx_id mismatch", why_bad)

        ok_chain, why_chain, _, chain_digest = verify_bootstrap_header_chain(
            [genesis.to_dict(), blk1.to_dict(), pruned_dict], genesis.block_hash, 1
        )
        self.assertTrue(ok_chain, why_chain)
        self.assertEqual(chain_digest, digest)

    def test_reconcile_l2_to_restores_checkpoint_or_marks_critical(self):
        w1 = Wallet.generate()
        self.bc.layer2.L2_deposit(w1.address, 500, l1_height=1, l1_block_hash="1" * 64)
        root_h1 = self.bc.layer2.root()
        self.bc.layer2.L2_deposit(w1.address, 500, l1_height=2, l1_block_hash="2" * 64)
        self.assertEqual(self.bc.layer2.get_balance_sat(w1.address), 1000)

        self.assertTrue(self.bc._reconcile_l2_to(1, "test-reconcile"))
        self.assertEqual(self.bc.layer2.root(), root_h1)
        self.assertEqual(self.bc.layer2.get_balance_sat(w1.address), 500)


if __name__ == "__main__":
    unittest.main()
