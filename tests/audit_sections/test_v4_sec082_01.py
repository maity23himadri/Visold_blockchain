"""V4 regression tests for Section 82: Rollup Batch Construction, Ordering and Size Limits."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.chain.blockchain import Blockchain
from visold.chain.sequencer import Sequencer
from visold.kernel.config import Config
from visold.rollup.batches import RollupSubmission
from visold.rollup.l2_state import L2Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = Config.SATOSHI_PER_VSD


def _make_l2_tx(sender_w: Wallet, receiver_addr: str, amount_sat: int,
                nonce: int, timestamp: int | None = None) -> L2Transaction:
    ts = int(time.time()) if timestamp is None else int(timestamp)
    return sender_w.sign_l2_tx(receiver_addr, amount_sat, nonce, timestamp=ts)


class TestV4Section82(unittest.TestCase):
    def setUp(self):
        self._prev_disable = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        self._tmpdir = tempfile.TemporaryDirectory()
        self.storage = Storage(os.path.join(self._tmpdir.name, "chain.db"))
        self.bc = Blockchain(self.storage)
        self.bc._rolling_pruner.prune_async = lambda h: None

        self.seq_wallet = Wallet.generate()
        self.alice = Wallet.generate()
        self.bob = Wallet.generate()

        ok, msg = self.bc.layer2.L2_deposit(self.alice.address, 100 * SAT, l1_height=0, l1_block_hash="0" * 64)
        self.assertTrue(ok, msg)

    def tearDown(self):
        logging.disable(self._prev_disable)
        self._tmpdir.cleanup()

    def test_sequencer_syncs_batch_id_after_external_commit(self):
        """V4 fix: Sequencer._seal_one() syncs _next_batch_id with layer2._last_batch_id."""
        orig_max_age = Config.L2_BATCH_MAX_AGE_SECS
        Config.L2_BATCH_MAX_AGE_SECS = 9999
        seq = Sequencer(self.bc.layer2, self.seq_wallet, self.bc)
        try:
            ok, msg = seq.start()
            self.assertTrue(ok, msg)

            ext_tx = _make_l2_tx(self.alice, self.bob.address, 10 * SAT, nonce=0)
            ok_a, msg_a = self.bc.layer2.apply_l2_tx(ext_tx)
            self.assertTrue(ok_a, msg_a)
            ok_c, msg_c = self.bc.layer2.commit_batch(
                batch_id=0,
                new_root_expected=self.bc.layer2.root(),
                l1_height=1,
                l1_block_hash="1" * 64,
            )
            self.assertTrue(ok_c, msg_c)
            self.assertEqual(self.bc.layer2._last_batch_id, 0)

            local_tx = _make_l2_tx(self.alice, self.bob.address, 5 * SAT, nonce=1)
            ok_add, msg_add = seq.add_l2_tx(local_tx)
            self.assertTrue(ok_add, msg_add)

            sealed = seq._seal_one()
            self.assertIsNotNone(sealed)
            l1_tx, batch_id, applied = sealed
            seq._finalize_seal(batch_id, applied)

            self.assertEqual(batch_id, 1)
            ok_tx, msg_tx = l1_tx.is_valid()
            self.assertTrue(ok_tx, msg_tx)

            dummy_block = types.SimpleNamespace(index=2, block_hash="2" * 64)
            ok_apply, msg_apply = self.bc._apply_rollup_tx(l1_tx, dummy_block)
            self.assertTrue(ok_apply, msg_apply)
            self.assertEqual(self.bc.layer2._last_batch_id, 1)
        finally:
            seq.stop()
            Config.L2_BATCH_MAX_AGE_SECS = orig_max_age

    def test_process_dropped_rollups_preserves_batch_order(self):
        """V4 fix: _process_dropped_rollups() preserves FIFO batch order so nonce=0 precedes nonce=1."""
        orig_max_size = Config.L2_MAX_BATCH_SIZE
        orig_max_age = Config.L2_BATCH_MAX_AGE_SECS
        Config.L2_MAX_BATCH_SIZE = 1
        Config.L2_BATCH_MAX_AGE_SECS = 9999
        seq = Sequencer(self.bc.layer2, self.seq_wallet, self.bc)
        seq._running = True
        seq._max_seal_attempts = 2
        try:
            tx0 = _make_l2_tx(self.alice, self.bob.address, 10 * SAT, nonce=0)
            tx1 = _make_l2_tx(self.alice, self.bob.address, 10 * SAT, nonce=1)

            self.assertTrue(seq.add_l2_tx(tx0)[0])
            l1_0, b0, app0 = seq._seal_one()
            seq._finalize_seal(b0, app0)

            seq._record_sealed("l1_batch_1", 1, [tx1])

            seq._on_rollup_dropped(l1_0.tx_id)
            seq._on_rollup_dropped("l1_batch_1")

            requeued = seq._process_dropped_rollups()
            self.assertEqual(requeued, 2)

            self.assertEqual([t.l2_tx_id for t in seq._pending], [tx0.l2_tx_id, tx1.l2_tx_id])

            sealed = seq._seal_one()
            self.assertIsNotNone(sealed)
            _, _, sealed_app = sealed
            self.assertEqual([t.l2_tx_id for t in sealed_app], [tx0.l2_tx_id])
            seq._finalize_seal(sealed[1], sealed_app)
            self.assertEqual([t.l2_tx_id for t in seq._pending], [tx1.l2_tx_id])
        finally:
            Config.L2_MAX_BATCH_SIZE = orig_max_size
            Config.L2_BATCH_MAX_AGE_SECS = orig_max_age

    def test_should_seal_not_blocked_by_future_timestamp_tx(self):
        """V4 fix: Far-future txs are rejected at admission, and a within-drift
        future-dated L2Transaction at _pending[0] does not block age-based sealing."""
        orig_max_age = Config.L2_BATCH_MAX_AGE_SECS
        Config.L2_BATCH_MAX_AGE_SECS = 30
        seq = Sequencer(self.bc.layer2, self.seq_wallet, self.bc)
        seq._running = True
        try:
            far_future_ts = int(time.time()) + 10**8
            tx_far_future = _make_l2_tx(self.alice, self.bob.address, 5 * SAT, nonce=0, timestamp=far_future_ts)
            ok_far, msg_far = seq.add_l2_tx(tx_far_future)
            self.assertFalse(ok_far)
            self.assertIn("future", msg_far)

            near_future_ts = int(time.time()) + 120
            tx_near_future = _make_l2_tx(self.alice, self.bob.address, 5 * SAT, nonce=0, timestamp=near_future_ts)
            tx_old = _make_l2_tx(self.alice, self.bob.address, 5 * SAT, nonce=1, timestamp=int(time.time()) - 120)

            self.assertTrue(seq.add_l2_tx(tx_near_future)[0])
            self.assertTrue(seq.add_l2_tx(tx_old)[0])

            self.assertTrue(seq._should_seal())
            self.assertGreaterEqual(seq.status()["oldest_tx_age"], 30.0)
        finally:
            Config.L2_BATCH_MAX_AGE_SECS = orig_max_age

    def test_seal_one_splits_when_compressed_exceeds_max_bytes(self):
        """V4 fix: _seal_one() splits the batch when compressed size exceeds MAX_COMPRESSED_BYTES."""
        orig_max_bytes = RollupSubmission.MAX_COMPRESSED_BYTES
        orig_max_size = Config.L2_MAX_BATCH_SIZE
        seq = Sequencer(self.bc.layer2, self.seq_wallet, self.bc)
        seq._running = True
        try:
            tx0 = _make_l2_tx(self.alice, self.bob.address, 5 * SAT, nonce=0)
            tx1 = _make_l2_tx(self.alice, self.bob.address, 5 * SAT, nonce=1)
            one_len = len(RollupSubmission.compress_batch([tx0]))
            two_len = len(RollupSubmission.compress_batch([tx0, tx1]))
            self.assertLess(one_len, two_len)

            RollupSubmission.MAX_COMPRESSED_BYTES = (one_len + two_len) // 2
            Config.L2_MAX_BATCH_SIZE = 10

            self.assertTrue(seq.add_l2_tx(tx0)[0])
            self.assertTrue(seq.add_l2_tx(tx1)[0])

            sealed1 = seq._seal_one()
            self.assertIsNotNone(sealed1)
            _, bid1, app1 = sealed1
            self.assertEqual([t.l2_tx_id for t in app1], [tx0.l2_tx_id])
            seq._finalize_seal(bid1, app1)
            self.assertEqual(len(seq._pending), 1)
        finally:
            RollupSubmission.MAX_COMPRESSED_BYTES = orig_max_bytes
            Config.L2_MAX_BATCH_SIZE = orig_max_size


if __name__ == "__main__":
    unittest.main()
