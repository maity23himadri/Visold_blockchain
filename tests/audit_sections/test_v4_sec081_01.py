from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.chain.sequencer import Sequencer
from visold.crypto.ecc import sig_to_hex
from visold.rollup.batches import RollupSubmission
from visold.rollup.compact_codec import l2_pub_compact, l2_sig_compact, l2_sig_expand
from visold.rollup.l2_state import (
    L2_BRIDGE_ADDRESS,
    L2_WITHDRAW_ADDRESS,
    L2Transaction,
    Layer2State,
)
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


class _DummyBlockchain:
    def __init__(self, storage):
        self.storage = storage

    def add_rollup_drop_listener(self, fn):
        pass


class TestV4Section81(unittest.TestCase):
    def test_l2_tx_from_dict_timestamp_zero_deterministic(self):
        """V4 fix: L2Transaction.__init__ preserves explicit timestamp=0 instead
        of substituting time.time(), keeping from_dict() and decompress_batch()
        deterministic across nodes."""
        sender = Wallet.generate()
        receiver = Wallet.generate()

        tx = L2Transaction(
            sender=sender.address,
            receiver=receiver.address,
            amount_sat=100,
            nonce=0,
            timestamp=0,
            pub=l2_pub_compact(sender.pub_hex),
        )
        self.assertEqual(tx.timestamp, 0)
        sig_pair = sender.sign(tx.signing_bytes())
        tx.sig = l2_sig_compact(sig_to_hex(sig_pair))
        tx.l2_tx_id = tx._compute_id()

        d_with_id = tx.to_dict()
        self.assertEqual(d_with_id["timestamp"], 0)

        # (a) Round-tripping with l2_tx_id present succeeds regardless of wall clock.
        with patch("visold.rollup.l2_state.time.time", return_value=2000.0):
            rt_tx = L2Transaction.from_dict(d_with_id)
            self.assertEqual(rt_tx.timestamp, 0)
            self.assertEqual(rt_tx.l2_tx_id, tx.l2_tx_id)
            ok_rt, msg_rt = rt_tx.is_valid()
            self.assertTrue(ok_rt, msg_rt)

        # (b) When l2_tx_id is omitted in the batch JSON, decompress_batch()
        # preserves timestamp=0 deterministically regardless of wall-clock time.
        d_no_id = dict(d_with_id)
        d_no_id.pop("l2_tx_id", None)
        raw = json.dumps([d_no_id], separators=(",", ":"), sort_keys=True).encode()
        blob = zlib.compress(raw, level=9)

        with patch("visold.rollup.l2_state.time.time", return_value=0.0):
            txs_t0 = RollupSubmission.decompress_batch(blob)
            ok_t0, msg_t0 = txs_t0[0].is_valid()
            self.assertTrue(ok_t0, f"expected valid at t=0, got {msg_t0}")
            self.assertEqual(txs_t0[0].timestamp, 0)

        with patch("visold.rollup.l2_state.time.time", return_value=2000.0):
            txs_t1 = RollupSubmission.decompress_batch(blob)
            ok_t1, msg_t1 = txs_t1[0].is_valid()
            self.assertTrue(ok_t1, f"expected valid at t=2000, got {msg_t1}")
            self.assertEqual(txs_t1[0].timestamp, 0)
            self.assertEqual(txs_t1[0].l2_tx_id, txs_t0[0].l2_tx_id)

    def test_l2_tx_to_bridge_sentinels_rejected(self):
        """V4 fix: L2Transaction.is_valid() and Layer2State.apply_l2_tx() reject
        L2_WITHDRAW_ADDRESS and L2_BRIDGE_ADDRESS as L2 receivers."""
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(os.path.join(td, "l2-sentinel.db"))
            l2 = Layer2State(storage)
            sender = Wallet.generate()

            ok_dep, _ = l2.L2_deposit(sender.address, 1000, l1_height=-1)
            self.assertTrue(ok_dep)

            tx_w = sender.sign_l2_tx(
                L2_WITHDRAW_ADDRESS, amount_sat=400, nonce=0, timestamp=1000
            )
            tx_b = sender.sign_l2_tx(
                L2_BRIDGE_ADDRESS, amount_sat=300, nonce=1, timestamp=1001
            )

            self.assertFalse(tx_w.is_valid()[0])
            self.assertFalse(tx_b.is_valid()[0])

            ok1, _ = l2.apply_l2_tx(tx_w)
            ok2, _ = l2.apply_l2_tx(tx_b)
            self.assertFalse(ok1)
            self.assertFalse(ok2)

            self.assertEqual(l2.get_balance_sat(sender.address), 1000)
            self.assertEqual(l2.get_balance_sat(L2_WITHDRAW_ADDRESS), 0)
            self.assertEqual(l2.get_balance_sat(L2_BRIDGE_ADDRESS), 0)
            self.assertEqual(l2.total_supply_sat(), 1000)

    def test_l2_tx_id_malleability_and_max_wire_bytes_enforced(self):
        """V4 fix: L2Transaction.is_valid() rejects non-canonical sig/pub
        encodings and enforces MAX_WIRE_BYTES so malleable variants cannot
        bypass Sequencer._seen_ids deduplication."""
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(os.path.join(td, "l2-malleable.db"))
            l2 = Layer2State(storage)
            bc = _DummyBlockchain(storage)
            seq_wallet = Wallet.generate()
            seq = Sequencer(bc, l2, seq_wallet)
            seq._running = True

            sender = Wallet.generate()
            receiver = Wallet.generate()
            base_tx = sender.sign_l2_tx(
                receiver.address, amount_sat=50, nonce=0, timestamp=12345
            )
            ok, msg = seq.add_l2_tx(base_tx)
            self.assertTrue(ok, msg)

            # Re-submit exact same tx -> rejected as duplicate
            ok_dup, msg_dup = seq.add_l2_tx(base_tx)
            self.assertFalse(ok_dup)
            self.assertEqual(msg_dup, "duplicate l2_tx_id")

            # Mutate sig/pub to uppercase hex -> rejected as non-canonical
            upper_tx = L2Transaction(
                sender=base_tx.sender,
                receiver=base_tx.receiver,
                amount_sat=base_tx.amount_sat,
                nonce=base_tx.nonce,
                timestamp=base_tx.timestamp,
                sig=base_tx.sig.upper(),
                pub=base_tx.pub.upper(),
            )
            self.assertFalse(upper_tx.is_valid()[0])
            ok_u, _ = seq.add_l2_tx(upper_tx)
            self.assertFalse(ok_u)

            # Mutate sig to bloated JSON array exceeding MAX_WIRE_BYTES (2048) -> rejected
            json_sig_base = l2_sig_expand(base_tx.sig)
            bloated_sig = json_sig_base[:-1] + (" " * 5000) + "]"
            self.assertGreater(len(bloated_sig), L2Transaction.MAX_WIRE_BYTES)
            bloated_tx = L2Transaction(
                sender=base_tx.sender,
                receiver=base_tx.receiver,
                amount_sat=base_tx.amount_sat,
                nonce=base_tx.nonce,
                timestamp=base_tx.timestamp,
                sig=bloated_sig,
                pub=base_tx.pub,
            )
            self.assertFalse(bloated_tx.is_valid()[0])
            ok_b, _ = seq.add_l2_tx(bloated_tx)
            self.assertFalse(ok_b)

            self.assertEqual(len(seq._pending), 1)


if __name__ == "__main__":
    unittest.main()
