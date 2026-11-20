import json
import sys
import unittest
from pathlib import Path

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.ledger.transaction import Transaction
from visold.rollup.batches import RollupSubmission
from visold.rollup.compact_codec import (
    l2_pub_compact,
    l2_pub_expand,
    l2_sig_compact,
    l2_sig_expand,
)
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, L2Transaction

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


class TestV4Section83CompactCodecAndMalformedInput(unittest.TestCase):
    """V4 regression tests for Section 83: Compact Codec Encoding/Decoding & Malformed Input."""

    def test_rollup_submission_non_str_roots_rejected_cleanly(self):
        """V4 fix: Non-string roots in RollupSubmission JSON are rejected cleanly without TypeError."""
        payload = json.dumps({
            "kind": "rollup_submission_v1",
            "batch_id": 1,
            "previous_l2_root": 12345,
            "new_l2_root": 67890,
        })
        tx = Transaction(
            sender="VSD1234567890abcdef",
            receiver=L2_BRIDGE_ADDRESS,
            amount=0.0,
            fee=0.0,
            tx_type=Transaction.TYPE_ROLLUP,
            data=payload,
            pub_hex="02" + "0" * 64,
            sig_hex="[1, 2]",
        )
        ok, msg = tx.is_valid(signature_already_verified=True)
        self.assertFalse(ok)

    def test_rollup_submission_list_roots_rejected_by_structural_ok(self):
        """V4 fix: 64-element list roots are rejected by structural_ok()."""
        sub = RollupSubmission(
            batch_id=1,
            previous_l2_root=[0] * 64,
            new_l2_root=[1] * 64,
            zk_proof=b"",
            compressed_data=b"",
            backend="sim",
            backend_security="sim",
        )
        ok, msg = sub.structural_ok()
        self.assertFalse(ok)

    def test_l2_pub_expand_rejects_x_ge_p(self):
        """V4 fix: l2_pub_expand() rejects x >= secp256k1 P and returns ''."""
        x_over_p = SECP256K1_P + 1
        compact_bad = "02" + f"{x_over_p:064x}"
        expanded = l2_pub_expand(compact_bad)
        self.assertEqual(expanded, "")

    def test_compact_codec_rejects_non_hex_and_malformed_json(self):
        """V4 fix: compact_codec functions reject non-hex / malformed inputs by returning ''."""
        bad_pub_66 = "02" + "z" * 64
        self.assertEqual(l2_pub_compact(bad_pub_66), "")

        bad_pub_130 = "04" + "z" * 64 + "0" * 64
        self.assertEqual(l2_pub_compact(bad_pub_130), "")

        ws_sig = " " * 126 + "01"
        self.assertEqual(l2_sig_compact(ws_sig), "")

        neg_hex_sig = "-0x" + "1" * 125
        self.assertEqual(l2_sig_compact(neg_hex_sig), "")

        self.assertEqual(l2_sig_expand("[not valid json"), "")

    def test_l2_transaction_from_dict_rejects_float_and_bool(self):
        """V4 fix: L2Transaction.from_dict() rejects float and bool amount_sat/nonce."""
        with self.assertRaises(ValueError):
            L2Transaction.from_dict({
                "sender": "VSDsender",
                "receiver": "VSDreceiver",
                "amount_sat": 100.9,
                "nonce": 2.7,
                "timestamp": 1700000000,
            })

        with self.assertRaises(ValueError):
            L2Transaction.from_dict({
                "sender": "VSDsender",
                "receiver": "VSDreceiver",
                "amount_sat": True,
                "nonce": False,
                "timestamp": 1700000000,
            })


if __name__ == "__main__":
    unittest.main()
