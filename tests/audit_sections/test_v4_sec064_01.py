import hashlib
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if V4_ROOT not in sys.path:
    sys.path.insert(0, V4_ROOT)

from visold.consensus.rate_defection import RateDefectionAuditor
from visold.consensus.slashing import SlashingEvidenceProtocol
from visold.crypto.ecc import (
    ecdsa_keygen,
    ecdsa_sign,
    pub_to_address,
    pub_to_hex,
    sig_to_hex,
)
from visold.crypto.hashing import hash_obj
from visold.kernel.config import Config
from visold.storage.storage import Storage


class _MockBlockStoreStorage:
    """Minimal storage stub for RateDefectionAuditor tests."""

    def __init__(self, blocks):
        self._blocks = blocks
        self.slash_calls = []
        self._state = None

    def get_block(self, height):
        return self._blocks.get(height)

    def slash(self, addr):
        self.slash_calls.append(("slash", addr, Config.SLASH_RATE))

    def slash_with_rate(self, addr, pct):
        self.slash_calls.append(("slash_with_rate", addr, pct))

    def get_rate_defection_state(self):
        return self._state

    def set_rate_defection_state(self, payload):
        self._state = payload


class TestV4Section64SlashingEvidence(unittest.TestCase):
    def setUp(self):
        self._saved_cfg = {
            "AUTO_SLASH_RATE_DEFECTION": Config.AUTO_SLASH_RATE_DEFECTION,
            "RATE_AUDIT_WINDOW": Config.RATE_AUDIT_WINDOW,
            "RATE_AUDIT_CADENCE": Config.RATE_AUDIT_CADENCE,
            "RATE_AUDIT_THRESHOLD": Config.RATE_AUDIT_THRESHOLD,
            "RATE_AUDIT_CONSECUTIVE": Config.RATE_AUDIT_CONSECUTIVE,
            "RATE_AUDIT_MIN_SHARE": Config.RATE_AUDIT_MIN_SHARE,
            "RATE_AUDIT_VERIFY_TOLERANCE": Config.RATE_AUDIT_VERIFY_TOLERANCE,
            "RATE_SLASH_SCHEDULE": Config.RATE_SLASH_SCHEDULE,
        }

    def tearDown(self):
        for k, v in self._saved_cfg.items():
            setattr(Config, k, v)

    def test_shifted_window_replay_rejected_single_violation_does_not_escalate(self):
        """
        V4 Regression (Bug 1):
        handle_received_evidence() must reject non-cadence-aligned / overlapping
        shifted windows so a single violation at height=50 cannot be replayed at
        51..54 to escalate offense_count to 5 and ban the miner.
        """
        Config.AUTO_SLASH_RATE_DEFECTION = True
        Config.RATE_AUDIT_WINDOW = 20
        Config.RATE_AUDIT_CADENCE = 10
        Config.RATE_AUDIT_THRESHOLD = 2.0
        Config.RATE_AUDIT_CONSECUTIVE = 2
        Config.RATE_AUDIT_MIN_SHARE = 0.03
        Config.RATE_AUDIT_VERIFY_TOLERANCE = 0.10
        Config.RATE_SLASH_SCHEDULE = [0.10, 0.25, 0.50, 1.0]

        miner = "VSD_DEFECTING_MINER"
        other = "VSD_HONEST_MINER"
        blocks = {}
        for h in range(0, 70):
            if h >= 31 and h % 2 == 0:
                blocks[h] = SimpleNamespace(miner_address=miner)
            else:
                blocks[h] = SimpleNamespace(miner_address=other)

        storage = _MockBlockStoreStorage(blocks)
        auditor = RateDefectionAuditor(storage, blockchain=None)
        cap_registry = {miner: 10.0, other: 90.0}

        emitted = []
        for h in range(1, 51):
            emitted.extend(auditor.run_audit_cycle(h, cap_registry))
        self.assertEqual(len(emitted), 1)
        ev = emitted[0]
        self.assertEqual(ev["window_end"], 50)

        receiver = RateDefectionAuditor(_MockBlockStoreStorage(blocks), blockchain=None)
        accepted_50, reason_50 = receiver.handle_received_evidence(dict(ev), cap_registry)
        self.assertTrue(accepted_50, f"Expected cadence-aligned end_h=50 to be accepted: {reason_50}")

        for end_h in (51, 52, 53, 54):
            forged = dict(ev)
            forged["window_start"] = end_h - 20 + 1
            forged["window_end"] = end_h
            accepted, _ = receiver.handle_received_evidence(forged, cap_registry)
            self.assertFalse(accepted, f"Shifted non-cadence window end_h={end_h} should be rejected")

        self.assertEqual(receiver.offense_count(miner), 1)
        self.assertFalse(receiver.is_banned(miner))
        self.assertEqual(len(receiver._storage.slash_calls), 1)

    def test_handle_received_evidence_enforces_min_share_exemption(self):
        """
        V4 Regression (Bug 2):
        handle_received_evidence() must enforce local_share >= RATE_AUDIT_MIN_SHARE,
        matching run_audit_cycle().
        """
        Config.AUTO_SLASH_RATE_DEFECTION = True
        Config.RATE_AUDIT_WINDOW = 20
        Config.RATE_AUDIT_CADENCE = 10
        Config.RATE_AUDIT_THRESHOLD = 2.0
        Config.RATE_AUDIT_CONSECUTIVE = 2
        Config.RATE_AUDIT_MIN_SHARE = 0.05
        Config.RATE_AUDIT_VERIFY_TOLERANCE = 0.10

        small_miner = "VSD_SMALL_MINER"
        big_miner = "VSD_BIG_MINER"
        blocks = {}
        for h in range(0, 45):
            blocks[h] = SimpleNamespace(
                miner_address=(small_miner if h in (25, 35) else big_miner)
            )

        cap_registry = {small_miner: 1.0, big_miner: 99.0}
        auditor = RateDefectionAuditor(_MockBlockStoreStorage(blocks), blockchain=None)

        emitted = []
        for h in range(1, 41):
            emitted.extend(auditor.run_audit_cycle(h, cap_registry))
        self.assertEqual(emitted, [])

        forged_ev = {
            "type": "RATE_DEFECTION_EVIDENCE",
            "miner": small_miner,
            "window_start": 21,
            "window_end": 40,
            "expected_wins": 0.2,
            "actual_wins": 2,
            "ratio": 10.0,
            "consecutive": 2,
        }
        accepted, reason = auditor.handle_received_evidence(forged_ev, cap_registry)
        self.assertFalse(accepted, f"Exempt small miner should not be slashed: {reason}")
        self.assertEqual(auditor.offense_count(small_miner), 0)
        self.assertEqual(len(auditor._storage.slash_calls), 0)

    def test_rate_defection_seen_evidence_persists_across_restart(self):
        """
        V4 Regression (Bug 3):
        Replaying identical rate-defection evidence after restart must be rejected.
        """
        Config.AUTO_SLASH_RATE_DEFECTION = True
        Config.RATE_AUDIT_WINDOW = 20
        Config.RATE_AUDIT_CADENCE = 10
        Config.RATE_AUDIT_THRESHOLD = 2.0
        Config.RATE_AUDIT_CONSECUTIVE = 2
        Config.RATE_AUDIT_MIN_SHARE = 0.03
        Config.RATE_AUDIT_VERIFY_TOLERANCE = 0.10

        miner = "VSD_MINER"
        other = "VSD_OTHER"
        blocks = {h: SimpleNamespace(miner_address=(miner if h % 2 == 0 else other))
                  for h in range(0, 50)}
        storage = _MockBlockStoreStorage(blocks)
        cap_registry = {miner: 10.0, other: 90.0}

        ev = {
            "type": "RATE_DEFECTION_EVIDENCE",
            "miner": miner,
            "window_start": 21,
            "window_end": 40,
            "expected_wins": 2.0,
            "actual_wins": 10,
            "ratio": 5.0,
            "consecutive": 2,
        }

        auditor1 = RateDefectionAuditor(storage, blockchain=None)
        ok1, r1 = auditor1.handle_received_evidence(ev, cap_registry)
        self.assertTrue(ok1, r1)
        self.assertEqual(auditor1.offense_count(miner), 1)

        auditor2 = RateDefectionAuditor(storage, blockchain=None)
        ok2, r2 = auditor2.handle_received_evidence(ev, cap_registry)
        self.assertTrue(ok2, r2)
        self.assertIn("Duplicate", r2)
        self.assertEqual(auditor2.offense_count(miner), 1)
        self.assertEqual(len(storage.slash_calls), 1)

    def test_slashing_evidence_protocol_rejects_duplicate_on_restart(self):
        """
        V4 Regression (Bug 4):
        SlashingEvidenceProtocol must reject previously applied slash_evidence:<id>
        records after restart.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "visold.db")
            storage = Storage(db_path)

            priv, pub = ecdsa_keygen()
            pub_hex = pub_to_hex(pub)
            val_addr = pub_to_address(pub)
            storage.set_role(val_addr, "investor", 250.0)

            header_a = {"index": 5, "prev_hash": "00" * 32, "nonce": 1}
            header_b = {"index": 5, "prev_hash": "00" * 32, "nonce": 2}
            bh_a = hash_obj(header_a)
            bh_b = hash_obj(header_b)

            sig_a = ecdsa_sign(priv, hashlib.sha256(bh_a.encode()).digest())
            sig_b = ecdsa_sign(priv, hashlib.sha256(bh_b.encode()).digest())
            sig_a_hex = sig_to_hex(sig_a)
            sig_b_hex = sig_to_hex(sig_b)

            proto1 = SlashingEvidenceProtocol(storage, blockchain=None)
            ev = proto1.build_evidence(
                validator_address=val_addr,
                pub_hex=pub_hex,
                block_hash_a=bh_a,
                sig_a=sig_a_hex,
                block_hash_b=bh_b,
                sig_b=sig_b_hex,
                height=5,
                own_address="VSD_REPORTER",
                block_header_a=header_a,
                block_header_b=header_b,
            )

            ok1, msg1 = proto1.apply_evidence(ev)
            self.assertTrue(ok1, msg1)
            ok_dup, _ = proto1.apply_evidence(ev)
            self.assertFalse(ok_dup)

            proto2 = SlashingEvidenceProtocol(storage, blockchain=None)
            ok2, msg2 = proto2.handle_network_evidence(ev)
            self.assertFalse(ok2, f"Duplicate evidence after restart should be rejected: {msg2}")


if __name__ == "__main__":
    unittest.main()
