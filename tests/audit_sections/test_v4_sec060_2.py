"""V4 Regression Tests for Section 60: Economic Monitoring, Collusion Detection,
and Solo-Mining Assumptions.
"""

import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.kernel.config import Config
from visold.consensus.rate_defection import RateDefectionAuditor
from visold.chain.blockchain import Blockchain
from visold.wallet.wallet import Wallet
from visold.crypto.hashing import sha256


class _StubStorage:
    def __init__(self, blocks=None, self_address="VSD_SELF"):
        self.blocks = blocks or {}
        self.self_address = self_address
        self.slashed = []
        self.persisted = None

    def get_block(self, height):
        return self.blocks.get(height)

    def get_rate_defection_state(self):
        return self.persisted

    def set_rate_defection_state(self, payload):
        self.persisted = payload

    def slash_with_rate(self, miner, rate):
        self.slashed.append((miner, rate))

    def slash(self, miner):
        self.slashed.append((miner, Config.SLASH_RATE))


class TestSection60RateDefectionFixes(unittest.TestCase):
    def setUp(self):
        self._orig_auto_slash = Config.AUTO_SLASH_RATE_DEFECTION
        self._orig_window = Config.RATE_AUDIT_WINDOW
        self._orig_cadence = Config.RATE_AUDIT_CADENCE
        self._orig_consec = Config.RATE_AUDIT_CONSECUTIVE
        self._orig_threshold = Config.RATE_AUDIT_THRESHOLD
        self._orig_min_share = Config.RATE_AUDIT_MIN_SHARE

    def tearDown(self):
        Config.AUTO_SLASH_RATE_DEFECTION = self._orig_auto_slash
        Config.RATE_AUDIT_WINDOW = self._orig_window
        Config.RATE_AUDIT_CADENCE = self._orig_cadence
        Config.RATE_AUDIT_CONSECUTIVE = self._orig_consec
        Config.RATE_AUDIT_THRESHOLD = self._orig_threshold
        Config.RATE_AUDIT_MIN_SHARE = self._orig_min_share

    def test_node_id_mapped_to_miner_address_key_alignment(self):
        """V4 Fix: Blockchain._maybe_run_rate_audit maps peer node_id -> miner_address
        via _peer_addresses and uses _own_address for local node.
        """
        Config.RATE_AUDIT_WINDOW = 10
        Config.RATE_AUDIT_CADENCE = 10
        Config.RATE_AUDIT_CONSECUTIVE = 1
        Config.RATE_AUDIT_THRESHOLD = 2.0
        Config.RATE_AUDIT_MIN_SHARE = 0.03

        w_defector = Wallet.generate()
        defector_addr = w_defector.address
        defector_node_id = sha256(w_defector.pub_hex.encode())
        self.assertNotEqual(defector_addr, defector_node_id)

        w_honest = Wallet.generate()
        honest_node_id = sha256(w_honest.pub_hex.encode())

        blocks = {
            h: SimpleNamespace(index=h, miner_address=defector_addr)
            for h in range(1, 11)
        }
        storage = _StubStorage(blocks=blocks)
        auditor = RateDefectionAuditor(storage, blockchain=None)

        gov = SimpleNamespace(
            _lock=threading.Lock(),
            _peer_rates={defector_node_id: (10.0, 1000.0)},
            _peer_addresses={defector_node_id: defector_addr},
            _local_actual_hashrate=90.0,
        )
        broadcasted = []
        net = SimpleNamespace(
            node_id=honest_node_id,
            _mining_engine_ref=SimpleNamespace(get_hashrate_governor=lambda: gov),
            broadcast_message=lambda msg: broadcasted.append(msg),
        )
        bc = Blockchain.__new__(Blockchain)
        bc.storage = storage
        bc._rate_auditor = auditor
        bc._network = net
        bc._own_address = w_honest.address

        bc._maybe_run_rate_audit(10)
        self.assertEqual(len(broadcasted), 1)
        self.assertEqual(broadcasted[0]["miner"], defector_addr)

        cap_registry = {defector_addr: 10.0, w_honest.address: 90.0}
        ev = {
            "type": "RATE_DEFECTION_EVIDENCE",
            "miner": defector_addr,
            "window_start": 1,
            "window_end": 10,
            "expected_wins": 1.0,
            "actual_wins": 10,
            "ratio": 10.0,
            "consecutive": 1,
        }
        accepted, reason = auditor.handle_received_evidence(ev, cap_registry)
        self.assertTrue(accepted, f"Expected evidence acceptance, got: {reason}")

    def test_handle_received_evidence_enforces_min_share_exemption(self):
        """V4 Fix: handle_received_evidence enforces RATE_AUDIT_MIN_SHARE exemption."""
        Config.AUTO_SLASH_RATE_DEFECTION = True
        Config.RATE_AUDIT_WINDOW = 100
        Config.RATE_AUDIT_CADENCE = 50
        Config.RATE_AUDIT_CONSECUTIVE = 3
        Config.RATE_AUDIT_THRESHOLD = 2.0
        Config.RATE_AUDIT_MIN_SHARE = 0.03

        small_miner = "VSD_TINY_MINER"
        big_miner = "VSD_BIG_MINER"
        blocks = {}
        for h in range(1, 201):
            addr = small_miner if (h % 33 == 0) else big_miner
            blocks[h] = SimpleNamespace(index=h, miner_address=addr)

        storage = _StubStorage(blocks=blocks)
        auditor = RateDefectionAuditor(storage, blockchain=None)
        cap_registry = {small_miner: 1.0, big_miner: 99.0}

        self.assertEqual(auditor.run_audit_cycle(200, cap_registry), [])

        ev = {
            "type": "RATE_DEFECTION_EVIDENCE",
            "miner": small_miner,
            "window_start": 101,
            "window_end": 200,
            "expected_wins": 1.0,
            "actual_wins": 3,
            "ratio": 3.0,
            "consecutive": 3,
        }
        accepted, _reason = auditor.handle_received_evidence(ev, cap_registry)
        self.assertFalse(accepted)
        self.assertEqual(len(storage.slashed), 0)

    def test_sliding_window_off_cadence_rejected(self):
        """V4 Fix: handle_received_evidence rejects off-cadence / overlapping
        shifted windows, preventing single-defection amplification.
        """
        Config.AUTO_SLASH_RATE_DEFECTION = True
        Config.RATE_AUDIT_WINDOW = 100
        Config.RATE_AUDIT_CADENCE = 50
        Config.RATE_AUDIT_CONSECUTIVE = 3
        Config.RATE_AUDIT_THRESHOLD = 2.0
        Config.RATE_AUDIT_MIN_SHARE = 0.03

        miner = "VSD_MINER_A"
        other = "VSD_MINER_B"
        blocks = {
            h: SimpleNamespace(index=h, miner_address=(miner if h % 2 == 0 else other))
            for h in range(1, 210)
        }
        storage = _StubStorage(blocks=blocks)
        auditor = RateDefectionAuditor(storage, blockchain=None)
        cap_registry = {miner: 10.0, other: 90.0}

        actual_200 = sum(1 for h in range(101, 201) if blocks[h].miner_address == miner)
        ev_200 = {
            "type": "RATE_DEFECTION_EVIDENCE",
            "miner": miner,
            "window_start": 101,
            "window_end": 200,
            "expected_wins": 10.0,
            "actual_wins": actual_200,
            "ratio": actual_200 / 10.0,
            "consecutive": 3,
        }
        accepted_200, _ = auditor.handle_received_evidence(ev_200, cap_registry)
        self.assertTrue(accepted_200)

        for end_h in (201, 202, 203):
            start_h = end_h - 100 + 1
            actual = sum(1 for h in range(start_h, end_h + 1) if blocks[h].miner_address == miner)
            ev = {
                "type": "RATE_DEFECTION_EVIDENCE",
                "miner": miner,
                "window_start": start_h,
                "window_end": end_h,
                "expected_wins": 10.0,
                "actual_wins": actual,
                "ratio": actual / 10.0,
                "consecutive": 3,
            }
            accepted, _ = auditor.handle_received_evidence(ev, cap_registry)
            self.assertFalse(accepted)

        self.assertEqual(auditor.offense_count(miner), 1)
        self.assertFalse(auditor.is_banned(miner))
        self.assertEqual(storage.slashed, [(miner, 0.05)])

    def test_reorg_rollback_rewinds_last_audit_height(self):
        """V4 Fix: RateDefectionAuditor.on_rollback() rewinds _last_audit_height
        so reorged canonical blocks at height H are audited.
        """
        Config.RATE_AUDIT_WINDOW = 10
        Config.RATE_AUDIT_CADENCE = 10
        Config.RATE_AUDIT_CONSECUTIVE = 1
        Config.RATE_AUDIT_THRESHOLD = 2.0
        Config.RATE_AUDIT_MIN_SHARE = 0.03

        miner = "VSD_MINER_A"
        other = "VSD_MINER_B"
        blocks = {
            h: SimpleNamespace(index=h, miner_address=other)
            for h in range(1, 11)
        }
        storage = _StubStorage(blocks=blocks)
        auditor = RateDefectionAuditor(storage, blockchain=None)
        cap_registry = {miner: 10.0, other: 90.0}

        self.assertEqual(auditor.run_audit_cycle(10, cap_registry), [])

        auditor.on_rollback(8)
        for h in range(1, 11):
            storage.blocks[h] = SimpleNamespace(index=h, miner_address=miner)

        evidence = auditor.run_audit_cycle(10, cap_registry)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["miner"], miner)


if __name__ == "__main__":
    unittest.main(verbosity=2)
