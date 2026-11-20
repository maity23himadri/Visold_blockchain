import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if V4_ROOT not in sys.path:
    sys.path.insert(0, V4_ROOT)

from visold.governance.engine import GovernanceEngine, UpgradePhase
from visold.governance.versioning import ProtocolVersionManager
from visold.storage.storage import Storage


def _fake_block(height: int, proto_ver: int = 1, block_hash: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        index=height,
        protocol_version=proto_ver,
        block_hash=block_hash or f"hash_{height:064x}",
        finalized=True,
        validator_sigs={},
        difficulty=1.0,
    )


class TestV4Section66GovernanceProposals(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "visold.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_load_persisted_active_proposal_syncs_proto_mgr_and_allows_next_propose(self):
        st1 = Storage(self.db_path)
        pm1 = ProtocolVersionManager(st1)
        gov1 = GovernanceEngine(st1, pm1)

        ok, msg = gov1.propose_upgrade(version=2, signal_start_height=1)
        self.assertTrue(ok, msg)

        for h in range(1, 5):
            st1.set_meta(f"proto_sig:{h}", "2")
            gov1.on_block_applied(_fake_block(h, proto_ver=2))

        prop_v2 = gov1.get_proposal(2)
        self.assertIsNotNone(prop_v2)
        self.assertEqual(prop_v2.phase, UpgradePhase.LOCKED_IN)

        act_h = prop_v2.activation_height
        gov1.on_block_applied(_fake_block(act_h, proto_ver=2))
        self.assertEqual(gov1.get_proposal(2).phase, UpgradePhase.ACTIVE)
        self.assertEqual(pm1.current_version(), 2)
        st1.close()

        # Simulate node restart: new ProtocolVersionManager + GovernanceEngine on same DB
        st2 = Storage(self.db_path)
        pm2 = ProtocolVersionManager(st2)
        gov2 = GovernanceEngine(st2, pm2)

        self.assertEqual(gov2.get_proposal(2).phase, UpgradePhase.ACTIVE)
        self.assertEqual(gov2.get_active_version(), 2)
        self.assertEqual(pm2.current_version(), 2)

        ok_v3, msg_v3 = gov2.propose_upgrade(
            version=3,
            signal_start_height=act_h + gov2._MIN_UPGRADE_SPACING_BLOCKS + 10,
        )
        self.assertTrue(ok_v3, f"Proposing v3 after restart should succeed: {msg_v3}")

        ok_v2, msg_v2 = gov2.propose_upgrade(
            version=2,
            signal_start_height=act_h + gov2._MIN_UPGRADE_SPACING_BLOCKS + 10,
        )
        self.assertFalse(ok_v2)
        st2.close()

    def test_propose_upgrade_rejects_zero_threshold(self):
        st = Storage(self.db_path)
        pm = ProtocolVersionManager(st)
        gov = GovernanceEngine(st, pm)

        ok, _ = gov.propose_upgrade(version=2, signal_start_height=10, threshold=0.0)
        self.assertFalse(ok, "Zero threshold must be rejected")
        st.close()

    def test_propose_upgrade_rejects_nan_threshold(self):
        st = Storage(self.db_path)
        gov = GovernanceEngine(st, ProtocolVersionManager(st))

        ok, _ = gov.propose_upgrade(
            version=2, signal_start_height=10, threshold=float("nan")
        )
        self.assertFalse(ok, "NaN threshold must be rejected")
        st.close()

    def test_propose_upgrade_rejects_negative_rollback_window(self):
        st = Storage(self.db_path)
        gov = GovernanceEngine(st, ProtocolVersionManager(st))

        ok, _ = gov.propose_upgrade(
            version=2, signal_start_height=10, rollback_window=-1
        )
        self.assertFalse(ok, "Negative rollback_window must be rejected")
        st.close()


if __name__ == "__main__":
    unittest.main()
