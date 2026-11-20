"""Section 68 V4 Regression Tests: Upgrade Timelocks and Governance Phase Transitions."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if V4_ROOT not in sys.path:
    sys.path.insert(0, V4_ROOT)

from visold.governance.engine import GovernanceEngine, UpgradePhase
from visold.governance.versioning import ProtocolVersionManager
from visold.kernel.config import Config
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


class _DummyBlock:
    def __init__(self, index: int, protocol_version: int = 1,
                 block_hash: str = "", finalized: bool = False):
        self.index = index
        self.protocol_version = protocol_version
        self.block_hash = block_hash or f"hash_{index}"
        self.finalized = finalized


class TestV4Section68UpgradeTimelocks(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmpdir.name, "test.db")
        self.storage = Storage(db_path=db_path)
        self.storage.set_meta("genesis_hash", "0" * 64)
        self.proto_mgr = ProtocolVersionManager(self.storage)
        self.gov = GovernanceEngine(self.storage, self.proto_mgr)

        self._orig_delay = Config.GOVERNANCE_ACTIVATION_DELAY
        self._orig_rw = Config.GOVERNANCE_ROLLBACK_WINDOW
        self._orig_win = Config.FORK_SIGNAL_WINDOW
        self._orig_fin_to = Config.GOVERNANCE_FINALITY_TIMEOUT

    def tearDown(self):
        Config.GOVERNANCE_ACTIVATION_DELAY = self._orig_delay
        Config.GOVERNANCE_ROLLBACK_WINDOW = self._orig_rw
        Config.FORK_SIGNAL_WINDOW = self._orig_win
        Config.GOVERNANCE_FINALITY_TIMEOUT = self._orig_fin_to
        try:
            self.storage.close()
        except Exception:
            pass
        self._tmpdir.cleanup()

    def _drive_to_active(self, version: int, signal_start: int,
                         finalized_height: int = 0):
        ok, msg = self.gov.propose_upgrade(
            version=version,
            signal_start_height=signal_start,
            threshold=0.75,
            rollback_window=Config.GOVERNANCE_ROLLBACK_WINDOW,
        )
        self.assertTrue(ok, f"propose_upgrade failed: {msg}")

        fin = [finalized_height]
        self.gov.set_finality_source(lambda: fin[0])

        self.proto_mgr.record_block_version(version, signal_start)
        self.gov.on_block_applied(_DummyBlock(signal_start, protocol_version=version))
        prop = self.gov.get_proposal(version)
        self.assertEqual(prop.phase, UpgradePhase.LOCKED_IN)

        act_h = prop.activation_height
        fin[0] = act_h
        self.proto_mgr.record_block_version(version, act_h)
        self.gov.on_block_applied(_DummyBlock(act_h, protocol_version=version))
        self.assertEqual(prop.phase, UpgradePhase.ACTIVE)
        return prop, fin

    def test_rollback_rewinds_proto_mgr_and_allows_reproposal(self):
        """V4 Regression (Bug 1a): _trigger_rollback() must rewind proto_mgr
        to version - 1, allowing re-proposal of the rolled-back version."""
        Config.FORK_SIGNAL_WINDOW = 10
        Config.GOVERNANCE_ACTIVATION_DELAY = 10
        Config.GOVERNANCE_ROLLBACK_WINDOW = 50
        Config.GOVERNANCE_FINALITY_TIMEOUT = 5

        prop, _ = self._drive_to_active(version=2, signal_start=1)
        self.assertEqual(self.proto_mgr.current_version(), 2)
        self.assertEqual(self.gov.get_active_version(), 2)

        rb_h = prop.activation_height + 6
        self.proto_mgr.record_block_version(2, rb_h)
        self.gov.on_block_applied(_DummyBlock(rb_h, protocol_version=2))
        self.assertEqual(prop.phase, UpgradePhase.FAILED)

        self.assertEqual(self.proto_mgr.current_version(), 1)
        self.assertEqual(self.gov.get_active_version(), 1)

        ok_repropose, msg_repropose = self.gov.propose_upgrade(
            version=2, signal_start_height=rb_h + 100
        )
        self.assertTrue(ok_repropose, f"Re-proposing v2 should succeed: {msg_repropose}")

        ok_skip, _ = self.gov.propose_upgrade(
            version=3, signal_start_height=rb_h + 100
        )
        self.assertFalse(ok_skip)

    def test_emergency_disable_of_active_upgrade_rewinds_proto_mgr(self):
        """V4 Regression (Bug 1b): record_emergency_vote() disabling an ACTIVE
        proposal must rewind proto_mgr to version - 1."""
        Config.FORK_SIGNAL_WINDOW = 10
        Config.GOVERNANCE_ACTIVATION_DELAY = 10
        Config.GOVERNANCE_ROLLBACK_WINDOW = 50

        prop, _ = self._drive_to_active(version=2, signal_start=1)
        self.assertEqual(self.proto_mgr.current_version(), 2)

        w1 = Wallet.generate()
        w2 = Wallet.generate()
        v1 = self.gov.sign_emergency_vote(w1, 2)
        v2 = self.gov.sign_emergency_vote(w2, 2)

        acc1, dis1, _ = self.gov.record_emergency_vote(v1, is_eligible=lambda _: True)
        self.assertTrue(acc1)
        self.assertFalse(dis1)
        acc2, dis2, _ = self.gov.record_emergency_vote(v2, is_eligible=lambda _: True)
        self.assertTrue(acc2)
        self.assertTrue(dis2)
        self.assertEqual(prop.phase, UpgradePhase.FAILED)
        self.assertTrue(prop.disabled)

        self.assertEqual(self.proto_mgr.current_version(), 1)
        self.assertEqual(self.gov.get_active_version(), 1)

    def test_rollback_cooldown_anchored_on_rollback_height(self):
        """V4 Regression (Bug 2): _trigger_rollback() must anchor _cooldown_until_height
        on the rollback height (300 + 200 = 500), not lock_in_height."""
        Config.FORK_SIGNAL_WINDOW = 100
        Config.GOVERNANCE_ACTIVATION_DELAY = 100
        Config.GOVERNANCE_ROLLBACK_WINDOW = 100
        Config.GOVERNANCE_FINALITY_TIMEOUT = 20

        self.gov._rollback_log.append((100, 2))
        self.gov._rollback_log.append((100, 2))

        prop, fin = self._drive_to_active(version=2, signal_start=100)
        self.assertEqual(prop.lock_in_height, 100)
        self.assertEqual(prop.activation_height, 200)

        fin[0] = 279
        rb_h = 300
        self.proto_mgr.record_block_version(2, rb_h)
        self.gov.on_block_applied(_DummyBlock(rb_h, protocol_version=2))
        self.assertEqual(prop.phase, UpgradePhase.FAILED)

        self.assertEqual(self.gov._cooldown_until_height, 500)

        ok, _ = self.gov.propose_upgrade(version=2, signal_start_height=301)
        self.assertFalse(ok, "Proposal during 200-block cooldown must be rejected")


if __name__ == "__main__":
    unittest.main()
