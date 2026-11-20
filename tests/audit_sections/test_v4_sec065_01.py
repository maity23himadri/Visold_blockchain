"""V4 Regression tests for Section 65: Slashing Calculation, Limits and Atomic Execution."""

import os
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock

V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if V4_ROOT not in sys.path:
    sys.path.insert(0, V4_ROOT)

from visold.kernel.config import Config
from visold.selfhealing.healing import (
    FreezeRegistry,
    HealingActionLayer,
    HealingActionLog,
    RateLimiter,
    ValidatorAlerter,
)
from visold.selfhealing.model import (
    AnomalyKind,
    AnomalyReport,
    Severity,
    SeverityDecision,
)
from visold.selfhealing.storage_patch import patch_storage
from visold.storage.storage import Storage


class TestV4Section65SlashingExecution(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmpdir.name, "test_visold.db")
        self.storage = Storage(db_path=self.db_path)

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        self._tmpdir.cleanup()

    def test_storage_slash_atomic_on_sqlite_roles(self):
        """Baseline sanity check: Storage.slash() atomically slashes once in SQLite roles."""
        addr = "VSD_VALIDATOR_1"
        self.storage.set_role(addr, "miner", 100.0)

        ok1 = self.storage.slash(addr)
        ok2 = self.storage.slash(addr)
        role = self.storage.get_role(addr)

        self.assertTrue(ok1)
        self.assertFalse(ok2)
        self.assertEqual(role["slashed"], 1)
        expected_stake = 100.0 * max(0.0, 1.0 - float(Config.SLASH_RATE))
        self.assertAlmostEqual(role["stake"], expected_stake, places=9)

    def test_storage_slash_validator_updates_sqlite_roles_and_hal_slashes(self):
        """
        V4 Regression (Bug 1):
        patch_storage() slash_validator() must slash in SQLite roles table and
        HealingActionLayer._trigger_slash() must actually slash the validator.
        """
        addr = "VSD_DOUBLE_SIGNER_1"
        self.storage.set_role(addr, "miner", 250.0)
        patch_storage(self.storage)

        result = self.storage.slash_validator(addr)
        self.assertTrue(result, "slash_validator should succeed on SQLite")

        role_after_direct = self.storage.get_role(addr)
        self.assertEqual(role_after_direct["slashed"], 1)
        self.assertLess(role_after_direct["stake"], 250.0)

        addr2 = "VSD_DOUBLE_SIGNER_2"
        self.storage.set_role(addr2, "miner", 250.0)
        hal = HealingActionLayer(
            action_log=HealingActionLog(self.storage),
            rate_limiter=RateLimiter(),
            freeze_registry=FreezeRegistry(),
            alerter=ValidatorAlerter(MagicMock()),
            rollback_executor=MagicMock(),
            circuit_breaker_ref=MagicMock(),
            storage_ref=self.storage,
            blockchain_ref=MagicMock(height=MagicMock(return_value=10)),
        )
        report = AnomalyReport(
            kind=AnomalyKind.DOUBLE_SIGN,
            confidence=1.0,
            description="Double sign at height 10",
            affected_addr=addr2,
            block_height=10,
            evidence={"height": 10},
            detected_at=time.time(),
            source="test",
        )
        decision = SeverityDecision(
            report=report,
            severity=Severity.HIGH,
            action_tags=["log", "slash_validator"],
            rationale="Double sign detected",
            attacker_ev=0.0,
            validator_ev=0.0,
            suppress=False,
        )

        hal._trigger_slash(addr2, decision)

        role_after_hal = self.storage.get_role(addr2)
        self.assertEqual(role_after_hal["slashed"], 1)
        self.assertLess(role_after_hal["stake"], 250.0)


if __name__ == "__main__":
    unittest.main()
