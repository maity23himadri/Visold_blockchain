import sys
import tempfile
import unittest
from pathlib import Path

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.rollup.l2_state import Layer2State, L2_BRIDGE_ADDRESS
from visold.selfhealing.supply_monitor import SupplyConservationMonitor
from visold.storage.storage import Storage


class _DummyADE:
    def __init__(self):
        self.reports = []
        self._listeners = [self.reports.append]


class _DummyBlockchain:
    def __init__(self, storage, layer2):
        self.storage = storage
        self.layer2 = layer2


class _DummyBlock:
    def __init__(self, index: int):
        self.index = index


class TestV4Section90L2Conservation(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmp.name) / "test_sec90.db")
        self.storage = Storage(db_path=self.db_path)
        self.layer2 = Layer2State(self.storage)

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        self._tmp.cleanup()

    def test_supply_invariant_ok_returns_three_tuple(self):
        self.storage.credit_sat(L2_BRIDGE_ADDRESS, 1_000_000)
        self.layer2.L2_deposit("VSD111111111111111111111111111111", 1_000_000, l1_height=1)
        res = self.layer2.supply_invariant_ok()
        self.assertEqual(res, (True, 1_000_000, 1_000_000))

    def test_supply_monitor_reports_l2_invariant_violation(self):
        """V4 fix: SupplyConservationMonitor.check() properly unpacks
        Layer2State.supply_invariant_ok()'s 3-tuple and emits an AnomalyReport
        on L2 bridge conservation violations."""
        self.layer2.L2_deposit("VSD111111111111111111111111111111", 1_000_000, l1_height=1)
        ok, l2_sat, l1_sat = self.layer2.supply_invariant_ok()
        self.assertFalse(ok)
        self.assertEqual(l2_sat, 1_000_000)
        self.assertEqual(l1_sat, 0)

        bc = _DummyBlockchain(self.storage, self.layer2)
        ade = _DummyADE()
        monitor = SupplyConservationMonitor(self.storage, blockchain_ref=bc)
        monitor.check(_DummyBlock(SupplyConservationMonitor.SAMPLE_INTERVAL), ade)

        l2_reports = [
            r for r in ade.reports
            if getattr(r, "evidence", {}).get("check") == "layer2.supply_invariant_ok"
        ]
        self.assertEqual(len(l2_reports), 1)


if __name__ == "__main__":
    unittest.main()
