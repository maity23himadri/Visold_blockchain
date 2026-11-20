import sys
import tempfile
import unittest
from pathlib import Path

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.chain.sequencer import Sequencer
from visold.rollup.l2_state import Layer2State, L2Transaction
from visold.storage.storage import Storage


class TestV4Section89L2RollbackAndReorg(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmp.name) / "test_sec89.db")
        self.storage = Storage(db_path=self.db_path)
        self.layer2 = Layer2State(self.storage)

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        self._tmp.cleanup()

    def test_rollback_plan_and_checkpoint_restoration(self):
        addr = "VSD111111111111111111111111111111"
        ok, msg = self.layer2.rollback_to_height(0)
        self.assertTrue(ok)
        self.assertEqual(msg, "no-l2-state")

        self.layer2.L2_deposit(addr, 1000, l1_height=2, l1_block_hash="h2")
        self.layer2.L2_deposit(addr, 500, l1_height=5, l1_block_hash="h5")
        self.assertEqual(self.layer2.get_balance_sat(addr), 1500)

        can, _ = self.layer2.can_rollback_to_height(3)
        self.assertTrue(can)
        ok, msg = self.layer2.rollback_to_height(3)
        self.assertTrue(ok)
        self.assertEqual(msg, "OK")
        self.assertEqual(self.layer2.get_balance_sat(addr), 1000)

        can, _ = self.layer2.can_rollback_to_height(1)
        self.assertTrue(can)
        ok, msg = self.layer2.rollback_to_height(1)
        self.assertTrue(ok)
        self.assertEqual(msg, "reset-to-empty")
        self.assertEqual(self.layer2.get_balance_sat(addr), 0)

    def test_evicted_history_refuses_rollback_to_lost_height(self):
        addr = "VSD111111111111111111111111111111"
        self.layer2._history_max = 3
        for h in (1, 2, 3, 4, 5):
            self.layer2.L2_deposit(addr, 100, l1_height=h, l1_block_hash=f"h{h}")

        can, reason = self.layer2.can_rollback_to_height(2)
        self.assertFalse(can)
        self.assertIn("missing or unreadable", reason)

        ok, _ = self.layer2.rollback_to_height(2)
        self.assertFalse(ok)
        self.assertEqual(self.layer2.get_balance_sat(addr), 500)

    def test_sequencer_dropped_rollup_requeue_and_abandon_seal(self):
        class _DummyBC:
            def __init__(self, storage, layer2):
                self.storage = storage
                self.layer2 = layer2
                self._listeners = []

            def add_rollup_drop_listener(self, fn):
                self._listeners.append(fn)

        class _DummyWallet:
            address = "VSD111111111111111111111111111111"

        bc = _DummyBC(self.storage, self.layer2)
        seq = Sequencer(bc, self.layer2, _DummyWallet())
        seq._running = True

        sender = "VSD111111111111111111111111111111"
        receiver = "VSD222222222222222222222222222222"
        l2_tx = L2Transaction(sender=sender, receiver=receiver, amount_sat=100, nonce=0)
        seq._record_sealed("l1_tx_abc", 0, [l2_tx])
        seq._on_rollup_dropped("l1_tx_abc")
        requeued = seq._process_dropped_rollups()
        self.assertEqual(requeued, 1)
        self.assertEqual(len(seq._pending), 1)
        self.assertEqual(seq._pending[0].l2_tx_id, l2_tx.l2_tx_id)

        seq._abandon_seal()


if __name__ == "__main__":
    unittest.main()
