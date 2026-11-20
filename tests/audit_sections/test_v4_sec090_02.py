"""V4 regression tests for Section 90: L2 Balance Conservation and Settlement Consistency."""

import sys
from pathlib import Path
from types import SimpleNamespace

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.kernel.units import conservation_check
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, Layer2State
from visold.selfhealing.supply_monitor import SupplyConservationMonitor
from visold.storage.storage import Storage


def _make_storage(tmp_path: Path) -> Storage:
    db_path = str(tmp_path / "visold_test.db")
    return Storage(db_path=db_path)


def test_supply_invariant_ok_returns_three_tuple_and_detects_mismatch(tmp_path: Path):
    storage = _make_storage(tmp_path)
    l2 = Layer2State(storage)

    ok, l2_sup, l1_sup = l2.supply_invariant_ok()
    assert ok is True
    assert l2_sup == 0
    assert l1_sup == 0

    ok_dep, msg_dep = l2.L2_deposit("VSD11111111111111111111111111", 50_000_000, l1_height=1)
    assert ok_dep, msg_dep
    ok, l2_sup, l1_sup = l2.supply_invariant_ok()
    assert ok is False
    assert l2_sup == 50_000_000
    assert l1_sup == 0

    storage.credit_sat(L2_BRIDGE_ADDRESS, 50_000_000)
    ok, l2_sup, l1_sup = l2.supply_invariant_ok()
    assert ok is True
    assert l2_sup == 50_000_000
    assert l1_sup == 50_000_000


def test_supply_conservation_monitor_l2_bridge_check_reports_violation(tmp_path: Path):
    """V4 fix: SupplyConservationMonitor.check() properly unpacks the 3-tuple
    from Layer2State.supply_invariant_ok() and emits an AnomalyReport."""
    storage = _make_storage(tmp_path)
    l2 = Layer2State(storage)

    ok_dep, _ = l2.L2_deposit("VSD11111111111111111111111111", 1_000_000_000, l1_height=1)
    assert ok_dep
    inv_ok, l2_sup, l1_sup = l2.supply_invariant_ok()
    assert inv_ok is False
    assert l2_sup == 1_000_000_000
    assert l1_sup == 0

    blockchain_stub = SimpleNamespace(layer2=l2)
    monitor = SupplyConservationMonitor(storage, blockchain_ref=blockchain_stub)
    reports = []
    ade_stub = SimpleNamespace(_listeners=[reports.append])

    block = SimpleNamespace(index=SupplyConservationMonitor.SAMPLE_INTERVAL)
    monitor.check(block, ade_stub)

    assert len(reports) == 1, (
        f"Expected L2 bridge conservation AnomalyReport, got {len(reports)}"
    )


def test_l2_deposit_withdraw_and_conservation_check(tmp_path: Path):
    storage = _make_storage(tmp_path)
    l2 = Layer2State(storage)
    addr = "VSD11111111111111111111111111"

    storage.credit_sat(addr, 200_000_000)
    storage.set_meta("cumulative_issued_sat", "200000000")
    assert conservation_check(storage) is True

    assert storage.debit_sat(addr, 100_000_000) is True
    storage.credit_sat(L2_BRIDGE_ADDRESS, 100_000_000)
    ok_d, _ = l2.L2_deposit(addr, 100_000_000, l1_height=1)
    assert ok_d is True
    assert conservation_check(storage) is True
    assert l2.supply_invariant_ok() == (True, 100_000_000, 100_000_000)

    ok_w, _ = l2.L2_withdraw(addr, 40_000_000, l1_height=2)
    assert ok_w is True
    assert storage.debit_sat(L2_BRIDGE_ADDRESS, 40_000_000) is True
    storage.credit_sat(addr, 40_000_000)
    assert conservation_check(storage) is True
    assert l2.supply_invariant_ok() == (True, 60_000_000, 60_000_000)
