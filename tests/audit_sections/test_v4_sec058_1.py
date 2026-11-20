"""V4 Regression Tests for Section 58: Rounding, Dust, Precision and Supply Conservation."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.economics.rewards import RewardConfig, RewardError, validate_block_rewards
from visold.kernel.units import gas_fee_to_sat
from visold.selfhealing.supply_monitor import SupplyConservationMonitor
from visold.wallet.wallet import Wallet


class _FakeSupplyStorage:
    def __init__(self, supply_sat: int, issued_sat: int):
        self.supply_sat = supply_sat
        self.issued_sat = issued_sat

    def get_total_supply_sat(self) -> int:
        return self.supply_sat

    def get_total_issued_satoshi(self) -> int:
        return self.issued_sat


def test_supply_monitor_detects_silent_inflation_and_allows_legitimate_issuance():
    """V4 Fix:
    SupplyConservationMonitor checks cumulative_issued_sat directly, detecting
    silent inflation regardless of threshold and allowing legitimate issuance
    across skipped sample intervals.
    """
    storage = _FakeSupplyStorage(supply_sat=1_000_000_000, issued_sat=1_000_000_000)
    monitor = SupplyConservationMonitor(storage_ref=storage, blockchain_ref=None)
    anomalies = []
    ade = SimpleNamespace(_listeners=[lambda r: anomalies.append(r)])

    monitor.check(SimpleNamespace(index=50), ade)
    assert anomalies == []

    # Silent inflation: supply_sat increases without issued_sat increasing
    storage.supply_sat += 52_400_000_000
    monitor.check(SimpleNamespace(index=100), ade)
    assert len(anomalies) == 1

    # Reconcile issued_sat and skip a sample interval with legitimate issuance
    storage.issued_sat += 52_400_000_000
    storage.supply_sat += 100_000_000_000
    storage.issued_sat += 100_000_000_000
    monitor.check(SimpleNamespace(index=200), ade)
    assert len(anomalies) == 1


def test_validate_block_rewards_raises_reward_error_on_malformed_coinbase_json():
    """V4 Fix:
    Non-dict JSON or non-numeric subsidy/fees in coinbase.data raises RewardError.
    """
    miner_addr = Wallet.generate().address
    for bad_data in ("[1, 2, 3]", "123", '"hello"', '{"subsidy": "not-an-int", "fees": 0}'):
        cb = {
            "tx_type": RewardConfig.TX_TYPE_REWARD,
            "sender": RewardConfig.COINBASE_SENDER,
            "receiver": miner_addr,
            "amount": 1000,
            "fee": 0,
            "nonce": 1,
            "signature": "",
            "data": bad_data,
        }
        block = SimpleNamespace(index=1, height=1, transactions=[cb])
        with pytest.raises(RewardError):
            validate_block_rewards(block, expected_subsidy=1000, chain_tip_height=1)


def test_gas_fee_to_sat_preserves_positive_gas_price_fee():
    """V4 Fix:
    Positive gas_price with non-zero gas_units does not silently round down to 0 sat.
    """
    assert gas_fee_to_sat(gas_units=10_000_000, gas_price=5e-9) > 0
    assert gas_fee_to_sat(gas_units=10_000_000, gas_price=4e-9) > 0
