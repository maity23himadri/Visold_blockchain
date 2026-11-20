"""V4 Regression Tests for Section 59: Reward Concentration and Validator Reward Manipulation Monitoring."""
from __future__ import annotations

import sys
from pathlib import Path

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.economics.monitor import EconomicMonitor


class _ValidatorStorage:
    def __init__(self, validators: list[dict]):
        self._validators = validators

    def get_all_by_role(self, role: str) -> list[dict]:
        assert role == "investor"
        return self._validators


def test_validator_stealing_entire_validator_pool_triggers_manipulation_alert(monkeypatch):
    """V4 Fix:
    _check_validator_reward_manipulation() normalizes over validator_total_reward
    and triggers 'reward/stake share divergence' when a 20%-stake validator captures 100% of the pool.
    """
    warnings = []
    monkeypatch.setattr(
        "visold.economics.monitor.log.warning",
        lambda msg, *a, **k: warnings.append(str(msg)),
    )

    storage = _ValidatorStorage([
        {"address": "val-1", "stake": 20.0},
        {"address": "val-2", "stake": 80.0},
    ])
    mon = EconomicMonitor(storage)

    for i in range(12):
        mon.record_block_rewards(
            f"miner-{i % 3}",
            {
                f"miner-{i % 3}": 65_000_000,
                "val-1": 35_000_000,
            },
        )

    mon.record_validator_sigs(["val-1", "val-2", "val-3"])
    assert any("reward/stake share divergence" in w.lower() for w in warnings)


def test_validator_reward_manipulation_runs_with_fewer_than_3_sigs(monkeypatch):
    """V4 Fix:
    record_validator_sigs() runs _check_validator_reward_manipulation() unconditionally,
    even when fewer than 3 validator signatures are present.
    """
    warnings = []
    monkeypatch.setattr(
        "visold.economics.monitor.log.warning",
        lambda msg, *a, **k: warnings.append(str(msg)),
    )

    storage = _ValidatorStorage([
        {"address": "val-1", "stake": 5.0},
        {"address": "val-2", "stake": 95.0},
    ])
    mon = EconomicMonitor(storage)
    for i in range(12):
        mon.record_block_rewards(
            f"miner-{i % 2}",
            {
                f"miner-{i % 2}": 50_000_000,
                "val-1": 50_000_000,
            },
        )

    mon.record_validator_sigs(["val-1", "val-2"])
    assert any("reward/stake share divergence" in w.lower() for w in warnings)
