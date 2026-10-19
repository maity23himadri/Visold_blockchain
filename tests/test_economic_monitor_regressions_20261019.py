"""Regression tests for solo-mining economic-monitor false positives."""
from __future__ import annotations

from visold.economics.monitor import EconomicMonitor
from visold.kernel.config import Config


class _StorageWithValidators:
    def get_all_by_role(self, role):
        assert role == "investor"
        return []


def _monitor(monkeypatch):
    monkeypatch.setattr(Config, "SOLO_MINING_MODE", False)
    monitor = EconomicMonitor(_StorageWithValidators())
    warnings = []
    critical = []
    monkeypatch.setattr("visold.economics.monitor.log.warning", lambda msg, *a, **k: warnings.append(str(msg)))
    monkeypatch.setattr("visold.economics.monitor.log.critical", lambda msg, *a, **k: critical.append(str(msg)))
    return monitor, warnings, critical


def test_single_producer_streak_never_claims_selfish_mining(monkeypatch):
    monitor, warnings, critical = _monitor(monkeypatch)
    for _ in range(95):
        monitor.record_block_rewards("miner-A", {"miner-A": 100_000_000})
        monitor._check_selfish_mining()
    assert not any("selfish mining" in message.lower() for message in warnings + critical)
    assert warnings == []
    assert critical == []


def test_one_historical_other_producer_does_not_trigger_alerts(monkeypatch):
    monitor, warnings, critical = _monitor(monkeypatch)
    monitor.record_block_rewards("old-miner", {"old-miner": 100_000_000})
    for _ in range(20):
        monitor.record_block_rewards("solo-miner", {"solo-miner": 100_000_000})
    assert warnings == []
    assert critical == []


def test_recent_competitor_followed_by_solo_streak_is_suppressed(monkeypatch):
    monitor, warnings, critical = _monitor(monkeypatch)
    for _ in range(2):
        monitor.record_block_rewards("previous-miner", {"previous-miner": 100})
    for _ in range(30):
        monitor.record_block_rewards("solo-miner", {"solo-miner": 100})
    assert warnings == []
    assert critical == []


def test_competing_producer_reward_alert_is_deduplicated(monkeypatch):
    monitor, warnings, critical = _monitor(monkeypatch)
    # Two producers each produced repeatedly in the same ten-block window;
    # the measured allocations deliberately concentrate payouts with miner A.
    # Competition is interleaved near the tip; B's two recent blocks are not
    # just stale history preceding a long solo streak by A.
    for producer, payouts in [
        ("miner-B", {"miner-B": 100}),
        ("miner-B", {"miner-B": 100}),
        ("miner-A", {"miner-A": 900, "validator-X": 100}),
        ("miner-A", {"miner-A": 900, "validator-X": 100}),
        ("miner-B", {"miner-B": 100}),
        ("miner-B", {"miner-B": 100}),
        ("miner-A", {"miner-A": 900, "validator-X": 100}),
        ("miner-A", {"miner-A": 900, "validator-X": 100}),
        ("miner-A", {"miner-A": 900, "validator-X": 100}),
        ("miner-A", {"miner-A": 900, "validator-X": 100}),
    ]:
        monitor.record_block_rewards(producer, payouts)
    first_count = len(warnings)
    assert first_count == 1
    assert "actual reward concentration" in warnings[0].lower()
    assert "not proof of selfish mining" in warnings[0].lower()

    # As the competing producer leaves the ten-block window, the alert clears;
    # it does not re-emit on every block while the same condition remains active.
    for _ in range(10):
        monitor.record_block_rewards("miner-A", {"miner-A": 900, "validator-X": 100})
    assert len(warnings) == first_count
    assert critical == []


def test_rollback_history_rebase_discards_orphaned_reward_and_fee_samples(monkeypatch):
    monitor, warnings, critical = _monitor(monkeypatch)
    for _ in range(12):
        monitor.record_block_rewards("orphaned-miner", {"orphaned-miner": 100})
        monitor.record_block_fees(1.0)

    monitor.replace_canonical_history(["canonical-miner"] * 8)
    assert list(monitor._miner_sequence) == ["canonical-miner"] * 8
    assert list(monitor._fee_log) == []
    assert all(allocations is None for _, allocations in monitor._reward_log)

    for _ in range(12):
        monitor.record_block_rewards("canonical-miner", {"canonical-miner": 100})
    assert warnings == []
    assert critical == []


def test_fee_spike_warning_emitted_once_per_continuous_condition(monkeypatch):
    monitor, warnings, _ = _monitor(monkeypatch)
    for _ in range(5):
        monitor.record_block_fees(1.0)
    for _ in range(8):
        monitor.record_block_fees(100.0)
    fee_warnings = [msg for msg in warnings if "fee spike" in msg.lower()]
    assert len(fee_warnings) == 1


def test_distribute_rewards_returns_exact_credited_allocations(monkeypatch):
    from types import SimpleNamespace

    from visold.chain.blockchain import Blockchain

    class _FakeStorage:
        def __init__(self):
            self.balances = {}

        def increment_cumulative_issued_sat(self, amount):
            self.issued = getattr(self, "issued", 0) + amount

        def get_all_by_role(self, role):
            if role == "miner":
                return [{"address": "miner-A"}, {"address": "miner-B"}]
            if role == "investor":
                return [
                    {"address": "validator-A", "stake": 3.0},
                    {"address": "validator-B", "stake": 1.0},
                ]
            raise AssertionError(role)

        def credit_sat(self, address, amount):
            self.balances[address] = self.balances.get(address, 0) + int(amount)

    storage = _FakeStorage()
    chain = Blockchain.__new__(Blockchain)
    chain.storage = storage
    chain.compute_reward_sat = lambda _height: 100_000
    chain._miner_reward_weight = lambda miner, _height: (
        3 if miner["address"] == "miner-A" else 1
    )
    monkeypatch.setattr(Config, "REWARD_CREATOR", 0.20)
    monkeypatch.setattr(Config, "REWARD_ALL_MINERS", 0.45)
    monkeypatch.setattr(Config, "REWARD_ALL_VALIDATORS", 0.35)
    monkeypatch.setattr(Config, "BURN_ADDRESS", "burn-address")

    allocations = chain._distribute_rewards(
        SimpleNamespace(index=5, miner_address="miner-A"), fee_pool_sat=0
    )
    assert allocations == storage.balances
    assert sum(allocations.values()) == 100_000
    assert allocations["miner-A"] == 53_750
    assert allocations["miner-B"] == 11_250
    assert allocations["validator-A"] == 26_250
    assert allocations["validator-B"] == 8_750
    assert "burn-address" not in allocations


def test_blockchain_rebuild_helper_uses_canonical_tip_blocks(monkeypatch):
    from types import SimpleNamespace

    from visold.chain.blockchain import Blockchain

    class _FakeChainStorage(_StorageWithValidators):
        def chain_height(self):
            return 12

        def get_block(self, height):
            return SimpleNamespace(miner_address=("canonical-A" if height % 2 else "canonical-B"))

    monitor = EconomicMonitor(_FakeChainStorage())
    chain = Blockchain.__new__(Blockchain)
    chain.storage = _FakeChainStorage()
    chain._eco_mon = monitor
    chain._rebuild_economic_monitor_history()

    assert len(monitor._miner_sequence) == 12
    assert monitor._miner_sequence[-1] == "canonical-B"
    assert monitor._miner_sequence[-2] == "canonical-A"
    assert all(allocations is None for _, allocations in monitor._reward_log)
    assert list(monitor._fee_log) == []
