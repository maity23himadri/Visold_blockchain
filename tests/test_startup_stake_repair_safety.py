"""Regression tests: startup must not mint coins from an aggregate heuristic."""
from visold.node.visold_node import VisoldNode
from visold.kernel.config import Config


class _Blockchain:
    def height(self):
        return 33

    def compute_reward_sat(self, height):
        assert 1 <= height <= 33
        return Config.INITIAL_REWARD


class _Storage:
    def __init__(self, balances_sat, staked_sat):
        self.balances_sat = balances_sat
        self.staked_sat = staked_sat
        self.credit_calls = []

    def sum_all_balances_satoshi(self):
        return self.balances_sat

    def sum_all_staked_satoshi(self):
        return self.staked_sat

    def credit_sat(self, address, amount):
        self.credit_calls.append((address, amount))
        raise AssertionError("startup diagnostic must never credit balances")


def test_possible_stake_shortfall_is_reported_without_credit(monkeypatch, caplog):
    node = object.__new__(VisoldNode)
    node.blockchain = _Blockchain()
    # 33 x 10 VSD issuance; this case has a 98 VSD shortfall with 100 VSD stake.
    node.storage = _Storage(232 * Config.SATOSHI_PER_VSD,
                            100 * Config.SATOSHI_PER_VSD)

    node._check_legacy_stake_balance_shortfall()

    assert node.storage.credit_calls == []
    assert node.storage.balances_sat == 232 * Config.SATOSHI_PER_VSD
    assert "No automatic credit was applied" in caplog.text


def test_no_repair_or_warning_when_balances_exceed_issuance(caplog):
    node = object.__new__(VisoldNode)
    node.blockchain = _Blockchain()
    node.storage = _Storage(332 * Config.SATOSHI_PER_VSD,
                            100 * Config.SATOSHI_PER_VSD)

    node._check_legacy_stake_balance_shortfall()

    assert node.storage.credit_calls == []
    assert "No automatic credit was applied" not in caplog.text


def test_height_33_balance_332_is_confirmed_overissuance():
    """Reproduce the startup warning visible in the supplied dashboard."""
    import sqlite3
    from visold.resilience.safety_invariants import SafetyInvariantChecker

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE balances (address TEXT, balance INTEGER)")
    conn.execute(("INSERT INTO balances(address, balance) VALUES (?, ?)"),
                 ("wallet", 332 * Config.SATOSHI_PER_VSD))

    class _InvariantStorage:
        _pgx_enabled = False

        @staticmethod
        def _conn():
            return conn

        @staticmethod
        def chain_height():
            return 33

        @staticmethod
        def sum_all_staked_satoshi():
            return 100 * Config.SATOSHI_PER_VSD

        @staticmethod
        def sum_all_slashed_satoshi():
            return 0

    class _InvariantBlockchain:
        @staticmethod
        def compute_reward_sat(height):
            assert 1 <= height <= 33
            return Config.INITIAL_REWARD

    checker = SafetyInvariantChecker(_InvariantStorage(), _InvariantBlockchain(), None)
    violations = []
    try:
        assert checker._check_balance_conservation(violations, full_scan=True) is False
        assert len(violations) == 1
        assert "held=332.00000000 VSD" in violations[0]
        assert "issued-slashed=330.00000000 VSD" in violations[0]
        assert "200000000 satoshi" in violations[0]
    finally:
        conn.close()
