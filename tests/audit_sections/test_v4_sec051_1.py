"""V4 Regression Tests for Section 51:
Genesis Supply, Initial Allocation and Monetary Issuance.
"""

import os
import sys
from pathlib import Path
import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.kernel.config import Config
from visold.kernel.units import conservation_check, to_satoshi
from visold.chain.blockchain import Blockchain
from visold.storage.storage import Storage
from visold.resilience.hardened_core import SystemInvariantGate


def _make_storage(tmp_path) -> Storage:
    db_path = os.path.join(str(tmp_path), "visold_test.db")
    return Storage(db_path=db_path)


def test_create_genesis_respects_genesis_tx_amount_units_and_credits_allocation(tmp_path, monkeypatch):
    """V4 Fix:
    When Config.GENESIS_TX_AMOUNT > 0 (satoshi), Blockchain._create_genesis()
    converts satoshi -> VSD for Transaction(..., amount=...), credits
    Config.GENESIS_MINER, and increments cumulative_issued_sat cleanly.
    """
    premine_sat = 1_000_000_000  # 10.0 VSD in satoshi
    monkeypatch.setattr(Config, "GENESIS_TX_AMOUNT", premine_sat)
    monkeypatch.setattr(Config, "GENESIS_HASH_PIN", "")

    storage = _make_storage(tmp_path)
    try:
        bc = Blockchain(storage)
        genesis = bc.get_block(0)
        assert genesis is not None
        assert len(genesis.transactions) == 1
        gtx = genesis.transactions[0]

        assert to_satoshi(gtx.amount) == premine_sat
        assert storage.get_balance_sat(Config.GENESIS_MINER) == premine_sat
        assert storage.get_total_issued_satoshi() == premine_sat
        assert storage.get_cumulative_issued_sat() == premine_sat
        assert conservation_check(storage) is True
    finally:
        storage.close()


def test_wipe_all_balances_resets_cumulative_issued_sat_and_preserves_conservation(tmp_path):
    """V4 Fix:
    Storage.wipe_all_balances() resets cumulative_issued_sat to 0 alongside
    clearing balance rows, preserving conservation_check() and SystemInvariantGate.
    """
    storage = _make_storage(tmp_path)
    try:
        storage.credit_sat("VSD_MINER_1", 1_000_000_000)
        storage.increment_cumulative_issued_sat(1_000_000_000)
        assert conservation_check(storage) is True

        storage.wipe_all_balances()

        assert storage.sum_all_balances_satoshi() == 0
        assert storage.get_total_issued_satoshi() == 0
        assert storage.get_cumulative_issued_sat() == 0
        assert conservation_check(storage) is True
        SystemInvariantGate.assert_conservation(storage, context="post_wipe")
    finally:
        storage.close()


def test_increment_cumulative_issued_sat_rejects_negative_values(tmp_path):
    """V4 Fix:
    Storage.increment_cumulative_issued_sat() rejects negative amounts with ValueError
    and leaves cumulative_issued_sat unchanged.
    """
    storage = _make_storage(tmp_path)
    try:
        storage.increment_cumulative_issued_sat(100_000_000)
        assert storage.get_cumulative_issued_sat() == 100_000_000

        with pytest.raises(ValueError, match="non-negative"):
            storage.increment_cumulative_issued_sat(-500_000_000)
        assert storage.get_cumulative_issued_sat() == 100_000_000
    finally:
        storage.close()
