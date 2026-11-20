"""V4 Regression Tests for Section 52: Subsidy Schedule and Coinbase Units."""

import sys
import time
from pathlib import Path
import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.kernel.config import Config
from visold.kernel.units import to_satoshi, from_satoshi
from visold.chain.blockchain import Blockchain
from visold.economics.rewards import RewardError, build_coinbase
from visold.ledger.transaction import Transaction
from visold.wallet.wallet import Wallet


def _bare_blockchain() -> Blockchain:
    return Blockchain.__new__(Blockchain)


def test_compute_reward_sat_clamps_exponentiation_at_min_reward_floor():
    """V4 Fix:
    compute_reward_sat() clamps n at the MIN_REWARD floor in O(1) without
    performing unbounded big-integer exponentiation for huge block heights.
    """
    bc = _bare_blockchain()

    assert bc.compute_reward_sat(458 * Config.REWARD_DECAY_BLOCKS) > Config.MIN_REWARD
    assert bc.compute_reward_sat(459 * Config.REWARD_DECAY_BLOCKS) == Config.MIN_REWARD

    t_large0 = time.perf_counter()
    r_large = bc.compute_reward_sat(2_000_000 * Config.REWARD_DECAY_BLOCKS)
    t_large = time.perf_counter() - t_large0

    assert r_large == Config.MIN_REWARD
    assert t_large < 0.05, f"Expected O(1) clamped computation, took {t_large:.6f}s"


def test_coinbase_to_dict_matches_transaction_from_dict_units():
    """V4 Fix:
    Coinbase.to_dict() emits 'amount' in VSD float matching Transaction.from_dict(),
    so round-tripping preserves exact satoshi amount without 10^8x inflation.
    """
    bc = _bare_blockchain()
    subsidy_sat = bc.compute_reward_sat(1)
    assert subsidy_sat == Config.INITIAL_REWARD

    miner_addr = Wallet.generate().address
    cb = build_coinbase(
        miner_address=miner_addr,
        height=1,
        subsidy=subsidy_sat,
        fees=0,
        consensus="pow",
    )
    wire_dict = cb.to_dict()
    assert wire_dict["amount"] == from_satoshi(subsidy_sat)

    tx = Transaction.from_dict(wire_dict)
    assert to_satoshi(tx.amount) == subsidy_sat


def test_compute_reward_sat_genesis_height_zero_matches_genesis_tx_amount():
    """V4 Fix:
    Genesis block (height=0) returns Config.GENESIS_TX_AMOUNT (0) instead of INITIAL_REWARD.
    """
    bc = _bare_blockchain()
    assert Config.GENESIS_TX_AMOUNT == 0
    assert bc.compute_reward_sat(0) == 0
    assert bc.compute_reward(0) == 0.0


def test_build_coinbase_rejects_bool_and_invalid_inputs_with_reward_error():
    """V4 Fix:
    build_coinbase() rejects booleans for height/subsidy/fees and invalid
    extra_nonce/timestamp inputs with RewardError.
    """
    miner_addr = Wallet.generate().address

    with pytest.raises(RewardError):
        build_coinbase(
            miner_address=miner_addr,
            height=True,
            subsidy=100,
            fees=0,
            consensus="pow",
        )

    with pytest.raises(RewardError):
        build_coinbase(
            miner_address=miner_addr,
            height=1,
            subsidy=True,
            fees=False,
            consensus="pow",
        )

    with pytest.raises(RewardError):
        build_coinbase(
            miner_address=miner_addr,
            height=1,
            subsidy=100,
            fees=0,
            consensus="pow",
            extra_nonce="not_bytes",
        )

    with pytest.raises(RewardError):
        build_coinbase(
            miner_address=miner_addr,
            height=1,
            subsidy=100,
            fees=0,
            consensus="pow",
            timestamp="not_a_timestamp",
        )

    with pytest.raises(RewardError):
        build_coinbase(
            miner_address=miner_addr,
            height=1,
            subsidy=100,
            fees=0,
            consensus="pow",
            timestamp=float("nan"),
        )
