"""
V4 Regression Tests for Section 53: Reward Configuration Validation and Transition Boundaries
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.chain.blockchain import Blockchain
from visold.economics.rewards import (
    RewardError,
    build_coinbase,
    validate_block_rewards,
)
from visold.kernel.config import Config
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_block(height: int, txs: list):
    return SimpleNamespace(height=height, index=height, transactions=txs)


def test_reward_decay_transition_boundaries_and_floor(tmp_path):
    """Verify compute_reward_sat at genesis, epoch boundaries, and MIN_REWARD floor."""
    storage = Storage(str(tmp_path / "test.db"))
    bc = Blockchain(storage)

    epoch = Config.REWARD_DECAY_BLOCKS  # 20000
    assert bc.compute_reward_sat(0) == Config.GENESIS_TX_AMOUNT
    assert bc.compute_reward_sat(1) == Config.INITIAL_REWARD
    assert bc.compute_reward_sat(epoch - 1) == Config.INITIAL_REWARD

    # First decay transition at height == 20000
    r_epoch1 = bc.compute_reward_sat(epoch)
    assert r_epoch1 == 990_000_000
    assert isinstance(r_epoch1, int)
    assert bc.compute_reward_sat(2 * epoch - 1) == r_epoch1

    # Second decay transition at height == 40000
    r_epoch2 = bc.compute_reward_sat(2 * epoch)
    assert r_epoch2 == 980_100_000
    assert isinstance(r_epoch2, int)

    # Floor transition: n=458 > MIN_REWARD, n=459 == MIN_REWARD
    assert bc.compute_reward_sat(458 * epoch) > Config.MIN_REWARD
    assert bc.compute_reward_sat(459 * epoch) == Config.MIN_REWARD
    assert bc.compute_reward_sat(500 * epoch) == Config.MIN_REWARD


def test_validate_block_rewards_enforces_tx_type_reward():
    """V4 Fix: validate_block_rewards() Rule R2 rejects tx_type != 'reward' with RewardError."""
    miner_addr = Wallet.generate().address
    cb = build_coinbase(
        miner_address=miner_addr,
        height=1,
        subsidy=Config.INITIAL_REWARD,
        fees=0,
        consensus="pow",
        timestamp=1_700_000_000,
    ).to_dict()
    cb["tx_type"] = "transfer"

    block = _make_block(height=1, txs=[cb])
    with pytest.raises(RewardError):
        validate_block_rewards(
            block,
            expected_subsidy=Config.INITIAL_REWARD,
            chain_tip_height=0,
        )


def test_validate_block_rewards_raises_reward_error_on_malformed_data():
    """V4 Fix: validate_block_rewards() raises RewardError on non-dict JSON,
    non-numeric fields, null fields, and booleans.
    """
    miner_addr = Wallet.generate().address
    base_cb = build_coinbase(
        miner_address=miner_addr,
        height=1,
        subsidy=Config.INITIAL_REWARD,
        fees=0,
        consensus="pow",
        timestamp=1_700_000_000,
    ).to_dict()

    cb_list = dict(base_cb, data="[]")
    with pytest.raises(RewardError):
        validate_block_rewards(_make_block(1, [cb_list]), Config.INITIAL_REWARD, 0)

    cb_str = dict(base_cb, data=json.dumps({"subsidy": "not_an_int", "fees": 0}))
    with pytest.raises(RewardError):
        validate_block_rewards(_make_block(1, [cb_str]), Config.INITIAL_REWARD, 0)

    cb_null = dict(base_cb, data=json.dumps({"subsidy": None, "fees": 0}))
    with pytest.raises(RewardError):
        validate_block_rewards(_make_block(1, [cb_null]), Config.INITIAL_REWARD, 0)

    cb_bool = dict(base_cb, amount=1, data=json.dumps({"subsidy": True, "fees": False}))
    with pytest.raises(RewardError):
        validate_block_rewards(_make_block(1, [cb_bool]), 1, 0)


def test_compute_reward_sat_rejects_negative_height(tmp_path):
    """V4 Fix: compute_reward_sat(height) with negative height raises ValueError."""
    storage = Storage(str(tmp_path / "test_neg.db"))
    bc = Blockchain(storage)

    with pytest.raises(ValueError, match="non-negative"):
        bc.compute_reward_sat(-1)
