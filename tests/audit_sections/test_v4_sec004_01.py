"""V4 regression tests for Audit Section 004: Units, Precision & Reward Validation."""

import json

import pytest

from visold.economics.rewards import (
    RewardConfig,
    RewardError,
    compute_tx_fee,
    validate_block_rewards,
)
from visold.kernel.config import Config
from visold.kernel.units import from_satoshi, gas_fee_to_sat, to_satoshi


def test_to_satoshi_and_from_satoshi_exact_precision_above_2_pow_53():
    """to_satoshi('100000000.00000001') preserves exact 1-satoshi precision above 2^53."""
    exact_sat = 100_000_000 * Config.SATOSHI_PER_VSD + 1
    assert to_satoshi("100000000.00000001") == exact_sat
    assert to_satoshi(from_satoshi(exact_sat)) == exact_sat


def test_gas_fee_to_sat_rejects_negative_and_float_inputs():
    """gas_fee_to_sat rejects negative inputs with ValueError and float gas_units with TypeError."""
    with pytest.raises(ValueError):
        gas_fee_to_sat(-100, 0.00000001)
    with pytest.raises(ValueError):
        gas_fee_to_sat(100, -0.00000001)
    with pytest.raises(TypeError):
        gas_fee_to_sat(1.5, 0.00000001)


def test_validate_block_rewards_raises_reward_error_on_malformed_coinbase_data():
    """validate_block_rewards raises RewardError on non-dict JSON or non-int subsidy in coinbase.data."""

    class DummyBlock:
        height = 1
        transactions = [
            {
                "tx_type": RewardConfig.TX_TYPE_REWARD,
                "sender": RewardConfig.COINBASE_SENDER,
                "receiver": "VSD_MINER_1",
                "amount": 1000,
                "nonce": 1,
                "signature": "",
                "data": "[]",
            }
        ]

    with pytest.raises(RewardError):
        validate_block_rewards(DummyBlock(), expected_subsidy=1000, chain_tip_height=0)

    DummyBlock.transactions[0]["data"] = json.dumps({"subsidy": "not-an-int", "fees": 0})
    with pytest.raises(RewardError):
        validate_block_rewards(DummyBlock(), expected_subsidy=1000, chain_tip_height=0)


def test_compute_tx_fee_rejects_float_output_amounts():
    """compute_tx_fee raises RewardError instead of silently truncating float output amounts."""
    tx = {
        "tx_id": "tx1",
        "tx_type": "transfer",
        "sender": "VSD_ALICE",
        "inputs": [{"prev_txid": "prev1", "prev_vout": 0}],
        "outputs": [{"amount": 9.9}],
    }
    utxo_lookup = lambda txid, vout: {"amount": 10}
    with pytest.raises(RewardError):
        compute_tx_fee(tx, utxo_lookup)
