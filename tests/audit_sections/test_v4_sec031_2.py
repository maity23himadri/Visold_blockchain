"""Targeted audit tests for Section 31: Proof-of-Work Verification and Target Validation."""
from __future__ import annotations

import math

from visold.consensus.difficulty import DifficultyEngine
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mining.parallel_miner import ParallelMiner
from visold.wallet.wallet import Wallet


def test_difficulty_to_target_and_validate_pow_target_boundaries():
    t_zero = DifficultyEngine.difficulty_to_target(0.0)
    assert t_zero == (1 << 256) - 1

    t_max = DifficultyEngine.difficulty_to_target(64.0)
    assert t_max == 0

    t_low = DifficultyEngine.difficulty_to_target(0.001)
    t_mid = DifficultyEngine.difficulty_to_target(1.5)
    t_high = DifficultyEngine.difficulty_to_target(4.0)
    assert t_zero > t_low > t_mid > t_high > t_max

    assert not DifficultyEngine.validate_pow_target("0" * 64, float("nan"))
    assert not DifficultyEngine.validate_pow_target("0" * 64, float("inf"))
    assert not DifficultyEngine.validate_pow_target("not_hex", 0.001)
    assert not DifficultyEngine.validate_pow_target("f" * 64, 1.0)
    assert DifficultyEngine.validate_pow_target("0" * 64, 64.0)


def test_block_mine_and_parallel_miner_cpu_pow_parity():
    miner = Wallet.generate()
    cb = Transaction.coinbase(miner.address, 50.0, 1)

    blk1 = Block(
        index=1,
        prev_hash="0" * 64,
        transactions=[cb],
        miner_address=miner.address,
        difficulty=0.001,
        state_root="a" * 64,
    )
    assert blk1.mine()
    assert blk1.nonce >= 16
    assert blk1.validate_pow()
    ok, msg = blk1.integrity_check()
    assert ok, msg

    blk2 = Block(
        index=1,
        prev_hash="0" * 64,
        transactions=[cb],
        miner_address=miner.address,
        difficulty=0.001,
        state_root="a" * 64,
    )
    pm = ParallelMiner()
    assert pm.mine(blk2)
    assert blk2.nonce >= 16
    assert blk2.validate_pow()
    ok2, msg2 = blk2.integrity_check()
    assert ok2, msg2

    # Non-finite difficulty fails closed in Block.mine()
    blk_nan = Block(
        index=1,
        prev_hash="0" * 64,
        transactions=[cb],
        miner_address=miner.address,
        difficulty=float("nan"),
        state_root="a" * 64,
    )
    assert not blk_nan.mine()
    assert not blk_nan.validate_pow()
