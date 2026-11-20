import math
import threading
import pytest

from visold.consensus.difficulty import DifficultyEngine
from visold.ledger.block import Block
from visold.mining.parallel_miner import ParallelMiner


def _make_candidate_block(miner_address: str = "VSDtestminer", difficulty: float = 0.001) -> Block:
    return Block(
        index=1,
        prev_hash="0" * 64,
        transactions=[],
        miner_address=miner_address,
        difficulty=difficulty,
        timestamp=1_700_000_000,
    )


def test_parallel_miner_cpu_handles_percent_in_header_field():
    """
    V4 regression: _build_mine_template() escapes '%' in header_dict() fields so
    a '%' in miner_address (or vrf_proof/state_root) does not crash _cy_mine_worker
    or hang ParallelMiner._mine_cpu().
    """
    miner = ParallelMiner()
    miner._backend = "cpu"
    miner._initialized = True

    blk = _make_candidate_block(miner_address="VSD%s_miner", difficulty=0.001)
    stop_evt = threading.Event()
    timer = threading.Timer(2.0, stop_evt.set)
    timer.start()
    try:
        ok = miner.mine(blk, stop_event=stop_evt)
    finally:
        timer.cancel()

    assert ok is True
    assert not stop_evt.is_set()
    assert blk.validate_pow() is True


def test_parallel_miner_cpu_fails_closed_on_nan_difficulty_and_zero_target():
    """
    V4 regression: ParallelMiner._mine_cpu() fails closed (returns False) on
    non-finite difficulty (NaN/Inf) and when target <= 0 (difficulty >= 64.0)
    without raising ValueError or spinning until stop_event fires.
    """
    miner = ParallelMiner()
    miner._backend = "cpu"
    miner._initialized = True

    # 2a. Non-finite difficulty fails closed (returns False)
    blk_nan = _make_candidate_block(difficulty=float("nan"))
    assert blk_nan.mine() is False
    assert miner.mine(blk_nan) is False

    # 2b. Zero target (difficulty >= 64.0) returns False immediately
    blk_zero_target = _make_candidate_block(difficulty=64.0)
    assert DifficultyEngine.difficulty_to_target(64.0) == 0
    assert blk_zero_target.mine() is False

    stop_evt = threading.Event()
    timer = threading.Timer(1.0, stop_evt.set)
    timer.start()
    try:
        ok = miner.mine(blk_zero_target, stop_event=stop_evt)
    finally:
        timer.cancel()

    assert ok is False
    assert not stop_evt.is_set()


def test_section_31_clean_pow_and_target_checks():
    """Verify baseline Block.mine(), validate_pow(), integrity_check(), and validate_pow_target()."""
    blk = _make_candidate_block(difficulty=0.001)
    assert blk.mine() is True
    assert blk.nonce >= 16
    assert blk.validate_pow() is True
    ok, msg = blk.integrity_check()
    assert ok is True, msg
    assert DifficultyEngine.validate_pow_target(blk.block_hash, blk.difficulty) is True
    assert DifficultyEngine.validate_pow_target(blk.block_hash, float("nan")) is False
    assert DifficultyEngine.validate_pow_target(blk.block_hash, float("inf")) is False
