"""V4 regression tests for Section 45: CPU/GPU Mining Parity and Compat Flags."""

import importlib.util
import threading

import pytest

from visold.kernel import compat
from visold.ledger.block import Block
from visold.mining.parallel_miner import ParallelMiner


def _make_test_block(difficulty: float = 0.001) -> Block:
    return Block(
        index=1,
        prev_hash="0" * 64,
        transactions=[],
        miner_address="VSD" + "a" * 37,
        difficulty=difficulty,
        timestamp=1_700_000_000,
    )


def test_compat_gpu_availability_flags_false_when_packages_missing():
    """V4: _CUDA_AVAILABLE and _OPENCL_AVAILABLE are False when pycuda/pyopencl are absent."""
    assert importlib.util.find_spec("pycuda") is None
    assert importlib.util.find_spec("pyopencl") is None

    miner = ParallelMiner()
    info = miner.backend_info()

    assert compat._CUDA_AVAILABLE is False
    assert compat._OPENCL_AVAILABLE is False
    assert info["cuda_avail"] is False
    assert info["opencl_avail"] is False


def test_parallel_miner_cpu_fails_closed_on_zero_target():
    """V4: ParallelMiner._mine_cpu() returns False immediately when difficulty >= 64.0 (target == 0)."""
    block_legacy = _make_test_block(difficulty=64.0)
    assert block_legacy.mine() is False

    block_parallel = _make_test_block(difficulty=64.0)
    miner = ParallelMiner()
    stop_evt = threading.Event()
    timer = threading.Timer(1.0, stop_evt.set)
    timer.start()
    try:
        result = miner.mine(block_parallel, stop_event=stop_evt)
    finally:
        timer.cancel()

    assert result is False
    assert not stop_evt.is_set()


@pytest.mark.parametrize("bad_diff", [float("nan"), float("inf"), float("-inf")])
def test_parallel_miner_fails_closed_on_non_finite_difficulty(bad_diff):
    """V4: ParallelMiner.mine() fails closed by returning False on non-finite difficulty."""
    block_legacy = _make_test_block(difficulty=bad_diff)
    assert block_legacy.mine() is False

    block_parallel = _make_test_block(difficulty=bad_diff)
    miner = ParallelMiner()
    assert miner.mine(block_parallel) is False
