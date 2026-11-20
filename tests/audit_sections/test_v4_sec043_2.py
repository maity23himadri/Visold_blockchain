"""V4 regression tests for Section 43 (Session 04): Parallel Mining Coordination and Edge Guards."""

import threading
from types import SimpleNamespace

from visold.consensus.hashrate_governor import HashrateGovernor
from visold.ledger.block import Block
from visold.mining.engine import MiningEngine
from visold.mining.parallel_miner import ParallelMiner


def _make_block(difficulty: float = 0.001) -> Block:
    return Block(
        index=1,
        transactions=[],
        prev_hash="0" * 64,
        difficulty=difficulty,
        miner_address="VSD1testminer",
        timestamp=1_700_000_000,
    )


def test_mine_cpu_handles_zero_target_and_non_finite_difficulty():
    """V4: ParallelMiner._mine_cpu() fails closed (returns False) on target==0
    and non-finite difficulties (NaN, +Inf, -Inf), matching Block.mine().
    """
    miner = ParallelMiner()
    miner._initialized = True
    miner._backend = "cpu"

    blk_zero = _make_block(difficulty=64.0)
    assert blk_zero.mine() is False

    stop_evt = threading.Event()
    result_holder = []

    def _run():
        result_holder.append(miner.mine(blk_zero, stop_event=stop_evt))

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=1.0)
    still_spinning = t.is_alive()
    if still_spinning:
        stop_evt.set()
        t.join(timeout=2.0)

    assert still_spinning is False, "Expected _mine_cpu to fail closed immediately when target == 0"
    assert result_holder == [False]

    for bad_diff in (float("nan"), float("inf"), float("-inf")):
        blk_bad = _make_block(difficulty=bad_diff)
        assert blk_bad.mine() is False
        assert miner.mine(blk_bad) is False


def test_mining_engine_handles_network_none():
    """V4: MiningEngine.status() and _submit_mined_block() handle network=None cleanly."""
    eng = object.__new__(MiningEngine)
    eng.network = None
    eng._state_engine = None
    eng.start_time = 100.0
    eng.hashes_done = 10
    eng.blocks_found = 0
    eng._running = False
    eng._paused = False
    eng._parallel = ParallelMiner()
    eng._hashrate_governor = HashrateGovernor()
    eng.blockchain = SimpleNamespace(
        get_difficulty=lambda: 1.0,
        height=lambda: 0,
        apply_block=lambda blk: (True, "ok"),
    )
    eng.consensus = SimpleNamespace(validate_and_finalize=lambda blk: None)

    st = eng.status()
    assert isinstance(st, dict)

    blk = _make_block(difficulty=0.001)
    assert eng._submit_mined_block(blk) is True
