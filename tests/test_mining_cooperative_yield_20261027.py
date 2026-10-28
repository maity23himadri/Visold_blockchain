"""Regression tests for miner fairness under long-running CPU-bound work."""
import threading
import time

import visold.mining.workers as workers


def test_cpu_worker_cooperatively_yields_without_changing_hash_work(monkeypatch):
    stop = threading.Event()
    result = []
    result_lock = threading.Lock()
    work_metrics = [(0, 0.0)]
    yields = []

    # An all-zero target is not realistically satisfiable. Stop the worker
    # after three scheduler yields so this test is deterministic and quick.
    def controlled_sleep(seconds):
        yields.append(seconds)
        if len(yields) >= 3:
            stop.set()

    monkeypatch.setattr(time, "sleep", controlled_sleep)
    monkeypatch.setattr(workers, "_COOPERATIVE_YIELD_INTERVAL_SECONDS", 0.0)
    workers._cy_mine_worker(
        '{"nonce":%d,"timestamp":%d}',
        b"\x00" * 32,
        1_700_000_000,
        0,
        1,
        0,
        result,
        result_lock,
        stop,
        0.0,
        0,
        work_metrics,
        0,
        None,
    )

    assert yields == [0, 0, 0]
    assert work_metrics[0][0] >= 3 * 1024
    assert result == []
