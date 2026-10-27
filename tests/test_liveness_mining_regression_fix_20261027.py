"""Regression tests for liveness breaker policy and short-input CPU mining."""

import threading
import time
from types import SimpleNamespace

from visold.kernel.config import Config
from visold.mining.parallel_miner import ParallelMiner
from visold.resilience.panic_breaker import PanicCircuitBreaker
from visold.resilience.safety_invariants import SafetyInvariantChecker
from visold.state.engine import StateEngine


class _Storage:
    def get_block(self, _height):
        return None


class _Blockchain:
    def __init__(self, height=5):
        self._height = height

    def height(self):
        return self._height


class _Network:
    def active_peer_count(self):
        return ["peer-a"]


class _Mining:
    def __init__(self):
        self.pause_calls = 0

    def pause(self):
        self.pause_calls += 1


def test_same_liveness_stall_remains_visible_but_does_not_trip_breaker(
        monkeypatch, caplog):
    monkeypatch.setattr(Config, "CIRCUIT_BREAKER_ENABLED", True)
    monkeypatch.setattr(Config, "CIRCUIT_BREAKER_VIOLATIONS", 2)
    blockchain = _Blockchain(height=5)
    checker = SafetyInvariantChecker(_Storage(), blockchain, _Network())
    checker._last_liveness_height = 5
    checker._last_liveness_time = time.time() - checker.LIVENESS_TIMEOUT_SECS - 2

    first = checker.rolling_check()["violations"]
    second = checker.rolling_check()["violations"]
    assert any(v.startswith("LIVENESS VIOLATION:") for v in first)
    assert any(v.startswith("LIVENESS VIOLATION:") for v in second)

    mining = _Mining()
    breaker = PanicCircuitBreaker(mining_engine=mining)
    for violation in first + second:
        breaker.record_violation(violation)

    assert breaker.state() == breaker.CLOSED
    assert mining.pause_calls == 0
    # A recurring one-second timer check is not allowed to flood the log for
    # one liveness episode; the checker re-emits at most once per minute.
    assert caplog.text.count("LIVENESS VIOLATION:") == 1
    breaker._stop_evt.set()


def test_real_safety_violations_still_trip_breaker(monkeypatch):
    monkeypatch.setattr(Config, "CIRCUIT_BREAKER_ENABLED", True)
    monkeypatch.setattr(Config, "CIRCUIT_BREAKER_VIOLATIONS", 2)
    mining = _Mining()
    breaker = PanicCircuitBreaker(mining_engine=mining)

    breaker.record_violation("SAFETY VIOLATION: broken chain linkage")
    assert breaker.state() == breaker.CLOSED
    breaker.record_violation("SAFETY VIOLATION: broken chain linkage")
    try:
        assert breaker.state() == breaker.OPEN
        assert mining.pause_calls == 1
    finally:
        breaker._stop_evt.set()


def test_state_engine_only_forwards_non_liveness_violations_to_breaker():
    recorded = []

    class _Mempool:
        _lock = threading.RLock()

        @staticmethod
        def _purge_expired():
            return None

        @staticmethod
        def size():
            return 0

    engine = object.__new__(StateEngine)
    engine._release_protected_transfer = lambda: None
    engine._purge_stale_protected_reveals = lambda: None
    engine._blockchain = SimpleNamespace(
        mempool=_Mempool(), height=lambda: 0)
    engine._state_pruner = None
    engine._invariant_checker = SimpleNamespace(
        rolling_check=lambda: {"violations": [
            "LIVENESS VIOLATION: no new block",
            "SAFETY VIOLATION: chain linkage broken",
        ]})
    engine._circuit_breaker = SimpleNamespace(
        record_violation=lambda reason: recorded.append(reason))

    engine._handle_timer()
    assert recorded == ["SAFETY VIOLATION: chain linkage broken"]


def _run_fake_cpu_candidate(monkeypatch, extra_header=None, configured_threads=4):
    workers = []
    stop = threading.Event()

    def fake_worker(*args, **_kwargs):
        # Capture nonce start/stride and wait until the caller requests stop.
        workers.append((args[3], args[4]))
        worker_stop_flag = args[8]
        while not worker_stop_flag.wait(0.005):
            pass

    monkeypatch.setattr("visold.mining.parallel_miner._cy_mine_worker", fake_worker)

    class _Candidate:
        difficulty = 6.0

        def header_dict(self):
            header = {
                "version": 1,
                "protocol_version": 1,
                "index": 999,
                "timestamp": int(time.time()),
                "difficulty": self.difficulty,
                "prev_hash": "00" * 32,
                "merkle_root": "11" * 32,
                "vrf_proof": "test-proof",
            }
            if extra_header:
                header.update(extra_header)
            return header

    miner = ParallelMiner()
    miner._n_threads = configured_threads
    stopper = threading.Thread(
        target=lambda: (time.sleep(0.16), stop.set()), daemon=True)
    stopper.start()
    assert miner._mine_cpu(_Candidate(), stop_event=stop, max_hps=0.0) is False
    stopper.join(2.0)
    assert not stopper.is_alive()
    return miner, workers


def test_short_canonical_hash_input_uses_one_effective_worker(monkeypatch, caplog):
    import logging
    caplog.set_level(logging.INFO, logger="VISOLD")
    miner, workers = _run_fake_cpu_candidate(monkeypatch, configured_threads=4)
    assert len(workers) == 1, workers
    assert workers[0] == (0, 1)
    info = miner.backend_info()
    assert info["cpu_threads"] == 1
    assert info["configured_cpu_threads"] == 4
    assert 0 < info["hash_input_bytes"] <= 2047
    notice = next(
        record for record in caplog.records
        if "Mining header input is" in record.getMessage()
    )
    assert notice.levelno == logging.INFO
    assert "Using 1 CPU worker" in notice.getMessage()


def test_hash_input_over_gil_threshold_can_use_configured_workers(monkeypatch):
    miner, workers = _run_fake_cpu_candidate(
        monkeypatch,
        extra_header={"long_payload_for_test": "x" * 2300},
        configured_threads=2,
    )
    assert len(workers) == 2, workers
    assert sorted(workers) == [(0, 2), (1, 2)]
    info = miner.backend_info()
    assert info["cpu_threads"] == 2
    assert info["configured_cpu_threads"] == 2
    assert info["hash_input_bytes"] > 2047
