"""Regression tests for 2026-10-26 hashrate governor redesign."""

from __future__ import annotations
import threading
import time
from types import SimpleNamespace

from visold.consensus.difficulty import DifficultyEngine
from visold.consensus.hashrate_governor import HashrateGovernor
from visold.kernel.config import Config
from visold.mining.workers import _cy_mine_worker


def _fixed_required(monkeypatch, value: float = 3192.5):
    monkeypatch.setattr(
        DifficultyEngine, "required_network_hashrate",
        staticmethod(lambda difficulty, target_block_time=None: float(value)))


def test_startup_without_local_measurement_is_unthrottled_calibration(monkeypatch):
    _fixed_required(monkeypatch)
    monkeypatch.setattr(Config, "HASHRATE_OPTIMIZATION_ENABLED", True)
    gov = HashrateGovernor()
    assert gov.record_peer_hashrate("peer-a", 5000.0, reported_ts=time.time(), sequence=1)

    cap, required, debug = gov.advise(4.0)
    assert required == 3192.5
    assert cap == float("inf"), "new miner must not be throttled by a peer-rate placeholder"
    assert debug["measurement_ready"] is False
    assert debug["mode"] == "startup_calibration"
    assert gov.status_snapshot()["measurement_ready"] is False


def test_below_required_local_capacity_is_not_throttled(monkeypatch):
    _fixed_required(monkeypatch, 3192.5)
    monkeypatch.setattr(Config, "HASHRATE_OPTIMIZATION_ENABLED", True)
    gov = HashrateGovernor()
    gov.update_local_actual_hashrate(1800.0)
    gov.record_peer_hashrate("peer-a", 9000.0)

    cap, required, debug = gov.advise(4.0)
    assert required == 3192.5
    assert cap == 1800.0
    assert debug["mode"] == "local_below_required"


def test_above_required_uses_local_actual_as_numerator(monkeypatch):
    _fixed_required(monkeypatch, 3192.5)
    monkeypatch.setattr(Config, "HASHRATE_OPTIMIZATION_ENABLED", True)
    monkeypatch.setattr(Config, "HASHRATE_SHARE_EXPONENT", 0.5)
    gov = HashrateGovernor()
    gov.update_local_actual_hashrate(7588.3)
    gov.record_peer_hashrate("peer-a", 4055.2)

    cap, required, debug = gov.advise(4.0)
    expected_share = (7588.3 ** 0.5) / (7588.3 ** 0.5 + 4055.2 ** 0.5)
    expected = max(required, 7588.3 * expected_share)
    assert abs(cap - expected) < 0.1
    assert cap >= required
    assert cap <= 7588.3
    assert debug["mode"] == "weighted_local_actual"


def test_calculated_cap_below_required_is_floored_at_required(monkeypatch):
    _fixed_required(monkeypatch, 3192.5)
    monkeypatch.setattr(Config, "HASHRATE_OPTIMIZATION_ENABLED", True)
    monkeypatch.setattr(Config, "HASHRATE_SHARE_EXPONENT", 0.5)
    gov = HashrateGovernor()
    gov.update_local_actual_hashrate(4000.0)
    # Many high-rate direct peers make this miner's weighted cap very small.
    for i in range(20):
        assert gov.record_peer_hashrate(f"peer-{i}", 1_000_000.0)

    cap, required, debug = gov.advise(4.0)
    assert debug["calculated_cap_before_floor_hps"] < required
    assert cap == required


def test_peer_report_rejects_stale_and_replayed_sequences(monkeypatch):
    monkeypatch.setattr(Config, "HASHRATE_PEER_TTL", 300)
    gov = HashrateGovernor()
    now = time.time()
    assert not gov.record_peer_hashrate("peer-a", 500.0,
                                        reported_ts=now - 1000, sequence=1)
    assert gov.record_peer_hashrate("peer-a", 500.0,
                                    reported_ts=now, sequence=10)
    assert not gov.record_peer_hashrate("peer-a", 600.0,
                                        reported_ts=now, sequence=10)
    assert not gov.record_peer_hashrate("peer-a", 600.0,
                                        reported_ts=now, sequence=9)
    assert gov.record_peer_hashrate("peer-a", 650.0,
                                    reported_ts=now + 1.0, sequence=11)
    with gov._lock:
        assert gov._peer_rates["peer-a"][0] == 650.0


def test_cpu_worker_emits_active_compute_metrics_without_a_solved_block():
    stop = threading.Event()
    result = []
    lock = threading.Lock()
    metrics = [(0, 0.0)]
    # No hash can practically equal the all-zero target; this checks ongoing
    # telemetry, rather than waiting for a successful block/nonce result.
    worker = threading.Thread(
        target=_cy_mine_worker,
        args=("{\"nonce\":%d,\"timestamp\":%d}", bytes(32),
              1_700_000_000, 0, 1, 0, result, lock, stop,
              0.0, 0, metrics, 0),
        daemon=True,
    )
    worker.start()
    time.sleep(0.15)
    stop.set()
    worker.join(3.0)
    assert not worker.is_alive()
    assert result == []
    assert metrics[0][0] > 0
    assert metrics[0][1] > 0.0


def test_dynamic_throttle_worker_flushes_telemetry_before_1024_batch(monkeypatch):
    # Make each digest deliberately slow so this is deterministic across hosts.
    # With a 1024-nonce throttle batch, telemetry must still flush at 256 hashes
    # rather than waiting for the first throttle boundary / solved block.
    import hashlib
    real_sha256 = hashlib.sha256

    def slow_sha256(data=b"", *args, **kwargs):
        time.sleep(0.0002)
        return real_sha256(data, *args, **kwargs)

    monkeypatch.setattr(hashlib, "sha256", slow_sha256)
    stop = threading.Event()
    result = []
    lock = threading.Lock()
    metrics = [(0, 0.0)]
    worker = threading.Thread(
        target=_cy_mine_worker,
        args=("{\"nonce\":%d,\"timestamp\":%d}", bytes(32),
              1_700_000_000, 0, 1, 0, result, lock, stop,
              0.0, 1024, metrics, 0, [float("inf")]),
        daemon=True,
    )
    worker.start()
    time.sleep(0.10)
    visible_count_before_stop = metrics[0][0]
    stop.set()
    worker.join(3.0)
    assert not worker.is_alive()
    assert visible_count_before_stop >= 256, visible_count_before_stop
    assert visible_count_before_stop < 1024, visible_count_before_stop


def test_ui_status_uses_measuring_label_before_first_sample(monkeypatch):
    # Exercise status formatting without spinning up a full node.
    from visold.mining.engine import MiningEngine
    gov = HashrateGovernor()
    fake = object.__new__(MiningEngine)
    fake.start_time = time.time()
    fake.hashes_done = 0
    fake.blocks_found = 0
    fake.network = SimpleNamespace(hashrate=0.0)
    fake.blockchain = SimpleNamespace(get_difficulty=lambda: 4.0, height=lambda: 12)
    fake._parallel = SimpleNamespace(
        backend_info=lambda: {
            "backend": "CPU", "cpu_threads": 2, "gpu_enabled": False,
            "gpu_device": 0, "gpu_batch": 0, "cuda_avail": False,
            "opencl_avail": False,
        },
        get_raw_hashrate=lambda: 0.0,
    )
    fake._hashrate_governor = gov
    fake._running = True
    fake._paused = False
    status = fake.status()
    assert status["hashrate"] == "measuring…"
    assert status["actual_hashrate"] == "measuring…"
    assert status["optimized_hashrate"] == "calibrating (unthrottled)"
    assert status["hashrate_measurement_ready"] is False


def test_parallel_miner_measures_rate_before_any_block_is_found():
    from visold.mining.parallel_miner import ParallelMiner

    class _Candidate:
        difficulty = 6.0  # too hard to solve during the short measurement test

        def header_dict(self):
            return {
                "version": 1, "protocol_version": 1, "index": 999,
                "nonce": 0, "timestamp": int(time.time()),
                "difficulty": self.difficulty,
                "prev_hash": "00" * 32, "merkle_root": "11" * 32,
                "vrf_proof": "test-proof",
            }

    miner = ParallelMiner()
    miner._n_threads = 2
    stop = threading.Event()
    stopper = threading.Thread(
        target=lambda: (time.sleep(0.45), stop.set()), daemon=True)
    stopper.start()
    assert miner._mine_cpu(_Candidate(), stop_event=stop, max_hps=0.0) is False
    stopper.join(2.0)
    assert miner.get_raw_hashrate() > 0.0, (
        "hashrate should be measured from ongoing hash work, not wait for a block")


def test_hashrate_report_signature_binds_origin_rate_and_timestamp():
    import hashlib
    from visold.wallet.wallet import Wallet
    from visold.consensus.hashrate_reports import (
        sign_hashrate_report, verify_hashrate_report,
    )
    wallet = Wallet.generate()
    node_id = hashlib.sha256(wallet.pub_hex.encode("ascii")).hexdigest()
    report = sign_hashrate_report(wallet, node_id, 4321.5,
                                  issued_at=int(time.time()), sequence=time.time_ns())
    assert verify_hashrate_report(report)
    changed_rate = dict(report, hashrate=123.0)
    assert not verify_hashrate_report(changed_rate)
    changed_origin = dict(report, node_id="0" * 64)
    assert not verify_hashrate_report(changed_origin)


def test_parallel_miner_refreshes_cap_during_an_unsolved_candidate(monkeypatch):
    from visold.mining.parallel_miner import ParallelMiner
    from visold.kernel.config import Config as _Config
    observations = []
    call_count = [0]
    start_at = time.monotonic()
    real_worker = __import__("visold.mining.parallel_miner", fromlist=["_cy_mine_worker"])._cy_mine_worker

    def fake_worker(*args, **kwargs):
        # dynamic_cap_ref is the final positional worker argument.
        stop_flag = args[8]
        dynamic_ref = args[-1]
        while not stop_flag.is_set():
            observations.append(float(dynamic_ref[0]))
            time.sleep(0.005)
        return None

    class _Candidate:
        difficulty = 6.0
        def header_dict(self):
            return {"version": 1, "protocol_version": 1, "index": 999,
                    "timestamp": int(time.time()), "difficulty": self.difficulty,
                    "prev_hash": "00" * 32, "merkle_root": "11" * 32,
                    "vrf_proof": "test-proof"}

    monkeypatch.setattr("visold.mining.parallel_miner._cy_mine_worker", fake_worker)
    monkeypatch.setattr(_Config, "HASHRATE_THROTTLE_BATCH_SIZE", 32)
    miner = ParallelMiner()
    miner._n_threads = 2
    stop = threading.Event()

    def cap_provider():
        call_count[0] += 1
        # First sample remains unthrottled; a measured cap is then applied to
        # the already-running candidate without waiting for a solved block.
        return float("inf") if time.monotonic() - start_at < 0.14 else 100.0

    stopper = threading.Thread(target=lambda: (time.sleep(0.42), stop.set()), daemon=True)
    stopper.start()
    assert miner._mine_cpu(_Candidate(), stop_event=stop, max_hps=0.0,
                           max_hps_provider=cap_provider) is False
    stopper.join(2.0)
    assert call_count[0] >= 2
    assert any(v == float("inf") for v in observations)
    assert any(abs(v - 50.0) < 1e-9 for v in observations), observations[:10]


def test_relayed_peer_rate_uses_origin_timestamp_for_decay(monkeypatch):
    monkeypatch.setattr(Config, "HASHRATE_PEER_TTL", 300)
    monkeypatch.setattr(Config, "HASHRATE_FRESH_SECS", 30)
    monkeypatch.setattr(Config, "HASHRATE_DECAY_SECS", 60)
    gov = HashrateGovernor()
    now = time.time()
    assert gov.record_peer_hashrate("relayed-origin", 1000.0,
                                    reported_ts=now - 45, sequence=1)
    with gov._lock:
        effective = gov._live_peer_rates()
    assert len(effective) == 1
    assert abs(effective[0] - 750.0) < 1.0, effective


def test_legacy_direct_reports_refresh_origin_timestamp_without_sequence():
    gov = HashrateGovernor()
    now = time.time()
    assert gov.record_peer_hashrate("legacy-peer", 500.0, reported_ts=now)
    assert gov.record_peer_hashrate("legacy-peer", 600.0, reported_ts=now + 5)
    with gov._lock:
        assert gov._peer_report_meta["legacy-peer"][0] == now + 5
        assert gov._peer_rates["legacy-peer"][0] == 600.0


def test_solo_miner_above_required_is_not_throttled(monkeypatch):
    _fixed_required(monkeypatch, 3192.5)
    monkeypatch.setattr(Config, "HASHRATE_OPTIMIZATION_ENABLED", True)
    gov = HashrateGovernor()
    gov.update_local_actual_hashrate(4055.2)
    cap, required, debug = gov.advise(4.0)
    assert required == 3192.5
    assert abs(cap - 4055.2) < 1e-9
    assert debug["local_share"] == 1.0


def test_equal_required_local_rate_never_receives_a_lower_cap(monkeypatch):
    _fixed_required(monkeypatch, 3192.5)
    monkeypatch.setattr(Config, "HASHRATE_OPTIMIZATION_ENABLED", True)
    gov = HashrateGovernor()
    gov.update_local_actual_hashrate(3192.5)
    gov.record_peer_hashrate("peer-a", 100_000.0)
    cap, required, _debug = gov.advise(4.0)
    assert cap == required == 3192.5
