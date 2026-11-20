"""V4 regression tests for Section 42 (Session 03): Mining Worker Lifecycle & Prewarm."""

import hashlib
import json
import threading
import time
from unittest.mock import MagicMock

from visold.crypto.vrf import vrf_verify
from visold.ledger.block import Block
from visold.mining.engine import MiningEngine
from visold.mining.parallel_miner import ParallelMiner
from visold.mining.workers import _build_mine_template, _cy_mine_worker
from visold.wallet.wallet import Wallet


def _make_block(
    index: int,
    prev_hash: str,
    difficulty: float = 1.0,
    vrf_proof: str = "",
    vrf_output: str = "",
    timestamp: int = 1700000000,
):
    return Block(
        index=index,
        transactions=[],
        prev_hash=prev_hash,
        miner_address="VSDminer1",
        difficulty=difficulty,
        timestamp=timestamp,
        vrf_proof=vrf_proof,
        vrf_output=vrf_output,
    )


def test_build_mine_template_matches_block_header_json():
    blk = _make_block(1, "a" * 64, difficulty=1.0, timestamp=1700000123)
    hdr = json.loads(json.dumps(blk.header_dict(), default=str))
    orig_ts = hdr.pop("timestamp")
    hdr.pop("nonce", None)
    fmt = _build_mine_template(hdr)

    for nonce in (0, 17, 123456):
        rendered = (fmt % (nonce, orig_ts)).encode("ascii")
        expected_dict = dict(blk.header_dict())
        expected_dict["nonce"] = nonce
        expected_dict["timestamp"] = orig_ts
        expected = json.dumps(expected_dict, sort_keys=True, default=str).encode("ascii")
        assert rendered == expected
        assert hashlib.sha256(rendered).digest() == hashlib.sha256(expected).digest()


def test_cy_mine_worker_stops_promptly_during_throttle_sleep():
    blk = _make_block(1, "b" * 64, difficulty=1000.0, timestamp=1700000123)
    hdr = json.loads(json.dumps(blk.header_dict(), default=str))
    orig_ts = hdr.pop("timestamp")
    hdr.pop("nonce", None)
    fmt = _build_mine_template(hdr)

    target_bytes = (1).to_bytes(32, "big")
    result = []
    lock = threading.Lock()
    stop_flag = threading.Event()
    work_metrics = [(0, 0.0)]
    dynamic_cap_ref = [0.001]

    t = threading.Thread(
        target=_cy_mine_worker,
        args=(
            fmt,
            target_bytes,
            orig_ts,
            0,
            1,
            16,
            result,
            lock,
            stop_flag,
            0.0,
            2,
            work_metrics,
            0,
            dynamic_cap_ref,
        ),
        daemon=True,
    )
    t.start()
    time.sleep(0.05)
    t0 = time.monotonic()
    stop_flag.set()
    t.join(timeout=1.0)
    elapsed = time.monotonic() - t0
    assert not t.is_alive()
    assert elapsed < 0.5
    assert result == []


def test_parallel_miner_cpu_single_vs_multi_worker_threshold_and_stop():
    pm = ParallelMiner()
    pm._initialized = True
    pm._backend = "cpu"
    pm._n_threads = 4

    blk = _make_block(1, "c" * 64, difficulty=0.0001, timestamp=1700000123)
    stop_evt = threading.Event()
    ok = pm.mine(blk, stop_event=stop_evt)
    assert ok is True
    assert pm.backend_info()["cpu_threads"] == 1

    hard_blk = _make_block(2, "d" * 64, difficulty=1e9, timestamp=1700000123)
    stop_evt2 = threading.Event()
    stop_evt2.set()
    t0 = time.monotonic()
    ok2 = pm.mine(hard_blk, stop_event=stop_evt2)
    assert ok2 is False
    assert (time.monotonic() - t0) < 0.5


def test_prewarm_consume_single_use_and_stale_rejection():
    wallet = Wallet.generate()
    tip5 = _make_block(5, "e" * 64)
    tip5.block_hash = "5" * 64
    tip6 = _make_block(6, "5" * 64)
    tip6.block_hash = "6" * 64

    bc = MagicMock()
    bc.latest_block.return_value = tip5
    consensus = MagicMock()
    storage = MagicMock()

    engine = MiningEngine(bc, consensus, None, wallet, storage)
    cand = _make_block(6, tip5.block_hash)
    with engine._prewarm_lock:
        engine._prewarm_block = cand
        engine._prewarm_height = 5

    assert engine._consume_prewarm() is cand
    assert engine._consume_prewarm() is None

    with engine._prewarm_lock:
        engine._prewarm_block = cand
        engine._prewarm_height = 5
    bc.latest_block.return_value = tip6
    assert engine._consume_prewarm() is None


def test_live_mining_threads_blocks_restart_while_thread_alive():
    wallet = Wallet.generate()
    bc = MagicMock()
    consensus = MagicMock()
    storage = MagicMock()
    storage.get_role.return_value = {"role": "miner"}

    engine = MiningEngine(bc, consensus, None, wallet, storage)
    blocker = threading.Event()
    live_t = threading.Thread(target=blocker.wait, daemon=True)
    live_t.start()
    try:
        engine._thread = live_t
        assert engine._live_mining_threads() == [live_t]
        ok, msg = engine.start()
        assert ok is False
        assert "still stopping" in msg
    finally:
        blocker.set()
        live_t.join(timeout=1.0)


def test_prewarm_vrf_tip_advance_rejects_stale_candidate():
    """V4: If tip advances between VRF proof and build_candidate_block(),
    _prewarm_loop() must not publish a candidate whose VRF proof does not
    match its prev_hash.
    """
    wallet = Wallet.generate()
    tip5 = _make_block(5, "0" * 64)
    tip5.block_hash = "5" * 64
    tip6 = _make_block(6, tip5.block_hash)
    tip6.block_hash = "6" * 64

    current_tip = [tip5]
    bc = MagicMock()
    bc.latest_block.side_effect = lambda: current_tip[0]

    stored_event = threading.Event()

    def _build_candidate_with_tip_advance(miner_addr, vrf_proof_hex, vrf_output_hex):
        current_tip[0] = tip6
        return _make_block(
            index=7,
            prev_hash=tip6.block_hash,
            vrf_proof=vrf_proof_hex,
            vrf_output=vrf_output_hex,
        )

    consensus = MagicMock()
    consensus.build_candidate_block.side_effect = _build_candidate_with_tip_advance
    storage = MagicMock()
    storage.get_role.return_value = {"role": "miner"}

    engine = MiningEngine(bc, consensus, None, wallet, storage)

    def _signal_after_first_build(timeout=None):
        stored_event.set()
        engine._prewarm_stop.set()
        return True

    engine._prewarm_wake.wait = _signal_after_first_build

    t = threading.Thread(target=engine._prewarm_loop, daemon=True)
    t.start()
    assert stored_event.wait(timeout=2.0)
    t.join(timeout=2.0)

    consumed = engine._consume_prewarm()
    if consumed is not None:
        assert vrf_verify(
            wallet.pub_hex,
            consumed.prev_hash.encode(),
            bytes.fromhex(consumed.vrf_proof),
            bytes.fromhex(consumed.vrf_output),
        ) is True
