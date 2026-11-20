"""V4 regression tests for Section 43 (Session 03): Parallel Mining Coordination."""

import threading
import time
from types import SimpleNamespace

from visold.crypto.ecc import ecdsa_keygen
from visold.crypto.vrf import vrf_verify
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.mining.engine import MiningEngine
from visold.mining.parallel_miner import ParallelMiner


def _make_dummy_block(
    index: int = 1,
    prev_hash: str = "a" * 64,
    difficulty: float = 0.001,
    extra_vrf_pad: int = 0,
) -> Block:
    vrf_proof = ("bb" * 40) + ("cc" * extra_vrf_pad)
    blk = Block(
        index=index,
        transactions=[],
        prev_hash=prev_hash,
        timestamp=1_700_000_000 + index,
        miner_address="VSD1testmineraddress000000000000000000000",
        difficulty=difficulty,
        vrf_proof=vrf_proof,
        vrf_output="dd" * 32,
        state_root="ee" * 32,
    )
    blk.merkle_root = blk._merkle()
    return blk


def test_parallel_miner_concurrent_initialize_thread_safe():
    miner = ParallelMiner()
    results = []
    barrier = threading.Barrier(8)

    def _init():
        barrier.wait()
        results.append(miner.initialize())

    threads = [threading.Thread(target=_init) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    assert len(results) == 8
    assert all(r == "cpu" for r in results)
    assert miner._initialized is True


def test_parallel_miner_multi_worker_strided_mining_and_hash_parity(monkeypatch):
    monkeypatch.setattr(Config, "MINING_THREADS", 4)
    miner = ParallelMiner()
    miner._n_threads = 4

    blk = _make_dummy_block(index=2, difficulty=0.001, extra_vrf_pad=900)
    ok = miner.mine(blk)
    assert ok is True
    assert miner.backend_info()["cpu_threads"] == 4
    assert miner.backend_info()["hash_input_bytes"] > 2047
    assert blk.nonce >= 16
    assert blk.block_hash == blk.compute_hash()


def test_parallel_miner_stop_event_cancels_promptly():
    miner = ParallelMiner()
    blk = _make_dummy_block(index=3, difficulty=12.0)
    stop_evt = threading.Event()

    def _trigger_stop():
        time.sleep(0.05)
        stop_evt.set()

    stopper = threading.Thread(target=_trigger_stop, daemon=True)
    stopper.start()
    t0 = time.monotonic()
    ok = miner.mine(blk, stop_event=stop_evt)
    elapsed = time.monotonic() - t0
    stopper.join(timeout=2.0)

    assert ok is False
    assert elapsed < 2.0


def test_parallel_miner_dynamic_cap_provider_fail_open_on_error(monkeypatch):
    monkeypatch.setattr(Config, "HASHRATE_THROTTLE_BATCH_SIZE", 16)
    miner = ParallelMiner()
    blk = _make_dummy_block(index=4, difficulty=0.001)

    calls = [0]

    def _flaky_provider():
        calls[0] += 1
        raise RuntimeError("telemetry error")

    ok = miner.mine(blk, max_hps=100.0, max_hps_provider=_flaky_provider)
    assert ok is True
    assert blk.block_hash == blk.compute_hash()


def test_mine_one_fallback_vrf_tip_advance_consistent(monkeypatch):
    """V4: If tip advances between latest_block() and build_candidate_block(),
    _mine_one() must either abort or re-prove VRF against the new tip so no
    block with mismatched VRF proof is mined/broadcast.
    """
    priv, pub_pt = ecdsa_keygen()
    pub_hex = ("02" if pub_pt.y % 2 == 0 else "03") + f"{pub_pt.x:064x}"
    wallet = SimpleNamespace(priv=priv, pub_hex=pub_hex, address="VSD1testminer")

    tip_old = SimpleNamespace(index=5, block_hash="11" * 32, timestamp=1_700_000_005)
    tip_new = SimpleNamespace(index=6, block_hash="22" * 32, timestamp=1_700_000_006)

    storage = SimpleNamespace(
        get_role=lambda addr: None,
        get_block=lambda idx: tip_new if idx == 6 else tip_old,
    )

    state = {"tip": tip_old}
    lock = threading.Lock()

    def _latest_block():
        return state["tip"]

    blockchain = SimpleNamespace(
        _lock=lock,
        latest_block=_latest_block,
        height=lambda: state["tip"].index,
        get_difficulty=lambda: 0.001,
        storage=storage,
        apply_block=lambda b: (True, "ok"),
    )

    def _build_candidate_block(miner_addr, vrf_proof_hex="", vrf_beta_hex=""):
        state["tip"] = tip_new
        with lock:
            cur = state["tip"]
            b = _make_dummy_block(index=cur.index + 1, prev_hash=cur.block_hash, difficulty=0.001)
            b.vrf_proof = vrf_proof_hex
            b.vrf_output = vrf_beta_hex
            b.miner_address = miner_addr
            return b

    consensus = SimpleNamespace(
        build_candidate_block=_build_candidate_block,
        validate_and_finalize=lambda b: None,
    )

    mined_blocks = []

    class _FakeNetwork:
        peers = {}
        node_id = "node1"
        wallet = None
        hashrate = 0.0

        def broadcast_block(self, b):
            mined_blocks.append(b)

    engine = MiningEngine(
        blockchain=blockchain,
        consensus=consensus,
        network=_FakeNetwork(),
        wallet=wallet,
        storage=storage,
        state_engine=None,
    )
    monkeypatch.setattr(Config, "MINING_SAFETY_ENABLED", False)

    engine._mine_one()

    for mined in mined_blocks:
        assert vrf_verify(
            pub_hex,
            mined.prev_hash.encode(),
            bytes.fromhex(mined.vrf_proof),
            bytes.fromhex(mined.vrf_output),
        ) is True


def test_submit_mined_block_none_network_succeeds_without_state_engine():
    """V4: _submit_mined_block() with state_engine=None and network=None
    applies and finalizes the block without raising AttributeError.
    """
    applied_blocks = []
    finalized_blocks = []

    blockchain = SimpleNamespace(
        _lock=threading.Lock(),
        latest_block=lambda: None,
        height=lambda: 0,
        get_difficulty=lambda: 0.001,
        apply_block=lambda b: (applied_blocks.append(b) or True, "ok"),
    )
    consensus = SimpleNamespace(
        validate_and_finalize=lambda b: finalized_blocks.append(b),
    )
    storage = SimpleNamespace(get_role=lambda addr: None)
    wallet = SimpleNamespace(priv=1, pub_hex="02" + "00" * 32, address="VSD1test")

    engine = MiningEngine(
        blockchain=blockchain,
        consensus=consensus,
        network=None,
        wallet=wallet,
        storage=storage,
        state_engine=None,
    )

    blk = _make_dummy_block(index=1)
    ok = engine._submit_mined_block(blk)
    assert ok is True
    assert len(applied_blocks) == 1
    assert len(finalized_blocks) == 1
