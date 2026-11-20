"""V4 regression tests for Section 42 (Session 04): Mining Worker Thread Lifecycle and Synchronization."""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from visold.crypto.ecc import ecdsa_keygen
from visold.crypto.vrf import vrf_verify
from visold.mining.engine import MiningEngine
from visold.wallet.wallet import Wallet


def _make_block(
    index: int,
    block_hash: str,
    prev_hash: str = "0" * 64,
    vrf_proof: str = "",
    vrf_output: str = "",
):
    return SimpleNamespace(
        index=index,
        block_hash=block_hash,
        prev_hash=prev_hash,
        vrf_proof=vrf_proof,
        vrf_output=vrf_output,
    )


def test_prewarm_loop_does_not_publish_candidate_with_stale_vrf_on_tip_advance():
    """V4: _prewarm_loop() discards or re-proves if the tip advances before
    build_candidate_block(), so _consume_prewarm() never yields a candidate
    whose VRF proof fails verification against its prev_hash.
    """
    wallet = Wallet(*ecdsa_keygen())
    tip_v1 = _make_block(index=5, block_hash="aa" * 32)
    tip_v2 = _make_block(index=6, block_hash="bb" * 32, prev_hash="aa" * 32)

    state = {"tip": tip_v1}
    entered_build = threading.Event()
    release_build = threading.Event()

    class _Blockchain:
        def latest_block(self):
            return state["tip"]

    class _Consensus:
        def build_candidate_block(self, miner_address, vrf_proof_hex, vrf_beta_hex):
            entered_build.set()
            assert release_build.wait(timeout=5.0)
            cur = state["tip"]
            return _make_block(
                index=cur.index + 1,
                block_hash="cc" * 32,
                prev_hash=cur.block_hash,
                vrf_proof=vrf_proof_hex,
                vrf_output=vrf_beta_hex,
            )

    m = object.__new__(MiningEngine)
    m.blockchain = _Blockchain()
    m.consensus = _Consensus()
    m.wallet = wallet
    m._paused = False
    m._prewarm_lock = threading.Lock()
    m._prewarm_block = None
    m._prewarm_height = -1
    m._prewarm_stop = threading.Event()
    m._prewarm_wake = threading.Event()

    t = threading.Thread(target=m._prewarm_loop, daemon=True)
    t.start()
    try:
        assert entered_build.wait(timeout=5.0)
        state["tip"] = tip_v2
        release_build.set()

        # Give _prewarm_loop() a short window to finish the iteration
        deadline = time.monotonic() + 0.3
        consumed = None
        while time.monotonic() < deadline:
            consumed = m._consume_prewarm()
            if consumed is not None:
                break
            time.sleep(0.01)

        if consumed is not None:
            proof_bytes = bytes.fromhex(consumed.vrf_proof)
            beta_bytes = bytes.fromhex(consumed.vrf_output)
            assert vrf_verify(
                wallet.pub_hex,
                consumed.prev_hash.encode(),
                proof_bytes,
                beta_bytes,
            ) is True
    finally:
        m._prewarm_stop.set()
        m._prewarm_wake.set()
        t.join(timeout=5.0)
