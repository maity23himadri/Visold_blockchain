"""Regression tests for audit findings VSA-04, VSA-05 and VSA-24."""

from __future__ import annotations

import os
import tempfile
import time

from visold.chain.blockchain import Blockchain
from visold.kernel.config import BLOCK_ALREADY_APPLIED_MSG, Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.resilience import hardened_core as hc
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _chain(td: str):
    st = Storage(os.path.join(td, "vsa_b1.db"))
    return st, Blockchain(st)


def _coinbase_block(bc, miner):
    height = bc.height() + 1
    cb = Transaction.coinbase(
        miner.address, bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD, height)
    prev = bc.latest_block()
    root = bc.dry_run_state_root([cb], miner.address, height)
    block = Block(
        index=height,
        prev_hash=prev.block_hash,
        transactions=[cb],
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        state_root=root,
    )
    assert block.mine(), "regression block failed to mine"
    return block


def _isolate_breaker(monkeypatch, td: str):
    """Give the process-wide breaker a clean NORMAL state for one test.

    HOME is redirected because breaker transitions write flag files under ~/.visold.
    monkeypatch restores every attribute afterwards.
    """
    monkeypatch.setenv("HOME", td)
    cb = hc._hc_panic_cb
    monkeypatch.setattr(cb, "_mode", hc._HardenedSystemMode.NORMAL)
    monkeypatch.setattr(cb, "_subsystems", {})
    monkeypatch.setattr(cb, "_corruption_timestamps", [])
    monkeypatch.setattr(cb, "_corruption_count", 0)
    monkeypatch.setattr(cb, "_read_only_since", 0.0, raising=False)
    return cb


def _assert_writes_blocked(cb, label: str) -> None:
    try:
        cb.assert_writable(label)
    except hc.ImmediateAbort:
        return
    raise AssertionError(f"assert_writable must reject writes ({label})")


# ── VSA-24: durable marker committed with the block ─────────────────────────

def test_block_apply_marker_is_written_inside_the_block_transaction():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        block = _coinbase_block(bc, Wallet.generate())
        ok, msg = bc.apply_block(block)
        assert ok, msg
        assert st.get_meta(f"block_apply:{block.index}") == "ok", (
            "apply_block must commit the block_apply marker with the block (VSA-24)")


def test_failed_marker_write_rolls_the_block_back(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        block = _coinbase_block(bc, Wallet.generate())

        def failing_marker(height, success):
            raise OSError("injected marker write failure")

        monkeypatch.setattr(st, "record_block_apply_result", failing_marker)
        try:
            ok, _msg = bc.apply_block(block)
        except OSError:
            ok = False
        assert not ok, "block was applied although its durable marker could not be written"
        assert bc.height() == block.index - 1
        assert st.get_block(block.index) is None, "block row must be rolled back with the marker"
        assert st.get_meta(f"block_apply:{block.index}") is None
        assert block.block_hash not in bc._applied_block_hashes


# ── VSA-04: duplicate delivery ──────────────────────────────────────────────

def test_duplicate_delivery_is_not_reported_as_state_root_mismatch(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        cb = _isolate_breaker(monkeypatch, td)
        miner = Wallet.generate()
        first = _coinbase_block(bc, miner)
        ok, msg = bc.apply_block(first)
        assert ok, msg
        second = _coinbase_block(bc, miner)
        ok, msg = bc.apply_block(second)
        assert ok, msg
        assert st.compute_state_root() != first.state_root, (
            "the test needs the current root to differ from the historical root")

        wrapped = hc._make_hardened_apply_block(Blockchain.apply_block)
        ok, msg = wrapped(bc, first)
        assert ok and msg == BLOCK_ALREADY_APPLIED_MSG, (ok, msg)
        assert cb.mode == hc._HardenedSystemMode.NORMAL, (
            "a duplicate delivery tripped the breaker (VSA-04)")


def test_engine_never_overwrites_an_ok_marker_with_fail_for_the_stored_block():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        block = _coinbase_block(bc, Wallet.generate())
        ok, msg = bc.apply_block(block)
        assert ok, msg
        assert st.get_meta(f"block_apply:{block.index}") == "ok"

        engine = object.__new__(StateEngine)
        engine._storage = st
        engine._record_apply_outcome(block, False)   # late duplicate reports failure
        assert st.get_meta(f"block_apply:{block.index}") == "ok", (
            "a failed outcome overwrote the ok marker of the stored block (VSA-04)")

        engine._record_apply_outcome(block, True)
        assert st.get_meta(f"block_apply:{block.index}") == "ok"


# ── VSA-05: breaker classification and recovery ─────────────────────────────

def test_future_dated_peer_blocks_never_trip_the_breaker(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        cb = _isolate_breaker(monkeypatch, td)
        wrapped = hc._make_hardened_apply_block(Blockchain.apply_block)
        future = int(time.time()) + 3 * 86_400
        for _ in range(hc._HC_CB_FAILURE_THRESHOLD + 2):
            peer_block = Block(
                index=1,
                prev_hash="0" * 64,
                transactions=[],
                miner_address=Wallet.generate().address,
                difficulty=bc.get_difficulty(),
                timestamp=future,
            )
            ok, msg = wrapped(bc, peer_block)
            assert not ok
            assert "pre-condition" in msg.lower(), (
                f"peer rejection must stay an ordinary pre-check outcome, got: {msg}")
        assert cb.mode == hc._HardenedSystemMode.NORMAL, (
            "peer-supplied future-dated blocks tripped the breaker (VSA-05)")


def test_breaker_auto_recovers_after_trip_delay_without_a_successful_apply(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        cb = _isolate_breaker(monkeypatch, td)
        for _ in range(hc._HC_CB_FAILURE_THRESHOLD):
            cb.record_failure("apply_block_exec", RuntimeError("transient"), corruption_level=False)
        assert cb.mode == hc._HardenedSystemMode.READ_ONLY
        _assert_writes_blocked(cb, "before the delay")

        cb._read_only_since = time.monotonic() - (hc._HC_CB_HALF_OPEN_DELAY_SEC + 1.0)
        cb.assert_writable("after the delay")   # must not raise: half-open without an apply
        assert cb.mode == hc._HardenedSystemMode.NORMAL, (
            "READ_ONLY never recovered without a successful apply (VSA-05)")

        cb.record_failure("apply_block_exec", RuntimeError("again"), corruption_level=False)
        assert cb.mode == hc._HardenedSystemMode.READ_ONLY, (
            "a failure after half-open must re-trip immediately")


def test_corruption_inside_the_window_still_blocks_recovery(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        cb = _isolate_breaker(monkeypatch, td)
        cb.record_failure("state_root_verify", RuntimeError("divergence"), corruption_level=True)
        assert cb.mode == hc._HardenedSystemMode.READ_ONLY
        cb._read_only_since = time.monotonic() - 10_000.0
        _assert_writes_blocked(cb, "corruption inside the window")
        assert cb.mode == hc._HardenedSystemMode.READ_ONLY, (
            "half-open recovery must not clear a corruption event inside the window")
