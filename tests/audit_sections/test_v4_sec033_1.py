import os
import tempfile
import time
from unittest.mock import patch

import pytest

from visold.chain.blockchain import Blockchain
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.clock import NetworkClock
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_coinbase_block(index: int, prev_hash: str, difficulty: float,
                         timestamp, miner: str = "VSD_MINER_1") -> Block:
    cb = Transaction.coinbase(miner, 0.0, index)
    blk = Block(
        index=index,
        prev_hash=prev_hash,
        transactions=[cb],
        miner_address=miner,
        difficulty=difficulty,
        timestamp=timestamp,
        nonce=0,
    )
    blk.mine()
    return blk


# ── Clean baseline tests for Section 33 ──────────────────────────────────────

def test_compute_mtp_odd_even_empty():
    assert DifficultyEngine.compute_mtp([]) == 0
    assert DifficultyEngine.compute_mtp([100]) == 100
    # Even length: lower median (index (N-1)//2)
    assert DifficultyEngine.compute_mtp([200, 100]) == 100
    assert DifficultyEngine.compute_mtp([400, 100, 300, 200]) == 200
    # Odd length: exact median
    assert DifficultyEngine.compute_mtp([50, 10, 40, 20, 30]) == 30


def test_validate_timestamp_bounds_and_nonfinite():
    now = 1_700_000_000
    recent = [now - 600 + i * 60 for i in range(11)]  # MTP = now - 300
    mtp = DifficultyEngine.compute_mtp(recent)
    assert mtp == now - 300

    # Strictly greater than MTP and <= now + DIFF_MAX_FUTURE_DRIFT
    ok, _ = DifficultyEngine.validate_timestamp(mtp + 1, recent, now)
    assert ok is True
    ok, _ = DifficultyEngine.validate_timestamp(now + Config.DIFF_MAX_FUTURE_DRIFT, recent, now)
    assert ok is True

    # Equal to or less than MTP must fail
    ok, _ = DifficultyEngine.validate_timestamp(mtp, recent, now)
    assert ok is False
    ok, _ = DifficultyEngine.validate_timestamp(mtp - 1, recent, now)
    assert ok is False

    # Beyond future drift must fail
    ok, _ = DifficultyEngine.validate_timestamp(now + Config.DIFF_MAX_FUTURE_DRIFT + 1, recent, now)
    assert ok is False

    # Single parent allows equal, rejects regression
    ok, _ = DifficultyEngine.validate_timestamp(now, [now], now)
    assert ok is True
    ok, _ = DifficultyEngine.validate_timestamp(now - 1, [now], now)
    assert ok is False

    # Non-finite values must fail cleanly
    for bad in (float("nan"), float("inf"), float("-inf")):
        ok, _ = DifficultyEngine.validate_timestamp(bad, recent, now)
        assert ok is False


def test_storage_get_block_timestamps_and_consensus_window():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        st = Storage(db_path=db_path)
        try:
            prev_h = "0" * 64
            base_ts = 1_700_000_000
            for i in range(5):
                blk = _make_coinbase_block(i, prev_h, 0.001, base_ts + i * 60)
                st.save_block(blk)
                prev_h = blk.block_hash

            assert st.get_block_timestamps(0, 4) == [base_ts + i * 60 for i in range(5)]
            assert st.get_block_timestamps(2, 3) == [base_ts + 120, base_ts + 180]
            assert st.get_block_timestamps(4, 2) == []
            assert st.get_block_consensus_window(1, 3) == [
                (base_ts + 60, 0.001),
                (base_ts + 120, 0.001),
                (base_ts + 180, 0.001),
            ]
        finally:
            st.close()


# ── V4 Regression 1: Bounded Future Clock in NetworkClock ────────────────────

def test_network_clock_caps_future_ratchet():
    """
    V4 regression: NetworkClock.network_time() bounds forward adjustment
    relative to local wall clock so repeated max-drift blocks cannot ratchet
    network_time() unboundedly into the future.
    """
    clk = NetworkClock()
    t0 = 1_700_000_000
    drift_limit = Config.DIFF_MAX_FUTURE_DRIFT  # 7200s

    with patch("visold.kernel.clock.time.time", return_value=float(t0)):
        clk.record_block_timestamp(t0)
        assert clk.network_time() == t0

        for _ in range(5):
            cur_net = clk.network_time()
            max_allowed_ts = cur_net + drift_limit
            ok1, _ = DifficultyEngine.validate_timestamp(max_allowed_ts, [t0], cur_net)
            assert ok1 is True
            clk.record_block_timestamp(max_allowed_ts)
            clk.record_block_timestamp(max_allowed_ts)

        bounded_net_time = clk.network_time()
        assert bounded_net_time <= t0 + drift_limit

        far_future_ts = t0 + 5 * drift_limit + 100
        ok_online, _ = DifficultyEngine.validate_timestamp(far_future_ts, [t0], bounded_net_time)
        assert ok_online is False

        fresh_clk = NetworkClock()
        ok_fresh, _ = DifficultyEngine.validate_timestamp(far_future_ts, [t0], fresh_clk.network_time())
        assert ok_fresh is False


# ── V4 Regression 2: String / Float / Zero Timestamp Handling ────────────────

def test_validate_timestamp_rejects_numeric_string():
    """
    V4 regression: DifficultyEngine.validate_timestamp() rejects numeric strings
    cleanly with (False, reason) instead of raising TypeError.
    """
    now = 1_700_000_000
    ok, msg = DifficultyEngine.validate_timestamp(str(now), [now - 60], now)
    assert ok is False
    assert msg


def test_blockchain_validate_block_rejects_string_timestamp():
    """
    V4 regression: A Block with a numeric-string timestamp fails integrity_check()
    and Blockchain.validate_block() cleanly with (False, reason) without TypeError.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        st = Storage(os.path.join(tmpdir, "bc.db"))
        bc = Blockchain(st)
        try:
            genesis = bc.latest_block()
            miner = Wallet.generate()
            now_str = str(int(time.time()))
            cb = Transaction.coinbase(miner.address, 0.0, 1)
            bad_dict = Block(
                index=1,
                prev_hash=genesis.block_hash,
                transactions=[cb],
                miner_address=miner.address,
                difficulty=bc.get_difficulty(),
                timestamp=now_str,
                nonce=0,
            ).to_dict()
            blk = Block.from_dict(bad_dict)
            assert blk.integrity_check()[0] is False
            ok, msg = bc.validate_block(blk)
            assert ok is False
            assert msg
        finally:
            st.close()


def test_validate_timestamp_rejects_float_timestamp():
    """
    V4 regression: DifficultyEngine.validate_timestamp() rejects fractional float
    timestamps so storage int truncation cannot bypass strict MTP.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "float_ts.db")
        st = Storage(db_path=db_path)
        try:
            prev_h = "0" * 64
            for i in range(11):
                blk = _make_coinbase_block(i, prev_h, 0.001, 1700000000)
                st.save_block(blk)
                prev_h = blk.block_hash

            recent_ts = st.get_block_timestamps(0, 10)
            ok, msg = DifficultyEngine.validate_timestamp(1700000000.5, recent_ts, 1700000010)
            assert ok is False
            assert msg
        finally:
            st.close()


def test_block_zero_timestamp_preserved():
    """
    V4 regression: Block.__init__ preserves explicit timestamp=0 instead of
    silently replacing it with int(time.time()).
    """
    blk = Block(
        index=0,
        prev_hash="0" * 64,
        transactions=[],
        miner_address="VSD_GENESIS",
        difficulty=5.0,
        timestamp=0,
    )
    assert blk.timestamp == 0
