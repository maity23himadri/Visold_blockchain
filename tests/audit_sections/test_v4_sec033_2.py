import time
import pytest
from unittest.mock import patch

from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.clock import NetworkClock, network_clock
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.storage.storage import Storage
from visold.chain.blockchain import Blockchain


class TestSection33BlockTimestampAndMTP:
    """Audit tests for Section 33: Block Timestamp Rules and Median-Time Validation."""

    def test_compute_mtp_edge_cases(self):
        assert DifficultyEngine.compute_mtp([]) == 0
        assert DifficultyEngine.compute_mtp([1000]) == 1000
        # Even length: lower median (N-1)//2
        assert DifficultyEngine.compute_mtp([1000, 2000]) == 1000
        assert DifficultyEngine.compute_mtp([2000, 1000, 3000, 4000]) == 2000
        # Odd length (11): exact median
        ts = [100, 500, 200, 900, 300, 700, 400, 800, 600, 1000, 1100]
        assert DifficultyEngine.compute_mtp(ts) == 600

    def test_validate_timestamp_boundaries(self):
        now = 1_700_000_000
        drift = Config.DIFF_MAX_FUTURE_DRIFT  # 7200
        recent = [now - 600 + i * 60 for i in range(11)]
        mtp = DifficultyEngine.compute_mtp(recent)

        # Upper bound: exactly now + drift is allowed; +1 is rejected
        ok, _ = DifficultyEngine.validate_timestamp(now + drift, recent, now)
        assert ok is True
        ok, msg = DifficultyEngine.validate_timestamp(now + drift + 1, recent, now)
        assert ok is False
        assert "exceeds maximum allowed" in msg

        # Lower bound (>=2 blocks): strictly greater than MTP required
        ok, msg = DifficultyEngine.validate_timestamp(mtp, recent, now)
        assert ok is False
        assert "strictly greater than" in msg
        ok, _ = DifficultyEngine.validate_timestamp(mtp + 1, recent, now)
        assert ok is True

        # Single parent (len == 1): equal is allowed, regression is rejected
        ok, _ = DifficultyEngine.validate_timestamp(now - 10, [now - 10], now)
        assert ok is True
        ok, msg = DifficultyEngine.validate_timestamp(now - 11, [now - 10], now)
        assert ok is False
        assert "regresses" in msg

        # Non-finite values rejected
        ok, _ = DifficultyEngine.validate_timestamp(float("nan"), recent, now)
        assert ok is False
        ok, _ = DifficultyEngine.validate_timestamp(float("inf"), recent, now)
        assert ok is False

    def test_network_clock_bounds_future_ratchet(self):
        """
        V4 regression: NetworkClock.network_time() bounds forward adjustment
        relative to local_ts so repeated max-drift blocks cannot ratchet
        network_time() arbitrarily far into the future.
        """
        clk = NetworkClock()
        base_now = 1_700_000_000
        drift = Config.DIFF_MAX_FUTURE_DRIFT  # 7200

        with patch("visold.kernel.clock.time.time", return_value=float(base_now)):
            clk.record_block_timestamp(base_now)
            assert clk.network_time() == base_now

            for _ in range(5):
                cur_net = clk.network_time()
                future_ts = cur_net + drift
                ok, _ = DifficultyEngine.validate_timestamp(future_ts, [base_now, base_now], cur_net)
                assert ok is True
                clk.record_block_timestamp(future_ts)
                clk.record_block_timestamp(future_ts)

            bounded_time = clk.network_time()
            assert bounded_time <= base_now + drift

            far_future_ts = base_now + 4 * drift
            ok_online, _ = DifficultyEngine.validate_timestamp(far_future_ts, [base_now, base_now], bounded_time)
            ok_fresh, _ = DifficultyEngine.validate_timestamp(far_future_ts, [base_now, base_now], base_now)
            assert ok_online is False
            assert ok_fresh is False

    def test_validate_timestamp_rejects_float_and_bool(self):
        """
        V4 regression: DifficultyEngine.validate_timestamp() rejects non-integer
        float and bool timestamps cleanly.
        """
        now = 1_700_000_000
        recent = [now - 120, now - 60]
        mtp = DifficultyEngine.compute_mtp(recent)

        frac_ts = mtp + 0.5
        ok_float, _ = DifficultyEngine.validate_timestamp(frac_ts, recent, now)
        assert ok_float is False

        ok_bool, _ = DifficultyEngine.validate_timestamp(True, [0, 0], now)
        assert ok_bool is False

    def test_block_from_dict_preserves_zero_timestamp(self):
        """
        V4 regression: Block.__init__ and Block.from_dict() preserve timestamp == 0
        so block_hash integrity_check() succeeds.
        """
        blk = Block(
            index=0,
            prev_hash="0" * 64,
            transactions=[],
            miner_address="VSD_genesis",
            difficulty=1.0,
            timestamp=1_700_000_000,
        )
        d = blk.to_dict()
        d["timestamp"] = 0
        object.__setattr__(blk, "timestamp", 0)
        d["block_hash"] = blk.compute_hash()

        loaded = Block.from_dict(d)
        assert loaded.timestamp == 0
        ok, msg = loaded.integrity_check()
        assert ok is True, msg
