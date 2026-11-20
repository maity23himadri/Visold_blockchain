"""Audit tests for Section 32: Difficulty Adjustment Algorithm and Retarget Boundaries."""

from __future__ import annotations

import math
import os
import tempfile
import threading
import time
import unittest

from visold.chain.blockchain import Blockchain
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


class _DictStorage:
    """Minimal in-memory storage double for deterministic DAA boundary tests."""

    def __init__(self, rows):
        # rows: list of (timestamp, difficulty) indexed by height 0..N
        self._rows = list(rows)

    def get_block_consensus_window(self, start_idx: int, end_idx: int):
        s = max(0, int(start_idx))
        e = min(int(end_idx), len(self._rows) - 1)
        if e < s:
            return []
        return list(self._rows[s : e + 1])


class TestSection32DifficultyAdjustment(unittest.TestCase):
    def setUp(self):
        DifficultyEngine.invalidate_cache(from_height=0)

    def tearDown(self):
        DifficultyEngine.invalidate_cache(from_height=0)

    def test_bootstrap_and_early_exits(self):
        st = _DictStorage([(1000, Config.INITIAL_DIFFICULTY)] * 5)
        self.assertEqual(
            DifficultyEngine._compute_uncached(st, -1),
            float(Config.INITIAL_DIFFICULTY),
        )
        for h in range(Config.DIFF_BOOTSTRAP_BLOCKS):
            self.assertEqual(
                DifficultyEngine._compute_uncached(st, h),
                float(Config.INITIAL_DIFFICULTY),
            )
        # Missing parent row falls back to INITIAL_DIFFICULTY
        self.assertEqual(
            DifficultyEngine._compute_uncached(st, 999),
            float(Config.INITIAL_DIFFICULTY),
        )

    def test_lwma_fixed_point_at_target_block_time(self):
        d0 = float(Config.INITIAL_DIFFICULTY)
        t0 = 1_700_000_000
        rows = [(t0 + i * Config.TARGET_BLOCK_TIME, d0) for i in range(25)]
        st = _DictStorage(rows)
        next_d = DifficultyEngine._compute_uncached(st, 24)
        self.assertAlmostEqual(next_d, d0, places=9)

    def test_lwma_step_clamp_and_swing_cap(self):
        d0 = 5.15
        t0 = 1_700_000_000
        max_delta = math.log2(Config.DIFF_LWMA_MAX_SWING) / 4.0

        # Extremely fast blocks (0s / negative timestamps clamped to MIN_TS_STEP=1s)
        fast_rows = [(t0, d0)] + [(t0, d0) for _ in range(1, 22)]
        fast_d = DifficultyEngine._compute_uncached(_DictStorage(fast_rows), 21)
        self.assertAlmostEqual(fast_d, d0 + max_delta, places=9)

        # Extremely slow blocks (10000s intervals clamped to MAX_TS_STEP=360s)
        slow_rows = [(t0 + i * 10_000, d0) for i in range(22)]
        slow_d = DifficultyEngine._compute_uncached(_DictStorage(slow_rows), 21)
        self.assertAlmostEqual(slow_d, d0 - max_delta, places=9)

    def test_hard_floor_and_ceiling(self):
        t0 = 1_700_000_000
        # At MIN_DIFFICULTY with slow blocks -> clamped at MIN_DIFFICULTY
        min_rows = [
            (t0 + i * Config.DIFF_LWMA_MAX_TS_STEP, float(Config.MIN_DIFFICULTY))
            for i in range(22)
        ]
        self.assertEqual(
            DifficultyEngine._compute_uncached(_DictStorage(min_rows), 21),
            float(Config.MIN_DIFFICULTY),
        )

        # At MAX_DIFFICULTY with fast blocks -> clamped at MAX_DIFFICULTY
        max_rows = [
            (t0 + i * Config.DIFF_LWMA_MIN_TS_STEP, float(Config.MAX_DIFFICULTY))
            for i in range(22)
        ]
        self.assertEqual(
            DifficultyEngine._compute_uncached(_DictStorage(max_rows), 21),
            float(Config.MAX_DIFFICULTY),
        )

    def test_required_network_hashrate_inverse_and_bounds(self):
        d = 5.15
        expected_hps = math.pow(2.0, 4.0 * d) / float(Config.TARGET_BLOCK_TIME)
        self.assertAlmostEqual(
            DifficultyEngine.required_network_hashrate(d),
            expected_hps,
            places=6,
        )
        # Clamped to MIN_DIFFICULTY and MAX_DIFFICULTY
        self.assertEqual(
            DifficultyEngine.required_network_hashrate(0.1),
            DifficultyEngine.required_network_hashrate(Config.MIN_DIFFICULTY),
        )
        self.assertEqual(
            DifficultyEngine.required_network_hashrate(100.0),
            DifficultyEngine.required_network_hashrate(Config.MAX_DIFFICULTY),
        )
        # Non-positive target_block_time falls back to 60.0
        self.assertEqual(
            DifficultyEngine.required_network_hashrate(d, target_block_time=0.0),
            DifficultyEngine.required_network_hashrate(d, target_block_time=60.0),
        )

    def test_cache_isolation_between_storages(self):
        t0 = 1_700_000_000
        s1 = _DictStorage([(t0 + i * 1, 5.15) for i in range(5)])
        s2 = _DictStorage([(t0 + i * 360, 5.15) for i in range(5)])
        d1 = DifficultyEngine.compute_next_difficulty(s1, 4)
        d2 = DifficultyEngine.compute_next_difficulty(s2, 4)
        self.assertGreater(d1, d2)

    def test_get_difficulty_holds_lock_and_prevents_cache_poisoning_during_rollback(self):
        """V4 regression: Blockchain.get_difficulty() holds self._lock, serializing
        with rollback()/reorg() so a concurrent reader cannot write stale pre-rollback
        difficulty into DifficultyEngine._cache after invalidate_cache() runs.
        """
        orig_min = Config.MIN_DIFFICULTY
        orig_init = Config.INITIAL_DIFFICULTY
        try:
            Config.MIN_DIFFICULTY = 1.0
            Config.INITIAL_DIFFICULTY = 1.0

            with tempfile.TemporaryDirectory() as tmpdir:
                db_path = os.path.join(tmpdir, "chain.db")
                storage = Storage(db_path)
                bc = Blockchain(storage)
                miner_a = Wallet.generate().address
                miner_b = Wallet.generate().address

                # Build canonical chain A to height 4 with fast 1s intervals
                base_ts = int(time.time()) - 1000
                for h in range(1, 5):
                    prev = bc.latest_block()
                    diff = bc.get_difficulty()
                    cb = Transaction.coinbase(miner_a, bc.compute_reward(h), h)
                    ts = base_ts + h * 1
                    sr = bc.dry_run_state_root([cb], miner_a, h, timestamp=ts, difficulty=diff)
                    blk = Block(
                        index=h,
                        prev_hash=prev.block_hash,
                        timestamp=ts,
                        transactions=[cb],
                        miner_address=miner_a,
                        difficulty=diff,
                        state_root=sr,
                    )
                    blk.mine()
                    ok, msg = bc.apply_block(blk)
                    self.assertTrue(ok, msg)

                # Clear cache at height 4 so a concurrent get_difficulty() must recompute
                DifficultyEngine.invalidate_cache(from_height=0)

                entered_compute = threading.Event()
                allow_finish = threading.Event()
                orig_get_window = storage.get_block_consensus_window

                def hooked_get_window(start_idx: int, end_idx: int):
                    rows = orig_get_window(start_idx, end_idx)
                    if (
                        threading.current_thread().name == "locked_reader"
                        and start_idx == 0
                        and end_idx == 4
                    ):
                        entered_compute.set()
                        allow_finish.wait(timeout=10.0)
                    return rows

                storage.get_block_consensus_window = hooked_get_window  # type: ignore[method-assign]

                reader_result = {}

                def run_locked_reader():
                    reader_result["diff"] = bc.get_difficulty()

                t = threading.Thread(
                    target=run_locked_reader,
                    name="locked_reader",
                    daemon=True,
                )
                t.start()
                self.assertTrue(entered_compute.wait(timeout=5.0))

                # Because get_difficulty() holds self._lock, a concurrent rollback(2)
                # waits for get_difficulty() to finish rather than interleaving
                # invalidate_cache() before the reader writes to _cache.
                rb_result = {}

                def run_rollback():
                    rb_result["res"] = bc.rollback(2)

                t_rb = threading.Thread(target=run_rollback, name="rollback_thread", daemon=True)
                t_rb.start()
                time.sleep(0.05)
                self.assertTrue(t_rb.is_alive())

                allow_finish.set()
                t.join(timeout=5.0)
                t_rb.join(timeout=5.0)
                ok_rb, msg_rb = rb_result["res"]
                self.assertTrue(ok_rb, msg_rb)

                storage.get_block_consensus_window = orig_get_window  # type: ignore[method-assign]

                # Build branch B up to height 4 with slow 360s intervals.
                for h in range(3, 5):
                    prev = bc.latest_block()
                    diff = bc.get_difficulty()
                    cb = Transaction.coinbase(miner_b, bc.compute_reward(h), h)
                    ts = prev.timestamp + 360
                    sr = bc.dry_run_state_root([cb], miner_b, h, timestamp=ts, difficulty=diff)
                    blk = Block(
                        index=h,
                        prev_hash=prev.block_hash,
                        timestamp=ts,
                        transactions=[cb],
                        miner_address=miner_b,
                        difficulty=diff,
                        state_root=sr,
                    )
                    blk.mine()
                    ok, msg = bc.apply_block(blk)
                    self.assertTrue(ok, msg)

                true_diff_h5 = DifficultyEngine._compute_uncached(storage, 4)
                stale_diff_h5 = reader_result["diff"]
                self.assertNotAlmostEqual(stale_diff_h5, true_diff_h5, places=4)

                # Cache is NOT poisoned: bc.get_difficulty() returns true branch B difficulty
                self.assertAlmostEqual(bc.get_difficulty(), true_diff_h5, places=9)

                # A legitimately mined block 5 using true_diff_h5 passes validate_block()
                prev = bc.latest_block()
                cb5 = Transaction.coinbase(miner_b, bc.compute_reward(5), 5)
                ts5 = prev.timestamp + 60
                sr5 = bc.dry_run_state_root([cb5], miner_b, 5, timestamp=ts5, difficulty=true_diff_h5)
                valid_b5 = Block(
                    index=5,
                    prev_hash=prev.block_hash,
                    timestamp=ts5,
                    transactions=[cb5],
                    miner_address=miner_b,
                    difficulty=true_diff_h5,
                    state_root=sr5,
                )
                valid_b5.mine()
                ok_val, msg_val = bc.validate_block(valid_b5)
                self.assertTrue(ok_val, msg_val)
        finally:
            Config.MIN_DIFFICULTY = orig_min
            Config.INITIAL_DIFFICULTY = orig_init


if __name__ == "__main__":
    unittest.main()
