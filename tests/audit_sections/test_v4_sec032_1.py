"""Section 32 Audit Tests: Difficulty Adjustment Algorithm and Retarget Boundaries."""

from __future__ import annotations

import math
import os

from visold.chain.blockchain import Blockchain
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.storage.storage import Storage


class _HeaderWindowStorage:
    def __init__(self, rows):
        # rows: list of (timestamp, difficulty) indexed by height
        self._rows = list(rows)

    def get_block_consensus_window(self, start_idx: int, end_idx: int):
        s = max(0, int(start_idx))
        e = min(int(end_idx), len(self._rows) - 1)
        if e < s:
            return []
        return list(self._rows[s : e + 1])


def test_bootstrap_boundary_and_first_daa_height():
    DifficultyEngine.invalidate_cache(from_height=0)
    base_ts = 1_700_000_000
    rows = [
        (base_ts, Config.INITIAL_DIFFICULTY),
        (base_ts + 60, Config.INITIAL_DIFFICULTY),
        (base_ts + 120, Config.INITIAL_DIFFICULTY),
        (base_ts + 180, Config.INITIAL_DIFFICULTY),
    ]
    st = _HeaderWindowStorage(rows)

    # Heights < DIFF_BOOTSTRAP_BLOCKS (3) must return INITIAL_DIFFICULTY
    assert DifficultyEngine.compute_next_difficulty(st, -1) == float(Config.INITIAL_DIFFICULTY)
    assert DifficultyEngine.compute_next_difficulty(st, 0) == float(Config.INITIAL_DIFFICULTY)
    assert DifficultyEngine.compute_next_difficulty(st, 1) == float(Config.INITIAL_DIFFICULTY)
    assert DifficultyEngine.compute_next_difficulty(st, 2) == float(Config.INITIAL_DIFFICULTY)

    # At height == 3 (DIFF_BOOTSTRAP_BLOCKS), DAA runs; steady 60s intervals keep INITIAL_DIFFICULTY
    d3 = DifficultyEngine.compute_next_difficulty(st, 3)
    assert abs(d3 - float(Config.INITIAL_DIFFICULTY)) < 1e-12


def test_lwma_steady_state_and_timestamp_step_clamping():
    DifficultyEngine.invalidate_cache(from_height=0)
    base_ts = 1_700_000_000
    n = int(Config.DIFF_LWMA_WINDOW)
    d = 6.5

    # Exact target block time across full window -> exact fixed point
    rows = [(base_ts + i * int(Config.TARGET_BLOCK_TIME), d) for i in range(n + 1)]
    st = _HeaderWindowStorage(rows)
    next_d = DifficultyEngine.compute_next_difficulty(st, n)
    assert abs(next_d - d) < 1e-12

    # Extreme negative/zero timestamp regression and huge positive jump are clamped
    # to [DIFF_LWMA_MIN_TS_STEP, DIFF_LWMA_MAX_TS_STEP]
    rows_fast = [(base_ts, d)] + [(base_ts - 1000, d) for _ in range(1, n + 1)]
    rows_min_clamped = [(base_ts + i * int(Config.DIFF_LWMA_MIN_TS_STEP), d) for i in range(n + 1)]
    assert abs(
        DifficultyEngine._compute_uncached(_HeaderWindowStorage(rows_fast), n)
        - DifficultyEngine._compute_uncached(_HeaderWindowStorage(rows_min_clamped), n)
    ) < 1e-12

    rows_slow = [(base_ts + i * 100_000, d) for i in range(n + 1)]
    rows_max_clamped = [(base_ts + i * int(Config.DIFF_LWMA_MAX_TS_STEP), d) for i in range(n + 1)]
    assert abs(
        DifficultyEngine._compute_uncached(_HeaderWindowStorage(rows_slow), n)
        - DifficultyEngine._compute_uncached(_HeaderWindowStorage(rows_max_clamped), n)
    ) < 1e-12


def test_swing_cap_and_global_min_max_boundaries():
    DifficultyEngine.invalidate_cache(from_height=0)
    max_delta = math.log2(float(Config.DIFF_LWMA_MAX_SWING)) / 4.0

    # Direct _apply_swing_cap symmetry
    parent = 10.0
    assert abs(DifficultyEngine._apply_swing_cap(50.0, parent) - (parent + max_delta)) < 1e-12
    assert abs(DifficultyEngine._apply_swing_cap(0.0, parent) - (parent - max_delta)) < 1e-12
    assert DifficultyEngine._apply_swing_cap(10.05, parent) == 10.05

    # Floor at MIN_DIFFICULTY
    n = int(Config.DIFF_LWMA_WINDOW)
    base_ts = 1_700_000_000
    rows_floor = [(base_ts + i * 360, float(Config.MIN_DIFFICULTY)) for i in range(n + 1)]
    d_floor = DifficultyEngine._compute_uncached(_HeaderWindowStorage(rows_floor), n)
    assert d_floor == float(Config.MIN_DIFFICULTY)

    # Ceiling at MAX_DIFFICULTY
    rows_ceil = [(base_ts + i * 1, float(Config.MAX_DIFFICULTY)) for i in range(n + 1)]
    d_ceil = DifficultyEngine._compute_uncached(_HeaderWindowStorage(rows_ceil), n)
    assert d_ceil == float(Config.MAX_DIFFICULTY)


def test_required_network_hashrate_inverse_and_bounds():
    d = 5.5
    expected_hps = math.pow(2.0, 4.0 * d) / float(Config.TARGET_BLOCK_TIME)
    assert abs(DifficultyEngine.required_network_hashrate(d) - expected_hps) < 1e-9

    # Clamped below MIN_DIFFICULTY and above MAX_DIFFICULTY
    min_hps = math.pow(2.0, 4.0 * float(Config.MIN_DIFFICULTY)) / float(Config.TARGET_BLOCK_TIME)
    max_hps = math.pow(2.0, 4.0 * float(Config.MAX_DIFFICULTY)) / float(Config.TARGET_BLOCK_TIME)
    assert abs(DifficultyEngine.required_network_hashrate(0.0) - min_hps) < 1e-9
    assert abs(DifficultyEngine.required_network_hashrate(100.0) - max_hps) / max_hps < 1e-12


def test_blockchain_get_difficulty_and_migration_idempotency(tmp_path):
    DifficultyEngine.invalidate_cache(from_height=0)
    db_path = os.path.join(str(tmp_path), "chain.db")
    st = Storage(db_path)
    bc = Blockchain(st)

    # Fresh chain sets hybrid_diff_v1 and delegates get_difficulty()
    assert st.get_meta("hybrid_diff_v1") == "1"
    assert bc.get_difficulty() == float(Config.INITIAL_DIFFICULTY)

    # Simulate legacy DB with asert_anchor and missing hybrid_diff_v1
    st.set_meta("hybrid_diff_v1", "")
    st.set_meta("asert_anchor", "100:5.15")
    bc._maybe_migrate_difficulty_state()
    assert st.get_meta("hybrid_diff_v1") == "1"
    assert bc.get_difficulty() == float(Config.INITIAL_DIFFICULTY)
