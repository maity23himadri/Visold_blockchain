from __future__ import annotations

import os
import tempfile
from types import SimpleNamespace

from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.rollup.l2_state import Layer2State
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def test_protocol_difficulty_ceiling_has_nonzero_pow_target() -> None:
    """The reachable consensus ceiling must never map to an impossible target."""
    assert float(Config.MAX_DIFFICULTY) < 64.0
    max_target = DifficultyEngine.difficulty_to_target(Config.MAX_DIFFICULTY)
    assert max_target > 0
    assert DifficultyEngine.difficulty_to_target(64.0) == 0


def test_lwma_cannot_return_the_old_zero_target_ceiling() -> None:
    """Extreme fast-history input may hit the ceiling, but only at a mineable D."""

    class FakeStorage:
        def __init__(self, blocks):
            self._blocks = {int(b.index): b for b in blocks}

        def get_block(self, index):
            return self._blocks.get(int(index))

    # A sustained one-second solve time with a high parent difficulty drives
    # the LWMA upward.  The canonical clamp must now stop at D=63, never D=64.
    blocks = [
        SimpleNamespace(index=i, timestamp=i, difficulty=62.9)
        for i in range(25)
    ]
    DifficultyEngine.invalidate_cache(0)
    next_diff = DifficultyEngine.compute_next_difficulty(FakeStorage(blocks), 24)
    assert next_diff == float(Config.MAX_DIFFICULTY)
    assert next_diff == 63.0
    assert DifficultyEngine.difficulty_to_target(next_diff) > 0


def test_l2_persistence_joins_active_sqlite_block_transaction_and_commits() -> None:
    """An L2 bridge mutation must succeed inside apply_block's SQLite transaction."""
    with tempfile.TemporaryDirectory() as td:
        storage = Storage(os.path.join(td, "l2.db"))
        l2 = Layer2State(storage)
        user = Wallet.generate().address

        storage.begin_sqlite_atomic_block()
        try:
            ok, msg = l2.L2_deposit(user, 123, l1_height=7, l1_block_hash="h7")
            assert ok, msg
            storage.commit_sqlite_atomic_block()
        except BaseException:
            storage.rollback_sqlite_atomic_block()
            raise

        assert l2.get_balance_sat(user) == 123
        restarted = Layer2State(storage)
        assert restarted.get_balance_sat(user) == 123


def test_l2_persistence_inside_sqlite_block_transaction_rolls_back_with_outer_block() -> None:
    """Joining the outer transaction must preserve all-or-nothing rollback."""
    with tempfile.TemporaryDirectory() as td:
        storage = Storage(os.path.join(td, "l2.db"))
        l2 = Layer2State(storage)
        user = Wallet.generate().address

        storage.begin_sqlite_atomic_block()
        try:
            ok, msg = l2.L2_deposit(user, 456, l1_height=8, l1_block_hash="h8")
            assert ok, msg
            # The current process can observe the uncommitted mutation, but it
            # must not become durable until the block transaction commits.
            assert l2.get_balance_sat(user) == 456
        finally:
            storage.rollback_sqlite_atomic_block()

        restarted = Layer2State(storage)
        assert restarted.get_balance_sat(user) == 0
