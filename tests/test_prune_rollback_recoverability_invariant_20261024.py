from __future__ import annotations

import os
import tempfile

import pytest

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


@pytest.fixture
def cfg(monkeypatch):
    DifficultyEngine.invalidate_cache()
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 4)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 5)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 4)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 100)
    monkeypatch.setattr(Config, "SNAPSHOT_KEEP", 3)
    yield
    DifficultyEngine.invalidate_cache()


def _mine_to(bc, miner, height):
    bc._rolling_pruner.prune_async = lambda _h: None
    ce = ConsensusEngine(bc, miner)
    while bc.height() < height:
        b = ce.build_candidate_block(miner.address)
        assert b.mine()
        ok, msg = bc.apply_block(b)
        assert ok, msg


def test_pruning_aligns_to_committed_snapshot_not_arbitrary_window_cutoff(cfg):
    # Analogue of tip=1490, window=600, previous committed snapshot=600,
    # raw cutoff=890: with scale 1:150 this is tip=11, window=4,
    # snapshot interval=4, raw cutoff=7, previous snapshot=4.
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "chain.db"))
        bc = Blockchain(st)
        miner = Wallet.generate()
        _mine_to(bc, miner, 11)
        bc._rolling_pruner._last_height = -1
        for _ in range(4):
            bc._rolling_pruner.maybe_prune(11)

        # Raw cutoff would be 7. Safe exclusive boundary is snapshot 4 + 1 = 5.
        assert int(st.get_meta("rolling_pruned_until") or 0) == 5
        assert bc.get_block(4).is_pruned is True
        assert bc.get_block(5).is_pruned is False
        assert bc.get_block(6).is_pruned is False
        assert bc.get_block(7).is_pruned is False

        # Any rollback target >=5 retains the h=5 commitment block and the
        # full-body suffix 5..target, so snapshot h=4 remains a valid recovery
        # anchor. The dedicated rollback tests exercise mutation itself.
        assert any(int(e["height"]) == 4 for e in bc._snapshot_engine.get_servable_manifest())


def test_legacy_unsafe_prune_shape_rejects_stranding_rollback_before_mutation(cfg):
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "chain.db"))
        bc = Blockchain(st)
        miner = Wallet.generate()
        _mine_to(bc, miner, 11)

        # Simulate a pre-fix arbitrary watermark analogous to 890 while the
        # newest snapshot that would survive rollback target 6 is h=4.
        st.set_meta("rolling_pruned_until", "7")
        before = bc.height()
        ok, msg = bc.rollback(8)
        assert not ok
        assert "unrecoverable pruned suffix" in msg
        assert bc.height() == before


def test_snapshot_servable_helpers_exclude_uncommitted_and_future_cache(cfg):
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "chain.db"))
        bc = Blockchain(st)
        miner = Wallet.generate()
        _mine_to(bc, miner, 8)
        # Materialise the boundary snapshot exactly as candidate construction
        # for block 9 would, but do not add block 9 (the commitment block).
        b8 = bc.get_block(8)
        digest, msg = bc._snapshot_engine.ensure_bootstrap_snapshot(8, b8.state_root)
        assert digest, msg

        # Snapshot 8 exists at the exact boundary but cannot be served until 9
        # commits it. Snapshot 4 is committed by 5 and remains servable.
        cached = {int(e["height"]) for e in bc._snapshot_engine.get_manifest()}
        assert 8 in cached and 4 in cached
        assert not bc._snapshot_engine.is_snapshot_servable(8)
        assert bc._snapshot_engine.is_snapshot_servable(4)
        assert bc._snapshot_engine.latest_servable_snapshot_height() == 4
