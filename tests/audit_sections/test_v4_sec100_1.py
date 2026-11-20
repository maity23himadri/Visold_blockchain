"""V4 regression tests for Section 100: Snapshots, Pruning, Recovery & Authenticated State Restoration."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.storage.rolling_window_pruner import RollingWindowPruner
from visold.storage.state_pruner import StatePruner
from visold.storage.storage import Storage


def _make_block(idx: int, prev_hash: str = "0" * 64, pruned: bool = False) -> Block:
    blk = Block(
        index=idx,
        prev_hash=prev_hash,
        timestamp=1_700_000_000 + idx,
        transactions=[],
        nonce=idx,
        difficulty=1.0,
        miner_address="VSD_miner",
        merkle_root="m" * 64,
        state_root="s" * 64,
        pruned=pruned,
    )
    blk.block_hash = blk.compute_hash()
    return blk


def test_v4_reconcile_after_bootstrap_preserves_watermark_with_genesis_exception(monkeypatch):
    """
    Fixed: RollingWindowPruner.reconcile_after_bootstrap() sets rolling_pruned_until=snap_h+1
    when blocks 1..snap_h are header-only (pruned=True), even when
    height < ROLLING_PRUNE_WINDOW + ROLLING_PRUNE_INTERVAL.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "visold.db")
        storage = Storage(db_path=db_path)
        try:
            g = _make_block(0, pruned=False)
            storage.save_block(g)
            prev = g.block_hash
            for h in range(1, 11):
                b = _make_block(h, prev_hash=prev, pruned=True)
                storage.save_block(b)
                prev = b.block_hash

            monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
            monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 600)
            monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 50)

            pruner = RollingWindowPruner(storage)
            pruner.reconcile_after_bootstrap(10)

            assert pruner.get_pruned_watermark() == 11
            assert bool(storage.get_block(0).to_dict().get("pruned", False)) is False
            assert bool(storage.get_block(1).to_dict().get("pruned", False)) is True
            assert bool(storage.get_block(10).to_dict().get("pruned", False)) is True
        finally:
            storage.close()


def test_v4_reconcile_after_bootstrap_preserves_watermark_when_rolling_prune_disabled(monkeypatch):
    """
    Fixed: Even when Config.ROLLING_PRUNE_ENABLED is False, reconcile_after_bootstrap()
    sets rolling_pruned_until=snap_h+1 when blocks 1..H are header-only.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "visold.db")
        storage = Storage(db_path=db_path)
        try:
            g = _make_block(0, pruned=False)
            storage.save_block(g)
            prev = g.block_hash
            for h in range(1, 21):
                b = _make_block(h, prev_hash=prev, pruned=True)
                storage.save_block(b)
                prev = b.block_hash

            monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", False)
            monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 5)
            monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 5)

            pruner = RollingWindowPruner(storage)
            pruner.reconcile_after_bootstrap(20)

            assert pruner.get_pruned_watermark() == 21
            assert bool(storage.get_block(20).to_dict().get("pruned", False)) is True
        finally:
            storage.close()


def test_v4_state_pruner_pgx_mode_deletes_pg_node_meta(monkeypatch):
    """
    Fixed: StatePruner._prune_state_snapshots() queries and deletes 'state_snapshot:*'
    from PostgreSQL node_meta when _pgx_enabled=True.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "aux.db")
        storage = Storage(db_path=db_path)
        try:
            pg_meta = {
                "state_snapshot:1": "root1",
                "state_snapshot:2": "root2",
                "state_snapshot:100": "root100",
            }
            storage._pgx_enabled = True

            def _pg_fetch(sql, *args):
                if "state_snapshot:%" in sql and args:
                    cutoff = int(args[0])
                    return [
                        {"key": k}
                        for k in sorted(pg_meta)
                        if k.startswith("state_snapshot:") and int(k.split(":")[1]) < cutoff
                    ]
                return []

            def _pg_exec(sql, *args):
                if "INSERT INTO node_meta" in sql:
                    pg_meta[args[0]] = args[1]
                elif "DELETE FROM node_meta" in sql and args:
                    for k in args[0]:
                        pg_meta.pop(k, None)

            storage._pg_fetch = MagicMock(side_effect=_pg_fetch)
            storage._pg_exec = MagicMock(side_effect=_pg_exec)
            storage._pg_fetchrow = MagicMock(
                side_effect=lambda sql, k: {"value": pg_meta[k]} if k in pg_meta else None
            )
            storage._pgx_after_commit = lambda fn, *a, **kw: fn(*a, **kw)

            monkeypatch.setattr(Config, "STATE_PRUNE_ENABLED", True)
            monkeypatch.setattr(Config, "STATE_PRUNE_KEEP_SNAPSHOTS", 10)
            monkeypatch.setattr(Config, "STATE_PRUNE_INTERVAL", 1)

            pruner = StatePruner(storage, blockchain=MagicMock())
            pruner.maybe_prune(50)  # cutoff = 40

            assert pg_meta.get("state_pruned_until") == "40"
            assert "state_snapshot:1" not in pg_meta
            assert "state_snapshot:2" not in pg_meta
            assert "state_snapshot:100" in pg_meta
        finally:
            storage.close()
