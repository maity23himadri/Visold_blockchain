from __future__ import annotations


import os
import tempfile


import pytest


from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.ledger.transaction import Transaction
from visold.network.bootstrap_sync import verify_bootstrap_header_chain
from visold.storage.state_pruner import StatePruner
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet




@pytest.fixture
def audit_cfg(monkeypatch):
    DifficultyEngine.invalidate_cache()
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 4)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 5)
    monkeypatch.setattr(Config, "BOOTSTRAP_HEADER_PAGE_SIZE", 4)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 4)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 100)
    monkeypatch.setattr(Config, "SNAPSHOT_KEEP", 2)
    yield
    DifficultyEngine.invalidate_cache()




def _mine_to(bc: Blockchain, miner: Wallet, height: int, tx_at_height: dict | None = None):
    bc._rolling_pruner.prune_async = lambda _height: None
    eng = ConsensusEngine(bc, miner)
    while bc.height() < height:
        nxt_h = bc.height() + 1
        if tx_at_height and nxt_h in tx_at_height:
            tx = tx_at_height[nxt_h]
            ok_mp, msg_mp = bc.mempool.add(tx)
            assert ok_mp, msg_mp
        candidate = eng.build_candidate_block(miner.address)
        assert candidate.mine(), f"mining failed at height {candidate.index}"
        ok, msg = bc.apply_block(candidate)
        assert ok, msg




def test_reconcile_after_bootstrap_non_fresh_sets_zero_watermark_allowing_corrupt_rollback(audit_cfg):
    """
    Bug 1:
    When a non-fresh node (local_h >= 1, full blocks 0..local_h) fast-forwards
    via restore_authenticated_bootstrap() to snap_h=4 (below WINDOW+INTERVAL=6,
    or when no servable snapshot < raw_cutoff exists), reconcile_after_bootstrap()
    computes all_prefix_boundary=0, genesis_exception_boundary=0, contiguous=0
    because blocks 0..local_h are unpruned, and sets rolling_pruned_until='0'.
    As a result, rollback() bypasses its pruned-watermark guard and rolls back
    pruned header-only blocks (transactions=[]), leaving user tx effects in state!
    """
    with tempfile.TemporaryDirectory() as td:
        src_st = Storage(os.path.join(td, "source.db"))
        src_bc = Blockchain(src_st)
        miner = Wallet.generate()
        alice = Wallet.generate()


        # Mine blocks 1..2 so miner has spendable funds
        _mine_to(src_bc, miner, 2)
        nonce = src_bc.storage.get_nonce(miner.address)
        tx = Transaction(miner.address, alice.address, 5.0, fee=0.05, nonce=nonce)
        tx.sign(miner)
        _mine_to(src_bc, miner, 5, tx_at_height={3: tx})
        assert src_st.get_balance_sat(alice.address) == 500_000_000


        entry = next(
            e for e in src_bc._snapshot_engine.get_manifest()
            if int(e["height"]) == 4
        )
        blob = src_bc._snapshot_engine.get_snapshot_blob(4)
        assert blob is not None
        transport = [src_bc.storage.get_block(h).to_dict() for h in range(0, 6)]
        ok, msg, verified, committed = verify_bootstrap_header_chain(
            transport, src_st.get_meta("genesis_hash"), 4
        )
        assert ok, msg
        assert committed == entry["bootstrap_digest"]


        # Stale node has blocks 0..2 full, then fast-forwards to snap_h=4
        dst_st = Storage(os.path.join(td, "stale.db"))
        dst_bc = Blockchain(dst_st)
        dst_bc._rolling_pruner.prune_async = lambda _h: None
        for h in range(1, 3):
            ok_apply, err_apply = dst_bc.apply_block(src_bc.storage.get_block(h))
            assert ok_apply, err_apply
        assert dst_bc.height() == 2
        assert dst_st.get_balance_sat(alice.address) == 0


        ok_boot, err_boot = dst_bc._snapshot_engine.restore_authenticated_bootstrap(
            blob, committed, verified
        )
        assert ok_boot, err_boot
        assert dst_bc.height() == 4
        assert dst_bc.storage.get_block(3).is_pruned is True
        assert dst_bc.storage.get_block(4).is_pruned is True
        assert dst_st.get_balance_sat(alice.address) == 500_000_000


        assert dst_bc._rolling_pruner.get_pruned_watermark() == 5

        ok_rb, msg_rb = dst_bc.rollback(2)
        assert ok_rb is False
        assert dst_bc.height() == 4
        assert dst_st.get_balance_sat(alice.address) == 500_000_000




def test_run_prune_pass_wipes_positive_watermark_when_blocks_0_and_1_full(audit_cfg):
    """
    Bug 2:
    RollingWindowPruner._run_prune_pass() resets rolling_pruned_until to '0'
    whenever block 0 and block 1 are full (pruned=False), even if blocks
    3..8 are pruned and a positive watermark (e.g. 9) was set.
    With a servable snapshot at h=4 and current_height=9 (raw_cutoff=5),
    _run_prune_pass(9) resets watermark from 9 to 0, prunes 0..4, and leaves
    rolling_pruned_until=5 even though blocks 5..8 are also pruned!
    """
    with tempfile.TemporaryDirectory() as td:
        src_st = Storage(os.path.join(td, "source.db"))
        src_bc = Blockchain(src_st)
        miner = Wallet.generate()
        _mine_to(src_bc, miner, 9)


        entry = next(
            e for e in src_bc._snapshot_engine.get_manifest()
            if int(e["height"]) == 8
        )
        blob = src_bc._snapshot_engine.get_snapshot_blob(8)
        assert blob is not None
        transport = [src_bc.storage.get_block(h).to_dict() for h in range(0, 10)]
        ok, msg, verified, committed = verify_bootstrap_header_chain(
            transport, src_st.get_meta("genesis_hash"), 8
        )
        assert ok, msg


        dst_st = Storage(os.path.join(td, "stale.db"))
        dst_bc = Blockchain(dst_st)
        dst_bc._rolling_pruner.prune_async = lambda _h: None
        for h in range(1, 3):
            ok_apply, err_apply = dst_bc.apply_block(src_bc.storage.get_block(h))
            assert ok_apply, err_apply


        ok_boot, err_boot = dst_bc._snapshot_engine.restore_authenticated_bootstrap(
            blob, committed, verified
        )
        assert ok_boot, err_boot
        # Apply block 9 and ensure a servable snapshot exists at h=4 so cutoff=5 > 0
        ok9, err9 = dst_bc.apply_block(src_bc.storage.get_block(9))
        assert ok9, err9
        b4 = dst_bc.storage.get_block(4)
        dst_bc._snapshot_engine.ensure_bootstrap_snapshot(4, b4.state_root)


        # Suppose a valid positive watermark is recorded for the pruned suffix 3..8.
        dst_st.set_meta("rolling_pruned_until", "9")
        dst_st.set_meta("rolling_prune_reconcile_version", "1")
        assert dst_bc._rolling_pruner.get_pruned_watermark() == 9


        # _run_prune_pass(9) resets watermark from 9 -> 0 because blocks 0 and 1 are full,
        # then prunes 0..4 and sets rolling_pruned_until = 5 even though 5..8 are pruned!
        dst_bc._rolling_pruner._run_prune_pass(9)
        assert dst_bc._rolling_pruner.get_pruned_watermark() == 9
        assert dst_bc.storage.get_block(8).is_pruned is True




def test_state_pruner_unordered_limit_500_stalls_when_keep_exceeds_500(monkeypatch):
    """
    Bug 3:
    StatePruner._prune_state_snapshots() queries
    `SELECT key FROM node_meta WHERE key LIKE 'state_snapshot:%' LIMIT 500`
    without ORDER BY. When >= 500 keys with height >= cutoff appear first in the
    PRIMARY KEY scan (e.g. 'state_snapshot:10000'..'10549' before '200'..'249'),
    0 old keys are deleted and pruning stalls indefinitely.
    """
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "sp.db"))
        bc = Blockchain(st)
        sp = StatePruner(st, bc)


        monkeypatch.setattr(Config, "STATE_PRUNE_ENABLED", True)
        monkeypatch.setattr(Config, "STATE_PRUNE_KEEP_SNAPSHOTS", 600)
        monkeypatch.setattr(Config, "STATE_PRUNE_INTERVAL", 1)


        # Heights 10000..10549 sort lexicographically BEFORE 200..249.
        # With current_height=10549 and KEEP=600, cutoff=9949.
        # Heights 200..249 are < 9949 and should be pruned, but LIMIT 500
        # only sees 10000..10499 (all >= 9949).
        c = st._conn()
        for h in range(10000, 10550):
            c.execute(
                "INSERT OR REPLACE INTO node_meta (key, value) VALUES (?, ?)",
                (f"state_snapshot:{h}", f"root_{h}"),
            )
        for h in range(200, 250):
            c.execute(
                "INSERT OR REPLACE INTO node_meta (key, value) VALUES (?, ?)",
                (f"state_snapshot:{h}", f"root_{h}"),
            )
        c.commit()


        pruned = sp.maybe_prune(10549)
        assert pruned == 50
        assert st.get_meta("state_snapshot:200") is None