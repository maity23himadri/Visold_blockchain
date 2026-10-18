from __future__ import annotations

import json
import os
import tempfile
import zlib

import pytest

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.bootstrap_sync import verify_bootstrap_header_chain
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


@pytest.fixture
def bootstrap_cfg(monkeypatch):
    # Tiny deterministic values exercise the production 600-block protocol in
    # seconds.  These are process-local test overrides, never runtime settings.
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 2)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 3)
    monkeypatch.setattr(Config, "BOOTSTRAP_HEADER_PAGE_SIZE", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 100)
    monkeypatch.setattr(Config, "SNAPSHOT_KEEP", 2)


def _mine_to(bc: Blockchain, miner: Wallet, height: int):
    eng = ConsensusEngine(bc, miner)
    while bc.height() < height:
        candidate = eng.build_candidate_block(miner.address)
        assert candidate.mine(), f"mining failed at height {candidate.index}"
        ok, msg = bc.apply_block(candidate)
        assert ok, msg


def _source(td: str):
    st = Storage(os.path.join(td, "source.db"))
    bc = Blockchain(st)
    miner = Wallet.generate()
    _mine_to(bc, miner, 5)
    # Ensure compaction is complete independent of daemon-thread scheduling.
    bc._rolling_pruner._last_height = -1
    bc._rolling_pruner.maybe_prune(bc.height())
    return st, bc, miner


def test_all_pruning_nodes_can_bootstrap_fresh_node_from_authenticated_snapshot(bootstrap_cfg):
    with tempfile.TemporaryDirectory() as td:
        st, source, _miner = _source(td)
        assert int(st.get_meta("rolling_pruned_until") or -1) >= 2
        assert source.get_block(1).is_pruned is True

        # H=4 is committed by full block H+1=5. Old H=1/2 history can already
        # be header-only; no archive body is involved in authentication.
        entry = next(e for e in source._snapshot_engine.get_manifest()
                     if int(e["height"]) == 4)
        blob = source._snapshot_engine.get_snapshot_blob(4)
        assert blob
        transport = [source.get_block(h).to_dict() for h in range(0, 6)]
        ok, msg, verified, committed = verify_bootstrap_header_chain(
            transport, st.get_meta("genesis_hash"), 4)
        assert ok, msg
        assert committed == entry["bootstrap_digest"]

        fresh_st = Storage(os.path.join(td, "fresh.db"))
        fresh = Blockchain(fresh_st)
        ok, msg = fresh._snapshot_engine.restore_authenticated_bootstrap(
            blob, committed, verified)
        assert ok, msg
        assert fresh.height() == 4
        assert fresh_st.get_meta("rolling_pruned_until") == "4"

        # Replay protection is part of the authenticated snapshot, despite old
        # transaction rows/bodies being absent on the fresh node.
        old_coinbase = source.get_block(2).bootstrap_commitment
        # Pick any confirmed txid from the source's replay guard.
        row = st._conn().execute(
            "SELECT tx_id FROM tx_replay_guard ORDER BY tx_id LIMIT 1").fetchone()
        assert row and fresh_st.replay_guard_exists(row["tx_id"])

        # Continue with ordinary fully-validated blocks after the snapshot.
        fresh.layer2._try_restore_from_storage()
        b5 = source.get_block(5)
        assert not b5.is_pruned and len(b5.transactions) > 0
        ok, msg = fresh.apply_block(b5)
        assert ok, msg
        assert fresh.height() == source.height() == 5
        assert fresh.latest_block().state_root == source.latest_block().state_root
        assert fresh_st.get_cumulative_issued_sat() == st.get_cumulative_issued_sat()


def test_forged_snapshot_bytes_are_rejected_before_any_state_install(bootstrap_cfg):
    with tempfile.TemporaryDirectory() as td:
        st, source, _miner = _source(td)
        blob = source._snapshot_engine.get_snapshot_blob(4)
        headers = [source.get_block(h).to_dict() for h in range(0, 6)]
        ok, msg, verified, committed = verify_bootstrap_header_chain(
            headers, st.get_meta("genesis_hash"), 4)
        assert ok, msg

        raw = zlib.decompress(blob)
        payload = json.loads(raw.decode())
        # Change a consensus balance while leaving the old committed digest.
        k = next(iter(payload["balances"]))
        payload["balances"][k] = int(payload["balances"][k]) + 1
        forged = zlib.compress(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(), 9)

        fresh_st = Storage(os.path.join(td, "fresh.db"))
        fresh = Blockchain(fresh_st)
        ok, msg = fresh._snapshot_engine.restore_authenticated_bootstrap(
            forged, committed, verified)
        assert not ok
        assert "digest mismatch" in msg
        assert fresh.height() == 0


def test_header_or_commitment_tampering_is_rejected(bootstrap_cfg):
    with tempfile.TemporaryDirectory() as td:
        st, source, _miner = _source(td)
        headers = [source.get_block(h).to_dict() for h in range(0, 6)]

        bad_header = [dict(x) for x in headers]
        bad_header[2] = dict(bad_header[2])
        bad_header[2]["state_root"] = "f" * 64
        ok, msg, _verified, _digest = verify_bootstrap_header_chain(
            bad_header, st.get_meta("genesis_hash"), 4)
        assert not ok and "block_hash mismatch" in msg

        # Change the commitment memo in the full H+1 block. Its tx-id/Merkle
        # chain can no longer authenticate, so verification must fail closed.
        bad_commit = [dict(x) for x in headers]
        b5 = json.loads(json.dumps(bad_commit[5]))
        b5["transactions"][0]["memo"] = (
            "coinbase:5|bootsnap:4:" + "0" * 64)
        bad_commit[5] = b5
        ok, _msg, _verified, _digest = verify_bootstrap_header_chain(
            bad_commit, st.get_meta("genesis_hash"), 4)
        assert not ok


def test_validator_rejects_miner_forged_snapshot_commitment(bootstrap_cfg):
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "chain.db"))
        bc = Blockchain(st)
        miner = Wallet.generate()
        _mine_to(bc, miner, 2)

        height = 3
        wrong = "0" * 64
        cb = Transaction.coinbase(
            miner.address,
            bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
            height,
            bootstrap_snapshot=(2, wrong),
        )
        root = bc.dry_run_state_root([cb], miner.address, height)
        bad = Block(
            index=height,
            prev_hash=bc.latest_block().block_hash,
            transactions=[cb],
            miner_address=miner.address,
            difficulty=bc.get_difficulty(),
            timestamp=bc.latest_block().timestamp + 1,
            state_root=root,
        )
        assert bad.mine()
        ok, msg = bc.validate_block(bad)
        assert not ok
        assert "commitment mismatch" in msg.lower()


def test_stale_height5_fast_forwards_to_11_after_required_blocks_are_pruned(bootstrap_cfg):
    """Exact regression: stale h=5 must recover from source h=11 even when h=6 is pruned."""
    import sqlite3

    with tempfile.TemporaryDirectory() as td:
        source_st = Storage(os.path.join(td, "source.db"))
        source = Blockchain(source_st)
        miner = Wallet.generate()
        _mine_to(source, miner, 5)

        # Clone the exact canonical prefix at h=5, as a real node that went
        # offline at that point. SQLite backup captures a consistent DB image.
        stale_path = os.path.join(td, "stale.db")
        dst = sqlite3.connect(stale_path)
        try:
            source_st._conn().backup(dst)
        finally:
            dst.close()

        # Source advances far enough that the stale node's next required body
        # (h=6) is compacted, while snapshot h=10 is committed by full h=11.
        _mine_to(source, miner, 11)
        source._rolling_pruner._last_height = -1
        source._rolling_pruner.maybe_prune(source.height())
        assert source.height() == 11
        assert source.get_block(6).is_pruned is True
        assert source.get_block(11).is_pruned is False

        entry = next(e for e in source._snapshot_engine.get_manifest()
                     if int(e["height"]) == 10)
        blob = source._snapshot_engine.get_snapshot_blob(10)
        assert blob
        transport = [source.get_block(h).to_dict() for h in range(0, 12)]
        ok, msg, verified, committed = verify_bootstrap_header_chain(
            transport, source_st.get_meta("genesis_hash"), 10)
        assert ok, msg
        assert committed == entry["bootstrap_digest"]

        stale_st = Storage(stale_path)
        stale = Blockchain(stale_st)
        assert stale.height() == 5

        # Ordinary block sync cannot cross h=6 because its body is gone.
        b6 = source.get_block(6)
        assert b6.is_pruned
        ok, msg = stale.apply_block(b6)
        assert not ok
        assert stale.height() == 5

        # Authenticated snapshot is permitted only because h=0..5 is an exact
        # prefix of the independently verified source header chain.
        ok, msg = stale._snapshot_engine.restore_authenticated_bootstrap(
            blob, committed, verified)
        assert ok, msg
        assert stale.height() == 10

        stale.layer2._try_restore_from_storage()
        b11 = source.get_block(11)
        assert not b11.is_pruned
        ok, msg = stale.apply_block(b11)
        assert ok, msg
        assert stale.height() == 11
        assert stale.latest_block().block_hash == source.latest_block().block_hash
        assert stale.latest_block().state_root == source.latest_block().state_root
        assert stale_st.get_cumulative_issued_sat() == source_st.get_cumulative_issued_sat()


def test_stale_snapshot_fast_forward_rejects_nonmatching_local_prefix(bootstrap_cfg):
    with tempfile.TemporaryDirectory() as td:
        st, source, miner = _source(td)
        # Extend to obtain committed snapshot h=4 and its verified chain.
        headers = [source.get_block(h).to_dict() for h in range(0, 6)]
        blob = source._snapshot_engine.get_snapshot_blob(4)
        ok, msg, verified, committed = verify_bootstrap_header_chain(
            headers, st.get_meta("genesis_hash"), 4)
        assert ok, msg

        # Build an independent node to h=1. Genesis matches, block 1 does not.
        other_st = Storage(os.path.join(td, "other.db"))
        other = Blockchain(other_st)
        other_miner = Wallet.generate()
        _mine_to(other, other_miner, 1)
        assert other.get_block(0).block_hash == source.get_block(0).block_hash
        assert other.get_block(1).block_hash != source.get_block(1).block_hash

        ok, why = other._snapshot_engine.restore_authenticated_bootstrap(
            blob, committed, verified)
        assert not ok
        assert "not a fast-forward" in why
        assert other.height() == 1
