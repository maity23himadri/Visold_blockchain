"""A protected transfer stays valid on a node that bootstrapped from an authenticated
snapshot. The fresh node keeps headers, not bodies, for heights up to the snapshot. The
commitment sits in block 3, below the snapshot at height 4, and the reveal is in block 6,
so validating the reveal needs a header alone."""

from __future__ import annotations

import os
import time

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.kernel.config import Config
from visold.mempool import mev
from visold.network.bootstrap_sync import verify_bootstrap_header_chain
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = 100_000_000


def _configure(monkeypatch):
    # The same tiny protocol values the bootstrap tests use.
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 2)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 3)
    monkeypatch.setattr(Config, "BOOTSTRAP_HEADER_PAGE_SIZE", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 100)
    monkeypatch.setattr(Config, "SNAPSHOT_KEEP", 2)


def _mine_one(bc, miner):
    candidate = ConsensusEngine(bc, miner).build_candidate_block(miner.address)
    assert candidate.mine(), "mining failed"
    ok, msg = bc.apply_block(candidate)
    assert ok, msg
    return candidate


def test_reveal_validates_on_a_node_bootstrapped_from_a_snapshot(tmp_path, monkeypatch):
    _configure(monkeypatch)
    st = Storage(os.path.join(str(tmp_path), "source.db"))
    src = Blockchain(st)
    sender, recipient = Wallet.generate(), Wallet.generate()
    _mine_one(src, sender)                                  # block 1: the sender is paid
    _mine_one(src, sender)                                  # block 2

    ts = int(time.time())
    salt = mev.new_salt()
    core = mev.core_transfer(sender.address, recipient.address, 1.0, 0.01, "", 1, ts)
    commit = mev.build_commitment_tx(sender, 1, ts, core.mev_commitment(salt))
    ok, msg = src.mempool.add(commit)
    assert ok, msg
    commit_block = _mine_one(src, sender)                   # block 3 carries the commitment
    assert any(t.tx_id == commit.tx_id for t in commit_block.transactions)
    # Build the reveal while block 3's body is still stored, as a sender node does.
    steps = mev.reveal_steps_for_commit(st, commit.tx_id, 3)
    reveal = mev.build_reveal_tx(sender, core, salt, 3, steps)
    _mine_one(src, sender)                                  # block 4
    _mine_one(src, sender)                                  # block 5
    ok, msg = src.mempool.add(reveal)
    assert ok, msg
    reveal_block = _mine_one(src, sender)                   # block 6 carries the reveal
    assert any(t.tx_id == reveal.tx_id for t in reveal_block.transactions)
    assert src.height() == 6

    entry = next(e for e in src._snapshot_engine.get_manifest() if int(e["height"]) == 4)
    blob = src._snapshot_engine.get_snapshot_blob(4)
    assert blob
    transport = [src.get_block(h).to_dict() for h in range(0, 6)]
    ok, msg, verified, committed = verify_bootstrap_header_chain(
        transport, st.get_meta("genesis_hash"), 4)
    assert ok, msg
    assert committed == entry["bootstrap_digest"]

    fresh_st = Storage(os.path.join(str(tmp_path), "fresh.db"))
    fresh = Blockchain(fresh_st)
    ok, msg = fresh._snapshot_engine.restore_authenticated_bootstrap(blob, committed, verified)
    assert ok, msg
    assert fresh.height() == 4
    # The fresh node holds headers, not bodies, below the snapshot: block 3 is one of them.
    assert not fresh_st.get_block(3).transactions

    fresh.layer2._try_restore_from_storage()
    for h in (5, 6):
        full = src.get_block(h)
        assert not full.is_pruned
        ok, msg = fresh.apply_block(full)
        assert ok, msg
    assert fresh.height() == 6
    assert fresh_st.get_balance_sat(recipient.address) == int(round(1.0 * SAT))
