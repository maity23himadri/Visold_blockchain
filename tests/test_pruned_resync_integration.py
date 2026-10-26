"""Deterministic integration regressions for pruning and reconnect safety.

These tests deliberately model the current recoverability contract:

* without a committed bootstrap snapshot, the pruner must fail closed and keep
  full block bodies even when the rolling-window threshold has passed;
* with real consensus-created bootstrap commitments, old bodies may be pruned,
  but stale/fresh full-body synchronization must reject header-only history
  without partially applying the supplied chain.

Difficulty is set to zero only to make actual PoW mining deterministic and fast;
this is not a consensus/PoW correctness test.  Production pruning and chain
application code remain unpatched.
"""
from __future__ import annotations

import time
from unittest.mock import patch

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _new_chain(tmp_path, filename):
    storage = Storage(str(tmp_path / filename))
    chain = Blockchain(storage)
    # Run pruning synchronously from the test, not from a background thread.
    chain._rolling_pruner.prune_async = lambda _height: None
    return storage, chain


def _mine_one_without_bootstrap_commitment(chain, miner, timestamp):
    """Build a simple block for the explicit no-servable-snapshot scenario."""
    height = chain.height() + 1
    parent = chain.latest_block()
    coinbase = Transaction.coinbase(
        miner.address, chain.compute_reward_sat(height) / Config.SATOSHI_PER_VSD, height
    )
    state_root = chain.dry_run_state_root([coinbase], miner.address, height)
    block = Block(
        index=height,
        prev_hash=parent.block_hash,
        transactions=[coinbase],
        miner_address=miner.address,
        difficulty=chain.get_difficulty(),
        timestamp=timestamp,
        state_root=state_root,
    )
    assert block.mine(), f"test block {height} mining failed"
    ok, reason = chain.apply_block(block)
    assert ok, f"test block {height} application failed: {reason}"
    return block


def _mine_to(chain, miner, target_height):
    """Mine using the real consensus candidate builder, including commitments."""
    chain._rolling_pruner.prune_async = lambda _height: None
    consensus = ConsensusEngine(chain, miner)
    while chain.height() < target_height:
        block = consensus.build_candidate_block(miner.address)
        assert block.mine(), f"consensus candidate {block.index} mining failed"
        ok, reason = chain.apply_block(block)
        assert ok, f"consensus block {block.index} application failed: {reason}"


def _chain_payload(chain, start_height, end_height_inclusive):
    payload = []
    for height in range(start_height, end_height_inclusive + 1):
        block = chain.get_block(height)
        assert block is not None, f"source block {height} unexpectedly missing"
        payload.append(Block.from_dict(block.to_dict()))
    return payload


def test_pruner_keeps_full_bodies_when_no_committed_snapshot_is_available(
    tmp_path, monkeypatch
):
    """A rolling-window cutoff alone must never authorize body deletion."""
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 3)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 200)
    monkeypatch.setattr(Config, "SNAPSHOT_FAST_SYNC_ENABLED", False)
    monkeypatch.setattr(Config, "SNAPSHOT_ENABLED", False)
    # Keep the consensus snapshot interval at its normal/default scale for this
    # case: the test chain never reaches an anchor/commitment boundary.

    with patch.object(Blockchain, "get_difficulty", return_value=0.0):
        storage, chain = _new_chain(tmp_path, "no_anchor.db")
        try:
            miner = Wallet.generate()
            # Finish near local time to avoid manufacturing large clock offsets.
            t0 = int(time.time()) - 11 * 60
            for height in range(1, 12):
                _mine_one_without_bootstrap_commitment(
                    chain, miner, t0 + height * 60
                )
                chain._rolling_pruner.maybe_prune(chain.height())

            assert chain.height() == 11
            assert chain._snapshot_engine.get_servable_manifest() == []
            assert chain._rolling_pruner._recoverability_aligned_cutoff(11) == 0
            old_block = chain.get_block(1)
            assert old_block is not None
            assert old_block.is_pruned is False
        finally:
            storage.close()


def test_pruned_history_fails_closed_without_partial_apply_when_commitments_exist(
    tmp_path, monkeypatch
):
    """Real committed anchors allow pruning; old-body sync still fails closed."""
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 3)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 200)
    monkeypatch.setattr(Config, "SNAPSHOT_FAST_SYNC_ENABLED", False)
    monkeypatch.setattr(Config, "SNAPSHOT_ENABLED", False)
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 4)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 5)
    monkeypatch.setattr(Config, "SNAPSHOT_KEEP", 3)

    # Keep pruning off while the receiver fixtures acquire complete history.
    # ConsensusEngine still creates/commits the required bootstrap snapshots at
    # the test-only 4-block interval. No production implementation is mocked.
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", False)

    with patch.object(Blockchain, "get_difficulty", return_value=0.0):
        source_storage, source = _new_chain(tmp_path, "source.db")
        short_storage, short = _new_chain(tmp_path, "short.db")
        stale_storage, stale = _new_chain(tmp_path, "stale.db")
        fresh_storage, fresh = _new_chain(tmp_path, "fresh.db")
        try:
            miner = Wallet.generate()
            _mine_to(source, miner, 14)

            # Candidate dry-runs must not leave node-local zero nonce rows that
            # a receiving validator cannot reproduce in the same bootstrap
            # snapshot digest. This assertion makes the discovered regression
            # explicit instead of relying only on the next block's validation.
            zero_nonce_rows = source_storage._conn().execute(
                "SELECT address FROM account_nonces WHERE nonce=0"
            ).fetchall()
            assert zero_nonce_rows == [], [row["address"] for row in zero_nonce_rows]

            # Verify snapshots are actually servable only after their H+1
            # commitment has committed to the source chain.
            anchors = {
                int(entry["height"])
                for entry in source._snapshot_engine.get_servable_manifest()
            }
            assert {4, 8, 12}.issubset(anchors), anchors

            # A recent node has all history through 14; another node only through 5.
            ok, reason = short.accept_chain(_chain_payload(source, 0, 14))
            assert ok, reason
            assert short.height() == 14

            ok, reason = stale.accept_chain(_chain_payload(source, 0, 5))
            assert ok, reason
            assert stale.height() == 5

            # Enable pruning only after those complete histories have been acquired.
            monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
            for height in range(15, 20):
                _mine_to(source, miner, height)
                source._rolling_pruner.maybe_prune(source.height())

            assert source.height() == 19
            old_block = source.get_block(1)
            assert old_block is not None and old_block.is_pruned
            assert old_block.transactions == ()
            assert old_block.to_dict()["pruned"] is True
            valid, reason = source.validate_block(old_block)
            assert not valid and "pruned" in reason.lower()

            # The latest recoverable suffix remains full and synchronizes normally.
            recent_missing = _chain_payload(source, 15, 19)
            ok, reason = short.accept_chain(recent_missing)
            assert ok, reason
            assert short.height() == 19

            # The stale node needs old block 6, whose body has been pruned.
            stale_missing = _chain_payload(source, 6, 19)
            ok, reason = stale.accept_chain(stale_missing)
            assert not ok
            assert "pruned/header-only" in reason
            assert stale.height() == 5, "failed batch partially changed local chain"

            # A fresh node cannot consume a full-history page that contains a
            # header-only block and must remain at genesis on rejection.
            full_payload = _chain_payload(source, 0, 19)
            ok, reason = fresh.accept_chain(full_payload)
            assert not ok
            assert "pruned/header-only" in reason
            assert fresh.height() == 0, "fresh sync partially applied pruned history"
        finally:
            source_storage.close()
            short_storage.close()
            stale_storage.close()
            fresh_storage.close()
