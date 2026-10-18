"""Deterministic integration regression for prune/reconnect safety.

PoW search is replaced with an always-valid test target so the real block
application, SQLite storage, pruner, serialization and accept_chain paths can
be exercised quickly. This is not a consensus/PoW correctness test.
"""
from __future__ import annotations

import time
from unittest.mock import patch

from visold.chain.blockchain import Blockchain
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


def _mine_one(chain, miner, timestamp):
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


def test_pruned_history_is_marked_and_missing_body_fails_closed_without_partial_apply(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 3)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 200)
    monkeypatch.setattr(Config, "SNAPSHOT_FAST_SYNC_ENABLED", False)
    if hasattr(Config, "SNAPSHOT_ENABLED"):
        monkeypatch.setattr(Config, "SNAPSHOT_ENABLED", False)

    # Fast deterministic integration: all actual storage, block application,
    # chain validation and pruning logic remain in use. Returning difficulty
    # zero makes the real PoW target maximal, so the real miner and PoW verifier
    # can run without patching the process-global DifficultyEngine or its cache.
    with patch.object(Blockchain, "get_difficulty", return_value=0.0):
        source_storage, source = _new_chain(tmp_path, "source.db")
        short_storage, short = _new_chain(tmp_path, "short.db")
        stale_storage, stale = _new_chain(tmp_path, "stale.db")
        fresh_storage, fresh = _new_chain(tmp_path, "fresh.db")
        try:
            miner = Wallet.generate()
            t0 = int(time.time()) + 3600

            # Mine first, while the entire chain body remains available.
            for height in range(1, 9):
                _mine_one(source, miner, t0 + height * 60)

            # Node 2a syncs through 8; node 2b syncs only through height 5.
            short_payload = [source.get_block(i).to_dict() for i in range(0, 9)]
            ok, reason = short.accept_chain([Block.from_dict(d) for d in short_payload])
            assert ok, reason
            assert short.height() == 8

            stale_payload = [source.get_block(i).to_dict() for i in range(0, 6)]
            ok, reason = stale.accept_chain([Block.from_dict(d) for d in stale_payload])
            assert ok, reason
            assert stale.height() == 5

            # Node 1 advances and prunes the bodies needed by stale/fresh nodes.
            for height in range(9, 12):
                _mine_one(source, miner, t0 + height * 60)
                source._rolling_pruner.maybe_prune(source.height())
            assert source.height() == 11
            old_block = source.get_block(1)
            assert old_block is not None and old_block.is_pruned
            assert old_block.transactions == ()
            assert old_block.to_dict()["pruned"] is True
            valid, reason = source.validate_block(old_block)
            assert not valid and "pruned" in reason.lower()

            # A recently synced node asks only for 9..11, whose bodies still exist.
            recent_missing = [source.get_block(i).to_dict() for i in range(9, 12)]
            ok, reason = short.accept_chain([Block.from_dict(d) for d in recent_missing])
            assert ok, reason
            assert short.height() == 11

            # Stale node needs pruned block 6. It must fail without applying 7..11.
            stale_missing = [source.get_block(i).to_dict() for i in range(6, 12)]
            ok, reason = stale.accept_chain([Block.from_dict(d) for d in stale_missing])
            assert not ok
            assert "pruned/header-only" in reason
            assert stale.height() == 5, "failed batch partially changed local chain"

            # Fresh node asks for full history. It must fail closed before applying
            # any of that page; never treat a pruned header as a full block.
            full_payload = [source.get_block(i).to_dict() for i in range(0, 12)]
            ok, reason = fresh.accept_chain([Block.from_dict(d) for d in full_payload])
            assert not ok
            assert "pruned/header-only" in reason
            assert fresh.height() == 0, "fresh sync partially applied a pruned-history page"
        finally:
            source_storage.close()
            short_storage.close()
            stale_storage.close()
            fresh_storage.close()
