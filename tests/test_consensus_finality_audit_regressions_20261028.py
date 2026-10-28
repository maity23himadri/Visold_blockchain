"""Regression coverage for the October 2026 consensus/finality audit findings.

These tests deliberately exercise the real Blockchain + Storage paths.  They
cover durable embedded-vote accounting, valid conflicting votes after finality,
bootstrap PoW finality with 0/1/2/3 validators, and the manual rollback fence.
"""
from __future__ import annotations

import os
import tempfile
import time
from contextlib import contextmanager

import pytest

from visold.chain.blockchain import Blockchain
from visold.crypto.ecc import sig_to_hex
from visold.consensus.slashing import SlashingEvidenceProtocol
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


@contextmanager
def _fast_chain(td: str):
    names = (
        "MIN_DIFFICULTY", "INITIAL_DIFFICULTY", "MIN_VALIDATORS_FOR_BFT",
        "POW_FINALITY_DEPTH", "BOOTSTRAP_POW_FINALITY_DEPTH",
        "GOVERNANCE_FINALITY_TIMEOUT", "AUTO_SLASH_EVIDENCE",
    )
    old = {key: getattr(Config, key) for key in names}
    Config.MIN_DIFFICULTY = 0.001
    Config.INITIAL_DIFFICULTY = 0.001
    Config.MIN_VALIDATORS_FOR_BFT = 3
    Config.POW_FINALITY_DEPTH = 50
    Config.BOOTSTRAP_POW_FINALITY_DEPTH = 50
    Config.GOVERNANCE_FINALITY_TIMEOUT = 20
    Config.AUTO_SLASH_EVIDENCE = False
    try:
        storage = Storage(os.path.join(td, "consensus-regression.db"))
        yield storage, Blockchain(storage)
    finally:
        for key, value in old.items():
            setattr(Config, key, value)


def _mine_block(bc: Blockchain, miner: Wallet, *, bad_root=False) -> Block:
    height = bc.height() + 1
    coinbase = Transaction.coinbase(
        miner.address,
        bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
        height,
    )
    txs = [coinbase]
    root = bc.dry_run_state_root(txs, miner.address, height)
    if bad_root:
        root = "f" * 64 if root != "f" * 64 else "e" * 64
    previous = bc.latest_block()
    block = Block(
        index=height,
        prev_hash=previous.block_hash,
        transactions=txs,
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        timestamp=max(int(time.time()), int(previous.timestamp) + 1),
        state_root=root,
    )
    assert block.mine(), f"failed to mine test block #{height}"
    return block


def _vote(wallet: Wallet, block_hash: str) -> dict:
    return {
        "addr": wallet.address,
        "sig": sig_to_hex(wallet.sign(str(block_hash).encode("utf-8"))),
        "pub": wallet.pub_hex,
    }


def _apply(bc: Blockchain, block: Block) -> None:
    ok, message = bc.apply_block(block)
    assert ok, message


def test_embedded_votes_check_conflicts_and_persist_history_without_counting_conflicting_stake():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (storage, bc):
        validators = [Wallet.generate() for _ in range(4)]
        for wallet in validators:
            storage.set_role(wallet.address, "investor", 100.0)

        # A valid prior vote for another hash at height 1 must remain visible,
        # even if the previous branch/block body is not in the canonical chain.
        old_hash = "a" * 64
        old_vote = _vote(validators[0], old_hash)
        storage.record_validator_vote(
            old_hash, validators[0].address, old_vote["sig"], old_vote["pub"],
            block_idx=1,
        )

        block = _mine_block(bc, Wallet.generate())
        block.validator_sigs = [_vote(wallet, block.block_hash) for wallet in validators[:3]]
        _apply(bc, block)

        stored = storage.get_block(1)
        assert stored is not None
        # Only two of four validators' stake remains eligible for quorum.
        assert stored.finalized is False
        assert bc._highest_finalized_height == 0
        assert bool(storage.get_role(validators[0].address)["slashed"])

        history = storage.get_validator_votes_at_height(1)
        assert {(row["validator_addr"], row["block_hash"]) for row in history} >= {
            (validators[0].address, old_hash),
            (validators[0].address, stored.block_hash),
            (validators[1].address, stored.block_hash),
            (validators[2].address, stored.block_hash),
        }


def test_rejected_block_does_not_persist_embedded_votes_or_advance_finality():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (storage, bc):
        validators = [Wallet.generate() for _ in range(3)]
        for wallet in validators:
            storage.set_role(wallet.address, "investor", 100.0)
        block = _mine_block(bc, Wallet.generate(), bad_root=True)
        block.validator_sigs = [_vote(wallet, block.block_hash) for wallet in validators]

        ok, _message = bc.apply_block(block)
        assert not ok
        assert storage.get_block(1) is None
        assert storage.get_validator_votes_at_height(1) == []
        assert bc._highest_finalized_height == 0


def test_valid_conflicting_live_vote_is_rejected_even_after_target_finalization():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (storage, bc):
        validators = [Wallet.generate() for _ in range(3)]
        for wallet in validators:
            storage.set_role(wallet.address, "investor", 100.0)

        block = _mine_block(bc, Wallet.generate())
        block.validator_sigs = [_vote(wallet, block.block_hash) for wallet in validators]
        _apply(bc, block)
        stored = storage.get_block(1)
        assert stored is not None and stored.finalized is True

        validator = validators[0]
        other_hash = "b" * 64
        other_vote = _vote(validator, other_hash)
        storage.record_validator_vote(
            other_hash, validator.address, other_vote["sig"], other_vote["pub"],
            block_idx=1,
        )
        conflicting = _vote(validator, stored.block_hash)
        before_stake = storage.get_role(validator.address)["stake"]

        result = bc.add_validator_sig(
            stored.block_hash, validator.address,
            conflicting["sig"], validator.pub_hex,
        )
        assert result is False
        assert bool(storage.get_role(validator.address)["slashed"])
        history = storage.get_validator_votes_at_height(1)
        assert (validator.address, other_hash) in {
            (row["validator_addr"], row["block_hash"]) for row in history
        }
        assert (validator.address, stored.block_hash) in {
            (row["validator_addr"], row["block_hash"]) for row in history
        }

        # Re-delivery is idempotent and must not repeatedly reduce stake.
        slashed_stake = storage.get_role(validator.address)["stake"]
        assert slashed_stake <= before_stake
        assert bc.add_validator_sig(
            stored.block_hash, validator.address,
            conflicting["sig"], validator.pub_hex,
        ) is False
        assert storage.get_role(validator.address)["stake"] == slashed_stake


def test_bootstrap_pow_finality_uses_minimum_validator_activation_threshold():
    for count in (0, 1, 2, 3):
        with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (storage, bc):
            Config.BOOTSTRAP_POW_FINALITY_DEPTH = 2
            Config.POW_FINALITY_DEPTH = 1
            Config.GOVERNANCE_FINALITY_TIMEOUT = 20
            for wallet in [Wallet.generate() for _ in range(count)]:
                storage.set_role(wallet.address, "investor", 100.0)

            for _ in range(3):
                _apply(bc, _mine_block(bc, Wallet.generate()))

            height1 = storage.get_block(1)
            height2 = storage.get_block(2)
            assert height1 is not None and height2 is not None
            if count < Config.MIN_VALIDATORS_FOR_BFT:
                assert height1.finalized is True, (
                    f"{count} validators must use bootstrap depth directly"
                )
                assert bc._highest_finalized_height >= 1
            else:
                # At/above the activation threshold the degraded-BFT fallback
                # retains its configured liveness timeout.
                assert height2.finalized is False
                assert bc._highest_finalized_height == 0


def test_manual_rollback_cannot_delete_finalized_history_even_with_stale_memory_fence():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (storage, bc):
        validators = [Wallet.generate() for _ in range(3)]
        for wallet in validators:
            storage.set_role(wallet.address, "investor", 100.0)

        block1 = _mine_block(bc, Wallet.generate())
        block1.validator_sigs = [_vote(wallet, block1.block_hash) for wallet in validators]
        _apply(bc, block1)
        assert storage.get_block(1).finalized is True
        _apply(bc, _mine_block(bc, Wallet.generate()))
        assert bc.height() == 2

        # Simulate an out-of-date in-memory fence (as could remain in a process
        # upgraded from the buggy implementation). The canonical scan must win.
        bc._highest_finalized_height = 0
        ok, message = bc.rollback(0)
        assert not ok
        assert "finalized" in message.lower()
        assert bc.height() == 2
        assert storage.get_block(1) is not None
        assert storage.get_block(1).finalized is True
        assert bc._highest_finalized_height == 1


def test_manual_rollback_to_finality_fence_and_unfinalized_suffix_still_works():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (storage, bc):
        # With a deep finality depth, height 1 is not finalized. Genesis remains
        # the only finalized block, so rollback to height 0 is still permitted.
        _apply(bc, _mine_block(bc, Wallet.generate()))
        assert storage.get_block(1).finalized is False
        ok, message = bc.rollback(0)
        assert ok, message
        assert bc.height() == 0
        assert bc._highest_finalized_height == 0


def test_rollback_to_the_finalized_height_can_remove_only_the_unfinalized_suffix():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (storage, bc):
        validators = [Wallet.generate() for _ in range(3)]
        for wallet in validators:
            storage.set_role(wallet.address, "investor", 100.0)
        block1 = _mine_block(bc, Wallet.generate())
        block1.validator_sigs = [_vote(wallet, block1.block_hash) for wallet in validators]
        _apply(bc, block1)
        _apply(bc, _mine_block(bc, Wallet.generate()))

        ok, message = bc.rollback(1)
        assert ok, message
        assert bc.height() == 1
        assert storage.get_block(1) is not None and storage.get_block(1).finalized
        assert storage.get_block(2) is None
        assert bc._highest_finalized_height == 1


def test_embedded_equivocation_penalty_is_discarded_if_block_transaction_rolls_back():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (storage, bc):
        validators = [Wallet.generate() for _ in range(4)]
        for wallet in validators:
            storage.set_role(wallet.address, "investor", 100.0)

        other_hash = "c" * 64
        old_vote = _vote(validators[0], other_hash)
        storage.record_validator_vote(
            other_hash, validators[0].address, old_vote["sig"], old_vote["pub"],
            block_idx=1,
        )
        block = _mine_block(bc, Wallet.generate())
        block.validator_sigs = [_vote(wallet, block.block_hash) for wallet in validators[:3]]

        # Force a failure after BFT vote processing, when vote rows have been
        # written inside the SQLite atomic block but before that transaction
        # can commit. The vote evidence, slash and fence must not leak out.
        def fail_after_finality(*_args, **_kwargs):
            raise RuntimeError("injected post-finality failure")

        bc.mempool.clear_confirmed = fail_after_finality
        with pytest.raises(RuntimeError, match="injected post-finality failure"):
            bc.apply_block(block)

        assert storage.get_block(1) is None
        history = storage.get_validator_votes_at_height(1)
        assert {(row["validator_addr"], row["block_hash"]) for row in history} == {
            (validators[0].address, other_hash)
        }
        assert not bool(storage.get_role(validators[0].address)["slashed"])
        assert bc._highest_finalized_height == 0
        assert block.finalized is False


def test_embedded_equivocation_runs_auto_evidence_after_block_commit():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (storage, bc):
        Config.AUTO_SLASH_EVIDENCE = True
        bc._slash_evidence = SlashingEvidenceProtocol(storage, bc)
        validators = [Wallet.generate() for _ in range(4)]
        for wallet in validators:
            storage.set_role(wallet.address, "investor", 100.0)

        other_hash = "d" * 64
        old_vote = _vote(validators[0], other_hash)
        storage.record_validator_vote(
            other_hash, validators[0].address, old_vote["sig"], old_vote["pub"],
            block_idx=1,
        )
        block = _mine_block(bc, Wallet.generate())
        block.validator_sigs = [_vote(wallet, block.block_hash) for wallet in validators[:3]]
        _apply(bc, block)

        # Both vote rows are committed before evidence verification runs, so the
        # evidence protocol can independently verify the prior and current votes.
        history = storage.get_validator_votes_at_height(1)
        assert (validators[0].address, other_hash) in {
            (row["validator_addr"], row["block_hash"]) for row in history
        }
        assert (validators[0].address, block.block_hash) in {
            (row["validator_addr"], row["block_hash"]) for row in history
        }
        assert bool(storage.get_role(validators[0].address)["slashed"])
        assert storage.get_block(1).finalized is False


def test_failed_apply_after_bft_finalization_reconciles_in_memory_fence():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (storage, bc):
        validators = [Wallet.generate() for _ in range(3)]
        for wallet in validators:
            storage.set_role(wallet.address, "investor", 100.0)
        block = _mine_block(bc, Wallet.generate())
        block.validator_sigs = [_vote(wallet, block.block_hash) for wallet in validators]

        def fail_after_finality(*_args, **_kwargs):
            raise RuntimeError("injected after BFT finalization")

        bc.mempool.clear_confirmed = fail_after_finality
        with pytest.raises(RuntimeError, match="injected after BFT finalization"):
            bc.apply_block(block)

        assert storage.get_block(1) is None
        assert storage.get_validator_votes_at_height(1) == []
        assert bc._highest_finalized_height == 0
        assert block.finalized is False
