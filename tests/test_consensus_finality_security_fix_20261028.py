"""Regression tests for BFT vote authentication, N+1 activation and reorg finality.

These tests use the real Storage/Blockchain/ConsensusEngine code paths.  The
reorg test deliberately corrupts only the final candidate block's committed
state_root after mining, so previous replacement blocks are valid and can
exercise the exact finality-side-effect rollback path.
"""
from __future__ import annotations

import os
import tempfile
import time

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.consensus.difficulty import DifficultyEngine
from visold.crypto.ecc import sig_to_hex
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _mine_block(bc: Blockchain, miner: Wallet, extra_txs=(), *, bad_root=False) -> Block:
    height = bc.height() + 1
    coinbase = Transaction.coinbase(
        miner.address,
        bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
        height,
    )
    txs = [coinbase, *list(extra_txs)]
    root = bc.dry_run_state_root(txs, miner.address, height)
    if bad_root:
        root = "f" * 64 if root != "f" * 64 else "e" * 64
    prev = bc.latest_block()
    block = Block(
        index=height,
        prev_hash=prev.block_hash,
        transactions=txs,
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        timestamp=max(int(time.time()), int(prev.timestamp) + 1),
        state_root=root,
    )
    assert block.mine(), f"failed to mine test block #{height}"
    return block


def _signed_vote(wallet: Wallet, block: Block) -> dict:
    return {
        "addr": wallet.address,
        "sig": sig_to_hex(wallet.sign(block.block_hash.encode("utf-8"))),
        "pub": wallet.pub_hex,
    }


def _config_patch(**values):
    old = {key: getattr(Config, key) for key in values}
    for key, value in values.items():
        setattr(Config, key, value)
    return old


def _restore_config(old):
    for key, value in old.items():
        setattr(Config, key, value)


def test_fabricated_embedded_votes_are_ignored_and_do_not_finalize_block():
    old = _config_patch(
        MIN_DIFFICULTY=0.001,
        INITIAL_DIFFICULTY=0.001,
        MIN_VALIDATORS_FOR_BFT=3,
        POW_FINALITY_DEPTH=50,
        BOOTSTRAP_POW_FINALITY_DEPTH=50,
    )
    try:
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(os.path.join(td, "fake-votes.db"))
            bc = Blockchain(storage)
            validators = [Wallet.generate() for _ in range(3)]
            for wallet in validators:
                storage.set_role(wallet.address, "investor", 100.0)

            miner = Wallet.generate()
            block = _mine_block(bc, miner)
            block.validator_sigs = [
                {"addr": wallet.address, "sig": "not-a-signature", "pub": "not-a-public-key"}
                for wallet in validators
            ]

            ok, message = bc.apply_block(block)
            assert ok, message
            stored = storage.get_block(1)
            assert stored is not None
            assert stored.finalized is False
            assert stored.validator_sigs == []
            assert bc._highest_finalized_height == 0
            eligible = bc.get_validator_set_for_block(stored)
            assert eligible is not None
            assert {item["address"] for item in eligible} == {
                wallet.address for wallet in validators
            }
    finally:
        _restore_config(old)


def test_genuine_embedded_votes_still_finalize_and_invalid_votes_cannot_add_weight():
    old = _config_patch(
        MIN_DIFFICULTY=0.001,
        INITIAL_DIFFICULTY=0.001,
        MIN_VALIDATORS_FOR_BFT=3,
        POW_FINALITY_DEPTH=50,
        BOOTSTRAP_POW_FINALITY_DEPTH=50,
    )
    try:
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(os.path.join(td, "valid-votes.db"))
            bc = Blockchain(storage)
            validators = [Wallet.generate() for _ in range(3)]
            for wallet in validators:
                storage.set_role(wallet.address, "investor", 100.0)

            miner = Wallet.generate()
            block = _mine_block(bc, miner)
            block.validator_sigs = [_signed_vote(w, block) for w in validators]
            block.validator_sigs.append({
                "addr": Wallet.generate().address,
                "sig": "fabricated",
                "pub": "fabricated",
            })

            ok, message = bc.apply_block(block)
            assert ok, message
            stored = storage.get_block(1)
            assert stored is not None and stored.finalized is True
            assert len(stored.validator_sigs) == 3
            assert {vote["addr"] for vote in stored.validator_sigs} == {
                wallet.address for wallet in validators
            }
            assert bc._highest_finalized_height == 1
            # Signature verification is also mandatory for live votes, even
            # when the target block is already finalized (the fast path must
            # not accidentally accept malformed vote envelopes).
            assert bc.add_validator_sig(
                stored.block_hash, validators[0].address,
                "not-a-valid-signature", validators[0].pub_hex,
            ) is False
    finally:
        _restore_config(old)


def test_invalid_embedded_votes_cannot_supply_the_missing_quorum_weight():
    old = _config_patch(
        MIN_DIFFICULTY=0.001,
        INITIAL_DIFFICULTY=0.001,
        MIN_VALIDATORS_FOR_BFT=3,
        POW_FINALITY_DEPTH=50,
        BOOTSTRAP_POW_FINALITY_DEPTH=50,
    )
    try:
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(os.path.join(td, "partial-votes.db"))
            bc = Blockchain(storage)
            validators = [Wallet.generate() for _ in range(4)]
            for wallet in validators:
                storage.set_role(wallet.address, "investor", 100.0)

            block = _mine_block(bc, Wallet.generate())
            block.validator_sigs = [
                _signed_vote(wallet, block) for wallet in validators[:2]
            ] + [
                {"addr": wallet.address, "sig": "forged", "pub": "forged"}
                for wallet in validators[2:]
            ]
            ok, message = bc.apply_block(block)
            assert ok, message
            stored = storage.get_block(1)
            assert stored is not None and not stored.finalized
            assert {vote["addr"] for vote in stored.validator_sigs} == {
                wallet.address for wallet in validators[:2]
            }
            assert bc._highest_finalized_height == 0
    finally:
        _restore_config(old)


def test_new_investor_cannot_vote_on_registration_block_but_can_vote_next_block():
    old = _config_patch(
        MIN_DIFFICULTY=0.001,
        INITIAL_DIFFICULTY=0.001,
        MIN_VALIDATORS_FOR_BFT=3,
        POW_FINALITY_DEPTH=50,
        BOOTSTRAP_POW_FINALITY_DEPTH=50,
    )
    try:
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(os.path.join(td, "activation-height.db"))
            bc = Blockchain(storage)
            existing = [Wallet.generate() for _ in range(2)]
            for wallet in existing:
                storage.set_role(wallet.address, "investor", 200.0)

            newcomer = Wallet.generate()
            storage.credit_sat(newcomer.address, 1_100 * Config.SATOSHI_PER_VSD)
            register = Transaction(
                sender=newcomer.address,
                receiver="",
                amount=1_000.0,
                fee=max(
                    1_000.0 * Config.TX_FEE_RATE,
                    Config.MIN_TX_FEE_SAT / Config.SATOSHI_PER_VSD,
                ),
                memo="investor",
                nonce=storage.get_nonce(newcomer.address),
                tx_type=Transaction.TYPE_REGISTER,
            )
            register.sign(newcomer)
            registration_block = _mine_block(bc, Wallet.generate(), [register])
            # This is a valid signature from the newcomer, but the validator
            # set before block N contains only the two existing validators.
            registration_block.validator_sigs = [_signed_vote(newcomer, registration_block)]
            ok, message = bc.apply_block(registration_block)
            assert ok, message

            stored_n = storage.get_block(registration_block.index)
            assert stored_n is not None and stored_n.finalized is False
            assert newcomer.address not in {
                item["address"] for item in bc.get_validator_set_for_block(stored_n)
            }
            assert storage.get_role(newcomer.address)["role"] == "investor"
            assert bc.add_validator_sig(
                stored_n.block_hash,
                newcomer.address,
                _signed_vote(newcomer, stored_n)["sig"],
                newcomer.pub_hex,
            ) is False
            # The normal post-application finalizer must obey the same set.
            ok, message = ConsensusEngine(bc, newcomer).finalize_applied_block(stored_n)
            assert ok, message
            assert all(
                vote["validator_addr"] != newcomer.address
                for vote in storage.get_validator_votes_at_height(stored_n.index)
            )

            next_block = _mine_block(bc, Wallet.generate())
            ok, message = bc.apply_block(next_block)
            assert ok, message
            stored_next = storage.get_block(next_block.index)
            assert stored_next is not None
            eligible_next = bc.get_validator_set_for_block(stored_next)
            assert eligible_next is not None
            assert newcomer.address in {item["address"] for item in eligible_next}

            ok, message = ConsensusEngine(bc, newcomer).finalize_applied_block(stored_next)
            assert ok, message
            assert any(
                vote["validator_addr"] == newcomer.address
                and vote["block_hash"] == stored_next.block_hash
                for vote in storage.get_validator_votes_at_height(stored_next.index)
            )
            assert storage.get_block(stored_next.index).finalized is True
    finally:
        _restore_config(old)


def test_failed_reorg_does_not_leave_finality_from_discarded_replacement_branch():
    old = _config_patch(
        MIN_DIFFICULTY=0.001,
        INITIAL_DIFFICULTY=0.001,
        MIN_VALIDATORS_FOR_BFT=3,
        POW_FINALITY_DEPTH=1,
        BOOTSTRAP_POW_FINALITY_DEPTH=50,
    )
    try:
        with tempfile.TemporaryDirectory() as td:
            main_storage = Storage(os.path.join(td, "main.db"))
            main = Blockchain(main_storage)
            miner = Wallet.generate()

            # Create the existing canonical chain while its bootstrap depth is
            # large, leaving only genesis finalized.
            main_blocks = []
            first = _mine_block(main, miner)
            assert main.apply_block(first)[0]
            main_blocks.append(first)
            side_storage = Storage(os.path.join(td, "side.db"))
            side = Blockchain(side_storage)
            assert side.apply_block(Block.from_dict(first.to_dict()))[0]

            for _ in range(3):
                candidate = _mine_block(main, miner)
                ok, message = main.apply_block(candidate)
                assert ok, message
                main_blocks.append(candidate)

            # Construct an alternate branch from the common height-1 block.
            # Make the candidate longer so fork choice accepts it; the last
            # block has valid PoW/header but a deliberately incorrect state root.
            DifficultyEngine.invalidate_cache(from_height=2)
            alt_blocks = []
            for _ in range(3):
                candidate = _mine_block(side, Wallet.generate())
                ok, message = side.apply_block(candidate)
                assert ok, message
                alt_blocks.append(candidate)
            final_bad = _mine_block(side, Wallet.generate(), bad_root=True)
            alt_blocks.append(final_bad)
            assert side.height() == 4

            # Enable the shallow depth at runtime only after the old branch was
            # built. Without deferred finality, applying the first three new
            # blocks would finalize heights 1..3 before the last block fails.
            Config.BOOTSTRAP_POW_FINALITY_DEPTH = 1
            pre_fence = main._highest_finalized_height
            pre_flags = {
                idx: bool(main_storage.get_block(idx).finalized)
                for idx in range(2, main.height() + 1)
            }
            assert pre_fence == 0
            assert all(flag is False for flag in pre_flags.values())
            main._cumulative_difficulty = lambda chain: float(len(chain))

            ok, message = main.reorg(alt_blocks)
            assert not ok
            assert "state_root" in message.lower()
            assert main.height() == 4
            assert main.latest_block().block_hash == main_storage.get_block(4).block_hash
            assert main._highest_finalized_height == pre_fence
            for idx, flag in pre_flags.items():
                restored = main_storage.get_block(idx)
                assert restored is not None
                assert restored.finalized is flag
            # The abandoned branch's height-scoped validator snapshots must not
            # leak into the restored canonical suffix.
            for idx in range(2, main.height() + 1):
                stored = main_storage.get_block(idx)
                snap = main_storage.get_block_validator_snapshot(idx, stored.block_hash)
                assert snap is not None
    finally:
        _restore_config(old)
        DifficultyEngine.invalidate_cache(from_height=0)


def test_successful_reorg_commits_branch_then_recomputes_pow_finality():
    old = _config_patch(
        MIN_DIFFICULTY=0.001,
        INITIAL_DIFFICULTY=0.001,
        MIN_VALIDATORS_FOR_BFT=3,
        POW_FINALITY_DEPTH=1,
        BOOTSTRAP_POW_FINALITY_DEPTH=50,
    )
    try:
        with tempfile.TemporaryDirectory() as td:
            main_storage = Storage(os.path.join(td, "success-main.db"))
            main = Blockchain(main_storage)
            miner = Wallet.generate()
            first = _mine_block(main, miner)
            assert main.apply_block(first)[0]

            side_storage = Storage(os.path.join(td, "success-side.db"))
            side = Blockchain(side_storage)
            assert side.apply_block(Block.from_dict(first.to_dict()))[0]

            for _ in range(3):
                candidate = _mine_block(main, miner)
                ok, message = main.apply_block(candidate)
                assert ok, message

            DifficultyEngine.invalidate_cache(from_height=2)
            replacement = []
            for _ in range(4):
                candidate = _mine_block(side, Wallet.generate())
                ok, message = side.apply_block(candidate)
                assert ok, message
                replacement.append(candidate)

            # The replacement has a greater tip height, but its finality must
            # be committed only once the entire replacement has succeeded.
            # Mirror the network configuration change used in the failed-reorg
            # test: bootstrap depth becomes shallow only for finality commit.
            Config.BOOTSTRAP_POW_FINALITY_DEPTH = 1
            main._cumulative_difficulty = lambda chain: float(len(chain))
            ok, message = main.reorg(replacement)
            assert ok, message
            assert main.height() == 5
            assert main.latest_block().block_hash == replacement[-1].block_hash
            # At depth 1, heights 1..4 are now finalized on the adopted chain;
            # the tip is not yet finalized. The fence must match canonical flags.
            for idx in range(1, 5):
                stored = main_storage.get_block(idx)
                assert stored is not None and stored.finalized
            tip = main_storage.get_block(5)
            assert tip is not None and not tip.finalized
            assert main._highest_finalized_height == 4
            for candidate in replacement:
                stored = main_storage.get_block(candidate.index)
                assert stored is not None and stored.block_hash == candidate.block_hash
                assert main_storage.get_block_validator_snapshot(
                    candidate.index, candidate.block_hash) is not None
    finally:
        _restore_config(old)
        DifficultyEngine.invalidate_cache(from_height=0)
