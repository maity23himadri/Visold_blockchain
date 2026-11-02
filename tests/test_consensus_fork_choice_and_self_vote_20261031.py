"""Regression tests for two consensus bugs (October 2026 review).

1. Self-equivocation on a normal one-block reorg. A validator that voted for
   block A must not sign a sibling B at the same height. Previously it did,
   add_validator_sig() recorded a double-sign, and the local stake penalty
   diverged its reward split. Its next block was then rejected with
   state_root mismatch.

2. Fork choice must depend on cumulative work alone. A shorter branch with more
   work has to win on every node, and equal work resolves by the same tip-hash
   rule on every node.

These tests use the real Blockchain + Storage paths with fast difficulty.
"""
from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


@contextmanager
def _fast_config():
    names = (
        "MIN_DIFFICULTY", "INITIAL_DIFFICULTY", "MIN_VALIDATORS_FOR_BFT",
        "POW_FINALITY_DEPTH", "BOOTSTRAP_POW_FINALITY_DEPTH",
        "AUTO_SLASH_EVIDENCE",
    )
    old = {key: getattr(Config, key) for key in names}
    Config.MIN_DIFFICULTY = 0.001
    Config.INITIAL_DIFFICULTY = 0.001
    Config.MIN_VALIDATORS_FOR_BFT = 3
    Config.POW_FINALITY_DEPTH = 50
    Config.BOOTSTRAP_POW_FINALITY_DEPTH = 50
    Config.AUTO_SLASH_EVIDENCE = False
    try:
        yield
    finally:
        for key, value in old.items():
            setattr(Config, key, value)


def _build(bc: Blockchain, miner: Wallet, ts_bump: int) -> Block:
    """Mine the next block on bc's tip. ts_bump varies the hash deterministically."""
    height = bc.height() + 1
    coinbase = Transaction.coinbase(
        miner.address,
        bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
        height,
    )
    txs = [coinbase]
    root = bc.dry_run_state_root(txs, miner.address, height)
    prev = bc.latest_block()
    block = Block(
        index=height,
        prev_hash=prev.block_hash,
        transactions=txs,
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        timestamp=int(prev.timestamp) + ts_bump,
        state_root=root,
    )
    assert block.mine(), f"failed to mine block #{height}"
    return block


def _grow(bc: Blockchain, count: int, ts_bump: int) -> list:
    miner = Wallet.generate()
    blocks = []
    for _ in range(count):
        block = _build(bc, miner, ts_bump)
        ok, message = bc.apply_block(block)
        assert ok, message
        blocks.append(block)
    return blocks


def test_validator_does_not_self_equivocate_on_one_block_reorg():
    with _fast_config(), tempfile.TemporaryDirectory() as td:
        st1 = Storage(os.path.join(td, "validator.db"))
        bc1 = Blockchain(st1)
        st2 = Storage(os.path.join(td, "network.db"))
        bc2 = Blockchain(st2)
        me = Wallet.generate()
        others = [Wallet.generate(), Wallet.generate()]
        for st in (st1, st2):
            st.set_role(me.address, "investor", 100.0)
            for other in others:
                st.set_role(other.address, "investor", 100.0)
        engine = ConsensusEngine(bc1, me)

        block_a = _build(bc1, Wallet.generate(), 1)
        block_b = None
        for i in range(2, 400):
            candidate = _build(bc1, Wallet.generate(), i)
            if candidate.block_hash < block_a.block_hash:
                block_b = candidate
                break
        assert block_b is not None, "could not find a lower-hash sibling"

        # The validator sees A first and votes for it.
        ok, message = bc1.apply_block(block_a)
        assert ok, message
        assert engine.finalize_applied_block(block_a) == (True, "OK")

        # The network's winning sibling B takes over at the same height.
        genesis = st1.get_block(0)
        ok, message = bc1.accept_chain([genesis, block_b])
        assert ok, message
        assert st1.get_block_hash(1) == block_b.block_hash
        assert engine.finalize_applied_block(block_b) == (True, "OK")

        # It must not sign B: no vote for B at height 1, and no slash.
        votes = st1.get_validator_votes_at_height(1)
        own = {row["block_hash"] for row in votes
               if row["validator_addr"] == me.address}
        assert own == {block_a.block_hash}
        role = st1.get_role(me.address)
        assert not bool(role["slashed"])
        assert role["stake"] == 100.0

        # The validator's reward split must still match the network, so the
        # next honest block (built on B by the network) is accepted here too.
        ok, message = bc2.apply_block(block_b)
        assert ok, message
        next_block = _build(bc2, Wallet.generate(), 5)
        ok, message = bc2.validate_block(next_block)
        assert ok, message
        ok, message = bc1.apply_block(next_block)
        assert ok, f"validator rejected valid network block: {message}"
        assert bc1.height() == 2


def test_shorter_heavier_branch_wins_on_both_nodes():
    with _fast_config(), tempfile.TemporaryDirectory() as td:
        node_x = Blockchain(Storage(os.path.join(td, "x.db")))  # slow blocks, low difficulty
        node_y = Blockchain(Storage(os.path.join(td, "y.db")))  # fast blocks, rising difficulty
        chain_x = _grow(node_x, 9, 300)
        chain_y = _grow(node_y, 7, 1)
        work_x = node_x._cumulative_difficulty(chain_x)
        work_y = node_y._cumulative_difficulty(chain_y)
        # Precondition for the scenario: Y is shorter but strictly heavier.
        assert len(chain_y) < len(chain_x)
        assert work_y > work_x

        genesis = node_x.storage.get_block(0)
        ok, message = node_x.accept_chain([genesis] + chain_y)
        assert ok, message
        # The lighter, longer chain must be refused by the heavier node.
        ok, _message = node_y.accept_chain([genesis] + chain_x)
        assert not ok

        assert node_x.height() == node_y.height() == 7
        for height in range(0, 8):
            assert (node_x.storage.get_block_hash(height)
                    == node_y.storage.get_block_hash(height))


def test_equal_work_tiebreak_is_independent_of_height():
    """Equal cumulative work resolves by tip hash, whatever the tip heights.

    Old rule: a taller equal-work branch was accepted on one node and refused
    by height on the other, so the nodes stayed split. Work is pinned equal
    here so that only the decision rule is exercised. Real retargeting would
    not produce exactly equal work across different heights.
    """
    from decimal import Decimal

    with _fast_config(), tempfile.TemporaryDirectory() as td:
        node_tall = Blockchain(Storage(os.path.join(td, "tall.db")))
        node_tall._cumulative_difficulty = lambda _blocks: Decimal(1)
        tall_branch = _grow(node_tall, 4, 1)    # taller: heights 1..4
        genesis = node_tall.storage.get_block(0)

        # Force the shorter branch to have the LOWER tip hash. Then the old
        # height gate and the new hash rule disagree, which is what this test
        # has to catch. Each attempt uses fresh random miners, so the hash varies.
        node_short = None
        short_branch = None
        for attempt in range(200):
            candidate_node = Blockchain(
                Storage(os.path.join(td, f"short-{attempt}.db")))
            candidate_node._cumulative_difficulty = lambda _blocks: Decimal(1)
            candidate_branch = _grow(candidate_node, 2, 2)  # shorter: heights 1..2
            if candidate_branch[-1].block_hash < tall_branch[-1].block_hash:
                node_short, short_branch = candidate_node, candidate_branch
                break
        assert node_short is not None, "could not find a lower-hash shorter branch"
        final_tip = short_branch[-1].block_hash

        # Deliver each branch to the other node, in both directions.
        node_tall.accept_chain([genesis] + short_branch)
        node_short.accept_chain([genesis] + tall_branch)

        # Both nodes end on the same chain, and it is the lower-hash tip.
        tall_tip = node_tall.storage.get_block_hash(node_tall.height())
        short_tip = node_short.storage.get_block_hash(node_short.height())
        assert tall_tip == short_tip == final_tip
