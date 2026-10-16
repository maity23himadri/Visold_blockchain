"""Regression tests for audit findings VSA-21, VSA-22, VSA-25 and VSA-26."""

from __future__ import annotations

import os
import tempfile
import time

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = Config.SATOSHI_PER_VSD
FAR_EXPIRY = 2_000_000_000


def _chain(td: str, name: str):
    st = Storage(os.path.join(td, name))
    return st, Blockchain(st)


def _coinbase(bc, miner, height):
    return Transaction.coinbase(
        miner.address, bc.compute_reward_sat(height) / SAT, height)


def _extend(bc, miner, timestamps):
    """Mine and apply one coinbase block per timestamp, using the DAA difficulty
    required at each height."""
    blocks = []
    for ts in timestamps:
        height = bc.height() + 1
        difficulty = bc.get_difficulty()
        cb = _coinbase(bc, miner, height)
        prev = bc.latest_block()
        root = bc.dry_run_state_root([cb], miner.address, height)
        block = Block(
            index=height,
            prev_hash=prev.block_hash,
            transactions=[cb],
            miner_address=miner.address,
            difficulty=difficulty,
            timestamp=ts,
            state_root=root,
        )
        assert block.mine(), "block failed to mine"
        ok, msg = bc.apply_block(block)
        assert ok, msg
        blocks.append(block)
    return blocks


def _with_bad_root(block, root):
    bad = Block(
        index=block.index,
        prev_hash=block.prev_hash,
        transactions=block.transactions,
        miner_address=block.miner_address,
        difficulty=block.difficulty,
        timestamp=block.timestamp,
        state_root=root,
    )
    assert bad.mine(), "bad-root block failed to mine"
    return bad


def _fork_scenario(td: str, monkeypatch):
    """Shared prefix of two blocks, a local branch at heights 3-4 and a peer branch at
    heights 3-5.  The peer chain is a separate Blockchain over its own storage."""
    monkeypatch.setattr(Config, "DIFF_BOOTSTRAP_BLOCKS", 1)
    # Timestamps are placed in the near future relative to mining time: Block.mine()
    # only advances a timestamp, so a past timestamp would be bumped to 'now' and break
    # the strictly increasing median-time-past sequence this fixture depends on.
    base = int(time.time())
    miner_prefix = Wallet.generate()
    miner_local = Wallet.generate()
    miner_peer = Wallet.generate()
    st, bc = _chain(td, "local.db")
    _pst, pc = _chain(td, "peer.db")

    DifficultyEngine.invalidate_cache(0)
    prefix = _extend(bc, miner_prefix, [base + 600, base + 660])
    for blk in prefix:
        ok, msg = pc.apply_block(blk)
        assert ok, msg

    DifficultyEngine.invalidate_cache(0)
    peer = _extend(pc, miner_peer, [base + 720, base + 780, base + 840])

    # Local suffix is built last, so the shared difficulty cache holds the LOCAL branch's
    # values for the heights the replacement branch will need.
    DifficultyEngine.invalidate_cache(0)
    local = _extend(bc, miner_local, [base + 1020, base + 1380])
    return bc, pc, st, prefix, local, peer, miner_local


# ── VSA-21: branch-dependent difficulty cache ───────────────────────────────

def test_reorg_validates_replacement_against_its_own_branch_difficulty(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        try:
            bc, _pc, _st, _prefix, local, peer, _ml = _fork_scenario(td, monkeypatch)
            assert local[1].difficulty != peer[1].difficulty, (
                "scenario must diverge at height 4 for the cache test to be meaningful")
            ok, msg = bc.reorg(peer)
            assert ok, f"valid replacement branch rejected (VSA-21 stale difficulty): {msg}"
            assert bc.height() == peer[-1].index
            assert bc.latest_block().block_hash == peer[-1].block_hash
        finally:
            DifficultyEngine.invalidate_cache(0)


def test_reorg_with_cold_cache_accepts_the_same_branch(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        try:
            bc, _pc, _st, _prefix, _local, peer, _ml = _fork_scenario(td, monkeypatch)
            DifficultyEngine.invalidate_cache(0)
            ok, msg = bc.reorg(peer)
            assert ok, f"cold-cache control must accept the branch: {msg}"
            assert bc.height() == peer[-1].index
        finally:
            DifficultyEngine.invalidate_cache(0)


# ── VSA-25: reorg below the prune watermark ─────────────────────────────────

def test_reorg_below_prune_watermark_is_refused_before_any_mutation(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        try:
            bc, _pc, st, _prefix, local, peer, miner_local = _fork_scenario(td, monkeypatch)
            monkeypatch.setattr(bc._rolling_pruner, "get_pruned_watermark", lambda: 4)
            root_before = st.compute_state_root()
            balance_before = st.get_balance_sat(miner_local.address)
            # Cold cache isolates VSA-25 from the VSA-21 stale-difficulty failure.
            DifficultyEngine.invalidate_cache(0)

            ok, msg = bc.reorg(peer)

            assert not ok, "reorg below the prune watermark was admitted (VSA-25)"
            assert "watermark" in msg, msg
            assert bc.latest_block().block_hash == local[-1].block_hash
            assert st.compute_state_root() == root_before
            assert st.get_balance_sat(miner_local.address) == balance_before
        finally:
            DifficultyEngine.invalidate_cache(0)


# ── VSA-26: checked restoration and critical recovery state ─────────────────

def _failing_replacement(peer):
    """Replacement chain: peer blocks 3 and 4 are valid; block 5 carries a wrong root,
    so the replacement fails after blocks 3 and 4 have been applied."""
    return [peer[0], peer[1], _with_bad_root(peer[2], "cd" * 32)]


def test_failed_reorg_restores_the_old_chain_exactly(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        try:
            bc, _pc, st, _prefix, local, peer, _ml = _fork_scenario(td, monkeypatch)
            root_before = st.compute_state_root()
            # Cold cache isolates the restoration behaviour from VSA-21.
            DifficultyEngine.invalidate_cache(0)

            ok, _msg = bc.reorg(_failing_replacement(peer))

            assert not ok
            assert bc.latest_block().block_hash == local[-1].block_hash
            assert st.compute_state_root() == root_before
            assert not getattr(bc, "_critical_recovery", None)
        finally:
            DifficultyEngine.invalidate_cache(0)


def test_failed_restoration_marks_critical_recovery_and_refuses_writes(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        try:
            bc, _pc, st, prefix, local, peer, _ml = _fork_scenario(td, monkeypatch)
            real_apply = bc.apply_block
            failing_hash = local[0].block_hash

            def injected_apply(block):
                if block.block_hash == failing_hash:
                    return False, "injected restoration failure"
                return real_apply(block)

            monkeypatch.setattr(bc, "apply_block", injected_apply)
            # Cold cache isolates the restoration check from VSA-21.
            DifficultyEngine.invalidate_cache(0)
            ok, msg = bc.reorg(_failing_replacement(peer))

            assert not ok
            assert "restoration of the old chain failed" in msg, (
                f"a failed restoration must be reported as critical (VSA-26): {msg}")
            assert bc._critical_recovery, "critical recovery state was not recorded"
            assert st.get_meta("chain_recovery_required"), "recovery marker was not persisted"
            refused, refusal = real_apply(prefix[0])
            assert not refused and "operator recovery" in refusal, refusal
        finally:
            DifficultyEngine.invalidate_cache(0)


# ── VSA-22: finalization of a committed block must not re-validate it ───────

def _validator_fixture(monkeypatch, st, bc, voter):
    monkeypatch.setattr(Config, "MIN_VALIDATORS_FOR_BFT", 1)
    monkeypatch.setattr(
        st, "get_all_by_role",
        lambda role: [{"address": voter.address, "stake": 1.0}] if role == "investor" else [])
    monkeypatch.setattr(
        st, "get_role",
        lambda addr: {"role": "investor", "stake": 1.0} if addr == voter.address else None)
    votes = []
    monkeypatch.setattr(
        bc, "add_validator_sig",
        lambda block_hash, addr, sig_hex, pub_hex: votes.append(block_hash) or True)
    return votes


def test_finalization_after_apply_records_one_vote_without_revalidating(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td, "finalize.db")
        voter = Wallet.generate()
        sender = Wallet.generate()
        receiver = Wallet.generate()
        st.credit_sat(sender.address, 10 * SAT)
        height = bc.height() + 1
        cb = _coinbase(bc, voter, height)
        tx = Transaction(
            sender=sender.address,
            receiver=receiver.address,
            amount=1.0,
            fee=1.0 * Config.TX_FEE_RATE,
            nonce=st.get_nonce(sender.address),
            expiry=FAR_EXPIRY,
        )
        tx.sign(sender)
        txs = [cb, tx]
        block = Block(
            index=height,
            prev_hash=bc.latest_block().block_hash,
            transactions=txs,
            miner_address=voter.address,
            difficulty=bc.get_difficulty(),
            state_root=bc.dry_run_state_root(txs, voter.address, height),
        )
        assert block.mine(), "block failed to mine"
        ok, msg = bc.apply_block(block)
        assert ok, msg

        votes = _validator_fixture(monkeypatch, st, bc, voter)
        ok, msg = ConsensusEngine(bc, voter).validate_and_finalize(block)

        assert ok, f"committed block was re-validated against post-state (VSA-22): {msg}"
        assert votes == [block.block_hash], votes


def test_finalization_never_votes_for_a_block_that_is_not_applied(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td, "unapplied.db")
        voter = Wallet.generate()
        height = bc.height() + 1
        cb = _coinbase(bc, voter, height)
        block = Block(
            index=height,
            prev_hash=bc.latest_block().block_hash,
            transactions=[cb],
            miner_address=voter.address,
            difficulty=bc.get_difficulty(),
            state_root=bc.dry_run_state_root([cb], voter.address, height),
        )
        assert block.mine(), "block failed to mine"

        votes = _validator_fixture(monkeypatch, st, bc, voter)
        ConsensusEngine(bc, voter).validate_and_finalize(block)

        assert votes == [], "a vote was cast for a block that was never applied (VSA-22)"
        assert bc.height() == height - 1
