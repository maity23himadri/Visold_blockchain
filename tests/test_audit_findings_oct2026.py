"""Regression tests for the confirmed October 2026 audit findings."""

from __future__ import annotations

import os
import tempfile
import time
from contextlib import contextmanager

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


@contextmanager
def _fast_chain(td: str):
    original_min = Config.MIN_DIFFICULTY
    original_init = Config.INITIAL_DIFFICULTY
    Config.MIN_DIFFICULTY = 0.001
    Config.INITIAL_DIFFICULTY = 0.001
    try:
        st = Storage(os.path.join(td, "regression.db"))
        yield st, Blockchain(st)
    finally:
        Config.MIN_DIFFICULTY = original_min
        Config.INITIAL_DIFFICULTY = original_init


def _mined_block(bc: Blockchain, txs: list[Transaction], miner: str, height: int) -> Block:
    txs = list(txs)
    state_root = bc.dry_run_state_root(txs, miner, height)
    prev = bc.latest_block()
    block = Block(
        index=height,
        prev_hash=prev.block_hash if prev else "0" * 64,
        transactions=txs,
        miner_address=miner,
        difficulty=bc.get_difficulty(),
        state_root=state_root,
    )
    assert block.mine()
    return block


def test_slashed_validator_unregister_does_not_unslash_or_reregister_in_same_block():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (st, bc):
        owner = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(owner.address, 50 * Config.SATOSHI_PER_VSD)
        st.set_role(owner.address, "miner", 20.0)
        st.slash(owner.address)
        before = dict(st.get_role(owner.address))
        assert before["slashed"] == 1

        unregister = Transaction(
            sender=owner.address,
            receiver="",
            amount=0.0,
            fee=Config.MIN_TX_FEE_SAT / Config.SATOSHI_PER_VSD,
            memo="none",
            nonce=st.get_nonce(owner.address),
            tx_type=Transaction.TYPE_REGISTER,
        )
        unregister.sign(owner)

        reregister = Transaction(
            sender=owner.address,
            receiver="",
            amount=1.0,
            fee=Config.TX_FEE_RATE,
            memo="miner",
            nonce=unregister.nonce + 1,
            tx_type=Transaction.TYPE_REGISTER,
        )
        reregister.sign(owner)

        coinbase = Transaction.coinbase(
            miner.address,
            bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
            1,
        )
        block = _mined_block(
            bc, [coinbase, unregister, reregister], miner.address, height=1
        )

        ok, msg = bc.validate_block(block)
        assert ok, msg
        ok, msg = bc.apply_block(block)
        assert ok, msg

        role = st.get_role(owner.address)
        assert role is not None
        assert role["role"] == "none"
        assert role["slashed"] == 1


def test_slashed_validator_cannot_reregister_after_unregister():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (st, bc):
        owner = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(owner.address, 50 * Config.SATOSHI_PER_VSD)
        st.set_role(owner.address, "miner", 20.0)
        st.slash(owner.address)

        unregister = Transaction(
            sender=owner.address,
            receiver="",
            amount=0.0,
            fee=Config.MIN_TX_FEE_SAT / Config.SATOSHI_PER_VSD,
            memo="none",
            nonce=st.get_nonce(owner.address),
            tx_type=Transaction.TYPE_REGISTER,
        )
        unregister.sign(owner)
        b1 = _mined_block(
            bc,
            [Transaction.coinbase(miner.address, bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD, 1), unregister],
            miner.address,
            height=1,
        )
        ok, msg = bc.apply_block(b1)
        assert ok, msg
        role = st.get_role(owner.address)
        assert role is not None and role["role"] == "none" and role["slashed"] == 1

        reregister = Transaction(
            sender=owner.address,
            receiver="",
            amount=1.0,
            fee=1.0 * Config.TX_FEE_RATE,
            memo="miner",
            nonce=st.get_nonce(owner.address),
            tx_type=Transaction.TYPE_REGISTER,
        )
        reregister.sign(owner)
        b2 = _mined_block(
            bc,
            [Transaction.coinbase(miner.address, bc.compute_reward_sat(2) / Config.SATOSHI_PER_VSD, 2), reregister],
            miner.address,
            height=2,
        )
        ok, msg = bc.validate_block(b2)
        assert ok, msg
        ok, msg = bc.apply_block(b2)
        assert ok, msg

        role = st.get_role(owner.address)
        assert role is not None
        assert role["role"] == "none"
        assert role["slashed"] == 1
        assert owner.address not in {m["address"] for m in st.get_all_by_role("miner")}


def test_coinbase_amount_must_equal_canonical_subsidy_exactly():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (st, bc):
        miner = Wallet.generate()
        expected = bc.compute_reward_sat(1)

        for amount_sat in (expected - 1, expected + 1):
            coinbase = Transaction.coinbase(
                miner.address,
                amount_sat / Config.SATOSHI_PER_VSD,
                1,
            )
            block = _mined_block(bc, [coinbase], miner.address, height=1)
            ok, msg = bc.validate_block(block)
            assert not ok
            assert "does not match required subsidy" in msg


def test_coinbase_subsidy_excludes_transaction_fees_from_new_issuance():
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (st, bc):
        sender = Wallet.generate()
        receiver = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(sender.address, 5 * Config.SATOSHI_PER_VSD)

        tx = Transaction(
            sender=sender.address,
            receiver=receiver.address,
            amount=1.0,
            fee=Config.TX_FEE_RATE,
            nonce=st.get_nonce(sender.address),
        )
        tx.sign(sender)
        coinbase = Transaction.coinbase(
            miner.address,
            bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
            1,
        )
        block = _mined_block(bc, [coinbase, tx], miner.address, height=1)
        ok, msg = bc.validate_block(block)
        assert ok, msg


def test_invalid_high_difficulty_deep_fork_cannot_destroy_canonical_state():
    """An invalid peer fork may win preliminary work ranking, but must be harmless.

    This reproduces the confirmed defect from the 2026-10-06 audit: an attacker
    supplied difficulty=64 on an otherwise invalid genesis-level fork, causing
    accept_chain() to hard-reset the local chain before the first peer block was
    validated.  The fixed reorg path must restore the complete old canonical
    suffix when the peer block fails validation.
    """
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (st, bc):
        miner = Wallet.generate()
        coinbase = Transaction.coinbase(
            miner.address,
            bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
            1,
        )
        local_block = _mined_block(bc, [coinbase], miner.address, height=1)
        ok, msg = bc.apply_block(local_block)
        assert ok, msg

        before_height = bc.height()
        before_hash = st.get_block(1).block_hash
        before_balance = st.get_balance_sat(miner.address)
        before_genesis_hash = st.get_block(0).block_hash
        before_issued = st.get_cumulative_issued_sat()

        # Structurally self-consistent, but intentionally wrong genesis:
        # changing only miner_address changes the committed block hash while
        # leaving the transaction/merkle data internally consistent.  The
        # canonical genesis hash check must reject it.
        canonical_genesis = st.get_block(0)
        fake_genesis = Block(
            index=canonical_genesis.index,
            prev_hash=canonical_genesis.prev_hash,
            transactions=list(canonical_genesis.transactions),
            miner_address=miner.address,
            difficulty=canonical_genesis.difficulty,
            timestamp=canonical_genesis.timestamp,
            nonce=canonical_genesis.nonce,
            state_root=canonical_genesis.state_root,
            protocol_version=canonical_genesis.protocol_version,
        ).seal()
        assert fake_genesis.block_hash != canonical_genesis.block_hash

        # The remaining attacker blocks claim enormous PoW difficulty. They do
        # not need valid PoW for this regression because the fake genesis must
        # be rejected first; the point is that their untrusted difficulty must
        # not be allowed to justify a destructive reset.
        fake_block_1 = Block(
            index=1,
            prev_hash=fake_genesis.block_hash,
            transactions=[],
            miner_address=miner.address,
            difficulty=float(Config.MAX_DIFFICULTY),
            timestamp=canonical_genesis.timestamp + 1,
        ).seal()
        fake_block_2 = Block(
            index=2,
            prev_hash=fake_block_1.block_hash,
            transactions=[],
            miner_address=miner.address,
            difficulty=float(Config.MAX_DIFFICULTY),
            timestamp=canonical_genesis.timestamp + 2,
        ).seal()

        ok, msg = bc.accept_chain([fake_genesis, fake_block_1, fake_block_2])
        assert not ok
        assert "peer genesis does not match" in msg

        # The failed peer fork must leave canonical state exactly where it was.
        assert bc.height() == before_height
        assert st.get_block(0).block_hash == before_genesis_hash
        assert st.get_block(1).block_hash == before_hash
        assert st.get_balance_sat(miner.address) == before_balance
        assert st.get_cumulative_issued_sat() == before_issued



def test_invalid_high_difficulty_replacement_block_is_rolled_back_without_state_loss():
    """A bad block after canonical genesis may trigger tentative reorg work
    but must restore the complete old suffix when validation fails.
    """
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (st, bc):
        miner = Wallet.generate()
        coinbase = Transaction.coinbase(
            miner.address,
            bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
            1,
        )
        local_block = _mined_block(bc, [coinbase], miner.address, height=1)
        ok, msg = bc.apply_block(local_block)
        assert ok, msg

        genesis = st.get_block(0)
        # Same canonical genesis establishes common_height=0.  The attacker
        # then supplies a structurally valid block header claiming difficulty
        # 64 but with no coinbase/valid PoW, so validation must reject it.
        bad_block_1 = Block(
            index=1,
            prev_hash=genesis.block_hash,
            transactions=[],
            miner_address=miner.address,
            difficulty=float(Config.MAX_DIFFICULTY),
            timestamp=genesis.timestamp + 1,
        ).seal()
        bad_block_2 = Block(
            index=2,
            prev_hash=bad_block_1.block_hash,
            transactions=[],
            miner_address=miner.address,
            difficulty=float(Config.MAX_DIFFICULTY),
            timestamp=genesis.timestamp + 2,
        ).seal()

        before_height = bc.height()
        before_block_hash = st.get_block(1).block_hash
        before_balance = st.get_balance_sat(miner.address)
        before_issued = st.get_cumulative_issued_sat()

        ok, msg = bc.accept_chain([genesis, bad_block_1, bad_block_2])
        assert not ok
        assert "Reorg apply block 1" in msg

        assert bc.height() == before_height
        assert st.get_block(0).block_hash == genesis.block_hash
        assert st.get_block(1).block_hash == before_block_hash
        assert st.get_balance_sat(miner.address) == before_balance
        assert st.get_cumulative_issued_sat() == before_issued



def test_invalid_deep_fork_restores_state_after_partial_reorg_application():
    """A peer chain that fails after one replacement block must be fully undone."""
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (st_a, bc_a):
        miner_a = Wallet.generate()
        coinbase_a = Transaction.coinbase(
            miner_a.address,
            bc_a.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
            1,
        )
        local_block = _mined_block(
            bc_a, [coinbase_a], miner_a.address, height=1
        )
        ok, msg = bc_a.apply_block(local_block)
        assert ok, msg

        before = {
            "height": bc_a.height(),
            "tip": st_a.get_block(1).block_hash,
            "balance": st_a.get_balance_sat(miner_a.address),
            "issued": st_a.get_cumulative_issued_sat(),
        }

        # Build a genuinely valid competing block 1 from an independent node
        # sharing the same canonical genesis.  This ensures reorg() applies at
        # least one new block before the later malicious block fails.
        st_b = Storage(os.path.join(td, "peer.db"))
        bc_b = Blockchain(st_b)
        miner_b = Wallet.generate()
        coinbase_b = Transaction.coinbase(
            miner_b.address,
            bc_b.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
            1,
        )
        peer_block_1 = _mined_block(
            bc_b, [coinbase_b], miner_b.address, height=1
        )
        ok, msg = bc_b.apply_block(peer_block_1)
        assert ok, msg

        # Block 2 claims very high work but is invalid (no required coinbase),
        # so the tentative reorg must roll peer_block_1 back and restore the
        # exact original canonical block 1 and derived state.
        peer_block_2 = Block(
            index=2,
            prev_hash=peer_block_1.block_hash,
            transactions=[],
            miner_address=miner_b.address,
            difficulty=float(Config.MAX_DIFFICULTY),
            timestamp=peer_block_1.timestamp + 1,
        ).seal()

        payload = [st_b.get_block(0), peer_block_1, peer_block_2]
        ok, msg = bc_a.accept_chain(payload)
        assert not ok
        assert "Reorg apply block 2" in msg

        assert bc_a.height() == before["height"]
        assert st_a.get_block(1).block_hash == before["tip"]
        assert st_a.get_balance_sat(miner_a.address) == before["balance"]
        assert st_a.get_cumulative_issued_sat() == before["issued"]


def test_valid_deep_no_investor_fork_still_adopts_heavier_chain():
    """The safety fix must not disable the intended PoW-only deep-fork path."""
    with tempfile.TemporaryDirectory() as td, _fast_chain(td) as (st_a, bc_a):
        st_b = Storage(os.path.join(td, "peer.db"))
        bc_b = Blockchain(st_b)
        miner_a = Wallet.generate()
        miner_b = Wallet.generate()
        base_ts = int(time.time())

        def mine_on(bc: Blockchain, miner: Wallet, height: int) -> None:
            ts = base_ts + height * 3
            tx = Transaction.coinbase(
                miner.address,
                bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
                height,
            )
            difficulty = bc.get_difficulty()
            root = bc.dry_run_state_root(
                [tx], miner.address, height, timestamp=ts, difficulty=difficulty
            )
            prev = bc.latest_block()
            block = Block(
                index=height,
                prev_hash=prev.block_hash if prev else "0" * 64,
                transactions=[tx],
                miner_address=miner.address,
                difficulty=difficulty,
                timestamp=ts,
                state_root=root,
            )
            assert block.mine()
            ok, msg = bc.apply_block(block)
            assert ok, msg

        # Bootstrap finality uses a 20-block PoW depth.  With A at 21 and B at
        # 22, A has finalized height 1, so the replacement crosses the ordinary
        # finality fence and must use the explicit no-investor exception.
        for h in range(1, 22):
            mine_on(bc_a, miner_a, h)
        for h in range(1, 23):
            mine_on(bc_b, miner_b, h)

        assert bc_a._highest_finalized_height >= 1
        payload = [st_b.get_block(h) for h in range(0, 23)]
        ok, msg = bc_a.accept_chain(payload)
        assert ok, msg
        assert bc_a.height() == 22
        assert st_a.get_block(22).block_hash == st_b.get_block(22).block_hash
