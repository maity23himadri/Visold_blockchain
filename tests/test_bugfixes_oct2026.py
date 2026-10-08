from __future__ import annotations

import os
import threading
import tempfile
from unittest.mock import patch

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _new_chain(td: str):
    st = Storage(os.path.join(td, "bugfix.db"))
    return st, Blockchain(st)


def test_block_validation_uses_fixed_consensus_size_not_local_dynamic_size():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _new_chain(td)
        miner = Wallet.generate()
        cb = Transaction.coinbase(
            miner.address,
            bc.compute_reward(1),
            1,
        )
        # Deliberately make the complete serialized block sit above the
        # low-mempool dynamic cap (1 MiB) but far below the hard 4,096,000-byte
        # consensus cap.
        cb.memo = "x" * (1_080_000)
        cb.tx_id = cb._compute_id()
        prev = bc.latest_block()
        block = Block(
            index=1,
            prev_hash=prev.block_hash,
            transactions=[cb],
            miner_address=miner.address,
            difficulty=bc.get_difficulty(),
            timestamp=prev.timestamp + 1,
        )
        assert block.size() > Config.MIN_BLOCK_SIZE
        assert block.size() < Config.MAX_BLOCK_SIZE

        # Skip cryptographic/PoW work here: this test isolates the size rule.
        block_size_overrides = [0, 2_000]
        for mempool_size in block_size_overrides:
            with patch.object(block, "integrity_check", return_value=(True, "OK")), \
                 patch.object(block, "validate_pow", return_value=True), \
                 patch.object(bc.mempool, "size", return_value=mempool_size):
                ok, msg = bc.validate_block(block)
            assert ok, (mempool_size, msg)


def test_unknown_transaction_type_fails_closed():
    sender = Wallet.generate()
    receiver = Wallet.generate()
    tx = Transaction(
        sender=sender.address,
        receiver=receiver.address,
        amount=1.0,
        fee=0.01,
        nonce=0,
        tx_type="future_type_not_implemented",
        expiry=2_000_000_000,
    )
    tx.sign(sender)
    ok, msg = tx.is_valid(reference_time=1_700_000_000, block_height=1)
    assert not ok
    assert "Unknown transaction type" in msg


def test_unregister_then_reregister_same_block_releases_old_stake_reserve():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _new_chain(td)
        owner = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(owner.address, int(10.2 * Config.SATOSHI_PER_VSD))
        st.set_role(owner.address, "miner", 10.0)

        nonce0 = st.get_nonce(owner.address)
        unstake = Transaction(
            sender=owner.address,
            receiver="",
            amount=0.0,
            fee=Config.MIN_TX_FEE_SAT / Config.SATOSHI_PER_VSD,
            memo="none",
            nonce=nonce0,
            tx_type=Transaction.TYPE_REGISTER,
            expiry=2_000_000_000,
        )
        unstake.sign(owner)
        reregister = Transaction(
            sender=owner.address,
            receiver="",
            amount=0.2,
            fee=0.2 * Config.TX_FEE_RATE,
            memo="miner",
            nonce=nonce0 + 1,
            tx_type=Transaction.TYPE_REGISTER,
            expiry=2_000_000_000,
        )
        reregister.sign(owner)
        cb = Transaction.coinbase(miner.address, bc.compute_reward(1), 1)

        txs = [cb, unstake, reregister]
        root = bc.dry_run_state_root(txs, miner.address, 1)
        prev = bc.latest_block()
        block = Block(
            index=1,
            prev_hash=prev.block_hash,
            transactions=txs,
            miner_address=miner.address,
            difficulty=bc.get_difficulty(),
            timestamp=prev.timestamp + 1,
            state_root=root,
        )

        # Isolate validation + application semantics from PoW cost. The real
        # integrity pass must still run so the test exercises the same
        # proof-set contract used by production validation.
        with patch.object(block, "validate_pow", return_value=True):
            ok, msg = bc.validate_block(block)
            assert ok, msg
            ok, msg = bc.apply_block(block)
            assert ok, msg

        role = st.get_role(owner.address)
        assert role is not None
        assert role["role"] == "miner"
        assert role["stake"] == 0.2


def test_candidate_builder_never_returns_block_above_hard_consensus_cap():
    class FakeMempool:
        def get_top(self, _n):
            return [large_tx]

    class FakeStorage:
        def get_block(self, _idx):
            return None

    class FakeBlockchain:
        def __init__(self):
            self._lock = threading.RLock()
            self.storage = FakeStorage()
            self.mempool = FakeMempool()

        def latest_block(self):
            return None

        def get_difficulty(self):
            return 0.001

        def compute_reward(self, _height):
            return 50.0

        def get_dynamic_block_size(self):
            return Config.MAX_BLOCK_SIZE

        def dry_run_state_root(self, transactions, miner_address, height):
            return "a" * 64

    miner = Wallet.generate()
    large_tx = Transaction(
        sender=miner.address,
        receiver=Wallet.generate().address,
        amount=1.0,
        fee=0.01,
        nonce=0,
        expiry=2_000_000_000,
        data="x" * (Config.MAX_BLOCK_SIZE - 1_000),
    )
    large_tx.sign(miner)
    bc = FakeBlockchain()
    engine = ConsensusEngine(bc, miner)

    candidate = engine.build_candidate_block(miner.address)
    assert candidate.size() <= Config.MAX_BLOCK_SIZE
    # The near-cap transaction fits the old tx-only budget but pushes the full
    # serialized block above the hard cap once the mandatory coinbase/header
    # bytes are included, so the safe candidate is coinbase-only.
    assert len(candidate.transactions) == 1
    assert candidate.transactions[0].sender == "COINBASE"


def test_fork_choice_compares_cumulative_pow_work_not_linear_difficulty():
    bc = object.__new__(Blockchain)

    branch_a = [
        Block(i, "0" * 64, [], "miner", 5.15, timestamp=i)
        for i in range(1, 11)
    ]
    branch_b = [
        Block(i, "0" * 64, [], "miner", 4.8, timestamp=i)
        for i in range(1, 12)
    ]

    work_a = bc._cumulative_difficulty(branch_a)
    work_b = bc._cumulative_difficulty(branch_b)

    assert work_a > work_b


def test_malformed_nonstring_transaction_type_fails_closed_without_exception():
    sender = Wallet.generate()
    receiver = Wallet.generate()
    tx = Transaction(
        sender=sender.address,
        receiver=receiver.address,
        amount=1.0,
        fee=0.01,
        nonce=0,
        tx_type=Transaction.TYPE_TRANSFER,
        expiry=2_000_000_000,
    )
    tx.tx_type = []
    ok, msg = tx.is_valid(reference_time=1_700_000_000, block_height=1)
    assert not ok
    assert "must be a string" in msg


def test_cumulative_pow_work_remains_finite_at_protocol_max_difficulty():
    bc = object.__new__(Blockchain)
    blocks = [
        Block(i, "0" * 64, [], "miner", Config.MAX_DIFFICULTY, timestamp=i)
        for i in range(1, 501)
    ]
    work = bc._cumulative_difficulty(blocks)
    assert work.is_finite()
    assert work > 0
