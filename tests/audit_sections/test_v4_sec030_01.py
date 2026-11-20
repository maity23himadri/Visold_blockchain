"""V4 regression tests for Section 30 (Session 01): Block Validation, Transaction Ordering, Duplicate Prevention."""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.kernel.units import from_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_chain(td: str, name: str = "chain.db") -> tuple[Storage, Blockchain]:
    storage = Storage(os.path.join(td, name))
    return storage, Blockchain(storage)


def _mine_block(bc: Blockchain, txs: list[Transaction], miner: str, height: int,
                timestamp: int | None = None) -> Block:
    ts = timestamp if timestamp is not None else int(time.time())
    state_root = bc.dry_run_state_root(txs, miner, height, timestamp=ts)
    tip = bc.latest_block()
    block = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=txs,
        miner_address=miner,
        difficulty=bc.get_difficulty(),
        timestamp=ts,
        state_root=state_root,
    )
    assert block.mine()
    return block


def test_coinbase_register_tx_type_rejected():
    """validate_block() rejects a coinbase transaction with tx_type='register'."""
    old_min, old_init = Config.MIN_DIFFICULTY, Config.INITIAL_DIFFICULTY
    Config.MIN_DIFFICULTY = Config.INITIAL_DIFFICULTY = 0.001
    try:
        with tempfile.TemporaryDirectory() as td:
            _storage, bc = _make_chain(td)
            miner = Wallet.generate()
            subsidy_vsd = from_satoshi(bc.compute_reward_sat(1))

            cb_register = Transaction(
                sender="COINBASE",
                receiver=miner.address,
                amount=subsidy_vsd,
                timestamp=int(time.time()),
                memo="investor",
                nonce=0,
                expiry=0,
                tx_type=Transaction.TYPE_REGISTER,
            )
            block1 = _mine_block(bc, [cb_register], miner.address, height=1)

            ok_val, _msg_val = bc.validate_block(block1)
            assert ok_val is False
    finally:
        Config.MIN_DIFFICULTY = old_min
        Config.INITIAL_DIFFICULTY = old_init


def test_coinbase_duplicate_tx_id_rejected():
    """validate_block() rejects a block whose coinbase reuses a prior block's coinbase tx_id."""
    old_min, old_init = Config.MIN_DIFFICULTY, Config.INITIAL_DIFFICULTY
    Config.MIN_DIFFICULTY = Config.INITIAL_DIFFICULTY = 0.001
    try:
        with tempfile.TemporaryDirectory() as td:
            _storage, bc = _make_chain(td)
            miner = Wallet.generate()
            fixed_ts = int(time.time())
            subsidy_vsd = from_satoshi(bc.compute_reward_sat(1))

            cb1 = Transaction(
                sender="COINBASE",
                receiver=miner.address,
                amount=subsidy_vsd,
                timestamp=fixed_ts,
                memo="coinbase:1",
                nonce=0,
                expiry=0,
            )
            block1 = _mine_block(bc, [cb1], miner.address, height=1, timestamp=fixed_ts)
            ok1, msg1 = bc.apply_block(block1)
            assert ok1, msg1

            subsidy2_vsd = from_satoshi(bc.compute_reward_sat(2))
            cb2 = Transaction(
                sender="COINBASE",
                receiver=miner.address,
                amount=subsidy2_vsd,
                timestamp=fixed_ts,
                memo="coinbase:1",
                nonce=0,
                expiry=0,
            )
            assert cb2.tx_id == cb1.tx_id

            block2 = _mine_block(bc, [cb2], miner.address, height=2, timestamp=fixed_ts + 1)
            ok_val, _msg_val = bc.validate_block(block2)
            assert ok_val is False
    finally:
        Config.MIN_DIFFICULTY = old_min
        Config.INITIAL_DIFFICULTY = old_init


def test_section30_clean_checks_duplicates_and_nonce_ordering():
    """Verify baseline Section 30 protections work as expected for non-coinbase txs."""
    old_min, old_init = Config.MIN_DIFFICULTY, Config.INITIAL_DIFFICULTY
    Config.MIN_DIFFICULTY = Config.INITIAL_DIFFICULTY = 0.001
    try:
        with tempfile.TemporaryDirectory() as td:
            storage, bc = _make_chain(td)
            alice = Wallet.generate()
            bob = Wallet.generate()
            miner = Wallet.generate()
            storage.credit_sat(alice.address, 100 * Config.SATOSHI_PER_VSD)

            ts = int(time.time())
            tx0 = Transaction(
                sender=alice.address,
                receiver=bob.address,
                amount=1.0,
                fee=0.01,
                timestamp=ts,
                nonce=0,
                expiry=ts + 3600,
            )
            tx0.sign(alice)

            cb1 = Transaction.coinbase(miner.address, from_satoshi(bc.compute_reward_sat(1)), 1)
            tip = bc.latest_block()
            dup_block = Block(
                index=1,
                prev_hash=tip.block_hash,
                transactions=[cb1, tx0, tx0],
                miner_address=miner.address,
                difficulty=bc.get_difficulty(),
                timestamp=ts,
                state_root=bc.dry_run_state_root([cb1, tx0], miner.address, 1, timestamp=ts),
            )
            assert dup_block.mine()
            ok_dup, msg_dup = bc.validate_block(dup_block)
            assert not ok_dup and "Duplicate tx in block" in msg_dup

            tx1 = Transaction(
                sender=alice.address,
                receiver=bob.address,
                amount=1.0,
                fee=0.01,
                timestamp=ts,
                nonce=1,
                expiry=ts + 3600,
            )
            tx1.sign(alice)
            gap_block = _mine_block(bc, [cb1, tx1], miner.address, 1, timestamp=ts)
            ok_gap, msg_gap = bc.validate_block(gap_block)
            assert not ok_gap and "Nonce mismatch" in msg_gap

            b1 = _mine_block(bc, [cb1, tx0], miner.address, 1, timestamp=ts)
            assert bc.apply_block(b1)[0]
            cb2 = Transaction.coinbase(miner.address, from_satoshi(bc.compute_reward_sat(2)), 2)
            replay_b2 = _mine_block(bc, [cb2, tx0], miner.address, 2, timestamp=ts + 1)
            ok_rep, msg_rep = bc.validate_block(replay_b2)
            assert not ok_rep and "Double-spend" in msg_rep
    finally:
        Config.MIN_DIFFICULTY = old_min
        Config.INITIAL_DIFFICULTY = old_init
