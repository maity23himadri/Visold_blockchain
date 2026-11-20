"""V4 regression tests for Section 30 (Session 03): Block Validation, Transaction Ordering, Duplicate Prevention."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _mine_block(bc: Blockchain, txs: list[Transaction], miner: str,
                height: int, prev_hash: str) -> Block:
    state_root = bc.dry_run_state_root(txs, miner, height)
    blk = Block(
        index=height,
        prev_hash=prev_hash,
        transactions=txs,
        miner_address=miner,
        difficulty=bc.get_difficulty(),
        state_root=state_root,
    )
    assert blk.mine()
    return blk


def test_validate_and_apply_rejects_stale_height_overwrite():
    """Blockchain.validate_block() and apply_block() reject stale-height blocks."""
    old_min, old_init = Config.MIN_DIFFICULTY, Config.INITIAL_DIFFICULTY
    Config.MIN_DIFFICULTY = Config.INITIAL_DIFFICULTY = 0.001
    try:
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(os.path.join(td, "chain.db"))
            bc = Blockchain(storage)
            miner1 = Wallet.generate()
            miner2 = Wallet.generate()

            gen = bc.latest_block()
            assert gen.index == 0

            cb1 = Transaction.coinbase(miner1.address, bc.compute_reward(1), 1)
            b1 = _mine_block(bc, [cb1], miner1.address, 1, gen.block_hash)
            ok1, msg1 = bc.apply_block(b1)
            assert ok1, msg1

            cb2 = Transaction.coinbase(miner1.address, bc.compute_reward(2), 2)
            b2 = _mine_block(bc, [cb2], miner1.address, 2, b1.block_hash)
            ok2, msg2 = bc.apply_block(b2)
            assert ok2, msg2
            assert bc.latest_block().index == 2

            cb1_alt = Transaction.coinbase(miner2.address, bc.compute_reward(1), 1)
            b1_alt = _mine_block(bc, [cb1_alt], miner2.address, 1, gen.block_hash)
            assert b1_alt.block_hash != b1.block_hash

            ok_val, _msg_val = bc.validate_block(b1_alt)
            ok_app, _msg_app = bc.apply_block(b1_alt)
            assert ok_val is False
            assert ok_app is False
            assert storage.get_block(1).block_hash == b1.block_hash
    finally:
        Config.MIN_DIFFICULTY = old_min
        Config.INITIAL_DIFFICULTY = old_init


def test_duplicate_coinbase_txid_across_blocks_rejected():
    """Blockchain.validate_block() and apply_block() reject duplicate coinbase tx_ids across blocks."""
    old_min, old_init = Config.MIN_DIFFICULTY, Config.INITIAL_DIFFICULTY
    Config.MIN_DIFFICULTY = Config.INITIAL_DIFFICULTY = 0.001
    try:
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(os.path.join(td, "chain_cb.db"))
            bc = Blockchain(storage)
            miner = Wallet.generate()
            gen = bc.latest_block()

            fixed_ts = int(gen.timestamp) + 10
            cb1 = Transaction(
                sender="COINBASE",
                receiver=miner.address,
                amount=bc.compute_reward(1),
                timestamp=fixed_ts,
                memo="shared-coinbase",
                nonce=0,
                expiry=0,
            )
            b1 = _mine_block(bc, [cb1], miner.address, 1, gen.block_hash)
            ok1, msg1 = bc.apply_block(b1)
            assert ok1, msg1

            cb2 = Transaction(
                sender="COINBASE",
                receiver=miner.address,
                amount=bc.compute_reward(2),
                timestamp=fixed_ts,
                memo="shared-coinbase",
                nonce=0,
                expiry=0,
            )
            assert cb1.tx_id == cb2.tx_id
            b2 = _mine_block(bc, [cb2], miner.address, 2, b1.block_hash)
            ok2, _msg2 = bc.apply_block(b2)
            assert ok2 is False

            row = storage._conn().execute(
                "SELECT block_idx FROM transactions WHERE tx_id=?",
                (cb1.tx_id,),
            ).fetchone()
            assert row is not None and row["block_idx"] == 1
    finally:
        Config.MIN_DIFFICULTY = old_min
        Config.INITIAL_DIFFICULTY = old_init
