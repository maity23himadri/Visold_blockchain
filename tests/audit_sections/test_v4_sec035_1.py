import os
import tempfile
import unittest.mock as mock

import pytest

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _mine_block(bc: Blockchain, prev: Block, miner: str) -> Block:
    cb = Transaction.coinbase(miner, bc.compute_reward(prev.index + 1), prev.index + 1)
    blk = Block(
        index=prev.index + 1,
        prev_hash=prev.block_hash,
        transactions=[cb],
        miner_address=miner,
        difficulty=bc.get_difficulty(),
        timestamp=prev.timestamp + 60,
        nonce=0,
    )
    assert blk.mine() is True
    return blk


def test_reorg_rejects_fork_height_zero_cleanly():
    """V4 regression: Blockchain.reorg() rejects fork_height == 0 cleanly without triggering critical recovery."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(os.path.join(tmpdir, "visold.db"))
        bc = Blockchain(storage)
        genesis = bc.get_block(0)
        assert genesis is not None

        alt_miner = Wallet.generate().address
        alt_tx = Transaction(
            sender="COINBASE",
            receiver=alt_miner,
            amount=0.0,
            fee=0.0,
            timestamp=genesis.timestamp,
            memo="alt-genesis",
            nonce=0,
            expiry=0,
        )
        alt_gen = Block(
            index=0,
            prev_hash="0" * 64,
            transactions=[alt_tx],
            miner_address=alt_miner,
            difficulty=genesis.difficulty + 1.0,
            timestamp=genesis.timestamp,
            nonce=99,
        )
        alt_gen.seal()

        ok, msg = bc.reorg([alt_gen], allow_deep_no_investor=True)
        assert ok is False
        assert bc._critical_recovery is None
        assert "genesis" in msg.lower() or "height 0" in msg.lower() or "fork_height" in msg.lower()


def test_reorg_resets_rolling_pruner_last_height():
    """V4 regression: Blockchain.reorg() resets _rolling_pruner._last_height = -1."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with mock.patch.object(Config, "INITIAL_DIFFICULTY", 1.0), \
             mock.patch.object(Config, "EMPTY_STATE_ROOT_LEGACY_END_HEIGHT", 10):
            storage = Storage(os.path.join(tmpdir, "visold.db"))
            bc = Blockchain(storage)
            miner_a = Wallet.generate().address
            miner_b = Wallet.generate().address
            gen = bc.get_block(0)
            b1 = _mine_block(bc, gen, miner=miner_a)
            ok1, m1 = bc.apply_block(b1)
            assert ok1, m1
            b2 = _mine_block(bc, b1, miner=miner_a)
            ok2, m2 = bc.apply_block(b2)
            assert ok2, m2

            bc._rolling_pruner._last_height = 500

            alt_b1 = _mine_block(bc, gen, miner=miner_b)
            alt_b2 = _mine_block(bc, alt_b1, miner=miner_b)
            alt_b3 = Block(
                index=3,
                prev_hash=alt_b2.block_hash,
                transactions=[Transaction.coinbase(miner_b, bc.compute_reward(3), 3)],
                miner_address=miner_b,
                difficulty=1.0,
                timestamp=alt_b2.timestamp + 60,
                nonce=0,
            )
            assert alt_b3.mine() is True

            with mock.patch.object(bc, "get_difficulty", return_value=1.0):
                ok_reorg, msg_reorg = bc.reorg([alt_b1, alt_b2, alt_b3])
            assert ok_reorg is True, msg_reorg
            assert bc._rolling_pruner._last_height == -1