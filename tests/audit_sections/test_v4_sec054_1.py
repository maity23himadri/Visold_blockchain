"""V4 Regression Tests for Section 54: Coinbase Validation and Uniqueness."""

import os
import sys
import tempfile
import shutil
from pathlib import Path

import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.wallet.wallet import Wallet
from visold.ledger.transaction import Transaction
from visold.ledger.block import Block
from visold.storage.storage import Storage
from visold.chain.blockchain import Blockchain
from visold.economics.rewards import validate_block_rewards, RewardError, RewardConfig


def _make_chain(tmpdir):
    bc = Blockchain(Storage(os.path.join(tmpdir, "chain.db")))
    bc.get_difficulty = lambda: 1.0
    return bc


def _mine_valid_block(bc: Blockchain, miner_addr: str, cb_tx: Transaction,
                      state_root: str = None) -> Block:
    tip = bc.latest_block()
    height = tip.index + 1
    blk = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=[cb_tx],
        miner_address=miner_addr,
        difficulty=bc.get_difficulty(),
        timestamp=max(int(tip.timestamp) + 1, 1700000000 + height),
    )
    if state_root is None:
        blk.state_root = bc.dry_run_state_root(
            blk.transactions, miner_addr, height, blk.timestamp, blk.difficulty
        )
    else:
        blk.state_root = state_root
    blk.mine()
    blk.seal()
    return blk


def test_duplicate_coinbase_txid_across_blocks_rejected():
    """V4 Fix:
    validate_block() enforces coinbase memo binding to block height and rejects
    duplicate coinbase tx_ids across blocks, keeping Block 1's tx record intact.
    """
    tmpdir = tempfile.mkdtemp(prefix="visold_s54_fix1_")
    try:
        bc = _make_chain(tmpdir)
        miner = Wallet.generate()
        reward_1 = bc.compute_reward(1)
        reward_2 = bc.compute_reward(2)
        assert reward_1 == reward_2

        fixed_ts = 1700000001
        cb1 = Transaction(
            sender="COINBASE",
            receiver=miner.address,
            amount=reward_1,
            timestamp=fixed_ts,
            memo="coinbase:1",
            nonce=0,
            expiry=0,
        )
        cb2 = Transaction(
            sender="COINBASE",
            receiver=miner.address,
            amount=reward_2,
            timestamp=fixed_ts,
            memo="coinbase:1",
            nonce=0,
            expiry=0,
        )
        assert cb1.tx_id == cb2.tx_id

        blk1 = _mine_valid_block(bc, miner.address, cb1)
        ok1, msg1 = bc.validate_block(blk1)
        assert ok1, f"Block 1 unexpectedly rejected: {msg1}"
        assert bc.apply_block(blk1)[0]

        blk2 = _mine_valid_block(bc, miner.address, cb2)
        ok2, msg2 = bc.validate_block(blk2)
        assert not ok2, "Duplicate/unbound coinbase at height 2 must be rejected"

        conn = bc.storage._conn()
        row = conn.execute(
            "SELECT block_idx FROM transactions WHERE tx_id=?", (cb1.tx_id,)
        ).fetchone()
        assert row is not None
        assert row[0] == 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_invalid_and_reserved_miner_address_rejected_in_coinbase():
    """V4 Fix:
    validate_block() rejects reserved 'COINBASE' sentinel and malformed
    non-canonical addresses as block.miner_address / coinbase receiver.
    """
    tmpdir = tempfile.mkdtemp(prefix="visold_s54_fix2_")
    try:
        bc = _make_chain(tmpdir)
        reward_1 = bc.compute_reward(1)

        cb_reserved = Transaction.coinbase("COINBASE", reward_1, 1)
        blk_reserved = _mine_valid_block(bc, "COINBASE", cb_reserved)
        ok_res, _msg_res = bc.validate_block(blk_reserved)
        assert not ok_res, "'COINBASE' must be rejected as miner_address"
        assert bc.storage.get_balance_sat("COINBASE") == 0

        cb_bad = Transaction.coinbase("not_a_valid_vsd_address", reward_1, 1)
        blk_bad = _mine_valid_block(bc, "not_a_valid_vsd_address", cb_bad)
        ok_bad, _msg_bad = bc.validate_block(blk_bad)
        assert not ok_bad, "Malformed address must be rejected as miner_address"
        assert bc.storage.get_balance_sat("not_a_valid_vsd_address") == 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_validate_block_rewards_rejects_signed_transaction_coinbase():
    """V4 Fix:
    validate_block_rewards() Rule R2 inspects both sig_hex/pub_hex and signature,
    raising RewardError when a coinbase transaction has a non-empty sig_hex/pub_hex.
    """
    class _BlockStub:
        def __init__(self, index, transactions):
            self.index = index
            self.transactions = transactions

    miner_addr = Wallet.generate().address
    cb_tx = Transaction(
        sender=RewardConfig.COINBASE_SENDER,
        receiver=miner_addr,
        amount=100,
        tx_type=RewardConfig.TX_TYPE_REWARD,
        sig_hex="deadbeef" * 16,
        pub_hex="02" + "aa" * 32,
        nonce=1,
        data='{"subsidy":100,"fees":0,"consensus":"pow"}',
    )
    blk = _BlockStub(index=1, transactions=[cb_tx])
    with pytest.raises(RewardError):
        validate_block_rewards(blk, expected_subsidy=100, chain_tip_height=0)
