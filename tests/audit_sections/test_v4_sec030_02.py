"""V4 regression tests for Section 30 (Session 02): Block Validation, Transaction Ordering, Duplicate Prevention."""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.kernel.units import from_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_chain(tmp_path):
    db_path = str(tmp_path / "test_sec30.db")
    storage = Storage(db_path)
    bc = Blockchain(storage)
    return bc, storage


def _mine_next_block(bc, miner_wallet, txs):
    tip = bc.storage.get_block(bc.height())
    height = tip.index + 1
    ts = max(int(time.time()), int(tip.timestamp) + 1)
    diff = bc.get_difficulty()
    subsidy = from_satoshi(bc.compute_reward_sat(height))
    cb = Transaction(
        sender="COINBASE",
        receiver=miner_wallet.address,
        amount=subsidy,
        fee=0.0,
        timestamp=ts,
        nonce=height,
    )
    cb.tx_id = cb._compute_id()
    all_txs = [cb] + list(txs)
    state_root = bc.dry_run_state_root(
        all_txs, miner_wallet.address, height, timestamp=ts, difficulty=diff
    )
    blk = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=all_txs,
        miner_address=miner_wallet.address,
        difficulty=diff,
        timestamp=ts,
        state_root=state_root,
    )
    assert blk.mine()
    blk.seal()
    return blk


def test_duplicate_tx_within_block_rejected(tmp_path):
    bc, _storage = _make_chain(tmp_path)
    w1 = Wallet.generate()
    w2 = Wallet.generate()
    b1 = _mine_next_block(bc, w1, [])
    ok, msg = bc.apply_block(b1)
    assert ok, msg

    ts = int(b1.timestamp) + 2
    tx = Transaction(
        sender=w1.address,
        receiver=w2.address,
        amount=1.0,
        fee=0.01,
        timestamp=ts,
        nonce=0,
        expiry=ts + 3600,
    )
    tx.sign(w1)

    tip = bc.storage.get_block(bc.height())
    height = tip.index + 1
    diff = bc.get_difficulty()
    cb = Transaction(
        sender="COINBASE",
        receiver=w1.address,
        amount=from_satoshi(bc.compute_reward_sat(height)),
        fee=0.0,
        timestamp=ts,
        nonce=height,
    )
    cb.tx_id = cb._compute_id()
    blk = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=[cb, tx, tx],
        miner_address=w1.address,
        difficulty=diff,
        timestamp=ts,
        state_root="0" * 64,
    )
    assert blk.mine()
    blk.seal()
    ok, msg = bc.validate_block(blk)
    assert not ok
    assert "Duplicate tx" in msg


def test_duplicate_tx_across_blocks_rejected(tmp_path):
    bc, _storage = _make_chain(tmp_path)
    w1 = Wallet.generate()
    w2 = Wallet.generate()
    b1 = _mine_next_block(bc, w1, [])
    ok, msg = bc.apply_block(b1)
    assert ok, msg

    ts = int(b1.timestamp) + 2
    tx = Transaction(
        sender=w1.address,
        receiver=w2.address,
        amount=1.0,
        fee=0.01,
        timestamp=ts,
        nonce=0,
        expiry=ts + 3600,
    )
    tx.sign(w1)
    b2 = _mine_next_block(bc, w1, [tx])
    ok, msg = bc.apply_block(b2)
    assert ok, msg

    tip = bc.storage.get_block(bc.height())
    height = tip.index + 1
    ts3 = int(b2.timestamp) + 2
    diff = bc.get_difficulty()
    cb = Transaction(
        sender="COINBASE",
        receiver=w1.address,
        amount=from_satoshi(bc.compute_reward_sat(height)),
        fee=0.0,
        timestamp=ts3,
        nonce=height,
    )
    cb.tx_id = cb._compute_id()
    blk3 = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=[cb, tx],
        miner_address=w1.address,
        difficulty=diff,
        timestamp=ts3,
        state_root="0" * 64,
    )
    assert blk3.mine()
    blk3.seal()
    ok, msg = bc.validate_block(blk3)
    assert not ok
    assert "Double-spend" in msg


def test_out_of_order_nonces_rejected(tmp_path):
    bc, _storage = _make_chain(tmp_path)
    w1 = Wallet.generate()
    w2 = Wallet.generate()
    b1 = _mine_next_block(bc, w1, [])
    ok, msg = bc.apply_block(b1)
    assert ok, msg

    ts = int(b1.timestamp) + 2
    tx0 = Transaction(
        sender=w1.address, receiver=w2.address, amount=1.0, fee=0.01,
        timestamp=ts, nonce=0, expiry=ts + 3600,
    )
    tx0.sign(w1)
    tx1 = Transaction(
        sender=w1.address, receiver=w2.address, amount=1.0, fee=0.01,
        timestamp=ts, nonce=1, expiry=ts + 3600,
    )
    tx1.sign(w1)

    tip = bc.storage.get_block(bc.height())
    height = tip.index + 1
    diff = bc.get_difficulty()
    cb = Transaction(
        sender="COINBASE",
        receiver=w1.address,
        amount=from_satoshi(bc.compute_reward_sat(height)),
        fee=0.0,
        timestamp=ts,
        nonce=height,
    )
    cb.tx_id = cb._compute_id()
    blk = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=[cb, tx1, tx0],
        miner_address=w1.address,
        difficulty=diff,
        timestamp=ts,
        state_root="0" * 64,
    )
    assert blk.mine()
    blk.seal()
    ok, msg = bc.validate_block(blk)
    assert not ok
    assert "Nonce mismatch" in msg


def test_coinbase_ordering_and_count(tmp_path):
    bc, _storage = _make_chain(tmp_path)
    w1 = Wallet.generate()
    w2 = Wallet.generate()
    b1 = _mine_next_block(bc, w1, [])
    ok, msg = bc.apply_block(b1)
    assert ok, msg

    ts = int(b1.timestamp) + 2
    tx0 = Transaction(
        sender=w1.address, receiver=w2.address, amount=1.0, fee=0.01,
        timestamp=ts, nonce=0, expiry=ts + 3600,
    )
    tx0.sign(w1)

    tip = bc.storage.get_block(bc.height())
    height = tip.index + 1
    diff = bc.get_difficulty()
    cb = Transaction(
        sender="COINBASE",
        receiver=w1.address,
        amount=from_satoshi(bc.compute_reward_sat(height)),
        fee=0.0,
        timestamp=ts,
        nonce=height,
    )
    cb.tx_id = cb._compute_id()
    blk = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=[tx0, cb],
        miner_address=w1.address,
        difficulty=diff,
        timestamp=ts,
        state_root="0" * 64,
    )
    assert blk.mine()
    blk.seal()
    ok, msg = bc.validate_block(blk)
    assert not ok
    assert "Coinbase must be the first transaction" in msg


def test_pruned_and_nonfinite_blocks_rejected(tmp_path):
    bc, _storage = _make_chain(tmp_path)
    w1 = Wallet.generate()
    b1 = _mine_next_block(bc, w1, [])

    pruned_blk = Block(
        index=1,
        prev_hash=b1.prev_hash,
        transactions=[],
        miner_address=w1.address,
        difficulty=b1.difficulty,
        timestamp=b1.timestamp,
        merkle_root=b1.merkle_root,
        state_root=b1.state_root,
        pruned=True,
    )
    ok, msg = bc.validate_block(pruned_blk)
    assert not ok
    assert "Pruned" in msg

    nan_blk = Block(
        index=1,
        prev_hash=b1.prev_hash,
        transactions=b1.transactions,
        miner_address=w1.address,
        difficulty=float("nan"),
        timestamp=b1.timestamp,
        state_root=b1.state_root,
    )
    ok, msg = bc.validate_block(nan_blk)
    assert not ok
    assert "nan" in msg.lower() or "finite" in msg.lower()
