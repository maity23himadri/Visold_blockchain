"""V4 regression tests for Section 94: MEV Commit-Reveal Mechanism and Reveal Validation."""

from __future__ import annotations

import os
import time

import pytest

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import (
    Transaction,
    parse_mev_commit_data,
    parse_mev_reveal_data,
)
from visold.mempool import mev
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = 100_000_000


@pytest.fixture(autouse=True)
def _fast_difficulty(monkeypatch):
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    monkeypatch.setattr(Config, "MIN_DIFFICULTY", 0.001)


def _build_block(bc: Blockchain, miner: Wallet, txs: list) -> Block:
    height = bc.height() + 1
    reward = bc.compute_reward_sat(height) / SAT
    cb = Transaction.coinbase(miner.address, reward, height)
    all_txs = [cb] + list(txs)
    root = bc.dry_run_state_root(all_txs, miner.address, height)
    prev = bc.latest_block()
    block = Block(
        index=height,
        prev_hash=prev.block_hash,
        transactions=all_txs,
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        state_root=root,
        timestamp=max(int(time.time()), prev.timestamp + 1),
    )
    assert block.mine(), "block failed to mine"
    return block


def _apply(bc: Blockchain, miner: Wallet, txs: list) -> Block:
    block = _build_block(bc, miner, txs)
    ok, msg = bc.apply_block(block)
    assert ok, msg
    return block


def test_v4_reorg_moving_commit_height_relocates_protected_transfer(tmp_path):
    """Fixed: If a reorg moves an already-mined commitment to a different block height,
    StateEngine._release_protected_transfer() re-locates the commitment and broadcasts
    the reveal instead of cancelling the protected transfer.
    """
    st = Storage(os.path.join(str(tmp_path), "mev_reorg.db"))
    bc = Blockchain(st)
    eng = StateEngine(bc, None, st)
    sender = Wallet.generate()
    receiver = Wallet.generate()
    miner = Wallet.generate()
    eng._mev_wallet = sender

    _apply(bc, sender, [])
    assert bc.height() == 1

    ts = int(time.time())
    salt = mev.new_salt()
    core = mev.core_transfer(sender.address, receiver.address, 1.0, 0.01, "reorg-test", 1, ts)
    commit_tx = mev.build_commitment_tx(sender, 1, ts, core.mev_commitment(salt))

    ok, msg = eng._start_protected_transfer(commit_tx, {
        "core": {
            "receiver": receiver.address,
            "amount_sat": int(round(core.amount * SAT)),
            "fee_sat": int(round(core.fee * SAT)),
            "memo": core.memo,
            "nonce": core.nonce,
            "timestamp": core.timestamp,
        },
        "salt": salt,
    })
    assert ok, msg

    _apply(bc, miner, [commit_tx])
    assert bc.height() == 2
    eng._release_protected_transfer()

    flight = mev.load_flight(st)
    assert flight is not None
    assert flight["phase"] == "reveal"
    assert flight["commit_height"] == 2

    # Reorg: roll back block 2, mine empty block 2', then mine commit_tx in block 3'
    bc._rollback_block(bc.latest_block())
    assert bc.height() == 1
    _apply(bc, miner, [])            # block 2'
    _apply(bc, miner, [commit_tx])   # block 3'
    _apply(bc, miner, [])            # block 4'
    _apply(bc, miner, [])            # block 5'
    _apply(bc, miner, [])            # block 6' (3 + DELAY=3)
    assert bc.height() == 6

    eng._release_protected_transfer()
    assert bc.mempool.size() == 1, "Expected reveal tx to be admitted to mempool after reorg relocation"


def test_v4_reorg_after_cached_reveal_invalidates_and_rebuilds_reveal(tmp_path):
    """Fixed: If reveal_tx was cached after a transient rejection and a reorg moves
    commit_tx to another height, _release_protected_transfer() invalidates the stale
    reveal_tx, re-locates commit_tx, and submits a fresh reveal_tx.
    """
    st = Storage(os.path.join(str(tmp_path), "mev_reorg_cached.db"))
    bc = Blockchain(st)
    eng = StateEngine(bc, None, st)
    sender = Wallet.generate()
    receiver = Wallet.generate()
    miner = Wallet.generate()
    eng._mev_wallet = sender

    _apply(bc, sender, [])  # height 1
    ts = int(time.time())
    salt = mev.new_salt()
    core = mev.core_transfer(sender.address, receiver.address, 1.0, 0.01, "cached-reorg", 1, ts)
    commit_tx = mev.build_commitment_tx(sender, 1, ts, core.mev_commitment(salt))

    ok, msg = eng._start_protected_transfer(commit_tx, {
        "core": {
            "receiver": receiver.address,
            "amount_sat": int(round(core.amount * SAT)),
            "fee_sat": int(round(core.fee * SAT)),
            "memo": core.memo,
            "nonce": core.nonce,
            "timestamp": core.timestamp,
        },
        "salt": salt,
    })
    assert ok, msg

    _apply(bc, miner, [commit_tx])  # height 2
    eng._release_protected_transfer()
    _apply(bc, miner, [])           # height 3
    _apply(bc, miner, [])           # height 4
    _apply(bc, miner, [])           # height 5

    orig_add = bc.mempool.add
    bc.mempool.add = lambda tx: (False, "Mempool full — try again later or increase fee")
    try:
        eng._release_protected_transfer()
    finally:
        bc.mempool.add = orig_add

    flight = mev.load_flight(st)
    assert flight is not None
    assert flight["reveal_tx"] is not None
    assert flight["commit_height"] == 2

    for _ in range(4):
        bc._rollback_block(bc.latest_block())
    assert bc.height() == 1
    _apply(bc, miner, [])            # height 2'
    _apply(bc, miner, [commit_tx])   # height 3'
    _apply(bc, miner, [])            # height 4'
    _apply(bc, miner, [])            # height 5'
    _apply(bc, miner, [])            # height 6'

    eng._release_protected_transfer()
    assert bc.mempool.size() == 1, "Expected rebuilt reveal tx to be admitted to mempool"


def test_core_mev_commit_reveal_invariants(tmp_path):
    """Verify core MEV commit-reveal validation invariants work as expected."""
    st = Storage(os.path.join(str(tmp_path), "mev_core.db"))
    bc = Blockchain(st)
    sender = Wallet.generate()
    receiver = Wallet.generate()
    miner = Wallet.generate()

    _apply(bc, sender, [])  # height 1
    ts = int(time.time())
    salt = mev.new_salt()
    core = mev.core_transfer(sender.address, receiver.address, 1.0, 0.01, "ok", 1, ts)
    commit_tx = mev.build_commitment_tx(sender, 1, ts, core.mev_commitment(salt))

    assert commit_tx.is_valid()[0]
    assert parse_mev_commit_data(commit_tx.data) == core.mev_commitment(salt)

    ok, msg = bc.mempool.add(commit_tx)
    assert ok, msg
    _apply(bc, miner, [commit_tx])  # height 2

    steps = mev.reveal_steps_for_commit(st, commit_tx.tx_id, 2)
    reveal_tx = mev.build_reveal_tx(sender, core, salt, 2, steps)
    assert parse_mev_reveal_data(reveal_tx.data) is not None

    assert mev.check_reveal(st, reveal_tx, 4)[0] is False
    assert mev.check_reveal(st, reveal_tx, 5)[0] is True
    assert mev.check_reveal(st, reveal_tx, 22)[0] is True
    assert mev.check_reveal(st, reveal_tx, 23)[0] is False
