"""Section 94 V4 regression tests: MEV Commit-Reveal Mechanism and Reveal Validation."""

from __future__ import annotations

import os
import time

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mempool import mev
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _chain(tmp_path):
    st = Storage(os.path.join(str(tmp_path), "audit94.db"))
    return st, Blockchain(st)


def _save_block(st, txs, miner):
    height = st.chain_height() + 1
    prev = st.get_block(height - 1)
    cb = Transaction.coinbase(miner.address, 1.0, height)
    block = Block(
        index=height,
        prev_hash=prev.block_hash,
        transactions=[cb] + list(txs),
        miner_address=miner.address,
        difficulty=1.0,
    )
    assert block.mine()
    st.save_block(block)
    return block


def _engine(st, bc, wallet):
    eng = StateEngine.__new__(StateEngine)
    eng._storage = st
    eng._blockchain = bc
    eng._network = None
    eng._node_ref = None
    eng._circuit_breaker = None
    eng._mev_wallet = wallet
    return eng


def _make_flight_inputs(sender, receiver, base_nonce=0):
    ts = int(time.time())
    salt = mev.new_salt()
    core = mev.core_transfer(
        sender.address, receiver.address, 1.0, 0.01, "", base_nonce + 1, ts
    )
    commit = mev.build_commitment_tx(
        sender, base_nonce + 1, ts, core.mev_commitment(salt)
    )
    flight_req = {
        "core": {
            "receiver": receiver.address,
            "amount_sat": 100_000_000,
            "fee_sat": 1_000_000,
            "memo": "",
            "nonce": base_nonce + 1,
            "timestamp": ts,
        },
        "salt": salt,
    }
    return core, commit, salt, flight_req


def test_reorg_during_reveal_phase_relocates_valid_protected_transfer(tmp_path):
    """Fixed: if a chain reorg moves commit_tx to a different height after
    flight['phase'] became 'reveal', _release_protected_transfer() re-locates
    commit_tx and broadcasts the reveal instead of cancelling the transfer."""
    st, bc = _chain(tmp_path)
    wallet, receiver = Wallet.generate(), Wallet.generate()
    st.credit_sat(wallet.address, 100 * Config.SATOSHI_PER_VSD)
    eng = _engine(st, bc, wallet)

    _core, commit, _salt, flight_req = _make_flight_inputs(wallet, receiver, base_nonce=0)
    ok, msg = eng._start_protected_transfer(commit, flight_req)
    assert ok, msg

    _save_block(st, [commit], wallet)
    bc.mempool.remove(commit.tx_id)
    st.set_nonce(wallet.address, 1)

    eng._release_protected_transfer()
    flight = mev.load_flight(st)
    assert flight is not None
    assert flight["phase"] == "reveal"
    assert flight["commit_height"] == 1

    st.delete_block(1)
    _save_block(st, [], wallet)          # height 1 (no commit_tx)
    _save_block(st, [commit], wallet)    # height 2 (commit_tx moved here)
    for _ in range(int(Config.COMMIT_REVEAL_DELAY_BLOCKS)):
        _save_block(st, [], wallet)      # tip = 2 + delay = 5

    eng._release_protected_transfer()
    assert bc.mempool.size() == 1


def test_reorg_below_started_height_finds_commit_tx(tmp_path):
    """Fixed: if a reorg drops tip below flight['started_height'] and commit_tx
    is mined at height <= tip < started_height, _release_protected_transfer()
    still locates commit_tx and transitions the flight to 'reveal'."""
    st, bc = _chain(tmp_path)
    wallet, receiver = Wallet.generate(), Wallet.generate()
    st.credit_sat(wallet.address, 100 * Config.SATOSHI_PER_VSD)
    eng = _engine(st, bc, wallet)

    for _ in range(5):
        _save_block(st, [], wallet)      # tip = 5

    _core, commit, _salt, flight_req = _make_flight_inputs(wallet, receiver, base_nonce=0)
    ok, msg = eng._start_protected_transfer(commit, flight_req)
    assert ok, msg
    assert mev.load_flight(st)["started_height"] == 5

    st.delete_block(5)
    st.delete_block(4)
    _save_block(st, [commit], wallet)    # height 4
    bc.mempool.remove(commit.tx_id)
    st.set_nonce(wallet.address, 1)

    eng._release_protected_transfer()
    flight = mev.load_flight(st)
    assert flight is not None
    assert flight["phase"] == "reveal"
    assert flight["commit_height"] == 4
