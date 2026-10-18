"""MEV recovery paths: a rejected reveal keeps its commitment, and reveals whose
commitment has aged out are removed from the mempool."""

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
    st = Storage(os.path.join(str(tmp_path), "recovery.db"))
    return st, Blockchain(st)


def _save_block(st, txs, miner):
    height = st.chain_height() + 1
    prev = st.get_block(height - 1)
    cb = Transaction.coinbase(miner.address, 1.0, height)
    block = Block(index=height, prev_hash=prev.block_hash,
                  transactions=[cb] + list(txs), miner_address=miner.address,
                  difficulty=1.0)
    assert block.mine()
    st.save_block(block)
    return block


def _engine(st, bc):
    eng = StateEngine.__new__(StateEngine)
    eng._storage = st
    eng._blockchain = bc
    return eng


def _protected(sender, receiver, st, base_nonce=0):
    ts = int(time.time())
    salt = mev.new_salt()
    core = mev.core_transfer(sender.address, receiver.address, 1.0, 0.01, "",
                             base_nonce + 1, ts)
    commit = mev.build_commitment_tx(sender, base_nonce + 1, ts, core.mev_commitment(salt))
    return core, commit, salt


def test_stale_reveal_is_purged_from_the_mempool(tmp_path):
    st, bc = _chain(tmp_path)
    wallet, receiver = Wallet.generate(), Wallet.generate()
    core, commit, salt = _protected(wallet, receiver, st)
    _save_block(st, [commit], wallet)                      # commitment at height 1
    steps = mev.reveal_steps_for_commit(st, commit.tx_id, 1)
    reveal = mev.build_reveal_tx(wallet, core, salt, 1, steps)
    for _ in range(3):
        _save_block(st, [], wallet)                        # tip 4
    st.set_nonce(wallet.address, 1)                        # as applying the commitment does
    ok, msg = bc.mempool.add(reveal)
    assert ok, msg
    assert bc.mempool.size() == 1
    for _ in range(25):
        _save_block(st, [], wallet)                        # the commitment is now too old
    _engine(st, bc)._purge_stale_protected_reveals()
    assert bc.mempool.size() == 0


def test_rejected_reveal_keeps_its_commitment_and_is_admitted_later(tmp_path, monkeypatch):
    st, bc = _chain(tmp_path)
    wallet, receiver = Wallet.generate(), Wallet.generate()
    core, commit, salt = _protected(wallet, receiver, st)
    _save_block(st, [commit], wallet)                      # commitment at height 1
    steps = mev.reveal_steps_for_commit(st, commit.tx_id, 1)
    reveal = mev.build_reveal_tx(wallet, core, salt, 1, steps)
    for _ in range(3):
        _save_block(st, [], wallet)                        # tip 4
    st.set_nonce(wallet.address, 1)
    monkeypatch.setattr(Config, "MEMPOOL_MAX", 0)          # force a 'Mempool full' rejection
    ok, msg = bc.mempool.add(reveal)
    assert not ok and "Mempool full" in msg, msg
    # The commitment lives on-chain, so nothing was used up: the same reveal still works.
    monkeypatch.setattr(Config, "MEMPOOL_MAX", 5000)
    ok, msg = bc.mempool.add(reveal)
    assert ok, msg
