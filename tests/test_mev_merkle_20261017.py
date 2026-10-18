"""MEV merkle paths must match Block._merkle exactly, and a reveal must still validate
after its commitment's block body has been pruned (the header is all that is needed)."""

from __future__ import annotations

import os
import time

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mempool import mev
from visold.storage.rolling_window_pruner import RollingWindowPruner
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _txs(n, height):
    return [Transaction.coinbase(f"VSD{i:040x}", 1.0, height) for i in range(n)]


def _block(txs, index=1):
    return Block(index=index, prev_hash="00" * 32, transactions=txs,
                 miner_address=Wallet.generate().address, difficulty=1.0)


def test_merkle_paths_match_block_merkle_v2(monkeypatch):
    monkeypatch.setattr(Config, "MERKLE_V2_ACTIVATION_HEIGHT", 0)
    for n in range(1, 34):
        txs = _txs(n, 1)
        root = _block(txs)._merkle()
        ids = [t.tx_id for t in txs]
        for i in range(n):
            steps = mev.merkle_steps(ids, i, True)
            assert mev.verify_merkle_steps(ids[i], steps, root, True), (n, i)
            if any(kind == "O" for kind, _ in steps):
                assert not mev.verify_merkle_steps(ids[i], steps, root, False), (n, i)


def test_merkle_paths_match_block_merkle_v1(monkeypatch):
    monkeypatch.setattr(Config, "MERKLE_V2_ACTIVATION_HEIGHT", 10 ** 9)
    for n in range(1, 34):
        txs = _txs(n, 1)
        root = _block(txs)._merkle()
        ids = [t.tx_id for t in txs]
        for i in range(n):
            steps = mev.merkle_steps(ids, i, False)
            assert mev.verify_merkle_steps(ids[i], steps, root, False), (n, i)


def test_a_wrong_leaf_or_path_is_rejected(monkeypatch):
    monkeypatch.setattr(Config, "MERKLE_V2_ACTIVATION_HEIGHT", 0)
    txs = _txs(7, 1)
    root = _block(txs)._merkle()
    ids = [t.tx_id for t in txs]
    steps = mev.merkle_steps(ids, 4, True)
    assert mev.verify_merkle_steps(ids[4], steps, root, True)
    assert not mev.verify_merkle_steps(ids[3], steps, root, True)
    bad = list(steps)
    kind, _ = bad[0]
    bad[0] = (kind, "0" * 64)
    assert not mev.verify_merkle_steps(ids[4], bad, root, True)


def _save_block(st, txs, miner):
    height = st.chain_height() + 1
    prev = st.get_block(height - 1)
    cb = Transaction.coinbase(miner.address, 1.0, height)
    block = Block(index=height, prev_hash=prev.block_hash,
                  transactions=[cb] + list(txs), miner_address=miner.address,
                  difficulty=1.0)
    assert block.mine()
    st.save_block(block)


def test_reveal_still_validates_after_the_commitment_body_is_pruned(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 5)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    st = Storage(os.path.join(str(tmp_path), "pruned.db"))
    Blockchain(st)
    sender, receiver = Wallet.generate(), Wallet.generate()
    ts = int(time.time())
    salt = mev.new_salt()
    core = mev.core_transfer(sender.address, receiver.address, 1.0, 0.01, "", 1, ts)
    commit = mev.build_commitment_tx(sender, 1, ts, core.mev_commitment(salt))
    _save_block(st, [commit], sender)                      # commitment at height 1
    steps = mev.reveal_steps_for_commit(st, commit.tx_id, 1)
    reveal = mev.build_reveal_tx(sender, core, salt, 1, steps)
    for _ in range(9):
        _save_block(st, [], sender)                        # tip 10
    pruner = RollingWindowPruner(st)
    for h in range(6, 11):
        pruner.maybe_prune(h)
    assert not st.get_block(1).transactions                # the body is gone
    ok, msg = mev.check_reveal(st, reveal, 11)
    assert ok, msg
