"""V4 regression tests for Section 29 (Session 02): Merkle Tree & SPV Proof Verification."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.receipt_relay import ReceiptRelayManager, _canonical_json
from visold.network.spv import SPVClient
from visold.wallet.wallet import Wallet


def _make_signed_tx(wallet: Wallet, receiver: str, amount: float, nonce: int, ts: int = 1_700_000_000) -> Transaction:
    tx = Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount=amount,
        fee=0.001,
        timestamp=ts,
        nonce=nonce,
    )
    tx.sign(wallet)
    return tx


def _make_coinbase(miner: str, height: int, ts: int = 1_700_000_000) -> Transaction:
    tx = Transaction(
        sender="COINBASE",
        receiver=miner,
        amount=50.0,
        fee=0.0,
        timestamp=ts,
        memo=f"reward:{height}",
        nonce=height,
    )
    tx.tx_id = tx._compute_id(height)
    return tx


def _make_block(index: int, txs, prev_hash: str = "0" * 64) -> Block:
    blk = Block(
        index=index,
        prev_hash=prev_hash,
        transactions=txs,
        miner_address="VSD_MINER",
        difficulty=0.001,
        timestamp=1_700_000_000 + index,
        nonce=1,
    )
    blk.block_hash = blk.compute_hash()
    return blk


def test_merkle_v2_and_spv_all_sizes():
    w = Wallet.generate()
    for n in range(1, 18):
        txs = [_make_coinbase(w.address, 1)] + [
            _make_signed_tx(w, "VSD_DEST", 1.0, nonce=i + 1) for i in range(n - 1)
        ]
        blk = _make_block(1, txs)
        root = blk._merkle()
        assert len(root) == 64
        for tx in txs:
            proof = SPVClient.get_merkle_proof(txs, tx.tx_id, block_height=blk.index)
            assert proof is not None
            assert SPVClient.verify_merkle_proof(tx.tx_id, proof, root) is True


def test_merkle_v2_prevents_cve_2012_2459():
    w = Wallet.generate()
    txs3 = [_make_coinbase(w.address, 1)] + [
        _make_signed_tx(w, "VSD_DEST", 1.0, nonce=i + 1) for i in range(2)
    ]
    txs4_dup = txs3 + [txs3[-1]]
    b3 = _make_block(1, txs3)
    b4 = _make_block(1, txs4_dup)
    assert b3._merkle() != b4._merkle()


def test_merkle_v1_legacy_when_activated(monkeypatch):
    monkeypatch.setattr(Config, "MERKLE_V2_ACTIVATION_HEIGHT", 10)
    w = Wallet.generate()
    txs3 = [_make_coinbase(w.address, 5)] + [
        _make_signed_tx(w, "VSD_DEST", 1.0, nonce=i + 1) for i in range(2)
    ]
    b_v1 = _make_block(5, txs3)
    root_v1 = b_v1._merkle()
    for tx in txs3:
        proof = SPVClient.get_merkle_proof(txs3, tx.tx_id, block_height=5)
        assert proof is not None
        assert SPVClient.verify_merkle_proof(tx.tx_id, proof, root_v1) is True


def test_block_integrity_check_merkle_and_header():
    w = Wallet.generate()
    txs = [_make_coinbase(w.address, 1), _make_signed_tx(w, "VSD_DEST", 2.0, nonce=1)]
    blk = _make_block(1, txs)
    ok, msg = blk.integrity_check()
    assert ok, msg

    bad = copy.deepcopy(blk)
    bad.merkle_root = "a" * 64
    ok, _ = bad.integrity_check()
    assert not ok

    d = blk.to_dict()
    d["pruned"] = True
    d["transactions"] = []
    pruned_blk = Block.from_dict(d)
    assert pruned_blk.is_pruned is True
    assert pruned_blk.merkle_root == blk.merkle_root
    ok, _ = pruned_blk.integrity_check()
    assert not ok


def test_spv_verify_merkle_proof_rejects_empty_and_split_strings():
    """SPVClient.verify_merkle_proof rejects empty, split, and root-as-leaf inputs."""
    assert SPVClient.verify_merkle_proof("", [], "") is False

    w = Wallet.generate()
    tx0 = _make_coinbase(w.address, 1)
    tx1 = _make_signed_tx(w, "VSD_DEST", 1.0, nonce=1)
    blk = _make_block(1, [tx0, tx1])
    root = blk.merkle_root

    forged_tx_id = tx0.tx_id[:16]
    forged_proof = [{"side": "R", "hash": tx0.tx_id[16:] + tx1.tx_id}]
    assert SPVClient.verify_merkle_proof(forged_tx_id, forged_proof, root) is False

    assert SPVClient.verify_merkle_proof("", [{"side": "R", "hash": tx0.tx_id + tx1.tx_id}], root) is False


def test_spv_verify_merkle_proof_root_as_leaf_rejected():
    w = Wallet.generate()
    tx0 = _make_coinbase(w.address, 1)
    tx1 = _make_signed_tx(w, "VSD_DEST", 1.0, nonce=1)
    blk = _make_block(1, [tx0, tx1])
    root = blk.merkle_root
    assert SPVClient.verify_merkle_proof(root, [], root) is False


def test_receipt_relay_merkle_verification():
    w_sender = Wallet.generate()
    w_recv = Wallet.generate()
    tx0 = _make_coinbase(w_sender.address, 1)
    tx1 = _make_signed_tx(w_sender, w_recv.address, 3.0, nonce=1)
    blk = _make_block(1, [tx0, tx1])

    class _DummyChain:
        def get_block(self, h):
            return blk if h == 1 else None

    mgr = ReceiptRelayManager(_DummyChain(), None, w_recv, "node-1")
    receipt = mgr.build_receipt(blk, tx1)
    assert receipt is not None
    ok, reason = mgr.verify_receipt(receipt, require_canonical=True)
    assert ok, reason

    bad_receipt = copy.deepcopy(receipt)
    bad_receipt["merkle_proof"][0]["hash"] = "f" * 64
    without_id = {k: v for k, v in bad_receipt.items() if k != "receipt_id"}
    bad_receipt["receipt_id"] = sha256(_canonical_json(without_id))
    ok, _ = mgr.verify_receipt(bad_receipt, require_canonical=True)
    assert not ok
