"""V4 regression tests for Section 29 (Session 01): Merkle Tree & SPV Proof Verification."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.crypto.ecc import ecdsa_keygen
from visold.crypto.hashing import sha256
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.spv import SPVClient
from visold.wallet.wallet import Wallet


def _new_wallet() -> Wallet:
    priv, pub = ecdsa_keygen()
    return Wallet(priv, pub)


def _make_signed_tx(wallet: Wallet, receiver: str, amount: int, nonce: int) -> Transaction:
    tx = Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount=amount,
        nonce=nonce,
        timestamp=1_700_000_000 + nonce,
    )
    tx.sign(wallet)
    return tx


def _make_block(n_txs: int, index: int = 1) -> Block:
    w1 = _new_wallet()
    w2 = _new_wallet()
    txs = []
    if n_txs >= 1:
        cb = Transaction.coinbase(w1.address, 50, index)
        txs.append(cb)
    for i in range(1, n_txs):
        txs.append(_make_signed_tx(w1, w2.address, 100 + i, nonce=i))
    blk = Block(
        index=index,
        prev_hash="0" * 64,
        transactions=txs,
        miner_address=w1.address,
        difficulty=0.001,
        timestamp=1_700_000_100,
    )
    blk.seal()
    return blk


def test_spv_verify_merkle_proof_rejects_preimage_splitting_forgery():
    """SPVClient.verify_merkle_proof validates 64-hex digests and 'side' keys, rejecting preimage splitting."""
    blk = _make_block(2, index=1)
    tx0_id = blk.transactions[0].tx_id
    tx1_id = blk.transactions[1].tx_id
    assert len(tx0_id) == 64 and len(tx1_id) == 64

    assert SPVClient.verify_merkle_proof(
        "", [{"side": "R", "hash": tx0_id + tx1_id}], blk.merkle_root
    ) is False

    fake_prefix = tx0_id[:16]
    assert SPVClient.verify_merkle_proof(
        fake_prefix, [{"side": "R", "hash": tx0_id[16:] + tx1_id}], blk.merkle_root
    ) is False

    assert SPVClient.verify_merkle_proof(
        tx0_id, [{"hash": tx1_id}], blk.merkle_root
    ) is False

    assert SPVClient.verify_merkle_proof("", [], "") is False


def test_merkle_internal_node_and_root_rejected_as_leaf():
    """Internal Merkle nodes and merkle_root itself cannot be proven as valid leaf transactions."""
    blk4 = _make_block(4, index=2)
    ids = [t.tx_id for t in blk4.transactions]
    h01 = sha256((ids[0] + ids[1]).encode())
    h23 = sha256((ids[2] + ids[3]).encode())
    assert h01 not in ids
    assert blk4.merkle_root not in ids

    assert SPVClient.verify_merkle_proof(
        h01, [{"side": "R", "hash": h23}], blk4.merkle_root
    ) is False

    assert SPVClient.verify_merkle_proof(
        blk4.merkle_root, [], blk4.merkle_root
    ) is False

    empty_blk = _make_block(0, index=3)
    assert SPVClient.verify_merkle_proof(
        empty_blk.merkle_root, [], empty_blk.merkle_root
    ) is False


def test_merkle_v1_v2_roundtrip_and_tamper_rejection():
    """Verify normal V2 and V1 Merkle root & SPV proof roundtrips across odd/even sizes."""
    for n in (1, 2, 3, 4, 5, 7, 8):
        blk = _make_block(n, index=10)
        ok, reason = blk.integrity_check()
        assert ok, reason
        for tx in blk.transactions:
            proof = SPVClient.get_merkle_proof(list(blk.transactions), tx.tx_id, block_height=blk.index)
            assert proof is not None
            assert SPVClient.verify_merkle_proof(tx.tx_id, proof, blk.merkle_root) is True

    blk3 = _make_block(3, index=10)
    object.__setattr__(blk3, "merkle_root", "f" * 64)
    ok, reason = blk3.integrity_check()
    assert not ok
    assert "merkle_root mismatch" in reason
