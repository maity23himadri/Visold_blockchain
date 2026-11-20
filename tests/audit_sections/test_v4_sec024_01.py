"""V4 regression tests for Section 24 (Session 01): Transaction Signature Authentication and Malleability."""
from __future__ import annotations

import hashlib
import sqlite3
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.crypto.ecc import (
    ECPoint,
    ecdsa_verify,
    sig_from_hex,
    sig_to_hex,
)
from visold.crypto.hashing import sha256
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.receipt_relay import ReceiptRelayManager, _canonical_json
from visold.wallet.wallet import Wallet


def _make_receipt_env():
    """Create a minimal ReceiptRelayManager backed by an in-memory SQLite DB."""
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """CREATE TABLE relay_receipts (
               receipt_id TEXT PRIMARY KEY,
               receiver TEXT NOT NULL,
               slot INTEGER NOT NULL,
               block_height INTEGER NOT NULL,
               block_hash TEXT NOT NULL,
               receipt_json TEXT NOT NULL,
               stored_at INTEGER NOT NULL,
               delivered_at INTEGER NOT NULL DEFAULT 0
           )"""
    )
    conn.execute(
        """CREATE TABLE relay_receipt_acks (
               receipt_id TEXT NOT NULL,
               receiver TEXT NOT NULL,
               ack_json TEXT NOT NULL,
               acked_at INTEGER NOT NULL,
               PRIMARY KEY (receipt_id, receiver)
           )"""
    )
    conn.execute(
        """CREATE TABLE wallet_receipts (
               receipt_id TEXT PRIMARY KEY,
               block_height INTEGER NOT NULL,
               block_hash TEXT NOT NULL,
               sender TEXT NOT NULL,
               receiver TEXT NOT NULL,
               amount_sat INTEGER NOT NULL,
               tx_type TEXT NOT NULL,
               timestamp INTEGER NOT NULL,
               receipt_json TEXT NOT NULL,
               received_at INTEGER NOT NULL
           )"""
    )
    conn.commit()

    sender_wallet = Wallet.generate()
    receiver_wallet = Wallet.generate()

    tx = Transaction(
        sender=sender_wallet.address,
        receiver=receiver_wallet.address,
        amount=5.0,
        fee=0.05,
        timestamp=1_700_000_000,
        nonce=0,
    )
    tx.sign(sender_wallet)

    block = Block(
        index=1,
        transactions=[tx],
        prev_hash="0" * 64,
        miner_address=sender_wallet.address,
        difficulty=1,
        timestamp=1_700_000_005,
    )

    storage = SimpleNamespace(_aux_lock=threading.Lock(), _conn=lambda: conn)
    blockchain = SimpleNamespace(
        get_block=lambda h: block if h == 1 else None,
        height=lambda: 1,
    )
    mgr = ReceiptRelayManager(blockchain, storage, receiver_wallet, node_id="node-1")
    return mgr, block, tx, conn


def test_receipt_verify_rejects_malleated_sig_pubkey_and_extra_fields():
    """ReceiptRelayManager.verify_receipt(..., require_canonical=True) rejects
    high-S malleated signatures, non-canonical sig_hex JSON, non-canonical pub_hex,
    and extra unauthenticated dict keys."""
    mgr, block, tx, conn = _make_receipt_env()
    original = mgr.build_receipt(block, tx)
    assert original is not None
    ok, msg = mgr.verify_receipt(original, require_canonical=True)
    assert ok, msg

    assert mgr.store_relay_receipt(original, slot=0) == (True, "stored")
    ack = mgr.make_ack(original["receipt_id"])
    assert mgr.accept_ack(ack) == (True, "ACK accepted")

    # 1. High-S signature malleability: flip s -> N - s
    r, s = sig_from_hex(original["sig_hex"])
    high_s = ECPoint.N - s
    assert high_s != s
    malleated_high_s = dict(original)
    malleated_high_s.pop("receipt_id")
    malleated_high_s["sig_hex"] = sig_to_hex((r, high_s))
    malleated_high_s["receipt_id"] = sha256(_canonical_json(malleated_high_s))
    assert malleated_high_s["receipt_id"] != original["receipt_id"]

    ok_hs, _msg_hs = mgr.verify_receipt(malleated_high_s, require_canonical=True)
    assert ok_hs is False

    # 2. Non-canonical sig_hex JSON (extra array element + whitespace)
    malleated_json = dict(original)
    malleated_json.pop("receipt_id")
    malleated_json["sig_hex"] = f"[{r}, {s}, 999]"
    malleated_json["receipt_id"] = sha256(_canonical_json(malleated_json))
    ok_js, _msg_js = mgr.verify_receipt(malleated_json, require_canonical=True)
    assert ok_js is False

    # 3. Non-canonical pub_hex (uppercase + whitespace) and extra dict key
    malleated_pub = dict(original)
    malleated_pub.pop("receipt_id")
    malleated_pub["pub_hex"] = original["pub_hex"].upper() + " "
    malleated_pub["extra_unauthenticated_key"] = "spam"
    malleated_pub["receipt_id"] = sha256(_canonical_json(malleated_pub))
    ok_pub, _msg_pub = mgr.verify_receipt(malleated_pub, require_canonical=True)
    assert ok_pub is False

    # Malleated receipts cannot be stored or delivered to wallet_receipts
    assert mgr.store_relay_receipt(malleated_high_s, slot=0)[0] is False
    assert mgr.store_relay_receipt(malleated_json, slot=0)[0] is False
    assert mgr.deliver_to_local_wallet(original) == (True, "delivered")
    assert mgr.deliver_to_local_wallet(malleated_high_s)[0] is False

    wallet_rows = conn.execute("SELECT COUNT(*) FROM wallet_receipts").fetchone()[0]
    assert wallet_rows == 1


def test_sig_from_hex_and_ecdsa_verify_reject_malformed_inputs():
    """sig_from_hex rejects extra array elements and bools; ecdsa_verify returns False on malformed sig."""
    w = Wallet.generate()
    msg_hash = hashlib.sha256(b"test-message").digest()
    tx = Transaction(sender=w.address, receiver=w.address, amount=1.0, timestamp=1_700_000_000)
    tx.sign(w)
    r, s = sig_from_hex(tx.sig_hex)

    with pytest.raises(ValueError):
        sig_from_hex(f"[{r}, {s}, \"trailing\", 12345]")

    with pytest.raises(ValueError):
        sig_from_hex("[true, false]")

    assert ecdsa_verify(w.pub, msg_hash, (r, s, 999)) is False  # type: ignore[arg-type]
    assert ecdsa_verify(w.pub, msg_hash, None) is False  # type: ignore[arg-type]


def test_unsigned_coinbase_register_tx_rejected():
    """Transaction.is_valid() and verify_signature() reject an unsigned COINBASE TYPE_REGISTER tx."""
    tx = Transaction(
        sender="COINBASE",
        receiver="",
        amount=10.0,
        fee=0.0,
        timestamp=1_700_000_000,
        tx_type=Transaction.TYPE_REGISTER,
        memo="miner",
        pub_hex="",
        sig_hex="",
    )
    assert tx.verify_signature() is False
    ok, _msg = tx.is_valid(reference_time=1_700_000_000)
    assert ok is False
