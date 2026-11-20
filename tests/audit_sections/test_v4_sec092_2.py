"""Section 92 V4 Regression Tests: Duplicate Transactions, Replacement and Conflict Resolution."""
from __future__ import annotations

import os
import tempfile
import time

from visold.kernel.config import Config
from visold.kernel.units import VSD_GLOBAL_MARKET, to_satoshi
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_signed_transfer(
    wallet: Wallet,
    receiver: str,
    amount: float,
    nonce: int,
    expiry: int,
    memo: str = "",
) -> Transaction:
    fee = round(amount * Config.TX_FEE_RATE, 8)
    tx = Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount=amount,
        fee=fee,
        nonce=nonce,
        expiry=expiry,
        memo=memo,
        tx_type=Transaction.TYPE_TRANSFER,
    )
    tx.sign(wallet)
    return tx


def test_mempool_add_and_restore_reject_pruned_tx_in_replay_guard():
    """
    Fixed: Mempool.add() and Mempool.restore() check replay_guard_exists()
    and reject already-confirmed tx_ids even after `transactions` row pruning.
    """
    with tempfile.TemporaryDirectory() as td:
        storage = Storage(os.path.join(td, "chain.db"))
        mempool = Mempool(storage)
        alice = Wallet.generate()
        storage.credit_sat(alice.address, to_satoshi(100.0))
        now = int(time.time())

        tx = _make_signed_transfer(
            alice,
            receiver=VSD_GLOBAL_MARKET,
            amount=1.0,
            nonce=0,
            expiry=now + 3600,
            memo="ORDER:SELL:1:10",
        )

        storage.record_applied_tx_id(tx.tx_id)
        storage.set_nonce(alice.address, 1)

        assert not storage.tx_exists(tx.tx_id)
        assert storage.replay_guard_exists(tx.tx_id)
        assert tx.tx_id in storage.existing_tx_ids([tx.tx_id])

        ok_add, msg_add = mempool.add(tx)
        assert ok_add is False, f"Expected add() to reject replayed tx, got: {msg_add}"
        assert tx.tx_id not in mempool._pending_tx_ids

        ok_restore, msg_restore = mempool.restore(tx)
        assert ok_restore is False, (
            f"Expected restore() to reject replayed tx, got: {msg_restore}"
        )


def test_vsd_global_market_enforces_nonce_and_rejects_duplicate_nonce():
    """
    Fixed: Mempool.add() enforces nonces for VSD_GLOBAL_MARKET txs,
    so duplicate nonce=0 is rejected and pending_nonces remains consistent.
    """
    with tempfile.TemporaryDirectory() as td:
        storage = Storage(os.path.join(td, "chain.db"))
        mempool = Mempool(storage)
        alice = Wallet.generate()
        bob = Wallet.generate()
        carol = Wallet.generate()
        storage.credit_sat(alice.address, to_satoshi(100.0))
        now = int(time.time())

        tx1 = _make_signed_transfer(
            alice, receiver=bob.address, amount=1.0, nonce=0, expiry=now + 3600
        )
        ok1, msg1 = mempool.add(tx1)
        assert ok1, msg1
        assert 0 in mempool._pending_nonces[alice.address]

        # Duplicate nonce=0 for VSD_GLOBAL_MARKET is rejected
        tx2_dup = _make_signed_transfer(
            alice,
            receiver=VSD_GLOBAL_MARKET,
            amount=2.0,
            nonce=0,
            expiry=now + 3600,
            memo="ORDER:BUY:2:5",
        )
        ok2_dup, msg2_dup = mempool.add(tx2_dup)
        assert ok2_dup is False, f"Expected duplicate nonce=0 to be rejected, got: {msg2_dup}"

        # Sequential nonce=1 is admitted and then removed without corrupting nonce=0
        tx2 = _make_signed_transfer(
            alice,
            receiver=VSD_GLOBAL_MARKET,
            amount=2.0,
            nonce=1,
            expiry=now + 3600,
            memo="ORDER:BUY:2:5",
        )
        ok2, msg2 = mempool.add(tx2)
        assert ok2, msg2

        mempool.remove(tx2.tx_id)
        assert storage.mempool_get_by_id(tx1.tx_id) is not None
        assert 0 in mempool._pending_nonces[alice.address]

        tx3 = _make_signed_transfer(
            alice, receiver=carol.address, amount=3.0, nonce=0, expiry=now + 3600
        )
        ok3, msg3 = mempool.add(tx3)
        assert ok3 is False, f"Expected conflicting nonce=0 to be rejected, got: {msg3}"

        pending_alice_nonces = [
            t.nonce for t in mempool.all_txs() if t.sender == alice.address
        ]
        assert pending_alice_nonces == [0]
