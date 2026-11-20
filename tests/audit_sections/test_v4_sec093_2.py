"""Section 93 V4 Regression Tests: Mempool Eviction, Prioritization and Fairness."""

import time

from visold.kernel.config import Config
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def test_vvm_tx_rejects_bogus_and_negative_fee(tmp_path):
    """Fixed: VVM (TYPE_DEPLOY / TYPE_CALL) txs reject negative fees and fees
    exceeding their gas budget.
    """
    db_path = str(tmp_path / "chain.db")
    storage = Storage(db_path)
    mempool = Mempool(storage)

    honest_w = Wallet.generate()
    attacker_w = Wallet.generate()
    recv_w = Wallet.generate()

    storage.credit_sat(honest_w.address, 1_000 * Config.SATOSHI_PER_VSD)
    storage.credit_sat(attacker_w.address, 1 * Config.SATOSHI_PER_VSD)

    now = int(time.time())
    honest_tx = Transaction(
        sender=honest_w.address,
        receiver=recv_w.address,
        amount=500.0,
        fee=round(500.0 * Config.TX_FEE_RATE, 8),
        timestamp=now,
        nonce=0,
        expiry=now + 3600,
        tx_type=Transaction.TYPE_TRANSFER,
    )
    honest_tx.sign(honest_w)
    ok, msg = mempool.add(honest_tx)
    assert ok, f"Honest tx should be admitted: {msg}"

    attack_tx = Transaction(
        sender=attacker_w.address,
        receiver="",
        amount=0.0,
        fee=1_000_000.0,
        timestamp=now + 1,
        nonce=0,
        expiry=now + 3600,
        tx_type=Transaction.TYPE_DEPLOY,
        data="6001600101",
        gas_limit=100,
        gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    attack_tx.sign(attacker_w)
    ok_atk, msg_atk = mempool.add(attack_tx)
    assert not ok_atk, f"Bogus-fee VVM tx should be rejected, got: {msg_atk}"

    top1 = mempool.get_top(1)
    assert len(top1) == 1
    assert top1[0].tx_id == honest_tx.tx_id

    neg_tx = Transaction(
        sender=attacker_w.address,
        receiver="",
        amount=0.0,
        fee=-100.0,
        timestamp=now + 2,
        nonce=0,
        expiry=now + 3600,
        tx_type=Transaction.TYPE_DEPLOY,
        data="6001600101",
        gas_limit=100,
        gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    neg_tx.sign(attacker_w)
    ok_neg, msg_neg = mempool.add(neg_tx)
    assert not ok_neg, f"Negative-fee VVM tx should be rejected, got: {msg_neg}"


def test_mempool_add_purges_expired_at_cap(tmp_path, monkeypatch):
    """Fixed: Mempool.add() purges expired transactions before rejecting for MEMPOOL_MAX."""
    monkeypatch.setattr(Config, "MEMPOOL_MAX", 5)
    db_path = str(tmp_path / "chain.db")
    storage = Storage(db_path)
    mempool = Mempool(storage)

    base_now = int(time.time())
    monkeypatch.setattr(time, "time", lambda: float(base_now))

    recv_w = Wallet.generate()
    for i in range(5):
        w = Wallet.generate()
        storage.credit_sat(w.address, 100 * Config.SATOSHI_PER_VSD)
        tx = Transaction(
            sender=w.address,
            receiver=recv_w.address,
            amount=10.0,
            fee=round(10.0 * Config.TX_FEE_RATE, 8),
            timestamp=base_now,
            nonce=0,
            expiry=base_now + 5,
            tx_type=Transaction.TYPE_TRANSFER,
        )
        tx.sign(w)
        ok, msg = mempool.add(tx)
        assert ok, f"Setup tx {i} failed: {msg}"

    assert mempool.size() == 5

    monkeypatch.setattr(time, "time", lambda: float(base_now + 100))

    fresh_w = Wallet.generate()
    storage.credit_sat(fresh_w.address, 100 * Config.SATOSHI_PER_VSD)
    fresh_tx = Transaction(
        sender=fresh_w.address,
        receiver=recv_w.address,
        amount=10.0,
        fee=round(10.0 * Config.TX_FEE_RATE, 8),
        timestamp=base_now + 100,
        nonce=0,
        expiry=base_now + 3600,
        tx_type=Transaction.TYPE_TRANSFER,
    )
    fresh_tx.sign(fresh_w)
    ok, msg = mempool.add(fresh_tx)
    assert ok, f"Fresh tx should be admitted after purging expired txs, got: {msg}"
    assert mempool.size() == 1


def test_mempool_heap_remove_unknown_tx_id_preserves_size(tmp_path):
    """Fixed: _MempoolHeap.remove() does not decrement _size for unknown tx_ids."""
    db_path = str(tmp_path / "chain.db")
    storage = Storage(db_path)
    mempool = Mempool(storage)

    recv_w = Wallet.generate()
    now = int(time.time())
    for i in range(3):
        w = Wallet.generate()
        storage.credit_sat(w.address, 100 * Config.SATOSHI_PER_VSD)
        tx = Transaction(
            sender=w.address,
            receiver=recv_w.address,
            amount=10.0,
            fee=round(10.0 * Config.TX_FEE_RATE, 8),
            timestamp=now,
            nonce=0,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_TRANSFER,
        )
        tx.sign(w)
        ok, msg = mempool.add(tx)
        assert ok, f"Setup tx {i} failed: {msg}"

    assert mempool._heap.size() == 3
    assert mempool.size() == 3

    mempool.clear_confirmed(["peer_cb_0", "peer_tx_1", "peer_tx_2"])

    assert mempool.size() == 3
    assert len(mempool._heap.get_all_live()) == 3
    assert mempool._heap.size() == 3
