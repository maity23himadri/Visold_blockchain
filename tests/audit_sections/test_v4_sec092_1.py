import time

from visold.kernel.config import Config
from visold.kernel.units import VSD_GLOBAL_MARKET, to_satoshi
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


FAR_EXPIRY = 2_000_000_000


def _signed_transfer(wallet, receiver, nonce, amount=1.0, timestamp=1, expiry=FAR_EXPIRY, memo=""):
    tx = Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount=amount,
        fee=round(amount * Config.TX_FEE_RATE, 8),
        nonce=nonce,
        timestamp=timestamp,
        expiry=expiry,
        memo=memo,
        tx_type=Transaction.TYPE_TRANSFER,
    )
    tx.sign(wallet)
    return tx


def test_v4_mempool_rejects_and_does_not_restore_pruned_tx_present_in_replay_guard(tmp_path):
    """
    Fixed: Mempool.add() and Mempool.restore() consult tx_replay_guard
    and reject already-applied transactions even after `transactions` rows are pruned.
    """
    storage = Storage(str(tmp_path / "replay_guard_mempool.db"))
    pool = Mempool(storage)
    sender = Wallet.generate()
    storage.credit_sat(sender.address, to_satoshi(100.0))

    tx = _signed_transfer(
        sender,
        VSD_GLOBAL_MARKET,
        nonce=0,
        amount=1.0,
        timestamp=100,
        memo="ORDER:BUY:1",
    )

    storage.record_applied_tx_id(tx.tx_id)
    assert storage.tx_exists(tx.tx_id) is False
    assert storage.replay_guard_exists(tx.tx_id) is True
    assert tx.tx_id in storage.existing_tx_ids([tx.tx_id])

    ok_add, msg_add = pool.add(tx)
    assert ok_add is False, f"Expected Mempool.add() to reject replayed tx, got: {ok_add}, {msg_add}"
    assert "Already in chain" in msg_add

    ok_restore, msg_restore = pool.restore(tx)
    assert ok_restore is False, f"Expected Mempool.restore() to reject replayed tx, got: {ok_restore}, {msg_restore}"


def test_v4_mempool_remove_preserves_pending_nonce_and_rejects_duplicate_market_nonce(tmp_path):
    """
    Fixed: VSD_GLOBAL_MARKET txs obey nonce rules, and removing a later nonce
    preserves earlier pending nonces so conflicting txs are rejected.
    """
    storage = Storage(str(tmp_path / "shared_nonce_remove.db"))
    pool = Mempool(storage)
    sender = Wallet.generate()
    receiver1 = Wallet.generate().address
    receiver2 = Wallet.generate().address
    storage.credit_sat(sender.address, to_satoshi(100.0))

    tx_norm = _signed_transfer(sender, receiver1, nonce=0, amount=1.0, timestamp=10)
    ok, msg = pool.add(tx_norm)
    assert ok, msg

    # Duplicate nonce=0 for VSD_GLOBAL_MARKET is rejected
    tx_mkt_dup = _signed_transfer(
        sender, VSD_GLOBAL_MARKET, nonce=0, amount=2.0, timestamp=11, memo="ORDER:SELL:2"
    )
    ok_dup, msg_dup = pool.add(tx_mkt_dup)
    assert ok_dup is False
    assert "Nonce mismatch" in msg_dup

    # Sequential nonce=1 for VSD_GLOBAL_MARKET is admitted, then removed
    tx_mkt = _signed_transfer(
        sender, VSD_GLOBAL_MARKET, nonce=1, amount=2.0, timestamp=11, memo="ORDER:SELL:2"
    )
    ok, msg = pool.add(tx_mkt)
    assert ok, msg
    assert 0 in pool._pending_nonces[sender.address]
    assert 1 in pool._pending_nonces[sender.address]

    pool.remove(tx_mkt.tx_id)
    assert pool.storage.mempool_get_by_id(tx_norm.tx_id) is not None
    assert 0 in pool._pending_nonces[sender.address]

    # Subsequent nonce=1 tx is admitted cleanly
    tx_next = _signed_transfer(sender, receiver2, nonce=1, amount=1.0, timestamp=12)
    ok_next, msg_next = pool.add(tx_next)
    assert ok_next is True, msg_next

    # Conflicting normal transfer at nonce=0 is rejected
    tx_conflict = _signed_transfer(sender, receiver2, nonce=0, amount=3.0, timestamp=13)
    ok_conflict, msg_conflict = pool.add(tx_conflict)
    assert ok_conflict is False


def test_v4_mempool_purge_expired_preserves_other_pending_nonces(tmp_path):
    """
    Fixed: Expiring a tx at nonce=1 does not drop nonce=0 from _pending_nonces,
    and conflicting nonce=0 txs remain rejected.
    """
    storage = Storage(str(tmp_path / "shared_nonce_expire.db"))
    pool = Mempool(storage)
    sender = Wallet.generate()
    receiver1 = Wallet.generate().address
    receiver2 = Wallet.generate().address
    storage.credit_sat(sender.address, to_satoshi(100.0))

    now = int(time.time())
    tx_norm = _signed_transfer(
        sender, receiver1, nonce=0, amount=1.0, timestamp=10, expiry=now + 3600
    )
    assert pool.add(tx_norm)[0] is True

    tx_mkt = _signed_transfer(
        sender, VSD_GLOBAL_MARKET, nonce=1, amount=2.0, timestamp=11, expiry=now + 1
    )
    assert pool.add(tx_mkt)[0] is True

    time.sleep(2.1)
    with pool._lock:
        pool._purge_expired()

    assert pool.storage.mempool_get_by_id(tx_norm.tx_id) is not None
    assert 0 in pool._pending_nonces[sender.address]

    tx_conflict = _signed_transfer(
        sender, receiver2, nonce=0, amount=3.0, timestamp=12, expiry=now + 3600
    )
    ok_conflict, _ = pool.add(tx_conflict)
    assert ok_conflict is False
