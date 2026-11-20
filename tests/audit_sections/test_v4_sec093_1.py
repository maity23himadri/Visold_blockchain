"""V4 regression tests for VISOLD Section 93: Mempool Eviction, Prioritization and Fairness."""

import time

from visold.kernel.config import Config
from visold.kernel.units import from_satoshi, gas_fee_to_sat, to_satoshi
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_pool(tmp_path):
    db_path = str(tmp_path / "visold_s93.db")
    storage = Storage(db_path)
    pool = Mempool(storage)
    return storage, pool


def test_v4_fake_fee_priority_hijacking_rejected(tmp_path):
    """Fixed: TYPE_CALL/TYPE_DEPLOY reject tx.fee exceeding gas budget, and
    get_top() prioritizes by actual consensus fee rather than unbacked fake fees.
    """
    storage, pool = _make_pool(tmp_path)
    now = int(time.time())

    alice = Wallet.generate()
    bob = Wallet.generate()
    carol = Wallet.generate()
    recipient = Wallet.generate()

    min_stake_vsd = from_satoshi(int(Config.MIN_MINER_STAKE))
    storage.credit_sat(alice.address, to_satoshi(500.0))
    storage.credit_sat(bob.address, to_satoshi(10.0))
    storage.credit_sat(carol.address, to_satoshi(min_stake_vsd + 10.0))

    tx_alice = Transaction(
        sender=alice.address,
        receiver=recipient.address,
        amount=100.0,
        fee=round(100.0 * Config.TX_FEE_RATE, 8),
        nonce=0,
        timestamp=now,
        expiry=now + 3600,
        tx_type=Transaction.TYPE_TRANSFER,
    )
    tx_alice.sign(alice)
    ok, msg = pool.add(tx_alice)
    assert ok, f"Alice transfer rejected: {msg}"

    # Bob: VVM TYPE_CALL with fake tx.fee = 1000.0 > gas budget -> rejected
    tx_bob = Transaction(
        sender=bob.address,
        receiver="VSDc" + "0" * 36,
        amount=0.0,
        fee=1000.0,
        nonce=0,
        timestamp=now + 1,
        expiry=now + 3600,
        tx_type=Transaction.TYPE_CALL,
        data="00",
        gas_limit=1,
        gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    tx_bob.sign(bob)
    ok_bob, msg_bob = pool.add(tx_bob)
    assert not ok_bob, f"Expected fake-fee VVM call to be rejected, got: {msg_bob}"

    # Carol: TYPE_REGISTER with fake tx.fee = 2000.0 -> rejected or ranked below Alice
    tx_carol = Transaction(
        sender=carol.address,
        receiver="",
        amount=min_stake_vsd,
        fee=2000.0,
        memo="miner",
        nonce=0,
        timestamp=now + 2,
        expiry=now + 3600,
        tx_type=Transaction.TYPE_REGISTER,
    )
    tx_carol.sign(carol)
    pool.add(tx_carol)

    top = pool.get_top(3)
    assert top[0].tx_id == tx_alice.tx_id


def test_v4_honest_vvm_zero_fee_ranked_by_gas_budget(tmp_path):
    """Fixed: An honest TYPE_CALL with default fee=0.0 and high gas_limit * gas_price
    is ranked above a tiny-fee transfer in Mempool.get_top().
    """
    storage, pool = _make_pool(tmp_path)
    now = int(time.time())

    alice = Wallet.generate()
    bob = Wallet.generate()
    recipient = Wallet.generate()

    storage.credit_sat(alice.address, to_satoshi(100.0))
    storage.credit_sat(bob.address, to_satoshi(2000.0))

    tx_alice = Transaction(
        sender=alice.address,
        receiver=recipient.address,
        amount=1.0,
        fee=round(1.0 * Config.TX_FEE_RATE, 8),
        nonce=0,
        timestamp=now,
        expiry=now + 3600,
        tx_type=Transaction.TYPE_TRANSFER,
    )
    tx_alice.sign(alice)
    ok, msg = pool.add(tx_alice)
    assert ok, f"Alice transfer rejected: {msg}"

    tx_bob = Transaction(
        sender=bob.address,
        receiver="VSDc" + "1" * 36,
        amount=0.0,
        fee=0.0,
        nonce=0,
        timestamp=now + 1,
        expiry=now + 3600,
        tx_type=Transaction.TYPE_CALL,
        data="00",
        gas_limit=100_000,
        gas_price=0.01,
    )
    tx_bob.sign(bob)
    ok, msg = pool.add(tx_bob)
    assert ok, f"Bob call rejected: {msg}"

    assert gas_fee_to_sat(tx_bob.gas_limit, tx_bob.gas_price) > tx_alice.compute_fee_sat()
    top = pool.get_top(2)
    assert [t.tx_id for t in top] == [tx_bob.tx_id, tx_alice.tx_id]


def test_v4_mempool_heap_remove_nonexistent_preserves_size(tmp_path):
    """Fixed: _MempoolHeap.remove() does not decrement _size when tx_id is absent."""
    storage, pool = _make_pool(tmp_path)
    now = int(time.time())

    alice = Wallet.generate()
    bob = Wallet.generate()
    recipient = Wallet.generate()

    storage.credit_sat(alice.address, to_satoshi(100.0))
    storage.credit_sat(bob.address, to_satoshi(100.0))

    tx1 = Transaction(
        sender=alice.address,
        receiver=recipient.address,
        amount=1.0,
        fee=0.01,
        nonce=0,
        timestamp=now,
        expiry=now + 3600,
    )
    tx1.sign(alice)
    assert pool.add(tx1)[0]

    tx2 = Transaction(
        sender=bob.address,
        receiver=recipient.address,
        amount=1.0,
        fee=0.01,
        nonce=0,
        timestamp=now + 1,
        expiry=now + 3600,
    )
    tx2.sign(bob)
    assert pool.add(tx2)[0]

    assert pool._heap.size() == 2
    assert len(pool._heap.get_all_live()) == 2

    pool.clear_confirmed(["coinbase_tx_0", "peer_mined_tx_1"])

    assert pool._heap.size() == 2
    assert len(pool._heap.get_all_live()) == 2
    assert pool.size() == 2
