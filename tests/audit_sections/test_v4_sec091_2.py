"""V4 regression tests for Section 91: Mempool Transaction Admission and Validation."""

from visold.crypto.ecc import ecdsa_keygen
from visold.kernel.config import Config
from visold.kernel.units import to_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_wallet() -> Wallet:
    priv, pub = ecdsa_keygen()
    return Wallet(priv, pub)


def test_tampered_tx_id_rejected_and_honest_tx_admitted(tmp_path):
    """Fixed: Transaction.is_valid() and Mempool.add() verify tx_id == _compute_id()."""
    storage = Storage(str(tmp_path / "chain.db"))
    mempool = Mempool(storage)
    sender = _make_wallet()
    receiver = _make_wallet()
    storage.credit_sat(sender.address, to_satoshi(100.0))

    honest_tx = Transaction(
        sender=sender.address,
        receiver=receiver.address,
        amount=10.0,
        fee=round(10.0 * Config.TX_FEE_RATE, 8),
        nonce=0,
    )
    honest_tx.sign(sender)
    assert honest_tx.tx_id == honest_tx._compute_id()

    spoofed_dict = honest_tx.to_dict()
    spoofed_dict["tx_id"] = "a" * 64
    spoofed_tx = Transaction.from_dict(spoofed_dict)

    ok_valid, msg_valid = spoofed_tx.is_valid()
    assert not ok_valid, f"Expected is_valid() to reject tampered tx_id, got: {msg_valid}"

    ok_add, msg_add = mempool.add(spoofed_tx)
    assert not ok_add, f"Expected mempool.add() to reject tampered tx_id, got: {msg_add}"

    # Honest tx with the same nonce is admitted cleanly
    ok_honest, msg_honest = mempool.add(honest_tx)
    assert ok_honest, msg_honest

    top_txs = mempool.get_top(10)
    assert [t.tx_id for t in top_txs] == [honest_tx.tx_id]
    cb = Transaction.coinbase(sender.address, 50.0, 1)
    block = Block(
        index=1,
        prev_hash="0" * 64,
        transactions=[cb] + top_txs,
        miner_address=sender.address,
        difficulty=Config.MIN_DIFFICULTY,
    )
    ok_blk, msg_blk = block.integrity_check()
    assert ok_blk, msg_blk


def test_unauthenticated_coinbase_tx_rejected_by_mempool(tmp_path):
    """Fixed: Mempool.add() rejects unauthenticated COINBASE transactions."""
    storage = Storage(str(tmp_path / "chain.db"))
    mempool = Mempool(storage)
    attacker_recv = _make_wallet()
    honest_sender = _make_wallet()
    honest_recv = _make_wallet()
    storage.credit_sat(honest_sender.address, to_satoshi(200.0))

    forged_cb = Transaction(
        sender="COINBASE",
        receiver=attacker_recv.address,
        amount=1_000_000.0,
        fee=999_999.0,
        expiry=0,
    )
    assert forged_cb.pub_hex == "" and forged_cb.sig_hex == ""

    ok_add, msg_add = mempool.add(forged_cb)
    assert not ok_add, f"Expected mempool.add() to reject forged COINBASE, got: {msg_add}"

    honest_tx = Transaction(
        sender=honest_sender.address,
        receiver=honest_recv.address,
        amount=100.0,
        fee=round(100.0 * Config.TX_FEE_RATE, 8),
        nonce=0,
    )
    honest_tx.sign(honest_sender)
    ok_h, msg_h = mempool.add(honest_tx)
    assert ok_h, msg_h

    top = mempool.get_top(10)
    assert len(top) == 1
    assert top[0].tx_id == honest_tx.tx_id


def test_vvm_tx_rejects_negative_and_unbacked_fake_fee(tmp_path):
    """Fixed: TYPE_DEPLOY/TYPE_CALL reject negative fees and fees exceeding gas budget."""
    storage = Storage(str(tmp_path / "chain.db"))
    mempool = Mempool(storage)
    vvm_sender = _make_wallet()
    xfer_sender = _make_wallet()
    xfer_recv = _make_wallet()
    storage.credit_sat(vvm_sender.address, to_satoshi(100.0))
    storage.credit_sat(xfer_sender.address, to_satoshi(200.0))

    vvm_neg = Transaction(
        sender=vvm_sender.address,
        receiver="",
        amount=0.0,
        fee=-1.0,
        nonce=0,
        tx_type=Transaction.TYPE_DEPLOY,
        data="6000",
        gas_limit=21000,
        gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    vvm_neg.sign(vvm_sender)
    ok_neg, msg_neg = vvm_neg.is_valid()
    assert not ok_neg, f"Expected negative-fee deploy to fail is_valid(), got: {msg_neg}"

    vvm_high = Transaction(
        sender=vvm_sender.address,
        receiver="",
        amount=0.0,
        fee=1_000_000.0,
        nonce=0,
        tx_type=Transaction.TYPE_DEPLOY,
        data="6000",
        gas_limit=21000,
        gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    vvm_high.sign(vvm_sender)
    ok_high, msg_high = mempool.add(vvm_high)
    assert not ok_high, f"Expected unbacked fake-fee deploy to be rejected, got: {msg_high}"

    honest_xfer = Transaction(
        sender=xfer_sender.address,
        receiver=xfer_recv.address,
        amount=100.0,
        fee=round(100.0 * Config.TX_FEE_RATE, 8),
        nonce=0,
    )
    honest_xfer.sign(xfer_sender)
    ok_xfer, msg_xfer = mempool.add(honest_xfer)
    assert ok_xfer, msg_xfer

    top = mempool.get_top(10)
    assert [t.tx_id for t in top] == [honest_xfer.tx_id]
