"""V4 regression tests for Section 21 (Session 02): Transaction Structure, Serialization and Canonical Hashing."""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.kernel.config import Config
from visold.kernel.units import VSD_GLOBAL_MARKET
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_funded_mempool(tmpdir: str, wallet: Wallet, balance_vsd: float = 1000.0):
    db_path = f"{tmpdir}/chain.db"
    storage = Storage(db_path)
    storage.credit_sat(wallet.address, int(round(balance_vsd * Config.SATOSHI_PER_VSD)))
    mempool = Mempool(storage)
    return storage, mempool


def test_from_dict_preserves_zero_expiry_and_timestamp():
    """from_dict(tx.to_dict()) preserves expiry=0 and timestamp=0, keeping tx_id and signature valid."""
    w1 = Wallet.generate()
    w2 = Wallet.generate()

    tx = Transaction(
        sender=w1.address,
        receiver=w2.address,
        amount=10.0,
        fee=0.1,
        timestamp=0,
        nonce=0,
        expiry=0,
    )
    tx.sign(w1)
    assert tx.is_expired() is False
    assert tx.tx_id == tx._compute_id()
    assert tx.verify_signature() is True

    d = tx.to_dict()
    assert d["expiry"] == 0
    assert d["timestamp"] == 0

    tx_rt = Transaction.from_dict(d)
    assert tx_rt.expiry == 0
    assert tx_rt.timestamp == 0
    assert tx_rt._compute_id() == tx_rt.tx_id
    assert tx_rt.verify_signature() is True


def test_from_dict_preserves_version_and_detects_tampering():
    """from_dict() preserves 'version', so v2 round-trips and tampered version fails validation."""
    w1 = Wallet.generate()
    w2 = Wallet.generate()

    tx = Transaction(
        sender=w1.address,
        receiver=w2.address,
        amount=5.0,
        fee=0.05,
        timestamp=1700000000,
        nonce=0,
        expiry=1700003600,
        version=2,
    )
    tx.sign(w1)
    assert tx.tx_id == tx._compute_id()
    assert tx.verify_signature() is True

    d = tx.to_dict()
    assert d["version"] == 2

    tx_rt = Transaction.from_dict(d)
    assert tx_rt.version == 2
    assert tx_rt._compute_id() == tx_rt.tx_id
    assert tx_rt.verify_signature() is True

    # Tampered "version": 999 in dict must NOT silently normalize to 1 and pass
    tx_v1 = Transaction(
        sender=w1.address,
        receiver=w2.address,
        amount=5.0,
        fee=0.05,
        timestamp=1700000000,
        nonce=0,
        expiry=1700003600,
    )
    tx_v1.sign(w1)
    tampered = tx_v1.to_dict()
    tampered["version"] = 999
    tx_tampered = Transaction.from_dict(tampered)
    assert tx_tampered.version == 999
    ok_t, _ = tx_tampered.is_valid(reference_time=1700000010)
    assert ok_t is False


def test_forged_tx_id_rejected_by_is_valid_and_mempool():
    """Transaction.is_valid() and Mempool.add() verify tx.tx_id == tx._compute_id() and reject forged tx_ids."""
    w1 = Wallet.generate()
    now = int(time.time())

    tx = Transaction(
        sender=w1.address,
        receiver=VSD_GLOBAL_MARKET,
        amount=1.0,
        fee=0.01,
        timestamp=now,
        nonce=0,
        expiry=now + 3600,
    )
    tx.sign(w1)

    with tempfile.TemporaryDirectory() as tmpdir:
        _, mempool = _make_funded_mempool(tmpdir, w1)

        d1 = tx.to_dict()
        d1["tx_id"] = "a" * 64
        tx1 = Transaction.from_dict(d1)
        assert tx1.tx_id != tx1._compute_id()

        ok_v, _ = tx1.is_valid(reference_time=now + 10)
        assert ok_v is False

        ok1, _msg1 = mempool.add(tx1)
        assert ok1 is False

        # Block.integrity_check() also rejects the forged tx_id
        block = Block(
            index=1,
            prev_hash="0" * 64,
            transactions=[tx1],
            timestamp=now + 10,
            miner_address=w1.address,
            difficulty=1,
        ).seal()
        ok_blk, reason = block.integrity_check()
        assert ok_blk is False
        assert "tx_id" in reason.lower()


def test_init_and_from_dict_handle_malformed_types_safely():
    """Transaction.__init__() / from_dict() do not crash with unhandled AttributeError/OverflowError."""
    w1 = Wallet.generate()
    w2 = Wallet.generate()

    base = {
        "sender": w1.address,
        "receiver": w2.address,
        "amount": 1.0,
        "fee": 0.01,
        "timestamp": 1700000000,
        "nonce": 0,
        "expiry": 1700003600,
    }

    for bad_key, bad_val in [
        ("data", 123),
        ("gas_limit", float("inf")),
        ("amount", None),
        ("memo", None),
    ]:
        bad_dict = dict(base, **{bad_key: bad_val})
        try:
            t = Transaction.from_dict(bad_dict)
            ok, _ = t.is_valid(reference_time=1700000001)
            assert ok is False
        except (ValueError, TypeError):
            pass
