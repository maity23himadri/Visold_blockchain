"""V4 regression tests for Section 23 (Session 01 doc_test): Nonce Management & Replay Protection."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.crypto.ecc import ecdsa_keygen
from visold.kernel.config import Config
from visold.kernel.units import VSD_GLOBAL_MARKET
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_wallet() -> Wallet:
    priv, pub = ecdsa_keygen()
    return Wallet(priv, pub)


def _make_funded_chain(tmpdir: str):
    storage = Storage(os.path.join(tmpdir, "visold.db"))
    bc = Blockchain(storage)
    w = _make_wallet()
    storage.credit_sat(w.address, 100_000 * Config.SATOSHI_PER_VSD)
    return storage, bc, w


def test_mempool_rejects_stale_and_gapped_nonces_for_vsd_global_market():
    """Mempool.add() enforces nonce rules even when receiver == VSD_GLOBAL_MARKET."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage, bc, w = _make_funded_chain(tmpdir)
        storage.set_nonce(w.address, 5)

        tx_stale = Transaction(
            sender=w.address,
            receiver=VSD_GLOBAL_MARKET,
            amount=1.0,
            fee=0.01,
            nonce=0,
            pub_hex=w.pub_hex,
        )
        tx_stale.sign(w)
        ok_stale, _msg_stale = bc.mempool.add(tx_stale)
        assert ok_stale is False

        tx_gap = Transaction(
            sender=w.address,
            receiver=VSD_GLOBAL_MARKET,
            amount=1.0,
            fee=0.01,
            nonce=999999,
            pub_hex=w.pub_hex,
        )
        tx_gap.sign(w)
        ok_gap, _msg_gap = bc.mempool.add(tx_gap)
        assert ok_gap is False


def test_mempool_rejects_tx_already_in_replay_guard_when_pruned_and_zero_expiry():
    """Mempool.add() checks replay_guard_exists() and rejects already-applied txs even if pruned."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage, bc, w = _make_funded_chain(tmpdir)

        tx_zero_exp = Transaction(
            sender=w.address,
            receiver=VSD_GLOBAL_MARKET,
            amount=1.0,
            fee=0.01,
            nonce=0,
            expiry=0,
            pub_hex=w.pub_hex,
        )
        tx_zero_exp.sign(w)

        storage.record_applied_tx_id(tx_zero_exp.tx_id)
        assert storage.replay_guard_exists(tx_zero_exp.tx_id) is True
        assert storage.tx_exists(tx_zero_exp.tx_id) is False

        ok, _msg = bc.mempool.add(tx_zero_exp)
        assert ok is False


def test_transaction_is_valid_rejects_negative_and_bool_nonces():
    """Transaction.is_valid() rejects negative and bool nonces."""
    w = _make_wallet()
    tx_neg = Transaction(
        sender=w.address,
        receiver=VSD_GLOBAL_MARKET,
        amount=1.0,
        fee=0.01,
        nonce=-1,
        pub_hex=w.pub_hex,
    )
    tx_neg.sign(w)
    ok_neg, _msg_neg = tx_neg.is_valid()
    assert ok_neg is False

    tx_bool = Transaction(
        sender=w.address,
        receiver=VSD_GLOBAL_MARKET,
        amount=1.0,
        fee=0.01,
        nonce=False,
        pub_hex=w.pub_hex,
    )
    tx_bool.sign(w)
    ok_bool, _msg_bool = tx_bool.is_valid()
    assert ok_bool is False
