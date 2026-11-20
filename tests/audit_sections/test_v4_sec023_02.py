"""V4 regression tests for Section 23 (Session 01): Transaction Nonce Management & Replay Protection."""
from __future__ import annotations

import os
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
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


@pytest.fixture
def tmp_storage():
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        st = Storage(db_path=db_path)
        yield st
        try:
            st.close()
        except Exception:
            pass


def _make_signed_tx(wallet: Wallet, receiver: str, amount: float, nonce: int,
                    memo: str = "", timestamp: int = 0) -> Transaction:
    tx = Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount=amount,
        fee=round(amount * Config.TX_FEE_RATE, 8),
        timestamp=timestamp or int(time.time()),
        memo=memo,
        nonce=nonce,
    )
    tx.sign(wallet)
    return tx


class TestSection23FixedV4:
    def test_vsd_global_market_enforces_nonce_and_prevents_pending_corruption(self, tmp_storage):
        """VSD_GLOBAL_MARKET enforces sequential/gap nonce rules in Mempool.add()."""
        w_alice = Wallet.generate()
        w_bob = Wallet.generate()
        tmp_storage.set_balance(w_alice.address, 100.0)
        mp = Mempool(tmp_storage)

        # (a) Duplicate same-nonce VSD_GLOBAL_MARKET txs: second is rejected
        tx_gm_0a = _make_signed_tx(w_alice, VSD_GLOBAL_MARKET, 1.0, nonce=0, memo="ORDER:1")
        tx_gm_0b = _make_signed_tx(w_alice, VSD_GLOBAL_MARKET, 1.0, nonce=0, memo="ORDER:2")
        ok1, msg1 = mp.add(tx_gm_0a)
        ok2, _msg2 = mp.add(tx_gm_0b)
        assert ok1 is True, msg1
        assert ok2 is False

        # (b) Gapped VSD_GLOBAL_MARKET tx is rejected
        tx_gm_gap = _make_signed_tx(w_alice, VSD_GLOBAL_MARKET, 1.0, nonce=20, memo="ORDER:gap")
        ok_gap, _msg_gap = mp.add(tx_gm_gap)
        assert ok_gap is False

        # (c) Stale nonce (nonce=0 when chain_nonce=5) is rejected for VSD_GLOBAL_MARKET
        tmp_storage.set_nonce(w_alice.address, 5)
        tx_gm_stale = _make_signed_tx(w_alice, VSD_GLOBAL_MARKET, 1.0, nonce=0, memo="ORDER:stale")
        ok_stale, _msg_stale = mp.add(tx_gm_stale)
        assert ok_stale is False

    def test_mempool_enforces_replay_guard_for_pruned_transactions(self, tmp_storage):
        """Mempool.add() and restore() check replay_guard_exists() and reject pruned replays."""
        w_alice = Wallet.generate()
        tmp_storage.set_balance(w_alice.address, 100.0)
        mp = Mempool(tmp_storage)

        tx_gm = _make_signed_tx(w_alice, VSD_GLOBAL_MARKET, 1.0, nonce=0, memo="ORDER:pruned")
        tmp_storage.record_applied_tx_id(tx_gm.tx_id)
        tmp_storage.set_nonce(w_alice.address, 1)
        assert tmp_storage.tx_exists(tx_gm.tx_id) is False
        assert tmp_storage.replay_guard_exists(tx_gm.tx_id) is True

        ok_add, _msg_add = mp.add(tx_gm)
        assert ok_add is False

        ok_res, _msg_res = mp.restore(tx_gm)
        assert ok_res is False

    def test_transaction_is_valid_rejects_bad_nonce_and_expiry_safely(self, tmp_storage):
        """Transaction.is_valid() rejects negative/float/string nonces and bad expiry without crashing."""
        w_alice = Wallet.generate()
        w_bob = Wallet.generate()
        tmp_storage.set_balance(w_alice.address, 100.0)
        mp = Mempool(tmp_storage)

        # (a) Negative nonce rejected
        tx_neg = _make_signed_tx(w_alice, w_bob.address, 1.0, nonce=-1)
        ok_neg, _ = tx_neg.is_valid()
        assert ok_neg is False

        # (b) Float nonce (1.5) rejected
        tx_flt = Transaction(
            sender=w_alice.address,
            receiver=w_bob.address,
            amount=1.0,
            fee=round(1.0 * Config.TX_FEE_RATE, 8),
            nonce=1.5,
        )
        tx_flt.sign(w_alice)
        ok_flt, _ = tx_flt.is_valid()
        assert ok_flt is False

        # (c) String nonce from JSON deserialization rejected cleanly (not TypeError crash in mp.add)
        tx_str_dict = _make_signed_tx(w_alice, w_bob.address, 1.0, nonce=0).to_dict()
        tx_str_dict["nonce"] = "0"
        try:
            tx_str = Transaction.from_dict(tx_str_dict)
            ok_str, _ = tx_str.is_valid()
            assert ok_str is False
            ok_mp, _ = mp.add(tx_str)
            assert ok_mp is False
        except (ValueError, TypeError):
            pass

        # (d) Non-integer expiry (None) rejected cleanly without TypeError crash in is_valid()
        tx_exp_dict = _make_signed_tx(w_alice, w_bob.address, 1.0, nonce=0).to_dict()
        tx_exp_dict["expiry"] = None
        try:
            tx_exp = Transaction.from_dict(tx_exp_dict)
            ok_exp, _ = tx_exp.is_valid()
            assert ok_exp is False
        except (ValueError, TypeError):
            pass
