"""V4 regression tests for Section 21 (Session 01): Transaction Structure, Serialization & Canonical Hashing."""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.kernel.config import Config
from visold.ledger.transaction import Transaction
from visold.wallet.wallet import Wallet


class TestSection21FixedV4:
    def test_non_finite_gas_price_and_gas_limit_rejected_cleanly(self):
        """
        V4 fix for BUG-21-01: Non-finite gas_price (NaN/Inf) and gas_limit
        (NaN/Inf/-Inf) must not be silently coerced to 0.0 and pass is_valid().
        Either construction/from_dict rejects them or preserves/flags them so
        is_valid() returns False.
        """
        w = Wallet.generate()
        recipient = Wallet.generate().address

        # 1. gas_price = NaN must not be accepted as valid
        try:
            tx = Transaction(
                w.address, recipient, 1.0, fee=0.01,
                timestamp=1700000000, gas_price=float("nan"),
            )
            tx.sign(w)
            ok, _reason = tx.is_valid(reference_time=1700000001)
            assert ok is False
        except (ValueError, TypeError):
            pass

        # Same via from_dict()
        base = Transaction(w.address, recipient, 1.0, fee=0.01, timestamp=1700000000)
        base.sign(w)
        tx_d = base.to_dict()
        tx_d["gas_price"] = float("nan")
        try:
            tx_rt = Transaction.from_dict(tx_d)
            ok_rt, _ = tx_rt.is_valid(reference_time=1700000001)
            assert ok_rt is False
        except (ValueError, TypeError):
            pass

        # 2. gas_limit = NaN / Inf / -Inf must be handled cleanly (ValueError/TypeError or invalid)
        for bad_val in (float("nan"), float("inf"), float("-inf")):
            try:
                t_bad = Transaction("sender", "receiver", 1.0, gas_limit=bad_val, timestamp=1700000000)
                ok_b, _ = t_bad.is_valid(reference_time=1700000001)
                assert ok_b is False
            except (ValueError, TypeError, OverflowError):
                pass

            try:
                t_rt_bad = Transaction.from_dict({
                    "sender": "sender",
                    "receiver": "receiver",
                    "amount": 1.0,
                    "gas_limit": bad_val,
                    "timestamp": 1700000000,
                })
                ok_rb, _ = t_rt_bad.is_valid(reference_time=1700000001)
                assert ok_rb is False
            except (ValueError, TypeError, OverflowError):
                pass

    def test_from_dict_preserves_expiry_zero_timestamp_zero_and_rejects_empty_tx_type(self):
        """
        V4 fix for BUG-21-02: from_dict() preserves explicit expiry=0 and
        timestamp=0 without mutating them, and does not coerce invalid tx_type
        ("" / None / 0 / []) to valid 'transfer'.
        """
        w = Wallet.generate()
        recipient = Wallet.generate().address

        # 1. expiry=0 preserved across to_dict -> from_dict round-trip
        tx = Transaction(w.address, recipient, 1.0, fee=0.01, timestamp=1700000000, expiry=0)
        tx.sign(w)
        assert tx.is_expired(reference_time=1700999999) is False
        assert tx.verify_signature() is True

        d = tx.to_dict()
        assert d["expiry"] == 0
        tx_rt = Transaction.from_dict(d)
        assert tx_rt.expiry == 0
        assert tx_rt._compute_id() == tx.tx_id
        assert tx_rt.verify_signature() is True

        # 2. timestamp=0 in from_dict() preserved as 0 (not mutated to time.time())
        cb = Transaction.coinbase(recipient, 50.0, 1)
        cb_dict = cb.to_dict()
        cb_dict["timestamp"] = 0
        cb_rt = Transaction.from_dict(cb_dict)
        assert cb_rt.timestamp == 0

        # 3. Invalid tx_type ("", None, 0, []) must not pass is_valid()
        for bad_type in ("", None, 0, []):
            try:
                t_bad = Transaction.from_dict({
                    "sender": w.address,
                    "receiver": recipient,
                    "amount": 1.0,
                    "fee": 0.01,
                    "timestamp": 1700000000,
                    "tx_type": bad_type,
                })
                ok_bad, _ = t_bad.is_valid(reference_time=1700000001)
                assert ok_bad is False
            except (ValueError, TypeError):
                pass

    def test_from_dict_preserves_version_field(self):
        """
        V4 fix for BUG-21-03: from_dict() preserves 'version' so non-v1
        transactions round-trip without altering tx_id or invalidating signature.
        """
        w = Wallet.generate()
        recipient = Wallet.generate().address
        tx = Transaction(w.address, recipient, 1.0, fee=0.01, timestamp=1700000000, version=2)
        tx.sign(w)

        d = tx.to_dict()
        assert d["version"] == 2
        tx_rt = Transaction.from_dict(d)

        assert tx_rt.version == 2
        assert tx_rt._compute_id() == tx.tx_id
        assert tx_rt.verify_signature() is True

    def test_sub_satoshi_gas_price_quantized_consistently(self):
        """
        V4 fix for BUG-21-04: gas_price is quantized to satoshi/8 decimals so
        mutating gas_price from 0.6 sat to 1.0 sat cannot keep the same tx_id
        and signature while flipping is_valid().
        """
        w = Wallet.generate()
        tx = Transaction(
            w.address, "", 0.0, fee=0.0, timestamp=1700000000,
            tx_type=Transaction.TYPE_DEPLOY, data="6001",
            gas_limit=100, gas_price=0.000000006,
        )
        tx.sign(w)

        d = tx.to_dict()
        d["gas_price"] = Config.VVM_MIN_GAS_PRICE  # 1e-8
        tx_mutated = Transaction.from_dict(d)
        # Either tx.gas_price was quantized to 1e-8 at init (so orig is valid)
        # OR mutating gas_price changes _compute_id() / invalidates signature.
        ok_orig, _ = tx.is_valid(reference_time=1700000001)
        if not ok_orig:
            assert tx_mutated._compute_id() != tx.tx_id or tx_mutated.verify_signature() is False

    def test_non_string_memo_or_data_handled_safely_in_from_dict(self):
        """
        V4 fix for BUG-21-05: from_dict() does not crash with unhandled
        AttributeError on non-string data or TypeError on memo=None; it either
        raises ValueError/TypeError cleanly or normalizes/rejects in is_valid().
        """
        try:
            t1 = Transaction.from_dict({
                "sender": "s",
                "receiver": "r",
                "amount": 1.0,
                "timestamp": 1700000000,
                "memo": None,
            })
            ok1, _ = t1.is_valid(reference_time=1700000001)
            assert ok1 is False
        except (ValueError, TypeError):
            pass

        try:
            t2 = Transaction.from_dict({
                "sender": "s",
                "receiver": "r",
                "amount": 1.0,
                "timestamp": 1700000000,
                "data": 12345,
            })
            ok2, _ = t2.is_valid(reference_time=1700000001)
            assert ok2 is False
        except (ValueError, TypeError):
            pass
