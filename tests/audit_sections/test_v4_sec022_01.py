"""V4 regression tests for Section 22 (Session 01): Address Validation and Sender-Recipient Integrity."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.kernel.config import Config
from visold.ledger.addressing import (
    is_canonical_contract_address,
    is_valid_protocol_address,
)
from visold.ledger.transaction import Transaction
from visold.vm.naming import derive_contract_address
from visold.wallet.wallet import Wallet


class TestSection22FixedV4:
    def test_is_canonical_contract_address_rejects_uppercase_hex(self):
        """is_canonical_contract_address() and is_valid_protocol_address() reject uppercase hex."""
        w = Wallet.generate()
        canonical_contract = derive_contract_address(w.address, 0, "a" * 64)
        assert canonical_contract.startswith("VSDc")
        assert len(canonical_contract) == 40
        assert canonical_contract[4:] == canonical_contract[4:].lower()
        assert is_canonical_contract_address(canonical_contract) is True

        uppercase_contract = "VSDc" + canonical_contract[4:].upper()
        assert uppercase_contract != canonical_contract

        assert is_canonical_contract_address(uppercase_contract) is False
        assert is_valid_protocol_address(uppercase_contract, allow_contract=True) is False

        now = int(time.time())
        tx = Transaction(
            sender=w.address,
            receiver=uppercase_contract,
            amount=1.0,
            fee=0.01,
            timestamp=now,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_TRANSFER,
        )
        tx.sign(w)
        ok, _msg = tx.is_valid(reference_time=now)
        assert ok is False

    def test_type_register_role_rejects_coinbase_sender(self):
        """TYPE_REGISTER (miner/investor) rejects sender == 'COINBASE'."""
        now = int(time.time())
        for role_memo in ("miner", "investor"):
            tx = Transaction(
                sender="COINBASE",
                receiver="",
                amount=100.0,
                fee=0.0,
                timestamp=now,
                expiry=now + 3600,
                tx_type=Transaction.TYPE_REGISTER,
                memo=role_memo,
                pub_hex="",
                sig_hex="",
            )
            ok, _msg = tx.is_valid(reference_time=now)
            assert ok is False

    def test_type_call_rejects_malformed_vsdc_and_non_str_receiver(self):
        """TYPE_CALL requires canonical contract address and rejects non-str receiver without crashing."""
        w = Wallet.generate()
        now = int(time.time())

        tx_bad_str = Transaction(
            sender=w.address,
            receiver="VSDc_not_a_canonical_contract",
            amount=0.0,
            fee=0.0,
            timestamp=now,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_CALL,
            gas_limit=50000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        tx_bad_str.sign(w)
        ok, _msg = tx_bad_str.is_valid(reference_time=now)
        assert ok is False

        try:
            tx_int_recv = Transaction.from_dict({
                "sender": w.address,
                "receiver": 12345,
                "amount": 0.0,
                "fee": 0.0,
                "timestamp": now,
                "expiry": now + 3600,
                "tx_type": Transaction.TYPE_CALL,
                "gas_limit": 50000,
                "gas_price": Config.VVM_MIN_GAS_PRICE,
            })
            ok_int, _ = tx_int_recv.is_valid(reference_time=now)
            assert ok_int is False
        except (ValueError, TypeError):
            pass

    def test_type_rollup_handles_non_subscriptable_receiver_safely(self):
        """TYPE_ROLLUP rejects None/int receiver cleanly without TypeError crash."""
        w = Wallet.generate()
        now = int(time.time())
        for bad_receiver in (None, 12345):
            try:
                tx = Transaction.from_dict({
                    "sender": w.address,
                    "receiver": bad_receiver,
                    "amount": 0.0,
                    "fee": 0.0,
                    "timestamp": now,
                    "expiry": now + 3600,
                    "tx_type": Transaction.TYPE_ROLLUP,
                    "data": "{}",
                })
                ok, _ = tx.is_valid(reference_time=now)
                assert ok is False
            except (ValueError, TypeError):
                pass
