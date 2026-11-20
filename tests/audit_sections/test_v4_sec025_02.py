"""V4 regression tests for Section 25 (Session 02): Transaction Fees, Gas Calculation, and Numerical Boundaries."""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.crypto.ecc import ecdsa_keygen, ecdsa_sign, pub_to_address, pub_to_hex
from visold.kernel.units import from_satoshi, to_satoshi
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.precompiles import VVMPrecompiles


def _make_signed_transfer(amount: float, fee: float, nonce: int = 0) -> tuple:
    priv, pub = ecdsa_keygen()
    sender = pub_to_address(pub)
    _, rec_pub = ecdsa_keygen()
    receiver = pub_to_address(rec_pub)

    class _W:
        pub_hex = pub_to_hex(pub)

        @staticmethod
        def sign(msg: bytes):
            return ecdsa_sign(priv, hashlib.sha256(msg).digest())

    tx = Transaction(
        sender=sender,
        receiver=receiver,
        amount=amount,
        fee=fee,
        timestamp=int(time.time()),
        nonce=nonce,
    )
    tx.sign(_W())
    return tx, sender


def test_mempool_admits_small_non_dust_transfer_with_canonical_fee():
    """For DUST_THRESHOLD <= amount < 0.001 VSD, mempool.add() admits the tx at its canonical fee."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        storage = Storage(db_path=db_path)
        pool = Mempool(storage=storage)

        # V4 raised DUST_THRESHOLD to 0.001 VSD (100,000 sat), eliminating the [0.0001, 0.001) contradiction
        assert pool.DUST_THRESHOLD == 0.001
        amount = 0.001
        probe = Transaction(sender="VSD1a", receiver="VSD1b", amount=amount)
        canonical_fee = from_satoshi(probe.compute_fee_sat())

        tx, sender = _make_signed_transfer(amount=amount, fee=canonical_fee)
        storage.credit_sat(sender, 10_000_000)
        ok_valid, reason_valid = tx.is_valid()
        assert ok_valid, f"Expected valid tx, got: {reason_valid}"
        ok, msg = pool.add(tx)
        assert ok is True, msg


def test_compute_fee_matches_compute_fee_sat_and_passes_mempool():
    """Transaction.compute_fee() agrees with compute_fee_sat() so Mempool.add() accepts it."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_round.db")
        storage = Storage(db_path=db_path)
        pool = Mempool(storage=storage)

        amount = 0.00100160  # 100,160 sat
        tmp_tx = Transaction(sender="VSD1a", receiver="VSD1b", amount=amount)
        fee_from_float = tmp_tx.compute_fee()
        assert to_satoshi(fee_from_float) == tmp_tx.compute_fee_sat()

        tx, sender = _make_signed_transfer(amount=amount, fee=fee_from_float)
        storage.credit_sat(sender, 10_000_000)
        ok, msg = pool.add(tx)
        assert ok is True, msg


def test_precompile_call_fails_oog_when_caller_lacks_gas():
    """VVMEngine._internal_call() fails OOG when caller lacks gas after 1/64th deduction."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_vm.db")
        storage = Storage(db_path=db_path)
        engine = VVMEngine(storage=storage)

        # With 3045 gas, ECRECOVER (3000 gas) succeeds with 45 gas remaining (no double 1/64th deduction)
        frame_ok = _VMFrame(
            code=b"",
            calldata=b"",
            caller="VSD1test",
            address="VSDc" + "0" * 36,
            origin="VSD1test",
            call_value=0,
            gas_limit=3045,
            storage_ref=storage,
        )
        ok_pass, _ = engine._internal_call(
            caller_frame=frame_ok,
            callee_addr=VVMPrecompiles.ECRECOVER,
            calldata=b"",
            call_value=0,
            gas=3045,
        )
        assert ok_pass is True
        assert frame_ok.gas_remaining == 45

        # With 2999 gas (< 3000), ECRECOVER fails OOG
        frame_oog = _VMFrame(
            code=b"",
            calldata=b"",
            caller="VSD1test",
            address="VSDc" + "0" * 36,
            origin="VSD1test",
            call_value=0,
            gas_limit=2999,
            storage_ref=storage,
        )
        ok_fail, _ = engine._internal_call(
            caller_frame=frame_oog,
            callee_addr=VVMPrecompiles.ECRECOVER,
            calldata=b"",
            call_value=0,
            gas=2999,
        )
        assert ok_fail is False
