"""Regression tests for audit finding VSA-01 (dry-run rejections)."""

from __future__ import annotations

import os
import tempfile

from visold.chain.blockchain import Blockchain
try:
    from visold.chain.blockchain import CandidateTxRejected
except ImportError:  # the original code has no such type; the tests then fail on behaviour
    class CandidateTxRejected(RuntimeError):
        pass
from visold.kernel.config import Config
from visold.ledger.transaction import Transaction
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, L2_WITHDRAW_ADDRESS
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = Config.SATOSHI_PER_VSD
FAR_EXPIRY = 2_000_000_000


class _FakeLayer2:
    def __init__(self, balances):
        self._balances = dict(balances)

    def get_balance_sat(self, address):
        return int(self._balances.get(address, 0))


def _chain(td):
    st = Storage(os.path.join(td, "dry.db"))
    return st, Blockchain(st)


def _coinbase(bc, miner, height):
    return Transaction.coinbase(miner.address, bc.compute_reward_sat(height) / SAT, height)


def _transfer(st, wallet, receiver, amount, nonce):
    tx = Transaction(
        sender=wallet.address, receiver=receiver, amount=amount,
        fee=amount * Config.TX_FEE_RATE, nonce=nonce, expiry=FAR_EXPIRY)
    tx.sign(wallet)
    return tx


def _call(wallet, nonce, gas_limit=10_000):
    tx = Transaction(
        sender=wallet.address, receiver="VSDc" + "bb" * 18, amount=0.0, fee=0.0,
        nonce=nonce, expiry=FAR_EXPIRY, tx_type=Transaction.TYPE_CALL, data="",
        gas_limit=gas_limit, gas_price=Config.VVM_MIN_GAS_PRICE)
    tx.sign(wallet)
    return tx


def test_dry_run_rejects_a_vvm_call_the_sender_cannot_pay_for():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        broke = Wallet.generate()          # zero balance: the upfront gas debit must fail
        cb = _coinbase(bc, miner, 1)
        call = _call(broke, nonce=0)
        try:
            bc.dry_run_state_root([cb, call], miner.address, 1)
        except CandidateTxRejected as rejected:
            assert rejected.index == 1, rejected
        else:
            raise AssertionError("an unpayable VVM call was silently skipped (VSA-01)")


def test_dry_run_counts_earlier_withdrawals_against_the_l2_balance():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        sender = Wallet.generate()
        st.credit_sat(sender.address, 10 * SAT)
        st.credit_sat(L2_BRIDGE_ADDRESS, 10 * SAT)
        bc.layer2 = _FakeLayer2({sender.address: 1 * SAT})   # 1.00 VSD on L2
        cb = _coinbase(bc, miner, 1)
        first = _transfer(st, sender, L2_WITHDRAW_ADDRESS, 0.75, nonce=0)
        second = _transfer(st, sender, L2_WITHDRAW_ADDRESS, 0.75, nonce=1)
        try:
            bc.dry_run_state_root([cb, first, second], miner.address, 1)
        except CandidateTxRejected as rejected:
            assert rejected.index == 2, rejected
            assert "L2 balance" in rejected.reason, rejected
        else:
            raise AssertionError("two withdrawals beyond the L2 balance were both accepted (VSA-01)")


def test_dry_run_accepts_a_withdrawal_that_fits():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        sender = Wallet.generate()
        st.credit_sat(sender.address, 10 * SAT)
        st.credit_sat(L2_BRIDGE_ADDRESS, 10 * SAT)
        bc.layer2 = _FakeLayer2({sender.address: 1 * SAT})
        cb = _coinbase(bc, miner, 1)
        only = _transfer(st, sender, L2_WITHDRAW_ADDRESS, 0.75, nonce=0)
        root = bc.dry_run_state_root([cb, only], miner.address, 1)
        assert root, "a withdrawal that fits must produce a root"
