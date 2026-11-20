"""V4 regression tests for Section 27 (Session 02): Balance Conservation, Double-Spend Prevention and Accounting."""
from __future__ import annotations

import logging
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.kernel.units import VSD_GLOBAL_MARKET, conservation_check
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.resilience.hardened_core import (
    ImmediateAbort,
    SystemInvariantGate,
    _HardenedSystemMode,
    _hc_panic_cb,
)
from visold.resilience.safety_invariants import SafetyInvariantChecker
from visold.state.batch_proxy import _StorageBatchProxy
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

FAR = 2_000_000_000


@pytest.fixture(autouse=True)
def _quiet_logs_and_reset_panic_cb():
    prev = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(prev)
        with _hc_panic_cb._mode_lock:
            _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
            _hc_panic_cb._subsystems.clear()
            _hc_panic_cb._corruption_timestamps.clear()
            _hc_panic_cb._corruption_count = 0


class _DummyNetwork:
    def active_peer_count(self):
        return []


def _make_chain(td: str, name: str = "sec27.db"):
    st = Storage(os.path.join(td, name))
    bc = Blockchain(st)
    bc._rolling_pruner.prune_async = lambda h: None
    return st, bc


def _mine_block(bc: Blockchain, miner_addr: str, txs: list[Transaction], ts_offset: int = 1) -> Block:
    tip = bc.latest_block()
    height = tip.index + 1
    diff = bc.get_difficulty()
    ts = max(int(tip.timestamp) + ts_offset, 1_700_000_000 + height * 10)
    cb = Transaction(
        sender="COINBASE",
        receiver=miner_addr,
        amount=bc.compute_reward(height),
        fee=0.0,
        nonce=height,
        timestamp=ts,
        expiry=0,
    )
    all_txs = [cb] + list(txs)
    state_root = bc.dry_run_state_root(
        all_txs, miner_addr, height, timestamp=ts, difficulty=diff
    )
    blk = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=all_txs,
        miner_address=miner_addr,
        difficulty=diff,
        timestamp=ts,
        state_root=state_root,
    )
    blk.mine()
    return blk


def test_deploy_name_collision_preserves_supply_and_conservation():
    """VVM DEPLOY name collision preserves supply conservation."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        w1 = Wallet.generate()
        w2 = Wallet.generate()

        b1 = _mine_block(bc, w1.address, [])
        ok1, msg1 = bc.apply_block(b1)
        assert ok1, msg1
        assert conservation_check(st) is True

        nonce_w1 = st.get_nonce(w1.address)
        tx_fund = Transaction(
            sender=w1.address,
            receiver=w2.address,
            amount=1.0,
            fee=round(1.0 * Config.TX_FEE_RATE, 8),
            nonce=nonce_w1,
            expiry=FAR,
        )
        tx_fund.sign(w1)

        tx_deploy1 = Transaction(
            sender=w1.address,
            receiver="",
            amount=0.0,
            fee=0.0,
            nonce=nonce_w1 + 1,
            tx_type=Transaction.TYPE_DEPLOY,
            data="00",
            gas_limit=Config.VVM_DEPLOY_GAS_BASE,
            gas_price=Config.VVM_MIN_GAS_PRICE,
            contract_name="audit_svc",
            expiry=FAR,
        )
        tx_deploy1.sign(w1)

        b2 = _mine_block(bc, w1.address, [tx_fund, tx_deploy1])
        ok2, msg2 = bc.apply_block(b2)
        assert ok2, msg2
        assert conservation_check(st) is True

        nonce_w2 = st.get_nonce(w2.address)
        tx_deploy2 = Transaction(
            sender=w2.address,
            receiver="",
            amount=0.0,
            fee=0.0,
            nonce=nonce_w2,
            tx_type=Transaction.TYPE_DEPLOY,
            data="00",
            gas_limit=Config.VVM_DEPLOY_GAS_BASE,
            gas_price=Config.VVM_MIN_GAS_PRICE,
            contract_name="audit_svc",
            expiry=FAR,
        )
        tx_deploy2.sign(w2)

        b3 = _mine_block(bc, w1.address, [tx_deploy2])
        ok3, msg3 = bc.apply_block(b3)
        assert ok3, msg3

        assert conservation_check(st) is True
        SystemInvariantGate.assert_conservation(st, context="post-collision")


def test_conservation_across_transfers_broadcast_register_and_rollback():
    """Verify conservation_check and SafetyInvariantChecker pass across
    normal transfers, VSD_GLOBAL_MARKET broadcast, REGISTER stake lock,
    and full block rollback.
    """
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        w1 = Wallet.generate()
        w2 = Wallet.generate()

        for _ in range(4):
            blk = _mine_block(bc, w1.address, [])
            ok, msg = bc.apply_block(blk)
            assert ok, msg
        assert conservation_check(st) is True

        n1 = st.get_nonce(w1.address)
        tx1 = Transaction(
            sender=w1.address,
            receiver=w2.address,
            amount=1.0,
            fee=round(1.0 * Config.TX_FEE_RATE, 8),
            nonce=n1,
            expiry=FAR,
        )
        tx1.sign(w1)

        tx2 = Transaction(
            sender=w1.address,
            receiver=VSD_GLOBAL_MARKET,
            amount=1.0,
            fee=round(1.0 * Config.TX_FEE_RATE, 8),
            nonce=n1 + 1,
            expiry=FAR,
        )
        tx2.sign(w1)

        tx3 = Transaction(
            sender=w1.address,
            receiver="",
            amount=10.0,
            fee=round(10.0 * Config.TX_FEE_RATE, 8),
            nonce=n1 + 2,
            tx_type=Transaction.TYPE_REGISTER,
            memo="miner",
            expiry=FAR,
        )
        tx3.sign(w1)

        b_tx = _mine_block(bc, w1.address, [tx1, tx2, tx3])
        ok2, msg2 = bc.apply_block(b_tx)
        assert ok2, msg2
        assert conservation_check(st) is True

        checker = SafetyInvariantChecker(st, bc, _DummyNetwork())
        rep = checker.check_all(full_scan=True)
        assert rep["consistency_ok"] is True

        rb_ok, rb_msg = bc.rollback(4)
        assert rb_ok, rb_msg
        assert conservation_check(st) is True
        assert checker.check_all(full_scan=True)["consistency_ok"] is True


def test_batch_proxy_rejects_negative_credit_and_debit():
    """Verify _StorageBatchProxy defense-in-depth against negative amounts."""
    with tempfile.TemporaryDirectory() as td:
        st, _bc = _make_chain(td)
        w = Wallet.generate()
        st.set_balance(w.address, 1000)

        proxy = _StorageBatchProxy(st)
        with pytest.raises((ImmediateAbort, ValueError)):
            proxy.credit_sat(w.address, -500)
        assert proxy.debit_sat(w.address, -500) is False
        assert proxy.get_balance_sat(w.address) == 1000
