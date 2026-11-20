"""V4 regression tests for Section 27 (Session 01): Balance Conservation, Double-Spend Prevention & Accounting."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.kernel.units import conservation_check, gas_fee_to_sat, to_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.resilience.hardened_core import SystemInvariantGate, _hc_panic_cb, _HardenedSystemMode
from visold.resilience.safety_invariants import SafetyInvariantChecker
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, Layer2State
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


@pytest.fixture(autouse=True)
def _reset_panic_cb():
    yield
    with _hc_panic_cb._mode_lock:
        _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
        _hc_panic_cb._corruption_timestamps.clear()
        _hc_panic_cb._corruption_count = 0
        _hc_panic_cb._subsystems.clear()
        _hc_panic_cb._read_only_since = 0.0


def _make_chain(tmpdir: str):
    st = Storage(os.path.join(tmpdir, "audit27.db"))
    mp = Mempool(st)
    bc = Blockchain(st)
    bc.mempool = mp
    l2 = Layer2State(st)
    bc.layer2 = l2
    return st, mp, bc


def _mine_block(bc: Blockchain, miner_addr: str, txs: list[Transaction]) -> Block:
    tip = bc.latest_block()
    height = tip.index + 1
    diff = bc.get_difficulty()
    ts = max(int(tip.timestamp) + 1, 1_700_000_000 + height)
    cb = Transaction.coinbase(miner_addr, bc.compute_reward(height), height)
    all_txs = [cb] + list(txs)
    state_root = bc.dry_run_state_root(
        all_txs, miner_addr, height, difficulty=diff, timestamp=ts
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


def test_name_collision_deploy_preserves_conservation():
    """VVM contract name collision preserves supply conservation."""
    with tempfile.TemporaryDirectory() as td:
        st, _mp, bc = _make_chain(td)
        alice = Wallet.generate()

        blk1 = _mine_block(bc, alice.address, [])
        ok1, msg1 = bc.apply_block(blk1)
        assert ok1, msg1
        assert conservation_check(st) is True

        tx1 = Transaction(
            sender=alice.address,
            receiver="",
            amount=0.0,
            fee=0.0,
            tx_type=Transaction.TYPE_DEPLOY,
            data="00",
            gas_limit=100_000,
            gas_price=0.00000001,
            nonce=0,
            expiry=blk1.timestamp + 3600,
            contract_name="alpha",
        )
        tx1.sign(alice)
        blk2 = _mine_block(bc, alice.address, [tx1])
        ok2, msg2 = bc.apply_block(blk2)
        assert ok2, msg2
        assert conservation_check(st) is True

        tx2 = Transaction(
            sender=alice.address,
            receiver="",
            amount=0.0,
            fee=0.0,
            tx_type=Transaction.TYPE_DEPLOY,
            data="00",
            gas_limit=100_000,
            gas_price=0.00000001,
            nonce=1,
            expiry=blk2.timestamp + 3600,
            contract_name="alpha",
        )
        tx2.sign(alice)
        blk3 = _mine_block(bc, alice.address, [tx2])
        ok3, msg3 = bc.apply_block(blk3)
        assert ok3, msg3

        assert conservation_check(st) is True
        SystemInvariantGate.assert_conservation(st, context="post-collision-block")


def test_safety_invariant_checker_detects_over_issuance_with_l2_bridge_escrow():
    """SafetyInvariantChecker detects over-issuance even when L2_BRIDGE_ADDRESS holds escrow."""
    with tempfile.TemporaryDirectory() as td:
        st, _mp, bc = _make_chain(td)
        alice = Wallet.generate()
        attacker = Wallet.generate()

        blk1 = _mine_block(bc, alice.address, [])
        ok1, msg1 = bc.apply_block(blk1)
        assert ok1, msg1

        issued_b1 = st.get_total_issued_satoshi()
        assert issued_b1 > 0

        deposit_sat = (issued_b1 * 4) // 10
        deposit_vsd = deposit_sat / Config.SATOSHI_PER_VSD
        tx_dep = Transaction(
            sender=alice.address,
            receiver=L2_BRIDGE_ADDRESS,
            amount=deposit_vsd,
            fee=0.001,
            tx_type=Transaction.TYPE_TRANSFER,
            nonce=0,
            expiry=blk1.timestamp + 3600,
        )
        tx_dep.sign(alice)
        blk2 = _mine_block(bc, alice.address, [tx_dep])
        ok2, msg2 = bc.apply_block(blk2)
        assert ok2, msg2
        assert st.get_balance_sat(L2_BRIDGE_ADDRESS) == to_satoshi(deposit_vsd)

        over_mint_sat = issued_b1 // 5
        st.credit_sat(attacker.address, over_mint_sat)

        with pytest.raises(ValueError, match="CONSERVATION VIOLATION"):
            conservation_check(st)

        dummy_net = SimpleNamespace(active_peer_count=lambda: [])
        checker = SafetyInvariantChecker(st, bc, dummy_net)
        report = checker.check_all(full_scan=True)
        assert report["consistency_ok"] is False
        assert len(report["violations"]) > 0
