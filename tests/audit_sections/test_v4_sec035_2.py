"""Section 35 Audit Tests: Chain Reorganization and Canonical Chain Consistency."""

from __future__ import annotations

import logging
import os
import tempfile

import pytest

from visold.chain.blockchain import Blockchain
from visold.consensus.difficulty import DifficultyEngine
from visold.governance.engine import UpgradePhase
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, Layer2State
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = Config.SATOSHI_PER_VSD
FAR = 2_000_000_000


@pytest.fixture(autouse=True)
def _quiet_logs():
    prev = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(prev)


def _make_chain(td: str, name: str = "chain.db"):
    st = Storage(os.path.join(td, name))
    bc = Blockchain(st)
    bc._rolling_pruner.prune_async = lambda h: None
    return st, bc


def _transfer(st: Storage, w: Wallet, receiver: str, amount: float, nonce=None) -> Transaction:
    tx = Transaction(
        sender=w.address,
        receiver=receiver,
        amount=amount,
        fee=round(amount * Config.TX_FEE_RATE, 8),
        nonce=st.get_nonce(w.address) if nonce is None else nonce,
        expiry=FAR,
    )
    tx.sign(w)
    return tx


def _build_and_mine(bc: Blockchain, miner: Wallet, txs, *, prev: Block = None, ts: int = None) -> Block:
    if prev is None:
        prev = bc.latest_block()
    height = prev.index + 1
    cb = Transaction.coinbase(miner.address, bc.compute_reward_sat(height) / SAT, height)
    all_txs = [cb] + list(txs)
    root = bc.dry_run_state_root(all_txs, miner.address, height)
    diff = DifficultyEngine.compute_next_difficulty(bc.storage, prev.index)
    b = Block(
        index=height,
        prev_hash=prev.block_hash,
        timestamp=ts if ts is not None else int(prev.timestamp) + Config.TARGET_BLOCK_TIME,
        transactions=all_txs,
        difficulty=diff,
        miner_address=miner.address,
        state_root=root,
        protocol_version=bc._governance.get_active_version(),
    )
    b.mine()
    return b


def test_reorg_heaviest_chain_and_equal_work_tiebreak():
    with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
        _, bc1 = _make_chain(td1)
        _, bc2 = _make_chain(td2)
        m1 = Wallet.generate()
        m2 = Wallet.generate()

        # Build common block 1
        b1 = _build_and_mine(bc1, m1, [])
        assert bc1.apply_block(b1)[0]
        assert bc2.apply_block(b1)[0]

        # Canonical chain on bc1: 2 blocks (heights 2, 3) at normal difficulty
        b2 = _build_and_mine(bc1, m1, [])
        assert bc1.apply_block(b2)[0]
        b3 = _build_and_mine(bc1, m1, [])
        assert bc1.apply_block(b3)[0]
        assert bc1.height() == 3

        # Shorter but lower-work fork (1 block at height 2) must be rejected
        f2_low = _build_and_mine(bc2, m2, [], prev=b1, ts=int(b1.timestamp) + 20)
        ok_low, _ = bc1.reorg([f2_low])
        assert not ok_low
        assert bc1.height() == 3
        assert bc1.latest_block().block_hash == b3.block_hash

        # Equal-work single-block fork at height 3: deterministic tip-hash tiebreak
        assert bc2.apply_block(b2)[0]
        f3_a = _build_and_mine(bc2, m2, [], prev=b2, ts=int(b2.timestamp) + 15)
        ok_eq, _ = bc1.reorg([f3_a])
        expected_win = f3_a.block_hash < b3.block_hash
        assert ok_eq == expected_win


def test_reorg_finality_fence_and_no_investor_deep_fork():
    with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
        st1, bc1 = _make_chain(td1)
        _, bc2 = _make_chain(td2)
        m1 = Wallet.generate()
        m2 = Wallet.generate()

        b1 = _build_and_mine(bc1, m1, [])
        assert bc1.apply_block(b1)[0]
        assert bc2.apply_block(b1)[0]

        b2 = _build_and_mine(bc1, m1, [])
        assert bc1.apply_block(b2)[0]
        # Manually finalize block 2 to simulate finality fence at height 2
        stored_b2 = st1.get_block(2)
        stored_b2.finalized = True
        st1.save_block(stored_b2)
        bc1._recompute_highest_finalized_height()
        assert bc1._highest_finalized_height == 2

        # Direct reorg at fork_height=2 without allow_deep_no_investor must fail
        f2 = _build_and_mine(bc2, m2, [], prev=b1, ts=int(b1.timestamp) + 12)
        assert bc2.apply_block(f2)[0]
        f3 = _build_and_mine(bc2, m2, [], prev=f2, ts=int(f2.timestamp) + 12)
        assert bc2.apply_block(f3)[0]

        ok_direct, msg_direct = bc1.reorg([f2, f3], allow_deep_no_investor=False)
        assert not ok_direct
        assert "finalized" in msg_direct.lower()

        # When an investor exists, accept_chain must also reject crossing the fence
        st1.set_role(m1.address, "investor", 100.0)
        ok_inv, msg_inv = bc1.accept_chain([b1, f2, f3])
        assert not ok_inv
        assert "finalized" in msg_inv.lower()

        # Remove investor -> Case 3 deep fork on no-investor network succeeds
        st1.set_role(m1.address, "none", 0.0)
        ok_deep, msg_deep = bc1.accept_chain([b1, f2, f3])
        assert ok_deep, msg_deep
        assert bc1.height() == 3
        assert bc1.latest_block().block_hash == f3.block_hash


def test_reorg_atomic_recovery_on_mid_branch_failure():
    with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
        st1, bc1 = _make_chain(td1)
        _, bc2 = _make_chain(td2)
        m1 = Wallet.generate()
        m2 = Wallet.generate()
        alice = Wallet.generate()

        # Block 1 gives m1 funds
        b1 = _build_and_mine(bc1, m1, [])
        assert bc1.apply_block(b1)[0]
        assert bc2.apply_block(b1)[0]

        # Canonical block 2 transfers 5 VSD to alice and deposits 2 VSD to L2
        tx_a = _transfer(st1, m1, alice.address, 5.0, nonce=0)
        tx_l2 = _transfer(st1, m1, L2_BRIDGE_ADDRESS, 2.0, nonce=1)
        b2 = _build_and_mine(bc1, m1, [tx_a, tx_l2])
        assert bc1.apply_block(b2)[0]

        alice_bal_before = st1.get_balance_sat(alice.address)
        l2_bal_before = bc1.layer2.get_balance_sat(m1.address)
        assert alice_bal_before == 5 * SAT
        assert l2_bal_before == 2 * SAT

        # Fork branch: valid f2 + invalid f3 (corrupted state_root)
        f2 = _build_and_mine(bc2, m2, [], prev=b1, ts=int(b1.timestamp) + 10)
        assert bc2.apply_block(f2)[0]
        f3_good = _build_and_mine(bc2, m2, [], prev=f2, ts=int(f2.timestamp) + 10)
        f3_bad = Block(
            index=f3_good.index,
            prev_hash=f3_good.prev_hash,
            timestamp=f3_good.timestamp,
            transactions=f3_good.transactions,
            difficulty=f3_good.difficulty,
            miner_address=f3_good.miner_address,
            state_root="0" * 64,
            protocol_version=f3_good.protocol_version,
        )
        f3_bad.mine()

        ok, _ = bc1.reorg([f2, f3_bad])
        assert not ok
        # Old chain, L1 balance, and L2 balance must be fully restored
        assert bc1.height() == 2
        assert bc1.latest_block().block_hash == b2.block_hash
        assert st1.get_balance_sat(alice.address) == alice_bal_before
        assert bc1.layer2.get_balance_sat(m1.address) == l2_bal_before
        assert bc1._critical_recovery is None


def test_accept_chain_overlap_and_anchor_paths():
    with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
        _, bc1 = _make_chain(td1)
        _, bc2 = _make_chain(td2)
        m1 = Wallet.generate()
        m2 = Wallet.generate()

        b0 = bc1.storage.get_block(0)
        b1 = _build_and_mine(bc1, m1, [])
        assert bc1.apply_block(b1)[0]
        assert bc2.apply_block(b1)[0]
        b2 = _build_and_mine(bc1, m1, [])
        assert bc1.apply_block(b2)[0]

        # Idempotent historical overlap
        ok_dup, msg_dup = bc1.accept_chain([b0, b1])
        assert ok_dup
        assert "already have" in msg_dup.lower()

        # Non-contiguous overlap rejected
        ok_nc, _ = bc1.accept_chain([b0, b2])
        assert not ok_nc

        # Fork starting at height 2 without b0/b1 in payload (anchored by prev_hash)
        f2 = _build_and_mine(bc2, m2, [], prev=b1, ts=int(b1.timestamp) + 11)
        assert bc2.apply_block(f2)[0]
        f3 = _build_and_mine(bc2, m2, [], prev=f2, ts=int(f2.timestamp) + 11)
        assert bc2.apply_block(f3)[0]

        ok_fork, msg_fork = bc1.accept_chain([f2, f3])
        assert ok_fork, msg_fork
        assert bc1.height() == 3
        assert bc1.latest_block().block_hash == f3.block_hash

        # Unanchored payload rejected
        rogue = _build_and_mine(bc2, m2, [], prev=f3, ts=int(f3.timestamp) + 11)
        rogue_bad = Block(
            index=2,
            prev_hash="f" * 64,
            timestamp=rogue.timestamp,
            transactions=rogue.transactions,
            difficulty=rogue.difficulty,
            miner_address=rogue.miner_address,
            state_root=rogue.state_root,
            protocol_version=rogue.protocol_version,
        )
        rogue_bad.mine()
        ok_unanchored, _ = bc1.accept_chain([rogue_bad])
        assert not ok_unanchored


def test_rollback_restores_state_nonces_mempool_and_replay_guard():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        m1 = Wallet.generate()
        alice = Wallet.generate()

        b1 = _build_and_mine(bc, m1, [])
        assert bc.apply_block(b1)[0]
        sr1 = st.compute_state_root()

        tx = _transfer(st, m1, alice.address, 4.0, nonce=0)
        b2 = _build_and_mine(bc, m1, [tx])
        assert bc.apply_block(b2)[0]

        assert st.get_balance_sat(alice.address) == 4 * SAT
        assert st.get_nonce(m1.address) == 1
        assert st.replay_guard_exists(tx.tx_id)

        # Invalid rollback targets
        assert not bc.rollback(-1)[0]
        assert not bc.rollback(2)[0]

        # Valid rollback to height 1
        ok, msg = bc.rollback(1)
        assert ok, msg
        assert bc.height() == 1
        assert st.get_balance_sat(alice.address) == 0
        assert st.get_nonce(m1.address) == 0
        assert not st.replay_guard_exists(tx.tx_id)
        assert st.compute_state_root() == sr1
        assert st.get_cumulative_issued_sat() == bc.compute_reward_sat(1)
        assert bc.mempool.size() == 1


def test_reconcile_tip_marker_restores_or_fences():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        m1 = Wallet.generate()
        b1 = _build_and_mine(bc, m1, [])
        assert bc.apply_block(b1)[0]

        # Case 1: missing marker but matching state_root -> marker restored
        st.set_meta("block_apply:1", "")
        bc._tip_marker_checked = False
        bc._reconcile_tip_marker()
        assert st.get_meta("block_apply:1") == "ok"
        assert bc._critical_recovery is None

        # Case 2: missing marker and mismatched state_root -> critical recovery
        st.set_meta("block_apply:1", "")
        st.credit_sat(m1.address, 12345)
        bc._tip_marker_checked = False
        bc._reconcile_tip_marker()
        assert bc._critical_recovery is not None


def test_l2_rollback_plan_and_evicted_history_lost():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "l2.db"))
        l2 = Layer2State(st)
        l2._history_max = 2
        alice = Wallet.generate().address

        # Empty -> none
        ok_n, msg_n = l2.rollback_to_height(5)
        assert ok_n and msg_n == "no-l2-state"

        # Deposit at height 5, then 6, then 7 (_history_max=2 evicts height 5)
        assert l2.L2_deposit(alice, 100, l1_height=5, l1_block_hash="h5")[0]
        assert l2.L2_deposit(alice, 200, l1_height=6, l1_block_hash="h6")[0]
        assert l2.L2_deposit(alice, 300, l1_height=7, l1_block_hash="h7")[0]

        # Height 5 was evicted while _history_first_height == 5 -> lost
        can_5, _ = l2.can_rollback_to_height(5)
        assert not can_5
        ok_5, _ = l2.rollback_to_height(5)
        assert not ok_5

        # Height 6 is retained -> restore succeeds
        can_6, _ = l2.can_rollback_to_height(6)
        assert can_6
        ok_6, msg_6 = l2.rollback_to_height(6)
        assert ok_6 and msg_6 == "OK"
        assert l2.get_balance_sat(alice) == 300

        # Height 4 is below _history_first_height (5) -> reset-to-empty
        ok_4, msg_4 = l2.rollback_to_height(4)
        assert ok_4 and msg_4 == "reset-to-empty"
        assert l2.get_balance_sat(alice) == 0


def test_governance_reconcile_to_height_rewinds_phases_and_version():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        gov = bc._governance
        base_ver = gov.proto_mgr.current_version()
        next_ver = base_ver + 1

        ok, msg = gov.propose_upgrade(
            version=next_ver,
            signal_start_height=1,
            threshold=0.5,
            rollback_window=5,
        )
        assert ok, msg
        prop = gov.get_proposal(next_ver)
        prop.phase = UpgradePhase.ACTIVE
        prop.lock_in_height = 5
        prop.activation_height = 10
        prop._persist(st)
        gov.proto_mgr.advance_version(next_ver)
        assert gov.proto_mgr.current_version() == next_ver

        # Rollback below activation_height (10) -> LOCKED_IN & version rewound
        gov.reconcile_to_height(7)
        assert prop.phase == UpgradePhase.LOCKED_IN
        assert gov.proto_mgr.current_version() == base_ver

        # Rollback below lock_in_height (5) -> SIGNALING
        gov.reconcile_to_height(4)
        assert prop.phase == UpgradePhase.SIGNALING
        assert prop.lock_in_height == 0
        assert prop.activation_height == 0
