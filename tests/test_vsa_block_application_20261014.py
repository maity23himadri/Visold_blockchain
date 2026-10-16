"""Regression tests for audit findings VSA-01, VSA-02, VSA-03, VSA-06, VSA-07,
VSA-19, VSA-20 and the candidate-precheck part of VSA-27.

Every test uses the real Blockchain, Storage, ConsensusEngine, validate_block()
and apply_block().  Concurrency tests use bounded joins so a regression is
reported as a failure instead of hanging the suite.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time

from visold.chain.blockchain import Blockchain, CandidateTxRejected
from visold.chain.consensus_engine import ConsensusEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, L2_WITHDRAW_ADDRESS
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = Config.SATOSHI_PER_VSD
FAR_EXPIRY = 2_000_000_000


def _chain(td: str):
    st = Storage(os.path.join(td, "vsa.db"))
    return st, Blockchain(st)


def _transfer(st, wallet, receiver, amount, nonce=None):
    tx = Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount=amount,
        fee=amount * Config.TX_FEE_RATE,
        nonce=st.get_nonce(wallet.address) if nonce is None else nonce,
        expiry=FAR_EXPIRY,
    )
    tx.sign(wallet)
    return tx


def _call(wallet, nonce, gas_limit=10_000):
    tx = Transaction(
        sender=wallet.address,
        receiver="VSDc" + "bb" * 18,
        amount=0.0,
        fee=0.0,
        nonce=nonce,
        expiry=FAR_EXPIRY,
        tx_type=Transaction.TYPE_CALL,
        data="",
        gas_limit=gas_limit,
        gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    tx.sign(wallet)
    return tx


def _coinbase(bc, miner, height):
    return Transaction.coinbase(
        miner.address, bc.compute_reward_sat(height) / SAT, height)


def _coinbase_block(bc, miner):
    height = bc.height() + 1
    cb = _coinbase(bc, miner, height)
    prev = bc.latest_block()
    root = bc.dry_run_state_root([cb], miner.address, height)
    block = Block(
        index=height,
        prev_hash=prev.block_hash,
        transactions=[cb],
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        state_root=root,
    )
    assert block.mine(), "regression block failed to mine"
    return block


def _build_candidate(bc, miner, mempool_txs, monkeypatch):
    monkeypatch.setattr(bc.mempool, "get_top", lambda _n: list(mempool_txs))
    return ConsensusEngine(bc, miner).build_candidate_block(miner.address)


def _assert_candidate_applies(bc, cand, expected_height):
    assert cand.state_root, "candidate must carry a non-empty state root (VSA-03)"
    assert cand.mine(), "candidate failed to mine"
    ok, msg = bc.validate_block(cand)
    assert ok, f"candidate rejected by validate_block: {msg}"
    ok, msg = bc.apply_block(cand)
    assert ok, f"candidate rejected by apply_block: {msg}"
    assert bc.height() == expected_height


class _FakeLayer2:
    def __init__(self, balances):
        self._balances = dict(balances)

    def get_balance_sat(self, address):
        return int(self._balances.get(address, 0))


# ── VSA-03 ───────────────────────────────────────────────────────────────────

def test_builder_never_returns_a_candidate_without_a_state_root(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        miner = Wallet.generate()

        def failing_dry_run(**_kwargs):
            raise OSError("injected storage failure during dry run")

        monkeypatch.setattr(bc, "dry_run_state_root", failing_dry_run)
        raised = False
        candidate = None
        try:
            candidate = ConsensusEngine(bc, miner).build_candidate_block(miner.address)
        except OSError:
            raised = True
        assert raised, (
            "build_candidate_block returned a candidate despite a failed root "
            f"computation (state_root={getattr(candidate, 'state_root', None)!r})")


def test_empty_state_root_is_rejected_outside_the_legacy_window(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        miner = Wallet.generate()
        height = bc.height() + 1
        cb = _coinbase(bc, miner, height)
        prev = bc.latest_block()
        block = Block(
            index=height,
            prev_hash=prev.block_hash,
            transactions=[cb],
            miner_address=miner.address,
            difficulty=bc.get_difficulty(),
            state_root="",
        )
        assert block.mine(), "empty-root block failed to mine"

        ok, msg = bc.apply_block(block)
        assert not ok and "empty state_root" in msg, msg
        assert bc.height() == height - 1, "rejected empty-root block must leave the chain unchanged"

        monkeypatch.setattr(Config, "EMPTY_STATE_ROOT_LEGACY_END_HEIGHT", height + 1)
        ok, msg = bc.apply_block(block)
        assert ok, f"legacy-window empty-root block should still apply: {msg}"
        assert bc.height() == height


# ── VSA-19 / VSA-20 / VSA-27 (candidate precheck) ────────────────────────────

def test_builder_excludes_spends_above_balance_minus_active_stake(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        staker = Wallet.generate()
        funded = Wallet.generate()
        receiver = Wallet.generate()
        st.credit_sat(staker.address, 20 * SAT)
        st.set_role(staker.address, "miner", 10.0)   # 10 VSD locked as stake
        st.credit_sat(funded.address, 10 * SAT)

        over = _transfer(st, staker, receiver.address, 11.0, nonce=0)   # 20 - 10 = 10 spendable
        later = _transfer(st, staker, receiver.address, 1.0, nonce=1)   # same sender, after 'over'
        ok_tx = _transfer(st, funded, receiver.address, 9.0, nonce=0)

        cand = _build_candidate(bc, miner, [over, later, ok_tx], monkeypatch)
        included = {t.tx_id for t in cand.transactions}
        assert over.tx_id not in included, "transfer above spendable balance (VSA-20) was selected"
        assert later.tx_id not in included, "same-sender successor must not leave a nonce gap"
        assert ok_tx.tx_id in included, "affordable transfer from another sender was dropped"
        _assert_candidate_applies(bc, cand, expected_height=1)


def test_builder_drops_second_transfer_when_combined_spend_exceeds_balance(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        sender = Wallet.generate()
        receiver = Wallet.generate()
        st.credit_sat(sender.address, 10 * SAT)

        first = _transfer(st, sender, receiver.address, 7.0, nonce=0)
        second = _transfer(st, sender, receiver.address, 7.0, nonce=1)   # 14 > 10 combined

        cand = _build_candidate(bc, miner, [first, second], monkeypatch)
        included = {t.tx_id for t in cand.transactions}
        assert first.tx_id in included
        assert second.tx_id not in included, "combined overspend (VSA-19) was selected"
        _assert_candidate_applies(bc, cand, expected_height=1)


def test_precheck_spendable_boundary_matches_validate_rule(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        staker = Wallet.generate()
        receiver = Wallet.generate()
        st.credit_sat(staker.address, 20 * SAT)
        st.set_role(staker.address, "miner", 10.0)
        cb = _coinbase(bc, miner, 1)

        fits = _transfer(st, staker, receiver.address, 9.0, nonce=0)
        bc._candidate_precheck([cb, fits], 1, int(time.time()))   # must not raise

        exceeds = _transfer(st, staker, receiver.address, 10.5, nonce=0)
        try:
            bc._candidate_precheck([cb, exceeds], 1, int(time.time()))
        except CandidateTxRejected as rejected:
            assert rejected.index == 1
            assert "insufficient spendable balance" in rejected.reason
        else:
            raise AssertionError("precheck accepted a spend above balance minus stake")


def test_precheck_enforces_aggregate_vvm_block_gas_cap(monkeypatch):
    monkeypatch.setattr(Config, "VVM_BLOCK_GAS_LIMIT", 15_000)
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        caller = Wallet.generate()
        st.credit_sat(caller.address, 100 * SAT)
        cb = _coinbase(bc, miner, 1)

        first = _call(caller, nonce=0, gas_limit=10_000)
        second = _call(caller, nonce=1, gas_limit=10_000)   # 20_000 declared > 15_000 cap
        try:
            bc._candidate_precheck([cb, first, second], 1, int(time.time()))
        except CandidateTxRejected as rejected:
            assert rejected.index == 2, f"expected the overflowing call at index 2, got {rejected.index}"
            assert "VVM gas" in rejected.reason
        else:
            raise AssertionError("precheck accepted a block above the aggregate VVM gas cap (VSA-07)")


def test_precheck_applies_cumulative_l2_balance_and_escrow_for_withdrawals():
    miner = Wallet.generate()
    sender = Wallet.generate()
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        st.credit_sat(sender.address, 10 * SAT)
        st.credit_sat(L2_BRIDGE_ADDRESS, 10 * SAT)
        bc.layer2 = _FakeLayer2({sender.address: 1 * SAT})   # 1.00 VSD on L2
        cb = _coinbase(bc, miner, 1)
        first = _transfer(st, sender, L2_WITHDRAW_ADDRESS, 0.75, nonce=0)
        second = _transfer(st, sender, L2_WITHDRAW_ADDRESS, 0.75, nonce=1)

        bc._candidate_precheck([cb, first], 1, int(time.time()))   # one withdrawal fits
        try:
            bc._candidate_precheck([cb, first, second], 1, int(time.time()))
        except CandidateTxRejected as rejected:
            assert rejected.index == 2
            assert "L2 balance" in rejected.reason
        else:
            raise AssertionError("two withdrawals exceeding the L2 balance were accepted (VSA-01)")

        bc.layer2 = None
        try:
            bc._candidate_precheck([cb, first], 1, int(time.time()))
        except CandidateTxRejected as rejected:
            assert rejected.index == 1
            assert "not initialised" in rejected.reason
        else:
            raise AssertionError("withdrawal accepted without an initialised L2 subsystem")

    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        st.credit_sat(sender.address, 10 * SAT)
        st.credit_sat(L2_BRIDGE_ADDRESS, 1 * SAT // 2)      # escrow 0.50 < 0.75
        bc.layer2 = _FakeLayer2({sender.address: 1 * SAT})
        cb = _coinbase(bc, miner, 1)
        withdrawal = _transfer(st, sender, L2_WITHDRAW_ADDRESS, 0.75, nonce=0)
        try:
            bc._candidate_precheck([cb, withdrawal], 1, int(time.time()))
        except CandidateTxRejected as rejected:
            assert rejected.index == 1
            assert "bridge escrow" in rejected.reason
        else:
            raise AssertionError("withdrawal accepted with insufficient bridge escrow (VSA-01)")


# ── VSA-02 ───────────────────────────────────────────────────────────────────

def test_apply_block_does_not_deadlock_against_a_chain_lock_holder(monkeypatch):
    """A thread holding Blockchain._lock (as candidate construction does) must not
    deadlock against apply_block(): the SQLite atomic block may not be entered
    while the chain lock is still pending."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        block = _coinbase_block(bc, miner)

        began = threading.Event()
        real_begin = st.begin_sqlite_atomic_block

        def traced_begin():
            began.set()
            real_begin()

        monkeypatch.setattr(st, "begin_sqlite_atomic_block", traced_begin)
        results = {}

        bc._lock.acquire()
        try:
            apply_thread = threading.Thread(
                target=lambda: results.__setitem__("apply", bc.apply_block(block)),
                daemon=True)
            apply_thread.start()
            apply_thread.join(timeout=0.3)   # give apply_block time to reach its first wait
            entered_sqlite_before_chain_lock = began.is_set()
            probe_done = threading.Event()

            def storage_probe():
                results["probe"] = st.get_nonce(miner.address)
                probe_done.set()

            probe_thread = threading.Thread(target=storage_probe, daemon=True)
            probe_thread.start()
            probe_finished = probe_done.wait(timeout=5.0)
        finally:
            bc._lock.release()

        apply_thread.join(timeout=15.0)
        assert not entered_sqlite_before_chain_lock, (
            "apply_block entered the SQLite atomic block while another thread held "
            "Blockchain._lock (VSA-02 lock-order inversion)")
        assert probe_finished, (
            "storage read under the chain lock deadlocked against apply_block (VSA-02)")
        assert not apply_thread.is_alive(), "apply_block did not complete after the lock was released"
        assert results.get("apply", (False, ""))[0] is True, results.get("apply")


# ── VSA-06 ───────────────────────────────────────────────────────────────────

def test_failed_commit_does_not_leave_block_marked_applied_in_memory(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        block = _coinbase_block(bc, miner)
        real_commit = st.commit_sqlite_atomic_block

        def failing_commit():
            st.rollback_sqlite_atomic_block()   # what the real failure path leaves behind
            raise OSError("injected COMMIT failure")

        monkeypatch.setattr(st, "commit_sqlite_atomic_block", failing_commit)
        try:
            bc.apply_block(block)
        except OSError:
            pass
        assert block.block_hash not in bc._applied_block_hashes, (
            "block marked applied in memory although COMMIT failed (VSA-06)")
        assert bc.height() == block.index - 1

        monkeypatch.setattr(st, "commit_sqlite_atomic_block", real_commit)
        ok, msg = bc.apply_block(block)
        assert ok, f"retry after failed commit must apply for real, got: {msg}"
        assert "already applied" not in msg
        assert bc.height() == block.index
