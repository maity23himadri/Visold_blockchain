"""Regression tests for block apply/rollback after sync, relay and L2 rollback.

Each test drives the real Blockchain / StateEngine / RollbackExecutor code over
SQLite storage and pins one defect:

  * a failed block rollback must not leave balances half-reversed, and a retry
    must not reverse the block a second time;
  * a failed block apply must restore Layer2State (no double credit on retry);
  * RollbackExecutor must work on canonical Block objects and reconcile L2;
  * a losing same-height or rejected sync candidate must not write the
    canonical block_apply:<height> marker;
  * the applied-hash cache is bounded;
  * governance finality comes from the canonical finality fence;
  * a partially failed rollback leaves the chain consistent at the height it
    reached and does not arm critical recovery.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time

import pytest

from visold.chain.blockchain import Blockchain
from visold.chain.sequencer import Sequencer
from visold.governance.engine import GovernanceEngine, UpgradePhase, UpgradeProposal
from visold.governance.versioning import ProtocolVersionManager
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS
from visold.selfhealing.rollback import RollbackExecutor, SnapshotStore
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = Config.SATOSHI_PER_VSD
FAR = 2_000_000_000


@pytest.fixture(autouse=True)
def _suppress_noisy_logs_without_leaking_global_state():
    """Silence expected error-path logs only while this test is running.

    ``logging.disable`` changes process-global state.  Saving and restoring the
    previous threshold prevents these regression tests from disabling
    ``caplog`` (or ordinary logging) in unrelated test modules.
    """
    previous_disable = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(previous_disable)



def _make_chain(td: str, name: str = "hardening.db"):
    st = Storage(os.path.join(td, name))
    bc = Blockchain(st)
    bc._rolling_pruner.prune_async = lambda h: None
    return st, bc


def _transfer(st, w, receiver, amount, nonce=None):
    tx = Transaction(sender=w.address, receiver=receiver, amount=amount,
                     fee=round(amount * Config.TX_FEE_RATE, 8),
                     nonce=st.get_nonce(w.address) if nonce is None else nonce,
                     expiry=FAR)
    tx.sign(w)
    return tx


def _build_block(bc, miner, txs):
    height = bc.height() + 1
    cb = Transaction.coinbase(miner.address, bc.compute_reward_sat(height) / SAT, height)
    root = bc.dry_run_state_root([cb] + list(txs), miner.address, height)
    b = Block(index=height, prev_hash=bc.latest_block().block_hash,
              transactions=[cb] + list(txs), miner_address=miner.address,
              difficulty=bc.get_difficulty(), state_root=root)
    assert b.mine()
    return b


def _balances(st, bc, *addresses):
    snap = {a: st.get_balance_sat(a) for a in addresses}
    snap["bridge"] = st.get_balance_sat(L2_BRIDGE_ADDRESS)
    snap["issued"] = st.get_cumulative_issued_sat()
    snap["total"] = st.sum_all_balances_satoshi()
    return snap


def test_failed_block_delete_rolls_back_whole_block_and_retry_is_exact():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        m, user, bob = Wallet.generate(), Wallet.generate(), Wallet.generate()
        st.credit_sat(user.address, 10 * SAT)
        assert bc.apply_block(_build_block(bc, m, []))[0]
        pre = _balances(st, bc, user.address, bob.address, m.address)

        t1 = _transfer(st, user, bob.address, 1.0, nonce=0)
        t2 = _transfer(st, user, L2_BRIDGE_ADDRESS, 2.0, nonce=1)
        assert bc.apply_block(_build_block(bc, m, [t1, t2]))[0]

        real_delete = st.delete_block
        calls = {"n": 0}

        def flaky_delete(idx, rollback_tx_ids=None):
            calls["n"] += 1
            if calls["n"] == 1:
                return False            # simulated lock/disk/IO failure
            return real_delete(idx, rollback_tx_ids=rollback_tx_ids)

        st.delete_block = flaky_delete
        ok, _msg = bc.rollback(1)
        st.delete_block = real_delete

        assert not ok
        assert bc.height() == 2, "failed block must stay canonical"
        assert st.get_balance_sat(bob.address) == 100_000_000, "failed rollback must not move funds"

        ok, _msg = bc.rollback(1)
        assert ok
        assert _balances(st, bc, user.address, bob.address, m.address) == pre
        assert bc.layer2.get_balance_sat(user.address) == 0


def test_failed_apply_after_l2_mutation_restores_l2_so_retry_is_exact():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        m, user = Wallet.generate(), Wallet.generate()
        st.credit_sat(user.address, 10 * SAT)
        deposit = _transfer(st, user, L2_BRIDGE_ADDRESS, 2.0, nonce=0)
        block = _build_block(bc, m, [deposit])

        real_record = st.record_block_apply_result

        def boom(idx, ok):
            raise RuntimeError("simulated failure after the L2 deposit")

        st.record_block_apply_result = boom
        try:
            bc.apply_block(block)
            raise AssertionError("expected the failure to propagate")
        except RuntimeError:
            pass
        finally:
            st.record_block_apply_result = real_record

        assert bc.height() == 0
        assert bc.layer2.get_balance_sat(user.address) == 0
        assert len(bc.layer2._history) == 0
        ok_ok, _ = bc.apply_block(block)
        assert ok_ok
        assert bc.layer2.get_balance_sat(user.address) == 200_000_000
        ok_l2, l2_total, l1_bridge = bc.layer2.supply_invariant_ok()
        assert ok_l2 and l2_total == l1_bridge == 200_000_000


def test_rollback_executor_uses_canonical_blocks_and_reconciles_l2():
    for replay in (True, False):
        with tempfile.TemporaryDirectory() as td:
            st, bc = _make_chain(td)
            miner, user, other, seqw = (Wallet.generate() for _ in range(4))
            st.credit_sat(user.address, 10 * SAT)
            st.credit_sat(seqw.address, 1 * SAT)
            assert bc.apply_block(_build_block(
                bc, miner, [_transfer(st, user, L2_BRIDGE_ADDRESS, 2.0)]))[0]
            seq = Sequencer(bc.layer2, seqw, bc)
            seq._running = True
            seq.add_l2_tx(user.sign_l2_tx(other.address, amount_sat=int(0.5 * SAT),
                                          nonce=0, timestamp=int(time.time())))
            l1_tx, bid, applied = seq._seal_one()
            seq._finalize_seal(bid, applied)
            assert bc.apply_block(_build_block(bc, miner, [l1_tx]))[0]
            assert bc.height() == 2

            ex = RollbackExecutor(bc, st, SnapshotStore(td))
            ok, msg = ex.execute(1, set(), replay_safe=replay)
            assert ok, msg
            assert bc.height() == 1
            # The L2 batch (block 2) is undone, so the L2 balances must be the
            # post-deposit state again, not the post-rollup state.
            assert bc.layer2.get_balance_sat(user.address) == 200_000_000
            assert bc.layer2.get_balance_sat(other.address) == 0
            assert bc.layer2.supply_invariant_ok()[0]


def test_losing_same_height_candidate_does_not_touch_canonical_marker():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        m1, m2 = Wallet.generate(), Wallet.generate()
        gov = GovernanceEngine(st, ProtocolVersionManager(st))
        eng = StateEngine(bc, gov, st)
        b1 = _build_block(bc, m1, [])
        assert bc.apply_block(b1)[0]
        b2 = _build_block(bc, m1, [])
        assert bc.apply_block(b2)[0]
        assert st.get_meta("block_apply:2") == "ok"

        height = 2
        cb = Transaction.coinbase(m2.address, bc.compute_reward_sat(height) / SAT, height)
        fork = Block(index=2, prev_hash=b1.block_hash, transactions=[cb],
                     miner_address=m2.address, difficulty=b2.difficulty,
                     state_root="ab" * 32, timestamp=b2.timestamp + 1)
        assert fork.mine()
        old_hash = bc.latest_block().block_hash
        eng._handle_new_block({"block": fork.to_dict()}, "peerX")

        assert bc.latest_block().block_hash == old_hash
        assert st.get_meta("block_apply:2") == "ok"


def test_rejected_sync_batch_does_not_poison_canonical_markers():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        m, evil = Wallet.generate(), Wallet.generate()
        gov = GovernanceEngine(st, ProtocolVersionManager(st))
        eng = StateEngine(bc, gov, st)
        blocks = []
        for _ in range(3):
            b = _build_block(bc, m, [])
            assert bc.apply_block(b)[0]
            blocks.append(b)

        bogus = []
        prev = blocks[0].prev_hash
        for h in (1, 2, 3):
            cb = Transaction.coinbase(evil.address, 1.0, h)
            bb = Block(index=h, prev_hash=prev, transactions=[cb],
                       miner_address=evil.address, difficulty=bc.get_difficulty(),
                       state_root="cd" * 32)
            prev = bb.block_hash
            bogus.append(bb)
        ok, _msg = eng._handle_chain_sync({"blocks": [b.to_dict() for b in bogus]}, "peerZ")

        assert not ok
        assert bc.height() == 3
        assert [st.get_meta(f"block_apply:{h}") for h in (1, 2, 3)] == ["ok", "ok", "ok"]
        assert st.get_block_invalid_rate(1, 3) == 0.0


def test_applied_hash_cache_is_bounded_and_evicts_oldest():
    from visold.chain.blockchain import _BoundedHashSet

    cache = _BoundedHashSet(3)
    for h in ("a", "b", "c", "d", "e"):
        cache.add(h)
    assert len(cache) == 3
    assert "a" not in cache and "b" not in cache
    assert "e" in cache
    cache.discard("e")
    assert "e" not in cache


def test_governance_finality_comes_from_canonical_fence_not_wire_flag():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        gov = GovernanceEngine(st, ProtocolVersionManager(st))
        ver = gov.proto_mgr.current_version() + 1
        p = UpgradeProposal(ver, UpgradePhase.ACTIVE, 1, 2, 2, 3, rollback_window=100)
        gov._proposals[ver] = p

        class _Wire:
            index = 9
            block_hash = "f" * 64
            finalized = True        # a relayed claim, never canonical

        gov.set_finality_source(lambda: 7)   # the blockchain's canonical fence
        gov.on_block_applied(_Wire())
        assert gov._last_finalized_height == 7

        # Without the fence, a wire claim alone must not count as finality.
        gov2 = GovernanceEngine(st, ProtocolVersionManager(st))
        gov2._last_finalized_height = -1
        gov2.on_block_applied(_Wire())
        assert gov2._last_finalized_height == -1


def test_partial_rollback_reconciles_to_reached_height_without_critical_recovery():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        m, user, bob = Wallet.generate(), Wallet.generate(), Wallet.generate()
        st.credit_sat(user.address, 10 * SAT)
        assert bc.apply_block(_build_block(bc, m, []))[0]
        assert bc.apply_block(_build_block(bc, m, [_transfer(st, user, bob.address, 1.0, nonce=0)]))[0]
        after_block_2 = _balances(st, bc, user.address, bob.address, m.address)
        assert bc.apply_block(_build_block(bc, m, [_transfer(st, user, bob.address, 1.0, nonce=1)]))[0]
        assert bc.height() == 3

        real_delete = st.delete_block

        def fail_at_2(idx, rollback_tx_ids=None):
            if idx == 2:
                return False
            return real_delete(idx, rollback_tx_ids=rollback_tx_ids)

        st.delete_block = fail_at_2
        try:
            ok, _msg = bc.rollback(0)
        finally:
            st.delete_block = real_delete

        assert not ok
        assert bc.height() == 2
        assert bc._critical_recovery is None
        assert _balances(st, bc, user.address, bob.address, m.address) == after_block_2
        assert bc.layer2.supply_invariant_ok()[0]
