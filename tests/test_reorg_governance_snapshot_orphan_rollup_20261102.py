"""Regression tests for four reorg / rollback / sync defects (reported 2026-11-01).

  1. Protocol-upgrade (governance) state must be undone when a rollback or reorg
     removes the block that caused a lock-in, an activation or a failure.
  2. A reorg must not leave a snapshot of the abandoned branch servable.
  3. A block without proof-of-work must not occupy the orphan slot of the real
     child block, and a block with a self-declared easy difficulty is refused.
  4. A TYPE_ROLLUP must not be skipped because a bridge deposit shares its
     block, and an L2 transfer whose rollup is skipped must be re-queued.

Each test drives the real Blockchain / StateEngine / Sequencer code over SQLite.
Config values that a test changes are restored in a finally block.
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading
import time

import pytest
import types

from visold.chain.blockchain import Blockchain
from visold.chain.sequencer import Sequencer
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS
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


def _make_chain(td, name="chain.db"):
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


def _build_block(bc, miner, txs, *, prev=None, ts=None, proto=None):
    height = bc.height() + 1
    cb = Transaction.coinbase(miner.address, bc.compute_reward_sat(height) / SAT, height)
    root = bc.dry_run_state_root([cb] + list(txs), miner.address, height)
    kw = {}
    if ts is not None:
        kw["timestamp"] = ts
    if proto is not None:
        kw["protocol_version"] = proto
    b = Block(index=height, prev_hash=(prev or bc.latest_block().block_hash),
              transactions=[cb] + list(txs), miner_address=miner.address,
              difficulty=bc.get_difficulty(), state_root=root, **kw)
    assert b.mine()
    return b


class _gov_config:
    """Set the governance timing constants a test needs, then restore them."""

    def __enter__(self):
        self._saved = (Config.FORK_SIGNAL_WINDOW, Config.GOVERNANCE_ACTIVATION_DELAY)
        Config.FORK_SIGNAL_WINDOW = 3
        Config.GOVERNANCE_ACTIVATION_DELAY = 2
        return self

    def __exit__(self, *exc):
        Config.FORK_SIGNAL_WINDOW, Config.GOVERNANCE_ACTIVATION_DELAY = self._saved
        return False


def _phase(bc):
    p = bc._governance.get_proposal(2)
    return (p.phase.value, p.lock_in_height, p.activation_height) if p else None


# ── 1. governance state ───────────────────────────────────────────────────────

def test_governance_lock_in_undone_by_manual_rollback():
    with _gov_config(), tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td, "R.db")
        assert bc._governance.propose_upgrade(2, 1, threshold=0.5)[0]
        eng = StateEngine(bc, bc._governance, st)
        m = Wallet.generate()
        b1 = _build_block(bc, m, [], proto=2)
        ok, _ = eng._handle_new_block({"block": b1.to_dict()}, "")
        assert ok
        assert _phase(bc)[0] == "LOCKED_IN", _phase(bc)
        ok, msg = bc.rollback(0)
        assert ok, msg
        assert _phase(bc) == ("SIGNALING", 0, 0), _phase(bc)


def test_governance_active_upgrade_rewinds_version_on_rollback():
    with _gov_config(), tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td, "A.db")
        assert bc._governance.propose_upgrade(2, 1, threshold=0.5)[0]
        eng = StateEngine(bc, bc._governance, st)
        m = Wallet.generate()
        base_version = bc._proto_mgr.current_version()
        # block 1 signals v2 -> LOCKED_IN(lock=1, activation=3)
        # blocks 2 and 3 are v1 -> block 3 activates v2 (version advances)
        for proto in (2, 1, 1):
            b = _build_block(bc, m, [], proto=proto)
            ok, msg = eng._handle_new_block({"block": b.to_dict()}, "")
            assert ok, msg
        assert _phase(bc)[0] == "ACTIVE", _phase(bc)
        assert bc._proto_mgr.current_version() == 2
        ok, msg = bc.rollback(1)
        assert ok, msg
        # The activating block (3) is gone: phase falls back to LOCKED_IN and the
        # enforced version returns to the pre-upgrade value.
        assert _phase(bc)[0] == "LOCKED_IN", _phase(bc)
        assert bc._proto_mgr.current_version() == base_version


def test_failed_signal_window_reverted_by_rollback():
    with _gov_config(), tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td, "F.db")
        assert bc._governance.propose_upgrade(2, 1, threshold=0.5)[0]
        eng = StateEngine(bc, bc._governance, st)
        m = Wallet.generate()
        # Signal window is [1, 4]; no block signals, so FAILED is set at height 5.
        for _ in range(5):
            b = _build_block(bc, m, [], proto=1)
            ok, msg = eng._handle_new_block({"block": b.to_dict()}, "")
            assert ok, msg
        assert _phase(bc)[0] == "FAILED", _phase(bc)
        ok, msg = bc.rollback(3)
        assert ok, msg
        assert _phase(bc)[0] == "SIGNALING", _phase(bc)


def test_reorg_to_non_signalling_branch_matches_fresh_node():
    with _gov_config(), tempfile.TemporaryDirectory() as td:
        stA, bcA = _make_chain(td, "A.db")
        stB, bcB = _make_chain(td, "B.db")
        for bc in (bcA, bcB):
            assert bc._governance.propose_upgrade(2, 1, threshold=0.5)[0]
        engA = StateEngine(bcA, bcA._governance, stA)
        m1, m2 = Wallet.generate(), Wallet.generate()
        a1 = _build_block(bcA, m1, [], proto=2)
        assert engA._handle_new_block({"block": a1.to_dict()}, "")[0]
        assert _phase(bcA)[0] == "LOCKED_IN"
        b1 = _build_block(bcB, m2, [], proto=1, ts=a1.timestamp + 1)
        assert bcB.apply_block(b1)[0]
        b2 = _build_block(bcB, m2, [], proto=1, ts=a1.timestamp + 2)
        assert bcB.apply_block(b2)[0]
        ok, msg = bcA.accept_chain([Block.from_dict(b1.to_dict()), Block.from_dict(b2.to_dict())])
        assert ok, msg
        assert _phase(bcA) == _phase(bcB) == ("SIGNALING", 0, 0), (_phase(bcA), _phase(bcB))
        assert bcA._proto_mgr.current_version() == bcB._proto_mgr.current_version() == 1


# ── 2. snapshots after a reorg ────────────────────────────────────────────────

def test_servable_manifest_refuses_entry_not_matching_canonical_anchor():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td, "S.db")
        m = Wallet.generate()
        for _ in range(3):
            assert bc.apply_block(_build_block(bc, m, []))[0]
        eng = bc._snapshot_engine
        h = 2
        header = st.get_block_header(h)
        blob = b"not-a-real-snapshot"
        st.set_meta(f"{eng._KEY_PREFIX}{h}", blob.hex())
        # Entry names a block hash that is NOT canonical at height 2 (as after a reorg).
        eng._update_manifest(h, header["state_root"], len(blob),
                             "00" * 32, bootstrap_digest="ab" * 32)
        assert [e["height"] for e in eng.get_servable_manifest()] == [], \
            "stale anchor must not be servable"
        # Same entry with the canonical anchor and state_root is servable.
        eng._update_manifest(h, header["state_root"], len(blob),
                             header["block_hash"], bootstrap_digest="ab" * 32)
        assert [e["height"] for e in eng.get_servable_manifest()] == [h]


def test_reorg_drops_snapshots_above_fork_point():
    with tempfile.TemporaryDirectory() as td:
        stA, bcA = _make_chain(td, "A.db")
        stP, bcP = _make_chain(td, "P.db")
        m1, m2 = Wallet.generate(), Wallet.generate()
        blocks = []
        for _ in range(3):
            b = _build_block(bcA, m1, [])
            assert bcA.apply_block(b)[0]
            blocks.append(b)
            if len(blocks) <= 2:
                assert bcP.apply_block(Block.from_dict(b.to_dict()))[0]
        b4 = _build_block(bcA, m1, [])
        assert bcA.apply_block(b4)[0]
        # Pretend a snapshot at height 3 was stored for the old block 3.
        eng = bcA._snapshot_engine
        st3 = stA.get_block_header(3)
        eng._update_manifest(3, st3["state_root"], 10, st3["block_hash"], bootstrap_digest="cd" * 32)
        assert any(e["height"] == 3 for e in eng.get_manifest())
        # Heavier competing branch from height 2.
        ts = b4.timestamp
        p3 = _build_block(bcP, m2, [], ts=ts + 1); assert bcP.apply_block(p3)[0]
        p4 = _build_block(bcP, m2, [], ts=ts + 2); assert bcP.apply_block(p4)[0]
        p5 = _build_block(bcP, m2, [], ts=ts + 3); assert bcP.apply_block(p5)[0]
        ok, msg = bcA.accept_chain([Block.from_dict(x.to_dict()) for x in (p3, p4, p5)])
        assert ok, msg
        assert not any(e["height"] == 3 for e in eng.get_manifest()), eng.get_manifest()


# ── 3. orphan pool ────────────────────────────────────────────────────────────

def _orphan_engine(bcA, stA):
    eng = StateEngine(bcA, bcA._governance, stA)
    calls = []
    eng._network = types.SimpleNamespace(
        _lock=threading.RLock(),
        peers={"evil": types.SimpleNamespace(connected=True),
               "honest": types.SimpleNamespace(connected=True)},
        _sync_request=lambda *a, **k: calls.append((a[1:], k.get("kind"))) or True,
        _mark_peer_height_verified=lambda *a, **k: None,
        publish_receipts_for_block=lambda b: None,
        broadcast_block=lambda *a, **k: None)
    return eng


def test_junk_block_cannot_take_orphan_slot_of_real_child():
    with tempfile.TemporaryDirectory() as td:
        stA, bcA = _make_chain(td, "A.db")
        stP, bcP = _make_chain(td, "P.db")
        m, evil = Wallet.generate(), Wallet.generate()
        for _ in range(3):
            b = _build_block(bcP, m, [])
            assert bcP.apply_block(b)[0]
            assert bcA.apply_block(Block.from_dict(b.to_dict()))[0]
        b4 = _build_block(bcP, m, []); assert bcP.apply_block(b4)[0]
        b5 = _build_block(bcP, m, []); assert bcP.apply_block(b5)[0]
        eng = _orphan_engine(bcA, stA)
        junk = Block(index=5, prev_hash=b4.block_hash,
                     transactions=[Transaction.coinbase(evil.address, 1.0, 5)],
                     miner_address=evil.address, difficulty=1.0, state_root="00" * 32)
        ok, msg = eng._handle_new_block({"block": junk.to_dict()}, "evil")
        assert not ok and "unproven" in msg, msg
        ok, msg = eng._handle_new_block({"block": b5.to_dict()}, "honest")
        assert not ok  # gap: block 4 missing, real block 5 is held
        held = [d["block_hash"] for d in eng._orphans.values()]
        assert b5.block_hash in held and junk.block_hash not in held
        ok, msg = eng._handle_new_block({"block": b4.to_dict()}, "honest")
        assert ok, msg
        assert bcA.height() == 5 and bcA.storage.get_block(5) is not None


def test_orphan_with_self_declared_easy_difficulty_is_refused():
    with tempfile.TemporaryDirectory() as td:
        stA, bcA = _make_chain(td, "A.db")
        eng = _orphan_engine(bcA, stA)
        w = Wallet.generate()
        easy = Block(index=5, prev_hash="11" * 32,
                     transactions=[Transaction.coinbase(w.address, 1.0, 5)],
                     miner_address=w.address, difficulty=1.0, state_root="00" * 32)
        assert easy.mine()
        assert easy.validate_pow()           # PoW holds for the block's own declared difficulty
        assert not eng._orphan_admissible(easy)  # but the difficulty is below the floor


# ── 4. rollups ────────────────────────────────────────────────────────────────

def _sequencer_setup(td):
    st, bc = _make_chain(td, "S.db")
    m, alice, bob, carol, seqw = (Wallet.generate() for _ in range(5))
    for w in (alice, carol):
        st.credit_sat(w.address, 10 * SAT)
    st.credit_sat(seqw.address, 1 * SAT)
    assert bc.apply_block(_build_block(bc, m, []))[0]
    assert bc.apply_block(_build_block(bc, m, [_transfer(st, alice, L2_BRIDGE_ADDRESS, 2.0)]))[0]
    seq = Sequencer(bc.layer2, seqw, bc)
    seq._running = True
    seq.add_l2_tx(alice.sign_l2_tx(bob.address, amount_sat=int(0.5 * SAT), nonce=0,
                                   timestamp=int(time.time())))
    return st, bc, m, alice, bob, carol, seqw, seq


def test_rollup_is_ordered_before_same_block_bridge_deposit():
    with tempfile.TemporaryDirectory() as td:
        st, bc, m, alice, bob, carol, seqw, seq = _sequencer_setup(td)
        R, bid, applied = seq._seal_one()
        seq._finalize_seal(bid, applied)
        D = _transfer(st, carol, L2_BRIDGE_ADDRESS, 1.0)
        assert bc.mempool.add(D)[0] and bc.mempool.add(R)[0]
        order = [t.tx_id for t in bc.mempool.get_top(10)]
        assert order.index(R.tx_id) < order.index(D.tx_id), "rollup must precede the deposit"
        ok, msg = bc.apply_block(_build_block(bc, m, [t for t in bc.mempool.get_top(10)]))
        assert ok, msg
        assert bc.layer2.get_balance_sat(bob.address) == int(0.5 * SAT)
        assert bc.layer2._last_batch_id == 0


def test_skipped_rollup_requeues_its_l2_transfers():
    with tempfile.TemporaryDirectory() as td:
        st, bc, m, alice, bob, carol, seqw, seq = _sequencer_setup(td)
        R, bid, applied = seq._seal_one()
        seq._finalize_seal(bid, applied)
        assert len(seq._pending) == 0          # finalized: transfer left the pending pool
        # A deposit lands in an earlier block, so R's prev root is now stale.
        assert bc.apply_block(_build_block(bc, m, [_transfer(st, carol, L2_BRIDGE_ADDRESS, 1.0)]))[0]
        ok, msg = bc.apply_block(_build_block(bc, m, [R]))
        assert ok, msg                         # block accepted, rollup skipped (deterministic)
        assert bc.layer2.get_balance_sat(bob.address) == 0
        assert seq._process_dropped_rollups() == 1
        assert len(seq._pending) == 1          # transfer is back in the pending pool
        R2, bid2, applied2 = seq._seal_one()
        seq._finalize_seal(bid2, applied2)
        ok, msg = bc.apply_block(_build_block(bc, m, [R2]))
        assert ok, msg
        assert bc.layer2.get_balance_sat(bob.address) == int(0.5 * SAT)
        assert len(seq._pending) == 0
