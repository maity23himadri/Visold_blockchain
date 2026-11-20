"""V4 regression tests for Section 96: Event-Driven State Application and Idempotency."""

from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace

import pytest

from visold.chain.blockchain import Blockchain
from visold.governance.engine import GovernanceEngine
from visold.kernel.config import BLOCK_ALREADY_APPLIED_MSG, Config
from visold.kernel.events import Event, EventType
from visold.kernel.metrics import metrics
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


SAT = Config.SATOSHI_PER_VSD


@pytest.fixture(autouse=True)
def _fast_difficulty(monkeypatch):
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    monkeypatch.setattr(Config, "MIN_DIFFICULTY", 0.001)


def _mine_child_block(bc: Blockchain, prev: Block, miner: Wallet,
                      timestamp: float | None = None,
                      difficulty: float | None = None) -> Block:
    height = prev.index + 1
    cb = Transaction.coinbase(
        miner.address, bc.compute_reward_sat(height) / SAT, height)
    if bc.latest_block() and bc.latest_block().block_hash == prev.block_hash:
        root = bc.dry_run_state_root([cb], miner.address, height)
    else:
        root = prev.state_root
    diff = difficulty if difficulty is not None else bc.get_difficulty()
    ts = timestamp if timestamp is not None else int(max(time.time(), prev.timestamp + 1))
    b = Block(
        index=height,
        prev_hash=prev.block_hash,
        transactions=[cb],
        miner_address=miner.address,
        difficulty=diff,
        timestamp=ts,
        state_root=root,
    )
    b.mine()
    return b


class _DummyNetwork:
    def __init__(self):
        self._lock = threading.Lock()
        self.peers = {}
        self.broadcasts = []
        self.receipts = []
        self.verified = []
        self.gossips = []

    def broadcast_block(self, block, exclude=None):
        self.broadcasts.append((block.block_hash, exclude))

    def publish_receipts_for_block(self, block):
        self.receipts.append(block.block_hash)

    def _mark_peer_height_verified(self, peer_id, blocks):
        self.verified.append((peer_id, len(blocks)))

    def _gossip(self, msg, exclude=None):
        self.gossips.append((msg, exclude))


class _DummySHBS:
    def __init__(self):
        self._running = True
        self.observed = []

    def on_block_applied(self, block):
        self.observed.append((block.index, block.block_hash))


def test_duplicate_block_delivery_is_idempotent_in_state_engine(tmp_path):
    """Fixed: Duplicate delivery of an already-applied block does not re-run
    side effects in _handle_new_block() or _handle_mine_result()."""
    st = Storage(os.path.join(str(tmp_path), "s96_dup.db"))
    bc = Blockchain(st)
    gov = GovernanceEngine(st, bc._proto_mgr)
    engine = StateEngine(bc, gov, st)
    net = _DummyNetwork()
    shbs = _DummySHBS()
    engine.set_network(net)
    engine._node_ref = SimpleNamespace(shbs=shbs, consensus=None)

    miner = Wallet.generate()
    b1 = _mine_child_block(bc, bc.latest_block(), miner)

    before_mined = metrics.get_counter("blocks_mined")
    ok1, msg1 = engine._handle(Event(EventType.MINE_RESULT, {"block": b1}))
    assert ok1 and msg1 == "OK"
    assert metrics.get_counter("blocks_mined") == before_mined + 1
    assert len(net.broadcasts) == 1
    assert len(shbs.observed) == 1

    ok2, msg2 = engine._handle(Event(EventType.MINE_RESULT, {"block": b1}))
    assert ok2 and msg2 == BLOCK_ALREADY_APPLIED_MSG
    assert metrics.get_counter("blocks_mined") == before_mined + 1
    assert len(net.broadcasts) == 1
    assert len(shbs.observed) == 1

    ok3, msg3 = engine._handle(
        Event(EventType.NEW_BLOCK, {"block": b1}, source_peer_id="peerA"))
    assert ok3 and msg3 == BLOCK_ALREADY_APPLIED_MSG
    assert len(net.broadcasts) == 1
    assert len(shbs.observed) == 1


def test_same_height_fork_win_runs_post_apply_hooks_and_drains_orphans(tmp_path):
    """Fixed: When a competing same-height block wins fork choice in
    _handle_new_block(), post-apply hooks run, orphans drain, and blocks relay."""
    st = Storage(os.path.join(str(tmp_path), "s96_fork.db"))
    bc = Blockchain(st)
    gov = GovernanceEngine(st, bc._proto_mgr)
    engine = StateEngine(bc, gov, st)
    net = _DummyNetwork()
    shbs = _DummySHBS()
    engine.set_network(net)
    engine._node_ref = SimpleNamespace(shbs=shbs, consensus=None)

    genesis = bc.latest_block()
    miner_a = Wallet.generate()
    miner_b = Wallet.generate()

    cand_x = _mine_child_block(bc, genesis, miner_a, timestamp=int(genesis.timestamp) + 5)
    cand_y = _mine_child_block(bc, genesis, miner_b, timestamp=int(genesis.timestamp) + 6)
    if cand_x.block_hash < cand_y.block_hash:
        b1a, b1b = cand_y, cand_x
        win_miner = miner_a
    else:
        b1a, b1b = cand_x, cand_y
        win_miner = miner_b

    ok_a, _ = engine._handle(
        Event(EventType.NEW_BLOCK, {"block": b1a}, source_peer_id="peerA"))
    assert ok_a
    assert bc.height() == 1
    net.broadcasts.clear()
    shbs.observed.clear()

    st_tmp = Storage(os.path.join(str(tmp_path), "s96_tmp.db"))
    bc_tmp = Blockchain(st_tmp)
    assert bc_tmp.apply_block(b1b)[0]
    b2b = _mine_child_block(bc_tmp, b1b, win_miner)

    assert engine._stash_orphan(b2b, b2b.to_dict(), source_peer="peerB")
    assert b2b.block_hash in engine._orphans

    ok_b, _msg_b = engine._handle(
        Event(EventType.NEW_BLOCK, {"block": b1b}, source_peer_id="peerB"))
    assert ok_b
    assert st.get_block(1).block_hash == b1b.block_hash

    assert b2b.block_hash not in engine._orphans
    assert bc.height() == 2
    assert len(net.broadcasts) >= 1
    assert len(shbs.observed) >= 1


def test_orphan_block_does_not_record_fail_apply_marker(tmp_path):
    """Fixed: Stashing a valid orphan block does not write block_apply:<h>='fail'."""
    st = Storage(os.path.join(str(tmp_path), "s96_orphan.db"))
    bc = Blockchain(st)
    gov = GovernanceEngine(st, bc._proto_mgr)
    engine = StateEngine(bc, gov, st)
    engine.set_network(_DummyNetwork())

    miner = Wallet.generate()

    st_tmp = Storage(os.path.join(str(tmp_path), "s96_tmp2.db"))
    bc_tmp = Blockchain(st_tmp)
    b1 = _mine_child_block(bc_tmp, bc_tmp.latest_block(), miner)
    assert bc_tmp.apply_block(b1)[0]
    b2 = _mine_child_block(bc_tmp, b1, miner)

    ok, msg = engine._handle(
        Event(EventType.NEW_BLOCK, {"block": b2}, source_peer_id="peerA"))
    assert not ok
    assert "stashed" in msg.lower()
    assert b2.block_hash in engine._orphans

    assert st.get_meta("block_apply:2") is None
    assert st.get_block_invalid_rate(2, 1) == 0.0
