"""V4 regression tests for Section 96: Event-Driven State Application and Idempotency."""

from __future__ import annotations

import logging
import os
import tempfile
import threading
import types

import pytest

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.kernel.metrics import metrics
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = Config.SATOSHI_PER_VSD


@pytest.fixture(autouse=True)
def _quiet_logs_and_fast_diff(monkeypatch):
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    monkeypatch.setattr(Config, "MIN_DIFFICULTY", 0.001)
    prev = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(prev)


def _make_chain(td, name="chain.db"):
    st = Storage(os.path.join(td, name))
    bc = Blockchain(st)
    bc._rolling_pruner.prune_async = lambda h: None
    return st, bc


def _build_block(bc, miner, txs=None, *, prev=None, height=None, nonce_start=0):
    txs = list(txs or [])
    h = (bc.height() + 1) if height is None else height
    cb = Transaction.coinbase(miner.address, bc.compute_reward_sat(h) / SAT, h)
    root = bc.dry_run_state_root([cb] + txs, miner.address, h)
    b = Block(
        index=h,
        prev_hash=(prev or bc.latest_block().block_hash),
        transactions=[cb] + txs,
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        state_root=root,
        nonce=nonce_start,
    )
    assert b.mine()
    return b


class _MockNetwork:
    def __init__(self):
        self._lock = threading.Lock()
        self.peers = {}
        self.broadcasted_blocks = []
        self.published_receipts = []
        self.gossiped = []
        self.sync_results = []

    def broadcast_block(self, block, exclude=None):
        self.broadcasted_blocks.append((block.index, block.block_hash, exclude))

    def publish_receipts_for_block(self, block):
        self.published_receipts.append((block.index, block.block_hash))

    def _gossip(self, payload, exclude=None):
        self.gossiped.append((payload.get("type"), exclude))

    def _mark_peer_height_verified(self, peer_id, blocks):
        pass

    def _on_chain_sync_result(self, *args, **kwargs):
        self.sync_results.append(args)


def test_v4_spoofed_applied_block_hash_is_rejected():
    """Fixed: Forged block at tip+1 carrying an already-applied block_hash is
    rejected rather than short-circuiting as 'already applied'.
    """
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        eng = StateEngine(bc, bc._governance, st)
        net = _MockNetwork()
        eng.set_network(net)

        miner = Wallet.generate()
        b1 = _build_block(bc, miner)
        ok, msg = eng._handle_new_block({"block": b1.to_dict()}, source_peer="honest_peer")
        assert ok, msg
        assert b1.block_hash in bc._applied_block_hashes
        assert bc.height() == 1

        forged = {
            "index": 2,
            "prev_hash": "0" * 64,
            "transactions": [],
            "miner_address": miner.address,
            "difficulty": 0.0001,
            "timestamp": b1.timestamp + 1,
            "nonce": 0,
            "block_hash": b1.block_hash,
            "state_root": "",
            "merkle_root": "0" * 64,
        }
        gov_calls = []
        orig_on_block = bc._governance.on_block_applied
        bc._governance.on_block_applied = lambda blk: (
            gov_calls.append((blk.index, blk.block_hash)),
            orig_on_block(blk),
        )

        net.broadcasted_blocks.clear()
        ok_forged, _msg_forged = eng._handle_new_block(
            {"block": forged}, source_peer="attacker_peer"
        )

        assert ok_forged is False
        assert st.get_block(2) is None
        assert (2, b1.block_hash) not in gov_calls
        assert not any(idx == 2 and h == b1.block_hash for idx, h, _ in net.broadcasted_blocks)


def test_v4_same_height_winning_fork_drains_orphans_and_relays():
    """Fixed: When a same-height competing block wins accept_chain() in _handle_new_block(),
    it drains dependent orphans and relays the winning block.
    """
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        eng = StateEngine(bc, bc._governance, st)
        net = _MockNetwork()
        eng.set_network(net)

        genesis = bc.latest_block()
        miner_a = Wallet.generate()
        miner_b = Wallet.generate()

        cand_x = _build_block(bc, miner_a, prev=genesis.block_hash, height=1, nonce_start=1)
        cand_y = _build_block(bc, miner_b, prev=genesis.block_hash, height=1, nonce_start=10000)
        if cand_x.block_hash < cand_y.block_hash:
            a1, b1 = cand_y, cand_x
        else:
            a1, b1 = cand_x, cand_y

        st2, bc2 = _make_chain(td, "fork.db")
        ok2, msg2 = bc2.apply_block(b1)
        assert ok2, msg2
        b2 = _build_block(bc2, miner_b, prev=b1.block_hash, height=2)

        ok_b2, _ = eng._handle_new_block({"block": b2.to_dict()}, source_peer="peerB")
        assert not ok_b2
        assert b2.block_hash in eng._orphans

        ok_a1, msg_a1 = eng._handle_new_block({"block": a1.to_dict()}, source_peer="peerA")
        assert ok_a1, msg_a1
        assert st.get_block(1).block_hash == a1.block_hash
        assert b2.block_hash in eng._orphans

        net.broadcasted_blocks.clear()
        ok_b1, _ = eng._handle_new_block({"block": b1.to_dict()}, source_peer="peerB")
        assert ok_b1
        assert st.get_block(1).block_hash == b1.block_hash

        assert b2.block_hash not in eng._orphans
        assert bc.height() == 2
        assert len(net.broadcasted_blocks) >= 1


def test_v4_duplicate_block_and_mine_result_are_idempotent():
    """Fixed: Duplicate _handle_new_block and _handle_mine_result do not re-run
    post-apply hooks (SHBS, receipts, broadcast_block, metrics.inc('blocks_mined')).
    """
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        eng = StateEngine(bc, bc._governance, st)
        net = _MockNetwork()
        eng.set_network(net)

        shbs_calls = []
        fake_shbs = types.SimpleNamespace(
            _running=True,
            on_block_applied=lambda blk: shbs_calls.append((blk.index, blk.block_hash)),
        )
        eng._node_ref = types.SimpleNamespace(shbs=fake_shbs, consensus=None)

        miner = Wallet.generate()
        b1 = _build_block(bc, miner)

        ok1, _ = eng._handle_new_block({"block": b1.to_dict()}, source_peer="peer1")
        assert ok1
        ok2, _ = eng._handle_new_block({"block": b1.to_dict()}, source_peer="peer2")
        assert ok2

        assert len(shbs_calls) == 1
        assert len(net.published_receipts) == 1
        assert len(net.broadcasted_blocks) == 1

        before_mined = metrics.get_counter("blocks_mined")
        ok_m, _ = eng._handle_mine_result({"block": b1})
        assert ok_m
        after_mined = metrics.get_counter("blocks_mined")

        assert after_mined == before_mined
        assert len(shbs_calls) == 1
