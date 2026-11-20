"""Section 37 Audit: Consensus Engine State Transitions and Validation."""
from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

from visold.chain.consensus_engine import ConsensusEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.state.engine import StateEngine


def _make_block(index: int, prev_hash: str, block_hash: str) -> Block:
    return Block(
        index=index,
        prev_hash=prev_hash,
        transactions=[],
        miner_address="VSDminer1",
        difficulty=0.001,
        timestamp=1_700_000_000 + index,
        state_root="sr_" + block_hash[:8],
        block_hash=block_hash,
    )


def test_same_height_fork_winner_runs_bft_vote_relay_and_orphan_drain():
    """V4 regression: When accept_chain() replaces tip with a same-height winner,
    _handle_new_block runs BFT vote, relay, receipt publication, and orphan drain.
    """
    parent = _make_block(1, "0" * 64, "h_parent")
    tip_a = _make_block(2, "h_parent", "h_tip_a")
    winner_b = _make_block(2, "h_parent", "h_winner_b")

    canonical = {1: parent, 2: tip_a}

    storage = SimpleNamespace(
        get_block=lambda idx: canonical.get(idx),
        get_block_by_hash=lambda h: next((b for b in canonical.values() if b.block_hash == h), None),
        get_meta=lambda *_a: None,
        record_block_apply_result=MagicMock(),
    )

    def _accept_chain(_blocks):
        canonical[2] = winner_b
        return True, "Reorganized to better chain"

    blockchain = SimpleNamespace(
        height=lambda: 2,
        accept_chain=_accept_chain,
    )
    network = SimpleNamespace(
        peers={},
        publish_receipts_for_block=MagicMock(),
        broadcast_block=MagicMock(),
    )
    consensus = SimpleNamespace(validate_and_finalize=MagicMock())
    governance = SimpleNamespace(on_block_applied=MagicMock())

    engine = StateEngine.__new__(StateEngine)
    engine._storage = storage
    engine._blockchain = blockchain
    engine._network = network
    engine._governance = governance
    engine._node_ref = SimpleNamespace(consensus=consensus)
    engine._drain_orphans_for = MagicMock()
    engine._record_apply_outcome = MagicMock()

    ok, msg = engine._handle_new_block({"block": winner_b}, source_peer="peer_1")
    assert ok is True, msg
    governance.on_block_applied.assert_called_once_with(winner_b)
    consensus.validate_and_finalize.assert_called_once_with(winner_b)
    network.broadcast_block.assert_called_once()
    network.publish_receipts_for_block.assert_called_once_with(winner_b)
    engine._drain_orphans_for.assert_called_once_with(winner_b.block_hash, "peer_1")


def test_invalid_same_height_fork_block_returns_false():
    """V4 regression: An invalid same-height fork block rejected by accept_chain() returns ok=False."""
    parent = _make_block(1, "0" * 64, "h_parent")
    tip_a = _make_block(2, "h_parent", "h_tip_a")
    invalid_b = _make_block(2, "h_parent", "h_invalid_b")

    storage = SimpleNamespace(
        get_block=lambda idx: {1: parent, 2: tip_a}.get(idx),
        get_block_by_hash=lambda h: None,
        get_meta=lambda *_a: None,
        record_block_apply_result=MagicMock(),
    )
    blockchain = SimpleNamespace(
        height=lambda: 2,
        accept_chain=lambda _blocks: (False, "Block #2 validation failed: Invalid PoW"),
    )

    engine = StateEngine.__new__(StateEngine)
    engine._storage = storage
    engine._blockchain = blockchain
    engine._network = None
    engine._governance = SimpleNamespace(on_block_applied=MagicMock())
    engine._record_apply_outcome = MagicMock()

    ok, msg = engine._handle_new_block({"block": invalid_b}, source_peer="peer_bad")
    assert ok is False
    assert "Invalid PoW" in msg


def test_build_candidate_block_holds_lock_across_tip_snapshot_and_dry_run(monkeypatch):
    """V4 regression: Concurrent tip advance between tip snapshot and dry_run_state_root produces a consistent candidate."""
    monkeypatch.setattr(Config, "DIFF_MTP_WINDOW", 1)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 10**9)
    monkeypatch.setattr(Config, "MAX_BLOCK_SIZE", 1_000_000)

    tip_1 = _make_block(1, "0" * 64, "h1")
    tip_2 = _make_block(2, "h1", "h2")
    state = {"tip": tip_1}
    seen_tip_during_dry_run = []

    class _FakeMempool:
        def get_top(self, _n):
            state["tip"] = tip_2
            return []

    class _FakeBlockchain:
        def __init__(self):
            self._lock = threading.RLock()
            self.mempool = _FakeMempool()
            self.storage = SimpleNamespace(get_block=lambda i: tip_1 if i == 1 else tip_2)

        def latest_block(self):
            return state["tip"]

        def get_difficulty(self):
            return 0.001

        def get_dynamic_block_size(self):
            return 100_000

        def compute_reward(self, _h):
            return 10.0

        def _candidate_precheck(self, _txs, _h, _ts):
            return None

        def dry_run_state_root(self, **kwargs):
            seen_tip_during_dry_run.append(state["tip"].index)
            return "root_computed_against_tip_" + str(state["tip"].index)

    chain = _FakeBlockchain()
    ce = ConsensusEngine(chain, wallet=None)
    candidate = ce.build_candidate_block("VSDminer1")

    assert candidate.index == 2
    assert candidate.prev_hash == "h1"
    assert seen_tip_during_dry_run == [2]
    assert candidate.state_root == "root_computed_against_tip_2"
