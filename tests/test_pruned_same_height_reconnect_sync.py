"""Regression tests for same-height reconnects between rolling-pruned peers."""
from __future__ import annotations

import threading
from types import SimpleNamespace

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork


class _FakeBlock:
    def __init__(self, height: int, *, pruned: bool = False, block_hash: str | None = None):
        self.index = height
        self.is_pruned = pruned
        self.block_hash = block_hash or f"hash-{height}"

    def to_dict(self):
        return {"index": self.index, "pruned": self.is_pruned,
                "block_hash": self.block_hash, "transactions": [] if self.is_pruned else [{}]}


class _FakeStorage:
    def __init__(self, watermark: str = "0"):
        self.watermark = watermark

    def get_meta(self, key: str):
        return self.watermark if key == "rolling_pruned_until" else None


class _FakeChain:
    def __init__(self, height: int, prune_before: int | None = None):
        self._height = height
        self._prune_before = prune_before

    def height(self):
        return self._height

    def get_block(self, height: int):
        if height < 0 or height > self._height:
            return None
        return _FakeBlock(height, pruned=(self._prune_before is not None and height < self._prune_before))


def _network(height: int, prune_before: int | None, watermark: str):
    net = P2PNetwork.__new__(P2PNetwork)
    net.blockchain = _FakeChain(height, prune_before)
    net.storage = _FakeStorage(watermark)
    return net


def test_pruned_same_height_autosync_starts_near_tip_not_genesis(monkeypatch):
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 600)
    net = _network(725, prune_before=125, watermark="125")

    assert net._has_pruned_local_history() is True
    start = net._auto_sync_request_start(725, 725)

    # 199 retained-overlap blocks, followed by the next block in a 200-block page.
    assert start == 527
    assert start > 199
    assert net.blockchain.get_block(start).is_pruned is False


def test_pruned_sync_start_respects_small_retention_window(monkeypatch):
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 9)
    net = _network(25, prune_before=16, watermark="16")

    start = net._auto_sync_request_start(25, 25)

    # With a 9-block retention window, blocks from 16 onward have bodies;
    # overlap begins at 17 and the request never asks for old pruned bodies.
    assert start == 17
    assert all(not net.blockchain.get_block(h).is_pruned
               for h in range(start, 26))


def test_archival_node_keeps_genesis_fork_check_and_progress_requests_next(monkeypatch):
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 600)
    net = _network(725, prune_before=None, watermark="0")

    assert net._auto_sync_request_start(725, 725) == 0
    assert net._auto_sync_request_start(726, 725) == 727


def test_recent_overlap_that_matches_canonical_hashes_is_idempotent_success():
    # Exercise the exact early-return branch without invoking unrelated PoW/state
    # validation. A matching pruned header is safe to compare by its block hash.
    # Simulate an authenticated-snapshot node whose older history is
    # header-only through height 599, while the recent tip remains full.
    local = {h: _FakeBlock(h, pruned=(h < 600)) for h in range(726)}
    fake_chain = SimpleNamespace(
        _lock=threading.RLock(),
        height=lambda: 725,
        storage=SimpleNamespace(get_block=lambda h: local.get(h)),
    )
    incoming = [
        _FakeBlock(h, pruned=local[h].is_pruned, block_hash=local[h].block_hash)
        for h in range(527, 726)
    ]

    ok, reason = Blockchain.accept_chain(fake_chain, incoming)

    assert ok is True
    assert reason == "Already have all these blocks"


def test_recent_overlap_hash_mismatch_is_not_treated_as_duplicate_success():
    local = {h: _FakeBlock(h, pruned=False) for h in range(726)}
    fake_chain = SimpleNamespace(
        _lock=threading.RLock(),
        height=lambda: 725,
        storage=SimpleNamespace(get_block=lambda h: local.get(h)),
    )
    incoming = [
        _FakeBlock(
            h,
            pruned=True,
            block_hash=("different-tip-hash" if h == 725 else local[h].block_hash),
        )
        for h in range(527, 726)
    ]

    ok, reason = Blockchain.accept_chain(fake_chain, incoming)

    assert ok is False
    assert reason != "Already have all these blocks"
