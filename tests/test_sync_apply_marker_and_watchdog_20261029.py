"""Regression tests for SYNC-1 and SYNC-2 (chain-sync batch markers and watchdog).

SYNC-1: a rejected chain-sync batch must not overwrite block_apply:<h> = "ok"
for canonical heights it merely overlaps, and a batch refused by accept_chain's
header-only preflight must not record failures for heights that were never
applied. A genuinely invalid new block must still be recorded as "fail".

SYNC-2: a prompt reply (accepted or rejected) to a pagination request must not
be treated as a silent zombie peer by the sync watchdog.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork
from visold.state.engine import StateEngine


# ── SYNC-1 helpers ────────────────────────────────────────────────────────────

class _Storage:
    """Minimal stand-in covering the storage calls used by the batch path."""

    def __init__(self, blocks=None):
        self.blocks = dict(blocks or {})  # height -> canonical block hash
        self.meta = {}

    def get_block_hash(self, idx):
        return self.blocks.get(idx)

    def get_block(self, idx):
        h = self.blocks.get(idx)
        return None if h is None else SimpleNamespace(index=idx, block_hash=h)

    def get_meta(self, key, default=None):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value

    def record_block_apply_result(self, height, success):
        self.set_meta(f"block_apply:{height}", "ok" if success else "fail")

    def apply_markers(self):
        return {k: v for k, v in self.meta.items() if k.startswith("block_apply:")}


def _blk(index, block_hash, pruned=False):
    return SimpleNamespace(index=index, block_hash=block_hash, is_pruned=pruned)


def _engine(storage, accept_result):
    eng = SimpleNamespace(
        _storage=storage,
        _blockchain=SimpleNamespace(accept_chain=lambda blocks: accept_result),
        _governance=SimpleNamespace(on_block_applied=lambda b: None),
        _network=None,
        _node_ref=None,
        _merge_incoming_validator_sigs=lambda blocks, peer: None,
        _drain_pending_validator_sigs=lambda: None,
        _rebroadcast_block_validator_sigs=lambda b, p: None,
    )
    eng._record_apply_outcome = lambda block, ok: StateEngine._record_apply_outcome(
        eng, block, ok)
    return eng


def _run_batch(storage, accept_result, blocks):
    eng = _engine(storage, accept_result)
    ok, msg = StateEngine._handle_chain_sync(eng, {"blocks": blocks}, "peer-x")
    # Guard against a silent exception path masking the result under test.
    assert "chain_sync error" not in str(msg), msg
    return ok, msg


def test_rejected_overlap_batch_keeps_canonical_ok_markers():
    storage = _Storage({h: f"a{h}" for h in range(1, 6)})
    for h in range(1, 6):
        storage.record_block_apply_result(h, True)
    blocks = [_blk(h, f"a{h}") for h in range(1, 6)]

    ok, _ = _run_batch(storage, (False, "Deep fork rejected: lighter fork"), blocks)

    assert ok is False
    assert storage.apply_markers() == {f"block_apply:{h}": "ok" for h in range(1, 6)}


def test_rejected_batch_still_records_failure_for_invalid_new_block():
    storage = _Storage({1: "a1"})
    storage.record_block_apply_result(1, True)
    blocks = [_blk(1, "a1"), _blk(2, "b2")]

    ok, _ = _run_batch(storage, (False, "Block 2: invalid signature"), blocks)

    assert ok is False
    assert storage.get_meta("block_apply:1") == "ok"
    assert storage.get_meta("block_apply:2") == "fail"


def test_header_only_preflight_refusal_records_no_apply_outcome():
    storage = _Storage({})
    blocks = [_blk(1, "x1"), _blk(2, "x2"), _blk(3, "x3", pruned=True)]

    ok, _ = _run_batch(
        storage,
        (False, "Block 3 is pruned/header-only; sync needs an authenticated "
                "bootstrap snapshot or the full block body"),
        blocks)

    assert ok is False
    assert storage.apply_markers() == {}


def test_accepted_batch_records_ok_for_every_height():
    storage = _Storage({})
    blocks = [_blk(1, "x1"), _blk(2, "x2")]

    ok, _ = _run_batch(storage, (True, "OK"), blocks)

    assert ok is True
    assert storage.apply_markers() == {"block_apply:1": "ok", "block_apply:2": "ok"}


# ── SYNC-2 helpers ────────────────────────────────────────────────────────────

class _Peer:
    def __init__(self, peer_id="peer-watchdog-0001"):
        self.peer_id = peer_id
        self.connected = True
        self._sync_state_lock = threading.RLock()
        self._sync_pending = None
        self._pagination_active = threading.Event()
        self._sync_last_reject_at = 0.0
        self.closed = threading.Event()

    def close(self):
        self.closed.set()


class _WatchdogNet:
    """Real P2PNetwork response handling, with request IDs and storage stubbed."""

    def __init__(self, peer, height):
        self._h = height
        self._lock = threading.RLock()
        self._seq = 0
        self.peers = {peer.peer_id: peer}
        self.bans = []
        self.blockchain = SimpleNamespace(height=lambda: self._h)
        self.storage = SimpleNamespace(
            add_ban_score=lambda pid, pts: self.bans.append((pid, pts)))

    def _sync_request(self, peer, from_idx, to_idx, *, kind="heartbeat", force=False):
        self._seq += 1
        rid = f"req-{self._seq}"
        with peer._sync_state_lock:
            peer._sync_pending = {
                "id": rid, "from_idx": from_idx, "to_idx": to_idx,
                "kind": kind, "sent_at": time.monotonic(), "status": "waiting",
            }
        return rid

    def _sync_finish(self, peer, request_id):
        return P2PNetwork._sync_finish(self, peer, request_id)

    def _mark_peer_height_verified(self, peer_id, blocks):
        return None

    def _on_chain_sync_result(self, *args, **kwargs):
        return P2PNetwork._on_chain_sync_result(self, *args, **kwargs)


def _start_pagination(net, peer):
    """Answer an initial page with more to come, so a next-page watchdog starts."""
    prev = net._sync_request(peer, 0, 199, kind="auto-sync")
    net._on_chain_sync_result(peer, [], True, "OK", True, 5, prev)
    next_rid = peer._sync_pending["id"]
    assert next_rid != prev
    return next_rid


def test_prompt_rejection_of_next_page_is_not_treated_as_zombie(monkeypatch):
    monkeypatch.setattr(Config, "CHAIN_SYNC_TIMEOUT_SECS", 0.1)
    peer = _Peer()
    net = _WatchdogNet(peer, height=4)

    next_rid = _start_pagination(net, peer)
    # The peer answers the next-page request promptly with a rejection.
    net._on_chain_sync_result(peer, [], False, "Block 5: invalid", False, 0, next_rid)

    time.sleep(0.6)  # well past the watchdog timeout
    assert not peer.closed.is_set()
    assert net.bans == []


def test_silent_next_page_still_closes_zombie_peer(monkeypatch):
    monkeypatch.setattr(Config, "CHAIN_SYNC_TIMEOUT_SECS", 0.1)
    peer = _Peer()
    net = _WatchdogNet(peer, height=4)

    _start_pagination(net, peer)  # no reply at all

    assert peer.closed.wait(2.0)
    assert net.bans == [(peer.peer_id, Config.PEER_SCORE_SYNC_TIMEOUT)]
