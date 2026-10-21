"""Regression tests for compact-block gossip loops in full-mesh P2P networks."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import threading
import time

import visold.network.p2p as p2p
from visold.network.p2p import P2PNetwork
from visold.kernel.lru_cache import LRUCache


class _Heap:
    def get_all_live(self):
        return []


class _FakeBlockType:
    @staticmethod
    def from_dict(data):
        return SimpleNamespace(
            merkle_root=data.get("merkle_root", "merkle-test"),
            index=int(data.get("index", 1)),
            miner_address=str(data.get("miner_address", "miner-test")),
            block_hash=str(data.get("block_hash", "block-test")),
        )


def _bare_network(post_delay=0.0):
    net = object.__new__(P2PNetwork)
    net._check_msg_rate = lambda *_args, **_kwargs: True
    net._seen_msgs = LRUCache(128, ttl=3600)
    net._block_gossip_lock = threading.Lock()
    net._block_gossip_inflight = set()
    net._compact_stash_lock = threading.RLock()
    net._compact_stash = {}
    net._callbacks = {}
    net.blockchain = SimpleNamespace(
        mempool=SimpleNamespace(_heap=_Heap())
    )
    calls = []

    def post(evt, timeout=None):
        calls.append(evt)
        if post_delay:
            time.sleep(post_delay)
        return True

    net._state_engine = SimpleNamespace(post=post)
    peer = SimpleNamespace(
        peer_id="peer-source",
        last_seen=0.0,
        trust_level=p2p.PeerConnection.TRUST_HIGH,
        connected=True,
    )
    return net, peer, calls


def _compact_msg(block_hash="block-test"):
    return {
        "type": p2p.MSG_CMPCTBLOCK,
        "header": {
            "block_hash": block_hash,
            "index": 1,
            "merkle_root": "merkle-test",
            "miner_address": "miner-test",
        },
        "coinbase": {"sender": "COINBASE", "tx_id": "coinbase-test"},
        "short_ids": [],
        "ttl": 8,
    }


def test_compact_block_duplicate_is_posted_only_once(monkeypatch):
    monkeypatch.setattr(p2p, "Block", _FakeBlockType)
    net, peer, calls = _bare_network()
    message = _compact_msg("same-block-hash")

    net._handle_message(peer, message)
    # Same canonical block arriving via another mesh edge must be ignored.
    net._handle_message(peer, message)

    assert len(calls) == 1
    assert net._seen_msgs.get(("BLOCK", "same-block-hash")) is True
    assert not net._block_gossip_inflight


def test_simultaneous_compact_copies_claim_and_post_once(monkeypatch):
    monkeypatch.setattr(p2p, "Block", _FakeBlockType)
    net, peer, calls = _bare_network(post_delay=0.05)
    message = _compact_msg("concurrent-block-hash")
    start = threading.Barrier(8)

    def deliver(_i):
        start.wait(timeout=2)
        net._handle_message(peer, message)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(deliver, i) for i in range(8)]
        for future in futures:
            future.result(timeout=5)

    assert len(calls) == 1
    assert net._seen_msgs.get(("BLOCK", "concurrent-block-hash")) is True
    assert not net._block_gossip_inflight


def test_failed_state_engine_post_releases_claim_for_retry(monkeypatch):
    monkeypatch.setattr(p2p, "Block", _FakeBlockType)
    net, peer, calls = _bare_network()
    attempts = {"n": 0}

    def post(evt, timeout=None):
        attempts["n"] += 1
        calls.append(evt)
        return attempts["n"] > 1

    net._state_engine = SimpleNamespace(post=post)
    message = _compact_msg("retryable-block-hash")

    net._handle_message(peer, message)
    assert not net._seen_msgs.get(("BLOCK", "retryable-block-hash"))
    assert not net._block_gossip_inflight

    net._handle_message(peer, message)
    assert len(calls) == 2
    assert net._seen_msgs.get(("BLOCK", "retryable-block-hash")) is True
    assert not net._block_gossip_inflight


def test_atomic_claim_has_only_one_winner():
    net, _peer, _calls = _bare_network()
    start = threading.Barrier(16)

    def claim(_i):
        start.wait(timeout=2)
        return net._claim_block_gossip("atomic-claim-hash")

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = [f.result(timeout=5) for f in
                    [pool.submit(claim, i) for i in range(16)]]

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 15
    net._finish_block_gossip("atomic-claim-hash", False)
    assert not net._block_gossip_inflight
    assert not net._seen_msgs.get(("BLOCK", "atomic-claim-hash"))


def test_origin_drops_its_own_block_when_it_returns_through_mesh():
    net, peer, calls = _bare_network()
    outbound = []

    class _LocalBlock:
        block_hash = "originated-block-hash"

        def to_dict(self):
            return {
                "block_hash": self.block_hash,
                "index": 1,
                "merkle_root": "merkle-test",
                "miner_address": "miner-test",
                "transactions": [{"sender": "COINBASE", "tx_id": "coinbase-test"}],
            }

    net._gossip = lambda msg, exclude=None: outbound.append((msg, exclude))
    net.broadcast_block(_LocalBlock())

    assert len(outbound) == 1
    sent_msg, _exclude = outbound[0]
    assert net._seen_msgs.get(("BLOCK", "originated-block-hash")) is True

    # A duplicate of our own block coming back from a neighbour is dropped
    # before it can be queued or relayed again.
    net._handle_message(peer, sent_msg)
    assert calls == []
