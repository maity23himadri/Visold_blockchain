"""Regression tests for untrusted peer-height claims (2026-10-21)."""
from types import SimpleNamespace
import threading

from visold.mining.engine import _best_verified_peer_height
import visold.network.p2p as p2p
from visold.network.p2p import P2PNetwork


class _CanonicalBlock:
    def __init__(self, idx, block_hash):
        self.index = idx
        self.block_hash = block_hash


class _Storage:
    def __init__(self, blocks):
        self.blocks = blocks

    def get_block(self, idx):
        return self.blocks.get(idx)


def _bare_network():
    net = object.__new__(P2PNetwork)
    net.node_id = "local-node"
    net._PEX_PAGE_SIZE = 100
    net._lock = threading.RLock()
    net.peers = {}
    net.storage = _Storage({5: _CanonicalBlock(5, "canonical-5")})
    return net


def test_advertised_fake_height_does_not_enter_mining_safety():
    network = SimpleNamespace(peers={
        "attacker": SimpleNamespace(
            connected=True,
            chain_height=1_000_000_000,
            advertised_chain_height=1_000_000_000,
            verified_chain_height=-1,
        )
    })
    assert _best_verified_peer_height(network) == -1


def test_mining_safety_uses_verified_height_not_raw_advertisement():
    network = SimpleNamespace(peers={
        "peer-a": SimpleNamespace(connected=True, chain_height=9000,
                                  verified_chain_height=21),
        "peer-b": SimpleNamespace(connected=True, chain_height=999999,
                                  verified_chain_height=30),
        "peer-c": SimpleNamespace(connected=False, chain_height=1000000,
                                  verified_chain_height=999),
    })
    assert _best_verified_peer_height(network) == 30


def test_peer_verified_height_advances_only_for_a_canonical_hash_match():
    net = _bare_network()
    peer = SimpleNamespace(peer_id="peer-a", verified_chain_height=-1)
    net.peers["peer-a"] = peer

    # Invalid/non-canonical block index must not earn verified-height credit.
    assert net._mark_peer_height_verified("peer-a", [
        {"index": 5, "block_hash": "attacker-hash"},
        {"index": 1_000_000, "block_hash": "invented"},
    ]) == -1
    assert peer.verified_chain_height == -1

    # A block whose hash matches the local canonical database can advance it.
    assert net._mark_peer_height_verified("peer-a", [
        {"index": 5, "block_hash": "canonical-5"},
    ]) == 5
    assert peer.verified_chain_height == 5
    assert peer.verified_chain_hash == "canonical-5"

    # A reorg replacing that height invalidates the formerly valid evidence.
    net.storage.blocks[5] = _CanonicalBlock(5, "replacement-5")
    assert net._current_verified_peer_height(peer) == -1
    assert peer.verified_chain_height == -1


def test_pex_does_not_relay_a_peer_advertised_height():
    net = _bare_network()
    net.get_network_directory = lambda: [{
        "peer_id": "peer-c", "ip": "192.0.2.4", "port": 8338,
        "user_id": "", "registered_name": "", "wallet_addr": "",
        "chain_height": 1_000_000_000,
        "verified_chain_height": -1,
        "seed_node": False,
    }]
    page, total, next_cursor = net._network_directory_page()
    assert total == 1 and next_cursor is None
    assert page[0]["peer_id"] == "peer-c"
    assert page[0]["chain_height"] == -1


class _SeenCache:
    def get(self, _key):
        return False

    def put(self, *_args, **_kwargs):
        return None


def test_inbound_msg_block_does_not_raise_peer_height_before_validation():
    net = _bare_network()
    net._check_msg_rate = lambda *_args, **_kwargs: True
    net._seen_msgs = _SeenCache()
    net._state_engine = SimpleNamespace(
        post=lambda *_args, **_kwargs: False)  # simulate rejected queue/post
    net._untrusted_rate_lock = threading.Lock()
    net._untrusted_rate = {}
    net._soft_ban_record_failure = lambda *_args, **_kwargs: None
    net._callbacks = {}
    peer = SimpleNamespace(
        peer_id="peer-c", connected=True, last_seen=0.0,
        chain_height=500, advertised_chain_height=500,
        verified_chain_height=-1, trust_level=p2p.PeerConnection.TRUST_HIGH,
    )
    net.peers[peer.peer_id] = peer

    net._handle_message(peer, {
        "type": p2p.MSG_BLOCK,
        "block": {"index": 1_000_000, "block_hash": "fake-hash"},
    })

    assert peer.chain_height == 500
    assert peer.advertised_chain_height == 500
    assert peer.verified_chain_height == -1
