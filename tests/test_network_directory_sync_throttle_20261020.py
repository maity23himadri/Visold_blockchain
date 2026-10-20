from collections import deque
import threading
from types import SimpleNamespace

import pytest

from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork


class _FakeStorage:
    def __init__(self, claims=None, peers=None):
        self.claims = claims or {}
        self.peers = peers or []

    def resolve_name_claim(self, name):
        return self.claims.get(str(name).casefold())

    def get_peers(self, limit=1000):
        return list(self.peers[:limit])


class _FakeRouter:
    def __init__(self, peers=None):
        self.peers = peers or []

    def all_peers(self):
        return list(self.peers)


class _FakeChain:
    def __init__(self, height):
        self._height = height

    def height(self):
        return self._height


def _network(monkeypatch, *, seed=False, height=0, router_peers=None, stored_peers=None, claims=None):
    monkeypatch.setattr(Config, "SEED_NODE_MODE", seed, raising=False)
    net = object.__new__(P2PNetwork)
    net.node_id = "node-a"
    net.blockchain = _FakeChain(height)
    net.storage = _FakeStorage(claims=claims, peers=stored_peers)
    net.router = _FakeRouter(router_peers)
    net.peers = {}
    net._lock = threading.RLock()
    net._node_directory = {}
    net._node_directory_lock = threading.RLock()
    net._node_directory_max = 5000
    net._node_directory_ttl_secs = 30 * 24 * 60 * 60
    net._node_directory_claim_cache = {}
    net._node_directory_storage_refresh_at = 0.0
    net._pex_dial_lock = threading.Lock()
    net._pex_dial_times = deque()
    net._pex_seed_dials_per_minute = 12
    net._pending_connections = set()
    net._pending_lock = threading.Lock()
    net._auto_sync_gate = threading.Lock()
    net._sync_heartbeat_cursor = 0
    net._sync_heartbeat_round = 0
    return net


def test_directory_keeps_endpoint_identity_and_only_marks_canonical_name(monkeypatch):
    claims = {"alice": {"user_id": "alice", "wallet_addr": "VSD-ALICE"}}
    net = _network(monkeypatch, claims=claims)
    record = {
        "peer_id": "peer-alice", "ip": "2001:db8::1", "port": 8338,
        "user_id": "alice", "wallet_addr": "VSD-ALICE", "chain_height": 71,
    }
    net._remember_node_info(record, verified=False, source="pex")
    rows = net.get_network_directory(refresh_sources=False)
    assert len(rows) == 1
    assert rows[0]["ip"] == "2001:db8::1"
    assert rows[0]["port"] == 8338
    assert rows[0]["registered_name"] == "alice"
    assert rows[0]["wallet_addr"] == "VSD-ALICE"
    assert rows[0]["status"] == "DISCOVERED"

    # A spoofed name with a different wallet must remain an advertised user ID.
    net._remember_node_info({**record, "ip": "192.0.2.22", "wallet_addr": "VSD-OTHER"},
                            verified=False, source="pex")
    rows2 = [r for r in net.get_network_directory(refresh_sources=False)
             if r["peer_id"] == "peer-alice"]
    assert rows2[0]["registered_name"] == ""


def test_verified_endpoint_is_not_overwritten_by_unverified_pex(monkeypatch):
    net = _network(monkeypatch)
    net._remember_node_info({
        "peer_id": "peer-1", "ip": "192.0.2.10", "port": 8338,
        "user_id": "first", "wallet_addr": "VSD1", "chain_height": 4,
    }, verified=True)
    net._remember_node_info({
        "peer_id": "peer-1", "ip": "192.0.2.99", "port": 9999,
        "user_id": "spoofed", "wallet_addr": "VSD-other", "chain_height": 1000,
    }, verified=False, source="pex")
    row = net.get_network_directory(refresh_sources=False)[0]
    assert row["ip"] == "192.0.2.10"
    assert row["port"] == 8338
    assert row["user_id"] == "first"
    assert row["wallet_addr"] == "VSD1"
    assert row["verified"] is True


def test_directory_pagination_is_stable_and_excludes_requester(monkeypatch):
    net = _network(monkeypatch)
    for idx in range(4):
        net._remember_node_info({
            "peer_id": f"peer-{idx}", "ip": f"192.0.2.{idx + 1}",
            "port": 8338 + idx, "user_id": f"user{idx}",
            "wallet_addr": f"VSD{idx}", "chain_height": idx,
        })
    page1, total1, next1 = net._network_directory_page(0, 2, exclude_peer_id="peer-3")
    page2, total2, next2 = net._network_directory_page(next1, 2, exclude_peer_id="peer-3")
    assert total1 == total2 == 3
    assert len(page1) == 2 and len(page2) == 1
    assert next1 == 2 and next2 is None
    assert {x["peer_id"] for x in page1 + page2} == {"peer-0", "peer-1", "peer-2"}
    assert all("ip" in item and "port" in item and "wallet_addr" in item for item in page1 + page2)


def test_directory_rejects_invalid_endpoint(monkeypatch):
    net = _network(monkeypatch)
    assert net._remember_node_info({"peer_id": "bad", "ip": "0.0.0.0", "port": 8338}) is None
    assert net._remember_node_info({"peer_id": "bad2", "ip": "192.0.2.1", "port": 99999}) is None
    assert net.get_network_directory(refresh_sources=False) == []


def test_seed_auto_dials_are_rate_bounded_but_incoming_peers_are_not_count_limited(monkeypatch):
    net = _network(monkeypatch, seed=True)
    assert all(net._allow_pex_auto_dial() for _ in range(12))
    assert net._allow_pex_auto_dial() is False
    assert len(net._pex_dial_times) == 12
    assert net._peer_capacity_limit() is None
    assert net._peer_subnet_limit() is None


def test_initial_sync_is_one_sided_and_seed_does_not_sync_each_lower_peer(monkeypatch):
    ordinary = _network(monkeypatch, seed=False, height=4)
    assert ordinary._should_auto_sync_peer(SimpleNamespace(peer_id="node-z", chain_height=9))
    assert not ordinary._should_auto_sync_peer(SimpleNamespace(peer_id="node-z", chain_height=3))
    assert ordinary._should_auto_sync_peer(SimpleNamespace(peer_id="node-z", chain_height=4))

    other_side = _network(monkeypatch, seed=False, height=9)
    assert not other_side._should_auto_sync_peer(SimpleNamespace(peer_id="node-a", chain_height=4))

    seed = _network(monkeypatch, seed=True, height=20)
    assert not seed._should_auto_sync_peer(SimpleNamespace(peer_id="node-b", chain_height=20))
    assert not seed._should_auto_sync_peer(SimpleNamespace(peer_id="node-b", chain_height=10))
    assert seed._should_auto_sync_peer(SimpleNamespace(peer_id="node-b", chain_height=21))


def test_account_user_id_suffix_resolves_bare_registered_name_only_for_matching_wallet(monkeypatch):
    claims = {"himadri": {"user_id": "himadri", "wallet_addr": "VSD-HIMADRI"}}
    net = _network(monkeypatch, claims=claims)
    net._remember_node_info({
        "peer_id": "peer-himadri", "ip": "192.0.2.77", "port": 8338,
        "user_id": "himadri#4009e90aa9", "wallet_addr": "VSD-HIMADRI",
    }, verified=False, source="pex")
    row = net.get_network_directory(refresh_sources=False)[0]
    assert row["registered_name"] == "himadri"

    net2 = _network(monkeypatch, claims=claims)
    net2._remember_node_info({
        "peer_id": "peer-impostor", "ip": "192.0.2.78", "port": 8338,
        "user_id": "himadri#4009e90aa9", "wallet_addr": "VSD-OTHER",
    }, verified=False, source="pex")
    row2 = net2.get_network_directory(refresh_sources=False)[0]
    assert row2["registered_name"] == ""


def test_same_tip_skips_expensive_initial_chain_replay_but_different_tip_syncs(monkeypatch):
    ordinary = _network(monkeypatch, seed=False, height=90)
    same_hash = "a" * 64
    ordinary._local_chain_tip_hash = lambda: same_hash
    assert not ordinary._should_auto_sync_peer(SimpleNamespace(
        peer_id="seed-1", chain_height=90, chain_tip_hash=same_hash,
        is_seed_node=True))
    assert ordinary._should_auto_sync_peer(SimpleNamespace(
        peer_id="seed-1", chain_height=90, chain_tip_hash="b" * 64,
        is_seed_node=True))

    seed = _network(monkeypatch, seed=True, height=90)
    seed._local_chain_tip_hash = lambda: same_hash
    assert not seed._should_auto_sync_peer(SimpleNamespace(
        peer_id="client-1", chain_height=90, chain_tip_hash=same_hash))
    # Seed does not start reverse sync against equal/lower clients even if a
    # remote advertises a different tip; the designated sync requester decides.
    assert not seed._should_auto_sync_peer(SimpleNamespace(
        peer_id="client-1", chain_height=90, chain_tip_hash="b" * 64))
