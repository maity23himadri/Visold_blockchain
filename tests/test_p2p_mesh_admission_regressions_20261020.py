"""Regressions for multi-node peer admission and false CONNECTED states."""

from __future__ import annotations

import threading

import visold.network.p2p as p2p
from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork


class _FakePeer:
    def __init__(self, ip="2401:4900:b7cc:1000::1", port=8338,
                 connected=True, local_outbound=None):
        self.peer_id = "fake-peer"
        self.ip = ip
        self.port = port
        self.connected = connected
        self.local_outbound = local_outbound
        self.messages = []
        self.closed = False

    def send(self, message):
        if self.closed or not self.connected:
            return False
        self.messages.append(message)
        return True

    def close(self):
        self.closed = True
        self.connected = False


def _network(node_id="zz-local"):
    net = object.__new__(P2PNetwork)
    net.node_id = node_id
    net._lock = threading.RLock()
    net._peer_admission_reservations = {}
    net.peers = {}
    net._eager_peers = set()
    return net


def test_six_nodes_in_same_mobile_ipv6_48_can_join_after_three_are_connected(monkeypatch):
    """The peer target must not become a hard cap for a carrier IPv6 /48."""
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    net = _network(node_id="zz-seed")
    # Reproduce the reported state: the seed already has three stable peers
    # from one carrier /48 when node 6 attempts to join.
    for index in range(1, 4):
        net.peers[f"node-{index}"] = _FakePeer(
            ip=f"2401:4900:b7cc:1000::{index}",
            port=8338 + index, local_outbound=False)
    tokens = []
    for index in range(4, 7):
        token = net._reserve_peer_admission(
            f"node-{index}", f"2401:4900:b7cc:1000::{index}",
            local_outbound=False)
        assert token is not None, f"node {index} refused despite room in the mesh"
        tokens.append(token)
    assert len(net._peer_admission_reservations) == 3
    for token in tokens:
        net._release_peer_admission(token)


def test_subnet_diversity_limit_is_not_three(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    net = _network()
    assert net._peer_subnet_limit() >= 6
    assert net._peer_subnet("2401:4900:b7cc:1000::1") == net._peer_subnet(
        "2401:4900:b7cc:ffff::99")
    assert net._peer_subnet("2401:4900:b7cc:1000::1") != net._peer_subnet(
        "2401:4900:bcd0:1000::1")


def test_subnet_cap_still_bounds_one_ipv6_48(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    net = _network(node_id="zz-seed")
    tokens = []
    limit = net._peer_subnet_limit()
    assert limit == 8
    for index in range(1, limit + 1):
        token = net._reserve_peer_admission(
            f"node-{index}", f"2401:4900:b7cc:1000::{index}",
            local_outbound=False)
        assert token is not None
        tokens.append(token)
    assert net._reserve_peer_admission(
        "node-over-limit", "2401:4900:b7cc:1000::99",
        local_outbound=False) is None
    for token in tokens:
        net._release_peer_admission(token)


def test_duplicate_inflight_handshake_same_direction_is_rejected(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    net = _network(node_id="a-local")
    first = net._reserve_peer_admission("b-peer", "192.0.2.2", local_outbound=True)
    assert first is not None
    duplicate = net._reserve_peer_admission("b-peer", "192.0.2.2", local_outbound=True)
    assert duplicate is None


def test_preferred_handshake_prevents_noncanonical_accept(monkeypatch):
    """The higher-ID node's outbound socket is noncanonical when lower ID dials."""
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    # At node-a, the canonical session is outbound (a < b).
    net = _network(node_id="a-local")
    noncanonical = net._reserve_peer_admission(
        "b-peer", "192.0.2.2", local_outbound=False)
    assert noncanonical is not None
    canonical = net._reserve_peer_admission(
        "b-peer", "192.0.2.2", local_outbound=True)
    assert canonical is not None

    loser = _FakePeer()
    winner = _FakePeer()
    accept = {"type": p2p.MSG_ACCEPT, "node_id": net.node_id}
    assert net._send_accept_if_admitted(noncanonical, "b-peer", loser, accept) is False
    assert loser.messages == []
    assert net._send_accept_if_admitted(canonical, "b-peer", winner, accept) is True
    assert len(winner.messages) == 1


def test_accept_reservation_blocks_new_duplicate_until_registration_cleanup(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    net = _network(node_id="zz-local")
    token = net._reserve_peer_admission("peer-a", "192.0.2.10", local_outbound=False)
    assert token is not None
    assert net._send_accept_if_admitted(
        token, "peer-a", _FakePeer(), {"type": p2p.MSG_ACCEPT}) is True
    # While ACCEPT is in flight, another session must not steal the token's slot.
    assert net._reserve_peer_admission(
        "peer-a", "192.0.2.10", local_outbound=False) is None
    net._release_peer_admission(token)
    assert net._reserve_peer_admission(
        "peer-a", "192.0.2.10", local_outbound=False) is not None


def test_client_side_acceptance_reservation_blocks_a_late_inbound_duplicate(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    net = _network(node_id="zz-local")
    token = net._reserve_peer_admission(
        "peer-a", "192.0.2.10", local_outbound=False)
    assert token is not None
    assert net._mark_peer_admission_accepted(token, "peer-a") is True
    # Simulates the remote ACCEPT being received by an outbound handshake:
    # another inbound connection cannot steal this slot before registration.
    assert net._reserve_peer_admission(
        "peer-a", "192.0.2.10", local_outbound=False) is None
    net._release_peer_admission(token)


def test_an_accepted_connection_suppresses_a_second_already_reserved_accept(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    net = _network(node_id="a-local")
    noncanonical = net._reserve_peer_admission(
        "b-peer", "192.0.2.10", local_outbound=False)
    canonical = net._reserve_peer_admission(
        "b-peer", "192.0.2.10", local_outbound=True)
    assert noncanonical is not None and canonical is not None
    assert net._mark_peer_admission_accepted(noncanonical, "b-peer") is True
    assert net._send_accept_if_admitted(
        canonical, "b-peer", _FakePeer(), {"type": p2p.MSG_ACCEPT}) is False


def test_capacity_counts_inflight_reservations(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 4)
    net = _network(node_id="zz-local")
    tokens = []
    for index in range(1, 5):
        token = net._reserve_peer_admission(
            f"peer-{index}", f"192.0.{index}.5", local_outbound=False)
        assert token is not None
        tokens.append(token)
    assert net._reserve_peer_admission(
        "peer-5", "192.0.5.5", local_outbound=False) is None
    for token in tokens:
        net._release_peer_admission(token)


def test_failed_admission_never_sends_accept(monkeypatch):
    net = _network()
    peer = _FakePeer()
    assert net._send_accept_if_admitted(
        None, "peer-a", peer, {"type": p2p.MSG_ACCEPT}) is False
    assert peer.messages == []

class _NullRouter:
    def update(self, *args, **kwargs):
        return None


class _NullStorage:
    def save_peer(self, *args, **kwargs):
        return None


class _NoStartThread:
    """Keep _register_peer's background auto-sync worker dormant in unit tests."""
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def start(self):
        return None


def _attach_registration_dependencies(net):
    net.router = _NullRouter()
    net.storage = _NullStorage()


def test_registered_peer_is_kept_after_accept_with_three_same_subnet_peers(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    monkeypatch.setattr(p2p.threading, "Thread", _NoStartThread)
    monkeypatch.setattr(p2p, "_push_peer_notif", lambda *args, **kwargs: None)
    net = _network(node_id="zz-seed")
    _attach_registration_dependencies(net)
    for index in range(1, 4):
        peer = _FakePeer(ip=f"2401:4900:b7cc:1000::{index}",
                         port=8338 + index, local_outbound=False)
        peer.peer_id = f"node-{index}"
        net.peers[peer.peer_id] = peer
    token = net._reserve_peer_admission(
        "node-4", "2401:4900:b7cc:1000::4", local_outbound=False)
    assert token is not None
    new_peer = _FakePeer(ip="2401:4900:b7cc:1000::4", port=8342,
                         local_outbound=False)
    new_peer.peer_id = "node-4"
    assert net._send_accept_if_admitted(
        token, "node-4", new_peer, {"type": p2p.MSG_ACCEPT}) is True
    net._register_peer(new_peer, "node-4", "pub", "user",
                       admission_token=token, local_outbound=False)
    assert net.peers.get("node-4") is new_peer
    assert new_peer.connected is True


def test_canonical_duplicate_replaces_active_noncanonical_peer(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    monkeypatch.setattr(p2p.threading, "Thread", _NoStartThread)
    monkeypatch.setattr(p2p, "_push_peer_notif", lambda *args, **kwargs: None)
    net = _network(node_id="a-local")
    _attach_registration_dependencies(net)
    old = _FakePeer(ip="192.0.2.20", port=8338, local_outbound=False)
    old.peer_id = "b-peer"
    net.peers["b-peer"] = old
    token = net._reserve_peer_admission("b-peer", "192.0.2.20", local_outbound=True)
    assert token is not None
    new_peer = _FakePeer(ip="192.0.2.20", port=8338, local_outbound=True)
    new_peer.peer_id = "b-peer"
    assert net._send_accept_if_admitted(
        token, "b-peer", new_peer, {"type": p2p.MSG_ACCEPT}) is True
    net._register_peer(new_peer, "b-peer", "pub", "user",
                       admission_token=token, local_outbound=True)
    assert net.peers.get("b-peer") is new_peer
    assert new_peer.connected is True
    assert old.connected is False


def test_seed_has_unbounded_minimum_target_but_ordinary_target_stays_three(monkeypatch):
    """Only the explicit seed has an unbounded discovery target and peer cap."""
    monkeypatch.setattr(Config, "MIN_PEERS", 3)
    monkeypatch.setattr(Config, "SEED_MIN_PEERS", None)
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    monkeypatch.setattr(Config, "SEED_NODE_MODE", False)
    ordinary = _network(node_id="ordinary-node")
    assert ordinary.minimum_peer_target() == 3
    assert ordinary._below_minimum_peer_target(0) is True
    assert ordinary._below_minimum_peer_target(3) is False
    assert ordinary._peer_capacity_limit() == 30

    monkeypatch.setattr(Config, "SEED_NODE_MODE", True)
    seed = _network(node_id="designated-seed")
    assert seed.minimum_peer_target() is None
    assert seed._below_minimum_peer_target(0) is True
    assert seed._below_minimum_peer_target(30) is True
    assert seed._below_minimum_peer_target(300000) is True
    assert seed._minimum_peer_target_met(300000) is False
    assert seed._peer_capacity_limit() is None
    assert Config.MAX_PEERS == 30  # global/default cap remains finite for ordinary nodes




def test_seed_bootstrap_keeps_exploring_after_thirty_active_peers(monkeypatch):
    """An unbounded seed target must not stop discovery at an arbitrary count."""
    monkeypatch.setattr(Config, "SEED_NODE_MODE", True)
    monkeypatch.setattr(Config, "SEED_PEERS", ["198.51.100.201:8338", "198.51.100.202:8338"])
    monkeypatch.setattr(Config, "LOOPBACK_ADDRESS", "::1")
    net = _network(node_id="unbounded-seed")
    net.port = 8338

    class _Storage:
        def get_peers(self, limit=20):
            return [
                {"ip": "198.51.100.101", "port": 8338, "peer_id": "known-a"},
                {"ip": "198.51.100.102", "port": 8338, "peer_id": "known-b"},
            ]

    net.storage = _Storage()
    for index in range(1, 31):
        peer = _FakePeer(ip=f"203.0.113.{index}", port=9000 + index)
        peer.peer_id = f"active-{index}"
        net.peers[peer.peer_id] = peer

    attempts = []
    monkeypatch.setattr(p2p.time, "sleep", lambda *_: None)
    monkeypatch.setattr(net, "_try_add_peer", lambda ip, port, peer_id="": attempts.append((ip, port, peer_id)))
    net._bootstrap()

    assert len(net.active_peer_count()) == 30
    assert len(attempts) == 4
    assert {attempt[0] for attempt in attempts} == {
        "198.51.100.101", "198.51.100.102",
        "198.51.100.201", "198.51.100.202",
    }

def test_only_explicit_seed_has_unlimited_total_and_subnet_capacity(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    monkeypatch.setattr(Config, "SEED_NODE_MODE", True)
    net = _network(node_id="zz-seed")
    assert net._peer_capacity_limit() is None
    assert net._peer_subnet_limit() is None

    # 35 existing peers from one carrier IPv6 /48 must not block another
    # authenticated newcomer at the designated seed.
    for index in range(1, 36):
        net.peers[f"node-{index}"] = _FakePeer(
            ip=f"2401:4900:b7cc:1000::{index}",
            port=8338 + index, local_outbound=False)
    token = net._reserve_peer_admission(
        "node-36", "2401:4900:b7cc:1000::36", local_outbound=False)
    assert token is not None
    net._release_peer_admission(token)


def test_ordinary_node_still_rejects_when_its_30_peer_cap_is_full(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    monkeypatch.setattr(Config, "SEED_NODE_MODE", False)
    net = _network(node_id="zz-ordinary")
    # Distinct IPv4 /24 networks isolate total-cap behaviour from subnet policy.
    for index in range(1, 31):
        net.peers[f"node-{index}"] = _FakePeer(
            ip=f"10.{index}.1.1", port=8338 + index, local_outbound=False)
    assert net._peer_capacity_limit() == 30
    assert net._peer_capacity_reached(30) is True
    assert net._reserve_peer_admission(
        "node-31", "10.31.1.1", local_outbound=False) is None


def test_seed_registration_succeeds_past_normal_30_peer_cap(monkeypatch):
    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    monkeypatch.setattr(Config, "SEED_NODE_MODE", True)
    monkeypatch.setattr(p2p.threading, "Thread", _NoStartThread)
    monkeypatch.setattr(p2p, "_push_peer_notif", lambda *args, **kwargs: None)
    net = _network(node_id="zz-seed")
    _attach_registration_dependencies(net)
    for index in range(1, 31):
        peer = _FakePeer(ip=f"2401:4900:b7cc:1000::{index}",
                         port=8338 + index, local_outbound=False)
        peer.peer_id = f"node-{index}"
        net.peers[peer.peer_id] = peer
    token = net._reserve_peer_admission(
        "node-31", "2401:4900:b7cc:1000::31", local_outbound=False)
    assert token is not None
    newcomer = _FakePeer(ip="2401:4900:b7cc:1000::31", port=8369,
                         local_outbound=False)
    newcomer.peer_id = "node-31"
    net._register_peer(newcomer, "node-31", "pub", "user",
                       admission_token=token, local_outbound=False)
    assert net.peers.get("node-31") is newcomer
    assert newcomer.connected is True
    assert len(net.peers) == 31
