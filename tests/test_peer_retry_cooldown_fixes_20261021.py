"""Regression tests for endpoint-scoped P2P retries and noisy activity rows."""

from collections import deque
import threading
import time
from types import SimpleNamespace

import visold.kernel.notifications as notifications
import visold.network.p2p as p2p
from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork


class _FakePeer:
    def __init__(self, peer_id, ip, port, connected=True):
        self.peer_id = peer_id
        self.ip = ip
        self.port = port
        self.connected = connected


class _FakeDB:
    def execute(self, *_args, **_kwargs):
        return self

    def fetchone(self):
        return None


class _FakeStorage:
    def resolve_name_claim(self, _name):
        return None

    def _conn(self):
        return _FakeDB()


class _NoStartThread:
    created = []

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        type(self).created.append(self)

    def start(self):
        pass


def _network(node_id="local"):
    net = object.__new__(P2PNetwork)
    net.node_id = node_id
    net.port = 8338
    net.peers = {}
    net._lock = threading.RLock()
    net._eager_peers = set()
    net._pending_connections = set()
    net._pending_lock = threading.Lock()
    net._pending_ip_counts = {}
    net._pending_peer_ids = set()
    net._outbound_fail = {}
    net._outbound_fail_lock = threading.Lock()
    net.storage = _FakeStorage()
    net._node_directory = {}
    net._node_directory_lock = threading.RLock()
    net._is_ip_banned = lambda _ip: False
    return net


def test_cooldown_for_one_port_does_not_block_another_port_on_same_mobile_ip(monkeypatch):
    monkeypatch.setattr(p2p.threading, "Thread", _NoStartThread)
    _NoStartThread.created.clear()
    net = _network()
    ip = "2401:4900:b175:985a::ba1f:b06d"
    net._outbound_fail[(ip, 8341)] = [5, time.time() + 300]

    net._try_add_peer(ip, 8347, "peer-on-8347")

    assert len(_NoStartThread.created) == 1
    assert (ip, 8347) in net._pending_connections
    assert (ip, 8341) not in net._pending_connections


def test_connected_identity_is_not_dialed_again_at_a_stale_endpoint(monkeypatch):
    monkeypatch.setattr(p2p.threading, "Thread", _NoStartThread)
    _NoStartThread.created.clear()
    net = _network()
    net.peers["peer-live"] = _FakePeer(
        "peer-live", "2401:4900:b175:985a::ba1f:b06d", 8347)

    net._try_add_peer("2001:db8::77", 9001, "peer-live")

    assert _NoStartThread.created == []
    assert net._pending_connections == set()


def test_peer_id_has_only_one_outbound_dial_in_flight(monkeypatch):
    monkeypatch.setattr(p2p.threading, "Thread", _NoStartThread)
    _NoStartThread.created.clear()
    net = _network()

    net._try_add_peer("2001:db8::10", 8347, "peer-mobile")
    net._try_add_peer("2001:db8::11", 8353, "peer-mobile")

    assert len(_NoStartThread.created) == 1
    assert net._pending_connections == {("2001:db8::10", 8347)}
    assert net._pending_peer_ids == {"peer-mobile"}


def test_same_ip_dial_burst_has_no_outbound_per_ip_cap(monkeypatch):
    monkeypatch.setattr(p2p.threading, "Thread", _NoStartThread)
    _NoStartThread.created.clear()
    net = _network()
    ip = "2401:4900:b175:985a::ba1f:b06d"

    for port in (8338, 8341, 8347, 8353):
        net._try_add_peer(ip, port, f"peer-{port}")
    net._try_add_peer("2001:db8::88", 8338, "other-ip-peer")

    assert len(_NoStartThread.created) == 5
    assert net._pending_connections == {
        (ip, 8338), (ip, 8341), (ip, 8347), (ip, 8353),
        ("2001:db8::88", 8338),
    }


def test_failed_attempt_counter_is_keyed_by_endpoint_not_ip(monkeypatch):
    net = _network()
    ip = "2001:db8::44"
    monkeypatch.setattr(Config, "P2P_CONNECT_BUDGET_SECS", 0.0)
    net._udp_connect_to = lambda *_args, **_kwargs: False
    net.connect_to = lambda *_args, **_kwargs: False
    net._pending_connections.add((ip, 8341))

    net._connect_with_fallback(ip, 8341)

    assert net._outbound_fail[(ip, 8341)][0] == 1
    assert ip not in net._outbound_fail
    assert (ip, 8341) not in net._pending_connections


def test_cooldown_activity_is_emitted_once_until_endpoint_state_changes():
    with notifications._peer_activity_lock:
        notifications._peer_activity_buf.clear()
        notifications._peer_activity_last_status.clear()
    ip, port = "2001:db8::55", 8341

    for _ in range(10):
        notifications._pa_push("OUT", ip, port, "COOLDOWN")
    with notifications._peer_activity_lock:
        assert len(notifications._peer_activity_buf) == 1

    notifications._pa_push("OUT", ip, port, "CONNECTING")
    notifications._pa_push("OUT", ip, port, "COOLDOWN")
    with notifications._peer_activity_lock:
        assert [r["status"] for r in notifications._peer_activity_buf] == [
            "COOLDOWN", "CONNECTING", "COOLDOWN"
        ]


def test_new_mobile_endpoint_is_kept_as_unverified_candidate_without_overwriting_identity():
    net = _network()
    net._node_directory_max = 5000
    net._node_directory_ttl_secs = 30 * 24 * 60 * 60
    net._node_directory_claim_cache = {}
    net._remember_node_info({
        "peer_id": "peer-mobile", "ip": "2001:db8::10", "port": 8341,
        "user_id": "stable-id", "wallet_addr": "VSD-stable", "chain_height": 50,
    }, verified=True)

    net._remember_node_info({
        "peer_id": "peer-mobile", "ip": "2001:db8::99", "port": 8347,
        "user_id": "spoofable-pex-label", "wallet_addr": "VSD-unknown",
        "chain_height": 999999,
    }, verified=False, source="pex")

    rows = net.get_network_directory(refresh_sources=False)
    old = next(row for row in rows if row["ip"] == "2001:db8::10")
    candidate = next(row for row in rows if row["ip"] == "2001:db8::99")
    assert old["verified"] is True
    assert old["status"] == "OFFLINE"
    assert old["user_id"] == "stable-id"
    assert candidate["verified"] is False
    assert candidate["status"] == "DISCOVERED"
    assert candidate["chain_height"] == -1


def test_under_target_auto_discovery_allows_one_half_open_probe_during_cooldown(monkeypatch):
    monkeypatch.setattr(p2p.threading, "Thread", _NoStartThread)
    _NoStartThread.created.clear()
    net = _network()
    ip, port, peer_id = "2001:db8::99", 8341, "recover-peer"
    # Five failed dials triggered the normal 300 s cooldown. A node with no
    # active peers must still make a bounded recovery probe without restart.
    net._outbound_fail[(ip, port)] = [5, time.time() + 300, 0.0]

    assert net._try_add_peer(
        ip, port, peer_id, auto_discovery=True, dial_source="reconnect-cache") is True
    assert len(_NoStartThread.created) == 1
    assert net._outbound_fail[(ip, port)][2] > 0

    # Simulate the attempt finishing, then ensure the same endpoint cannot be
    # probed repeatedly inside the configured reconnect interval.
    with net._pending_lock:
        net._pending_connections.clear()
        net._pending_peer_ids.clear()
    assert net._try_add_peer(
        ip, port, peer_id, auto_discovery=True, dial_source="reconnect-cache") is False
    assert len(_NoStartThread.created) == 1


def test_manual_dial_still_obeys_endpoint_cooldown(monkeypatch):
    monkeypatch.setattr(p2p.threading, "Thread", _NoStartThread)
    _NoStartThread.created.clear()
    net = _network()
    ip, port = "2001:db8::100", 8341
    net._outbound_fail[(ip, port)] = [5, time.time() + 300, 0.0]

    assert net._try_add_peer(ip, port, "manual-retry") is False
    assert _NoStartThread.created == []
