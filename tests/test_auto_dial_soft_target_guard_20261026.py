"""Regression tests for soft-target enforcement across automatic dial sources."""

import threading
from types import SimpleNamespace

from visold.network.p2p import P2PNetwork


class _Peer:
    def __init__(self, peer_id):
        self.peer_id = peer_id
        self.connected = True
        self.ip = f"192.0.2.{int(peer_id[-1], 36) % 200 + 1}"
        self.port = 8338


def _net(active_ids=("peer-1", "peer-2", "peer-3")):
    net = object.__new__(P2PNetwork)
    net.node_id = "self"
    net._lock = threading.RLock()
    net._pending_lock = threading.Lock()
    net._pending_connections = set()
    net._pending_peer_ids = set()
    net._auto_dial_lock = threading.RLock()
    net.peers = {pid: _Peer(pid) for pid in active_ids}
    net.active_peer_count = lambda: [p for p in net.peers.values() if p.connected]
    net._desired_peer_target = lambda: 3
    return net


def _install_impl_that_reserves_pending(net, starts):
    def impl(ip, port, peer_id=""):
        starts.append((ip, port, peer_id))
        with net._pending_lock:
            net._pending_connections.add((ip, port))
            if peer_id:
                net._pending_peer_ids.add(peer_id)
        return True
    net._try_add_peer_impl = impl


def test_regular_automatic_discovery_is_blocked_after_soft_target():
    net = _net()
    starts = []
    _install_impl_that_reserves_pending(net, starts)

    assert net._try_add_peer(
        "192.0.2.80", 8338, "peer-4",
        auto_discovery=True, dial_source="dns-seeder") is False
    assert starts == []
    assert net._pending_connections == set()


def test_automatic_discovery_reserves_only_remaining_target_slots():
    net = _net(active_ids=("peer-1", "peer-2"))
    starts = []
    _install_impl_that_reserves_pending(net, starts)

    assert net._try_add_peer(
        "192.0.2.80", 8338, "peer-3",
        auto_discovery=True, dial_source="pex") is True
    # Two active + one pending fills the target; concurrent discovery is blocked.
    assert net._try_add_peer(
        "192.0.2.81", 8338, "peer-4",
        auto_discovery=True, dial_source="capability") is False
    assert len(starts) == 1


def test_explicit_topology_probe_allows_only_one_pending_extra_dial():
    net = _net()
    starts = []
    _install_impl_that_reserves_pending(net, starts)

    assert net._try_add_peer(
        "192.0.2.80", 8338, "peer-4", auto_discovery=True,
        topology_probe=True, dial_source="pex-topology-probe") is True
    assert net._try_add_peer(
        "192.0.2.81", 8338, "peer-5", auto_discovery=True,
        topology_probe=True, dial_source="pex-topology-probe") is False
    assert len(starts) == 1


def test_manual_dial_is_not_blocked_by_soft_topology_target():
    net = _net()
    starts = []
    _install_impl_that_reserves_pending(net, starts)

    assert net._try_add_peer("192.0.2.80", 8338, "manual-peer") is True
    assert len(starts) == 1
