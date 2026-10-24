"""Regression tests for PEX dial-budget starvation and pending-slot leaks."""

from collections import deque
import threading
from types import SimpleNamespace

import visold.network.p2p as p2p
from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork


class _Peer:
    def __init__(self, peer_id, connected=True):
        self.peer_id = peer_id
        self.ip = "192.0.2.10"
        self.port = 8338
        self.connected = connected
        self._fork_sync_buffer = []
        self._fork_sync_buffer_bytes = 0
        self._fork_sync_target_height = -1

    def close(self):
        self.connected = False


def _pex_net(monkeypatch, *, seed=False, target=4, active_ids=("a", "b")):
    net = object.__new__(P2PNetwork)
    net.node_id = "self"
    net._lock = threading.RLock()
    net.peers = {pid: _Peer(pid) for pid in active_ids}
    net._pending_lock = threading.Lock()
    net._pending_connections = set()
    net._pending_peer_ids = set()
    net._pex_dial_lock = threading.Lock()
    net._pex_dial_times = deque()
    net._pex_seed_dials_per_minute = 1
    net._is_seed_node_mode = lambda: seed
    net.minimum_peer_target = lambda: target
    net.active_peer_count = lambda: [p for p in net.peers.values() if p.connected]
    return net


def test_pex_budget_counts_only_workers_that_really_start(monkeypatch):
    """Connected/source/self candidates must not starve later eligible peers."""
    net = _pex_net(monkeypatch, target=4, active_ids=("a", "b"))
    attempts = []

    def try_add(ip, port, peer_id=""):
        attempts.append(peer_id)
        return peer_id in {"c", "d"}

    net._try_add_peer = try_add
    candidates = [
        {"ip": "192.0.2.10", "port": 8338, "peer_id": "a"},
        {"ip": "192.0.2.11", "port": 8338, "peer_id": "b"},
        {"ip": "192.0.2.12", "port": 8338, "peer_id": "source"},
        {"ip": "192.0.2.13", "port": 8338, "peer_id": "self"},
        {"ip": "192.0.2.14", "port": 8338, "peer_id": "c"},
        {"ip": "192.0.2.15", "port": 8338, "peer_id": "d"},
        {"ip": "192.0.2.16", "port": 8338, "peer_id": "e"},
    ]

    started = net._dial_pex_candidates(SimpleNamespace(peer_id="source"), candidates)

    assert started == 2
    assert attempts == ["a", "b", "c", "d"]


def test_seed_pex_rate_slot_is_released_when_candidate_is_skipped(monkeypatch):
    """An ineligible seed candidate must not burn the only per-minute slot."""
    net = _pex_net(monkeypatch, seed=True, target=None, active_ids=("a",))
    attempts = []

    def try_add(ip, port, peer_id=""):
        attempts.append(peer_id)
        return peer_id == "b"

    net._try_add_peer = try_add
    candidates = [
        {"ip": "192.0.2.10", "port": 8338, "peer_id": "a"},
        {"ip": "192.0.2.11", "port": 8338, "peer_id": "b"},
        {"ip": "192.0.2.12", "port": 8338, "peer_id": "c"},
    ]

    started = net._dial_pex_candidates(SimpleNamespace(peer_id="source"), candidates)

    assert started == 1
    assert attempts == ["a", "b"]
    assert len(net._pex_dial_times) == 1
    assert net._pex_dial_times[0][1] <= __import__("time").monotonic()


class _FakeDB:
    def execute(self, *_args, **_kwargs):
        return self

    def fetchone(self):
        return None


class _Storage:
    def _conn(self):
        return _FakeDB()


class _ThreadStartFailure:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        raise RuntimeError("simulated thread start failure")


def _dial_net():
    net = object.__new__(P2PNetwork)
    net.node_id = "local"
    net.port = 8338
    net.peers = {}
    net._lock = threading.RLock()
    net._eager_peers = set()
    net._pending_connections = set()
    net._pending_lock = threading.Lock()
    net._pending_peer_ids = set()
    net._outbound_fail = {}
    net._outbound_fail_lock = threading.Lock()
    net.storage = _Storage()
    net._node_directory = {}
    net._node_directory_lock = threading.RLock()
    net._is_ip_banned = lambda _ip: False
    net._connect_with_fallback = lambda *_args: None
    return net


def test_blacklist_lookup_error_does_not_leak_pending_dial(monkeypatch):
    net = _dial_net()

    class BrokenStorage:
        def _conn(self):
            raise RuntimeError("db unavailable")

    net.storage = BrokenStorage()
    started = net._try_add_peer("192.0.2.44", 8341, "peer-x")

    assert started is False
    assert net._pending_connections == set()
    assert net._pending_peer_ids == set()


def test_thread_start_failure_cleans_pending_and_returns_false(monkeypatch):
    net = _dial_net()
    monkeypatch.setattr(p2p.threading, "Thread", _ThreadStartFailure)
    statuses = []
    monkeypatch.setattr(p2p, "_pa_push", lambda direction, ip, port, status: statuses.append(status))

    started = net._try_add_peer("192.0.2.45", 8341, "peer-y")

    assert started is False
    assert net._pending_connections == set()
    assert net._pending_peer_ids == set()
    assert statuses == ["CONNECTING", "FAILED"]


def test_connecting_activity_is_published_before_worker_can_finish(monkeypatch):
    net = _dial_net()
    statuses = []
    monkeypatch.setattr(p2p, "_pa_push", lambda direction, ip, port, status: statuses.append(status))

    class _InlineThread:
        def __init__(self, target, args, daemon=True):
            self.target = target
            self.args = args

        def start(self):
            self.target(*self.args)

    monkeypatch.setattr(p2p.threading, "Thread", _InlineThread)

    def fast_finish(ip, port, peer_id):
        p2p._pa_push("OUT", ip, port, "CONNECTED")
        with net._pending_lock:
            net._pending_connections.discard((ip, port))
            net._pending_peer_ids.discard(peer_id)

    net._connect_with_fallback = fast_finish

    assert net._try_add_peer("192.0.2.46", 8341, "peer-z") is True
    assert statuses == ["CONNECTING", "CONNECTED"]


def test_old_duplicate_session_disconnect_cannot_evict_current_session():
    """The losing session's delayed EOF cleanup must not remove its winner."""
    net = _pex_net(None, active_ids=())
    current = _Peer("peer-a", connected=True)
    stale = _Peer("peer-a", connected=True)
    net.peers["peer-a"] = current
    net._eager_peers = {"peer-a"}

    net._on_peer_disconnect(stale)

    assert stale.connected is False
    assert net.peers["peer-a"] is current
    assert "peer-a" in net._eager_peers
