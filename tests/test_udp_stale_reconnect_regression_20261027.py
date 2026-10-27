"""Regression tests for stale UDP peer mappings during reconnect."""
from types import SimpleNamespace
import threading

import visold.network.p2p as p2p
from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork
from visold.network.udp.wire import _udp_normalize_addr


class _Session:
    def __init__(self, alive):
        self.alive = alive
        self.removed = False

    def is_alive(self):
        return self.alive

    def send_heartbeat(self):
        pass


class _UdpTransport:
    def __init__(self, session):
        self.session = session
        self.removals = []

    def get_session(self, _addr):
        return self.session

    def remove_session(self, addr, expected_session=None):
        self.removals.append((addr, expected_session))
        if expected_session is not None:
            expected_session.removed = True
        return True


class _HandshakePeer:
    def __init__(self, _role, _ip, _port, _session):
        self.connected = False
        self.closed = False

    def recv_line(self, timeout=None):
        return None

    def send(self, _msg):
        pass

    def close(self):
        self.closed = True


class _StalePeer:
    def __init__(self, ip, port, session):
        self.peer_id = "stale-peer"
        self.ip, self.port = ip, port
        self._session = session
        self.connected = False
        self.closed = False

    def close(self):
        self.closed = True
        self.connected = False


def test_udp_reconnect_does_not_report_stale_mapping_as_success(monkeypatch):
    ip, port = "192.0.2.40", 8341
    addr = _udp_normalize_addr((ip, port))
    stale_session = _Session(False)
    fresh_session = _Session(True)
    stale_peer = _StalePeer(ip, port, stale_session)

    net = object.__new__(P2PNetwork)
    net._udp_peers_lock = threading.RLock()
    net._udp_peers = {addr: stale_peer}
    net._udp = _UdpTransport(fresh_session)
    net._on_peer_disconnect = lambda peer: peer.close()
    net._budget = lambda wait, deadline: wait
    net._is_seed_node_mode = lambda: False
    net._local_chain_tip_hash = lambda: ""
    net.port = 8341
    net.node_id = "local"
    net.wallet = SimpleNamespace(pub_hex="pub", address="VSD-test")
    net.storage = SimpleNamespace(get_meta=lambda _key: "")
    net.blockchain = SimpleNamespace(height=lambda: 0)
    monkeypatch.setattr(p2p, "UDPPeerConnection", _HandshakePeer)
    monkeypatch.setattr(Config, "ICE_ENABLED", False)

    # The fake handshake intentionally receives no response, so a new attempt
    # must fail. The key assertion is that a stale registry hit is not reported
    # as a successful connection before this attempt is made.
    result = net._udp_connect_to(ip, port)

    assert result is False
    assert stale_peer.closed is True
    assert stale_session.removed is True
    assert addr not in net._udp_peers
    assert fresh_session.removed is True


def test_old_udp_receive_loop_cannot_pop_replacement_at_same_endpoint():
    ip, port = "192.0.2.41", 8341
    addr = _udp_normalize_addr((ip, port))
    old_session = _Session(False)
    new_session = _Session(True)
    old_peer = _StalePeer(ip, port, old_session)
    replacement = _StalePeer(ip, port, new_session)
    replacement.peer_id = "replacement-peer"
    replacement.connected = True

    net = object.__new__(P2PNetwork)
    net._running = True
    net._udp_peers_lock = threading.RLock()
    net._udp_peers = {addr: replacement}
    net._udp = _UdpTransport(old_session)
    net._on_peer_disconnect = lambda _peer: None

    # Old loop has already stopped, but its finally-style cleanup still runs.
    P2PNetwork._udp_peer_message_loop(net, old_peer)

    assert net._udp_peers.get(addr) is replacement
    assert net._udp.removals == [(addr, old_session)]
