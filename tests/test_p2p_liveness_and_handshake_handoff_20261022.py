"""Regression tests for P2P liveness and TCP/UDP handshake handoff cleanup."""

from collections import defaultdict
import inspect
import socket
import threading
import time
from types import SimpleNamespace

from visold.kernel.lru_cache import LRUCache
from visold.kernel.messages import MSG_PING, MSG_PONG
from visold.network.p2p import P2PNetwork
from visold.network.peer_connection import PeerConnection
from visold.network.udp.transport import UDPPeerConnection


def _lightweight_network(peer):
    net = object.__new__(P2PNetwork)
    net._check_msg_rate = lambda _peer, _mtype: True
    net._seen_msgs = LRUCache(64, ttl=3600)
    net._lock = threading.RLock()
    net.peers = {peer.peer_id: peer}
    net._eager_peers = set()
    net._callbacks = defaultdict(list)
    return net


def test_repeated_identical_ping_is_answered_for_each_received_ping():
    sent = []
    peer = SimpleNamespace(
        peer_id="remote-node",
        connected=True,
        trust_level=PeerConnection.TRUST_HIGH,
        last_seen=0.0,
        send=lambda msg: sent.append(dict(msg)) or True,
    )
    net = _lightweight_network(peer)

    P2PNetwork._handle_message(net, peer, {"type": MSG_PING})
    first_seen = peer.last_seen
    time.sleep(0.002)
    P2PNetwork._handle_message(net, peer, {"type": MSG_PING})

    assert sent == [{"type": MSG_PONG}, {"type": MSG_PONG}]
    assert peer.last_seen > first_seen


def test_ping_rate_limit_still_blocks_oversized_heartbeat_traffic():
    sent = []
    peer = SimpleNamespace(
        peer_id="remote-node",
        connected=True,
        trust_level=PeerConnection.TRUST_HIGH,
        last_seen=0.0,
        send=lambda msg: sent.append(dict(msg)) or True,
    )
    net = _lightweight_network(peer)
    net._check_msg_rate = lambda _peer, _mtype: False

    P2PNetwork._handle_message(net, peer, {"type": MSG_PING})

    assert sent == []


def test_repeated_identical_pong_reaches_connection_local_callback_each_time():
    peer = SimpleNamespace(
        peer_id="remote-node",
        connected=True,
        trust_level=PeerConnection.TRUST_HIGH,
        last_seen=0.0,
        send=lambda _msg: True,
    )
    net = _lightweight_network(peer)
    seen = []
    net._callbacks[MSG_PONG].append(lambda _peer, msg: seen.append(msg["type"]))

    P2PNetwork._handle_message(net, peer, {"type": MSG_PONG})
    P2PNetwork._handle_message(net, peer, {"type": MSG_PONG})

    assert seen == [MSG_PONG, MSG_PONG]


def test_temporary_handshake_writer_can_stop_without_closing_transferred_socket():
    left, right = socket.socketpair()
    tmp = PeerConnection("temporary", "127.0.0.1", 9999, left)
    writer = tmp._writer_thread
    try:
        assert writer is not None and writer.is_alive()
        tmp.close_writer()
        writer.join(timeout=2.0)
        assert not writer.is_alive(), "temporary writer thread leaked after stop"
        assert tmp.connected, "writer shutdown must not mutate peer/socket ownership"
        left.sendall(b"socket-still-open")
        assert right.recv(64) == b"socket-still-open"
    finally:
        tmp.close()
        right.close()


def test_inbound_and_outbound_handshake_handoffs_stop_temporary_writer():
    inbound = inspect.getsource(P2PNetwork._handle_inbound)
    outbound = inspect.getsource(P2PNetwork.connect_to)

    inbound_stop = inbound.find("tmp.close_writer()")
    inbound_final_peer = inbound.find("peer = PeerConnection(peer_id, client_ip")
    assert inbound_stop >= 0 and inbound_final_peer > inbound_stop

    outbound_stop = outbound.find("tmp.close_writer()")
    outbound_final_peer = outbound.find("peer = PeerConnection(peer_id, ip, port")
    assert outbound_stop >= 0 and outbound_final_peer > outbound_stop


def test_admission_rejection_exposes_max_peer_reason_per_call(monkeypatch):
    import visold.network.p2p as p2p
    from visold.kernel.config import Config

    monkeypatch.setattr(Config, "MAX_PEERS", 1)
    monkeypatch.setattr(Config, "SEED_NODE_MODE", False)
    peer = SimpleNamespace(
        peer_id="existing-peer", ip="192.0.2.2", port=8338,
        connected=True, local_outbound=False,
    )
    net = _lightweight_network(peer)
    net.node_id = "a-local"
    rejection = {}

    token = P2PNetwork._reserve_peer_admission(
        net, "z-new-peer", "192.0.2.3", False,
        rejection_reason=rejection,
    )

    assert token is None
    assert rejection == {"reason": "MAX_PEERS_REACHED"}


def test_admission_rejection_exposes_subnet_reason_per_call(monkeypatch):
    from visold.kernel.config import Config

    monkeypatch.setattr(Config, "MAX_PEERS", 30)
    monkeypatch.setattr(Config, "SEED_NODE_MODE", False)
    net = object.__new__(P2PNetwork)
    net.node_id = "a-local"
    net._lock = threading.RLock()
    net.peers = {
        f"peer-{i}": SimpleNamespace(
            peer_id=f"peer-{i}", ip=f"192.0.2.{i+1}", port=8338+i,
            connected=True, local_outbound=False,
        ) for i in range(8)
    }
    net._peer_admission_reservations = {}
    rejection = {}

    token = P2PNetwork._reserve_peer_admission(
        net, "z-new-peer", "192.0.2.99", False,
        rejection_reason=rejection,
    )

    assert token is None
    assert rejection == {"reason": "SUBNET_LIMIT_REACHED"}


def test_explicit_admission_reject_is_handled_before_signature_validation():
    inbound = inspect.getsource(P2PNetwork._handle_inbound)
    outbound = inspect.getsource(P2PNetwork.connect_to)
    udp_inbound = inspect.getsource(P2PNetwork._udp_handle_inbound)
    udp_outbound = inspect.getsource(P2PNetwork._udp_connect_to)

    reject_branch = inbound.find('if resp.get("type") == MSG_REJECT:')
    signature_parse = inbound.find('sig  = sig_from_hex(resp.get("sig", "[]"))')
    assert reject_branch >= 0 and signature_parse > reject_branch
    assert '"reason": f"Local peer admission rejected: {reason}"' in outbound
    assert 'if msg.get("type") == MSG_REJECT:' in outbound

    udp_reject_branch = udp_inbound.find('if resp.get("type") == MSG_REJECT:')
    udp_signature_parse = udp_inbound.find('sig = sig_from_hex(resp.get("sig", "[]"))')
    assert udp_reject_branch >= 0 and udp_signature_parse > udp_reject_branch
    assert '"reason": f"Peer admission rejected: {reason}"' in udp_inbound
    assert 'if accept_msg and accept_msg.get("type") == MSG_REJECT:' in udp_outbound


class _FakeUDPSession:
    def __init__(self):
        self.closed = False
        self.sent = []
        self.inbound = None

    def send_message(self, data):
        self.sent.append(data)
        return True

    def close(self):
        self.closed = True


def test_temporary_udp_handshake_writer_stops_without_closing_transferred_session():
    import queue

    session = _FakeUDPSession()
    session.inbound = queue.Queue()
    tmp = UDPPeerConnection("temporary", "127.0.0.1", 9999, session)
    writer = tmp._writer_thread
    try:
        assert writer is not None and writer.is_alive()
        tmp.close_writer()
        writer.join(timeout=2.0)
        assert not writer.is_alive(), "temporary UDP writer thread leaked after stop"
        assert tmp.connected, "writer shutdown must not mark transferred session disconnected"
        assert tmp.send({"type": "TEST"}) is True
        assert session.sent, "transferred UDP session should remain writable"
        assert not session.closed, "temporary wrapper must not close shared session"
    finally:
        tmp.close()


def test_udp_inbound_and_outbound_handoffs_stop_temporary_writer():
    inbound = inspect.getsource(P2PNetwork._udp_handle_inbound)
    outbound = inspect.getsource(P2PNetwork._udp_connect_to)

    inbound_stop = inbound.find("peer.close_writer()")
    inbound_final_peer = inbound.find("final_peer = UDPPeerConnection(")
    assert inbound_stop >= 0 and inbound_final_peer > inbound_stop

    outbound_stop = outbound.find("peer.close_writer()")
    outbound_final_peer = outbound.find("final_peer = UDPPeerConnection(")
    assert outbound_stop >= 0 and outbound_final_peer > outbound_stop


def test_udp_admission_rejection_includes_reason_and_is_handled_before_signature():
    inbound = inspect.getsource(P2PNetwork._udp_handle_inbound)
    outbound = inspect.getsource(P2PNetwork._udp_connect_to)

    inbound_reject = inbound.find('if resp.get("type") == MSG_REJECT:')
    inbound_sig = inbound.find('sig = sig_from_hex(resp.get("sig", "[]"))')
    assert inbound_reject >= 0 and inbound_sig > inbound_reject
    assert '"reason": f"Peer admission rejected: {reason}"' in inbound
    assert '"reason": f"Local peer admission rejected: {reason}"' in outbound
