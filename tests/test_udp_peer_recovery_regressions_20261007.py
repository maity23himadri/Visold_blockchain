"""Regression tests for the confirmed UDP peer-recovery/sync defects."""

from __future__ import annotations

import queue
import threading


from visold.network.p2p import P2PNetwork
from visold.network.udp.transport import UDPPeerConnection


class _FakeSession:
    def __init__(self, messages=None):
        self.inbound = queue.Queue()
        for msg in messages or ():
            self.inbound.put(msg)
        self.closed = False

    def send_message(self, _data):
        if self.closed:
            raise RuntimeError("session closed")

    def close(self):
        self.closed = True
        try:
            self.inbound.put_nowait(None)
        except Exception:
            pass

    def is_alive(self):
        return not self.closed


class _FakeUDPTransport:
    def __init__(self, session):
        self.session = session
        self.removed = []

    def get_session(self, _addr):
        return self.session

    def remove_session(self, addr, expected_session=None):
        if expected_session is not None and expected_session is not self.session:
            return False
        self.removed.append((addr, expected_session))
        self.session.close()
        return True

    def release_inbound(self, _addr):
        pass


def _make_udp_peer(session=None):
    session = session or _FakeSession()
    return UDPPeerConnection("peer", "127.0.0.1", 9999, session), session


def test_udp_peer_exposes_all_shared_sync_state():
    peer, _session = _make_udp_peer()
    try:
        assert isinstance(peer._pagination_active, threading.Event)
        assert isinstance(peer._auto_sync_active, threading.Event)
        assert peer._fork_sync_buffer == []
        assert peer._fork_sync_buffer_bytes == 0
        assert peer._fork_sync_target_height == -1
        assert peer.chain_height == -1
        assert peer.capabilities == []
        assert peer._block_chunk_queue is None
        assert peer._snap_response_queue is None
    finally:
        peer.close_writer()
        peer.connected = False


def test_outbound_udp_handshake_failure_removes_its_session():
    # A message other than VERIFY forces the actual outbound handshake failure
    # path without waiting for a timeout.
    session = _FakeSession([{"type": "UNEXPECTED"}])
    udp = _FakeUDPTransport(session)

    net = P2PNetwork.__new__(P2PNetwork)
    net._udp = udp
    net._udp_peers_lock = threading.Lock()
    net._udp_peers = {}
    net.node_id = "local"
    net.wallet = type("Wallet", (), {"pub_hex": "pub", "priv": object()})()

    ok = net._udp_connect_to("127.0.0.1", 9999)
    assert ok is False
    assert session.closed is True
    assert udp.removed == [(('127.0.0.1', 9999), session)]
    assert net._udp_peers == {}


def test_inbound_udp_handshake_failure_removes_its_session(monkeypatch):
    session = _FakeSession()
    udp = _FakeUDPTransport(session)

    net = P2PNetwork.__new__(P2PNetwork)
    net._udp = udp

    # Force the first handshake receive to fail immediately, exercising the
    # real finally/cleanup path rather than a timeout.
    monkeypatch.setattr(
        UDPPeerConnection,
        "recv_line",
        lambda self, timeout=30.0: None,
    )

    net._udp_handle_inbound(("127.0.0.1", 9999))

    assert session.closed is True
    assert udp.removed == [(('127.0.0.1', 9999), session)]


def test_identity_checked_session_removal_does_not_close_replacement():
    from visold.network.udp.transport import UDPTransport

    transport = UDPTransport(port=0, bind_addr="127.0.0.1")
    old = _FakeSession()
    new = _FakeSession()
    addr = ("127.0.0.1", 9999)
    try:
        with transport._lock:
            transport._sessions[addr] = new
        assert transport.remove_session(addr, expected_session=old) is False
        assert transport.has_session(addr) is True
        assert new.closed is False
    finally:
        transport.remove_session(addr, expected_session=new)
        transport._sock.close()
