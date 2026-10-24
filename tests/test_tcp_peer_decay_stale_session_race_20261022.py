"""Regression test for stale TCP decay snapshots racing with peer replacement."""

import time
import socket
import threading

import visold.network.p2p as p2p
from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork
from visold.network.peer_connection import PeerConnection


class _Peer:
    def __init__(self, peer_id, last_seen):
        self.peer_id = peer_id
        self.connected = True
        self.last_seen = last_seen
        self.closed = False

    def close(self):
        self.closed = True
        self.connected = False


class _ReplaceBetweenLockWindows:
    """Install a replacement after stale selection and before stale removal."""

    def __init__(self, backing_lock, peers, peer_id, replacement):
        self.backing_lock = backing_lock
        self.peers = peers
        self.peer_id = peer_id
        self.replacement = replacement
        self.enter_count = 0

    def __enter__(self):
        self.backing_lock.acquire()
        self.enter_count += 1
        return self

    def __exit__(self, exc_type, exc, tb):
        self.backing_lock.release()
        if self.enter_count == 1:
            # This is the real race window: the dead snapshot has been built,
            # its lock has been released, and the decay thread has not yet
            # acquired the lock again to remove the peer by ID.
            with self.backing_lock:
                self.peers[self.peer_id] = self.replacement
        return False


def test_decay_snapshot_does_not_close_replacement_session(monkeypatch):
    old = _Peer("peer-a", last_seen=0.0)
    replacement = _Peer("peer-a", last_seen=time.time())
    net = object.__new__(P2PNetwork)
    net._running = True
    net.peers = {"peer-a": old}
    net._eager_peers = {"peer-a"}
    net._lock = _ReplaceBetweenLockWindows(
        threading.RLock(), net.peers, "peer-a", replacement)

    # Execute exactly one decay pass without waiting an hour or starting a thread.
    monkeypatch.setattr(Config, "PEER_DECAY_SECS", 0.1)

    def stop_after_first_sleep(_seconds):
        net._running = False

    monkeypatch.setattr(p2p.time, "sleep", stop_after_first_sleep)

    P2PNetwork._peer_decay_loop(net)

    assert net.peers.get("peer-a") is replacement
    assert replacement.connected is True
    assert replacement.closed is False
    assert "peer-a" in net._eager_peers
    assert old.closed is False


def test_decay_still_closes_the_same_stale_session(monkeypatch):
    old = _Peer("peer-a", last_seen=0.0)
    net = object.__new__(P2PNetwork)
    net._running = True
    net.peers = {"peer-a": old}
    net._eager_peers = {"peer-a"}
    net._lock = threading.RLock()
    monkeypatch.setattr(Config, "PEER_DECAY_SECS", 0.1)
    monkeypatch.setattr(p2p.time, "sleep", lambda _seconds: setattr(net, "_running", False))

    P2PNetwork._peer_decay_loop(net)

    assert "peer-a" not in net.peers
    assert "peer-a" not in net._eager_peers
    assert old.closed is True
    assert old.connected is False


def test_replacement_loopback_tcp_socket_does_not_receive_false_eof(monkeypatch):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(0.2)
    client.connect(listener.getsockname())
    server, _address = listener.accept()
    listener.close()

    old = _Peer("peer-a", last_seen=0.0)
    replacement = PeerConnection(
        "peer-a", "127.0.0.1", client.getsockname()[1], sock=server)
    replacement.last_seen = time.time()
    net = object.__new__(P2PNetwork)
    net._running = True
    net.peers = {"peer-a": old}
    net._eager_peers = {"peer-a"}
    net._lock = _ReplaceBetweenLockWindows(
        threading.RLock(), net.peers, "peer-a", replacement)
    monkeypatch.setattr(Config, "PEER_DECAY_SECS", 0.1)
    monkeypatch.setattr(p2p.time, "sleep", lambda _seconds: setattr(net, "_running", False))

    try:
        P2PNetwork._peer_decay_loop(net)

        assert net.peers.get("peer-a") is replacement
        assert replacement.connected is True
        try:
            received = client.recv(1)
        except socket.timeout:
            received = None
        assert received is None, "replacement TCP stream was closed and emitted EOF"
    finally:
        replacement.close()
        client.close()


def test_valid_inbound_tcp_message_refreshes_peer_decay_timestamp():
    left, right = socket.socketpair()
    peer = PeerConnection("peer-a", "127.0.0.1", 8338, sock=left)
    peer.last_seen = time.time() - 7200
    old_last_seen = peer.last_seen
    net = object.__new__(P2PNetwork)
    net._running = True
    net._handle_message = lambda _peer, _message: None
    net._on_peer_disconnect = lambda connection: connection.close()

    try:
        right.sendall(b'{"type":"PING"}\n')
        right.close()
        P2PNetwork._peer_message_loop(net, peer)

        assert peer.last_seen > old_last_seen
        assert peer._last_rx_message_type == "PING"
    finally:
        peer.close()
        try:
            right.close()
        except OSError:
            pass
