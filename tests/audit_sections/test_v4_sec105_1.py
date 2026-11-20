"""Section 105 V4 Regression Tests: UDP Wire Protocol, Framing and Packet Validation."""

from __future__ import annotations

import os
import queue
import sys
import threading
import zlib

import pytest

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.kernel.compression_utils import DecompressedSizeLimitError
from visold.network.p2p import P2PNetwork
from visold.network.udp.transport import UDPPeerConnection, UDPTransport
from visold.network.udp.wire import (
    _udp_decompress,
    _udp_normalize_addr,
    _udp_pack,
    _udp_unpack,
)


class _DummyStorage:
    def get_meta(self, _key):
        return None

    def add_ban_score(self, *_args, **_kwargs):
        pass

    def save_peer(self, *_args, **_kwargs):
        pass


class _DummySession:
    def __init__(self, addr: tuple):
        self.addr = addr
        self.inbound: queue.Queue = queue.Queue()
        self.closed = False
        self.sent = []

    def send_message(self, data: bytes):
        self.sent.append(data)

    def send_heartbeat(self):
        pass

    def close(self):
        self.closed = True
        self.inbound.put_nowait(None)

    def expire_if_silent(self, now=None):
        return self.closed

    def is_alive(self):
        return not self.closed


class _DummyUDPTransport:
    def __init__(self, sessions: dict):
        self._sessions = sessions
        self.removed_addrs = []
        self.released_addrs = []

    def get_session(self, addr: tuple):
        addr = _udp_normalize_addr(addr)
        if addr not in self._sessions:
            self._sessions[addr] = _DummySession(addr)
        return self._sessions[addr]

    def remove_session(self, addr: tuple, expected_session=None):
        addr = _udp_normalize_addr(addr)
        self.removed_addrs.append(addr)
        cur = self._sessions.get(addr)
        if cur is None:
            return False
        if expected_session is not None and cur is not expected_session:
            return False
        self._sessions.pop(addr, None)
        cur.close()
        return True

    def release_inbound(self, addr: tuple):
        self.released_addrs.append(_udp_normalize_addr(addr))


def test_udp_peer_message_loop_cleans_up_session_on_listen_port_mismatch():
    """
    V4 Regression: _udp_peer_message_loop cleans up using the session's source
    addr (ip, source_port) rather than (peer.ip, peer.port), preventing leaks.
    """
    source_addr = ("127.0.0.1", 49152)
    listen_port = 8338

    sess = _DummySession(source_addr)
    sessions = {source_addr: sess}
    udp_transport = _DummyUDPTransport(sessions)

    net = P2PNetwork.__new__(P2PNetwork)
    net._running = True
    net._udp = udp_transport
    net._udp_peers = {}
    net._udp_peers_lock = threading.Lock()
    net.storage = _DummyStorage()
    net._on_peer_disconnect = lambda _peer: None

    peer = UDPPeerConnection("peer-abc123", "127.0.0.1", listen_port, sess)
    with net._udp_peers_lock:
        net._udp_peers[source_addr] = peer

    sess.close()
    net._udp_peer_message_loop(peer)

    assert source_addr in udp_transport.removed_addrs
    assert source_addr not in net._udp_peers
    assert source_addr not in sessions


def test_udp_connect_to_rejects_unauthenticated_impersonated_responder():
    """
    V4 Regression: _udp_connect_to rejects a responder whose ACCEPT node_id does
    not match sha256(pub_hex), preserving any existing honest peer.
    """
    local_node_id = "0000" + "a" * 60
    target_node_id = "ffff" + "b" * 60

    class _Wallet:
        def __init__(self):
            self.priv = 1
            self.pub_hex = "04" + "11" * 64
            self.address = "VSD_local"

    class _Chain:
        def height(self):
            return 0

    remote_addr = ("127.0.0.1", 19000)
    sess = _DummySession(remote_addr)
    sess.inbound.put({"type": "POW_CHALLENGE", "challenge": "", "difficulty": 0})
    sess.inbound.put({"type": "VERIFY", "challenge": "deadbeef", "node_id": target_node_id})
    sess.inbound.put({
        "type": "ACCEPT",
        "node_id": target_node_id,
        "pub_hex": "0" * 128,
        "user_id": "",
        "wallet_addr": "",
        "seed_node": False,
        "version": "1.0",
        "tls_fp": "",
        "logic_hash": "",
        "capabilities": [],
        "chain_height": 0,
        "chain_tip_hash": "",
        "udp_port": 19000,
    })

    net = P2PNetwork.__new__(P2PNetwork)
    net._running = True
    net._on_peer_disconnect = lambda _p: None
    net.node_id = local_node_id
    net.port = 18338
    net.wallet = _Wallet()
    net.storage = _DummyStorage()
    net.blockchain = _Chain()
    net._local_chain_tip_hash = lambda: "0" * 64
    net._is_seed_node_mode = lambda: False
    net._budget = lambda base, _dl=None: base
    net._udp = _DummyUDPTransport({remote_addr: sess})
    net._udp_peers = {}
    net._udp_peers_lock = threading.Lock()
    net._lock = threading.Lock()
    net._peer_admission_reservations = {"tok-1": {"peer_id": target_node_id, "local_outbound": True}}
    net._reserve_peer_admission = lambda pid, ip, local_outbound=True, rejection_reason=None: "tok-1"
    net._mark_peer_admission_accepted = lambda tok, pid: True
    net._release_peer_admission = lambda tok: None

    honest_peer = UDPPeerConnection(
        target_node_id, "10.0.0.5", 8338, _DummySession(("10.0.0.5", 8338))
    )
    net.peers = {target_node_id: honest_peer}
    net._eager_peers = {target_node_id}
    net._topology_prune_cooldown_active = lambda _pid: False
    net._peer_capacity_limit = lambda: 64
    net.router = type("R", (), {"update": lambda *a, **k: None})()
    net._remember_node_info = lambda *a, **k: None
    net._auto_sync_from_peer = lambda *_a, **_k: None

    ok = net._udp_connect_to("127.0.0.1", 19000)

    assert ok is False
    assert net.peers[target_node_id] is honest_peer
    assert honest_peer.connected is True
    net._running = False
    sess.close()


def test_udp_unpack_rejects_zero_and_reserved_flags():
    """
    V4 Regression: _udp_unpack rejects packets with flags=0 or undefined reserved flag bits.
    """
    pkt_zero = _udp_pack(0x00, 1, 42, 0, b"evil_zero_flag")
    pkt_reserved = _udp_pack(0xC0, 2, 43, 0, b"evil_reserved")

    assert _udp_unpack(pkt_zero) is None
    assert _udp_unpack(pkt_reserved) is None


def test_udp_normalize_addr_handles_uppercase_ipv4_mapped_prefix():
    """
    V4 Regression: _udp_normalize_addr normalizes both lowercase '::ffff:' and
    uppercase '::FFFF:' IPv4-mapped IPv6 addresses.
    """
    assert _udp_normalize_addr(("::ffff:127.0.0.1", 8338)) == ("127.0.0.1", 8338)
    assert _udp_normalize_addr(("::FFFF:127.0.0.1", 8338)) == ("127.0.0.1", 8338)


def test_udp_decompress_raises_decompressed_size_limit_error():
    """
    V4 Regression: _udp_decompress propagates DecompressedSizeLimitError on zip bombs
    instead of swallowing it as ValueError.
    """
    bomb = zlib.compress(b"\x00" * (33 * 1024 * 1024), level=9)
    assert len(bomb) < 100_000
    with pytest.raises(DecompressedSizeLimitError):
        _udp_decompress(bomb)


def test_udp_inbound_yields_when_outbound_handshake_active_on_same_addr():
    """
    V4 Regression: _udp_handle_inbound checks _udp_handshake_state() and yields
    immediately when an outbound handshake is already active for the same addr.
    """
    addr = ("127.0.0.1", 19111)
    transport = UDPTransport(port=0, bind_addr="127.0.0.1")
    try:
        net = P2PNetwork.__new__(P2PNetwork)
        net._udp = transport
        net._udp_peers = {}
        net._udp_peers_lock = threading.Lock()
        net._running = True

        hs_lock, hs_map = net._udp_handshake_state()
        outbound_evt = threading.Event()
        with hs_lock:
            hs_map[addr] = outbound_evt

        # _udp_handle_inbound must yield immediately without touching the session
        net._udp_handle_inbound(addr)
        assert not transport.has_session(addr)
    finally:
        transport.stop()
