import os
import socket
import sys
import threading

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.chain.blockchain import Blockchain
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.messages import (
    MSG_ACCEPT,
    MSG_HELLO,
    MSG_POW_CHALLENGE,
    MSG_REJECT,
    MSG_VERIFY,
)
from visold.network.capabilities import (
    CAP_ARCHIVE,
    CAP_FULL_NODE,
    CAP_VVM_EXEC,
    CapabilityRouter,
    MSG_CAPABILITY_ADV,
    MSG_CAPABILITY_QUERY,
)
from visold.network.p2p import P2PNetwork, TLSManager
from visold.network.peer_connection import PeerConnection
from visold.network.reputation import PeerReputationManager
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_node(tmp_path, name: str, port: int):
    db_path = str(tmp_path / f"{name}.db")
    storage = Storage(db_path=db_path)
    wallet = Wallet.generate()
    bc = Blockchain(storage=storage)
    p2p = P2PNetwork(bc, wallet, storage, port=port)
    return p2p, wallet, storage


def test_inbound_handshake_rejects_mismatched_node_id_and_pub_hex(tmp_path, monkeypatch):
    """
    V4 Regression: _handle_inbound() verifies node_id == sha256(pub_hex.encode())
    and rejects impersonation attempts with MSG_REJECT.
    """
    monkeypatch.setattr(TLSManager, "server_context", staticmethod(lambda: None))
    monkeypatch.setattr(Config, "PEER_POW_DIFFICULTY", 0)

    server_p2p, _, server_storage = _make_node(tmp_path, "server", 19101)
    server_p2p._running = True
    attacker_wallet = Wallet.generate()
    victim_wallet = Wallet.generate()
    victim_node_id = sha256(victim_wallet.pub_hex.encode())
    assert victim_node_id != sha256(attacker_wallet.pub_hex.encode())

    srv_sock, cli_sock = socket.socketpair()
    srv_thread = threading.Thread(
        target=server_p2p._handle_inbound,
        args=(srv_sock, ("127.0.0.1", 50001)),
        daemon=True,
    )
    srv_thread.start()

    client_conn = PeerConnection("client", "127.0.0.1", 19101, cli_sock)
    try:
        assert client_conn.send({
            "type": MSG_HELLO,
            "node_id": victim_node_id,
            "pub_hex": attacker_wallet.pub_hex,
            "listen_port": 19102,
            "capabilities": ["full_node"],
        })

        reply = client_conn.recv_line(timeout=5)
        assert reply is not None and reply.get("type") == MSG_REJECT
        assert victim_node_id not in server_p2p.peers
        row = server_storage._conn().execute(
            "SELECT ip, port FROM peers WHERE peer_id=?", (victim_node_id,)
        ).fetchone()
        assert row is None
    finally:
        server_p2p._running = False
        client_conn.close()
        srv_thread.join(timeout=2.0)
        server_storage.close()


def test_outbound_handshake_rejects_empty_pub_hex(tmp_path, monkeypatch):
    """
    V4 Regression: connect_to() rejects MSG_ACCEPT with empty pub_hex or
    mismatched node_id.
    """
    monkeypatch.setattr(TLSManager, "client_context", staticmethod(lambda: None))
    monkeypatch.setattr(Config, "ICE_ENABLED", False)

    client_p2p, _, client_storage = _make_node(tmp_path, "client", 19103)
    client_p2p._running = True
    victim_wallet = Wallet.generate()
    victim_node_id = sha256(victim_wallet.pub_hex.encode())

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    srv_port = listener.getsockname()[1]

    def _rogue_server():
        conn, _ = listener.accept()
        pc = PeerConnection("rogue", "127.0.0.1", 0, conn)
        try:
            pc.send({"type": MSG_POW_CHALLENGE, "challenge": "", "difficulty": 0})
            hello = pc.recv_line(timeout=5)
            assert hello and hello.get("type") == MSG_HELLO
            pc.send({
                "type": MSG_VERIFY,
                "challenge": "static_challenge",
                "node_id": victim_node_id,
                "tls_fp": "",
            })
            resp = pc.recv_line(timeout=5)
            assert resp and resp.get("type") == "CHALLENGE_RESP"
            pc.send({
                "type": MSG_ACCEPT,
                "node_id": victim_node_id,
                "pub_hex": "",
                "version": Config.VERSION,
                "tls_fp": "",
                "capabilities": ["full_node"],
                "chain_height": 0,
            })
            threading.Event().wait(0.3)
        finally:
            pc.close()

    t = threading.Thread(target=_rogue_server, daemon=True)
    t.start()

    try:
        ok = client_p2p.connect_to("127.0.0.1", srv_port)
        assert ok is False
        assert victim_node_id not in client_p2p.peers
    finally:
        client_p2p._running = False
        for p in list(client_p2p.peers.values()):
            p.close()
        t.join(timeout=2.0)
        listener.close()
        client_storage.close()


def test_capability_router_removes_stale_capabilities_on_update(tmp_path):
    """
    V4 Regression: CapabilityRouter.record_peer_capabilities() removes old
    capabilities from _cap_index and SQLite when a peer updates its capabilities.
    """
    db_path = str(tmp_path / "caps.db")
    storage = Storage(db_path=db_path)
    try:
        router = CapabilityRouter(storage)
        peer_id = "peer_abc123"

        router.record_peer_capabilities(peer_id, [CAP_ARCHIVE, CAP_VVM_EXEC])
        assert peer_id in router.find_peers_with(CAP_ARCHIVE)
        assert peer_id in router.find_peers_with(CAP_VVM_EXEC)

        router.record_peer_capabilities(peer_id, [CAP_FULL_NODE])
        assert peer_id in router.find_peers_with(CAP_FULL_NODE)
        assert peer_id not in router.find_peers_with(CAP_ARCHIVE)
        assert peer_id not in router.find_peers_with(CAP_VVM_EXEC)

        router2 = CapabilityRouter(storage)
        assert router2._peer_caps[peer_id] == {CAP_FULL_NODE}
    finally:
        storage.close()


def test_capability_handlers_safe_when_capability_router_is_none(tmp_path):
    """
    V4 Regression: _handle_message() and _on_peer_disconnect() guard against
    _capability_router being None without raising AttributeError.
    """
    p2p, _, storage = _make_node(tmp_path, "cap_none", 19104)
    try:
        assert p2p._capability_router is None
        peer = PeerConnection("peer_1", "127.0.0.1", 19105, sock=None)

        p2p._handle_message(peer, {
            "type": MSG_CAPABILITY_ADV,
            "capabilities": [CAP_FULL_NODE],
        })
        p2p._handle_message(peer, {
            "type": MSG_CAPABILITY_QUERY,
            "capability": CAP_FULL_NODE,
        })
        p2p.peers["peer_1"] = peer
        p2p._on_peer_disconnect(peer)
    finally:
        storage.close()


def test_capability_adv_validates_payload_type(tmp_path):
    """
    V4 Regression: MSG_CAPABILITY_ADV validates that capabilities is a list/set/tuple
    of strings, ignoring invalid types without crashing or splitting strings into chars.
    """
    p2p, _, storage = _make_node(tmp_path, "cap_type", 19106)
    p2p._capability_router = CapabilityRouter(storage)
    p2p._reputation_mgr = PeerReputationManager(storage)
    try:
        peer = PeerConnection("peer_2", "127.0.0.1", 19107, sock=None)

        # Non-iterable int is safely ignored without TypeError
        p2p._handle_message(peer, {
            "type": MSG_CAPABILITY_ADV,
            "capabilities": 12345,
        })

        # String is not split into single-character capabilities
        p2p._handle_message(peer, {
            "type": MSG_CAPABILITY_ADV,
            "capabilities": "archive",
        })
        assert "peer_2" not in p2p._capability_router.find_peers_with("a")
        assert "peer_2" not in p2p._capability_router.find_peers_with("r")
    finally:
        storage.close()
