"""V4 Regression tests for Section 104: TCP Peer Connections, Reconnection & Connection Lifecycle."""

from __future__ import annotations

import os
import socket
import ssl
import sys
import tempfile
import threading
import time
from collections import defaultdict, deque
from unittest.mock import patch

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.netutil import _create_dual_stack_server_socket, wildcard_for_family
from visold.network.p2p import (
    MSG_ACCEPT,
    MSG_HELLO,
    MSG_REJECT,
    MSG_VERIFY,
    P2PNetwork,
)
from visold.network.peer_connection import PeerConnection
from visold.network.tls import TLSManager
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_minimal_p2p(td: str, wallet: Wallet, port: int = 18338) -> P2PNetwork:
    """Create a P2PNetwork instance backed by a real temp Storage without starting server loops."""
    st = Storage(os.path.join(td, f"{wallet.address[:8]}.db"))
    net = object.__new__(P2PNetwork)
    net.wallet = wallet
    net.storage = st
    net.node_id = sha256(wallet.pub_hex.encode())
    net.port = port
    net._running = True
    net._lock = threading.RLock()
    net._pending_lock = threading.Lock()
    net._pending_connections = set()
    net._pending_peer_ids = set()
    net._outbound_fail_lock = threading.Lock()
    net._outbound_fail = {}
    net._conn_rate = defaultdict(deque)
    net._CONN_RATE_WINDOW = 60.0
    net._CONN_RATE_LIMIT = 100
    net.peers = {}
    net._eager_peers = set()
    net._peer_admission_reservations = {}
    net._untrusted_rate_lock = threading.Lock()
    net._untrusted_rate = {}
    net._compact_stash_lock = threading.Lock()
    net._compact_stash = {}
    net._callbacks = defaultdict(list)
    net._topology_reports = {}
    net.router = type("R", (), {"update": lambda *a, **k: None, "remove": lambda *a, **k: None})()
    net.blockchain = type(
        "BC",
        (),
        {
            "height": lambda self: 0,
            "get_block": lambda self, h: None,
        },
    )()
    net._peer_capacity_limit = lambda: 32
    net._peer_subnet_limit = lambda: 8
    net._peer_subnet = lambda ip: ip
    net._topology_prune_cooldown_active = lambda pid: False
    net._is_ip_banned = lambda ip: False
    net._auto_sync_on_connect = lambda peer: None
    net._LISTEN_PORT_SEARCH = 4
    net._rpc_port_is_available = lambda p: True
    return net


def test_handle_inbound_pre_auth_tofu_tls_fp_not_poisoned():
    """V4 Regression: Unauthenticated MSG_HELLO must not persist tls_fp before ECDSA verification."""
    with tempfile.TemporaryDirectory() as td:
        server_wallet = Wallet.generate()
        victim_wallet = Wallet.generate()
        victim_node_id = sha256(victim_wallet.pub_hex.encode())
        net = _make_minimal_p2p(td, server_wallet)

        net.storage._conn().execute(
            "INSERT INTO peers (peer_id, ip, port, tls_fp) VALUES (?, ?, ?, ?)",
            (victim_node_id, "198.51.100.20", 8338, ""),
        )
        net.storage._conn().commit()
        assert net.storage.get_peer_tls_fp(victim_node_id) is None

        s_srv, s_cli = socket.socketpair()
        orig_pow = Config.PEER_POW_DIFFICULTY
        Config.PEER_POW_DIFFICULTY = 0
        try:
            with patch.object(TLSManager, "server_context", return_value=object()), \
                 patch.object(net, "_wrap_inbound_tls", side_effect=lambda s, ctx, ip: s), \
                 patch.object(TLSManager, "fingerprint", return_value="aa" * 32):
                t = threading.Thread(
                    target=net._handle_inbound,
                    args=(s_srv, ("192.0.2.50", 40001)),
                    daemon=True,
                )
                t.start()

                cli = PeerConnection("att", "192.0.2.50", 40001, s_cli)
                attacker_fp = "de" * 32
                cli.send({
                    "type": MSG_HELLO,
                    "node_id": victim_node_id,
                    "pub_hex": victim_wallet.pub_hex,
                    "tls_fp": attacker_fp,
                    "listen_port": 8338,
                })
                verify_msg = cli.recv_line(timeout=3.0)
                assert verify_msg is not None and verify_msg["type"] == MSG_VERIFY

                cli.close()
                t.join(timeout=3.0)

            assert net.storage.get_peer_tls_fp(victim_node_id) is None
        finally:
            Config.PEER_POW_DIFFICULTY = orig_pow
            try:
                s_srv.close()
            except Exception:
                pass
            try:
                s_cli.close()
            except Exception:
                pass


def test_handle_inbound_impersonation_rejected_and_honest_peer_preserved():
    """V4 Regression: _handle_inbound rejects node_id != sha256(pub_hex) and preserves honest peer."""
    with tempfile.TemporaryDirectory() as td:
        w1 = Wallet.generate()
        w2 = Wallet.generate()
        id1 = sha256(w1.pub_hex.encode())
        id2 = sha256(w2.pub_hex.encode())
        if id1 > id2:
            server_wallet, victim_wallet = w1, w2
        else:
            server_wallet, victim_wallet = w2, w1
        victim_node_id = sha256(victim_wallet.pub_hex.encode())

        attacker_wallet = Wallet.generate()
        net = _make_minimal_p2p(td, server_wallet)
        assert net.node_id > victim_node_id

        real_victim_fp = "11" * 32
        net.storage._conn().execute(
            "INSERT INTO peers (peer_id, ip, port, tls_fp) VALUES (?, ?, ?, ?)",
            (victim_node_id, "198.51.100.10", 8338, real_victim_fp),
        )
        net.storage._conn().commit()

        honest_srv, honest_cli = socket.socketpair()
        honest_peer = PeerConnection(victim_node_id, "198.51.100.10", 8338, honest_srv)
        honest_peer.local_outbound = True
        net.peers[victim_node_id] = honest_peer

        s_srv, s_cli = socket.socketpair()
        orig_pow = Config.PEER_POW_DIFFICULTY
        Config.PEER_POW_DIFFICULTY = 0
        try:
            with patch.object(TLSManager, "server_context", return_value=object()), \
                 patch.object(net, "_wrap_inbound_tls", side_effect=lambda s, ctx, ip: s), \
                 patch.object(TLSManager, "fingerprint", return_value="aa" * 32), \
                 patch.object(net, "_peer_message_loop", return_value=None):
                t = threading.Thread(
                    target=net._handle_inbound,
                    args=(s_srv, ("192.0.2.99", 41111)),
                    daemon=True,
                )
                t.start()

                cli = PeerConnection("att", "192.0.2.99", 41111, s_cli)
                cli.send({
                    "type": MSG_HELLO,
                    "node_id": victim_node_id,
                    "pub_hex": attacker_wallet.pub_hex,
                    "tls_fp": "",
                    "listen_port": 8338,
                })
                reply = cli.recv_line(timeout=3.0)
                assert reply is not None and reply["type"] == MSG_REJECT
                t.join(timeout=3.0)

                assert honest_peer.connected is True
                assert net.peers.get(victim_node_id) is honest_peer
                cli.close()
        finally:
            Config.PEER_POW_DIFFICULTY = orig_pow
            honest_peer.close()
            try:
                honest_cli.close()
            except Exception:
                pass


def _generate_self_signed_cert(cert_path: str, key_path: str) -> str:
    """Generate a temporary self-signed TLS cert+key and return its SHA-256 hex fingerprint."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "visold-test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    return cert.fingerprint(hashes.SHA256()).hex()


def test_connect_to_rejects_omitted_tls_fp_when_pinned():
    """V4 Regression: Outbound connect_to() enforces pinned TLS cert fingerprint even if tls_fp=''."""
    with tempfile.TemporaryDirectory() as td:
        client_wallet = Wallet.generate()
        victim_wallet = Wallet.generate()
        victim_node_id = sha256(victim_wallet.pub_hex.encode())

        net = _make_minimal_p2p(td, client_wallet)
        pinned_fp = "ff" * 32
        net.storage._conn().execute(
            "INSERT INTO peers (peer_id, ip, port, tls_fp) VALUES (?, ?, ?, ?)",
            (victim_node_id, "127.0.0.1", 8338, pinned_fp),
        )
        net.storage._conn().commit()
        assert net.storage.get_peer_tls_fp(victim_node_id) == pinned_fp

        cert_path = os.path.join(td, "mitm.crt")
        key_path = os.path.join(td, "mitm.key")
        mitm_fp = _generate_self_signed_cert(cert_path, key_path)
        assert mitm_fp != pinned_fp

        srv_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv_ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

        cli_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cli_ssl_ctx.check_hostname = False
        cli_ssl_ctx.verify_mode = ssl.CERT_NONE

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def _mitm_server():
            raw, _ = listener.accept()
            tls_conn = srv_ssl_ctx.wrap_socket(raw, server_side=True)
            pc = PeerConnection("srv", "127.0.0.1", port, tls_conn)
            try:
                pc.send({"type": MSG_HELLO})
                hello = pc.recv_line(timeout=3.0)
                if hello and hello["type"] == MSG_HELLO:
                    pc.send({
                        "type": MSG_VERIFY,
                        "challenge": "mitm_challenge",
                        "tls_fp": "",
                        "node_id": victim_node_id,
                    })
                    pc.recv_line(timeout=1.0)
            finally:
                pc.close()

        t = threading.Thread(target=_mitm_server, daemon=True)
        t.start()

        orig_ice = Config.ICE_ENABLED
        orig_pow = Config.PEER_POW_DIFFICULTY
        Config.ICE_ENABLED = False
        Config.PEER_POW_DIFFICULTY = 0
        try:
            with patch.object(TLSManager, "client_context", return_value=cli_ssl_ctx), \
                 patch.object(TLSManager, "bootstrap_fingerprint_for_endpoint", return_value=""), \
                 patch.object(TLSManager, "fingerprint", return_value="cc" * 32), \
                 patch.object(net, "_peer_message_loop", return_value=None):
                ok = net.connect_to("127.0.0.1", port)
                assert ok is False
                assert victim_node_id not in net.peers
        finally:
            Config.ICE_ENABLED = orig_ice
            Config.PEER_POW_DIFFICULTY = orig_pow
            listener.close()
            t.join(timeout=3.0)


def test_dual_stack_server_socket_supports_ipv4_bind_address():
    """V4 Regression: _create_dual_stack_server_socket creates AF_INET when bind_addr is IPv4."""
    orig_bind = Config.BIND_ADDRESS
    Config.BIND_ADDRESS = "127.0.0.1"
    srv = None
    try:
        srv = _create_dual_stack_server_socket(0, bind_addr="127.0.0.1")
        assert srv.family == socket.AF_INET
        bind_host = wildcard_for_family(srv.family, Config.BIND_ADDRESS)
        assert bind_host == "127.0.0.1"
        srv.bind((bind_host, 0))
    finally:
        Config.BIND_ADDRESS = orig_bind
        if srv is not None:
            srv.close()
