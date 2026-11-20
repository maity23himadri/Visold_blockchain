"""V4 Regression Section 108 tests: TLS Security, Certificate Validation, Connection Authentication."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.crypto.ecc import sig_to_hex
from visold.kernel.config import Config
from visold.kernel.messages import (
    MSG_ACCEPT,
    MSG_HELLO,
    MSG_POW_CHALLENGE,
    MSG_REJECT,
    MSG_VERIFY,
)
from visold.network.compression import CompressionEngine
from visold.network.p2p import P2PNetwork
from visold.network.tls import TLSManager
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


class _DummyBlockchain:
    def height(self) -> int:
        return 0

    def get_tip(self):
        return None


def _make_node(td: str, name: str, port: int = 19000):
    st = Storage(os.path.join(td, f"{name}.db"))
    wallet = Wallet.generate()
    net = P2PNetwork(_DummyBlockchain(), wallet, st, port=port)
    return net, st, wallet


def _make_tls_contexts(td: str, prefix: str):
    cert = os.path.join(td, f"{prefix}_cert.pem")
    key = os.path.join(td, f"{prefix}_key.pem")
    TLSManager._generate_cert(cert, key)
    with open(cert, "rb") as f:
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509 import load_pem_x509_certificate
        fp = load_pem_x509_certificate(f.read()).fingerprint(hashes.SHA256()).hex()
    srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv.minimum_version = ssl.TLSVersion.TLSv1_2
    srv.load_cert_chain(cert, key)
    srv.check_hostname = False
    srv.verify_mode = ssl.CERT_NONE

    cli = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cli.minimum_version = ssl.TLSVersion.TLSv1_2
    cli.load_cert_chain(cert, key)
    cli.check_hostname = False
    cli.verify_mode = ssl.CERT_NONE
    return srv, cli, fp


def _send_frame(sock, msg: dict) -> None:
    raw = json.dumps(msg).encode()
    sock.sendall(CompressionEngine.compress(raw) + b"\n")


def _recv_frame(sock, buf: bytearray) -> dict:
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("socket closed")
        buf.extend(chunk)
    idx = buf.index(b"\n")
    line = bytes(buf[:idx])
    del buf[: idx + 1]
    return json.loads(CompressionEngine.decompress(line).decode())


def _tcp_pair():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    cli = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    conn, addr = srv.accept()
    srv.close()
    return conn, addr, cli, port


def test_first_connection_tls_fp_persisted_inbound(monkeypatch):
    """V4 Regression: _handle_inbound persists peer TLS fingerprint after save_peer."""
    with tempfile.TemporaryDirectory() as td:
        net, st, _ = _make_node(td, "srv", port=19101)
        srv_ctx, cli_ctx, srv_fp = _make_tls_contexts(td, "srv")
        _, _, cli_fp = _make_tls_contexts(td, "cli")
        client_wallet = Wallet.generate()
        client_id = hashlib.sha256(client_wallet.pub_hex.encode()).hexdigest()

        monkeypatch.setattr(Config, "TLS_ENABLED", True)
        monkeypatch.setattr(Config, "PEER_POW_DIFFICULTY", 0)
        monkeypatch.setattr(Config, "ICE_ENABLED", False)
        monkeypatch.setattr(TLSManager, "server_context", classmethod(lambda cls: srv_ctx))
        monkeypatch.setattr(TLSManager, "fingerprint", classmethod(lambda cls: srv_fp))

        conn, addr, cli_raw, _ = _tcp_pair()
        t = threading.Thread(target=net._handle_inbound, args=(conn, addr), daemon=True)
        t.start()

        cli = cli_ctx.wrap_socket(cli_raw, server_hostname=None)
        buf = bytearray()
        _send_frame(cli, {
            "type": MSG_HELLO,
            "node_id": client_id,
            "pub_hex": client_wallet.pub_hex,
            "tls_fp": cli_fp,
            "listen_port": 19102,
        })
        verify_msg = _recv_frame(cli, buf)
        assert verify_msg["type"] == MSG_VERIFY
        sig = client_wallet.sign(verify_msg["challenge"].encode())
        _send_frame(cli, {"type": "CHALLENGE_RESP", "sig": sig_to_hex(sig)})
        accept_msg = _recv_frame(cli, buf)
        assert accept_msg["type"] == MSG_ACCEPT
        cli.close()
        t.join(timeout=5.0)

        assert st.get_peer_tls_fp(client_id) == cli_fp


def test_first_connection_tls_fp_persisted_outbound(monkeypatch):
    """V4 Regression: connect_to persists peer TLS fingerprint after save_peer."""
    with tempfile.TemporaryDirectory() as td:
        net, st, _ = _make_node(td, "cli", port=19103)
        srv_ctx, cli_ctx, srv_fp = _make_tls_contexts(td, "srv")
        srv_wallet = Wallet.generate()
        srv_id = hashlib.sha256(srv_wallet.pub_hex.encode()).hexdigest()

        monkeypatch.setattr(Config, "TLS_ENABLED", True)
        monkeypatch.setattr(Config, "PEER_POW_DIFFICULTY", 0)
        monkeypatch.setattr(Config, "ICE_ENABLED", False)
        monkeypatch.setattr(TLSManager, "client_context", classmethod(lambda cls: cli_ctx))
        monkeypatch.setattr(TLSManager, "fingerprint", classmethod(lambda cls: "00" * 32))
        monkeypatch.setattr(net, "_auto_sync_on_connect", lambda *a, **kw: None, raising=False)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def server_fn():
            conn, _ = listener.accept()
            s = srv_ctx.wrap_socket(conn, server_side=True)
            buf = bytearray()
            try:
                _send_frame(s, {"type": MSG_POW_CHALLENGE, "challenge": "", "difficulty": 0})
                hello = _recv_frame(s, buf)
                assert hello["type"] == MSG_HELLO
                _send_frame(s, {
                    "type": MSG_VERIFY,
                    "challenge": "deadbeef",
                    "tls_fp": srv_fp,
                    "node_id": srv_id,
                })
                resp = _recv_frame(s, buf)
                assert resp["type"] == "CHALLENGE_RESP"
                _send_frame(s, {
                    "type": MSG_ACCEPT,
                    "node_id": srv_id,
                    "pub_hex": srv_wallet.pub_hex,
                    "tls_fp": srv_fp,
                })
                time.sleep(0.3)
            finally:
                s.close()
                listener.close()

        t = threading.Thread(target=server_fn, daemon=True)
        t.start()
        ok = net.connect_to("127.0.0.1", port)
        t.join(timeout=5.0)
        if srv_id in net.peers:
            net.peers[srv_id].close()

        assert ok is True
        assert st.get_peer_tls_fp(srv_id) == srv_fp


def test_connect_to_empty_tls_fp_rejected_when_pinned(monkeypatch):
    """V4 Regression: Omitting tls_fp in MSG_VERIFY is rejected against pinned TLS cert."""
    with tempfile.TemporaryDirectory() as td:
        net, st, _ = _make_node(td, "cli", port=19104)
        srv_ctx, cli_ctx, _ = _make_tls_contexts(td, "mitm_srv")
        srv_wallet = Wallet.generate()
        srv_id = hashlib.sha256(srv_wallet.pub_hex.encode()).hexdigest()

        st.save_peer(srv_id, "127.0.0.1", 19105)
        st.set_peer_tls_fp(srv_id, "aa" * 32)

        monkeypatch.setattr(Config, "TLS_ENABLED", True)
        monkeypatch.setattr(Config, "PEER_POW_DIFFICULTY", 0)
        monkeypatch.setattr(Config, "ICE_ENABLED", False)
        monkeypatch.setattr(TLSManager, "client_context", classmethod(lambda cls: cli_ctx))
        monkeypatch.setattr(TLSManager, "fingerprint", classmethod(lambda cls: "00" * 32))

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def mitm_server():
            conn, _ = listener.accept()
            s = srv_ctx.wrap_socket(conn, server_side=True)
            buf = bytearray()
            try:
                _send_frame(s, {"type": MSG_POW_CHALLENGE, "challenge": "", "difficulty": 0})
                _recv_frame(s, buf)
                _send_frame(s, {
                    "type": MSG_VERIFY,
                    "challenge": "cafebabe",
                    "tls_fp": "",
                    "node_id": srv_id,
                })
                _recv_frame(s, buf)
            except EOFError:
                pass
            finally:
                s.close()
                listener.close()

        t = threading.Thread(target=mitm_server, daemon=True)
        t.start()
        ok = net.connect_to("127.0.0.1", port)
        t.join(timeout=5.0)
        if srv_id in net.peers:
            net.peers[srv_id].close()

        assert ok is False


def test_handle_inbound_empty_tls_fp_rejected_when_pinned(monkeypatch):
    """V4 Regression: Omitting tls_fp in MSG_HELLO is rejected with MSG_REJECT when pinned."""
    with tempfile.TemporaryDirectory() as td:
        net, st, _ = _make_node(td, "srv", port=19106)
        srv_ctx, cli_ctx, srv_fp = _make_tls_contexts(td, "srv")
        client_wallet = Wallet.generate()
        client_id = hashlib.sha256(client_wallet.pub_hex.encode()).hexdigest()

        st.save_peer(client_id, "127.0.0.1", 19107)
        st.set_peer_tls_fp(client_id, "bb" * 32)

        monkeypatch.setattr(Config, "TLS_ENABLED", True)
        monkeypatch.setattr(Config, "PEER_POW_DIFFICULTY", 0)
        monkeypatch.setattr(Config, "ICE_ENABLED", False)
        monkeypatch.setattr(TLSManager, "server_context", classmethod(lambda cls: srv_ctx))
        monkeypatch.setattr(TLSManager, "fingerprint", classmethod(lambda cls: srv_fp))

        conn, addr, cli_raw, _ = _tcp_pair()
        t = threading.Thread(target=net._handle_inbound, args=(conn, addr), daemon=True)
        t.start()

        cli = cli_ctx.wrap_socket(cli_raw, server_hostname=None)
        buf = bytearray()
        _send_frame(cli, {
            "type": MSG_HELLO,
            "node_id": client_id,
            "pub_hex": client_wallet.pub_hex,
            "tls_fp": "",
            "listen_port": 19107,
        })
        verify_msg = _recv_frame(cli, buf)
        assert verify_msg["type"] == MSG_VERIFY
        sig = client_wallet.sign(verify_msg["challenge"].encode())
        _send_frame(cli, {"type": "CHALLENGE_RESP", "sig": sig_to_hex(sig)})
        reply = _recv_frame(cli, buf)
        assert reply["type"] == MSG_REJECT
        cli.close()
        t.join(timeout=5.0)


def test_handle_inbound_pre_auth_tls_fp_not_poisoned_before_ecdsa(monkeypatch):
    """V4 Regression: Unauthenticated MSG_HELLO cannot overwrite empty tls_fp before ECDSA verify."""
    with tempfile.TemporaryDirectory() as td:
        net, st, _ = _make_node(td, "srv", port=19108)
        srv_ctx, cli_ctx, srv_fp = _make_tls_contexts(td, "srv")
        victim_wallet = Wallet.generate()
        victim_id = hashlib.sha256(victim_wallet.pub_hex.encode()).hexdigest()

        st.save_peer(victim_id, "127.0.0.1", 19109)
        assert st.get_peer_tls_fp(victim_id) is None

        monkeypatch.setattr(Config, "TLS_ENABLED", True)
        monkeypatch.setattr(Config, "PEER_POW_DIFFICULTY", 0)
        monkeypatch.setattr(Config, "ICE_ENABLED", False)
        monkeypatch.setattr(TLSManager, "server_context", classmethod(lambda cls: srv_ctx))
        monkeypatch.setattr(TLSManager, "fingerprint", classmethod(lambda cls: srv_fp))

        conn, addr, cli_raw, _ = _tcp_pair()
        t = threading.Thread(target=net._handle_inbound, args=(conn, addr), daemon=True)
        t.start()

        cli = cli_ctx.wrap_socket(cli_raw, server_hostname=None)
        buf = bytearray()
        attacker_fp = "deadbeef" * 8
        _send_frame(cli, {
            "type": MSG_HELLO,
            "node_id": victim_id,
            "pub_hex": victim_wallet.pub_hex,
            "tls_fp": attacker_fp,
            "listen_port": 19109,
        })
        verify_msg = _recv_frame(cli, buf)
        assert verify_msg["type"] == MSG_VERIFY
        cli.close()
        t.join(timeout=5.0)

        assert st.get_peer_tls_fp(victim_id) is None


def test_handle_inbound_rejects_spoofed_node_id_with_attacker_key(monkeypatch):
    """V4 Regression: _handle_inbound rejects HELLO when node_id != sha256(pub_hex.encode())."""
    with tempfile.TemporaryDirectory() as td:
        net, st, _ = _make_node(td, "srv", port=19110)
        srv_ctx, cli_ctx, srv_fp = _make_tls_contexts(td, "srv")
        victim_id = "ab" * 32
        attacker_wallet = Wallet.generate()
        assert hashlib.sha256(attacker_wallet.pub_hex.encode()).hexdigest() != victim_id

        monkeypatch.setattr(Config, "TLS_ENABLED", True)
        monkeypatch.setattr(Config, "PEER_POW_DIFFICULTY", 0)
        monkeypatch.setattr(Config, "ICE_ENABLED", False)
        monkeypatch.setattr(TLSManager, "server_context", classmethod(lambda cls: srv_ctx))
        monkeypatch.setattr(TLSManager, "fingerprint", classmethod(lambda cls: srv_fp))

        conn, addr, cli_raw, _ = _tcp_pair()
        t = threading.Thread(target=net._handle_inbound, args=(conn, addr), daemon=True)
        t.start()

        cli = cli_ctx.wrap_socket(cli_raw, server_hostname=None)
        buf = bytearray()
        _send_frame(cli, {
            "type": MSG_HELLO,
            "node_id": victim_id,
            "pub_hex": attacker_wallet.pub_hex,
            "tls_fp": "cc" * 32,
            "listen_port": 19111,
        })
        reply = _recv_frame(cli, buf)
        assert reply["type"] == MSG_REJECT
        cli.close()
        t.join(timeout=5.0)

        assert st.get_peers() == []
