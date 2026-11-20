"""Section 101 V4 Regression Tests: Peer Handshake, Identity Verification, Capability Negotiation."""

import json
import os
import socket
import sys
import threading
import types

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.messages import MSG_ACCEPT, MSG_HELLO, MSG_REJECT, MSG_VERIFY
from visold.network.p2p import P2PNetwork
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_p2p(tmp_path, name, port, monkeypatch):
    monkeypatch.setattr(Config, "PEER_POW_DIFFICULTY", 0)
    monkeypatch.setattr(Config, "ICE_ENABLED", False)
    monkeypatch.setattr(Config, "UPNP_ENABLED", False)
    st = Storage(str(tmp_path / f"{name}.db"))
    w = Wallet.generate()
    bc = types.SimpleNamespace(
        height=lambda: 0,
        latest_block=lambda: types.SimpleNamespace(block_hash="0" * 64),
        get_block=lambda _i: None,
        mempool=types.SimpleNamespace(all_txs=lambda: []),
    )
    net = P2PNetwork(bc, w, st, port=port)
    net._running = True
    return net, st, w


def _send_line(sock: socket.socket, obj: dict):
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def _recv_line(sock: socket.socket) -> dict:
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("socket closed")
        buf += chunk
    line, _ = buf.split(b"\n", 1)
    return json.loads(line.decode("utf-8"))


def test_inbound_pre_auth_tofu_tls_fp_not_poisoned(tmp_path, monkeypatch):
    """V4 Regression: Unauthenticated MSG_HELLO must not persist tls_fp before ECDSA verification."""
    net, st, _ = _make_p2p(tmp_path, "srv_tofu", 19101, monkeypatch)
    try:
        monkeypatch.setattr("visold.network.p2p.TLSManager.server_context", staticmethod(lambda: object()))
        monkeypatch.setattr(net, "_wrap_inbound_tls", lambda s, _ctx, _ip: s)
        monkeypatch.setattr(net, "_tcp_admit_inbound", lambda _ip: True)

        victim_wallet = Wallet.generate()
        victim_peer_id = sha256(victim_wallet.pub_hex.encode())
        st.save_peer(victim_peer_id, "10.0.0.1", 8333)
        poisoned_fp = "deadbeef" * 8
        assert not st.get_peer_tls_fp(victim_peer_id)

        s_srv, s_cli = socket.socketpair()
        t = threading.Thread(
            target=net._handle_inbound,
            args=(s_srv, ("127.0.0.1", 12345)),
            daemon=True,
        )
        t.start()
        try:
            _send_line(s_cli, {
                "type": MSG_HELLO,
                "node_id": victim_peer_id,
                "pub_hex": victim_wallet.pub_hex,
                "tls_fp": poisoned_fp,
            })
            verify_msg = _recv_line(s_cli)
            assert verify_msg["type"] == MSG_VERIFY
        finally:
            s_cli.close()
            t.join(timeout=3)

        assert not st.get_peer_tls_fp(victim_peer_id)
    finally:
        net.stop()


def test_inbound_peer_id_spoofing_rejected(tmp_path, monkeypatch):
    """V4 Regression: _handle_inbound() rejects HELLO when node_id != sha256(pub_hex.encode())."""
    net, _st, _ = _make_p2p(tmp_path, "srv_spoof", 19111, monkeypatch)
    try:
        monkeypatch.setattr("visold.network.p2p.TLSManager.server_context", staticmethod(lambda: None))
        monkeypatch.setattr(net, "_tcp_admit_inbound", lambda _ip: True)

        attacker = Wallet.generate()
        victim_node_id = sha256(Wallet.generate().pub_hex.encode())
        assert victim_node_id != sha256(attacker.pub_hex.encode())

        s_srv, s_cli = socket.socketpair()
        t = threading.Thread(
            target=net._handle_inbound,
            args=(s_srv, ("127.0.0.1", 12346)),
            daemon=True,
        )
        t.start()
        try:
            _send_line(s_cli, {
                "type": MSG_HELLO,
                "node_id": victim_node_id,
                "pub_hex": attacker.pub_hex,
                "listen_port": 8333,
            })
            reply = _recv_line(s_cli)
            assert reply["type"] == MSG_REJECT
            assert victim_node_id not in net.peers
        finally:
            s_cli.close()
            t.join(timeout=3)
    finally:
        net.stop()


def test_outbound_connect_to_rejects_empty_pub_hex(tmp_path, monkeypatch):
    """V4 Regression: connect_to() rejects MSG_ACCEPT with empty pub_hex."""
    client_net, _st, _ = _make_p2p(tmp_path, "cli_noauth", 19121, monkeypatch)
    try:
        monkeypatch.setattr("visold.network.p2p.TLSManager.client_context", staticmethod(lambda: None))

        spoofed_server_id = sha256(Wallet.generate().pub_hex.encode())
        s_cli, s_srv = socket.socketpair()
        monkeypatch.setattr(
            "visold.network.p2p._create_connection_dual_stack",
            lambda _ip, _port, _timeout: s_cli,
        )
        done_evt = threading.Event()

        def _malicious_server():
            try:
                _send_line(s_srv, {"type": MSG_HELLO})
                hello = _recv_line(s_srv)
                assert hello["type"] == MSG_HELLO
                _send_line(s_srv, {
                    "type": MSG_VERIFY,
                    "challenge": "deadbeef" * 4,
                    "node_id": spoofed_server_id,
                    "tls_fp": "",
                })
                resp = _recv_line(s_srv)
                assert resp["type"] == "CHALLENGE_RESP"
                _send_line(s_srv, {
                    "type": MSG_ACCEPT,
                    "node_id": spoofed_server_id,
                    "pub_hex": "",
                    "tls_fp": "",
                })
                done_evt.wait(timeout=3)
            finally:
                s_srv.close()

        srv_thread = threading.Thread(target=_malicious_server, daemon=True)
        srv_thread.start()
        ok = client_net.connect_to("127.0.0.1", 8333)
        assert ok is False
        assert spoofed_server_id not in client_net.peers
        done_evt.set()
        srv_thread.join(timeout=3)
    finally:
        client_net.stop()
