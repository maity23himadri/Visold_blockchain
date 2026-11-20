import hashlib
import json
import os
import socket
import sys
import tempfile
import threading
import time

import pytest

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.messages import MSG_ACCEPT, MSG_HELLO, MSG_REJECT, MSG_VERIFY
from visold.network.capabilities import CapabilityRouter
from visold.network.p2p import P2PNetwork
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


class _DummyBlockchain:
    def __init__(self, storage):
        self.storage = storage

    def height(self):
        return 0

    def get_block(self, h):
        return None


def _recv_json_line(sock, buf: bytearray, timeout: float = 5.0):
    sock.settimeout(timeout)
    deadline = time.monotonic() + timeout
    while True:
        nl = buf.find(b"\n")
        if nl != -1:
            line = bytes(buf[:nl])
            del buf[: nl + 1]
            if line:
                return json.loads(line.decode("utf-8"))
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise TimeoutError("Timed out waiting for JSON line")
        sock.settimeout(rem)
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("Socket closed before newline")
        buf.extend(chunk)


def _send_json_line(sock, obj: dict):
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def test_inbound_handshake_rejects_peer_id_spoofing_and_preserves_victim():
    """
    V4 Regression: _handle_inbound() verifies node_id == sha256(pub_hex.encode()).
    An attacker claiming victim_node_id with attacker_wallet.pub_hex is rejected
    with MSG_REJECT and cannot evict the legitimate victim peer.
    """
    orig_ice = Config.ICE_ENABLED
    orig_pow = Config.PEER_POW_DIFFICULTY
    Config.ICE_ENABLED = False
    Config.PEER_POW_DIFFICULTY = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(db_path=os.path.join(tmpdir, "srv.db"))
        try:
            while True:
                srv_wallet = Wallet.generate()
                srv_node_id = sha256(srv_wallet.pub_hex.encode())
                victim_wallet = Wallet.generate()
                victim_node_id = sha256(victim_wallet.pub_hex.encode())
                if srv_node_id > victim_node_id:
                    break

            attacker_wallet = Wallet.generate()
            attacker_node_id = sha256(attacker_wallet.pub_hex.encode())
            assert attacker_node_id != victim_node_id

            p2p = P2PNetwork(
                _DummyBlockchain(storage),
                srv_wallet,
                storage,
                port=18440,
                node_id=srv_node_id,
            )
            p2p._running = True
            p2p._capability_router = CapabilityRouter(storage)

            class _FakeVictimPeer:
                def __init__(self):
                    self.peer_id = victim_node_id
                    self.ip = "127.0.0.2"
                    self.port = 18338
                    self.connected = True
                    self.local_outbound = True
                    self.closed = False

                def close(self):
                    self.connected = False
                    self.closed = True

                def send(self, msg):
                    pass

            real_victim = _FakeVictimPeer()
            with p2p._lock:
                p2p.peers[victim_node_id] = real_victim

            srv_sock, cli_sock = socket.socketpair()
            t = threading.Thread(
                target=p2p._handle_inbound,
                args=(srv_sock, ("127.0.0.1", 55555)),
                daemon=True,
            )
            t.start()

            try:
                buf = bytearray()
                _send_json_line(cli_sock, {
                    "type": MSG_HELLO,
                    "node_id": victim_node_id,
                    "pub_hex": attacker_wallet.pub_hex,
                    "version": Config.VERSION,
                    "listen_port": 18339,
                    "capabilities": [],
                })

                reply = _recv_json_line(cli_sock, buf)
                assert reply["type"] == MSG_REJECT, (
                    f"Expected MSG_REJECT for spoofed node_id, got {reply}"
                )

                with p2p._lock:
                    cur = p2p.peers.get(victim_node_id)
                assert cur is real_victim, "Legitimate victim peer must not be evicted"
                assert real_victim.closed is False
            finally:
                p2p._running = False
                for sock_attr in ("_listen_sock", "_udp"):
                    obj = getattr(p2p, sock_attr, None)
                    if obj is not None:
                        try:
                            obj.close()
                        except Exception:
                            pass
                try:
                    cli_sock.close()
                except Exception:
                    pass
                t.join(timeout=2.0)
        finally:
            Config.ICE_ENABLED = orig_ice
            Config.PEER_POW_DIFFICULTY = orig_pow
            storage.close()


def test_outbound_handshake_rejects_mismatched_server_identity():
    """
    V4 Regression: connect_to() verifies node_id == sha256(pub_hex.encode())
    and rejects a server whose ACCEPT node_id does not match its pub_hex.
    """
    orig_ice = Config.ICE_ENABLED
    orig_pow = Config.PEER_POW_DIFFICULTY
    Config.ICE_ENABLED = False
    Config.PEER_POW_DIFFICULTY = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(db_path=os.path.join(tmpdir, "cli.db"))
        try:
            cli_wallet = Wallet.generate()
            cli_node_id = sha256(cli_wallet.pub_hex.encode())
            victim_wallet = Wallet.generate()
            victim_node_id = sha256(victim_wallet.pub_hex.encode())
            attacker_wallet = Wallet.generate()

            p2p = P2PNetwork(
                _DummyBlockchain(storage),
                cli_wallet,
                storage,
                port=18450,
                node_id=cli_node_id,
            )
            p2p._running = True

            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]

            from visold.network import tls as tls_mod
            orig_client_ctx = tls_mod.TLSManager.client_context
            tls_mod.TLSManager.client_context = staticmethod(lambda: None)

            p2p._capability_router = CapabilityRouter(storage)
            done_evt = threading.Event()

            def rogue_server():
                conn, _ = srv.accept()
                try:
                    buf = bytearray()
                    _send_json_line(conn, {"type": MSG_HELLO})
                    hello = _recv_json_line(conn, buf)
                    assert hello["type"] == MSG_HELLO

                    _send_json_line(conn, {
                        "type": MSG_VERIFY,
                        "challenge": "deadbeef" * 4,
                        "tls_fp": "",
                        "node_id": victim_node_id,
                    })
                    resp = _recv_json_line(conn, buf)
                    assert resp["type"] == "CHALLENGE_RESP"

                    # Mismatched node_id vs pub_hex must be rejected
                    _send_json_line(conn, {
                        "type": MSG_ACCEPT,
                        "node_id": victim_node_id,
                        "pub_hex": attacker_wallet.pub_hex,
                        "version": Config.VERSION,
                        "tls_fp": "",
                        "capabilities": ["full_node"],
                        "chain_height": 0,
                        "chain_tip_hash": "0" * 64,
                        "udp_port": port,
                    })
                    done_evt.wait(timeout=1.0)
                finally:
                    conn.close()

            st = threading.Thread(target=rogue_server, daemon=True)
            st.start()

            try:
                ok = p2p.connect_to("127.0.0.1", port)
                assert ok is False
                with p2p._lock:
                    assert victim_node_id not in p2p.peers
            finally:
                p2p._running = False
                done_evt.set()
                tls_mod.TLSManager.client_context = orig_client_ctx
                with p2p._lock:
                    for p in list(p2p.peers.values()):
                        try:
                            p.close()
                        except Exception:
                            pass
                srv.close()
                st.join(timeout=2.0)
        finally:
            Config.ICE_ENABLED = orig_ice
            Config.PEER_POW_DIFFICULTY = orig_pow
            storage.close()


def test_outbound_handshake_requires_server_signature_for_public_key():
    """A rogue server supplying victim's public key without private key proof must be rejected."""
    import json, socket, threading
    from visold.network import tls as tls_mod
    victim = Wallet.generate()
    victim_node_id = sha256(victim.pub_hex.encode())
    cli_wallet = Wallet.generate()
    cli_node_id = sha256(cli_wallet.pub_hex.encode())
    orig_ice = Config.ICE_ENABLED
    orig_pow = Config.PEER_POW_DIFFICULTY
    orig_client_ctx = tls_mod.TLSManager.client_context
    Config.ICE_ENABLED = False
    Config.PEER_POW_DIFFICULTY = 0
    tls_mod.TLSManager.client_context = staticmethod(lambda: None)
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(db_path=os.path.join(tmpdir, "cli.db"))
        p2p = P2PNetwork(_DummyBlockchain(storage), cli_wallet, storage, port=18451, node_id=cli_node_id)
        p2p._running = True
        p2p._capability_router = CapabilityRouter(storage)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def rogue_server():
            conn, _ = srv.accept()
            with conn:
                f = conn.makefile("r")
                conn.sendall((json.dumps({"type": "HELLO", "node_id": victim_node_id}) + "\n").encode())
                f.readline()  # client HELLO
                conn.sendall((json.dumps({"type": "VERIFY", "challenge": "c" * 32, "node_id": victim_node_id}) + "\n").encode())
                f.readline()  # client CHALLENGE_RESP
                conn.sendall((json.dumps({
                    "type": "ACCEPT",
                    "node_id": victim_node_id,
                    "pub_hex": victim.pub_hex,
                    "sig": "",
                }) + "\n").encode())

        t = threading.Thread(target=rogue_server, daemon=True)
        t.start()
        try:
            assert p2p.connect_to("127.0.0.1", port) is False
        finally:
            p2p._running = False
            Config.ICE_ENABLED = orig_ice
            Config.PEER_POW_DIFFICULTY = orig_pow
            tls_mod.TLSManager.client_context = orig_client_ctx
            srv.close()
            t.join(timeout=2)
            storage.close()


def test_core_capability_router_invariants():
    """Verify CapabilityRouter record, query, and peer removal."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(db_path=os.path.join(tmpdir, "cap.db"))
        try:
            router = CapabilityRouter(storage)
            router.record_peer_capabilities("peer_1", ["full_node", "vvm"])
            router.record_peer_capabilities("peer_2", ["full_node"])
            assert set(router.find_peers_with("full_node")) == {"peer_1", "peer_2"}
            assert router.find_peers_with("vvm") == ["peer_1"]
            router.remove_peer("peer_1")
            assert router.find_peers_with("vvm") == []
            assert router.find_peers_with("full_node") == ["peer_2"]
        finally:
            storage.close()
