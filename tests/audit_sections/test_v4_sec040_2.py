import hashlib
import json
import socket
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from visold.chain.blockchain import Blockchain
from visold.crypto.ecc import ecdsa_sign, ecdsa_keygen, pub_to_hex, sig_to_hex
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.messages import (
    MSG_ACCEPT,
    MSG_CHAIN,
    MSG_HELLO,
    MSG_PING,
    MSG_POW_CHALLENGE,
    MSG_VERIFY,
)
from visold.network.compression import CompressionEngine
from visold.network.p2p import P2PNetwork
from visold.network.peer_connection import PeerConnection
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_node(tmp_path: Path, name: str = "node", port: int = 19100):
    db_path = str(tmp_path / f"{name}.db")
    storage = Storage(db_path)
    priv, pub = ecdsa_keygen()
    wallet = Wallet(priv, pub)
    bc = Blockchain(storage)
    net = P2PNetwork(bc, wallet, storage, port=port)
    return storage, wallet, bc, net


def _recv_json_line(sock: socket.socket, timeout: float = 5.0) -> dict:
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("socket closed")
        buf += chunk
    line, _ = buf.split(b"\n", 1)
    return json.loads(CompressionEngine.decompress(line).decode("utf-8"))


def _send_json_line(sock: socket.socket, obj: dict) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def test_check_msg_rate_applies_ban_penalty_on_burst(tmp_path):
    """
    V4 regression (Finding 1): P2PNetwork._check_msg_rate() enforces the
    hard-breach ban-score penalty when a peer floods beyond _MSG_RATE_GLOBAL.
    """
    storage, _wallet, _bc, net = _make_node(tmp_path, "rate")
    peer = PeerConnection("peer_" + "a" * 59, "127.0.0.1", 9001, sock=None)

    ban_calls = []
    orig_add_ban = storage.add_ban_score

    def spy_add_ban(pid, delta):
        ban_calls.append((pid, delta))
        return orig_add_ban(pid, delta)

    storage.add_ban_score = spy_add_ban

    allowed = 0
    dropped = 0
    total_burst = net._MSG_RATE_GLOBAL * 5
    for _ in range(total_burst):
        if net._check_msg_rate(peer, MSG_PING):
            allowed += 1
        else:
            dropped += 1

    assert allowed == net._MSG_RATE_GLOBAL
    assert dropped == total_burst - net._MSG_RATE_GLOBAL
    assert len(ban_calls) > 0


def test_empty_logic_hash_forces_full_audit_and_logic_hash_ban_works(tmp_path):
    """
    V4 regression (Finding 2):
    (a) Empty `logic_hash` in MSG_HELLO classifies the peer as TRUST_LOW (Full Audit Mode).
    (b) Unknown non-empty `logic_hash` sets `peer.logic_hash`, and strike 3 in
        _soft_ban_record_failure() writes `logic_hash_ban:<hash>`.
    """
    storage, _wallet, _bc, net = _make_node(tmp_path, "lh", port=19110)
    net._running = True

    def _run_inbound_handshake(hello_extra: dict, peer_priv, peer_pub_hex: str, peer_id: str):
        srv_sock, cli_sock = socket.socketpair()
        with patch.object(net, "_peer_message_loop", side_effect=lambda p: None), \
             patch("visold.network.p2p.TLSManager.server_context", return_value=None), \
             patch.object(Config, "PEER_POW_DIFFICULTY", 0):
            t = threading.Thread(
                target=net._handle_inbound,
                args=(srv_sock, ("127.0.0.1", 40000)),
                daemon=True,
            )
            t.start()

            hello = {
                "type": MSG_HELLO,
                "node_id": peer_id,
                "pub_hex": peer_pub_hex,
                "version": Config.VERSION,
                "listen_port": 40001,
            }
            hello.update(hello_extra)
            _send_json_line(cli_sock, hello)

            verify_msg = _recv_json_line(cli_sock)
            assert verify_msg["type"] == MSG_VERIFY
            challenge = verify_msg["challenge"]
            sig = ecdsa_sign(peer_priv, hashlib.sha256(challenge.encode()).digest())
            _send_json_line(cli_sock, {"type": "CHALLENGE_RESP", "sig": sig_to_hex(sig)})

            accept_msg = _recv_json_line(cli_sock)
            assert accept_msg["type"] == MSG_ACCEPT
            t.join(timeout=5.0)
            cli_sock.close()

    # Part (a): empty logic_hash -> TRUST_LOW
    priv1, pub1 = ecdsa_keygen()
    pub1_hex = pub_to_hex(pub1)
    pid1 = sha256(pub1_hex.encode())
    _run_inbound_handshake({"logic_hash": ""}, priv1, pub1_hex, pid1)
    assert pid1 in net.peers
    assert net.peers[pid1].trust_level == PeerConnection.TRUST_LOW

    # Part (b): unknown non-empty logic_hash -> TRUST_LOW, peer.logic_hash set, ban recorded
    priv2, pub2 = ecdsa_keygen()
    pub2_hex = pub_to_hex(pub2)
    pid2 = sha256(pub2_hex.encode())
    unknown_lh = "deadbeef" * 8
    _run_inbound_handshake({"logic_hash": unknown_lh}, priv2, pub2_hex, pid2)
    peer2 = net.peers[pid2]
    assert peer2.trust_level == PeerConnection.TRUST_LOW
    assert getattr(peer2, "logic_hash", None) == unknown_lh

    for _ in range(3):
        net._soft_ban_record_failure(peer2, "MSG_BLOCK")
    assert storage.get_meta(f"logic_hash_ban:{unknown_lh}") is not None


def test_inbound_handshake_rejects_unbound_node_id_spoofing(tmp_path):
    """
    V4 regression (Finding 3): _handle_inbound() rejects a peer whose `node_id`
    does not match sha256(pub_hex.encode()).
    """
    _storage, _wallet, _bc, net = _make_node(tmp_path, "spoof", port=19120)
    net._running = True

    _attacker_priv, attacker_pub = ecdsa_keygen()
    attacker_pub_hex = pub_to_hex(attacker_pub)
    victim_node_id = "f" * 64
    assert victim_node_id != sha256(attacker_pub_hex.encode())

    srv_sock, cli_sock = socket.socketpair()
    with patch.object(net, "_peer_message_loop", side_effect=lambda p: None), \
         patch("visold.network.p2p.TLSManager.server_context", return_value=None), \
         patch.object(Config, "PEER_POW_DIFFICULTY", 0):
        t = threading.Thread(
            target=net._handle_inbound,
            args=(srv_sock, ("127.0.0.1", 40002)),
            daemon=True,
        )
        t.start()

        _send_json_line(cli_sock, {
            "type": MSG_HELLO,
            "node_id": victim_node_id,
            "pub_hex": attacker_pub_hex,
            "version": Config.VERSION,
            "listen_port": 40003,
        })
        resp_msg = _recv_json_line(cli_sock)
        assert resp_msg["type"] == "REJECT"
        t.join(timeout=5.0)
        cli_sock.close()

    assert victim_node_id not in net.peers


def test_msg_chain_non_int_server_height_rejected_cleanly(tmp_path):
    """
    V4 regression (Finding 4): In _handle_message() for MSG_CHAIN, non-integer
    `server_height` is rejected cleanly without raising TypeError or leaving
    `_sync_pending` stuck in `processing`.
    """
    _storage, _wallet, bc, net = _make_node(tmp_path, "srv_h", port=19130)
    peer = PeerConnection("peer_" + "b" * 59, "127.0.0.1", 9002, sock=None)
    req_id = "req-123"
    peer._sync_pending = {
        "id": req_id,
        "from_idx": 0,
        "to_idx": 199,
        "status": "waiting",
        "kind": "test",
    }

    genesis = bc.storage.get_block(0)
    assert genesis is not None
    bad_block = genesis.to_dict()
    bad_block["block_hash"] = "0" * 64

    net._handle_message(peer, {
        "type": MSG_CHAIN,
        "request_id": req_id,
        "server_height": "100",
        "blocks": [bad_block],
    })

    assert peer._sync_pending is None or peer._sync_pending.get("status") != "processing"