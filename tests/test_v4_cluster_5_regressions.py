"""V4 positive regression tests for Cluster 5 (visold/network/) audit findings.

Converted from the 11 adversarial tests in test_cluster_5_adversarial.py to
assert the fixed V4 behavior across Sections 101-110.
"""

import hashlib
import hmac
import json
import time
import threading
import urllib.request
import zlib
from unittest.mock import MagicMock, patch

import pytest

from visold.crypto.ecc import ecdsa_keygen, ecdsa_sign, pub_to_address, pub_to_hex, sig_to_hex
from visold.crypto.hashing import sha256
from visold.kernel.compression_utils import DecompressedSizeLimitError
from visold.kernel.config import Config
from visold.kernel.messages import (
    MSG_ALERT,
    MSG_BLOCK_CHUNK_DATA,
    MSG_BLOCK_MANIFEST,
    MSG_GET_PEERS,
    MSG_IDENTITY,
)
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.block_download import ParallelBlockDownloader
from visold.network.kademlia import KBucket, KademliaRouter
from visold.network.nat.hole_punch import UDPHolePuncher
from visold.network.nat.ice import ICEManager
from visold.network.nat.upnp import UPnPManager
from visold.network.p2p import P2PNetwork
from visold.network.receipt_relay import ReceiptRelayManager
from visold.network.udp.reliability import _UDPReassembler
from visold.network.udp.wire import _udp_decompress
from visold.storage.storage import Storage


def _make_wallet():
    priv, pub = ecdsa_keygen()
    pub_hex = pub_to_hex(pub)
    addr = pub_to_address(pub)
    node_id = sha256(pub_hex.encode())

    class _Wallet:
        def __init__(self):
            self.priv = priv
            self.pub = pub
            self.pub_hex = pub_hex
            self.address = addr
            self.user_id = ""

        def sign(self, data: bytes):
            return ecdsa_sign(self.priv, hashlib.sha256(data).digest())

    return _Wallet(), node_id


_PORT_COUNTER = 19100


def _make_network(tmp_path, name="node"):
    global _PORT_COUNTER
    _PORT_COUNTER += 10
    db_path = str(tmp_path / f"{name}.db")
    storage = Storage(db_path=db_path)
    wallet, node_id = _make_wallet()
    blockchain = MagicMock()
    blockchain.height.return_value = 0
    blockchain.get_block.return_value = None
    net = P2PNetwork(
        blockchain=blockchain,
        wallet=wallet,
        storage=storage,
        port=_PORT_COUNTER,
        node_id=node_id,
    )
    return net, storage, wallet, node_id


# ---------------------------------------------------------------------------
# NEW-01: Unauthenticated MSG_ALERT must not blacklist or evict peers
# ---------------------------------------------------------------------------
def test_new01_msg_alert_unauthenticated_does_not_blacklist_or_evict_victim(tmp_path):
    net, storage, _, _ = _make_network(tmp_path, "alert_victim")
    victim_id = sha256(b"honest-validator-pubkey")
    attacker_id = sha256(b"attacker-pubkey")

    storage.save_peer(victim_id, "198.51.100.10", 8338)
    victim_peer = MagicMock()
    victim_peer.peer_id = victim_id
    victim_peer.connected = True
    with net._lock:
        net.peers[victim_id] = victim_peer
        net._eager_peers.add(victim_id)

    attacker_peer = MagicMock()
    attacker_peer.peer_id = attacker_id
    attacker_peer.ip = "203.0.113.50"
    attacker_peer.port = 8338
    attacker_peer.trust_level = "TRUST_LEVEL_LOW"
    attacker_peer.connected = True

    # Unauthenticated MSG_ALERT without signature/timestamp/trust is ignored
    net._handle_message(attacker_peer, {"type": MSG_ALERT, "bad_node_id": victim_id})

    victim_peer.close.assert_not_called()
    assert victim_id in net.peers
    assert victim_id in net._eager_peers
    row = storage._conn().execute(
        "SELECT blacklisted FROM peers WHERE peer_id=?", (victim_id,)
    ).fetchone()
    assert row is not None and row["blacklisted"] == 0


# ---------------------------------------------------------------------------
# NEW-02: MSG_IDENTITY rejects peer_id / multiaddrs hijacking without auth
# ---------------------------------------------------------------------------
def test_new02_msg_identity_rejects_peer_id_hijack_without_binding_to_pub_hex(tmp_path):
    net, storage, _, _ = _make_network(tmp_path, "identity_hijack")
    victim_wallet, victim_node_id = _make_wallet()
    attacker_id = sha256(b"attacker-node-key")

    # Canonical on-chain name claim belongs to victim's pub_hex
    storage.save_name_claim("alice", victim_wallet.address, victim_wallet.pub_hex, 1, "00" * 32)
    storage.save_identity(
        "alice", victim_node_id, victim_wallet.address, victim_wallet.pub_hex, ["/ip4/1.2.3.4/tcp/8338"]
    )

    attacker_peer = MagicMock()
    attacker_peer.peer_id = attacker_id
    attacker_peer.trust_level = "TRUST_LEVEL_HIGH"

    # Attacker replays victim's pub_hex but substitutes attacker's peer_id & multiaddrs
    net._handle_message(
        attacker_peer,
        {
            "type": MSG_IDENTITY,
            "user_id": "alice",
            "peer_id": attacker_id,
            "pub_hex": victim_wallet.pub_hex,
            "multiaddrs": ["/ip4/203.0.113.99/tcp/8338"],
        },
    )

    resolved = storage.resolve_identity("alice")
    assert resolved is not None
    assert resolved["peer_id"] == victim_node_id
    assert resolved["multiaddrs"] == ["/ip4/1.2.3.4/tcp/8338"]

    # Properly signed MSG_IDENTITY from the owner succeeds
    new_maddrs = ["/ip4/1.2.3.5/tcp/8338"]
    payload_hash = hashlib.sha256(
        json.dumps({"user_id": "alice", "peer_id": victim_node_id, "multiaddrs": new_maddrs}, sort_keys=True).encode()
    ).digest()
    sig_hex = sig_to_hex(ecdsa_sign(victim_wallet.priv, payload_hash))
    net._handle_message(
        attacker_peer,
        {
            "type": MSG_IDENTITY,
            "user_id": "alice",
            "peer_id": victim_node_id,
            "pub_hex": victim_wallet.pub_hex,
            "multiaddrs": new_maddrs,
            "sig_hex": sig_hex,
        },
    )
    updated = storage.resolve_identity("alice")
    assert updated is not None
    assert updated["peer_id"] == victim_node_id
    assert updated["multiaddrs"] == new_maddrs


# ---------------------------------------------------------------------------
# NEW-03: ICEManager._make_session_token uses CSPRNG or HMAC-SHA256
# ---------------------------------------------------------------------------
def test_new03_ice_relay_session_token_is_unpredictable():
    target_ip = "198.51.100.42"
    target_port = 8338
    token_a = ICEManager._make_session_token(target_ip, target_port)
    token_b = ICEManager._make_session_token(target_ip, target_port)
    predictable = hashlib.sha256(
        f"vsd-relay:{target_ip}:{target_port}:{int(time.time()) // 30}".encode()
    ).hexdigest()[:32]

    assert len(token_a) == 32
    assert token_a != predictable
    assert token_a != token_b

    secret = b"high-entropy-session-secret"
    hmac_token = ICEManager._make_session_token(target_ip, target_port, shared_secret=secret)
    expected_hmac = hmac.new(
        secret,
        f"vsd-relay:{target_ip}:{target_port}:{int(time.time()) // 30}".encode(),
        hashlib.sha256,
    ).hexdigest()[:32]
    assert hmac_token == expected_hmac
    assert hmac_token != predictable


# ---------------------------------------------------------------------------
# NEW-04: UPnPManager._parse_description rejects non-LAN & cross-origin URLs
# ---------------------------------------------------------------------------
def test_new04_upnp_parse_description_rejects_non_lan_and_cross_origin_urls():
    upnp = UPnPManager(8338)

    # 1. Public / non-LAN description URL is rejected before any HTTP request
    with patch.object(urllib.request, "urlopen") as mock_open:
        with pytest.raises(ValueError, match="disallowed non-LAN"):
            upnp._parse_description("http://8.8.8.8:5000/igd.xml")
        mock_open.assert_not_called()

    # 2. LAN description URL with cross-origin / link-local controlURL is rejected
    malicious_xml = (
        b"<root><device><serviceList><service>"
        b"<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>"
        b"<controlURL>http://169.254.169.254/latest/meta-data/</controlURL>"
        b"</service></serviceList></device></root>"
    )
    fake_resp = MagicMock()
    fake_resp.read.return_value = malicious_xml
    with patch.object(urllib.request, "urlopen", return_value=fake_resp):
        with pytest.raises(RuntimeError, match="No WANIPConnection service found"):
            upnp._parse_description("http://192.168.1.1:5000/igd.xml")

    # 3. Valid LAN description URL with same-origin controlURL succeeds
    valid_xml = (
        b"<root><device><serviceList><service>"
        b"<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>"
        b"<controlURL>/ctl/IPConn</controlURL>"
        b"</service></serviceList></device></root>"
    )
    valid_resp = MagicMock()
    valid_resp.read.return_value = valid_xml
    with patch.object(urllib.request, "urlopen", return_value=valid_resp):
        ctrl_url, svc_type, gw_host = upnp._parse_description("http://192.168.1.1:5000/igd.xml")
        assert ctrl_url == "http://192.168.1.1:5000/ctl/IPConn"
        assert "WANIPConnection" in svc_type
        assert gw_host == "192.168.1.1"


# ---------------------------------------------------------------------------
# Hist-102: Storage.add_ban_score preserves blacklisted=1 when score < threshold
# ---------------------------------------------------------------------------
def test_hist102_add_ban_score_preserves_blacklisted_flag(tmp_path):
    storage = Storage(db_path=str(tmp_path / "ban.db"))
    pid = sha256(b"bad-peer")
    storage.save_peer(pid, "203.0.113.10", 8338)
    storage.blacklist_peer(pid)
    assert storage._conn().execute("SELECT blacklisted FROM peers WHERE peer_id=?", (pid,)).fetchone()["blacklisted"] == 1

    # Small penalty (< PEER_BAN_SCORE_THRESHOLD) must preserve blacklisted=1
    storage.add_ban_score(pid, 5)
    row = storage._conn().execute("SELECT blacklisted, ban_score FROM peers WHERE peer_id=?", (pid,)).fetchone()
    assert row["ban_score"] == 5
    assert row["blacklisted"] == 1


# ---------------------------------------------------------------------------
# Hist-103: KademliaRouter.get_closest deduplicates & enforces IPv6 /48 limit
# ---------------------------------------------------------------------------
def test_hist103_kademlia_get_closest_deduplicates_and_enforces_ipv6_subnet_limit():
    local_id = "0" * 40
    router = KademliaRouter(local_id)
    p1 = "0" * 39 + "1"
    router.update(p1, {"peer_id": p1, "ip": "192.0.2.1", "port": 8338})
    closest = router.get_closest(p1, k=5)
    # Offset=0 visits bucket 0 only once -> p1 appears exactly once
    assert [c["peer_id"] for c in closest].count(p1) == 1

    # IPv6 non-canonical representations in the same /48 are capped at MAX_NODES_PER_SUBNET
    bucket = KBucket(k=20)
    variants = [
        "2001:db8::1",
        "2001:0db8::2",
        "2001:db8:0:1::3",
        "2001:0db8:0:2::4",
        "2001:db8:0000:3::5",
        "2001:DB8:0:4::6",
    ]
    for idx, ip in enumerate(variants):
        bucket.add(f"peer_{idx}", {"peer_id": f"peer_{idx}", "ip": ip, "port": 8338})
    assert len(bucket.get_all()) == bucket.MAX_NODES_PER_SUBNET


# ---------------------------------------------------------------------------
# Hist-105 & 106: _udp_decompress raises on zipbomb & FEC preserves trailing nulls
# ---------------------------------------------------------------------------
def test_hist105_106_udp_decompress_rejects_zipbomb_and_fec_preserves_trailing_nulls():
    # 33 MB of zeros compresses small, exceeds 32 MB limit in _udp_decompress
    big = b"\x00" * (33 * 1024 * 1024)
    compressed = zlib.compress(big, level=9)
    with pytest.raises(DecompressedSizeLimitError):
        _udp_decompress(compressed)

    # FEC try_fec_recover preserves legitimate trailing 0x00 on last fragment
    frag0 = b"AAAA"
    frag1_orig = b"BBBB\x00\x00"
    fec_sym = bytes(a ^ b for a, b in zip(frag0 + b"\x00\x00", frag1_orig))
    r2 = _UDPReassembler(frag_id=2)
    r2.frags[0] = frag0
    r2.last_off = 1
    r2.fec_syms[0] = (1, fec_sym)
    assert r2.try_fec_recover() is True
    assert r2.frags[1] == frag1_orig
    assert r2.fec_recovered_last is True


# ---------------------------------------------------------------------------
# Hist-107: UDPHolePuncher.punch succeeds simultaneously for both peers
# ---------------------------------------------------------------------------
def test_hist107_udp_hole_punch_succeeds_simultaneously():
    p1 = UDPHolePuncher(local_port=0)
    p2 = UDPHolePuncher(local_port=0)
    s1 = p1.stun_bind("127.0.0.1")
    s2 = p2.stun_bind("127.0.0.1")
    assert s1 is not None and s2 is not None
    port1 = p1.get_local_port()
    port2 = p2.get_local_port()

    res = [None, None]
    t1 = threading.Thread(target=lambda: res.__setitem__(0, p1.punch("127.0.0.1", port2, timeout=0.6)))
    t2 = threading.Thread(target=lambda: res.__setitem__(1, p2.punch("127.0.0.1", port1, timeout=0.6)))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    try:
        assert res[0] is not None and res[1] is not None
    finally:
        for sock in res:
            if sock is not None:
                sock.close()


# ---------------------------------------------------------------------------
# Hist-109: _check_msg_rate hard-breach applies ban_score penalty
# ---------------------------------------------------------------------------
def test_hist109_check_msg_rate_penalizes_hard_breach(tmp_path):
    net, storage, _, _ = _make_network(tmp_path, "ratelimit")
    pid = sha256(b"flooder")
    storage.save_peer(pid, "203.0.113.77", 8338)
    peer = MagicMock()
    peer.peer_id = pid

    limit = net._MSG_RATE_PERTYPE[MSG_GET_PEERS]
    for _ in range(limit * 5):
        net._check_msg_rate(peer, MSG_GET_PEERS)

    assert storage.get_ban_score(pid) >= Config.PEER_BAN_SCORE_THRESHOLD


# ---------------------------------------------------------------------------
# Hist-110: ParallelBlockDownloader rejects forged block_hash
# ---------------------------------------------------------------------------
def test_hist110_block_downloader_rejects_forged_block_hash(tmp_path):
    net, _, _, _ = _make_network(tmp_path, "blk_dl")
    target_hash = "ab" * 32
    forged_block = {
        "version": 1,
        "protocol_version": Config.PROTOCOL_VERSION,
        "index": 1,
        "prev_hash": "00" * 32,
        "timestamp": int(time.time()),
        "miner_address": "VSD_miner",
        "difficulty": 1.0,
        "nonce": 0,
        "merkle_root": "cd" * 32,
        "state_root": "ef" * 32,
        "block_hash": target_hash,  # Forged! Does not match compute_hash()
        "transactions": [],
    }
    blob = json.dumps(forged_block).encode("utf-8")
    chunk_hash = hashlib.sha256(blob).hexdigest()

    fake_peer = MagicMock()
    fake_peer.peer_id = "peer12345678"
    fake_peer.connected = True
    fake_peer._block_chunk_queue = None

    def _send(msg):
        if msg["type"] == "GET_BLOCK_MANIFEST":
            fake_peer._block_chunk_queue.put({
                "type": MSG_BLOCK_MANIFEST,
                "block_hash": target_hash,
                "total_chunks": 1,
                "chunk_hashes": [chunk_hash],
            })
        elif msg["type"] == "GET_BLOCK_CHUNK":
            fake_peer._block_chunk_queue.put({
                "type": MSG_BLOCK_CHUNK_DATA,
                "block_hash": target_hash,
                "chunk_index": 0,
                "data_hex": blob.hex(),
            })

    fake_peer.send.side_effect = _send
    with net._lock:
        net.peers[fake_peer.peer_id] = fake_peer

    dl = ParallelBlockDownloader(net, target_hash)
    blk = dl.download()
    assert blk is None


# ---------------------------------------------------------------------------
# Hist-110: ReceiptRelayManager prevents resurrection of ACKed & GC'd receipts
# ---------------------------------------------------------------------------
def test_hist110_receipt_relay_prevents_resurrection_of_acked_gc_receipt(tmp_path):
    storage = Storage(db_path=str(tmp_path / "varr.db"))
    sender_w, _ = _make_wallet()
    recv_w, recv_nid = _make_wallet()

    tx = Transaction(
        sender=sender_w.address,
        receiver=recv_w.address,
        amount=1.0,
        timestamp=int(time.time()),
        pub_hex=sender_w.pub_hex,
    )
    tx.sign(sender_w)
    blk = Block(
        index=1,
        prev_hash="00" * 32,
        transactions=[tx],
        miner_address=sender_w.address,
        difficulty=1.0,
        timestamp=int(time.time()),
    )

    bc = MagicMock()
    bc.height.return_value = 1
    bc.get_block.return_value = blk

    mgr = ReceiptRelayManager(bc, storage, recv_w, recv_nid)
    receipt = mgr.build_receipt(blk, tx)
    assert receipt is not None

    ok, _ = mgr.store_relay_receipt(receipt, 0)
    assert ok
    ack = mgr.make_ack(receipt["receipt_id"])
    ok_ack, _ = mgr.accept_ack(ack)
    assert ok_ack

    # Force delivered_at into the past and GC
    storage._conn().execute("UPDATE relay_receipts SET delivered_at=1")
    storage._conn().commit()
    assert mgr.gc_delivered() == 1

    # Re-publishing the already-ACKed receipt must be rejected
    ok_res, reason = mgr.store_relay_receipt(receipt, 0)
    assert not ok_res
    assert reason == "receipt already acknowledged"
    assert mgr.get_mailbox(recv_w.address, 0) == []
