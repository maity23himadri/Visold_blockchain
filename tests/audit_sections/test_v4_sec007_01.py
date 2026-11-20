"""V4 regression tests for Audit Section 007: P2P Network Security & Protocol Versioning."""

import json
import os
import socket
import threading
import time
from unittest.mock import MagicMock

import pytest

from visold.chain.blockchain import Blockchain
from visold.governance.versioning import ProtocolVersionManager
from visold.kernel.config import Config
from visold.kernel.messages import (
    MSG_ALERT,
    MSG_BLOCKTXN,
    MSG_CMPCTBLOCK,
    MSG_GET_BLOCK,
    MSG_GET_BLOCK_CHUNK,
    MSG_RESOLVE,
    MSG_RESOLVE_RESP,
)
from visold.network.capabilities import (
    CAP_ARCHIVE,
    CAP_FULL_NODE,
    CAP_VVM_EXEC,
    MSG_CAPABILITY_ADV,
    MSG_GET_CHUNK,
    MSG_GET_CHUNK_MANIFEST,
    MSG_GET_SNAPSHOT,
    CapabilityRouter,
)
from visold.network.p2p import P2PNetwork, PeerConnection
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_p2p(tmp_path):
    db_path = os.path.join(str(tmp_path), "node.db")
    storage = Storage(db_path)
    blockchain = Blockchain(storage)
    wallet = Wallet.generate()
    p2p = P2PNetwork(blockchain, wallet, storage, port=19501, node_id="local_node_id_0001")
    return p2p, storage, blockchain


def _make_mock_peer(peer_id: str, trust_level=PeerConnection.TRUST_LOW):
    peer = MagicMock(spec=PeerConnection)
    peer.peer_id = peer_id
    peer.trust_level = trust_level
    peer.connected = True
    peer.last_seen = 0.0
    peer.consecutive_audit_failures = 0
    peer._soft_ban_throttle_until = 0.0
    peer._recv_buf = b""
    peer._fork_sync_buffer = []
    peer._fork_sync_buffer_bytes = 0
    peer._fork_sync_target_height = -1
    peer.sent_messages = []
    peer.send.side_effect = lambda m: peer.sent_messages.append(m) or True
    return peer


def test_unauthenticated_msg_alert_does_not_blacklist_or_disconnect_peer(tmp_path):
    """Unauthenticated MSG_ALERT is rate-limited and ignored without blacklisting or disconnecting the target peer."""
    p2p, storage, _ = _make_p2p(tmp_path)
    attacker = _make_mock_peer("attacker_peer_0001", trust_level=PeerConnection.TRUST_LOW)
    victim_id = "honest_validator_0001"
    victim = _make_mock_peer(victim_id, trust_level=PeerConnection.TRUST_HIGH)

    storage._conn().execute(
        "INSERT OR REPLACE INTO peers (peer_id, ip, port, blacklisted) VALUES (?, ?, ?, 0)",
        (victim_id, "127.0.0.1", 9001),
    )
    storage._conn().commit()
    with p2p._lock:
        p2p.peers[victim_id] = victim
        p2p._eager_peers.add(victim_id)

    assert MSG_ALERT == "INVALID_NODE_ALERT"
    assert MSG_ALERT in p2p._MSG_RATE_PERTYPE

    p2p._handle_message(attacker, {"type": MSG_ALERT, "bad_node_id": victim_id})

    row = storage._conn().execute(
        "SELECT blacklisted FROM peers WHERE peer_id=?", (victim_id,)
    ).fetchone()
    assert row is not None and row["blacklisted"] == 0
    victim.close.assert_not_called()
    assert victim_id in p2p.peers
    assert victim_id in p2p._eager_peers


def test_msg_resolve_does_not_serve_stale_cache_when_canonical_claim_absent(tmp_path):
    """MSG_RESOLVE returns None when storage.resolve_identity(uid) is None, ignoring stale _id_cache."""
    p2p, storage, _ = _make_p2p(tmp_path)
    peer = _make_mock_peer("querier_peer_0001")

    stale_entry = {
        "user_id": "alice",
        "wallet_addr": "VSDstaleaddress123",
        "pub_hex": "02" + "aa" * 32,
        "multiaddrs": ["/ip4/127.0.0.1/tcp/9000"],
    }
    p2p._id_cache.put("alice", stale_entry)
    assert storage.resolve_identity("alice") is None

    p2p._handle_message(peer, {"type": MSG_RESOLVE, "user_id": "alice"})

    assert len(peer.sent_messages) == 1
    resp = peer.sent_messages[0]
    assert resp["type"] == MSG_RESOLVE_RESP
    assert resp["user_id"] == "alice"
    assert resp["result"] is None


def test_capability_router_removes_revoked_capabilities_from_index_and_db(tmp_path):
    """CapabilityRouter.record_peer_capabilities() removes revoked capabilities from _cap_index and SQLite."""
    db_path = os.path.join(str(tmp_path), "cap.db")
    storage = Storage(db_path)
    router = CapabilityRouter(storage)

    peer_id = "peer_cap_test_0001"
    router.handle_adv(peer_id, [CAP_ARCHIVE, CAP_VVM_EXEC])
    assert peer_id in router.handle_query(CAP_ARCHIVE)
    assert peer_id in router.handle_query(CAP_VVM_EXEC)

    router.handle_adv(peer_id, [CAP_FULL_NODE])

    assert router._peer_caps[peer_id] == {CAP_FULL_NODE}
    assert peer_id not in router.handle_query(CAP_ARCHIVE)
    assert peer_id not in router.handle_query(CAP_VVM_EXEC)

    router_reloaded = CapabilityRouter(storage)
    assert CAP_ARCHIVE not in router_reloaded._peer_caps[peer_id]
    assert CAP_VVM_EXEC not in router_reloaded._peer_caps[peer_id]


def test_msg_blocktxn_rejects_unrelated_peer_eviction_of_compact_stash(tmp_path):
    """MSG_BLOCKTXN from an unrelated peer cannot evict another peer's _compact_stash entry."""
    p2p, _, _ = _make_p2p(tmp_path)
    honest_peer = _make_mock_peer("honest_peer_0001", trust_level=PeerConnection.TRUST_HIGH)
    attacker_peer = _make_mock_peer("attacker_peer_0002", trust_level=PeerConnection.TRUST_LOW)

    block_hash = "ab" * 32
    coinbase_dict = {
        "sender": "COINBASE",
        "recipient": "VSDminer",
        "amount": 10.0,
        "timestamp": 1700000000,
        "tx_id": "cb" * 32,
    }
    cmpct_msg = {
        "type": MSG_CMPCTBLOCK,
        "header": {
            "index": 1,
            "prev_hash": "00" * 32,
            "block_hash": block_hash,
            "merkle_root": "cd" * 32,
            "timestamp": 1700000000,
            "miner_address": "VSDminer",
            "difficulty": 1,
            "nonce": 0,
            "version": 1,
            "protocol_version": 1,
        },
        "coinbase": coinbase_dict,
        "short_ids": ["1122334455667788"],
    }

    p2p._handle_message(honest_peer, cmpct_msg)
    assert block_hash in p2p._compact_stash
    assert p2p._compact_stash[block_hash]["source_peer"] == honest_peer.peer_id

    p2p._handle_message(
        attacker_peer,
        {"type": MSG_BLOCKTXN, "block_hash": block_hash, "txs": []},
    )

    assert block_hash in p2p._compact_stash


@pytest.mark.parametrize(
    "bad_msg",
    [
        {"type": MSG_GET_BLOCK, "index": "not_an_int"},
        {"type": MSG_GET_BLOCK_CHUNK, "block_hash": "aa" * 32, "chunk_index": "bad"},
        {"type": MSG_GET_SNAPSHOT, "height": "bad"},
        {"type": MSG_GET_CHUNK_MANIFEST, "height": "bad"},
        {"type": MSG_GET_CHUNK, "height": "bad", "chunk_index": 0},
        {"type": MSG_CAPABILITY_ADV, "capabilities": [{"unhashable": 1}]},
    ],
)
def test_malformed_schema_fields_handled_safely_without_killing_peer_loop(tmp_path, bad_msg):
    """Malformed wire schema fields are caught cleanly without crashing _peer_message_loop."""
    p2p, _, _ = _make_p2p(tmp_path)
    p2p.blockchain._snapshot_engine = MagicMock()
    p2p._capability_router = CapabilityRouter(p2p.storage)

    s_local, s_remote = socket.socketpair()
    t = None
    try:
        peer = PeerConnection("bad_schema_peer_0001", "127.0.0.1", 9999, sock=s_local)
        peer.connected = True
        p2p._running = True

        payload = (json.dumps(bad_msg) + "\n").encode("utf-8")
        s_remote.sendall(payload)

        t = threading.Thread(target=p2p._peer_message_loop, args=(peer,), daemon=True)
        t.start()
        time.sleep(0.2)

        assert t.is_alive(), "Expected _peer_message_loop to stay alive after malformed schema message"
        assert peer.connected is True
    finally:
        p2p._running = False
        try:
            s_remote.close()
        except Exception:
            pass
        try:
            s_local.close()
        except Exception:
            pass
        if t is not None:
            t.join(timeout=2.0)


def test_protocol_version_manager_rejects_non_positive_and_prevents_rewind_below_v1(tmp_path):
    """ProtocolVersionManager rejects <= 0 versions and refuses to rewind below version 1."""
    db_path = os.path.join(str(tmp_path), "ver.db")
    storage = Storage(db_path)
    pvm = ProtocolVersionManager(storage)

    assert pvm.current_version() == Config.PROTOCOL_VERSION
    ok_zero, _ = pvm.validate_block_version(0)
    ok_neg, _ = pvm.validate_block_version(-5)
    assert ok_zero is False
    assert ok_neg is False

    pvm.rewind_version(0)
    assert pvm.current_version() >= 1
    pvm.rewind_version(-3)
    assert pvm.current_version() >= 1
