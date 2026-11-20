"""V4 Regression Section 110 tests: Authenticated Bootstrap, Block Download,
Receipt Relay, and SPV Verification.
"""
import hashlib
import json
import os
import sys
import threading
from types import SimpleNamespace

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.crypto.ecc import ecdsa_keygen, ecdsa_sign, pub_to_address, pub_to_hex, sig_to_hex
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.messages import (
    MSG_BLOCK_CHUNK_DATA,
    MSG_BLOCK_MANIFEST,
    MSG_GET_BLOCK_CHUNK,
    MSG_GET_BLOCK_MANIFEST,
)
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.block_download import ParallelBlockDownloader
from visold.network.p2p import (
    MSG_CHUNK_DATA,
    MSG_CHUNK_MANIFEST,
    MSG_GET_CHUNK,
    MSG_GET_CHUNK_MANIFEST,
    P2PNetwork,
)
from visold.network.receipt_relay import ReceiptRelayManager
from visold.storage.storage import Storage


class _FakeChunkPeer:
    """Minimal peer stub that drives ParallelBlockDownloader via _block_chunk_queue."""

    def __init__(self, peer_id: str, responder):
        self.peer_id = peer_id
        self.connected = True
        self._block_chunk_queue = None
        self._chunk_response_queue = None
        self._responder = responder
        self.requests = []

    def send(self, msg: dict):
        self.requests.append(msg)
        resp = self._responder(msg)
        if resp is not None:
            q = self._block_chunk_queue or self._chunk_response_queue
            if q is not None:
                q.put(resp)


class _FakeNetwork:
    def __init__(self, peers):
        self._lock = threading.Lock()
        self.peers = {p.peer_id: p for p in peers}


def test_parallel_block_downloader_bounded_retries_on_error_response(monkeypatch):
    """V4 Regression: ParallelBlockDownloader retires peer / bounds retries on error response."""
    monkeypatch.setattr(ParallelBlockDownloader, "CHUNK_TIMEOUT", 0.2)
    monkeypatch.setattr(ParallelBlockDownloader, "MAX_RETRIES", 3)

    block_hash = "ab" * 32
    chunk_bytes = b"hello-world"
    chunk_hash = hashlib.sha256(chunk_bytes).hexdigest()

    def responder(msg):
        mtype = msg.get("type")
        if mtype == MSG_GET_BLOCK_MANIFEST:
            return {
                "type": MSG_BLOCK_MANIFEST,
                "block_hash": block_hash,
                "total_chunks": 1,
                "chunk_hashes": [chunk_hash],
            }
        if mtype == MSG_GET_BLOCK_CHUNK:
            return {
                "type": MSG_BLOCK_CHUNK_DATA,
                "block_hash": block_hash,
                "chunk_index": msg["chunk_index"],
                "error": "chunk unavailable",
            }
        return None

    peer = _FakeChunkPeer("peer-err-" + "0" * 24, responder)
    net = _FakeNetwork([peer])
    dl = ParallelBlockDownloader(net, block_hash)

    blk = dl.download()
    assert blk is None
    chunk_reqs = [r for r in peer.requests if r.get("type") == MSG_GET_BLOCK_CHUNK]
    assert len(chunk_reqs) <= ParallelBlockDownloader.MAX_RETRIES


def test_parallel_block_downloader_rejects_forged_block_hash(monkeypatch):
    """V4 Regression: ParallelBlockDownloader.download() verifies computed block hash and rejects forged blocks."""
    monkeypatch.setattr(ParallelBlockDownloader, "CHUNK_TIMEOUT", 1.0)
    monkeypatch.setattr(ParallelBlockDownloader, "MAX_RETRIES", 2)

    target_hash = "cd" * 32
    forged_block_dict = {
        "version": 1,
        "protocol_version": Config.PROTOCOL_VERSION,
        "index": 1,
        "prev_hash": "00" * 32,
        "timestamp": 1700000000,
        "miner_address": "VSD_ATTACKER",
        "difficulty": 1.0,
        "nonce": 42,
        "merkle_root": sha256(b"empty"),
        "state_root": "ee" * 32,
        "block_hash": target_hash,
        "transactions": [],
    }
    blob = json.dumps(forged_block_dict).encode("utf-8")
    chunk_hash = hashlib.sha256(blob).hexdigest()

    def responder(msg):
        if msg.get("type") == MSG_GET_BLOCK_MANIFEST:
            return {
                "type": MSG_BLOCK_MANIFEST,
                "block_hash": target_hash,
                "total_chunks": 1,
                "chunk_hashes": [chunk_hash],
            }
        if msg.get("type") == MSG_GET_BLOCK_CHUNK:
            return {
                "type": MSG_BLOCK_CHUNK_DATA,
                "block_hash": target_hash,
                "chunk_index": 0,
                "data_hex": blob.hex(),
            }
        return None

    peer = _FakeChunkPeer("peer-forge-" + "0" * 24, responder)
    dl = ParallelBlockDownloader(_FakeNetwork([peer]), target_hash)
    blk = dl.download()

    assert blk is None


def test_receipt_relay_prevents_zombie_resurrection_and_handles_out_of_order_ack(tmp_path):
    """V4 Regression: ReceiptRelayManager records out-of-order ACKs and prevents resurrection of ACKed/GC'd receipts."""
    db_path = str(tmp_path / "test_varr.db")
    storage = Storage(db_path)
    try:
        priv_s, pub_s = ecdsa_keygen()
        addr_s = pub_to_address(pub_s)
        priv_r, pub_r = ecdsa_keygen()
        addr_r = pub_to_address(pub_r)

        genesis = Block(
            index=0,
            prev_hash="0" * 64,
            timestamp=1700000000,
            transactions=[],
            miner_address=addr_s,
            difficulty=1.0,
            nonce=0,
        )
        genesis.merkle_root = genesis._merkle()
        genesis.block_hash = genesis.compute_hash()
        storage.save_block(genesis)

        tx = Transaction(
            sender=addr_s,
            receiver=addr_r,
            amount=5.0,
            fee=0.01,
            timestamp=1700000100,
            nonce=1,
        )
        tx.pub_hex = pub_to_hex(pub_s)
        tx.sig_hex = sig_to_hex(ecdsa_sign(priv_s, hashlib.sha256(tx.signing_bytes(1)).digest()))
        tx.tx_id = tx._compute_id(block_height=1)

        blk = Block(
            index=1,
            prev_hash=genesis.block_hash,
            timestamp=1700000100,
            transactions=[tx],
            miner_address=addr_s,
            difficulty=1.0,
            nonce=1,
        )
        blk.merkle_root = blk._merkle()
        blk.block_hash = blk.compute_hash()
        storage.save_block(blk)

        fake_bc = SimpleNamespace(get_block=lambda h: blk if h == 1 else genesis if h == 0 else None, height=lambda: 1)
        receiver_wallet = SimpleNamespace(
            address=addr_r,
            pub_hex=pub_to_hex(pub_r),
            sign=lambda payload: ecdsa_sign(priv_r, hashlib.sha256(payload).digest()),
        )
        mgr = ReceiptRelayManager(fake_bc, storage, receiver_wallet, "node-1")

        receipt = mgr.build_receipt(blk, tx)
        assert receipt is not None
        rid = receipt["receipt_id"]
        ack = mgr.make_ack(rid)

        # (b) Out-of-order ACK arrives BEFORE receipt is stored
        ok_ack, _ = mgr.accept_ack(ack)
        assert ok_ack

        # Storing the receipt afterwards must respect the recorded ACK
        mgr.store_relay_receipt(receipt, slot=0)
        mailbox = mgr.get_mailbox(addr_r, slot=0)
        assert mailbox == []

        # (a) GC and re-publication must not resurrect an ACKed receipt
        orig_grace = Config.RECEIPT_ACK_GRACE_SECS
        try:
            Config.RECEIPT_ACK_GRACE_SECS = 0
            mgr.gc_delivered()
        finally:
            Config.RECEIPT_ACK_GRACE_SECS = orig_grace

        mgr.store_relay_receipt(receipt, slot=0)
        assert mgr.get_mailbox(addr_r, slot=0) == []
    finally:
        storage.close()


def test_fast_sync_from_peer_rejects_mismatched_manifest_or_short_chunk_hashes(tmp_path, monkeypatch):
    """V4 Regression: P2PNetwork._fast_sync_from_peer() requires manifest consensus including total_chunks and chunk_hashes."""
    monkeypatch.setattr(Config, "SNAPSHOT_FAST_SYNC_ENABLED", True)
    monkeypatch.setattr(Config, "SNAPSHOT_FAST_SYNC_MIN_HEIGHT", 100)
    monkeypatch.setattr(Config, "SNAPSHOT_CHUNK_TIMEOUT", 1.0)
    monkeypatch.setattr(Config, "SNAPSHOT_CHUNK_MAX_RETRIES", 2)

    chunk0 = b"first-chunk-"
    chunk0_hash = hashlib.sha256(chunk0).hexdigest()
    bogus_chunk1 = b"unverified-tampered-chunk-1"

    observed_restore_calls = []

    class _FakeSnapEngine:
        _snap_lock = threading.Lock()

        def restore_from_blob(self, blob, state_root, anchor):
            observed_restore_calls.append((blob, state_root, anchor))
            return False, "rejected by local state comparison"

    fake_bc = SimpleNamespace(
        height=lambda: 5,
        _snapshot_engine=_FakeSnapEngine(),
    )

    net = P2PNetwork.__new__(P2PNetwork)
    net._lock = threading.Lock()
    net.node_id = "local-node-" + "0" * 20
    net.blockchain = fake_bc

    def make_responder(peer_idx):
        def responder(msg):
            mtype = msg.get("type")
            if mtype == MSG_GET_CHUNK_MANIFEST:
                if peer_idx == 1:
                    return {
                        "type": MSG_CHUNK_MANIFEST,
                        "height": 5,
                        "state_root": "aa" * 32,
                        "anchor_block_hash": "bb" * 32,
                        "total_chunks": 2,
                        "chunk_hashes": [chunk0_hash],
                    }
                return {
                    "type": MSG_CHUNK_MANIFEST,
                    "height": 5,
                    "state_root": "aa" * 32,
                    "anchor_block_hash": "bb" * 32,
                    "total_chunks": 2,
                    "chunk_hashes": [chunk0_hash, hashlib.sha256(b"real-chunk-1").hexdigest()],
                }
            if mtype == MSG_GET_CHUNK:
                idx = msg["chunk_index"]
                data = chunk0 if idx == 0 else bogus_chunk1
                return {
                    "type": MSG_CHUNK_DATA,
                    "height": 5,
                    "chunk_index": idx,
                    "data_hex": data.hex(),
                }
            return None
        return responder

    p1 = _FakeChunkPeer("p1-" + "1" * 29, make_responder(1))
    p2 = _FakeChunkPeer("p2-" + "2" * 29, make_responder(2))
    net.peers = {p1.peer_id: p1, p2.peer_id: p2}

    net._fast_sync_from_peer(p1)

    assert len(observed_restore_calls) == 0
