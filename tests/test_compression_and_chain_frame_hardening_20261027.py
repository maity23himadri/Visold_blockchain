"""Regression tests for bounded P2P decompression and chain-frame sizing."""
import base64
import json
import socket
import threading
import zlib
from collections import defaultdict
from types import SimpleNamespace

import pytest

from visold.kernel.config import Config
from visold.kernel.compression_utils import DecompressedSizeLimitError
from visold.kernel.messages import MSG_GET_CHAIN, MSG_PING
from visold.network.compression import CompressionEngine
from visold.network.peer_connection import PeerConnection
from visold.network.p2p import P2PNetwork


class _Storage:
    def __init__(self):
        self.bans = []

    def add_ban_score(self, *args):
        self.bans.append(args)


def _zlib_frame(raw: bytes) -> bytes:
    return CompressionEngine.MAGIC + base64.b64encode(zlib.compress(raw, level=3))


def test_compression_rejects_expanded_payload_at_frame_limit(monkeypatch):
    monkeypatch.setattr(Config, "MAX_MESSAGE_SIZE", 1024 * 1024)
    monkeypatch.setattr("visold.network.compression._ZSTD_AVAILABLE", False)
    monkeypatch.setattr(CompressionEngine, "_zstd_dctx", None)
    monkeypatch.setattr(CompressionEngine, "_zstd_cctx", None)

    raw = json.dumps({"type": "PING", "pad": "A" * (1024 * 1024)}).encode()
    wire = _zlib_frame(raw)

    # Over-limit data must be rejected explicitly, not handed to JSON parsing.
    with pytest.raises(DecompressedSizeLimitError):
        CompressionEngine.decompress(wire)


def test_compression_accepts_payload_exactly_at_frame_limit(monkeypatch):
    limit = 1024 * 1024
    monkeypatch.setattr(Config, "MAX_MESSAGE_SIZE", limit)
    monkeypatch.setattr("visold.network.compression._ZSTD_AVAILABLE", False)
    monkeypatch.setattr(CompressionEngine, "_zstd_dctx", None)
    monkeypatch.setattr(CompressionEngine, "_zstd_cctx", None)

    prefix = b'{"type":"PING","pad":"'
    suffix = b'"}'
    raw = prefix + (b"A" * (limit - len(prefix) - len(suffix))) + suffix
    assert len(raw) == limit
    assert CompressionEngine.decompress(_zlib_frame(raw)) == raw


def test_zstd_streaming_path_enforces_output_limit_without_full_inflate(monkeypatch):
    import base64
    import io

    limit = 1024 * 1024

    class FakeZstdDctx:
        def __init__(self, output):
            self.output = output
            self.read_size = None
            self.read_across_frames = None

        def stream_reader(self, _source, *, read_size, read_across_frames):
            self.read_size = read_size
            self.read_across_frames = read_across_frames
            return io.BytesIO(self.output)

    fake_dctx = FakeZstdDctx(b"X" * (limit + 128))
    monkeypatch.setattr(Config, "MAX_MESSAGE_SIZE", limit)
    monkeypatch.setattr("visold.network.compression._ZSTD_AVAILABLE", True)
    monkeypatch.setattr(CompressionEngine, "_zstd_cctx", object())
    monkeypatch.setattr(CompressionEngine, "_zstd_dctx", fake_dctx)
    wire = CompressionEngine.MAGIC + base64.b64encode(b"fake-zstd-frame")

    with pytest.raises(DecompressedSizeLimitError):
        CompressionEngine.decompress(wire)
    assert fake_dctx.read_size == 128 * 1024
    assert fake_dctx.read_across_frames is False


def test_zstd_streaming_path_accepts_exact_limit(monkeypatch):
    import base64
    import io

    limit = 1024

    class FakeZstdDctx:
        def stream_reader(self, _source, *, read_size, read_across_frames):
            assert read_size == min(128 * 1024, limit + 1)
            assert read_across_frames is False
            return io.BytesIO(b"Z" * limit)

    monkeypatch.setattr(Config, "MAX_MESSAGE_SIZE", limit)
    monkeypatch.setattr("visold.network.compression._ZSTD_AVAILABLE", True)
    monkeypatch.setattr(CompressionEngine, "_zstd_cctx", object())
    monkeypatch.setattr(CompressionEngine, "_zstd_dctx", FakeZstdDctx())
    wire = CompressionEngine.MAGIC + base64.b64encode(b"fake-zstd-frame")
    assert CompressionEngine.decompress(wire) == b"Z" * limit


def test_peer_receive_loop_does_not_dispatch_over_limit_compressed_frame(monkeypatch):
    limit = 1024 * 1024
    monkeypatch.setattr(Config, "MAX_MESSAGE_SIZE", limit)
    monkeypatch.setattr("visold.network.compression._ZSTD_AVAILABLE", False)
    monkeypatch.setattr(CompressionEngine, "_zstd_dctx", None)
    monkeypatch.setattr(CompressionEngine, "_zstd_cctx", None)

    left, right = socket.socketpair()
    peer = PeerConnection("oversize-test-peer", "127.0.0.1", 8338, sock=left)
    peer.send = lambda msg: True
    net = object.__new__(P2PNetwork)
    net._running = True
    net.storage = _Storage()
    net._msg_rate_lock = threading.Lock()
    net._msg_rate = {}
    net._callbacks = defaultdict(list)
    disconnected = threading.Event()
    handled = []
    def _mark_disconnected(_peer):
        _peer.connected = False
        disconnected.set()
    net._on_peer_disconnect = _mark_disconnected
    net._handle_message = lambda _peer, message: handled.append(message)

    payload = json.dumps({"type": MSG_PING, "pad": "B" * (limit + 1)}).encode()
    try:
        thread = threading.Thread(
            target=P2PNetwork._peer_message_loop, args=(net, peer), daemon=True
        )
        thread.start()
        right.sendall(_zlib_frame(payload) + b"\n")
        assert disconnected.wait(timeout=5), "reader failed to terminate after rejected frame"
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert not peer.connected
        assert handled == [], "oversized decompressed payload reached message dispatch"
        assert net.storage.bans == [(peer.peer_id, Config.PEER_SCORE_OVERSIZED_MSG)]
    finally:
        right.close()
        try:
            peer.close()
        except Exception:
            pass


def test_get_chain_reply_is_byte_budgeted_and_remains_paginated(monkeypatch):
    # Shrink only this test's cap to force pagination with small fake blocks.
    monkeypatch.setattr(Config, "MAX_MESSAGE_SIZE", 20_000)

    class FakeBlock:
        def __init__(self, index):
            self.index = index

        def to_dict(self):
            return {"index": self.index, "payload": "x" * 6_000}

    class FakeBlockchain:
        def height(self):
            return 9

        def get_block(self, index):
            return FakeBlock(index) if 0 <= index <= 9 else None

    class FakePeer:
        peer_id = "chain-size-test"

        def __init__(self):
            self.sent = []

        def send(self, message):
            self.sent.append(message)
            return True

    net = object.__new__(P2PNetwork)
    net._check_msg_rate = lambda _peer, _type: True
    net._callbacks = defaultdict(list)
    net.blockchain = FakeBlockchain()
    net._local_chain_tip_hash = lambda: "tip-hash"
    peer = FakePeer()

    cursor = 0
    collected_indices = []
    for page_number in range(10):
        peer.sent.clear()
        P2PNetwork._handle_message(net, peer, {
            "type": MSG_GET_CHAIN,
            "from_idx": cursor,
            "to_idx": 9,
            "request_id": f"byte-budget-regression-{page_number}",
        })

        assert len(peer.sent) == 1
        reply = peer.sent[0]
        assert reply["type"] == "MSG_CHAIN" or reply["type"] == "CHAIN"
        assert len(json.dumps(reply).encode()) <= Config.MAX_MESSAGE_SIZE
        assert reply["blocks"], "a valid block page must make forward progress"
        indices = [block["index"] for block in reply["blocks"]]
        assert indices == list(range(cursor, cursor + len(indices)))
        collected_indices.extend(indices)
        cursor = indices[-1] + 1
        if cursor > reply["server_height"]:
            break

    assert collected_indices == list(range(10)), "byte-budget pagination lost or duplicated blocks"
