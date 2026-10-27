"""Isolated regression check: a compressed 64 MiB P2P payload is rejected.

Run from the extracted project root with: PYTHONPATH=. python visold_v3_p2p_compression_regression.py
This uses only a local socketpair; it does not connect to external hosts.
"""
import resource
import socket
import threading
import time
from collections import defaultdict

from visold.kernel.config import Config
from visold.network.compression import CompressionEngine
from visold.network.peer_connection import PeerConnection
from visold.network.p2p import P2PNetwork

EXPAND = 64 * 1024 * 1024
raw = b'{"type":"PING","pad":"' + (b'A' * EXPAND) + b'"}'
wire = CompressionEngine.compress(raw) + b"\n"

class Storage:
    def __init__(self):
        self.bans = []

    def add_ban_score(self, *args):
        self.bans.append(args)

left, right = socket.socketpair()
peer = PeerConnection("attackpeer000001", "127.0.0.1", 8338, sock=left)
peer.send = lambda msg: True
net = object.__new__(P2PNetwork)
net._running = True
net.storage = Storage()
net._msg_rate_lock = threading.Lock()
net._msg_rate = {}
net._callbacks = defaultdict(list)
disconnected = threading.Event()
handled = []

def on_disconnect(p):
    p.connected = False
    disconnected.set()

net._on_peer_disconnect = on_disconnect
net._handle_message = lambda _peer, msg: handled.append(msg)
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
start = time.monotonic()
thread = threading.Thread(
    target=P2PNetwork._peer_message_loop, args=(net, peer), daemon=True
)
thread.start()
try:
    right.sendall(wire)
    assert disconnected.wait(5), "peer loop did not terminate the oversized frame"
    thread.join(2)
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    assert not thread.is_alive(), "reader thread remained alive after rejection"
    assert not peer.connected, "oversized peer session remained connected"
    assert handled == [], "oversized decompressed payload reached message dispatch"
    assert net.storage.bans == [(peer.peer_id, Config.PEER_SCORE_OVERSIZED_MSG)], net.storage.bans
    print("CONFIG_MAX_MESSAGE_SIZE", Config.MAX_MESSAGE_SIZE)
    print("RAW_JSON_BYTES", len(raw), "WIRE_FRAME_BYTES", len(wire))
    print("EXPANSION_RATIO", round(len(raw) / len(wire), 1))
    print("ACTUAL_HANDLER_DISPATCHED", False)
    print("OVERSIZED_BAN_EVENTS", len(net.storage.bans))
    print("READER_THREAD_ALIVE", thread.is_alive())
    print("RSS_PEAK_KB_BEFORE", before, "RSS_PEAK_KB_AFTER", after)
    print("RESULT=PASS: the live P2P receive/decompress/parse path rejected the 64 MiB expansion before dispatch.")
finally:
    right.close()
    try:
        peer.close()
    except Exception:
        pass
