"""Isolated live-socket regression for RPC /headers rate limiting.

Run from project root with: PYTHONPATH=. python visold_v3_rpc_headers_rate_regression.py
The server binds to 127.0.0.1 only; no external network is contacted.
"""
import concurrent.futures
import http.client
import os
import socket
import tempfile
import threading
import time

from visold.api.rpc_server import RPCServer
from visold.kernel.config import Config

TOKEN = "headers-rate-regression-token"

class Chain:
    def __init__(self):
        self.lookups = 0
        self.lock = threading.Lock()

    def get_block(self, index):
        with self.lock:
            self.lookups += 1
        return None

    def height(self):
        return 0

class Node:
    def __init__(self):
        self.blockchain = Chain()
        self.network = type("Network", (), {"peer_list": lambda self: []})()

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def get_headers(port):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(
            "GET", "/headers?from=0&count=100",
            headers={"Authorization": "Bearer " + TOKEN},
        )
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()

with tempfile.TemporaryDirectory(prefix="visold-header-rate-regression-") as temp_dir:
    old_data = Config.DATA_DIR
    old_ensure = Config.ensure_dirs
    old_token_file = RPCServer.TOKEN_FILE
    Config.DATA_DIR = temp_dir
    Config.ensure_dirs = classmethod(lambda cls: None)
    RPCServer.TOKEN_FILE = os.path.join(temp_dir, "rpc_token")
    with open(RPCServer.TOKEN_FILE, "w", encoding="utf-8") as token_file:
        token_file.write(TOKEN)
    node = Node()
    rpc = RPCServer(node, free_port())
    rpc.start()
    try:
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
            statuses = list(pool.map(lambda _index: get_headers(rpc.rpc_port), range(40)))
        elapsed = time.monotonic() - start
        allowed = statuses.count(200)
        limited = statuses.count(429)
        print("ENDPOINT=GET /headers?from=0&count=100")
        print("REQUESTS=40 HTTP_200", allowed, "HTTP_429", limited,
              "OTHER", sorted(set(statuses) - {200, 429}))
        print("BLOCK_LOOKUPS", node.blockchain.lookups,
              "ELAPSED_SECONDS", round(elapsed, 3))
        assert limited >= 30, f"expected concurrent requests to be rate-limited; got {limited} HTTP 429s"
        assert node.blockchain.lookups == allowed * 100, (
            "rate-limited requests performed block lookups"
        )
        assert not (set(statuses) - {200, 429}), "unexpected HTTP status observed"
        print("RESULT=PASS: /headers rate limit rejects the flood before expensive block lookups.")
    finally:
        rpc.stop()
        Config.DATA_DIR = old_data
        Config.ensure_dirs = old_ensure
        RPCServer.TOKEN_FILE = old_token_file
