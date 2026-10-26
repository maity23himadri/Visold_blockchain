"""Regression coverage for RPC rate limiting and bounded burst handling."""
import concurrent.futures
import http.client
import json
import socket
import threading
import time
from types import SimpleNamespace

import pytest


import visold.api.rpc_server as rpc_module
from visold.api.rpc_server import RPCServer
from visold.kernel.config import Config


_TOKEN = "rpc-regression-test-token"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _FakeBlockchain:
    def __init__(self, height_hook=None):
        self.mempool = SimpleNamespace(all_txs=lambda: [])
        self._height_hook = height_hook

    def height(self):
        if self._height_hook is not None:
            return self._height_hook()
        return 7


class _FakeNode:
    def __init__(self, height_hook=None):
        self.blockchain = _FakeBlockchain(height_hook)
        self.network = SimpleNamespace(peer_list=lambda: [])


def _post(port: int, method: str, *, timeout=3.0, sent_event=None) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []})
    try:
        conn.request(
            "POST",
            "/",
            body=body,
            headers={
                "Authorization": f"Bearer {_TOKEN}",
                "Content-Type": "application/json",
            },
        )
        if sent_event is not None:
            sent_event.set()
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


@pytest.fixture
def rpc_factory(tmp_path, monkeypatch):
    servers = []
    token_file = tmp_path / "rpc_token"
    token_file.write_text(_TOKEN, encoding="utf-8")
    monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(Config, "ensure_dirs", classmethod(lambda cls: None))
    monkeypatch.setattr(RPCServer, "TOKEN_FILE", str(token_file))

    def _start(node=None):
        rpc = RPCServer(node or _FakeNode(), _free_port())
        rpc.start()
        assert rpc._server is not None, "RPC server failed to start"
        servers.append(rpc)
        return rpc

    yield _start

    for rpc in reversed(servers):
        rpc.stop()


def _freeze_rate_clock(monkeypatch):
    # Freeze only rpc_server's clock after start() initialized the bucket. This
    # makes token-bucket tests deterministic without affecting threading/timeouts.
    now = time.time()
    monkeypatch.setattr(rpc_module, "time", SimpleNamespace(time=lambda: now))


def test_slow_rpc_methods_consume_ten_tokens_and_are_throttled(rpc_factory, monkeypatch):
    rpc = rpc_factory()
    _freeze_rate_clock(monkeypatch)

    statuses = [_post(rpc.rpc_port, "getmempool") for _ in range(3)]

    assert statuses == [200, 200, 429]


def test_normal_rpc_methods_keep_standard_token_cost(rpc_factory, monkeypatch):
    rpc = rpc_factory()
    _freeze_rate_clock(monkeypatch)

    statuses = [_post(rpc.rpc_port, "getblockcount") for _ in range(21)]

    assert statuses == [200] * 20 + [429]


def test_worker_saturation_queues_connections_and_recovers(rpc_factory, monkeypatch):
    # A tiny worker cap makes back-pressure deterministic. Production defaults
    # to 32 workers; excess connections should queue rather than reset sockets.
    monkeypatch.setattr(rpc_module, "_RPC_MAX_WORKERS", 2)
    entered = threading.Event()
    release = threading.Event()
    active_lock = threading.Lock()
    active = {"count": 0, "max": 0}

    def blocking_height():
        with active_lock:
            active["count"] += 1
            active["max"] = max(active["max"], active["count"])
            if active["count"] >= 2:
                entered.set()
        try:
            release.wait(timeout=2.0)
            return 7
        finally:
            with active_lock:
                active["count"] -= 1

    rpc = rpc_factory(_FakeNode(blocking_height))
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    futures = []
    third_sent = threading.Event()
    try:
        futures = [
            pool.submit(_post, rpc.rpc_port, "getblockcount", timeout=4.0)
            for _ in range(2)
        ]
        assert entered.wait(timeout=1.5), "two RPC workers did not become active"

        # This third request must remain queued under back-pressure, not be reset.
        third = pool.submit(
            _post, rpc.rpc_port, "getblockcount", timeout=4.0, sent_event=third_sent
        )
        futures.append(third)
        assert third_sent.wait(timeout=1.5), "third client could not send its request"
        release.set()
        statuses = [future.result(timeout=4.0) for future in futures]
    finally:
        release.set()
        for future in futures:
            if not future.done():
                future.result(timeout=4.0)
        pool.shutdown(wait=True)

    assert statuses == [200, 200, 200]
    assert active["max"] <= 2, "RPC request execution exceeded the worker cap"


def test_server_uses_large_backlog_and_bounded_worker_pool(rpc_factory):
    rpc = rpc_factory()
    assert rpc._server.request_queue_size == 128
    assert rpc._server._worker_slots._initial_value == 32


def test_24_client_burst_has_no_transport_exceptions(rpc_factory):
    rpc = rpc_factory()
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        futures = [
            pool.submit(_post, rpc.rpc_port, "getblockcount", timeout=4.0)
            for _ in range(24)
        ]
        statuses = [future.result(timeout=5.0) for future in futures]

    assert len(statuses) == 24
    assert set(statuses) <= {200, 429}


def test_shutdown_does_not_hang_while_accept_loop_waits_for_worker(rpc_factory, monkeypatch):
    monkeypatch.setattr(rpc_module, "_RPC_MAX_WORKERS", 1)
    entered = threading.Event()
    release = threading.Event()

    def blocking_height():
        entered.set()
        release.wait(timeout=3.0)
        return 7

    rpc = rpc_factory(_FakeNode(blocking_height))
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    first = pool.submit(_post, rpc.rpc_port, "getblockcount", timeout=5.0)
    second_sent = threading.Event()
    second = None
    try:
        assert entered.wait(timeout=1.0)
        # Only submit the second connection after the first request is confirmed
        # inside dispatch, so the test knows which response must remain in flight.
        second = pool.submit(
            _post,
            rpc.rpc_port,
            "getblockcount",
            timeout=3.0,
            sent_event=second_sent,
        )
        assert second_sent.wait(timeout=1.0)
        # Stop must interrupt the accept loop's bounded-slot wait instead of
        # deadlocking shutdown while the only worker remains occupied.
        pool.submit(rpc.stop).result(timeout=1.5)
    finally:
        release.set()

    assert first.result(timeout=3.0) == 200
    # The second request was pending during an intentional server shutdown, so
    # its transport outcome is deliberately not asserted.
    if second is not None:
        try:
            second.result(timeout=3.5)
        except (OSError, TimeoutError, http.client.HTTPException):
            pass
    pool.shutdown(wait=True)
