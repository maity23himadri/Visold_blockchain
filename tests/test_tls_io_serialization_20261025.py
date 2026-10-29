"""Regression tests: one TLS peer socket must never be read and written at the same time.

OpenSSL does not support overlapping SSL_read()/SSL_write() on the same
connection.  The node's reader thread and its writer paths used to do exactly
that, which produced spontaneous EOF / BAD_RECORD_MAC session drops with no
network cause.  These tests use REAL TLS sockets (loopback) and the real
PeerConnection / reader helper.
"""
import functools
import hashlib
import json
import os
import socket
import ssl
import tempfile
import threading
import time

from visold.network import p2p
from visold.network.compression import CompressionEngine
from visold.network.peer_connection import (
    PeerConnection,
    tls_recv,
    tls_sendall,
)
from visold.network.tls import TLSManager


@functools.lru_cache(maxsize=1)
def _contexts():
    tmp = tempfile.mkdtemp(prefix="visold_tls_io_")
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    TLSManager._generate_cert(cert, key)  # classmethod; touches no global state
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(cert, key)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    return server, client


def _raises(exc_type, fn, *args):
    try:
        fn(*args)
    except exc_type:
        return
    raise AssertionError(f"{exc_type.__name__} was not raised")


def _make_pair(contexts):
    """Return (server_side_ssl_socket, client_side_ssl_socket), blocking like the node's."""
    server_ctx, client_ctx = contexts
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    accepted = {}

    def accept():
        conn, _ = listener.accept()
        conn.settimeout(10)
        accepted["s"] = server_ctx.wrap_socket(conn, server_side=True)
        accepted["s"].settimeout(None)

    t = threading.Thread(target=accept)
    t.start()
    raw = socket.create_connection(("127.0.0.1", port))
    client = client_ctx.wrap_socket(raw, server_hostname=None)
    t.join()
    listener.close()
    return accepted["s"], client


class _OverlapMonitor:
    """Instruments one SSLSocket instance and records overlapping SSL operations."""

    def __init__(self, sock):
        self.active = 0
        self.max_active = 0
        self.calls = 0
        self._lock = threading.Lock()
        for name in ("recv", "send", "pending"):
            real = getattr(sock, name)
            setattr(sock, name, self._wrap(real))

    def _wrap(self, real):
        def wrapper(*args, **kwargs):
            with self._lock:
                self.active += 1
                self.calls += 1
                self.max_active = max(self.max_active, self.active)
            try:
                time.sleep(0.002)  # widen the window so any overlap is observed
                return real(*args, **kwargs)
            finally:
                with self._lock:
                    self.active -= 1
        return wrapper


def _reader(peer, sink, stop):
    while not stop.is_set() and peer.connected:
        try:
            chunk = p2p._recv_with_blockingio_retry(peer.sock, 65536, timeout=30.0)
        except socket.timeout:
            continue
        except Exception as exc:  # noqa: BLE001 - test records any failure
            if not stop.is_set():
                sink.append(f"reader exception {type(exc).__name__}: {exc}")
            peer.connected = False
            return
        if not chunk:
            if not stop.is_set():
                sink.append("reader saw EOF")
            peer.connected = False
            return
        sink.append(chunk)


def test_reader_and_writers_never_overlap_inside_one_tls_connection():
    server_sock, client_sock = _make_pair(_contexts())
    monitor = _OverlapMonitor(server_sock)
    peer = PeerConnection("serverpeer0000000", "127.0.0.1", 1, sock=server_sock)
    remote = PeerConnection("clientpeer0000000", "127.0.0.1", 2, sock=client_sock)
    stop = threading.Event()
    got, remote_got = [], []
    threads = [
        threading.Thread(target=_reader, args=(peer, got, stop), daemon=True),
        threading.Thread(target=_reader, args=(remote, remote_got, stop), daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        deadline = time.time() + 3.0
        n = 0
        while time.time() < deadline:
            n += 1
            msg = {"type": "PING", "n": n, "pad": "x" * 500}
            assert peer.send(msg)              # synchronous writer path
            assert peer.send_priority(msg, 1)  # asynchronous writer thread
            assert remote.send(msg)            # makes the server's reader busy too
            time.sleep(0.003)
    finally:
        stop.set()
        peer.close()
        remote.close()
    assert monitor.calls > 20
    assert monitor.max_active == 1, (
        "SSL_read/SSL_write overlapped on one TLS connection "
        f"(max concurrent operations: {monitor.max_active})")
    errors = [x for x in got + remote_got if isinstance(x, str)]
    assert errors == []


def test_idle_reader_does_not_block_a_writer():
    server_sock, client_sock = _make_pair(_contexts())
    done = {}

    def idle_read():
        try:
            tls_recv(server_sock, 65536, 5.0)
        except socket.timeout:
            done["timeout"] = True

    t = threading.Thread(target=idle_read, daemon=True)
    t.start()
    time.sleep(0.3)  # reader is now waiting for data
    started = time.monotonic()
    tls_sendall(server_sock, b"hello\n")
    assert time.monotonic() - started < 1.0, "writer was blocked by an idle reader"
    assert client_sock.recv(16) == b"hello\n"
    client_sock.sendall(b"x")  # wake the reader so the thread ends
    t.join(timeout=5)
    server_sock.close()
    client_sock.close()


def test_large_frame_with_backpressure_arrives_intact():
    server_sock, client_sock = _make_pair(_contexts())
    payload = os.urandom(6 * 1024 * 1024)
    digest = hashlib.sha256(payload).hexdigest()
    received = bytearray()

    def slow_receiver():
        client_sock.settimeout(None)
        while len(received) < len(payload):
            chunk = client_sock.recv(8192)
            if not chunk:
                return
            received.extend(chunk)
            if len(received) < 512 * 1024:
                time.sleep(0.001)  # keep the sender hitting WANT_WRITE early on

    t = threading.Thread(target=slow_receiver, daemon=True)
    t.start()
    tls_sendall(server_sock, payload)
    t.join(timeout=60)
    assert hashlib.sha256(bytes(received)).hexdigest() == digest
    server_sock.close()
    client_sock.close()


def test_tls_recv_timeout_and_eof_semantics_are_preserved():
    server_sock, client_sock = _make_pair(_contexts())
    started = time.monotonic()
    _raises(socket.timeout, tls_recv, server_sock, 1024, 0.4)
    assert 0.3 <= time.monotonic() - started < 2.0
    # Exercise a *graceful TLS EOF*.  SSLSocket.close() may tear down the
    # underlying TCP connection without a TLS close_notify on some Python/
    # OpenSSL combinations, where the peer correctly observes ECONNRESET
    # instead of b"".  unwrap() sends close_notify; run it concurrently because
    # it waits for the peer's reciprocal close_notify.
    shutdown_errors = []

    def clean_client_shutdown():
        try:
            raw = client_sock.unwrap()
            raw.close()
        except Exception as exc:
            shutdown_errors.append(exc)

    shutdown = threading.Thread(target=clean_client_shutdown, daemon=True)
    shutdown.start()
    assert tls_recv(server_sock, 1024, 5.0) == b""
    raw_server = server_sock.unwrap()
    raw_server.close()
    shutdown.join(5.0)
    assert not shutdown.is_alive()
    assert shutdown_errors == []


def test_tls_recv_on_closed_socket_raises_oserror():
    server_sock, client_sock = _make_pair(_contexts())
    server_sock.close()
    _raises(OSError, tls_recv, server_sock, 1024, 1.0)
    client_sock.close()


def test_handshake_recv_line_and_send_work_over_tls():
    server_sock, client_sock = _make_pair(_contexts())
    a = PeerConnection("peer-a-000000000", "127.0.0.1", 1, sock=server_sock)
    b = PeerConnection("peer-b-000000000", "127.0.0.1", 2, sock=client_sock)
    assert a.send({"type": "HELLO", "n": 1})
    assert b.recv_line(timeout=5) == {"type": "HELLO", "n": 1}
    assert b.send({"type": "VERIFY", "n": 2})
    assert a.recv_line(timeout=5) == {"type": "VERIFY", "n": 2}
    assert b.recv_line(timeout=0.3) is None  # nothing pending -> timeout -> None, as before
    a.close()
    b.close()


def test_two_connections_sharing_one_socket_share_one_io_lock():
    server_sock, client_sock = _make_pair(_contexts())
    tmp = PeerConnection("unknown", "127.0.0.1", 1, sock=server_sock)
    final = PeerConnection("finalpeer0000000", "127.0.0.1", 1, sock=server_sock)
    from visold.network.peer_connection import _tls_io_lock, _tls_write_lock
    assert _tls_io_lock(tmp.sock) is _tls_io_lock(final.sock)
    assert _tls_write_lock(tmp.sock) is _tls_write_lock(final.sock)
    tmp.close_writer()
    final.close()
    client_sock.close()


def test_plain_sockets_keep_the_original_unwrapped_path():
    a, b = socket.socketpair()
    pa = PeerConnection("plain-a-00000000", "127.0.0.1", 1, sock=a)
    pb = PeerConnection("plain-b-00000000", "127.0.0.1", 2, sock=b)
    assert pa.send({"type": "PING"})
    assert pb.recv_line(timeout=5) == {"type": "PING"}
    pa.close()
    pb.close()


def test_bidirectional_stress_keeps_every_session_alive():
    pairs = [_make_pair(_contexts()) for _ in range(3)]
    peers, sinks = [], []
    stop = threading.Event()
    for i, (srv, cli) in enumerate(pairs):
        for name, sock in (("srv", srv), ("cli", cli)):
            peer = PeerConnection(f"{name}{i}".ljust(16, "0"), "127.0.0.1", i, sock=sock)
            sink = []
            peers.append(peer)
            sinks.append(sink)
            threading.Thread(target=_reader, args=(peer, sink, stop), daemon=True).start()

    def sender(peer, sync):
        n = 0
        while not stop.is_set() and peer.connected:
            n += 1
            msg = {"type": "PING", "n": n, "pad": "x" * (n % 3000)}
            (peer.send(msg) if sync else peer.send_priority(msg, 1))
            time.sleep(0.004)

    for peer in peers:
        threading.Thread(target=sender, args=(peer, True), daemon=True).start()
        threading.Thread(target=sender, args=(peer, False), daemon=True).start()
    time.sleep(10)
    stop.set()
    lost = [p for p in peers if not p.connected]
    errors = [x for sink in sinks for x in sink if isinstance(x, str)]
    # every received chunk must be a valid framed message stream
    frames = 0
    for sink in sinks:
        data = b"".join(x for x in sink if isinstance(x, bytes))
        for line in data.split(b"\n")[:-1]:
            json.loads(CompressionEngine.decompress(line).decode())
            frames += 1
    for p in peers:
        p.close()
    assert lost == [] and errors == []
    assert frames > 100
