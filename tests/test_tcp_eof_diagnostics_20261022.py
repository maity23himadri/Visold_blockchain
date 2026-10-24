"""Regression tests for diagnostic-only TCP peer-loop termination reasons.

These tests ensure the logging additions preserve control flow: they don't
change whether the loop disconnects; they only explain why it exited.
"""
import socket
import ssl
from types import SimpleNamespace

import pytest

from visold.network.p2p import P2PNetwork
from visold.network.peer_connection import (
    PeerConnection,
    _enable_strict_tls_eof_diagnostic,
    _tcp_session_diagnostics,
    _tcp_transport_snapshot,
)


class _FakeSock:
    def __init__(self, recv_result=None, recv_exc=None, send_exc=None,
                 tcp_state=1, tls_pending=0):
        self.recv_result = recv_result
        self.recv_exc = recv_exc
        self.send_exc = send_exc
        self.tcp_state = tcp_state
        self.tls_pending = tls_pending
        self._closed = False
        self.timeout_values = []

    def settimeout(self, value):
        self.timeout_values.append(value)

    def recv(self, _size):
        if self.recv_exc is not None:
            raise self.recv_exc
        return self.recv_result

    def sendall(self, _data):
        if self.send_exc is not None:
            raise self.send_exc

    def fileno(self):
        return 42

    def gettimeout(self):
        return self.timeout_values[-1] if self.timeout_values else None

    def pending(self):
        return self.tls_pending

    def getsockopt(self, _level, option, _length=None):
        if option == getattr(socket, "TCP_INFO", None):
            return bytes([self.tcp_state]) + bytes(103)
        raise OSError("unsupported fake socket option")


class _FakePeer:
    def __init__(self, sock):
        self.peer_id = "peer-diagnostics-test"
        self.ip = "127.0.0.1"
        self.port = 12345
        self.local_outbound = True
        self.sock = sock
        self.connected = True
        self._recv_buf = b""
        self._fork_sync_buffer = []
        self._fork_sync_buffer_bytes = 0
        self._fork_sync_target_height = -1

    def send(self, _msg):
        return False


def _bare_network():
    net = object.__new__(P2PNetwork)
    net._running = True
    net._on_peer_disconnect = lambda peer: None
    return net


def test_remote_eof_is_logged_without_changing_disconnect_flow(caplog):
    peer = _FakePeer(_FakeSock(recv_result=b""))
    net = _bare_network()

    with caplog.at_level("INFO"):
        P2PNetwork._peer_message_loop(net, peer)

    assert peer.connected is False
    assert any("[PeerLoopExit]" in r.message and "reason=remote_eof" in r.message for r in caplog.records)
    assert any("peer=peer-diagnos" in r.message for r in caplog.records)
    assert any("session_id=" in r.message and "ts_ns=" in r.message for r in caplog.records)
    assert any("tcp_state=ESTABLISHED" in r.message
               and "ssl_pending=0" in r.message
               and "socket_timeout=30" in r.message
               and "socket_fd=42" in r.message
               for r in caplog.records if "[PeerLoopExit]" in r.message)


def test_strict_tls_eof_diagnostic_is_opt_in(monkeypatch):
    sock = _FakeSock()
    sock.suppress_ragged_eofs = True

    monkeypatch.delenv("VISOLD_TLS_STRICT_EOF_DIAGNOSTIC", raising=False)
    assert _enable_strict_tls_eof_diagnostic(sock) is False
    assert sock.suppress_ragged_eofs is True

    monkeypatch.setenv("VISOLD_TLS_STRICT_EOF_DIAGNOSTIC", "1")
    assert _enable_strict_tls_eof_diagnostic(sock) is True
    assert sock.suppress_ragged_eofs is False


def test_unexpected_recv_exception_logs_type_and_traceback(caplog):
    peer = _FakePeer(_FakeSock(recv_exc=RuntimeError("diagnostic test error")))
    net = _bare_network()

    with caplog.at_level("WARNING"):
        P2PNetwork._peer_message_loop(net, peer)

    assert any("reason=unexpected_exception:RuntimeError" in r.message for r in caplog.records)
    assert any(r.exc_info for r in caplog.records if "PeerLoopExit" in r.message)


def test_ssl_eof_exception_logs_transport_state_before_cleanup(caplog):
    peer = _FakePeer(_FakeSock(
        recv_exc=ssl.SSLEOFError(8, "unexpected EOF"), tcp_state=1))
    net = _bare_network()

    with caplog.at_level("WARNING"):
        P2PNetwork._peer_message_loop(net, peer)

    record = next(r for r in caplog.records
                  if "[PeerLoopExit]" in r.message
                  and "reason=unexpected_exception:SSLEOFError" in r.message)
    assert "tcp_state=ESTABLISHED" in record.message
    assert "socket_fd=42" in record.message


def test_ping_send_failure_after_socket_timeout_has_specific_reason(caplog):
    peer = _FakePeer(_FakeSock(recv_exc=socket.timeout()))
    net = _bare_network()

    with caplog.at_level("WARNING"):
        P2PNetwork._peer_message_loop(net, peer)

    assert any("reason=ping_send_failed_after_socket_timeout" in r.message for r in caplog.records)


def test_peer_send_logs_socket_error_without_payload(caplog):
    peer = PeerConnection("peer-send-test", "127.0.0.1", 12345,
                          sock=_FakeSock(send_exc=BrokenPipeError("pipe broken")))

    with caplog.at_level("WARNING"):
        ok = peer.send({"type": "PING", "nonce": "secret-payload-must-not-log"})

    assert ok is False
    assert peer.connected is False
    assert any("[PeerSendFailure]" in r.message and "BrokenPipeError" in r.message for r in caplog.records)
    assert all("secret-payload-must-not-log" not in r.message for r in caplog.records)


def test_writer_send_failure_logs_original_socket_exception_without_payload(caplog):
    peer = PeerConnection("peer-writer-test", "127.0.0.1", 12347,
                          sock=_FakeSock(send_exc=BrokenPipeError("writer pipe failed")))

    with caplog.at_level("WARNING"):
        ok = peer._raw_send({"type": "BLOCK", "body": "private-payload"})
    peer.close()

    assert ok is False
    assert peer.connected is False
    assert any("path=writer" in r.message and "BrokenPipeError" in r.message
               and "session_id=" in r.message and "ts_ns=" in r.message
               for r in caplog.records)
    assert all("private-payload" not in r.message for r in caplog.records)


def test_endpoint_pair_produces_same_session_id_at_both_tcp_endpoints():
    class _EndpointSock:
        def __init__(self, local, remote):
            self.local = local
            self.remote = remote

        def getsockname(self):
            return self.local

        def getpeername(self):
            return self.remote

    left = _tcp_session_diagnostics(_EndpointSock(("192.0.2.10", 51001),
                                                   ("192.0.2.20", 8338)))
    right = _tcp_session_diagnostics(_EndpointSock(("192.0.2.20", 8338),
                                                    ("192.0.2.10", 51001)))

    assert left[0] == right[0]
    assert left[1] == right[1] == "tcp_endpoint_pair"


def test_tcp_transport_snapshot_decodes_tcp_info_and_ssl_pending():
    snapshot = _tcp_transport_snapshot(
        _FakeSock(tcp_state=8, tls_pending=3))

    assert snapshot["tcp_state"] == "CLOSE_WAIT"
    assert snapshot["tcp_state_code"] == "8"
    assert snapshot["ssl_pending"] == "3"
    assert snapshot["socket_fd"] == "42"
    assert snapshot["socket_closed"] == "False"


def test_last_successfully_received_message_is_in_peer_loop_exit_log(caplog):
    class _SequenceSock:
        def __init__(self):
            self.results = [b'{"type":"PING"}\n', b""]

        def settimeout(self, _value):
            pass

        def recv(self, _size):
            return self.results.pop(0)

    peer = _FakePeer(_SequenceSock())
    net = _bare_network()
    net._handle_message = lambda _peer, _msg: None

    with caplog.at_level("INFO"):
        P2PNetwork._peer_message_loop(net, peer)

    exit_rows = [r.message for r in caplog.records if "[PeerLoopExit]" in r.message]
    assert len(exit_rows) == 1
    assert "reason=remote_eof" in exit_rows[0]
    assert "last_rx_message_type=PING" in exit_rows[0]
    assert "last_rx_message_ts_ns=" in exit_rows[0]


def test_peer_close_logs_immediate_caller_and_does_not_log_payload(caplog):
    peer = PeerConnection("peer-close-test", "127.0.0.1", 12346,
                          sock=_FakeSock(recv_result=b""))
    with caplog.at_level("INFO"):
        peer.close()
    close_rows = [r.message for r in caplog.records if "[PeerSocketClose]" in r.message]
    assert close_rows
    assert "caller=test_peer_close_logs_immediate_caller_and_does_not_log_payload" in close_rows[0]
    assert "peer-close-test"[:12] in close_rows[0]


def _tls_socket_pair_without_handshake():
    left, right = socket.socketpair()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls_sock = ctx.wrap_socket(left, server_hostname=None,
                               do_handshake_on_connect=False)
    return tls_sock, right


def test_unwrapped_tls_socket_close_reports_caller_and_session(caplog):
    tls_sock, other_sock = _tls_socket_pair_without_handshake()
    peer = PeerConnection("peer-raw-close-test", "127.0.0.1", 12348,
                          sock=tls_sock)
    peer.close_writer()

    try:
        with caplog.at_level("WARNING"):
            # Deliberately bypass PeerConnection.close() as the broad
            # connect_to() exception cleanup can do after registration.
            tls_sock.close()
        rows = [r.message for r in caplog.records
                if "[PeerRawSocketAction]" in r.message]
        assert len(rows) == 1
        assert "operation=close" in rows[0]
        assert "peer=peer-raw-clo" in rows[0]
        assert "session_id=" in rows[0]
        assert "caller=test_unwrapped_tls_socket_close_reports_caller_and_session" in rows[0]
    finally:
        peer.close()
        other_sock.close()


def test_normal_peer_close_suppresses_raw_socket_duplicate_audit(caplog):
    tls_sock, other_sock = _tls_socket_pair_without_handshake()
    peer = PeerConnection("peer-guarded-close-test", "127.0.0.1", 12349,
                          sock=tls_sock)
    try:
        with caplog.at_level("INFO"):
            peer.close()
        assert any("[PeerSocketClose]" in r.message for r in caplog.records)
        assert not any("[PeerRawSocketAction]" in r.message
                       for r in caplog.records)
    finally:
        other_sock.close()


def test_tls_unwrap_reports_caller_when_it_bypasses_peer_close(caplog):
    tls_sock, other_sock = _tls_socket_pair_without_handshake()
    peer = PeerConnection("peer-unwrap-test", "127.0.0.1", 12350,
                          sock=tls_sock)
    peer.close_writer()
    try:
        with caplog.at_level("WARNING"):
            with pytest.raises((ssl.SSLError, OSError)):
                tls_sock.unwrap()
        assert any("[PeerRawSocketAction]" in r.message
                   and "operation=unwrap" in r.message
                   and "peer=peer-unwrap" in r.message
                   for r in caplog.records)
    finally:
        peer.close()
        other_sock.close()


def test_tls_shutdown_reports_caller_and_half_close_direction(caplog):
    tls_sock, other_sock = _tls_socket_pair_without_handshake()
    peer = PeerConnection("peer-shutdown-test", "127.0.0.1", 12351,
                          sock=tls_sock)
    peer.close_writer()
    try:
        with caplog.at_level("WARNING"):
            tls_sock.shutdown(socket.SHUT_RD)
        assert any("[PeerRawSocketAction]" in r.message
                   and "operation=shutdown" in r.message
                   and "detail=0" in r.message
                   and "peer=peer-shutdo" in r.message
                   and "caller=test_tls_shutdown_reports_caller_and_half_close_direction" in r.message
                   for r in caplog.records)
    finally:
        peer.close()
        other_sock.close()


def test_recv_timeout_does_not_ping_session_already_marked_disconnected(caplog):
    class _PeerMarkedDisconnectedDuringRecv(_FakePeer):
        def __init__(self, sock):
            super().__init__(sock)
            self.send_calls = 0

        def send(self, _msg):
            self.send_calls += 1
            return False

    class _TimeoutSocket(_FakeSock):
        def __init__(self, peer_holder):
            super().__init__()
            self.peer_holder = peer_holder

        def recv(self, _size):
            self.peer_holder[0].connected = False
            raise socket.timeout()

    holder = []
    peer = _PeerMarkedDisconnectedDuringRecv(_TimeoutSocket(holder))
    holder.append(peer)
    net = _bare_network()

    with caplog.at_level("INFO"):
        P2PNetwork._peer_message_loop(net, peer)

    assert peer.send_calls == 0
    assert any("reason=peer_marked_disconnected_elsewhere" in r.message
               for r in caplog.records if "[PeerLoopExit]" in r.message)


def test_eof_after_local_send_failure_is_not_mislabelled_remote_eof(caplog):
    peer = _FakePeer(_FakeSock(recv_result=b""))
    peer._local_transport_failure_reason = "async_writer_sendall_failed"
    net = _bare_network()

    with caplog.at_level("INFO"):
        P2PNetwork._peer_message_loop(net, peer)

    assert any("reason=local_transport_failure:async_writer_sendall_failed:recv_eof" in r.message
               for r in caplog.records if "[PeerLoopExit]" in r.message)
    assert not any("reason=remote_eof" in r.message
                   for r in caplog.records if "[PeerLoopExit]" in r.message)


def test_reader_exception_after_socket_closed_is_not_misreported_as_unexpected(caplog):
    class _ClosedSock(_FakeSock):
        def __init__(self):
            super().__init__(recv_exc=OSError(9, "Bad file descriptor"))
            self._closed = True

        def fileno(self):
            return -1

    # Model the real close race: another thread closed the descriptor, but
    # this thread has not yet observed connected=False.
    peer = _FakePeer(_ClosedSock())
    net = _bare_network()

    with caplog.at_level("INFO"):
        P2PNetwork._peer_message_loop(net, peer)

    rows = [r for r in caplog.records if "[PeerLoopExit]" in r.message]
    assert rows
    assert any("reason=socket_already_closed_before_reader_exception:OSError" in r.message
               for r in rows)
    assert not any("reason=unexpected_exception:OSError" in r.message for r in rows)
    assert not any(r.exc_info for r in rows)
