"""Regression tests for transient BlockingIOError on timed TLS recv."""
import socket

import pytest

from visold.network import p2p


class _FakeTLSReadSocket:
    def __init__(self, errors=1, payload=b'{"type":"PING"}\\n', pending=0):
        self.errors_left = errors
        self.payload = payload
        self.pending_count = pending
        self.recv_calls = 0
        self.pending_calls = 0

    def recv(self, _size):
        self.recv_calls += 1
        if self.errors_left:
            self.errors_left -= 1
            raise BlockingIOError(11, "Resource temporarily unavailable")
        return self.payload

    def pending(self):
        self.pending_calls += 1
        return self.pending_count


def test_transient_blockingio_waits_for_readability_and_retries(monkeypatch):
    sock = _FakeTLSReadSocket(errors=1)
    calls = []

    def ready(readers, writers, exceptional, timeout):
        calls.append(timeout)
        assert readers == [sock]
        assert writers == []
        assert exceptional == []
        return [sock], [], []

    monkeypatch.setattr(p2p.select, "select", ready)
    result = p2p._recv_with_blockingio_retry(sock, 65536, timeout=30.0)

    assert result == b'{"type":"PING"}\\n'
    assert sock.recv_calls == 2
    assert calls and 0 < calls[0] <= 30.0


def test_buffered_tls_data_gets_bounded_immediate_retries(monkeypatch):
    sock = _FakeTLSReadSocket(errors=1, pending=4)

    def should_not_wait(*_args, **_kwargs):
        pytest.fail("buffered TLS plaintext should be retried before select")

    monkeypatch.setattr(p2p.select, "select", should_not_wait)
    result = p2p._recv_with_blockingio_retry(sock, 65536, timeout=30.0)

    assert result == b'{"type":"PING"}\\n'
    assert sock.recv_calls == 2
    assert sock.pending_calls == 1


def test_blockingio_readiness_timeout_uses_existing_socket_timeout_path(monkeypatch):
    sock = _FakeTLSReadSocket(errors=1)

    def not_ready(readers, writers, exceptional, timeout):
        assert readers == [sock]
        assert 0 <= timeout <= 30.0
        return [], [], []

    monkeypatch.setattr(p2p.select, "select", not_ready)
    with pytest.raises(socket.timeout):
        p2p._recv_with_blockingio_retry(sock, 65536, timeout=30.0)
    assert sock.recv_calls == 1
