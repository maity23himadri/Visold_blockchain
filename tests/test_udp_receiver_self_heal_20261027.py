"""Regression tests for UDP receiver failure recovery and stale-GC races."""

import errno
import socket
import threading

import visold.network.udp.transport as transport_module
from visold.network.udp.transport import UDPTransport
from visold.network.udp.session import UDPSession


class _FailOnceSocket:
    def __init__(self, on_recv=None, fail_first=False):
        self.on_recv = on_recv
        self.fail_first = fail_first
        self.recv_calls = 0
        self.closed = False
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def recvfrom(self, _size):
        self.recv_calls += 1
        if self.fail_first and self.recv_calls == 1:
            raise OSError(9, "simulated receive socket failure")
        if self.on_recv is not None:
            self.on_recv()
        raise socket.timeout()

    def close(self):
        self.closed = True

    def sendto(self, data, addr):
        if self.closed:
            raise OSError("socket is closed")
        return len(data)

    def getsockname(self):
        return ("127.0.0.1", 18338)


def test_recv_loop_recreates_socket_instead_of_silently_dying(monkeypatch, caplog):
    transport = object.__new__(UDPTransport)
    transport._port = 18338
    transport._bind_addr = "127.0.0.1"
    transport._socket_lock = threading.RLock()
    transport._running = True
    initial = _FailOnceSocket(fail_first=True)
    replacement = _FailOnceSocket(on_recv=lambda: setattr(transport, "_running", False))
    transport._sock = initial
    created = []

    def create_socket():
        created.append(replacement)
        return replacement

    transport._create_socket = create_socket
    monkeypatch.setattr(transport_module.time, "sleep", lambda _delay: None)

    transport._recv_loop()

    assert initial.closed is True
    assert transport._sock is replacement
    assert replacement.recv_calls == 1
    assert created == [replacement]
    assert "UDP receive socket recovered" in caplog.text
    # The receiver exits only because the test explicitly shut it down, not
    # because the first OSError terminated the loop.



def test_repeated_transient_receive_errors_eventually_rebuild_socket(monkeypatch, caplog):
    transport = object.__new__(UDPTransport)
    transport._port = 18340
    transport._bind_addr = "127.0.0.1"
    transport._socket_lock = threading.RLock()
    transport._running = True

    class _TransientSocket(_FailOnceSocket):
        def recvfrom(self, _size):
            self.recv_calls += 1
            if self.recv_calls <= 3:
                raise OSError(errno.ENOBUFS, "simulated transient receive pressure")
            transport._running = False
            raise socket.timeout()

    initial = _TransientSocket()
    replacement = _FailOnceSocket(
        on_recv=lambda: setattr(transport, "_running", False))
    transport._sock = initial
    created = []

    def create_socket():
        created.append(replacement)
        return replacement

    transport._create_socket = create_socket
    monkeypatch.setattr(transport_module.time, "sleep", lambda _delay: None)

    transport._recv_loop()

    assert initial.closed is True
    assert transport._sock is replacement
    assert initial.recv_calls == 3
    assert created == [replacement]
    assert "Transient UDP receive error" in caplog.text
    assert "UDP receive socket recovered" in caplog.text

def test_packet_dispatch_exception_does_not_kill_receiver(monkeypatch, caplog):
    transport = object.__new__(UDPTransport)
    transport._port = 18339
    transport._bind_addr = "127.0.0.1"
    transport._socket_lock = threading.RLock()
    transport._lock = threading.Lock()
    transport._sessions = {}
    transport._pending_inbound = set()
    transport._max_pending_inbound = 16
    transport._running = True

    class _PacketSocket(_FailOnceSocket):
        def recvfrom(self, _size):
            self.recv_calls += 1
            if self.recv_calls == 1:
                return (b"valid-wire", ("127.0.0.1", 9999))
            transport._running = False
            raise socket.timeout()

    sock = _PacketSocket()
    transport._sock = sock
    transport._on_new_peer = None
    transport._inbound_admission = None
    transport._admit_inbound = lambda _addr: True
    transport.release_inbound = lambda _addr: None
    transport._get_or_create_session = lambda _addr: (_BrokenSession(), False)
    monkeypatch.setattr(transport_module, "_udp_unpack", lambda _data: (1, 2, 3, 4, b""))
    monkeypatch.setattr(transport_module.time, "sleep", lambda _delay: None)

    transport._recv_loop()

    assert sock.recv_calls == 2
    assert "Dropping UDP datagram after dispatch failure" in caplog.text


class _BrokenSession:
    def on_packet(self, *_args):
        raise RuntimeError("simulated bad packet handler")


def test_gc_does_not_remove_replacement_session_from_stale_snapshot(monkeypatch):
    transport = object.__new__(UDPTransport)
    transport._running = True
    transport._lock = threading.Lock()
    transport._pending_inbound = set()
    addr = ("127.0.0.1", 9998)
    replacement = _GcSession(alive=True)

    class _OldSession(_GcSession):
        def expire_if_silent(self):
            with transport._lock:
                transport._sessions[addr] = replacement
            transport._running = False
            return True

    old = _OldSession(alive=False)
    old.closed = False
    replacement.closed = False
    transport._sessions = {addr: old}
    monkeypatch.setattr(transport_module.time, "sleep", lambda _delay: None)

    transport._gc_loop()

    assert transport._sessions[addr] is replacement
    assert replacement.closed is False
    assert old.closed is False


class _GcSession:
    def __init__(self, alive):
        self.alive = alive
        self.closed = False

    def is_alive(self):
        return self.alive

    def close(self):
        self.closed = True


def test_expired_udp_session_cannot_be_revived_by_late_packet():
    # Construct only the liveness state to avoid starting a retransmit thread.
    session = object.__new__(UDPSession)
    session._liveness_lock = threading.Lock()
    session._liveness_expired = False
    session._last_hb_recv = 0.0
    assert session.expire_if_silent(now=10**12) is True
    session.on_packet(0, 1, 1, 0, b"")
    assert session.is_alive() is False


def test_late_identity_scoped_cleanup_does_not_release_new_admission_slot():
    transport = UDPTransport(port=0, bind_addr="127.0.0.1")
    addr = ("127.0.0.1", 9997)
    old = _GcSession(alive=False)
    replacement = _GcSession(alive=True)
    try:
        with transport._lock:
            transport._sessions[addr] = replacement
            transport._pending_inbound.add(addr)
        assert transport.remove_session(addr, expected_session=old) is False
        assert transport._sessions[addr] is replacement
        assert addr in transport._pending_inbound
        assert replacement.closed is False
    finally:
        transport.remove_session(addr)
        transport._sock.close()
