"""Section 106 V4 Regression Tests: UDP Reliability, Retransmission, Fragmentation and FEC."""

import hashlib
import json
import os
import socket
import sys
import threading
import time

import pytest

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.network.udp.reliability import _UDPReassembler
from visold.network.udp.session import UDPSession
from visold.network.udp.transport import UDPPeerConnection, UDPTransport
from visold.network.udp.wire import (
    _F_FEC,
    _F_FRAG,
    _F_LAST,
    _UDP_CWND_INIT,
    _UDP_FEC_GROUP,
    _UDP_PAYLOAD_MAX,
    _udp_compress,
    _xor_bytes,
)


def test_dualstack_udp_transport_sends_to_ipv4_peer():
    """V4 Regression: Dual-stack UDPTransport.sendto() handles IPv4 addresses without gaierror."""
    t_sender = UDPTransport(0)
    t_receiver = UDPTransport(0)
    if t_sender._sock.family != socket.AF_INET6:
        t_sender.stop()
        t_receiver.stop()
        pytest.skip("Host does not support AF_INET6 dual-stack sockets")

    t_sender.start()
    t_receiver.start()
    try:
        t_sender.sendto(b"probe", ("127.0.0.1", t_receiver._port))

        sess = t_sender.get_session(("127.0.0.1", t_receiver._port))
        sess.send_message(b'{"type": "PING"}')
        deadline = time.monotonic() + 2.0
        while ("127.0.0.1", t_sender._port) not in t_receiver._sessions and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ("127.0.0.1", t_sender._port) in t_receiver._sessions
    finally:
        t_sender.stop()
        t_receiver.stop()


def test_send_message_aborts_promptly_when_closed_while_window_full():
    """V4 Regression: UDPSession.send_message() aborts promptly if close() is called while full."""

    class _DummyTransport:
        def __init__(self):
            self.sent = []

        def sendto(self, pkt, addr):
            self.sent.append(pkt)

    transport = _DummyTransport()
    sess = UDPSession(transport, ("127.0.0.1", 9999))

    n_frags = _UDP_CWND_INIT * 3
    payload = b"A" * (n_frags * _UDP_PAYLOAD_MAX)

    exc_holder = []

    def _run_send():
        try:
            sess.send_message(payload)
        except Exception as e:
            exc_holder.append(e)

    t = threading.Thread(target=_run_send, daemon=True)
    t.start()

    deadline = time.monotonic() + 2.0
    while not sess._window.is_full() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert sess._window.is_full()

    sess.close()

    t.join(timeout=1.5)
    assert not t.is_alive(), "Expected send_message() to abort promptly after close()"
    assert len(exc_holder) == 1 and isinstance(exc_holder[0], ConnectionError)


def test_try_fec_recover_preserves_last_fragment_trailing_null_bytes():
    """V4 Regression: try_fec_recover() preserves legitimate trailing 0x00 bytes on last_off."""
    frag0 = b"B" * _UDP_PAYLOAD_MAX
    frag1 = b"TAIL_DATA\x00\x00"
    fec_sym = _xor_bytes(frag0, frag1)

    r2 = _UDPReassembler(frag_id=2)
    r2.last_off = 1
    r2.add_data(0, False, frag0)
    r2.add_fec(fec_sym, group_end_off=1)
    assert r2.try_fec_recover() is True
    assert r2.complete() is True
    reassembled = r2.reassemble()
    assert reassembled.startswith(frag0 + frag1)
    assert reassembled != frag0 + b"TAIL_DATA"


def test_try_fec_recover_preserves_zlib_adler32_ending_in_zero_and_delivers_msg():
    """V4 Regression: JSON payload whose zlib Adler-32 trailer ends in 0x00 is recovered and delivered."""
    target_compressed = None
    target_msg = None
    base_hex = "".join(hashlib.sha256(f"k{j}".encode()).hexdigest() for j in range(80))
    for i in range(10000):
        msg_obj = {"pad": base_hex, "tail": "a" * i}
        candidate = json.dumps(msg_obj).encode()
        comp = _udp_compress(candidate)
        if comp != candidate and comp.endswith(b"\x00"):
            target_compressed = comp
            target_msg = msg_obj
            break
    assert target_compressed is not None

    chunks = [
        target_compressed[i : i + _UDP_PAYLOAD_MAX]
        for i in range(0, len(target_compressed), _UDP_PAYLOAD_MAX)
    ]
    assert len(chunks) >= 2
    last_off = len(chunks) - 1
    group_start = (last_off // _UDP_FEC_GROUP) * _UDP_FEC_GROUP
    fec_acc = b""
    for off in range(group_start, last_off + 1):
        fec_acc = _xor_bytes(fec_acc, chunks[off])

    class _DummyTransport:
        def sendto(self, pkt, addr):
            pass

    sess = UDPSession(_DummyTransport(), ("127.0.0.1", 9999))
    try:
        r = sess._get_or_create_reassembler(10)
        for off in range(last_off):
            r.add_data(off, False, chunks[off])
        r.last_off = last_off
        r.add_fec(fec_acc, last_off)
        assert r.try_fec_recover() is True
        sess._try_deliver(10, r)
        assert not sess.inbound.empty()
        assert sess.inbound.get_nowait() == target_msg
    finally:
        sess.close()


def test_on_packet_triggers_fec_recovery_when_fec_arrives_before_last_frag():
    """V4 Regression: on_packet() triggers try_fec_recover() after add_data() when FEC arrived earlier."""

    class _DummyTransport:
        def sendto(self, pkt, addr):
            pass

    sess = UDPSession(_DummyTransport(), ("127.0.0.1", 9999))
    try:
        msg = {"type": "TEST", "body": "Z" * 5000}
        raw = json.dumps(msg).encode()
        chunks = [
            raw[i : i + _UDP_PAYLOAD_MAX]
            for i in range(0, len(raw), _UDP_PAYLOAD_MAX)
        ]
        assert len(chunks) == 4

        fec_sym = b""
        for c in chunks:
            fec_sym = _xor_bytes(fec_sym, c)

        sess.on_packet(_F_FRAG, 1, 7, 0, chunks[0])
        sess.on_packet(_F_FRAG, 2, 7, 2, chunks[2])
        sess.on_packet(_F_FEC | _F_LAST, 3, 7, 3, fec_sym)
        assert sess.inbound.empty()

        sess.on_packet(_F_FRAG | _F_LAST, 4, 7, 3, chunks[3])

        assert not sess.inbound.empty()
        assert sess.inbound.get_nowait() == msg
    finally:
        sess.close()


def test_try_fec_recover_rejects_short_group_end():
    """V4 Regression: try_fec_recover() rejects FEC symbols whose group_end < miss_off."""
    r = _UDPReassembler(frag_id=9)
    f0 = b"0" * 10
    f1 = b"1" * 10
    f2 = b"2" * 10

    r.add_data(0, False, f0)
    r.add_data(1, False, f1)
    r.add_data(2, False, f2)
    r.add_data(4, True, b"4" * 10)

    assert r.add_fec(b"X" * 10, group_end_off=0) is True
    assert r.try_fec_recover() is False
    assert r.complete() is False


def test_udp_peer_connection_close_removes_session_from_transport():
    """V4 Regression: UDPPeerConnection.close() removes the session from UDPTransport."""
    t_server = UDPTransport(0, bind_addr="127.0.0.1")
    t_client = UDPTransport(0, bind_addr="127.0.0.1")
    t_server.start()
    t_client.start()
    try:
        peer_addr = ("127.0.0.1", t_client._port)
        sess = t_server.get_session(peer_addr)
        conn = UDPPeerConnection("peer1", "127.0.0.1", t_client._port, sess)

        conn.close()
        assert not t_server.has_session(peer_addr)

        c_sess = t_client.get_session(("127.0.0.1", t_server._port))
        c_sess.send_message(b'{"type": "HELLO"}')
        time.sleep(0.15)

        new_sess = t_server.get_session(peer_addr)
        assert new_sess is not sess
        assert new_sess.inbound.get(timeout=1.0) == {"type": "HELLO"}
    finally:
        t_server.stop()
        t_client.stop()
