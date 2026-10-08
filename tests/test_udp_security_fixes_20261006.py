"""Regression tests for the confirmed UDP resource-exhaustion vulnerabilities."""

from __future__ import annotations

import socket
import time

from visold.network.udp.reliability import _UDPReassembler
from visold.network.udp.transport import UDPTransport
from visold.network.udp.wire import (
    _F_HB,
    _F_LAST,
    _UDP_FRAG_MAX_PER_GROUP,
    _UDP_MTU,
    _UDP_PAYLOAD_MAX,
    _udp_pack,
    _udp_unpack,
    _xor_bytes,
)


def _send_probe(port: int, count: int = 1):
    """Send valid Visold UDP packets from distinct ephemeral source ports."""
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sockets.append(sock)
            sock.sendto(
                _udp_pack(_F_HB | _F_LAST, 1, 0, 0, b""),
                ("127.0.0.1", port),
            )
    finally:
        for sock in sockets:
            sock.close()


def _wait_until(predicate, timeout: float = 1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def test_udp_admission_rejection_happens_before_session_allocation():
    transport = UDPTransport(
        port=0,
        bind_addr="127.0.0.1",
        max_pending_inbound=8,
    )
    transport.start(
        on_new_peer=lambda _addr: (_ for _ in ()).throw(AssertionError("rejected source reached callback")),
        inbound_admission=lambda _addr: False,
    )
    try:
        port = transport._sock.getsockname()[1]
        _send_probe(port, count=1)
        assert _wait_until(lambda: not transport.has_session(("127.0.0.1", 1)))
        assert not transport._sessions
        assert transport.pending_inbound_count() == 0
    finally:
        transport.stop()


def test_udp_pre_auth_session_budget_caps_new_source_allocation():
    transport = UDPTransport(
        port=0,
        bind_addr="127.0.0.1",
        max_pending_inbound=2,
    )
    transport.start(
        on_new_peer=lambda _addr: None,
        inbound_admission=lambda _addr: True,
    )
    try:
        port = transport._sock.getsockname()[1]
        _send_probe(port, count=10)
        assert _wait_until(lambda: len(transport._sessions) == 2)
        # The important invariant: no matter how many new endpoints arrive,
        # only the configured number can allocate a pre-auth session.
        assert len(transport._sessions) == 2
        assert transport.pending_inbound_count() == 2
    finally:
        transport.stop()


def test_udp_wire_rejects_packets_larger_than_protocol_mtu():
    exact = _udp_pack(_F_HB | _F_LAST, 1, 0, 0, b"x" * _UDP_PAYLOAD_MAX)
    oversized = _udp_pack(_F_HB | _F_LAST, 1, 0, 0, b"x" * (_UDP_PAYLOAD_MAX + 1))
    assert len(exact) == _UDP_MTU
    assert _udp_unpack(exact) is not None
    assert len(oversized) == _UDP_MTU + 1
    assert _udp_unpack(oversized) is None


def test_udp_fec_rejects_out_of_range_offsets_and_oversized_symbols():
    r = _UDPReassembler(1)
    assert r.add_fec(b"ok", 3) is True
    assert r.add_fec(b"bad", _UDP_FRAG_MAX_PER_GROUP) is False
    assert r.add_fec(b"bad", 0xFFFF) is False
    assert r.add_fec(b"x" * (_UDP_PAYLOAD_MAX + 1), 7) is False
    assert len(r.fec_syms) == 1


def test_udp_fec_group_limit_matches_bounded_data_offsets():
    r = _UDPReassembler(2)
    for group in range(_UDP_FRAG_MAX_PER_GROUP // 4):
        assert r.add_fec(b"p", group * 4 + 3) is True
    assert len(r.fec_syms) == _UDP_FRAG_MAX_PER_GROUP // 4
    assert r.add_fec(b"overflow", _UDP_FRAG_MAX_PER_GROUP) is False


def test_udp_fec_recovery_still_works_after_bounds_hardening():
    r = _UDPReassembler(3)
    a, b, c = b"aa", b"bbbb", b"ccc"
    assert r.add_data(0, False, a) is True
    assert r.add_data(2, True, c) is True
    fec = _xor_bytes(_xor_bytes(a, b), c)
    assert r.add_fec(fec, 2) is True
    assert r.try_fec_recover() is True
    assert r.frags[1] == b
    assert r.complete() is True
    assert r.reassemble() == a + b + c
