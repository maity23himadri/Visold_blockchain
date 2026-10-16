"""Regression tests for audit findings VSA-15, VSA-16, VSA-17 and VSA-18."""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time

import visold.network.p2p as p2p
from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork
from visold.storage.storage import Storage


def _storage(td: str) -> Storage:
    return Storage(os.path.join(td, "peers.db"))


def _net(storage=None) -> P2PNetwork:
    net = object.__new__(P2PNetwork)
    if storage is not None:
        net.storage = storage
    return net


def _future(seconds: int = 3600) -> str:
    return json.dumps({"until": int(time.time()) + seconds, "reason": "test"})


def _set_peer_columns(st: Storage, peer_id: str, **columns) -> None:
    assignments = ", ".join(f"{name}=?" for name in columns)
    st._conn().execute(
        f"UPDATE peers SET {assignments} WHERE peer_id=?",
        (*columns.values(), peer_id))
    st._conn().commit()


def _peer_row(st: Storage, peer_id: str):
    return st._conn().execute(
        "SELECT * FROM peers WHERE peer_id=?", (peer_id,)).fetchone()


# ── VSA-15: subnet bans are enforced by the ban check ───────────────────────

def test_subnet_ban_applies_to_fresh_addresses_inside_the_banned_ipv4_subnet():
    with tempfile.TemporaryDirectory() as td:
        st = _storage(td)
        st.set_meta("subnet_ban:192.168.1.0/24", _future())
        net = _net(st)
        assert net._is_ip_banned("192.168.1.77") is True
        assert net._is_ip_banned("192.168.1.250") is True


def test_subnet_ban_does_not_apply_outside_the_banned_subnet():
    with tempfile.TemporaryDirectory() as td:
        st = _storage(td)
        st.set_meta("subnet_ban:192.168.1.0/24", _future())
        assert _net(st)._is_ip_banned("192.168.2.5") is False


def test_expired_and_malformed_subnet_records_are_not_enforced():
    with tempfile.TemporaryDirectory() as td:
        st = _storage(td)
        st.set_meta("subnet_ban:10.0.0.0/24", _future(seconds=-60))
        st.set_meta("subnet_ban:10.0.1.0/24", "not-json")
        st.set_meta("subnet_ban:10.0.2.0/24", json.dumps(["not", "a", "record"]))
        net = _net(st)
        assert net._is_ip_banned("10.0.0.5") is False
        assert net._is_ip_banned("10.0.1.5") is False
        assert net._is_ip_banned("10.0.2.5") is False


def test_ipv6_subnet_ban_matches_every_spelling_of_the_same_48_only():
    with tempfile.TemporaryDirectory() as td:
        st = _storage(td)
        st.set_meta(f"subnet_ban:{P2PNetwork._ip_subnet('2001:db8:1::5')}", _future())
        net = _net(st)
        assert net._is_ip_banned("2001:DB8:1:0:0:0:0:9") is True
        assert net._is_ip_banned("2001:db8:1:ffff::9") is True
        assert net._is_ip_banned("2001:db8:2::9") is False


def test_subnet_key_is_canonical_for_ipv4_and_ipv4_mapped_addresses():
    assert P2PNetwork._ip_subnet("192.168.1.77") == "192.168.1.0/24"
    assert P2PNetwork._ip_subnet("::ffff:192.168.1.77") == "192.168.1.0/24"
    assert P2PNetwork._ip_subnet("not-an-ip") == "not-an-ip"


# ── VSA-16: registrations never erase TLS fingerprints, scores or blacklists ─

def test_save_peer_preserves_tls_fingerprint_and_ban_score_across_a_reconnect():
    with tempfile.TemporaryDirectory() as td:
        st = _storage(td)
        st.save_peer("peer-a", "10.1.0.1", 9000, reputation=0.9)
        _set_peer_columns(st, "peer-a", tls_fp="ab" * 32, ban_score=15)

        st.save_peer("peer-a", "10.1.0.2", 9001, reputation=0.8)

        row = _peer_row(st, "peer-a")
        assert row["tls_fp"] == "ab" * 32, "reconnect erased the stored TLS fingerprint (VSA-16)"
        assert row["ban_score"] == 15, "reconnect reset the ban score (VSA-16)"
        assert row["ip"] == "10.1.0.2" and row["port"] == 9001
        assert abs(row["reputation"] - 0.8) < 1e-9


def test_save_peer_does_not_clear_an_existing_blacklist():
    with tempfile.TemporaryDirectory() as td:
        st = _storage(td)
        st.save_peer("peer-b", "10.1.1.1", 9000)
        _set_peer_columns(st, "peer-b", blacklisted=1)

        st.save_peer("peer-b", "10.1.1.1", 9000)

        assert _peer_row(st, "peer-b")["blacklisted"] == 1, (
            "a registration cleared a blacklist (VSA-16/VSA-17)")


# ── VSA-17: routine failure updates never clear an explicit blacklist ───────

def test_routine_failure_update_never_clears_an_explicit_blacklist_at_high_reputation():
    with tempfile.TemporaryDirectory() as td:
        st = _storage(td)
        st.save_peer("peer-c", "10.2.0.1", 9000, reputation=1.0)
        _set_peer_columns(st, "peer-c", blacklisted=1)

        st.mark_peer_fail("peer-c")

        assert _peer_row(st, "peer-c")["blacklisted"] == 1, (
            "disconnect cleanup cleared a strike-three blacklist (VSA-17)")


def test_failure_update_keeps_the_blacklist_flag_at_low_reputation():
    with tempfile.TemporaryDirectory() as td:
        st = _storage(td)
        st.save_peer("peer-d", "10.2.0.2", 9000, reputation=0.2)
        _set_peer_columns(st, "peer-d", blacklisted=1, fail_count=0)

        st.mark_peer_fail("peer-d")

        assert _peer_row(st, "peer-d")["blacklisted"] == 1


def test_failure_counting_applies_the_sanction_at_the_limit_and_not_before():
    with tempfile.TemporaryDirectory() as td:
        st = _storage(td)
        st.save_peer("peer-e", "10.2.1.1", 9000, reputation=0.2)
        limit = int(Config.PEER_MAX_FAIL)
        for expected_fail in range(1, limit):
            st.mark_peer_fail("peer-e")
            row = _peer_row(st, "peer-e")
            assert row["fail_count"] == expected_fail
            assert row["blacklisted"] == 0, "sanction applied before the limit"
        st.mark_peer_fail("peer-e")
        assert _peer_row(st, "peer-e")["blacklisted"] == 1, "sanction not applied at the limit"


# ── VSA-18: bounded inbound TLS handshake ────────────────────────────────────

class _FakeSock:
    def __init__(self):
        self.timeouts = []
        self.closed = False

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True


class _FakeTLSContext:
    def __init__(self, stall=False):
        self.stall = stall
        self.seen_timeouts = []
        self.wrapped = []

    def wrap_socket(self, sock, server_side=False):
        assert server_side is True
        self.seen_timeouts.append(sock.timeouts[-1] if sock.timeouts else None)
        if self.stall:
            raise socket.timeout("handshake stalled")
        wrapped = _FakeSock()
        self.wrapped.append(wrapped)
        return wrapped


def _slot_is_free() -> bool:
    if not p2p._TLS_HANDSHAKE_SLOTS.acquire(blocking=False):
        return False
    p2p._TLS_HANDSHAKE_SLOTS.release()
    return True


def test_stalled_inbound_handshake_is_bounded_closed_and_releases_its_slot(monkeypatch):
    monkeypatch.setattr(p2p, "_TLS_HANDSHAKE_SLOTS", threading.BoundedSemaphore(1))
    sock = _FakeSock()
    ctx = _FakeTLSContext(stall=True)

    assert _net()._wrap_inbound_tls(sock, ctx, "10.9.9.9") is None
    assert sock.closed, "a stalled handshake left its socket open"
    assert ctx.seen_timeouts == [float(Config.P2P_TLS_HANDSHAKE_TIMEOUT)], (
        "the handshake ran without the explicit timeout (VSA-18)")
    assert _slot_is_free(), "a failed handshake leaked its concurrency slot"


def test_completed_inbound_handshake_restores_blocking_mode_and_releases_its_slot(monkeypatch):
    monkeypatch.setattr(p2p, "_TLS_HANDSHAKE_SLOTS", threading.BoundedSemaphore(1))
    sock = _FakeSock()
    ctx = _FakeTLSContext()

    wrapped = _net()._wrap_inbound_tls(sock, ctx, "10.9.9.8")

    assert wrapped is not None and wrapped is ctx.wrapped[0]
    assert wrapped.timeouts == [None], "blocking mode was not restored after the handshake"
    assert not sock.closed
    assert _slot_is_free()


def test_inbound_handshake_is_refused_at_once_when_the_concurrency_cap_is_reached(monkeypatch):
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(p2p, "_TLS_HANDSHAKE_SLOTS", slots)
    assert slots.acquire(blocking=False), "test setup: the only slot must be taken"
    sock = _FakeSock()
    ctx = _FakeTLSContext()

    assert _net()._wrap_inbound_tls(sock, ctx, "10.9.9.7") is None
    assert sock.closed
    assert ctx.seen_timeouts == [], "a refused connection still started handshake work"
    slots.release()
