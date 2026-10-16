"""Regression tests for audit findings VSA-09, VSA-12 and VSA-14."""

from __future__ import annotations

import socket
import threading
from collections import defaultdict, deque

from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork, _create_dual_stack_server_socket

try:
    from visold.kernel.netutil import wildcard_for_family
except ImportError:  # the original code has no such helper; the tests then fail clearly
    wildcard_for_family = None


def _free_base_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _listener_net(port: int) -> P2PNetwork:
    net = object.__new__(P2PNetwork)
    net.port = port
    net._running = True
    return net


class _NoBans:
    def get_meta(self, key):
        return None


def _admission_net() -> P2PNetwork:
    net = object.__new__(P2PNetwork)
    net.storage = _NoBans()
    net._lock = threading.RLock()
    net._conn_rate = defaultdict(deque)
    return net


# ── VSA-12: the wildcard follows the socket's address family ────────────────

def test_wildcard_is_chosen_for_the_socket_family():
    assert wildcard_for_family(socket.AF_INET, "::") == "0.0.0.0"
    assert wildcard_for_family(socket.AF_INET, None) == "0.0.0.0"
    assert wildcard_for_family(socket.AF_INET, "") == "0.0.0.0"
    assert wildcard_for_family(socket.AF_INET6, None) == "::"
    assert wildcard_for_family(socket.AF_INET6, "::") == "::"
    assert wildcard_for_family(socket.AF_INET, "192.168.1.5") == "192.168.1.5"
    try:
        wildcard_for_family(socket.AF_INET, "::1")
    except ValueError:
        pass
    else:
        raise AssertionError("an IPv6 literal must not be bound by an IPv4 socket (VSA-12)")


# ── VSA-14: the listener never takes the RPC port and reports failure ───────

def test_listener_skips_an_occupied_port_and_never_takes_the_rpc_port():
    base = _free_base_port()
    rpc_port = base + Config.RPC_PORT_OFFSET
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("0.0.0.0", base))
    srv = _create_dual_stack_server_socket(base)
    try:
        net = _listener_net(base)
        assert net._bind_listener(srv, base) is True, "a free candidate port existed"
        assert net.port != base, "the occupied configured port was reported as bound"
        assert net.port != rpc_port, "the listener took the RPC port (VSA-14)"
    finally:
        srv.close()
        blocker.close()


def test_listener_reports_failure_instead_of_raising_when_nothing_is_free(monkeypatch):
    base = _free_base_port()
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("0.0.0.0", base))
    monkeypatch.setattr(P2PNetwork, "_LISTEN_PORT_SEARCH", 1)   # base only; RPC port excluded
    srv = _create_dual_stack_server_socket(base)
    try:
        assert _listener_net(base)._bind_listener(srv, base) is False
    finally:
        srv.close()
        blocker.close()


# ── VSA-09: UDP and TCP admission windows are separate ──────────────────────

def test_udp_admissions_do_not_consume_the_tcp_admission_window():
    net = _admission_net()
    ip = "10.6.6.6"
    for _ in range(P2PNetwork._CONN_RATE_LIMIT + 1):
        net._udp_admit_inbound((ip, 9000))
    assert net._udp_admit_inbound((ip, 9000)) is False, "the UDP window should be full"
    assert net._tcp_admit_inbound(ip) is True, (
        "UDP attempts consumed the TCP admission budget (VSA-09)")


def test_tcp_window_still_limits_tcp_admissions():
    net = _admission_net()
    ip = "10.6.6.7"
    for _ in range(P2PNetwork._CONN_RATE_LIMIT):
        assert net._tcp_admit_inbound(ip) is True
    assert net._tcp_admit_inbound(ip) is False


class _SubnetBanned:
    """Storage stub with one active subnet ban record covering 10.8.8.0/24."""

    def get_meta(self, key):
        if key == "subnet_ban:10.8.8.0/24":
            return '{"until": %d, "reason": "test"}' % (int(__import__("time").time()) + 3600)
        return None


def test_udp_inbound_admission_refuses_an_address_in_a_banned_subnet():
    net = _admission_net()
    net.storage = _SubnetBanned()
    assert net._udp_admit_inbound(("10.8.8.77", 9000)) is False, (
        "a fresh UDP address inside a banned subnet was admitted (VSA-15)")
    assert net._udp_admit_inbound(("10.8.9.77", 9000)) is True
