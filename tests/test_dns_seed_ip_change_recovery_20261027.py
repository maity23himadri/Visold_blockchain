"""Regressions for prompt DNS-seed retry after IP migration / seed restart."""
import socket
import time
from types import SimpleNamespace

from visold.kernel.config import Config
from visold.network.dns_seeder import DNSSeeder


def test_recovery_refresh_requeries_dns_before_background_600s_timer(monkeypatch):
    monkeypatch.setattr(Config, "DNS_SEEDS", ["seed.example"])
    calls = []
    seeder = DNSSeeder(SimpleNamespace(port=8338))
    seeder._last_query_monotonic = time.monotonic() - 20.0
    monkeypatch.setattr(seeder, "_query_one", lambda hostname: calls.append(hostname) or 1)

    # A recovery refresh can happen after a failed initial dial; the second
    # request is throttled so repeated recovery callers do not storm DNS.
    assert seeder.refresh_now(min_interval_seconds=15.0) == 1
    assert calls == ["seed.example"]
    assert seeder.refresh_now(min_interval_seconds=15.0) == 0
    assert calls == ["seed.example"]


def test_dns_seed_rotates_to_alternate_family_after_scheduled_attempt(monkeypatch):
    monkeypatch.setattr(Config, "DNS_SEED_PORT", 8338)
    monkeypatch.setattr(Config, "LOOPBACK_ADDRESS", "127.0.0.1")
    attempts = []

    def schedule(ip, port, **kwargs):
        attempts.append((ip, port, kwargs.get("dial_source")))
        return True

    network = SimpleNamespace(port=8338, _try_add_peer=schedule)
    seeder = DNSSeeder(network)
    answers = [
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:db8::5", 8338, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.5", 8338)),
    ]
    monkeypatch.setattr("visold.network.dns_seeder.socket.getaddrinfo", lambda *a, **kw: answers)

    assert seeder._query_one("seed.example") == 1
    assert seeder._query_one("seed.example") == 1
    assert attempts == [
        ("2001:db8::5", 8338, "dns-seeder"),
        ("192.0.2.5", 8338, "dns-seeder"),
    ]


def test_dns_seed_tries_alternative_when_first_endpoint_is_suppressed(monkeypatch):
    monkeypatch.setattr(Config, "DNS_SEED_PORT", 8338)
    monkeypatch.setattr(Config, "LOOPBACK_ADDRESS", "127.0.0.1")
    attempts = []

    def schedule(ip, port, **kwargs):
        attempts.append(ip)
        # The IPv6 route is already pending/cooling down; the seeder must not
        # treat that rejection as proof that the whole hostname is unusable.
        return ip == "192.0.2.5"

    seeder = DNSSeeder(SimpleNamespace(port=8338, _try_add_peer=schedule))
    answers = [
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:db8::5", 8338, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.5", 8338)),
    ]
    monkeypatch.setattr("visold.network.dns_seeder.socket.getaddrinfo", lambda *a, **kw: answers)

    assert seeder._query_one("seed.example") == 1
    assert attempts == ["2001:db8::5", "192.0.2.5"]


def test_reconnect_recovery_calls_dns_refresh_helper():
    from visold.network.p2p import P2PNetwork

    calls = []
    net = object.__new__(P2PNetwork)
    net._dns_seeder = SimpleNamespace(
        refresh_now=lambda min_interval_seconds: calls.append(min_interval_seconds) or 2)

    assert net._refresh_dns_seeds_for_recovery() == 2
    assert calls == [15.0]


def test_tcp_socket_failure_reason_is_visible_for_ip_change_diagnostics(monkeypatch, caplog):
    import logging
    import visold.network.p2p as p2p
    from visold.kernel.config import Config as RuntimeConfig

    net = object.__new__(p2p.P2PNetwork)
    monkeypatch.setattr(RuntimeConfig, "ICE_ENABLED", False)
    monkeypatch.setattr(
        p2p, "_create_connection_dual_stack",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("Network is unreachable")))

    with caplog.at_level(logging.INFO):
        assert net.connect_to("2001:db8::7", 8338) is False

    assert "[P2PConnect] TCP dial to [2001:db8::7]:8338 failed" in caplog.text
    assert "Network is unreachable" in caplog.text
