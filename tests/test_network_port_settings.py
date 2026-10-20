"""Regression tests for safe operator-configurable P2P ports."""
import json
import socket

import pytest

from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork
from visold.network.port_settings import (
    load_saved_port_settings,
    probe_port_plan,
    save_port_settings,
    validate_p2p_port,
    _probe_rpc_loopback_port,
)


def _free_tcp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _free_port_plan() -> int:
    for _ in range(100):
        port = _free_tcp_port()
        if port + max(Config.RPC_PORT_OFFSET, Config.RELAY_PORT_OFFSET) >= 65535:
            continue
        blockers, _warnings = probe_port_plan(port)
        if not blockers:
            return port
    raise AssertionError("could not find a free test port plan")


def _occupy_tcp(port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(1)
    return sock


def test_port_validation_reserves_room_for_rpc_and_relay():
    assert validate_p2p_port("8338") == 8338
    assert validate_p2p_port(65533) == 65533
    for invalid in ("nope", "8338.5", True, 1023, 65534, 65535, 0):
        with pytest.raises(ValueError):
            validate_p2p_port(invalid)


def test_port_settings_save_atomically_and_preserve_other_config(tmp_path):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"max_peers": 22, "dns_seeds": ["seed.example"]}), encoding="utf-8")

    saved = save_port_settings(8347, "manual", str(tmp_path))
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))

    assert saved == str(cfg_path)
    assert cfg["port"] == 8347
    assert cfg["port_mode"] == "manual"
    assert cfg["max_peers"] == 22
    assert cfg["dns_seeds"] == ["seed.example"]
    assert load_saved_port_settings(str(tmp_path)) == (8347, "manual")


def test_malformed_config_is_never_overwritten(tmp_path):
    cfg_path = tmp_path / "config.json"
    original = "{not valid json"
    cfg_path.write_text(original, encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        save_port_settings(8347, "manual", str(tmp_path))
    assert cfg_path.read_text(encoding="utf-8") == original


def test_manual_mode_binds_exact_requested_port(monkeypatch):
    base = _free_port_plan()
    monkeypatch.setattr(Config, "PORT_MODE", "manual")
    net = object.__new__(P2PNetwork)
    srv = udp = None
    try:
        srv, udp = net._open_listen_sockets(base)
        assert net.port == base
        assert srv.getsockname()[1] == base
        assert udp._port == base
    finally:
        if srv is not None:
            srv.close()
        if udp is not None:
            udp._sock.close()


def test_manual_mode_fails_instead_of_silently_switching_ports(monkeypatch):
    base = _free_port_plan()
    blocker = _occupy_tcp(base)
    monkeypatch.setattr(Config, "PORT_MODE", "manual")
    net = object.__new__(P2PNetwork)
    net.port = base
    try:
        with pytest.raises(RuntimeError, match="Manual mode was configured"):
            net._open_listen_sockets(base)
        assert net.port == base
    finally:
        blocker.close()


def test_auto_mode_skips_a_port_whose_rpc_offset_is_occupied(monkeypatch):
    base = _free_port_plan()
    blocker = _occupy_tcp(base + Config.RPC_PORT_OFFSET)
    monkeypatch.setattr(Config, "PORT_MODE", "auto")
    net = object.__new__(P2PNetwork)
    net.port = base
    srv = udp = None
    try:
        srv, udp = net._open_listen_sockets(base)
        assert net.port != base, "auto mode should not choose a P2P port whose RPC offset is busy"
        assert net.port + Config.RPC_PORT_OFFSET != base + Config.RPC_PORT_OFFSET
        assert srv.getsockname()[1] == net.port
        assert udp._port == net.port
    finally:
        blocker.close()
        if srv is not None:
            srv.close()
        if udp is not None:
            udp._sock.close()


def test_network_ports_screen_reports_live_ports_ips_and_nat_limits(monkeypatch, capsys):
    import threading
    from types import SimpleNamespace
    import visold.cli.interactive as interactive

    class BoundSocket:
        def __init__(self, address):
            self.address = address

        def getsockname(self):
            return self.address

    ready = threading.Event()
    ready.set()
    ice = SimpleNamespace(
        _relay_port=18340,
        _local_ip="192.168.1.10",
        _relay_proc=None,
        _get_local_ips=lambda: ["192.168.1.10", "fe80::1"],
        _public_ip="203.0.113.7",
        _public_port=52123,
        _ready=ready,
    )
    network = SimpleNamespace(
        port=18338,
        _listen_sock=BoundSocket(("::", 18338, 0, 0)),
        _udp=SimpleNamespace(_sock=BoundSocket(("::", 18338, 0, 0))),
        _ice=ice,
        _upnp=None,
        active_peer_count=lambda: [object()],
    )
    rpc = SimpleNamespace(
        rpc_port=18339,
        _server=SimpleNamespace(server_address=("127.0.0.1", 18339)),
    )
    cli = interactive.CLI()
    cli.node = SimpleNamespace(network=network, port=18338, rpc=rpc)
    monkeypatch.setattr(interactive, "load_saved_port_settings", lambda: (18338, "manual"))
    cli._read_input = lambda _prompt: ""

    cli._network_ports()
    output = capsys.readouterr().out

    assert "P2P TCP listener" in output and "::" in output and "18338" in output
    assert "P2P UDP listener" in output and "18338" in output
    assert "127.0.0.1:18339 (local-only; listening)" in output
    assert "Local IPs" in output and "192.168.1.10" in output
    assert "STUN candidate" in output and "203.0.113.7:52123" in output
    assert "Connected peers  : 1" in output
    assert "not firewall bypass guarantees" in output
    assert "separate VISOLD_DATA_DIR" in output


def test_rpc_port_probe_matches_localhost_only_rpc_server():
    # RPCServer binds to 127.0.0.1, so its preflight must test that exact
    # address instead of requiring the port to be free on all interfaces.
    local = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local.bind(("127.0.0.1", 0))
    local.listen(1)
    port = local.getsockname()[1]
    try:
        ok, reason = _probe_rpc_loopback_port(port)
        assert not ok
        assert reason
    finally:
        local.close()


def test_rpc_loopback_probe_does_not_reject_other_specific_interface():
    # A service bound only to 127.0.0.2 is not a conflict for Visold's
    # actual 127.0.0.1-only RPC server. 127/8 is loopback on Linux/Android.
    specific = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    specific.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        specific.bind(("127.0.0.2", 0))
        specific.listen(1)
    except OSError:
        specific.close()
        pytest.skip("platform does not permit binding a distinct 127/8 loopback address")
    port = specific.getsockname()[1]
    try:
        ok, reason = _probe_rpc_loopback_port(port)
        assert ok, reason
    finally:
        specific.close()


def test_port_plan_reports_rpc_conflict_separately_from_free_p2p_ports():
    base = _free_tcp_port()
    if base + Config.RPC_PORT_OFFSET >= 65535 or base + Config.RELAY_PORT_OFFSET >= 65535:
        pytest.skip("OS allocated a port too close to the upper bound")
    rpc_port = base + Config.RPC_PORT_OFFSET
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        blocker.bind(("127.0.0.1", rpc_port))
        blocker.listen(1)
    except OSError:
        blocker.close()
        pytest.skip("could not reserve test RPC port")
    try:
        blockers, _warnings = probe_port_plan(base)
        assert any(f"local JSON-RPC TCP port {rpc_port} is unavailable" in item
                   for item in blockers)
        assert not any(f"P2P TCP port {base} is unavailable" in item for item in blockers)
        assert not any(f"P2P UDP port {base} is unavailable" in item for item in blockers)
    finally:
        blocker.close()
