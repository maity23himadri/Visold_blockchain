"""Safe, persistent operator settings for Visold network listen ports.

Port changes are saved for the next process start.  Rebinding TCP/UDP, RPC,
UPnP and ICE atomically while the node is live is deliberately unsupported.
"""
from __future__ import annotations

import json
import os
import socket
import tempfile
from typing import Iterable, List, Tuple

from visold.kernel.config import Config


PORT_MODES = ("auto", "manual")


def validate_p2p_port(value: object) -> int:
    """Return an unprivileged P2P port whose standard +1/+2 offsets are valid."""
    if isinstance(value, bool):
        raise ValueError("Port must be an integer between 1024 and 65533.")
    try:
        port = int(value)  # accept numeric text from the CLI
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Port must be an integer between 1024 and 65533.") from exc
    if str(value).strip() != str(port) and not isinstance(value, int):
        raise ValueError("Port must be a whole number (for example, 8348).")
    max_port = min(65535 - int(Config.RPC_PORT_OFFSET),
                   65535 - int(Config.RELAY_PORT_OFFSET))
    if not 1024 <= port <= max_port:
        raise ValueError(f"Port must be between 1024 and {max_port}; this leaves room for RPC/relay ports.")
    if int(Config.RPC_PORT_OFFSET) <= 0 or int(Config.RELAY_PORT_OFFSET) <= 0:
        raise ValueError("Configured RPC/relay offsets must be positive.")
    if Config.RPC_PORT_OFFSET == Config.RELAY_PORT_OFFSET:
        raise ValueError("RPC and relay ports use the same offset; correct the port configuration first.")
    return port


def _bind_probe(port: int, sock_type: int) -> Tuple[bool, str]:
    """Probe the same wildcard family policy used by the P2P listener.

    Prefer a real dual-stack IPv6 socket when the platform supports it. If
    IPv6 socket creation or IPV6_V6ONLY configuration is unavailable, mirror
    the listener's IPv4 fallback. A failed bind on a successfully configured
    dual-stack socket is a genuine conflict and must not be masked by probing
    IPv4 alone.
    """
    last_error = "port unavailable"
    if socket.has_ipv6:
        sock = None
        dual_stack_ready = False
        try:
            try:
                sock = socket.socket(socket.AF_INET6, sock_type)
            except OSError as exc:
                last_error = str(exc)
            if sock is not None:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    dual_stack_ready = True
                except (AttributeError, OSError) as exc:
                    # The production listener falls back to IPv4 when this
                    # setup is unavailable, so the probe must do the same.
                    last_error = str(exc)
                if dual_stack_ready:
                    try:
                        sock.bind(("::", port, 0, 0))
                        return True, ""
                    except OSError as exc:
                        # The production listener would use this same socket
                        # and fail its bind; do not incorrectly report success
                        # just because an IPv4-only bind might succeed.
                        return False, str(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    # IPv4-only fallback, matching _create_dual_stack_server_socket().
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, sock_type)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        return True, ""
    except OSError as exc:
        last_error = str(exc)
        return False, last_error
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _probe_rpc_loopback_port(port: int) -> Tuple[bool, str]:
    """Probe exactly the address used by RPCServer: IPv4 loopback only.

    RPCServer binds to 127.0.0.1, not to a wildcard/dual-stack interface.
    Probing a wildcard socket can falsely reject an otherwise valid local RPC
    port when an unrelated service is bound only to a specific non-loopback
    interface.  Match the production bind address and SO_REUSEADDR policy.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", int(port)))
        return True, ""
    except (OSError, ValueError, OverflowError) as exc:
        return False, str(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_port_plan(port: object, ignore_current_ports: Iterable[int] = ()) -> Tuple[List[str], List[str]]:
    """Probe the required P2P TCP/UDP and RPC TCP ports.

    ``ignore_current_ports`` may contain this node's own live ports: the
    configuration applies after restart, so its current sockets will be closed
    before the new plan is bound.  Returns (blocking_conflicts, relay_warnings).
    The relay is a best-effort service which deliberately scans for a free port.
    """
    p = validate_p2p_port(port)
    ignored = {int(x) for x in ignore_current_ports if str(x).isdigit()}
    blockers: List[str] = []
    relay_warnings: List[str] = []
    required = (
        (p, socket.SOCK_STREAM, "P2P TCP"),
        (p, socket.SOCK_DGRAM, "P2P UDP"),
        (p + int(Config.RPC_PORT_OFFSET), socket.SOCK_STREAM, "local JSON-RPC TCP"),
    )
    for candidate, sock_type, label in required:
        if candidate in ignored:
            continue
        if label == "local JSON-RPC TCP":
            ok, reason = _probe_rpc_loopback_port(candidate)
        else:
            ok, reason = _bind_probe(candidate, sock_type)
        if not ok:
            blockers.append(f"{label} port {candidate} is unavailable ({reason}).")

    relay_port = p + int(Config.RELAY_PORT_OFFSET)
    if relay_port not in ignored:
        ok, reason = _bind_probe(relay_port, socket.SOCK_STREAM)
        if not ok:
            relay_warnings.append(
                f"Preferred relay port {relay_port} is busy ({reason}); ICE will try other ports."
            )
    return blockers, relay_warnings


def load_saved_port_settings(data_dir: str | None = None) -> Tuple[int, str]:
    """Read the configured next-start port/mode without mutating live settings."""
    port = int(Config.DEFAULT_PORT)
    mode = str(getattr(Config, "PORT_MODE", "auto")).lower()
    path = os.path.join(data_dir or Config.DATA_DIR, "config.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        if isinstance(cfg, dict):
            if "port" in cfg:
                port = validate_p2p_port(cfg["port"])
            if str(cfg.get("port_mode", mode)).lower() in PORT_MODES:
                mode = str(cfg.get("port_mode", mode)).lower()
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        # A malformed config is handled by Config's own startup diagnostics;
        # don't hide the status screen because the optional read failed.
        pass
    return port, mode if mode in PORT_MODES else "auto"


def save_port_settings(port: object, mode: str, data_dir: str | None = None) -> str:
    """Atomically save the P2P port/mode while preserving all other config keys."""
    p = validate_p2p_port(port)
    mode = str(mode).strip().lower()
    if mode not in PORT_MODES:
        raise ValueError("Mode must be 'auto' or 'manual'.")
    directory = data_dir or Config.DATA_DIR
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "config.json")
    cfg = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if not isinstance(loaded, dict):
                raise ValueError("config.json must contain a JSON object; no changes saved.")
            cfg = loaded
        except json.JSONDecodeError as exc:
            raise ValueError("config.json is malformed; no changes saved to avoid overwriting other settings.") from exc
    cfg["port"] = p
    cfg["port_mode"] = mode

    fd, tmp_path = tempfile.mkstemp(prefix=".config-port-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return path
