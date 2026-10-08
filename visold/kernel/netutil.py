# ─────────────────────────────────────────────────────────────────────────────
#  Visold (VSD) Blockchain Protocol
#  Copyright (c) 2025 Visold Contributors
#  Licensed under the MIT License.
#
#  The original and canonical source is maintained by the Visold Project.
#  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#  the license agreement.
# ─────────────────────────────────────────────────────────────────────────────
# cython: language_level=3
# cython: boundscheck=True
# cython: wraparound=True
# cython: cdivision=True
# cython: nonecheck=True
# cython: initializedcheck=False
# cython: infer_types=True
# cython: optimize.use_switch=True
# cython: optimize.unpack_method_calls=True
"""visold.kernel.netutil


Origin: visold_vsd_.py L4980-5219
"""

import json
import os
import socket
import threading
from typing import Optional, Tuple

from visold.kernel.config import Config
from visold.kernel.logging_setup import log


# Centralised IPv4/IPv6 address formatting and parsing so that no other
# module needs to hard-code protocol-specific string formats.
# ─────────────────────────────────────────────────────────────────────────────

def _is_ipv6_address(addr: str) -> bool:
    """Return True if addr is a bare IPv6 address (not bracket-wrapped)."""
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except (socket.error, OSError):
        return False


def _format_peer_addr(ip: str, port: int) -> str:
    """
    Return a host:port string that is safe to parse back with _parse_peer_addr.
    IPv6 addresses are wrapped in brackets: [::1]:8338
    IPv4 addresses use the classic form:   127.0.0.1:8338
    """
    if _is_ipv6_address(ip):
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def _parse_peer_addr(addr_str: str) -> Tuple[str, int]:
    """
    Parse 'host:port' or '[ipv6]:port' into (host, port).
    Raises ValueError on malformed input.
    """
    addr_str = addr_str.strip()
    if addr_str.startswith("["):
        # IPv6 bracketed form: [::1]:8338
        bracket_end = addr_str.find("]")
        if bracket_end == -1:
            raise ValueError(f"Malformed IPv6 address: {addr_str}")
        host = addr_str[1:bracket_end]
        rest = addr_str[bracket_end + 1:]
        if not rest.startswith(":"):
            raise ValueError(f"Missing port in: {addr_str}")
        port = int(rest[1:])
    else:
        # IPv4 or hostname: 127.0.0.1:8338
        parts = addr_str.rsplit(":", 1)
        if len(parts) != 2:
            raise ValueError(f"Cannot parse addr: {addr_str}")
        host = parts[0]
        port = int(parts[1])
    return host, port


def _normalize_ip(ip: str) -> str:
    """
    Normalize an IP address string.
    IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are converted to plain IPv4
    so that peer dedup and blacklist lookups are consistent regardless of
    whether the connection arrived via an IPv4-mapped socket.
    """
    if not ip:
        return ip
    # strip IPv4-mapped prefix
    if ip.startswith("::ffff:") or ip.startswith("::FFFF:"):
        candidate = ip[7:]
        try:
            socket.inet_pton(socket.AF_INET, candidate)
            return candidate
        except (socket.error, OSError):
            pass
    return ip


def _write_node_status(p2p_port: int, rpc_port: int, relay_port: int) -> None:
    """
    Write a small JSON file (.node_status.json) to DATA_DIR so that the
    Explorer and other tools can always find the node's live ports — even
    when the relay port shifted due to Scan-to-Bind.

    The file is written atomically (write-then-rename) so readers never
    see a partial update.

    Schema:
      {
        "p2p_port":   <int>,   # P2P listener (static, e.g. 8338)
        "rpc_port":   <int>,   # JSON-RPC port (p2p + 1)
        "relay_port": <int>    # ICE relay port (scan-to-bind result)
      }
    """
    status = {
        "p2p_port":   p2p_port,
        "rpc_port":   rpc_port,
        "relay_port": relay_port,
    }
    path = Config.NODE_STATUS_FILE
    if not path:
        return
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(status, f)
        os.replace(tmp, path)
        log.debug(f"Node status written → {path} "
                  f"(p2p={p2p_port} rpc={rpc_port} relay={relay_port})")
    except Exception as exc:
        log.warning(f"Could not write node status file: {exc}")


def _create_dual_stack_server_socket(port: int,
                                     bind_addr: Optional[str] = None) -> socket.socket:
    """
    Create a TCP server socket that accepts BOTH IPv4 and IPv6 connections.

    On Linux/macOS a single AF_INET6 socket with IPV6_V6ONLY=0 handles both
    protocol families.  On Windows IPV6_V6ONLY defaults to 0 already.
    Falls back to AF_INET if AF_INET6 is unavailable (rare, old kernels).
    """
    if bind_addr is None:
        bind_addr = Config.BIND_ADDRESS
    try:
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        # IPV6_V6ONLY = 0  →  also accept IPv4-mapped connections (::ffff:x.x.x.x)
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        srv.setsockopt(socket.SOL_SOCKET,   socket.SO_REUSEADDR, 1)
        return srv
    except (AttributeError, OSError):
        # Kernel has no IPv6 support at all — fall back gracefully to IPv4
        log.warning("IPv6 not available on this system; falling back to IPv4-only server socket")
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return srv


def _create_connection_dual_stack(host: str, port: int,
                                   timeout: Optional[float] = None) -> socket.socket:
    """
    Open a TCP connection to host:port using the Happy Eyeballs algorithm
    (RFC 8305) to avoid CGNAT-induced hangs.

    Root problem this fixes
    ───────────────────────
    On mobile/CGNAT networks the outbound IPv4 address is NOT publicly
    routable.  A naive sequential strategy (try IPv6, then IPv4) fails
    silently when IPv4 *hangs* rather than refusing — the caller must wait
    the full PEER_TIMEOUT before IPv6 is even attempted.

    Happy Eyeballs fix
    ──────────────────
    1. Resolve all addresses with AF_UNSPEC (IPv4 + IPv6).
    2. Partition them: IPv6 first in the preferred list, IPv4 second.
    3. Start the first IPv6 attempt immediately.
    4. After HAPPY_EYEBALLS_DELAY_MS (250 ms) — while the IPv6 attempt is
       still in flight — start the first IPv4 attempt in a background thread.
    5. Whichever socket connects first wins; the loser is closed.
    6. If all attempts in the preferred family fail quickly, start all
       remaining attempts without waiting.

    This guarantees that a hung IPv4 attempt never delays IPv6 by more than
    250 ms, which is imperceptible to users.
    """
    # RFC 8305 §4: default interleave delay is 250 ms
    _HAPPY_DELAY = 0.250

    t = timeout if timeout is not None else Config.PEER_TIMEOUT

    infos = socket.getaddrinfo(host, port,
                               family=socket.AF_UNSPEC,
                               type=socket.SOCK_STREAM,
                               proto=socket.IPPROTO_TCP)
    if not infos:
        raise OSError(f"getaddrinfo returned nothing for {host}:{port}")

    # Separate into preferred (IPv6) and fallback (IPv4) lists
    preferred = [i for i in infos if i[0] == socket.AF_INET6]
    fallback  = [i for i in infos if i[0] != socket.AF_INET6]

    # If only one family is available, just attempt sequentially
    if not preferred or not fallback:
        ordered = preferred + fallback
        last_exc: Optional[Exception] = None
        for af, socktype, proto, _canon, sockaddr in ordered:
            try:
                s = socket.socket(af, socktype, proto)
                s.settimeout(t)
                s.connect(sockaddr)
                return s
            except OSError as exc:
                last_exc = exc
                try:
                    s.close()
                except Exception:
                    pass
        raise OSError(f"Cannot connect to {host}:{port}") from last_exc

    # ── Happy Eyeballs: race both families ───────────────────────────────────
    result_sock: list = [None]   # [0] = winning socket
    result_exc:  list = [None]   # [0] = last exception if all fail
    winner_evt   = threading.Event()
    attempts_done = [0]
    total_attempts = len(preferred) + len(fallback)
    attempts_lock  = threading.Lock()

    def _attempt(af, socktype, proto, sockaddr):
        """Try to connect; if this is the first to succeed, claim the win."""
        try:
            s = socket.socket(af, socktype, proto)
            s.settimeout(t)
            s.connect(sockaddr)
            # Race: only the first successful connect wins
            with attempts_lock:
                if result_sock[0] is None:
                    result_sock[0] = s
                    winner_evt.set()
                    return
            # Lost the race — close the extra socket
            try:
                s.close()
            except Exception:
                pass
        except OSError as exc:
            with attempts_lock:
                result_exc[0] = exc
        finally:
            with attempts_lock:
                attempts_done[0] += 1
                if attempts_done[0] >= total_attempts:
                    winner_evt.set()   # signal even on total failure

    # Start preferred (IPv6) attempts immediately in background threads
    for af, socktype, proto, _canon, sockaddr in preferred:
        threading.Thread(
            target=_attempt,
            args=(af, socktype, proto, sockaddr),
            daemon=True
        ).start()

    # Wait the Happy Eyeballs delay, then start fallback (IPv4) attempts
    # unless a winner was already found
    winner_evt.wait(timeout=_HAPPY_DELAY)
    if result_sock[0] is None:
        for af, socktype, proto, _canon, sockaddr in fallback:
            threading.Thread(
                target=_attempt,
                args=(af, socktype, proto, sockaddr),
                daemon=True
            ).start()

    # Wait for the first winner or all attempts to finish
    winner_evt.wait(timeout=t + 1.0)

    if result_sock[0] is not None:
        return result_sock[0]
    raise OSError(f"Cannot connect to {host}:{port}") from result_exc[0]
