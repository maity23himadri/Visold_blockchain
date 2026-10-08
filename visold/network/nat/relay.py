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
"""visold.network.nat.relay


Defines: RelayBridge
Origin: visold_vsd_.py L32538-32832
"""

import json
import os
import socket
import sys
import time
from typing import Optional

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.netutil import _create_connection_dual_stack


class RelayBridge:
    """
    Minimal TCP relay bridge (TURN-lite fallback).

    When both STUN and UDP hole-punching fail, two peers can exchange data
    through a relay TCP server.  The relay server is a simple stream splitter:

        PeerA ──TCP──► RelayServer:relay_port ──TCP──► PeerB

    Relay server format (auto-created as relay_server.py if AUTO_RELAY=True):
    ─────────────────────────────────────────────────────────────────────────
    Clients connect and send a JSON handshake line:
      {"action": "register", "session": "<hex>"}
    The first peer registers a session token; the second peer with the same
    token is bridged to the first — the server splices the two TCP streams.

    RelayBridge here is the *client* side only.  The server is
    auto-generated and launched as a subprocess if AUTO_RELAY is set.
    """

    RELAY_SCRIPT_NAME = "relay_server.py"
    # Embedded relay server source — written to disk if file is missing
    RELAY_SCRIPT_SOURCE = r'''#!/usr/bin/env python3
"""
Visold VSD — ICE Relay Server (auto-generated, do not edit)
Minimal TCP relay: bridges two peers that share a session token.
F-04 FIX: Adds per-IP connection rate limiting to prevent session exhaustion.
Bind address: defaults to 127.0.0.1 (loopback) when launched without argv[2].
  Pass an explicit bind address as argv[2] to serve remote peers, e.g.:
    python relay_server.py 8340 0.0.0.0
  Operators using the default loopback binding must route external traffic
  through an SSH tunnel or local proxy to reach the relay port.
"""
import socket, threading, json, sys, logging, time, secrets

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("RELAY")

RELAY_PORT     = int(sys.argv[1]) if len(sys.argv) > 1 else 8340
RELAY_BIND     = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"  # default: loopback
MAX_SESSIONS   = 512
IDLE_TIMEOUT   = 120              # seconds before an unmatched session is cleaned up
BUF_SIZE       = 65536
MAX_CONN_PER_IP = 8               # F-04 FIX: rate limit per source IP


class Session:
    def __init__(self, token: str, sock: socket.socket):
        self.token   = token
        self.sock    = sock
        self.peer    = None
        self.created = time.time()
        self.matched = threading.Event()


sessions: dict = {}
_ip_conns: dict = {}    # F-04: track active connections per IP
_lock = threading.Lock()


def splice(a: socket.socket, b: socket.socket):
    """Bidirectional splice between two sockets (each direction in own thread)."""
    def forward(src, dst):
        try:
            while True:
                data = src.recv(BUF_SIZE)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try: src.close()
            except Exception: pass
            try: dst.close()
            except Exception: pass

    threading.Thread(target=forward, args=(a, b), daemon=True).start()
    threading.Thread(target=forward, args=(b, a), daemon=True).start()


def handle(conn: socket.socket, addr):
    client_ip = addr[0]
    # F-04 FIX: Enforce per-IP connection limit
    with _lock:
        _ip_conns[client_ip] = _ip_conns.get(client_ip, 0) + 1
        if _ip_conns[client_ip] > MAX_CONN_PER_IP:
            _ip_conns[client_ip] -= 1
            try: conn.close()
            except Exception: pass
            log.warning(f"Relay: rate-limited {client_ip} (>{MAX_CONN_PER_IP} conns)")
            return
    try:
        conn.settimeout(15)
        raw = b""
        while b"\n" not in raw:
            chunk = conn.recv(512)
            if not chunk:
                conn.close()
                return
            raw += chunk
        line = raw.split(b"\n", 1)[0]
        msg  = json.loads(line.decode())
        action  = msg.get("action")
        token   = msg.get("session", "")[:64]
        if not token or action != "register":
            conn.close()
            return

        with _lock:
            existing = sessions.get(token)
            if existing is None:
                if len(sessions) >= MAX_SESSIONS:
                    conn.close()
                    return
                sess = Session(token, conn)
                sessions[token] = sess
            else:
                # Second peer — bridge them
                del sessions[token]
                existing.peer = conn

        if existing is None:
            # Wait for partner (with timeout)
            sess.matched.wait(timeout=IDLE_TIMEOUT)
            with _lock:
                sessions.pop(token, None)
            if sess.peer is None:
                conn.close()
                return
            conn.sendall(b'{"status":"ok"}\n')
            sess.peer.sendall(b'{"status":"ok"}\n')
            splice(conn, sess.peer)
        else:
            # We are the second peer — signal first
            existing.matched.set()
            time.sleep(0.1)
            conn.sendall(b'{"status":"ok"}\n')
            splice(existing.sock, conn)
    except Exception as e:
        log.debug(f"handle error {addr}: {e}")
        try: conn.close()
        except Exception: pass
    finally:
        with _lock:
            _ip_conns[client_ip] = max(0, _ip_conns.get(client_ip, 1) - 1)


def cleanup_loop():
    while True:
        time.sleep(30)
        now = time.time()
        with _lock:
            stale = [t for t, s in sessions.items()
                     if (now - s.created) > IDLE_TIMEOUT]
            for t in stale:
                s = sessions.pop(t, None)
                if s:
                    try: s.sock.close()
                    except Exception: pass
        if stale:
            log.debug(f"Relay: cleaned up {len(stale)} stale sessions")


if __name__ == "__main__":
    threading.Thread(target=cleanup_loop, daemon=True).start()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((RELAY_BIND, RELAY_PORT))   # bind address from argv[2], default 127.0.0.1
    srv.listen(64)
    log.info(f"Relay server listening on {RELAY_BIND}:{RELAY_PORT}")
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
'''

    def __init__(self, relay_host: str, relay_port: int):
        self.relay_host = relay_host
        self.relay_port = relay_port
        self._proc      = None

    # ── Client side ───────────────────────────────────────────────────────────

    def connect_via_relay(self, session_token: str,
                          timeout: float = 10.0) -> Optional[socket.socket]:
        """
        Connect to the relay server and register under `session_token`.
        Returns a socket bridged to the peer sharing the same token,
        or None on failure.
        """
        try:
            sock = _create_connection_dual_stack(
                self.relay_host, self.relay_port, timeout=timeout)
            msg = json.dumps({"action": "register", "session": session_token})
            sock.sendall((msg + "\n").encode())
            sock.settimeout(timeout)
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(256)
                if not chunk:
                    sock.close()
                    return None
                buf += chunk
            line = buf.split(b"\n", 1)[0]
            resp = json.loads(line.decode())
            if resp.get("status") == "ok":
                sock.settimeout(None)
                log.info(f"ICE: relay bridge established via "
                         f"{self.relay_host}:{self.relay_port}")
                return sock
            sock.close()
            return None
        except Exception as exc:
            log.debug(f"ICE relay connect failed: {exc}")
            return None

    # ── Server management (auto-create + auto-start) ──────────────────────────

    @classmethod
    def ensure_relay_script(cls, path: str):
        """Write relay_server.py to `path` if it does not already exist."""
        if os.path.exists(path):
            return
        try:
            with open(path, "w") as f:
                f.write(cls.RELAY_SCRIPT_SOURCE)
            try:
                os.chmod(path, 0o700)  # nosec B103 – owner-only rwx; relay script launched by same process user
            except Exception:
                pass
            log.info(f"ICE: relay script auto-created at {path}")
        except Exception as exc:
            log.warning(f"ICE: could not write relay script: {exc}")

    @classmethod
    def start_relay_server(cls, relay_port: int,
                           bind_addr: str = "127.0.0.1") -> Optional[object]:
        """
        Launch relay_server.py as a background subprocess.
        Returns the subprocess.Popen handle or None on failure.

        bind_addr controls which interface the relay server listens on.
        Defaults to "127.0.0.1" (loopback) for safe local-only operation.
        Pass the node's public/LAN IP (e.g. self._local_ip) when the relay
        must be reachable by remote peers without an SSH tunnel.

        MAJOR-03 FIX: Validate relay_port is a plain integer in [1024, 65535]
        before constructing the Popen argument list.  This prevents adversarial
        config values from injecting unexpected arguments into the subprocess.
        shell=False (already used) ensures no shell interpolation occurs, but
        type/range validation is a necessary additional guard.
        bind_addr is validated to be a non-empty string for the same reason.
        """
        import subprocess as _sp
        # MAJOR-03: strict port validation before subprocess launch
        if not isinstance(relay_port, int) or not (1024 <= relay_port <= 65535):
            log.error(
                f"ICE: relay_port {relay_port!r} is out of valid range "
                f"[1024, 65535] — refusing to launch relay subprocess"
            )
            return None
        # Validate bind_addr: must be a non-empty string (no shell injection risk
        # because shell=False, but we enforce type for defence-in-depth).
        if not isinstance(bind_addr, str) or not bind_addr.strip():
            log.error(
                f"ICE: bind_addr {bind_addr!r} is invalid — "
                "refusing to launch relay subprocess"
            )
            return None
        script_dir  = Config.DATA_DIR
        script_path = os.path.join(script_dir, cls.RELAY_SCRIPT_NAME)
        cls.ensure_relay_script(script_path)
        try:
            proc = _sp.Popen(
                [sys.executable, script_path, str(relay_port), bind_addr],
                stdout=_sp.DEVNULL,
                stderr=_sp.DEVNULL,
                start_new_session=True,
            )
            time.sleep(0.5)   # give it a moment to bind
            if proc.poll() is not None:
                log.warning("ICE: relay server exited immediately — check port conflict")
                return None
            log.info(f"ICE: relay server started on {bind_addr}:{relay_port} (pid={proc.pid})")
            return proc
        except Exception as exc:
            log.warning(f"ICE: could not start relay server: {exc}")
            return None
