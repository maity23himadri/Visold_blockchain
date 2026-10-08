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
"""visold.network.nat.hole_punch


Defines: UDPHolePuncher
Origin: visold_vsd_.py L32334-32535
"""

import secrets
import socket
import threading
import time
from typing import Optional

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.netutil import _is_ipv6_address


class UDPHolePuncher:
    """
    Simultaneous UDP hole punching (RFC 5128 §3.4).

    Algorithm:
    1. Both peers agree on each other's (public_ip, public_port) via the
       existing TCP signaling channel (HELLO message + ice_candidates field).
    2. Both peers start sending UDP probes to each other *simultaneously*.
    3. When a probe from the remote arrives, the NAT entry is open and we
       confirm success by echoing back.
    4. Returns the connected UDP socket on success, None on failure.

    The puncher re-uses the same local UDP port across all attempts so that
    the NAT binding remains consistent.
    """

    PROBE_MAGIC    = b"\x56\x53\x44\x49\x43\x45"   # "VSDICE"
    ACK_MAGIC      = b"\x56\x53\x44\x41\x43\x4b"   # "VSDACK"
    KEEPALIVE_MAGIC = b"\x56\x53\x44\x4b\x41"       # "VSDKA"

    def __init__(self, local_port: int = 0):
        self._local_port  = local_port
        self._sock: Optional[socket.socket] = None
        self._lock        = threading.Lock()
        # AUDIT-FIX-23: once a punch on this instance succeeds, its socket
        # is handed to the caller for ongoing use as that peer's live
        # connection — this instance's port must never be touched again
        # after that (reusing it for a different peer would let a later
        # punch attempt silently steal the established peer's traffic).
        self._claimed     = False

    @property
    def is_claimed(self) -> bool:
        return self._claimed

    def stun_bind(self, remote_ip: str = "") -> Optional[socket.socket]:
        """
        AUDIT-FIX-23: bind (or return the already-bound) local socket so a
        STUN query can discover the NAT mapping for the EXACT socket that
        punch() will subsequently reuse. Without this, the candidate
        advertised to peers and the socket actually used to punch are two
        different, uncorrelated local ports, and hole punching cannot work
        against anything but a full-cone NAT. Returns None if this
        instance's port is already claimed by an earlier successful punch
        (the caller should use a different puncher instance in that case).
        """
        with self._lock:
            if self._claimed:
                return None
            if self._sock is None:
                try:
                    self._sock = self._make_sock(remote_ip)
                except Exception as exc:
                    log.debug(f"ICE: puncher socket bind failed: {exc}")
                    return None
            return self._sock

    def close(self):
        """Release this puncher's socket, if any (used on ICE shutdown)."""
        with self._lock:
            sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    def _make_sock(self, remote_ip: str = "") -> socket.socket:
        # Select the address family that matches the remote peer.
        # A bare IPv6 address (contains ':') requires AF_INET6 and must bind
        # to '::' instead of '0.0.0.0' — using AF_INET for an IPv6 remote
        # causes EINVAL on sendto.
        if remote_ip and _is_ipv6_address(remote_ip):
            af       = socket.AF_INET6
            bind_any = "::"
        else:
            af       = socket.AF_INET
            bind_any = "0.0.0.0"  # nosec B104 – intentional bind-any for ICE NAT traversal
        s = socket.socket(af, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        s.bind((bind_any, self._local_port))
        if self._local_port == 0:
            self._local_port = s.getsockname()[1]
        return s

    def get_local_port(self) -> int:
        return self._local_port

    def punch(self, remote_ip: str, remote_port: int,
              timeout: Optional[float] = None) -> Optional[socket.socket]:
        """
        Attempt UDP hole punch to (remote_ip, remote_port).
        Returns a bound UDP socket pointed at the remote on success, else None.

        AUDIT-FIX-23: if this instance's port has already been claimed by
        an earlier successful punch (handed off for that peer's ongoing
        use), refuse outright — the caller must use a different puncher
        instance instead of risking cross-talk with that live connection.
        Otherwise, reuse (or create) this instance's single socket for the
        whole attempt, holding the lock for its full duration: two
        concurrent punches must never share one socket's recvfrom(), or
        either attempt can silently steal the other's response.
        """
        if self._claimed:
            return None

        if timeout is None:
            timeout = Config.ICE_HOLE_PUNCH_TIMEOUT
        attempts = Config.ICE_HOLE_PUNCH_ATTEMPTS
        interval = Config.ICE_HOLE_PUNCH_INTERVAL

        with self._lock:
            if self._claimed:
                return None
            if self._sock is not None:
                sock = self._sock
            else:
                try:
                    sock = self._make_sock(remote_ip)
                except Exception as exc:
                    log.debug(f"ICE hole-punch socket creation failed: {exc}")
                    return None
                self._sock = sock

            # Identify this attempt with a random nonce so we can match ACK
            nonce = secrets.token_bytes(8)
            probe = self.PROBE_MAGIC + nonce

            deadline = time.time() + timeout
            sock.settimeout(interval)
            sent = 0

            try:
                while time.time() < deadline:
                    # Send probe burst
                    if sent < attempts:
                        try:
                            sock.sendto(probe, (remote_ip, remote_port))
                            sent += 1
                        except Exception:
                            pass

                    # Listen for incoming probe or ACK
                    try:
                        data, addr = sock.recvfrom(256)
                    except socket.timeout:
                        continue
                    except Exception:
                        break

                    if addr[0] != remote_ip:
                        continue

                    if data == probe:
                        # Remote punched through; send ACK
                        try:
                            sock.sendto(self.ACK_MAGIC + nonce, (remote_ip, remote_port))
                        except Exception:
                            pass
                        log.info(f"ICE: UDP hole punch SUCCESS (remote probe) "
                                 f"→ {remote_ip}:{remote_port}")
                        sock.settimeout(None)
                        self._claimed = True
                        return sock

                    if data[:len(self.ACK_MAGIC)] == self.ACK_MAGIC:
                        log.info(f"ICE: UDP hole punch SUCCESS (ACK received) "
                                 f"→ {remote_ip}:{remote_port}")
                        sock.settimeout(None)
                        self._claimed = True
                        return sock

            except Exception as exc:
                log.debug(f"ICE hole-punch error: {exc}")

            # Failed — this socket was never claimed, so it's free to be
            # closed and rebuilt (on the same verified port) for a future
            # attempt on this instance.
            try:
                sock.close()
            except Exception:
                pass
            self._sock = None
            return None

    def keepalive_loop(self, remote_ip: str, remote_port: int,
                       stop_evt: threading.Event):
        """Send periodic UDP keepalives to maintain the NAT hole."""
        interval = Config.ICE_KEEPALIVE_INTERVAL
        while not stop_evt.wait(timeout=interval):
            with self._lock:
                sock = self._sock
            if sock is None:
                break
            try:
                sock.sendto(self.KEEPALIVE_MAGIC, (remote_ip, remote_port))
            except Exception:
                break
