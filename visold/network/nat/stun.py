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
"""visold.network.nat.stun

Original section: ║  SECTION 12D: ICE NAT TRAVERSAL SYSTEM                                   ║

Defines: ICECandidate, STUNClient
Origin: visold_vsd_.py L32151-32184, L32187-32331
"""

import secrets
import socket
import struct
import time
from typing import Optional, Tuple

from visold.kernel.logging_setup import log


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                         === ICE START ===                                 ║
# ║  SECTION 12D: ICE NAT TRAVERSAL SYSTEM                                   ║
# ║  (STUN + UDP Hole Punching + TURN Relay Fallback)                        ║
# ║  Plug-in addition — zero changes to consensus, wallet, mempool.          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

class ICECandidate:
    """
    Represents a single ICE candidate address.

    Types:
      host  — local LAN address directly reachable on the LAN segment
      srflx — server-reflexive: public IP:port as seen by the STUN server
      relay — TURN relay address for peers that cannot hole-punch
    """
    HOST  = "host"
    SRFLX = "srflx"
    RELAY = "relay"

    def __init__(self, ctype: str, ip: str, port: int, priority: int = 0):
        self.ctype    = ctype
        self.ip       = ip
        self.port     = port
        self.priority = priority

    def to_dict(self) -> dict:
        return {"type": self.ctype, "ip": self.ip,
                "port": self.port, "priority": self.priority}

    @classmethod
    def from_dict(cls, d: dict) -> 'ICECandidate':
        return cls(
            ctype    = d.get("type", cls.HOST),
            ip       = d.get("ip", ""),
            port     = int(d.get("port", 0)),
            priority = int(d.get("priority", 0)),
        )

    def __repr__(self):
        return f"ICECandidate({self.ctype} {self.ip}:{self.port})"


class STUNClient:
    """
    Minimal RFC-5389 STUN client.

    Sends a Binding Request over raw UDP and parses the Binding Response to
    extract the server-reflexive (public) IP and port.  No external libraries
    required — built entirely on the stdlib `socket` and `struct` modules.

    STUN message layout (RFC 5389 §6):
      0-1   Type      (0x0001 = Binding Request, 0x0101 = Binding Success)
      2-3   Length    (body length in bytes, not counting 20-byte header)
      4-7   Magic Cookie (fixed: 0x2112A442)
      8-19  Transaction ID (12 random bytes)
      20+   Attributes (TLV)

    XOR-MAPPED-ADDRESS attribute (0x0020):
      1     0x00 (reserved)
      1     family (0x01 = IPv4)
      2     port XOR'd with high 16 bits of magic cookie
      4     IP  XOR'd with magic cookie (IPv4)
    """

    MAGIC_COOKIE = 0x2112A442
    MSG_BINDING_REQUEST  = 0x0001
    MSG_BINDING_RESPONSE = 0x0101
    ATTR_MAPPED_ADDRESS     = 0x0001
    ATTR_XOR_MAPPED_ADDRESS = 0x0020

    @classmethod
    def get_public_address(
            cls,
            stun_host: str,
            stun_port: int,
            local_sock: Optional[socket.socket] = None,
            timeout: float = 3.0
    ) -> Optional[Tuple[str, int]]:
        """
        Query a STUN server and return (public_ip, public_port) or None.

        If `local_sock` is provided, the request is sent on that socket so
        that the NAT binding for the existing socket is discovered rather than
        opening a new ephemeral port (important for hole punching).
        """
        own_sock = local_sock is None
        try:
            # Resolve STUN server (may be a hostname)
            try:
                infos = socket.getaddrinfo(stun_host, stun_port,
                                           socket.AF_UNSPEC, socket.SOCK_DGRAM)
                if not infos:
                    return None
                _af, _st, _pr, _cn, stun_addr = infos[0]
            except Exception:
                return None

            if own_sock:
                # Use the address family returned by getaddrinfo so that
                # IPv6-only STUN servers (AAAA records) work correctly.
                local_sock = socket.socket(_af, socket.SOCK_DGRAM)
                local_sock.settimeout(timeout)

            # Build Binding Request
            txn_id = secrets.token_bytes(12)
            header = struct.pack(
                "!HHI12s",
                cls.MSG_BINDING_REQUEST,
                0,                  # length = 0 (no attributes)
                cls.MAGIC_COOKIE,
                txn_id,
            )
            local_sock.sendto(header, stun_addr)

            # Receive response (may arrive in fragments — loop with timeout)
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    local_sock.settimeout(max(0.1, deadline - time.time()))
                    data, _ = local_sock.recvfrom(2048)
                except socket.timeout:
                    break
                result = cls._parse_response(data, txn_id)
                if result:
                    return result
            return None
        except Exception as exc:
            log.debug(f"STUN query {stun_host}:{stun_port} failed: {exc}")
            return None
        finally:
            if own_sock and local_sock:
                try:
                    local_sock.close()
                except Exception:
                    pass

    @classmethod
    def _parse_response(cls, data: bytes,
                        txn_id: bytes) -> Optional[Tuple[str, int]]:
        """Parse a STUN Binding Response; return (ip, port) or None."""
        if len(data) < 20:
            return None
        msg_type, length, magic, resp_txn = struct.unpack_from("!HHI12s", data)
        if msg_type != cls.MSG_BINDING_RESPONSE:
            return None
        if magic != cls.MAGIC_COOKIE:
            return None
        if resp_txn != txn_id:
            return None

        # Parse TLV attributes
        offset = 20
        while offset + 4 <= len(data):
            attr_type, attr_len = struct.unpack_from("!HH", data, offset)
            offset += 4
            attr_val = data[offset: offset + attr_len]
            # Pad to 4-byte boundary
            offset += (attr_len + 3) & ~3

            if attr_type == cls.ATTR_XOR_MAPPED_ADDRESS and attr_len >= 8:
                # XOR-MAPPED-ADDRESS: family=IPv4 only for now
                _reserved, family = struct.unpack_from("!BB", attr_val)
                if family == 0x01:  # IPv4
                    xport, xip = struct.unpack_from("!HI", attr_val, 2)
                    port = xport ^ (cls.MAGIC_COOKIE >> 16)
                    ip_int = xip ^ cls.MAGIC_COOKIE
                    ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                    return ip, port
                elif family == 0x02 and len(attr_val) >= 20:  # IPv6
                    xport = struct.unpack_from("!H", attr_val, 2)[0]
                    port = xport ^ (cls.MAGIC_COOKIE >> 16)
                    xaddr = attr_val[4:20]
                    magic_bytes = struct.pack("!I", cls.MAGIC_COOKIE) + txn_id
                    ip_bytes = bytes(a ^ b for a, b in zip(xaddr, magic_bytes))
                    ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
                    return ip, port

            elif attr_type == cls.ATTR_MAPPED_ADDRESS and attr_len >= 8:
                # Fallback: plain MAPPED-ADDRESS (older servers)
                _reserved, family = struct.unpack_from("!BB", attr_val)
                if family == 0x01:
                    port = struct.unpack_from("!H", attr_val, 2)[0]
                    ip_int = struct.unpack_from("!I", attr_val, 4)[0]
                    ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                    return ip, port

        return None
