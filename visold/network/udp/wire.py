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
"""visold.network.udp.wire

Original section: SECTION UDP-TRANSPORT: Resilient UDP Transport Layer for VSD P2P Network

Origin: visold_vsd_.py L1914-1930, L1939-1940, L1943-1948, L1952-1956, L1959-1973, L1976-1982, L2430-2433, L2436-2448, L2677-2686
"""

import struct
import zlib

from visold.network.compression import bounded_zlib_decompress


# STANDARD LIBRARY IMPORTS
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# SECTION UDP-TRANSPORT: Resilient UDP Transport Layer for VSD P2P Network
#
# Design goals:
#   • Resilience over throughput — every critical message arrives even on
#     jittery / lossy mobile links (CGNAT, satellite, bad WiFi).
#   • Drop-in replacement for the TCP socket layer — _handle_message and the
#     entire gossip/sync stack above are untouched.
#   • Single-file, zero extra dependencies — pure stdlib only (struct, socket,
#     threading, zlib, hashlib, secrets, json, time).
#
# Architecture:
#   UDPTransport        — singleton per P2PNetwork instance.  Owns the raw
#                         UDP socket (dual-stack), receive thread, and the
#                         per-peer UDPSession registry.
#   UDPSession          — per-peer state: fragment reassembly buffers, sliding
#                         window retransmit queue, heartbeat timer, sequence
#                         counters.
#   UDPPeerConnection   — thin shim that satisfies the PeerConnection interface
#                         so the rest of P2PNetwork can call .send()/.recv_line()
#                         without knowing it is UDP underneath.
#
# Wire format (all multi-byte fields big-endian):
#
#   ┌──────────┬──────────┬──────────┬──────────┬──────────┬────────────────┐
#   │ magic(2) │ flags(1) │ seq(4)   │ frag_id  │ frag_off │ payload (var)  │
#   │ 0xVD 0x50│          │          │  (2)     │   (2)    │                │
#   └──────────┴──────────┴──────────┴──────────┴──────────┴────────────────┘
#   Total header: 11 bytes.  Max UDP payload to fit in 1400-byte MTU: 1389 bytes.
#
#   flags bits:
#     bit 0 (0x01) — FRAG: this packet is a fragment (frag_id/frag_off valid)
#     bit 1 (0x02) — LAST: this is the last (or only) fragment of a message
#     bit 2 (0x04) — ACK:  seq field contains the seq being acknowledged
#     bit 3 (0x08) — NACK: seq field is a retransmit request
#     bit 4 (0x10) — HB:   heartbeat (keep-alive)
#     bit 5 (0x20) — FEC:  this packet is an XOR FEC repair symbol
#
# Forward Error Correction:
#   Every N data fragments within the same frag_id are followed by 1 XOR
#   parity symbol (FEC packet) that is the byte-wise XOR of those N data
#   fragments (zero-padded to equal length).  The receiver can reconstruct
#   any single lost fragment without a retransmit request.  N = UDP_FEC_GROUP.
#
# Congestion / rate control (Sliding Window):
#   _UDPWindow per session.  cwnd (congestion window, in packets) starts at
#   UDP_CWND_INIT and grows additively up to UDP_CWND_MAX on each ACK.  Any
#   retransmit request (NACK) causes a multiplicative decrease by half.
#   The window caps how many un-ACKed data packets may be in flight at once.
#   A BULK sender sleeps briefly when the window is full, ensuring a fast
#   node cannot flood a slow peer.
# ─────────────────────────────────────────────────────────────────────────────

# ── UDP transport tunables ───────────────────────────────────────────────────
# 2-byte magic: 0xAD 0x50 ('VD P(rotocol)')
_UDP_MAGIC        = bytes([0xAD, 0x50])


_UDP_HDR_FMT      = '>2sBIHH'            # magic(2) flags(1) seq(4) frag_id(2) frag_off(2)


_UDP_HDR_LEN      = struct.calcsize(_UDP_HDR_FMT)  # == 11


_UDP_MTU          = 1400      # conservative payload MTU (bytes)


_UDP_PAYLOAD_MAX  = _UDP_MTU - _UDP_HDR_LEN  # == 1389 bytes per fragment


_UDP_FEC_GROUP    = 4         # 1 FEC symbol per N data fragments


_UDP_CWND_INIT    = 8         # initial congestion window (packets)


_UDP_CWND_MAX     = 128       # maximum congestion window


_UDP_RTO_INIT     = 0.5       # initial retransmit timeout (seconds)


_UDP_RTO_MAX      = 8.0       # maximum RTO after backoff


_UDP_RTO_MIN      = 0.1       # minimum RTO


_UDP_MAX_RETRIES  = 6         # drop message after this many retransmit attempts


_UDP_HB_INTERVAL  = 15.0      # heartbeat period (seconds)


_UDP_HB_TIMEOUT   = 60.0      # peer considered dead after this silence (seconds)


_UDP_FRAG_TTL          = 30.0   # discard incomplete reassembly after 30 s


_UDP_FRAG_MAX          = 512    # max concurrent in-flight fragment groups per peer


# FIX-1: hard cap on fragments stored per reassembly group.
# Without this, a peer that sends frag_off 0,1,2,… without _F_LAST can grow
# a single _UDPReassembler.frags dict without bound, causing memory exhaustion.
# 1 GB / 1389 bytes-per-frag ≈ 766 k frags; 2048 is a generous real-world
# ceiling (a 1 GB MAX_MESSAGE_SIZE blob needs ~771 k frags — far more than
# one honest message ever needs in practice under the 200-block page cap).
# Any group that exceeds this limit is silently dropped; the peer's retransmit
# logic will eventually time-out and the session stays intact.
_UDP_FRAG_MAX_PER_GROUP = 2048  # max fragments within one reassembly group

# At most one XOR repair symbol is retained for each complete data-fragment
# group.  This is derived from the bounded per-group fragment count rather
# than from the 16-bit wire offset, so attacker-controlled FEC metadata cannot
# create an unbounded symbol table.
_UDP_FEC_MAX_SYMBOLS = (_UDP_FRAG_MAX_PER_GROUP + _UDP_FEC_GROUP - 1) // _UDP_FEC_GROUP


_UDP_WINDOW_SLEEP = 0.005       # sleep between window-full polls (5 ms)


# flag bits
_F_FRAG  = 0x01


_F_LAST  = 0x02


_F_ACK   = 0x04


_F_NACK  = 0x08


_F_HB    = 0x10


_F_FEC   = 0x20


# ─────────────────────────────────────────────────────────────────────────────

def _udp_pack(flags: int, seq: int, frag_id: int, frag_off: int,
              payload: bytes) -> bytes:
    """Serialize a UDP transport packet."""
    hdr = struct.pack(_UDP_HDR_FMT, _UDP_MAGIC, flags, seq, frag_id, frag_off)
    return hdr + payload


def _udp_unpack(data: bytes):
    """
    Deserialize a UDP transport packet.
    Returns (flags, seq, frag_id, frag_off, payload) or None on bad magic/length.
    """
    if len(data) < _UDP_HDR_LEN:
        return None
    try:
        magic, flags, seq, frag_id, frag_off = struct.unpack_from(
            _UDP_HDR_FMT, data)
    except struct.error:
        return None
    if magic != _UDP_MAGIC:
        return None
    # The transport promises a 1400-byte maximum wire packet.  Enforce that
    # promise at ingress so oversized UDP datagrams can never reach reassembly
    # or FEC bookkeeping.
    if len(data) > _UDP_MTU:
        return None
    return flags, seq, frag_id, frag_off, data[_UDP_HDR_LEN:]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings, zero-padding the shorter one."""
    if len(a) < len(b):
        a = a + b'\x00' * (len(b) - len(a))
    elif len(b) < len(a):
        b = b + b'\x00' * (len(a) - len(b))
    return bytes(x ^ y for x, y in zip(a, b))


# ── Shared (de)compression helpers used by UDP layer ─────────────────────────
def _udp_compress(data: bytes) -> bytes:
    """Compress data for UDP transport using zlib (stdlib, zero deps)."""
    compressed = zlib.compress(data, level=6)
    return compressed if len(compressed) < len(data) else data


def _udp_decompress(data: bytes) -> bytes:
    """
    Attempt zlib decompression; fall back to raw bytes if not compressed.
    Hard cap at 32 MB to prevent zip-bomb attacks.
    """
    _MAX = 32 * 1024 * 1024
    try:
        out = bounded_zlib_decompress(data, _MAX)
        return out
    except (zlib.error, ValueError):
        return data   # not compressed — return as-is


def _udp_normalize_addr(addr: tuple) -> tuple:
    """
    Normalize a (host, port[, ...]) addr tuple to a plain (str, int) pair.
    Strips IPv4-mapped IPv6 prefixes (::ffff:x.x.x.x → x.x.x.x).
    """
    host = addr[0]
    port = addr[1]
    if host.startswith('::ffff:'):
        host = host[7:]
    return (host, port)
