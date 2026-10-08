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
"""visold.network.udp.transport


Defines: UDPTransport, UDPPeerConnection
Origin: visold_vsd_.py L2551-2674, L2690-2878
"""

import json
import socket
import threading
import time
from typing import Callable, Dict, Optional

from visold.network.udp.session import UDPSession
from visold.network.udp.wire import (
    _UDP_HB_TIMEOUT,
    _udp_compress,
    _udp_normalize_addr,
    _udp_unpack,
)


# ─────────────────────────────────────────────────────────────────────────────
class UDPTransport:
    """
    Singleton UDP socket layer for one P2PNetwork instance.

    Owns:
      • One bound dual-stack UDP socket (AF_INET6, IPV6_V6ONLY=0, fallback AF_INET).
      • A single recv thread that demultiplexes packets to UDPSessions.
      • A registry of UDPSession objects keyed by normalized (ip, port) tuples.
      • A background GC thread that reaps dead sessions.

    Thread-safety: all session-map mutations are guarded by self._lock.
    """

    def __init__(self, port: int, bind_addr: str = '',
                 max_pending_inbound: int = 64):
        self._port       = port
        self._bind_addr  = bind_addr
        self._lock       = threading.Lock()
        self._sessions: Dict[tuple, UDPSession] = {}
        # Addresses that passed the cheap pre-session admission gate but have
        # not completed the higher-level P2P handshake yet.  This prevents an
        # unbounded stream of spoofed/new endpoints from allocating a session
        # (and its retransmission thread) each.
        self._pending_inbound: set = set()
        self._max_pending_inbound = max(1, int(max_pending_inbound))
        self._running    = False
        # One callback per newly discovered peer addr (set by P2PNetwork)
        self._on_new_peer = None   # Callable[[tuple], None]
        # Cheap synchronous admission predicate.  It MUST NOT perform the
        # handshake; it only decides whether a new source may allocate a
        # UDPSession.
        self._inbound_admission: Optional[Callable[[tuple], bool]] = None
        self._sock       = self._create_socket()

    def _create_socket(self) -> socket.socket:
        """Create a dual-stack UDP socket bound to self._port."""
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            s.bind((self._bind_addr or '::', self._port))
        except OSError:
            # Fallback: IPv4-only
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            s.bind((self._bind_addr or '0.0.0.0', self._port))  # nosec B104 – intentional P2P bind-all
        return s

    def start(self, on_new_peer=None, inbound_admission=None):
        """Start background threads.

        `inbound_admission`, when supplied, is evaluated for a previously
        unseen source *before* its UDPSession is created.  It must be a cheap
        synchronous predicate returning a truthy value to admit the source.
        """
        self._on_new_peer = on_new_peer
        self._inbound_admission = inbound_admission
        self._running     = True
        threading.Thread(target=self._recv_loop,  daemon=True,
                         name='udp-recv').start()
        threading.Thread(target=self._gc_loop,    daemon=True,
                         name='udp-gc').start()

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except Exception:
            pass
        with self._lock:
            for s in self._sessions.values():
                s.close()
            self._sessions.clear()
            self._pending_inbound.clear()

    # ── Session access ────────────────────────────────────────────────────
    def _get_or_create_session(self, addr: tuple):
        """Return (session, created) under the session-map lock."""
        addr = _udp_normalize_addr(addr)
        with self._lock:
            sess = self._sessions.get(addr)
            if sess is not None:
                return sess, False
            sess = UDPSession(self, addr)
            self._sessions[addr] = sess
            return sess, True

    def get_session(self, addr: tuple) -> UDPSession:
        """Return (creating if necessary) the UDPSession for addr."""
        sess, _created = self._get_or_create_session(addr)
        return sess

    def release_inbound(self, addr: tuple):
        """Release a pre-authentication inbound admission reservation."""
        addr = _udp_normalize_addr(addr)
        with self._lock:
            self._pending_inbound.discard(addr)

    def pending_inbound_count(self) -> int:
        """Return the number of admitted but not-yet-released inbound sources."""
        with self._lock:
            return len(self._pending_inbound)

    def _admit_inbound(self, addr: tuple) -> bool:
        """Gate new source addresses before allocating a UDPSession."""
        addr = _udp_normalize_addr(addr)
        with self._lock:
            if addr in self._sessions:
                return True
            if addr in self._pending_inbound:
                return False
            if len(self._pending_inbound) >= self._max_pending_inbound:
                return False
            self._pending_inbound.add(addr)

        predicate = self._inbound_admission
        if predicate is not None:
            try:
                accepted = bool(predicate(addr))
            except Exception:
                accepted = False
            if not accepted:
                self.release_inbound(addr)
                return False
        return True

    def has_session(self, addr: tuple) -> bool:
        addr = _udp_normalize_addr(addr)
        with self._lock:
            return addr in self._sessions

    def remove_session(self, addr: tuple, expected_session=None) -> bool:
        """Remove and close the session for *addr*.

        If ``expected_session`` is supplied, removal occurs only when the
        currently registered session is that exact object.  This makes
        handshake-failure cleanup safe against a concurrent reconnect that
        has already installed a replacement session for the same endpoint.

        Returns True when a session was removed, otherwise False.
        """
        addr = _udp_normalize_addr(addr)
        with self._lock:
            current = self._sessions.get(addr)
            if current is None:
                self._pending_inbound.discard(addr)
                return False
            if expected_session is not None and current is not expected_session:
                # A newer session owns this endpoint now.  Do not close it.
                self._pending_inbound.discard(addr)
                return False
            sess = self._sessions.pop(addr)
            # A pre-auth reservation belongs to this endpoint.  Releasing it
            # here also covers defensive/external session teardown paths that
            # bypass the normal handshake worker's finally block.
            self._pending_inbound.discard(addr)
        sess.close()
        return True

    # ── Background threads ────────────────────────────────────────────────
    def _recv_loop(self):
        """
        Single receive thread — demultiplexes every inbound UDP datagram to the
        correct UDPSession.  New source addresses trigger _on_new_peer so that
        the P2PNetwork can initiate a handshake for spontaneously connecting peers.
        """
        self._sock.settimeout(1.0)
        while self._running:
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            parsed = _udp_unpack(data)
            if parsed is None:
                continue   # bad magic / too short
            flags, seq, frag_id, frag_off, payload = parsed
            addr = _udp_normalize_addr(addr)

            # Admission MUST happen before a new UDPSession is allocated.
            # Existing sessions bypass the gate so authenticated peers are not
            # affected by the pre-authentication resource budget.
            if not self._admit_inbound(addr):
                continue

            sess, created = self._get_or_create_session(addr)
            if not created:
                # Another local path (normally an outbound dial) won the race
                # between admission and session creation.  Do not start a
                # second inbound handshake for the same endpoint.
                self.release_inbound(addr)
            sess.on_packet(flags, seq, frag_id, frag_off, payload)

            # Notify P2PNetwork of brand-new senders so it can do a handshake.
            # The P2P handler releases the pre-auth reservation as soon as the
            # handshake either fails or the peer is successfully registered.
            if created and self._on_new_peer:
                try:
                    self._on_new_peer(addr)
                except Exception:
                    # No worker was successfully launched; do not strand the
                    # admission slot.
                    self.release_inbound(addr)
            elif created and not self._on_new_peer:
                self.release_inbound(addr)

    def _gc_loop(self):
        """Reap UDPSessions that have gone silent beyond the heartbeat timeout."""
        while self._running:
            time.sleep(_UDP_HB_TIMEOUT / 4)
            with self._lock:
                dead = [a for a, s in self._sessions.items() if not s.is_alive()]
            for addr in dead:
                self.remove_session(addr)


# ─────────────────────────────────────────────────────────────────────────────
class UDPPeerConnection:
    """
    Shim that satisfies the PeerConnection interface expected by P2PNetwork
    (_peer_message_loop, _handle_message, connect_to, _handle_inbound, etc.)
    while using UDPSession as the transport underneath.

    Key mappings:
      send(msg)          → session.send_message(compress(json(msg)))
      recv_line(timeout) → session.inbound.get(timeout=timeout)
      close()            → transport.remove_session(addr)

    All other PeerConnection attributes (peer_id, ip, port, reputation,
    trust_level, connected, last_seen, _recv_buf, _lock, consecutive_audit_failures,
    _soft_ban_throttle_until, _pagination_active, _out_queue, PRI_*) are
    replicated here so that the upper layers see a compatible object.
    """

    TRUST_HIGH = "TRUST_LEVEL_HIGH"
    TRUST_LOW  = "TRUST_LEVEL_LOW"

    def __init__(self, peer_id: str, ip: str, port: int,
                 session: UDPSession,
                 reputation: float = 1.0,
                 trust_level: Optional[str] = None):
        self.peer_id   = peer_id
        self.ip        = ip
        self.port      = port
        self._session  = session
        self.reputation  = reputation
        self.fail_count  = 0
        self.last_seen   = time.time()
        self.connected   = True
        self._lock       = threading.Lock()
        self.trust_level = trust_level or self.TRUST_HIGH

        # Soft-ban / audit fields (mirrors PeerConnection)
        self.consecutive_audit_failures: int  = 0
        self._soft_ban_throttle_until:   float = 0.0

        # Temporary download/fast-sync queues.  These are normally None and
        # are populated only while a higher-level downloader owns the peer.
        # Keep them present so the UDP shim is structurally compatible with
        # PeerConnection and shared P2P handlers can safely access either
        # transport.
        self._block_chunk_queue = None
        self._snap_response_queue = None

        # Handshake byte buffer (kept for interface parity; UDP already
        # delivers complete decoded messages from UDPSession.inbound).
        self._recv_buf: bytes = b""

        # Pagination coordination event (mirrors PeerConnection)
        self._pagination_active: threading.Event = threading.Event()
        # Correlated chain-sync state: one request flight per peer.
        self._sync_state_lock = threading.RLock()
        self._sync_request_seq = 0
        self._sync_pending = None
        self._sync_last_reject_at = 0.0

        # Auto-sync deduplication (mirrors PeerConnection).  _register_peer()
        # starts the same shared auto-sync worker for UDP peers, so the UDP
        # shim must expose this guard as well.
        self._auto_sync_active: threading.Event = threading.Event()

        # Deep-fork synchronization state (mirrors PeerConnection).
        self._fork_sync_buffer: list = []
        self._fork_sync_buffer_bytes: int = 0
        self._fork_sync_target_height: int = -1

        # Peer-advertised state used by sync/mining-safety code.
        self.chain_height: int = -1
        self.capabilities: list = []

        # Priority queue shim — UDPPeerConnection does its own flow control
        # via the sliding window, so the priority queue is a passthrough that
        # calls send() immediately.
        import queue as _q
        self.PRI_CRITICAL = 0
        self.PRI_NORMAL   = 1
        self.PRI_BULK     = 2
        self._out_queue: _q.PriorityQueue = _q.PriorityQueue()
        self._out_seq     = 0
        self._out_seq_lock = threading.Lock()
        self._out_lock     = threading.Lock()
        self._out_bytes    = 0
        self.MAX_OUT_QUEUE = 512
        self.MAX_OUT_BYTES = 32 * 1024 * 1024
        self._writer_stop  = threading.Event()
        self._writer_thread = threading.Thread(
            target=self._writer_loop, daemon=True,
            name=f'udp-writer-{peer_id[:8]}')
        self._writer_thread.start()

    # ── Writer loop (mirrors PeerConnection._writer_loop) ─────────────────
    def _writer_loop(self):
        """Drain priority queue → send via UDP session."""
        while not self._writer_stop.is_set():
            try:
                item = self._out_queue.get(timeout=1.0)
            except Exception:
                continue
            if item is None:
                break
            pri, _seq, msg = item
            if msg is None:
                break
            try:
                est = len(json.dumps(msg))
            except Exception:
                est = 0
            with self._out_lock:
                self._out_bytes = max(0, self._out_bytes - est)
            if self.connected:
                self._raw_send(msg)

    def _raw_send(self, msg: dict) -> bool:
        try:
            raw  = json.dumps(msg).encode()
            data = _udp_compress(raw)
            self._session.send_message(data)
            self.last_seen = time.time()
            return True
        except Exception:
            self.connected = False
            return False

    # ── Public interface ───────────────────────────────────────────────────
    def send_priority(self, msg: dict, priority: int = 1) -> bool:
        """Enqueue msg for asynchronous prioritized send.

        AUDIT-FIX-24: previously a CRITICAL message always bypassed the
        MAX_OUT_QUEUE/MAX_OUT_BYTES cap with no eviction, so a sustained
        stream of critical messages during congestion could grow this
        queue without bound — unlike the TCP PeerConnection this class
        mirrors, which evicts one lower-priority entry to make room. Match
        that behaviour here so both transports enforce the same bound.
        """
        if self._writer_stop.is_set():
            return False
        try:
            est_bytes = len(json.dumps(msg))
        except Exception:
            est_bytes = 0
        with self._out_seq_lock:
            self._out_seq += 1
            seq = self._out_seq
        with self._out_lock:
            over = (self._out_queue.qsize() >= self.MAX_OUT_QUEUE or
                    self._out_bytes + est_bytes > self.MAX_OUT_BYTES)
        if over:
            if priority == self.PRI_CRITICAL:
                try:
                    drained = []
                    while True:
                        try: drained.append(self._out_queue.get_nowait())
                        except Exception: break
                    drained.sort()
                    if drained:
                        evicted = drained.pop()
                        try:
                            ev_bytes = len(json.dumps(evicted[2]))
                        except Exception:
                            ev_bytes = 0
                        with self._out_lock:
                            self._out_bytes = max(0, self._out_bytes - ev_bytes)
                    for it in drained:
                        self._out_queue.put_nowait(it)
                except Exception:
                    pass
            else:
                return False
        self._out_queue.put((priority, seq, msg))
        with self._out_lock:
            self._out_bytes += est_bytes
        return True

    def send(self, msg: dict) -> bool:
        """Synchronous send (used during handshake)."""
        return self._raw_send(msg)

    def recv_line(self, timeout: float = 30.0) -> Optional[dict]:
        """
        Block until a fully-reassembled, decoded message is available or
        timeout expires.  Returns None on timeout or session closed.
        """
        try:
            msg = self._session.inbound.get(timeout=timeout)
            if msg is None:
                return None
            self.last_seen = time.time()
            return msg
        except Exception:
            return None

    def close_writer(self):
        self._writer_stop.set()
        try:
            self._out_queue.put_nowait((0, 0, None))
        except Exception:
            pass

    def close(self):
        self.close_writer()
        self.connected = False
        try:
            self._session.close()
        except Exception:
            pass

    def _start_writer(self):
        """No-op — writer started in __init__."""
        pass
