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
"""visold.network.peer_connection


Defines: PeerConnection
Origin: visold_vsd_.py L31300-31628
"""

import errno
import hashlib
import ipaddress
import json
import os
import select
import ssl
import socket
import sys
import threading
import time
import uuid
import weakref
from typing import Any, List, Optional

from visold.kernel.config import Config
from visold.kernel.compression_utils import DecompressedSizeLimitError
from visold.kernel.logging_setup import log
from visold.network.compression import CompressionEngine
from visold.network.message_logger import P2PMessageLogger


# ─────────────────────────────────────────────────────────────────────────────
#  Serialized TLS I/O  (fix for random session drops: EOF / BAD_RECORD_MAC)
# ─────────────────────────────────────────────────────────────────────────────
# One TLS connection is an OpenSSL SSL object.  OpenSSL does NOT support two
# threads calling SSL_read() and SSL_write() on the same SSL object at the same
# time (they share per-connection state such as the socket-BIO retry flags and
# record-layer buffers).  This node's reader thread (_peer_message_loop) and its
# writer paths (PeerConnection._raw_send / PeerConnection.send) do exactly that,
# and the unsynchronized overlap shows up as spontaneous "EOF" or
# "bad record MAC" drops of healthy sessions.
#
# Rule enforced here: for a TLS socket EVERY SSL read or write is one
# NON-BLOCKING attempt made while holding a single per-socket lock.  Waiting for
# readability/writability happens OUTSIDE that lock, so a reader that is idle
# never blocks a writer (and vice versa).  The lock lives on the socket object
# itself, so a temporary handshake PeerConnection and the final registered
# PeerConnection that share one socket also share one lock.  Plain (non-TLS)
# sockets keep their original behavior: concurrent recv()/send() on a plain TCP
# socket is safe.
_TLS_IO_LOCK_ATTR = "_visold_tls_io_lock"
_TLS_WRITE_LOCK_ATTR = "_visold_tls_write_lock"
_TLS_ATTR_GUARD = threading.Lock()
_TLS_IO_WAIT_SLICE = 1.0       # max seconds one idle reader waits before re-checking the socket
_TLS_WRITE_WAIT_SLICE = 0.25   # max seconds a blocked writer waits before retrying
_TLS_SEND_TIMEOUT = 30.0       # seconds without write progress before a send fails


def _is_tls_socket(sock) -> bool:
    return isinstance(sock, ssl.SSLSocket)


def _socket_lock(sock, attr: str):
    lock = getattr(sock, attr, None)
    if lock is None:
        with _TLS_ATTR_GUARD:
            lock = getattr(sock, attr, None)
            if lock is None:
                lock = threading.Lock()
                setattr(sock, attr, lock)
    return lock


def _tls_io_lock(sock):
    """Lock that serializes every SSL_read/SSL_write on this TLS socket."""
    return _socket_lock(sock, _TLS_IO_LOCK_ATTR)


def _tls_write_lock(sock):
    """Keeps one complete frame write at a time per TLS socket, regardless of
    how many PeerConnection wrappers share it (an interrupted SSL_write must be
    retried with the same buffer before any other write)."""
    return _socket_lock(sock, _TLS_WRITE_LOCK_ATTR)


def _tls_set_nonblocking(sock) -> None:
    # Called while holding the I/O lock.  Idempotent; every TLS read/write below
    # uses non-blocking attempts and does its own deadline handling.
    if sock.gettimeout() != 0.0:
        sock.settimeout(0.0)


def _wait_socket_ready(sock, want_read: bool, want_write: bool, timeout: float) -> None:
    """Block (without holding any lock) until the fd is ready or timeout.

    Uses poll() where available because select() cannot handle descriptors
    >= 1024, which a seed node with many peers can reach.  A closed/invalid fd
    raises OSError(EBADF), matching what recv() on a closed socket raised.
    """
    fd = sock.fileno()
    if fd is None or fd < 0:
        raise OSError(errno.EBADF, "Bad file descriptor")
    if timeout <= 0:
        return
    if hasattr(select, "poll"):
        poller = select.poll()
        mask = 0
        if want_read:
            mask |= select.POLLIN
        if want_write:
            mask |= select.POLLOUT
        poller.register(fd, mask)
        # POLLHUP/POLLERR/POLLNVAL are always reported -> the following
        # recv()/send() attempt surfaces the real condition.
        poller.poll(int(timeout * 1000) + 1)
        return
    select.select([sock] if want_read else [], [sock] if want_write else [], [], timeout)


def tls_recv(sock, size: int, timeout: float) -> bytes:
    """recv() for a TLS socket that is safe next to concurrent writers.

    Returns bytes (b"" means EOF, exactly like SSLSocket.recv).  Raises
    socket.timeout after ``timeout`` seconds without data, so the caller's
    existing idle/PING handling is unchanged.
    """
    deadline = time.monotonic() + max(0.0, float(timeout))
    lock = _tls_io_lock(sock)
    while True:
        with lock:
            fd = sock.fileno()
            if fd is None or fd < 0:
                raise OSError(errno.EBADF, "Bad file descriptor")
            _tls_set_nonblocking(sock)
            try:
                return sock.recv(size)
            except ssl.SSLWantReadError:
                want_read, want_write = True, False
            except ssl.SSLWantWriteError:
                want_read, want_write = False, True
            except BlockingIOError:
                want_read, want_write = True, False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("timed out waiting for readable TLS socket")
        _wait_socket_ready(sock, want_read, want_write,
                           min(remaining, _TLS_IO_WAIT_SLICE))


def tls_sendall(sock, data, timeout: float = _TLS_SEND_TIMEOUT) -> None:
    """sendall() for a TLS socket that is safe next to a concurrent reader.

    ``timeout`` is the longest stretch without write progress.  Raises
    socket.timeout when it expires; any other exception is a real send failure
    (the caller must treat the stream as unusable, as before).
    """
    with memoryview(data) as raw_view, raw_view.cast("B") as view_b:
        view = view_b
        write_lock = _tls_write_lock(sock)
        io_lock = _tls_io_lock(sock)
        with write_lock:
            deadline = time.monotonic() + max(0.0, float(timeout))
            while len(view):
                with io_lock:
                    fd = sock.fileno()
                    if fd is None or fd < 0:
                        raise OSError(errno.EBADF, "Bad file descriptor")
                    _tls_set_nonblocking(sock)
                    try:
                        sent = sock.send(view)
                    except ssl.SSLWantWriteError:
                        want_read, want_write = False, True
                    except ssl.SSLWantReadError:
                        want_read, want_write = True, False
                    except BlockingIOError:
                        want_read, want_write = False, True
                    else:
                        if sent:
                            view = view[sent:]
                            deadline = time.monotonic() + max(0.0, float(timeout))
                        continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("timed out waiting for writable TLS socket")
                _wait_socket_ready(sock, want_read, want_write,
                                   min(remaining, _TLS_WRITE_WAIT_SLICE))


def _sock_sendall(sock, data) -> None:
    if _is_tls_socket(sock):
        tls_sendall(sock, data)
    else:
        sock.sendall(data)


def _tls_pending_safe(sock):
    """SSL_pending() for diagnostics, taken under the I/O lock (never hangs)."""
    lock = _tls_io_lock(sock)
    if not lock.acquire(timeout=0.5):
        return "unavailable_busy"
    try:
        return str(int(sock.pending()))
    finally:
        lock.release()


def _tcp_session_diagnostics(sock):
    """Return an endpoint-derived TCP link ID and observed socket endpoints."""
    def _format_endpoint(value):
        try:
            host, port = value[0], int(value[1])
            raw_host = str(host).split("%", 1)[0]
            try:
                address = ipaddress.ip_address(raw_host)
                if getattr(address, "ipv4_mapped", None) is not None:
                    address = address.ipv4_mapped
                canonical_host = address.compressed
            except ValueError:
                canonical_host = raw_host.lower()
            if ":" in canonical_host:
                return f"[{canonical_host}]:{port}"
            return f"{canonical_host}:{port}"
        except Exception:
            return "?"

    local = remote = "?"
    if sock is not None:
        try:
            local = _format_endpoint(sock.getsockname())
        except Exception:
            pass
        try:
            remote = _format_endpoint(sock.getpeername())
        except Exception:
            pass
    if local != "?" and remote != "?":
        pair = "\0".join(sorted((local, remote))).encode("utf-8", "replace")
        session_id = hashlib.sha256(pair).hexdigest()[:20]
        kind = "tcp_endpoint_pair"
    else:
        session_id = uuid.uuid4().hex[:20]
        kind = "local_fallback"
    return session_id, kind, local, remote


_TCP_STATE_NAMES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSED",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
    12: "NEW_SYN_RECV",
}


def _tcp_transport_snapshot(sock):
    """Return passive best-effort transport state for an EOF diagnostic."""
    snapshot = {
        "tcp_state": "unavailable",
        "tcp_state_code": "?",
        "ssl_pending": "unavailable",
        "socket_timeout": "unavailable",
        "socket_fd": "-1",
        "socket_closed": "unknown",
    }
    if sock is None:
        return snapshot

    try:
        snapshot["socket_fd"] = str(sock.fileno())
    except Exception:
        pass
    try:
        snapshot["socket_closed"] = str(bool(getattr(sock, "_closed")))
    except Exception:
        pass
    try:
        snapshot["socket_timeout"] = str(sock.gettimeout())
    except Exception:
        pass
    try:
        pending = getattr(sock, "pending", None)
        if callable(pending):
            if _is_tls_socket(sock):
                snapshot["ssl_pending"] = _tls_pending_safe(sock)
            else:
                snapshot["ssl_pending"] = str(int(pending()))
    except Exception:
        pass

    # Probe the socket capability instead of gating on sys.platform.
    # Android reports sys.platform == "android" on a Linux kernel; TCP_INFO
    # may still be available and useful there. Unsupported kernels/sockets are
    # handled by the getsockopt exception below without affecting peer flow.
    tcp_info = getattr(socket, "TCP_INFO", None)
    if tcp_info is None:
        snapshot["tcp_state"] = "unsupported_option"
        return snapshot
    try:
        info = sock.getsockopt(socket.IPPROTO_TCP, tcp_info, 104)
        if not isinstance(info, (bytes, bytearray)) or not info:
            snapshot["tcp_state"] = "unavailable_empty_info"
            return snapshot
        state = int(info[0])
        snapshot["tcp_state_code"] = str(state)
        snapshot["tcp_state"] = _TCP_STATE_NAMES.get(
            state, f"UNKNOWN_{state}")
    except Exception as exc:
        snapshot["tcp_state"] = f"unavailable_{type(exc).__name__}"
    return snapshot


def _enable_strict_tls_eof_diagnostic(sock) -> bool:
    """Expose unexpected TCP EOFs instead of suppressing them, only when opted in."""
    if os.environ.get("VISOLD_TLS_STRICT_EOF_DIAGNOSTIC") != "1":
        return False
    try:
        if not hasattr(sock, "suppress_ragged_eofs"):
            return False
        sock.suppress_ragged_eofs = False
        return sock.suppress_ragged_eofs is False
    except Exception:
        return False


def _log_peer_socket_action(sock, operation, detail="-"):
    """Log TLS socket close/unwrap/shutdown calls outside normal peer cleanup."""
    if getattr(sock, "_visold_peer_close_guard", False):
        return
    peer_ref = getattr(sock, "_visold_peer_close_audit_ref", None)
    try:
        peer = peer_ref() if peer_ref is not None else None
    except Exception:
        peer = None
    if peer is None or str(getattr(peer, "peer_id", "unknown")) == "unknown":
        return
    try:
        caller_frame = sys._getframe(2)
        caller = f"{caller_frame.f_code.co_name}:{caller_frame.f_lineno}"
        stack = []
        frame = caller_frame
        for _ in range(6):
            stack.append(f"{frame.f_code.co_name}:{frame.f_lineno}")
            frame = frame.f_back
            if frame is None:
                break
        stack = ">".join(stack)
    except Exception:
        caller = stack = "unknown"
    try:
        fd_before = sock.fileno()
    except Exception:
        fd_before = -1
    log.warning(
        "[PeerRawSocketAction] ts_ns=%s operation=%s detail=%s session_id=%s "
        "session_id_kind=%s socket_local=%s socket_remote=%s peer=%s "
        "endpoint=%s:%s direction=%s connected=%s fd_before=%s "
        "caller=%s stack=%s thread=%s",
        time.time_ns(), operation, detail,
        getattr(peer, "session_id", "unknown"),
        getattr(peer, "_session_id_kind", "unknown"),
        getattr(peer, "_diag_socket_local", "?"),
        getattr(peer, "_diag_socket_remote", "?"),
        str(getattr(peer, "peer_id", ""))[:12],
        getattr(peer, "ip", "?"), getattr(peer, "port", "?"),
        "outbound" if getattr(peer, "local_outbound", False)
        else "inbound/unknown",
        bool(getattr(peer, "connected", False)), fd_before,
        caller, stack, threading.current_thread().name,
    )


def _install_peer_socket_action_audit(peer):
    """Observe raw TLS close/unwrap calls on one peer socket, without altering them."""
    sock = getattr(peer, "sock", None)
    if not isinstance(sock, ssl.SSLSocket):
        return
    try:
        sock._visold_peer_close_audit_ref = weakref.ref(peer)
        if getattr(sock, "_visold_peer_close_audit_installed", False):
            return
        sock_ref = weakref.ref(sock)
        real_close = type(sock).close
        real_unwrap = type(sock).unwrap
        real_shutdown = type(sock).shutdown

        def _audited_close(*args, **kwargs):
            target = sock_ref()
            if target is not None:
                _log_peer_socket_action(target, "close")
                return real_close(target, *args, **kwargs)
            return None

        def _audited_unwrap(*args, **kwargs):
            target = sock_ref()
            if target is not None:
                _log_peer_socket_action(target, "unwrap")
                return real_unwrap(target, *args, **kwargs)
            return None

        def _audited_shutdown(*args, **kwargs):
            target = sock_ref()
            if target is not None:
                detail = str(args[0]) if args else str(kwargs.get("how", "missing"))
                _log_peer_socket_action(target, "shutdown", detail)
                return real_shutdown(target, *args, **kwargs)
            return None

        # Instance-level wrappers avoid changing SSL behavior process-wide.
        sock.close = _audited_close
        sock.unwrap = _audited_unwrap
        sock.shutdown = _audited_shutdown
        sock._visold_peer_close_audit_installed = True
    except Exception:
        # Diagnostic instrumentation must never prevent a peer from being used.
        return


class PeerConnection:
    # ── Trust level constants — assigned during the HELLO handshake ───────────
    # TRUST_HIGH: peer's logic_hash matches ours or is on the Known-Good list.
    #             Standard validation only; no extra overhead.
    # TRUST_LOW:  peer's logic_hash is unknown (hacker/modified node).
    #             Connection is kept open (hybrid approach) but all MSG_TX and
    #             MSG_BLOCK messages are subjected to Full Audit Mode:
    #               • Deep re-verification of every signature
    #               • Rolling SafetyInvariant checks
    #               • 1 MB/min bandwidth throttle
    TRUST_HIGH = "TRUST_LEVEL_HIGH"
    TRUST_LOW  = "TRUST_LEVEL_LOW"

    def __init__(self, peer_id: str, ip: str, port: int,
                 sock: Optional[socket.socket] = None, reputation: float = 1.0,
                 trust_level: Optional[str] = None):
        self._block_chunk_queue: Optional[Any] = None  # set temporarily during block download
        self._snap_response_queue: Optional[Any] = None  # set temporarily during fast sync
        self.peer_id     = peer_id
        self.ip          = ip
        self.port        = port
        self.sock        = sock
        self._diag_strict_tls_eof = _enable_strict_tls_eof_diagnostic(sock)
        (self.session_id, self._session_id_kind,
         self._diag_socket_local, self._diag_socket_remote) = (
             _tcp_session_diagnostics(sock))
        self._last_rx_message_type = None
        self._last_rx_message_ts_ns = None
        # Public reachability metadata learned during authenticated handshake.
        self.user_id     = ""
        self.wallet_addr = ""
        self.is_seed_node = False
        self.registered_name = ""
        self._bootstrap_header_queue = None
        self._bootstrap_header_request_id = None
        # Peer-reported height is an untrusted advertisement used only for
        # sync discovery.  It must never be treated as validated chain progress.
        self.chain_height = -1  # backward-compatible alias: advertised height
        self.advertised_chain_height = -1
        self.verified_chain_height = -1  # advanced only after canonical block verification
        self.verified_chain_hash = ""
        self.chain_tip_hash = ""
        self._pex_cursor = 0
        self.reputation  = reputation
        self.fail_count  = 0
        self.last_seen   = time.time()
        self.connected   = sock is not None
        _install_peer_socket_action_audit(self)
        self._lock       = threading.Lock()
        # trust_level is set by the handshake; defaults to HIGH until classified
        self.trust_level = trust_level if trust_level is not None else self.TRUST_HIGH
        # ── Soft Ban state (v6.0.0) ──────────────────────────────────────────────
        # Tracks consecutive Full-Audit rejections for this peer session.
        # Resets to 0 whenever the peer sends a valid MSG_TX or MSG_BLOCK.
        # Drives three-strikes escalation: warn → throttle → 24-hour ban.
        self.consecutive_audit_failures: int  = 0
        # Monotonic epoch (time.time()) past which the strike-2 throttle is
        # still active.  Set to 0.0 initially (no throttle).
        self._soft_ban_throttle_until:   float = 0.0
        # ── Frame-buffer for recv_line (v6.9.8 BUG-FIX) ──────────────────────
        # Persistent across consecutive recv_line() calls so that bytes received
        # after the first \n in a TCP segment are NOT discarded.  TCP is a stream
        # protocol — multiple application-layer frames can arrive in a single
        # recv() call during the handshake (e.g. POW_CHALLENGE+VERIFY coalesce).
        self._recv_buf: bytes = b""
        # ── Pagination coordination flag (v7.0.1.1 — Partial-Sync Fix) ───────
        self._pagination_active: threading.Event = threading.Event()
        # Correlated chain-sync state: one request flight per peer.
        self._sync_state_lock = threading.RLock()
        self._sync_request_seq = 0
        self._sync_pending = None
        self._sync_last_result = None
        self._sync_last_reject_at = 0.0
        # ── Auto-sync dedup flag (sync-fix-4) ────────────────────────────────
        # Prevents two concurrent _auto_sync_on_connect threads from running
        # for the same peer simultaneously.  Both the inbound and outbound
        # handler call _register_peer(initiator=True) after v7.0.1.2, so
        # without a guard two threads fire identical MSG_GET_CHAIN bursts at
        # exactly the same time (visible as duplicate attempt 3/4 log lines).
        # The first thread to set this flag owns the sync; the second exits.
        self._auto_sync_active: threading.Event = threading.Event()

        # Deep-fork synchronization buffer. Populated only after a genuine
        # block-hash divergence is observed in a paginated chain response.
        self._fork_sync_buffer: list = []
        self._fork_sync_buffer_bytes: int = 0
        self._fork_sync_target_height: int = -1

        # Chain-height fields are initialized above. `chain_height` is only
        # the compatibility alias for the advertised sync target; mining safety
        # and PEX use independently verified progress, never this value.
        self.capabilities: List[str] = []

        # ── Prioritized outbound queue (v7.1.0) ──────────────────────────────
        # Without this, all send() calls are synchronous and serialized — a
        # single slow peer can block a MSG_BLOCK broadcast behind a large
        # MSG_GET_CHAIN response to another peer.  Priority tiers:
        #   0 = CRITICAL  (new blocks, consensus votes) — jumps the queue
        #   1 = NORMAL    (transactions, capability updates)
        #   2 = BULK      (peer exchange, chain sync pages, gossip)
        # A small per-peer writer thread drains the queue; overflow above
        # MAX_OUT_QUEUE drops the lowest-priority pending message, ensuring
        # blocks are NEVER dropped in favor of gossip backlog.
        import queue as _queue_mod
        self.PRI_CRITICAL = 0
        self.PRI_NORMAL   = 1
        self.PRI_BULK     = 2
        self._out_queue: '_queue_mod.PriorityQueue' = _queue_mod.PriorityQueue()
        self._out_seq    = 0                  # tiebreaker for equal priorities
        self._out_seq_lock = threading.Lock()
        self.MAX_OUT_QUEUE = 512              # per-peer outbound backlog cap
        # v7.1.0: also cap total bytes queued so a slow peer can't make us
        # buffer GBs of pending blocks.  Tracked separately from item count.
        self.MAX_OUT_BYTES = 32 * 1024 * 1024  # 32 MB pending per peer
        self._out_bytes    = 0
        self._out_lock     = threading.Lock()
        # Serializes writer startup, shutdown, and queue admission. Without this
        # lifecycle lock, a sender could clear _writer_stop/start a new writer
        # in the narrow race after a fatal send error had marked the transport
        # unusable.
        self._writer_lifecycle_lock = threading.Lock()
        self._writer_thread: Optional[threading.Thread] = None
        self._writer_stop  = threading.Event()
        self._local_transport_failure_reason = None
        if self.connected:
            self._start_writer()

    def _start_writer_locked(self) -> bool:
        """Start the per-peer writer while holding _writer_lifecycle_lock."""
        if self._writer_stop.is_set() or not self.connected:
            return False
        if self._writer_thread and self._writer_thread.is_alive():
            return True
        t = threading.Thread(target=self._writer_loop,
                             name=f"peer-writer-{self.peer_id[:8]}",
                             daemon=True)
        self._writer_thread = t
        try:
            t.start()
        except Exception:
            self._writer_thread = None
            log.exception("[PeerWriterStartFailure] peer=%s endpoint=%s:%s",
                          str(self.peer_id)[:12], self.ip, self.port)
            return False
        return True

    def _start_writer(self) -> bool:
        with self._writer_lifecycle_lock:
            return self._start_writer_locked()

    def _abort_after_send_failure(self, reason: str, error=None) -> None:
        """Fail closed after a socket write whose partial progress is unknown.

        TCP sendall() does not report how many bytes were transmitted when it
        raises. The stream can therefore no longer safely carry another frame.
        Stop queue admission, discard the old session's queued frames, and
        shutdown the socket to wake the reader; normal peer-loop cleanup owns
        the final close and identity-level bookkeeping.
        """
        self.connected = False
        self._local_transport_failure_reason = str(reason)
        with self._writer_lifecycle_lock:
            self._writer_stop.set()
            with self._out_lock:
                while True:
                    try:
                        self._out_queue.get_nowait()
                    except Exception:
                        break
                self._out_bytes = 0

        log.warning(
            "[PeerTransportAbort] ts_ns=%s session_id=%s peer=%s endpoint=%s:%s "
            "direction=%s reason=%s error=%s detail=%s action=shutdown",
            time.time_ns(), getattr(self, "session_id", "unknown"),
            str(getattr(self, "peer_id", ""))[:12], self.ip, self.port,
            "outbound" if getattr(self, "local_outbound", False) else "inbound/unknown",
            str(reason)[:96], type(error).__name__ if error is not None else "?",
            str(error)[:200] if error is not None else "?",
        )
        sock = self.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception as shutdown_exc:
                # The original write failure remains the primary error. This
                # follow-up is useful when shutdown cannot wake a blocked recv.
                log.debug(
                    "[PeerTransportAbortShutdownFailure] ts_ns=%s session_id=%s "
                    "peer=%s reason=%s error=%s detail=%s",
                    time.time_ns(), getattr(self, "session_id", "unknown"),
                    str(getattr(self, "peer_id", ""))[:12], str(reason)[:96],
                    type(shutdown_exc).__name__, str(shutdown_exc)[:200],
                )

    def _writer_loop(self):
        """Drain the priority queue using exactly one writer per TCP stream.

        A failed sendall() makes the transmitted byte count unknowable. Retrying
        that frame (or continuing with a later frame) on the same stream can
        corrupt the application's newline-framed protocol. A transport write
        failure therefore aborts this session; only a *pre-send encoding*
        failure drops one message and leaves the healthy stream available.
        """
        while not self._writer_stop.is_set():
            try:
                item = self._out_queue.get(timeout=1.0)
            except Exception:
                continue
            if item is None:
                break
            _pri, _seq, msg = item
            if msg is None:  # poison pill from close_writer
                break

            try:
                est_bytes = len(json.dumps(msg))
            except Exception:
                est_bytes = 0
            with self._out_lock:
                self._out_bytes = max(0, self._out_bytes - est_bytes)

            result = self._raw_send(msg)
            if result is True:
                continue
            if result is None:
                # Serialization/compression failed before touching the socket;
                # drop only this invalid message and keep the transport alive.
                continue

            # False means sendall() raised after the write may have begun. The
            # socket must not carry a retry or any subsequent application frame.
            # _raw_send() already made the stream unusable, stopped queue
            # admission, and shut down the socket before returning False.
            break
        log.debug(
            "[WRITER %s] exit stop=%s connected=%s",
            self.peer_id[:8], self._writer_stop.is_set(), self.connected,
        )

    def _raw_send(self, msg: dict) -> Optional[bool]:
        """Send one framed message from the asynchronous writer.

        Returns True on success, None when encoding failed before any socket
        write (message dropped), and False when sendall failed and the stream
        must be considered unusable. Never retry False on the same socket.
        """
        try:
            raw = json.dumps(msg).encode()
            data = CompressionEngine.compress(raw) + b"\n"
        except Exception as exc:
            log.warning(
                "[PeerEncodeFailure] ts_ns=%s session_id=%s peer=%s endpoint=%s:%s "
                "direction=%s msg_type=%s error=%s detail=%s path=writer",
                time.time_ns(), getattr(self, "session_id", "unknown"),
                str(getattr(self, "peer_id", ""))[:12], self.ip, self.port,
                "outbound" if getattr(self, "local_outbound", False) else "inbound/unknown",
                str(msg.get("type", "<missing>"))[:64], type(exc).__name__, str(exc)[:240],
            )
            return None

        send_error = None
        try:
            with self._lock:
                # Recheck under the same lock used by every socket writer. A
                # concurrent synchronous sender must not slip onto the stream
                # after another writer has observed an ambiguous sendall failure.
                if self._writer_stop.is_set() or not self.connected:
                    return False
                try:
                    _sock_sendall(self.sock, data)
                except Exception as exc:
                    # Publish failure BEFORE releasing the write lock. Otherwise
                    # a waiting synchronous sender could acquire the lock and
                    # append a new frame in the small gap before abort cleanup.
                    self.connected = False
                    self._local_transport_failure_reason = "async_writer_sendall_failed"
                    send_error = exc
            if send_error is None:
                self.last_seen = time.time()
                return True
        except Exception as exc:
            # A failure in lock/socket wrapper logic is also terminal: we cannot
            # prove whether application bytes reached the transport.
            send_error = exc
            self.connected = False
            self._local_transport_failure_reason = "async_writer_sendall_failed"

        log.warning(
            "[PeerSendFailure] ts_ns=%s session_id=%s session_id_kind=%s "
            "socket_local=%s socket_remote=%s peer=%s endpoint=%s:%s "
            "direction=%s msg_type=%s error=%s detail=%s path=writer",
            time.time_ns(), getattr(self, "session_id", "unknown"),
            getattr(self, "_session_id_kind", "unknown"),
            getattr(self, "_diag_socket_local", "?"),
            getattr(self, "_diag_socket_remote", "?"),
            str(getattr(self, "peer_id", ""))[:12],
            getattr(self, "ip", "?"), getattr(self, "port", "?"),
            "outbound" if getattr(self, "local_outbound", False) else "inbound/unknown",
            str(msg.get("type", "<missing>"))[:64], type(send_error).__name__, str(send_error)[:240],
        )
        self._abort_after_send_failure("async_writer_sendall_failed", send_error)
        return False

    def send_priority(self, msg: dict, priority: int = 1) -> bool:
        """Queue a message for the single writer, preserving priority ordering.

        A disconnected or stopped session cannot be revived by enqueuing into
        its old queue: reconnect creates a different PeerConnection object.
        The lifecycle lock makes the stop check atomic with queue insertion.
        """
        try:
            est_bytes = len(json.dumps(msg))
        except Exception as exc:
            log.warning(
                "[PeerQueueEncodeFailure] ts_ns=%s session_id=%s peer=%s "
                "endpoint=%s:%s msg_type=%s error=%s detail=%s",
                time.time_ns(), getattr(self, "session_id", "unknown"),
                str(getattr(self, "peer_id", ""))[:12], self.ip, self.port,
                str(msg.get("type", "<missing>"))[:64], type(exc).__name__, str(exc)[:200],
            )
            return False

        with self._out_seq_lock:
            self._out_seq += 1
            seq = self._out_seq

        with self._writer_lifecycle_lock:
            if self._writer_stop.is_set() or not self.connected:
                return False
            with self._out_lock:
                over_count = self._out_queue.qsize() >= self.MAX_OUT_QUEUE
                over_bytes = self._out_bytes + est_bytes > self.MAX_OUT_BYTES
                if over_count or over_bytes:
                    if priority != self.PRI_CRITICAL:
                        return False
                    # Preserve the existing critical-message overflow policy:
                    # evict the least preferred queued item and keep ordering.
                    drained = []
                    while True:
                        try:
                            drained.append(self._out_queue.get_nowait())
                        except Exception:
                            break
                    drained.sort()
                    if drained:
                        evicted = drained.pop()
                        try:
                            evicted_bytes = len(json.dumps(evicted[2]))
                        except Exception:
                            evicted_bytes = 0
                        self._out_bytes = max(0, self._out_bytes - evicted_bytes)
                    for queued in drained:
                        self._out_queue.put_nowait(queued)

                # Start while holding the lifecycle lock so a concurrent fatal
                # transport error cannot set stop and then have this path clear it.
                if not self._start_writer_locked():
                    return False
                self._out_queue.put((priority, seq, msg))
                self._out_bytes += est_bytes
                return True

    def close_writer(self):
        with self._writer_lifecycle_lock:
            if self._writer_stop.is_set():
                return
            self._writer_stop.set()
            try:
                self._out_queue.put_nowait((0, 0, None))  # wake the thread
            except Exception:
                pass

    def send(self, msg: dict) -> bool:
        # Do not let synchronous control/heartbeat paths reuse a session after
        # its writer or peer cleanup has already declared it unusable.
        if self._writer_stop.is_set() or not self.connected:
            return False
        # Encode before touching the socket. An invalid local message should not
        # disconnect a healthy peer because no bytes have been written.
        try:
            raw = json.dumps(msg).encode()
            data = CompressionEngine.compress(raw) + b"\n"
        except Exception as exc:
            log.warning(
                "[PeerEncodeFailure] ts_ns=%s session_id=%s peer=%s endpoint=%s:%s "
                "direction=%s msg_type=%s error=%s detail=%s path=sync",
                time.time_ns(), getattr(self, "session_id", "unknown"),
                str(getattr(self, "peer_id", ""))[:12], self.ip, self.port,
                "outbound" if getattr(self, "local_outbound", False) else "inbound/unknown",
                str(msg.get("type", "<missing>"))[:64], type(exc).__name__, str(exc)[:240],
            )
            return False

        send_error = None
        try:
            with self._lock:
                # The state check belongs under the stream-write lock. This
                # closes the race where another sender begins after a partial
                # sendall failure but before the failed sender marks the stream.
                if self._writer_stop.is_set() or not self.connected:
                    return False
                try:
                    _sock_sendall(self.sock, data)
                except Exception as exc:
                    self.connected = False
                    self._local_transport_failure_reason = "sync_sendall_failed"
                    send_error = exc
            if send_error is None:
                self.last_seen = time.time()
                # Logging is diagnostic-only and intentionally stays outside
                # the socket-write exception handler.
                P2PMessageLogger.log_out(self, msg, len(data))
                return True
        except Exception as exc:
            # A wrapper/socket error with uncertain write progress also makes
            # this stream unsafe for future framed messages.
            send_error = exc
            self.connected = False
            self._local_transport_failure_reason = "sync_sendall_failed"

        log.warning(
            "[PeerSendFailure] ts_ns=%s session_id=%s session_id_kind=%s "
            "socket_local=%s socket_remote=%s peer=%s endpoint=%s:%s "
            "direction=%s msg_type=%s error=%s detail=%s path=sync",
            time.time_ns(), getattr(self, "session_id", "unknown"),
            getattr(self, "_session_id_kind", "unknown"),
            getattr(self, "_diag_socket_local", "?"),
            getattr(self, "_diag_socket_remote", "?"),
            str(getattr(self, "peer_id", ""))[:12],
            getattr(self, "ip", "?"), getattr(self, "port", "?"),
            "outbound" if getattr(self, "local_outbound", False) else "inbound/unknown",
            str(msg.get("type", "<missing>"))[:64], type(send_error).__name__, str(send_error)[:240],
        )
        self._abort_after_send_failure("sync_sendall_failed", send_error)
        return False

    def recv_line(self, timeout: float = Config.PEER_TIMEOUT) -> Optional[dict]:
        # BUG-FIX v6.9.8: Use self._recv_buf (persistent across calls) instead
        # of a local buf=b"" that is thrown away after each call.  TCP is a
        # stream protocol — a single recv() during the handshake can deliver
        # two back-to-back frames (e.g. POW_CHALLENGE immediately followed by
        # VERIFY after the client sends HELLO).  The old local-buf approach
        # silently discarded everything after the first \n, causing the next
        # recv_line() call to block until timeout and then drop the connection.
        try:
            _tls_sock = _is_tls_socket(self.sock)
            if not _tls_sock:
                self.sock.settimeout(timeout)
            while b"\n" not in self._recv_buf:
                if _tls_sock:
                    chunk = tls_recv(self.sock, 4096, timeout)
                else:
                    chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                self._recv_buf += chunk
                if len(self._recv_buf) > Config.MAX_MESSAGE_SIZE:
                    self.connected = False
                    return None
            line, self._recv_buf = self._recv_buf.split(b"\n", 1)
            if not line:
                return None
            # Decompress if compressed frame (MAGIC prefix present)
            decompressed = CompressionEngine.decompress(line)
            # BUG-FIX: Update last_seen on every successful recv so that
            # _peer_decay_loop does not evict peers that are actively
            # RECEIVING data (e.g. listening nodes / non-miners).  Previously
            # last_seen was only updated in send(), so a peer that never sent
            # anything (but received blocks/txs continuously) would appear
            # "stale" to the decay loop and be evicted after PEER_DECAY_SECS,
            # immediately triggering _reconnect_loop → constant
            # ARRIVING → CONNECTED cycling visible in the dashboard.
            self.last_seen = time.time()
            return json.loads(decompressed.decode())
        except DecompressedSizeLimitError:
            # An oversized compressed handshake/control frame is terminal for
            # this session, not an ordinary read timeout.
            self.connected = False
            return None
        except Exception:
            return None
    def close(self):
        # Diagnostic-only: record the immediate local caller before closing the
        # socket. Paired-node logs can then distinguish an intentional local
        # close from a peer EOF whose initiating side had no close record.
        try:
            _caller_frame = sys._getframe(1)
            _close_caller = f"{_caller_frame.f_code.co_name}:{_caller_frame.f_lineno}"
        except Exception:
            _close_caller = "unknown"
        try:
            _fd_before = self.sock.fileno() if self.sock is not None else -1
        except Exception:
            _fd_before = -1
        log.info(
            "[PeerSocketClose] ts_ns=%s session_id=%s session_id_kind=%s "
            "socket_local=%s socket_remote=%s peer=%s endpoint=%s:%s direction=%s "
            "connected_before_close=%s fd_before=%s caller=%s thread=%s "
            "last_rx_message_type=%s last_rx_message_ts_ns=%s",
            time.time_ns(), getattr(self, "session_id", "unknown"),
            getattr(self, "_session_id_kind", "unknown"),
            getattr(self, "_diag_socket_local", "?"),
            getattr(self, "_diag_socket_remote", "?"),
            str(getattr(self, "peer_id", ""))[:12],
            getattr(self, "ip", "?"), getattr(self, "port", "?"),
            "outbound" if getattr(self, "local_outbound", False) else "inbound/unknown",
            bool(getattr(self, "connected", False)), _fd_before,
            _close_caller, threading.current_thread().name,
            getattr(self, "_last_rx_message_type", None),
            getattr(self, "_last_rx_message_ts_ns", None),
        )
        # Stop the prioritized writer thread first so a pending send doesn't
        # race with socket close.
        try:
            self.close_writer()
        except Exception:
            pass
        try:
            if self.sock:
                try:
                    self.sock._visold_peer_close_guard = True
                except Exception:
                    pass
                try:
                    self.sock.close()
                finally:
                    try:
                        self.sock._visold_peer_close_guard = False
                    except Exception:
                        pass
        except Exception:
            pass
        self.connected = False
