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

import json
import socket
import threading
import time
from typing import Any, List, Optional

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.network.compression import CompressionEngine
from visold.network.message_logger import P2PMessageLogger


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
        self.reputation  = reputation
        self.fail_count  = 0
        self.last_seen   = time.time()
        self.connected   = sock is not None
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

        # ── v7.6.0 Peer chain-height & capability cache ──────────────────────
        # Populated from MSG_HELLO, MSG_ACCEPT, and MSG_BLOCK / MSG_CMPCTBLOCK.
        # MiningSafetyGuard's best_peer_height_fn reads this to decide whether
        # the local node is sufficiently synced to start mining.  -1 means
        # "unknown" (peer hasn't told us yet); the safety guard treats that
        # as not-behind so a brand-new connection cannot deadlock mining.
        self.chain_height: int           = -1
        self.capabilities: List[str]     = []

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
        self._writer_thread: Optional[threading.Thread] = None
        self._writer_stop  = threading.Event()
        if self.connected:
            self._start_writer()

    def _start_writer(self):
        if self._writer_thread and self._writer_thread.is_alive():
            return
        self._writer_stop.clear()
        t = threading.Thread(target=self._writer_loop,
                             name=f"peer-writer-{self.peer_id[:8]}",
                             daemon=True)
        self._writer_thread = t
        t.start()

    def _writer_loop(self):
        """Drain the priority queue and push to the socket.
        A single blocked sendall on this thread does NOT block other peers
        because each peer has its own writer thread + queue.

        v7.1.8 BUG-FIX (Bug 1): the loop condition used to be
            while not self._writer_stop.is_set() and self.connected:
        but ``self.connected`` is flipped to False inside ``_raw_send`` on
        ANY transient sendall exception (broken pipe, EAGAIN, slow peer
        backpressure, transient ECONNRESET).  The next iteration the while
        evaluated False and the writer thread DIED SILENTLY.

        The reconnect machinery normally builds a NEW PeerConnection object
        on reconnect rather than flipping ``.connected`` back to True on the
        same instance, so the dead writer was never resurrected — every
        subsequent send_priority() enqueued into a queue with no draining
        thread.  ``broadcast_block`` logged "broadcast to N peers" but the
        bytes never left the box.

        Fix:
          • Loop condition is now ``self._writer_stop`` ONLY.
          • On _raw_send failure, the message is re-queued (priority
            preserved) and we sleep briefly before retrying, giving the
            socket a chance to recover.  After MAX_SEND_RETRIES consecutive
            failures we drop the message (peer is genuinely dead) but the
            thread keeps draining so subsequent enqueues don't pile up.
          • The thread only exits when _writer_stop is explicitly set
            (close_writer / close).
        """
        MAX_SEND_RETRIES = 3
        consecutive_failures = 0
        while not self._writer_stop.is_set():
            try:
                item = self._out_queue.get(timeout=1.0)
            except Exception:
                continue
            if item is None:
                break
            pri, _seq, msg = item
            if msg is None:                       # poison pill from close_writer
                break
            # Maintain the byte-counter accounting symmetrically with enqueue.
            try:
                _est = len(json.dumps(msg)) if msg is not None else 0
            except Exception:
                _est = 0
            with self._out_lock:
                self._out_bytes = max(0, self._out_bytes - _est)
            ok = self._raw_send(msg)
            if ok:
                consecutive_failures = 0
                continue
            # ── Send failed.  Decide: retry or drop. ─────────────────────
            consecutive_failures += 1
            if consecutive_failures >= MAX_SEND_RETRIES:
                log.warning(
                    f"[WRITER {self.peer_id[:8]}] dropping {msg.get('type','?')} "
                    f"after {consecutive_failures} consecutive send failures")
                consecutive_failures = 0          # reset counter, keep draining
                continue
            # Re-queue at the same priority and back off briefly.  Keeps
            # block / consensus messages first in line on socket recovery.
            try:
                with self._out_seq_lock:
                    self._out_seq += 1
                    new_seq = self._out_seq
                self._out_queue.put((pri, new_seq, msg))
                with self._out_lock:
                    self._out_bytes += _est
            except Exception:
                pass
            time.sleep(0.2 * consecutive_failures)
        log.debug(
            f"[WRITER {self.peer_id[:8]}] exit "
            f"stop={self._writer_stop.is_set()} connected={self.connected}")

    def _raw_send(self, msg: dict) -> bool:
        try:
            raw  = json.dumps(msg).encode()
            data = CompressionEngine.compress(raw) + b"\n"
            with self._lock:
                self.sock.sendall(data)
            self.last_seen = time.time()
            return True
        except Exception:
            # v7.1.8 BUG-FIX (Bug 1): we still flip ``connected`` so other
            # paths (heartbeat, reconnect loop) notice the broken socket,
            # but ``_writer_loop`` no longer uses this flag as a kill
            # switch — it keeps draining and retries the message above.
            self.connected = False
            return False

    def send_priority(self, msg: dict, priority: int = 1) -> bool:
        """Enqueue ``msg`` for asynchronous send with the given priority.
        CRITICAL (0) > NORMAL (1) > BULK (2).  Returns True if queued, False
        on overflow (and in that case the lowest-priority pending msg is
        evicted so the new critical message still goes through).

        v7.1.8 BUG-FIX (Bug 1): even if ``self.connected`` is momentarily
        False (transient send error mid-broadcast), we still allow the
        message to be QUEUED — the writer thread will retry it once the
        socket recovers, or the reconnect loop will rebuild the connection
        and the new PeerConnection will take over.  Refusing to queue here
        was the second half of the silent-broadcast-loss bug.
        """
        if self._writer_stop.is_set():
            return False                          # peer is being torn down
        if self._writer_thread is None or not self._writer_thread.is_alive():
            self._start_writer()
        try:
            est_bytes = len(json.dumps(msg))
        except Exception:
            est_bytes = 0
        with self._out_seq_lock:
            self._out_seq += 1
            seq = self._out_seq
        # Overflow policy: for CRITICAL, always admit by dropping a BULK/NORMAL.
        # Check both queue length AND byte cap.
        with self._out_lock:
            over_count = self._out_queue.qsize() >= self.MAX_OUT_QUEUE
            over_bytes = self._out_bytes + est_bytes > self.MAX_OUT_BYTES
        if over_count or over_bytes:
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

    def close_writer(self):
        self._writer_stop.set()
        try: self._out_queue.put_nowait((0, 0, None))      # wake the thread
        except Exception: pass

    def send(self, msg: dict) -> bool:
        try:
            # BUG-FIX v6.9.8: Compress only the bare JSON bytes — NOT the
            # trailing \n.  Compressed binary payloads routinely contain the
            # byte 0x0a (\n) internally; if \n is inside the compressed blob
            # then recv_line's buf.split(b"\n", 1) splits mid-frame, producing
            # a truncated/corrupt slice that fails decompression and JSON parse.
            # Appending \n AFTER compression guarantees the delimiter is always
            # the very last byte of the wire frame.
            raw  = json.dumps(msg).encode()   # pure JSON, no trailing \n
            data = CompressionEngine.compress(raw)
            data = data + b"\n"               # frame delimiter AFTER compression
            with self._lock:
                self.sock.sendall(data)
            self.last_seen = time.time()
            # v7.1.7: outbound P2P message logging (no-op unless enabled).
            P2PMessageLogger.log_out(self, msg, len(data))
            return True
        except Exception:
            self.connected = False
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
            self.sock.settimeout(timeout)
            while b"\n" not in self._recv_buf:
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
        except Exception:
            return None
    def close(self):
        # Stop the prioritized writer thread first so a pending send doesn't
        # race with socket close.
        try:
            self.close_writer()
        except Exception:
            pass
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.connected = False
