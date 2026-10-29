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
"""visold.network.udp.session


Defines: UDPSession
Origin: visold_vsd_.py L2197-2426
"""

import json
import queue
import threading
import time
from typing import TYPE_CHECKING

from visold.network.udp.reliability import _UDPReassembler, _UDPWindow
from visold.network.udp.wire import (
    _F_ACK,
    _F_FEC,
    _F_FRAG,
    _F_HB,
    _F_LAST,
    _F_NACK,
    _UDP_FEC_GROUP,
    _UDP_FRAG_MAX,
    _UDP_FRAG_MAX_PER_GROUP,
    _UDP_HB_INTERVAL,
    _UDP_HB_TIMEOUT,
    _UDP_PAYLOAD_MAX,
    _UDP_RTO_MIN,
    _UDP_WINDOW_SLEEP,
    _udp_decompress,
    _udp_pack,
    _xor_bytes,
)

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.network.udp.transport import UDPTransport


# ─────────────────────────────────────────────────────────────────────────────
class UDPSession:
    """
    Per-peer UDP session state.

    Responsibilities:
      • Outbound sequence number allocation.
      • Sending fragmented + FEC-protected messages.
      • Maintaining the sliding window (_UDPWindow).
      • Tracking inbound fragment groups (_UDPReassembler).
      • Heartbeat management.
      • Delivering fully-reassembled messages to the inbound queue.
    """

    def __init__(self, transport: 'UDPTransport', addr: tuple):
        self._transport    = transport        # reference to owning UDPTransport
        self.addr          = addr             # (ip, port) of remote peer
        self._seq          = 0               # next outbound sequence number
        self._seq_lock     = threading.Lock()
        self._frag_counter = 0               # frag_id counter
        self._frag_lock    = threading.Lock()
        self._window       = _UDPWindow()
        # inbound reassembly: frag_id → _UDPReassembler
        self._reassemblers: dict = {}
        self._rassem_lock  = threading.Lock()
        # inbound message queue (decoded dicts)
        self.inbound: queue.Queue = queue.Queue(maxsize=2048)
        # heartbeat
        self._last_hb_sent  = time.monotonic()
        # Liveness uses every inbound packet, but topology-prune completion
        # must distinguish actual heartbeat frames from control/data packets
        # (notably TOPOLOGY_PRUNE_FINALIZE, which also refreshes _last_hb_recv).
        self._last_hb_recv  = time.monotonic()   # any inbound packet; session liveness
        self._last_hb_packet_recv = self._last_hb_recv  # only _F_HB frames
        self._liveness_lock = threading.Lock()
        self._liveness_expired = False
        # retransmit background thread (one per session, daemon)
        self._rtx_stop      = threading.Event()
        self._rtx_thread    = threading.Thread(
            target=self._retransmit_loop, daemon=True,
            name=f'udp-rtx-{addr[0]}:{addr[1]}')
        self._rtx_thread.start()

    # ── Sequence / fragment ID allocation ────────────────────────────────
    def _next_seq(self) -> int:
        with self._seq_lock:
            s = self._seq
            self._seq = (self._seq + 1) & 0xFFFFFFFF
            return s

    def _next_frag_id(self) -> int:
        with self._frag_lock:
            f = self._frag_counter
            self._frag_counter = (self._frag_counter + 1) & 0xFFFF
            return f

    # ── Send helpers ──────────────────────────────────────────────────────
    def _raw_sendto(self, pkt: bytes):
        """Send one raw UDP packet.  Silently swallows transient OS errors."""
        try:
            # Route through UDPTransport when available so socket recovery cannot
            # race sends. The fallback preserves compatibility with lightweight
            # transport doubles used by integrations and tests.
            sendto = getattr(self._transport, "sendto", None)
            if callable(sendto):
                sendto(pkt, self.addr)
            else:
                self._transport._sock.sendto(pkt, self.addr)
        except OSError:
            pass

    def send_ack(self, seq: int):
        pkt = _udp_pack(_F_ACK, seq, 0, 0, b'')
        self._raw_sendto(pkt)

    def send_nack(self, seq: int):
        pkt = _udp_pack(_F_NACK, seq, 0, 0, b'')
        self._raw_sendto(pkt)

    def send_heartbeat(self):
        seq = self._next_seq()
        pkt = _udp_pack(_F_HB | _F_LAST, seq, 0, 0, b'')
        self._raw_sendto(pkt)
        self._last_hb_sent = time.monotonic()

    def send_message(self, data: bytes):
        """
        Fragment *data* into MTU-sized chunks, add a FEC parity symbol every
        _UDP_FEC_GROUP fragments, and send them through the sliding window.

        This is the sole egress path for all P2P messages over UDP.
        """
        frag_id  = self._next_frag_id()
        chunks   = [data[i:i + _UDP_PAYLOAD_MAX]
                    for i in range(0, max(len(data), 1), _UDP_PAYLOAD_MAX)]
        n_frags  = len(chunks)
        if n_frags > _UDP_FRAG_MAX_PER_GROUP:
            raise ValueError(
                f"UDP message requires {n_frags} fragments; maximum is "
                f"{_UDP_FRAG_MAX_PER_GROUP}")
        fec_acc  = b''           # running XOR accumulator for FEC group
        fec_grp  = 0             # count within current FEC group

        for off, chunk in enumerate(chunks):
            is_last = (off == n_frags - 1)
            flags   = _F_FRAG | (_F_LAST if is_last else 0)

            # --- Sliding window back-pressure ---
            # Block until there is room in the window.  This is the
            # rate-limiter: a fast sender is throttled here instead of
            # flooding the receiver's UDP buffer.
            while self._window.is_full():
                time.sleep(_UDP_WINDOW_SLEEP)

            seq = self._next_seq()
            pkt = _udp_pack(flags, seq, frag_id, off, chunk)
            self._window.add(seq, pkt)
            self._raw_sendto(pkt)

            # XOR accumulate for FEC
            fec_acc = _xor_bytes(fec_acc, chunk)
            fec_grp += 1

            # Emit FEC symbol at end of each group OR at the last fragment
            if fec_grp == _UDP_FEC_GROUP or is_last:
                fec_seq = self._next_seq()
                fec_pkt = _udp_pack(_F_FEC | _F_LAST, fec_seq, frag_id, off, fec_acc)
                self._raw_sendto(fec_pkt)
                fec_acc = b''
                fec_grp = 0

    # ── Inbound packet dispatcher ─────────────────────────────────────────
    def on_packet(self, flags: int, seq: int, frag_id: int,
                  frag_off: int, payload: bytes):
        """
        Called by UDPTransport._recv_loop for every packet destined for this
        session.  Updates general session activity unconditionally and records
        real heartbeat frames separately, then dispatches by flag.
        """
        with self._liveness_lock:
            # GC may have atomically expired this session immediately before a
            # late packet arrived. Do not revive a session already detached from
            # the transport; the next packet will create/find a fresh session.
            if self._liveness_expired:
                return
            now = time.monotonic()
            self._last_hb_recv = now
            if flags & _F_HB:
                self._last_hb_packet_recv = now

        # ── Control packets ───────────────────────────────────────────────
        if flags & _F_ACK:
            self._window.on_ack(seq)
            return

        if flags & _F_NACK:
            pkt = self._window.on_nack(seq)
            if pkt:
                self._raw_sendto(pkt)
            return

        if flags & _F_HB:
            # Heartbeat — always ACK so the sender knows we are alive
            self.send_ack(seq)
            return

        # ── Data / FEC ────────────────────────────────────────────────────
        # A fragment that cannot be represented by this receiver must not be
        # ACKed: ACK would make the sender drop its retransmit copy and turn the
        # receiver-side rejection into silent permanent message loss (BUG-42).
        if frag_off < 0 or frag_off >= _UDP_FRAG_MAX_PER_GROUP:
            return

        if flags & _F_FEC:
            self._handle_fec(frag_id, frag_off, payload)
            self.send_ack(seq)
            return

        is_last = bool(flags & _F_LAST)
        r = self._get_or_create_reassembler(frag_id)
        if r.last_off is not None and frag_off > r.last_off:
            return
        if frag_off not in r.frags:
            if not r.add_data(frag_off, is_last, payload):
                return
        # Duplicates are ACKed so ordinary retransmission can terminate.
        self.send_ack(seq)
        self._try_deliver(frag_id, r)

    def _get_or_create_reassembler(self, frag_id: int) -> '_UDPReassembler':
        with self._rassem_lock:
            if frag_id not in self._reassemblers:
                # Evict oldest if too many in-flight groups (safety cap)
                if len(self._reassemblers) >= _UDP_FRAG_MAX:
                    oldest = min(self._reassemblers,
                                 key=lambda k: self._reassemblers[k].ts)
                    del self._reassemblers[oldest]
                self._reassemblers[frag_id] = _UDPReassembler(frag_id)
            return self._reassemblers[frag_id]

    def _handle_data(self, frag_id: int, frag_off: int,
                     is_last: bool, payload: bytes):
        r = self._get_or_create_reassembler(frag_id)
        r.add_data(frag_off, is_last, payload)
        self._try_deliver(frag_id, r)

    def _handle_fec(self, frag_id: int, frag_off: int, payload: bytes):
        r = self._get_or_create_reassembler(frag_id)
        r.add_fec(payload, frag_off)
        if not r.complete():
            r.try_fec_recover()
        self._try_deliver(frag_id, r)

    def _try_deliver(self, frag_id: int, r: '_UDPReassembler'):
        """If reassembly is complete, decode the message and enqueue it."""
        if not r.complete():
            return
        raw = r.reassemble()
        with self._rassem_lock:
            self._reassemblers.pop(frag_id, None)
        try:
            decompressed = _udp_decompress(raw)
            msg = json.loads(decompressed.decode())
            self.inbound.put_nowait(msg)
        except Exception:
            pass   # malformed or oversized — silently drop

    # ── Retransmit background loop ────────────────────────────────────────
    def _retransmit_loop(self):
        """
        Runs in a daemon thread.  Periodically:
          1. Retransmits any un-ACKed packets whose RTO has expired.
          2. Sends a heartbeat when idle.
          3. Evicts stale reassembly groups.
        """
        while not self._rtx_stop.is_set():
            time.sleep(_UDP_RTO_MIN)
            try:
                # Retransmit expired in-flight packets
                for seq, pkt, retries in self._window.expired_seqs():
                    self._raw_sendto(pkt)

                # Heartbeat
                now = time.monotonic()
                if now - self._last_hb_sent >= _UDP_HB_INTERVAL:
                    self.send_heartbeat()

                # Evict stale reassembly groups
                with self._rassem_lock:
                    stale = [fid for fid, r in self._reassemblers.items()
                             if r.is_expired()]
                    for fid in stale:
                        del self._reassemblers[fid]
            except Exception:
                pass

    # ── Session teardown ──────────────────────────────────────────────────
    def close(self):
        with self._liveness_lock:
            self._liveness_expired = True
        self._rtx_stop.set()
        self._window.clear()
        # Unblock any waiting recv
        try:
            self.inbound.put_nowait(None)
        except Exception:
            pass

    def expire_if_silent(self, now=None) -> bool:
        """Atomically mark this session expired only if its heartbeat is stale.

        Synchronizing this check with ``on_packet`` prevents the GC thread from
        deciding a session is dead just before an inbound heartbeat refreshes it.
        Once marked expired, a late packet cannot revive a detached session.
        """
        if now is None:
            now = time.monotonic()
        with self._liveness_lock:
            if self._liveness_expired:
                return True
            if now - self._last_hb_recv >= _UDP_HB_TIMEOUT:
                self._liveness_expired = True
                return True
            return False

    def is_alive(self) -> bool:
        """False if closed or silent for longer than _UDP_HB_TIMEOUT."""
        with self._liveness_lock:
            return (not self._liveness_expired and
                    (time.monotonic() - self._last_hb_recv) < _UDP_HB_TIMEOUT)
