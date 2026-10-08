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
"""visold.network.udp.reliability


Origin: visold_vsd_.py L1986-2076, L2080-2193
"""

import threading
import time
from typing import Optional

from visold.network.udp.wire import (
    _UDP_CWND_INIT,
    _UDP_CWND_MAX,
    _UDP_FEC_GROUP,
    _UDP_FEC_MAX_SYMBOLS,
    _UDP_FRAG_MAX_PER_GROUP,
    _UDP_PAYLOAD_MAX,
    _UDP_FRAG_TTL,
    _UDP_MAX_RETRIES,
    _UDP_RTO_INIT,
    _UDP_RTO_MAX,
    _UDP_RTO_MIN,
    _xor_bytes,
)


# ─────────────────────────────────────────────────────────────────────────────
class _UDPWindow:
    """
    Sliding-window send buffer with retransmission and RTT-adaptive RTO.

    Each entry in the window is:
        seq → (payload_bytes, send_time, retries, flags, frag_id, frag_off)

    ACKs advance the window; NACKs trigger immediate retransmit of the
    indicated seq and halve the cwnd.  On each ACK the cwnd grows by 1
    (additive increase).
    """
    def __init__(self):
        self._lock    = threading.Lock()
        self._inflight: dict = {}         # seq → (pkt_bytes, ts, retries)
        self.cwnd     = _UDP_CWND_INIT
        self.rto      = _UDP_RTO_INIT
        self._srtt    = None              # smoothed RTT (seconds)
        self._rttvar  = None

    # ── RTT / RTO updates (RFC 6298) ─────────────────────────────────────
    def _update_rtt(self, rtt: float):
        if self._srtt is None:
            self._srtt   = rtt
            self._rttvar = rtt / 2.0
        else:
            alpha = 0.125
            beta  = 0.25
            self._rttvar = (1 - beta)  * self._rttvar + beta  * abs(self._srtt - rtt)
            self._srtt   = (1 - alpha) * self._srtt   + alpha * rtt
        self.rto = max(_UDP_RTO_MIN,
                       min(_UDP_RTO_MAX, self._srtt + 4 * self._rttvar))

    # ── Window management ─────────────────────────────────────────────────
    def is_full(self) -> bool:
        with self._lock:
            return len(self._inflight) >= self.cwnd

    def add(self, seq: int, pkt_bytes: bytes):
        """Record a newly sent packet in the window."""
        with self._lock:
            self._inflight[seq] = (pkt_bytes, time.monotonic(), 0)

    def on_ack(self, seq: int):
        """Process an incoming ACK.  Advances window and updates RTT."""
        with self._lock:
            entry = self._inflight.pop(seq, None)
            if entry:
                rtt = time.monotonic() - entry[1]
                self._update_rtt(rtt)
                # Additive increase
                self.cwnd = min(_UDP_CWND_MAX, self.cwnd + 1)

    def on_nack(self, seq: int) -> Optional[bytes]:
        """
        Process a NACK (retransmit request).
        Returns the raw packet to retransmit, or None if unknown/expired.
        """
        with self._lock:
            entry = self._inflight.get(seq)
            if entry is None:
                return None
            pkt_bytes, ts, retries = entry
            retries += 1
            if retries > _UDP_MAX_RETRIES:
                self._inflight.pop(seq, None)
                return None
            self._inflight[seq] = (pkt_bytes, time.monotonic(), retries)
            # Multiplicative decrease on NACK
            self.cwnd = max(1, self.cwnd // 2)
            return pkt_bytes

    def expired_seqs(self):
        """
        Return list of (seq, pkt_bytes, retries) for packets whose RTO has
        elapsed — caller should retransmit them.
        """
        now   = time.monotonic()
        expired = []
        with self._lock:
            for seq, (pkt, ts, retries) in list(self._inflight.items()):
                if now - ts >= self.rto:
                    if retries >= _UDP_MAX_RETRIES:
                        self._inflight.pop(seq, None)
                    else:
                        self._inflight[seq] = (pkt, now, retries + 1)
                        expired.append((seq, pkt, retries + 1))
        return expired

    def clear(self):
        with self._lock:
            self._inflight.clear()


# ─────────────────────────────────────────────────────────────────────────────
class _UDPReassembler:
    """
    Fragment reassembly for one (peer_addr, frag_id) group.

    A message is split into fragments 0..N-1.  The last fragment carries
    _F_LAST.  When all data fragments are present the message is yielded.
    If a FEC symbol is received and exactly one data fragment is missing it
    is reconstructed immediately without a retransmit request.
    """
    def __init__(self, frag_id: int):
        self.frag_id   = frag_id
        self.frags: dict = {}    # frag_off → payload bytes
        # AUDIT-FIX-22: FEC symbols are per-group, not per-message — the
        # sender (send_message) emits one XOR symbol every _UDP_FEC_GROUP
        # fragments, not a single symbol covering the whole message.
        # Keyed by the group's starting frag_off; value is
        # (group_end_off, xor_bytes).
        self.fec_syms: dict = {}
        self.last_off: Optional[int]  = None    # frag_off of the fragment with _F_LAST
        self.ts        = time.monotonic()

    def add_data(self, frag_off: int, is_last: bool, payload: bytes) -> bool:
        """Return True if this fragment was new.

        FIX-1: Enforce two hard bounds to prevent memory exhaustion:
          1. frag_off must be within [0, _UDP_FRAG_MAX_PER_GROUP).  An attacker
             sending frag_off=2^16-1 on the first packet would make complete()
             wait for 65535 fragments that never arrive while holding a large
             last_off sentinel.
          2. len(frags) must stay below _UDP_FRAG_MAX_PER_GROUP.  Without this
             cap, sending an endless stream of unique frag_off values (none
             marked _F_LAST) grows the dict indefinitely within the TTL window.
        Both conditions return False (drop); the session is not torn down.
        """
        if frag_off < 0 or frag_off >= _UDP_FRAG_MAX_PER_GROUP:
            return False   # out-of-bounds offset — drop silently
        if frag_off in self.frags:
            return False
        if len(self.frags) >= _UDP_FRAG_MAX_PER_GROUP:
            return False   # group size cap exceeded — drop silently
        self.frags[frag_off] = payload
        if is_last:
            self.last_off = frag_off
        return True

    def add_fec(self, payload: bytes, group_end_off: int) -> bool:
        """Record a bounded FEC repair symbol.

        FEC metadata is untrusted network input just like data fragments.
        Keep it inside the same fragment-offset and payload bounds enforced
        for normal reassembly, and cap the number of distinct symbols that a
        single reassembler can retain.
        """
        # The sender emits the offset of the last data fragment covered by the
        # symbol.  Only offsets representable by an allowed data reassembly
        # group are valid here.
        if group_end_off < 0 or group_end_off >= _UDP_FRAG_MAX_PER_GROUP:
            return False
        if len(payload) > _UDP_PAYLOAD_MAX:
            return False

        group_start = (group_end_off // _UDP_FEC_GROUP) * _UDP_FEC_GROUP
        if group_end_off - group_start >= _UDP_FEC_GROUP:
            return False

        # Re-sending a symbol for the same group is harmless and replaces the
        # existing value without increasing memory usage.  A new group is only
        # accepted while the derived maximum number of symbols remains.
        if group_start not in self.fec_syms and len(self.fec_syms) >= _UDP_FEC_MAX_SYMBOLS:
            return False
        self.fec_syms[group_start] = (group_end_off, payload)
        return True

    def complete(self) -> bool:
        """True if all fragments have been received."""
        if self.last_off is None:
            return False
        return len(self.frags) == self.last_off + 1

    def try_fec_recover(self) -> bool:
        """
        If exactly one fragment is missing overall, and it falls inside a
        FEC group we hold a symbol for, recover it via XOR against that
        group's other fragments only.

        AUDIT-FIX-22: this previously XORed the most-recently-received FEC
        symbol against every fragment held for the WHOLE message. Since
        each FEC symbol only covers its own _UDP_FEC_GROUP-sized slice,
        that produced a corrupted "recovered" fragment for any message
        spanning more than one group (i.e. any message over
        _UDP_FEC_GROUP * _UDP_PAYLOAD_MAX bytes) — the corrupted bytes
        would then fail to decode and the whole message was silently
        dropped with no retransmit ever requested. Recovery must be
        scoped to the missing fragment's own group.
        """
        if self.last_off is None or not self.fec_syms:
            return False
        expected = set(range(self.last_off + 1))
        missing  = expected - set(self.frags.keys())
        if len(missing) != 1:
            return False
        (miss_off,) = missing

        group_start = (miss_off // _UDP_FEC_GROUP) * _UDP_FEC_GROUP
        entry = self.fec_syms.get(group_start)
        if entry is None:
            return False   # haven't received this group's FEC symbol yet
        group_end, fec_sym = entry

        # XOR the group's FEC symbol against every OTHER fragment in that
        # same group only — never fragments from a different group.
        acc = fec_sym
        for off in range(group_start, group_end + 1):
            if off == miss_off:
                continue
            frag = self.frags.get(off)
            if frag is None:
                return False   # group member missing too — can't recover safely
            acc = _xor_bytes(acc, frag)
        self.frags[miss_off] = acc.rstrip(b'\x00') if miss_off == self.last_off else acc
        return True

    def reassemble(self) -> bytes:
        """Concatenate fragments in order and return the full message bytes."""
        if self.last_off is None:
            return b''
        return b''.join(self.frags[i] for i in range(self.last_off + 1))

    def is_expired(self) -> bool:
        return time.monotonic() - self.ts > _UDP_FRAG_TTL
