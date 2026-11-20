"""Section 106 V4 Regression Tests (Part 2): UDP Deduplication and Reassembler Cleanup."""

import json
import os
import sys

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.network.udp.session import UDPSession
from visold.network.udp.wire import _F_FRAG, _F_LAST, _udp_compress


class _DummyTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, pkt, addr):
        self.sent.append((pkt, addr))


def test_retransmitted_single_frag_message_deduplicated_after_ack_loss():
    """V4 Regression: Retransmitted single-fragment message is deduplicated and delivered once."""
    transport = _DummyTransport()
    sess = UDPSession(transport, ("127.0.0.1", 9999))
    try:
        msg = {"type": "TX_BROADCAST", "tx_id": "abc123"}
        payload = _udp_compress(json.dumps(msg).encode())

        sess.on_packet(_F_FRAG | _F_LAST, seq=1, frag_id=42, frag_off=0, payload=payload)
        delivered_1 = sess.inbound.get(timeout=1.0)
        assert delivered_1 == msg
        assert 42 not in sess._reassemblers

        sess.on_packet(_F_FRAG | _F_LAST, seq=1, frag_id=42, frag_off=0, payload=payload)
        assert sess.inbound.empty()
    finally:
        sess.close()


def test_retransmitted_last_frag_of_multifrag_does_not_create_orphan_reassembler():
    """V4 Regression: Retransmitted final fragment of a completed message does not create an orphan reassembler."""
    transport = _DummyTransport()
    sess = UDPSession(transport, ("127.0.0.1", 9999))
    try:
        msg = {"type": "BLOCK", "data": "x" * 2000}
        raw = json.dumps(msg).encode()
        mid = len(raw) // 2

        sess.on_packet(_F_FRAG, seq=10, frag_id=7, frag_off=0, payload=raw[:mid])
        sess.on_packet(_F_FRAG | _F_LAST, seq=11, frag_id=7, frag_off=1, payload=raw[mid:])
        assert sess.inbound.get(timeout=1.0) == msg
        assert 7 not in sess._reassemblers

        sess.on_packet(_F_FRAG | _F_LAST, seq=11, frag_id=7, frag_off=1, payload=raw[mid:])
        assert 7 not in sess._reassemblers
    finally:
        sess.close()
