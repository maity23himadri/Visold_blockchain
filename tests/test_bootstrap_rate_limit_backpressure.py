from collections import defaultdict, deque
import threading
import time

from visold.kernel.messages import MSG_CHAIN, MSG_GET_CHAIN
from visold.network.p2p import P2PNetwork


class _FakeChain:
    def height(self):
        return 1256


class _FakePeer:
    def __init__(self):
        self.peer_id = "peer-rate-limit-test"
        self.sent = []

    def send(self, msg):
        self.sent.append(msg)


def _network_with_full_get_chain_bucket(now):
    net = P2PNetwork.__new__(P2PNetwork)
    net._msg_rate_lock = threading.Lock()
    net._msg_rate = {
        "peer-rate-limit-test": {
            "global": deque([now] * 5),
            "types": defaultdict(deque, {"GET_CHAIN": deque([now] * 5)}),
        }
    }
    net.blockchain = _FakeChain()
    net._local_chain_tip_hash = lambda: "tip-hash"
    return net


def test_rate_limited_get_chain_gets_correlated_busy_reply(monkeypatch):
    now = time.time()
    net = _network_with_full_get_chain_bucket(now)
    peer = _FakePeer()

    net._handle_message(peer, {
        "type": MSG_GET_CHAIN,
        "from_idx": 1000,
        "to_idx": 1199,
        "request_id": "bootsnap-test-6",
    })

    assert len(peer.sent) == 1
    reply = peer.sent[0]
    assert reply["type"] == MSG_CHAIN
    assert reply["busy"] is True
    assert reply["reason"] == "rate_limited"
    assert reply["request_id"] == "bootsnap-test-6"
    assert reply["blocks"] == []
    # Five accepted requests just filled a 10-second bucket. The response must
    # tell the requester to wait for the bucket to reopen instead of timing out.
    assert 9000 <= reply["retry_after_ms"] <= 11000


def test_retry_after_shrinks_with_existing_bucket_age():
    now = time.time()
    net = _network_with_full_get_chain_bucket(now - 7.5)
    peer = _FakePeer()
    delay = net._rate_limit_retry_after_ms(peer, MSG_GET_CHAIN)
    assert 2400 <= delay <= 2800
