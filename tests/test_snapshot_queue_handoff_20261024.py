import queue
import threading
from types import SimpleNamespace

from visold.network.p2p import P2PNetwork, MSG_GET_SNAPSHOT_MANIFEST, MSG_SNAPSHOT_MANIFEST


class DummyPeer:
    def __init__(self):
        self.peer_id = "peer-old-version-1400"
        self.connected = True
        self._sync_state_lock = threading.RLock()
        self._snap_response_queue = None

    def send(self, msg):
        if msg.get("type") == MSG_GET_SNAPSHOT_MANIFEST:
            self._snap_response_queue.put({
                "type": MSG_SNAPSHOT_MANIFEST,
                "manifest": [{
                    "height": 1200,
                    "state_root": "state",
                    "size": 1,
                    "anchor_block_hash": "anchor",
                    "bootstrap_digest": "digest",
                }],
            })


class DummyBlockchain:
    def __init__(self):
        self._snapshot_engine = object()

    def height(self):
        return 0


def make_net():
    net = P2PNetwork.__new__(P2PNetwork)
    net.blockchain = DummyBlockchain()
    return net


def test_snapshot_queue_claim_and_identity_safe_release():
    net = make_net()
    peer = DummyPeer()
    q1 = queue.Queue()
    q2 = queue.Queue()

    assert net._claim_snapshot_response_queue(peer, q1) is True
    assert net._claim_snapshot_response_queue(peer, q2) is False
    assert peer._snap_response_queue is q1

    # An old owner must not be able to clear a newer/current owner.
    assert net._release_snapshot_response_queue(peer, q2) is False
    assert peer._snap_response_queue is q1
    assert net._release_snapshot_response_queue(peer, q1) is True
    assert peer._snap_response_queue is None


def test_legacy_fast_sync_cleanup_does_not_clobber_recovery_queue():
    """Reproduce the 600-height handoff race seen with an old 1400-height peer.

    The authenticated bootstrap finishes snapshot traffic, releases its queue,
    and a pruned-history recovery immediately claims a new queue before the
    legacy caller unwinds. Legacy cleanup must leave that newer queue intact.
    """
    net = make_net()
    peer = DummyPeer()
    recovery_q = queue.Queue()

    def fake_authenticated_bootstrap(peer_arg, manifest, resp_q, snapshot_timeout=60, **kwargs):
        assert peer_arg is peer
        assert peer._snap_response_queue is resp_q
        assert net._release_snapshot_response_queue(peer, resp_q) is True
        assert net._claim_snapshot_response_queue(peer, recovery_q) is True
        return True

    net._authenticated_bootstrap_from_manifest = fake_authenticated_bootstrap

    assert net._fast_sync_legacy(peer) is True
    # Regression assertion: the historical delayed/unconditional cleanup set
    # this to None ~5 seconds later, killing the recovery response route.
    assert peer._snap_response_queue is recovery_q
