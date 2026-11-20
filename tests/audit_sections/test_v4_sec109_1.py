import os
import sys
import tempfile
import threading
from collections import defaultdict
from types import SimpleNamespace
from unittest.mock import MagicMock

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.kernel.lru_cache import LRUCache
from visold.network.p2p import MSG_CAPABILITY_ADV, P2PNetwork
from visold.network.reputation import PeerReputationManager
from visold.storage.storage import Storage


def _make_minimal_p2p(storage):
    p2p = P2PNetwork.__new__(P2PNetwork)
    p2p.storage = storage
    p2p.node_id = "node_self_109"
    p2p.peers = {}
    p2p._lock = threading.RLock()
    p2p._msg_rate = {}
    p2p._msg_rate_lock = threading.Lock()
    p2p._seen_msgs = LRUCache(1024, ttl=3600)
    p2p._eager_peers = set()
    p2p._untrusted_rate = {}
    p2p._untrusted_rate_lock = threading.Lock()
    p2p._callbacks = defaultdict(list)
    p2p._reputation_mgr = None
    p2p._capability_router = MagicMock()
    return p2p


def test_check_msg_rate_hard_breach_penalizes_ban_score():
    """
    V4 Regression: P2PNetwork._check_msg_rate() records attempts and applies
    ban_score penalties when a peer exceeds >2x the per-type or global quota.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "visold.db")
        storage = Storage(db_path=db_path)
        try:
            peer_id = "attacker_peer_rate_flood"
            storage.save_peer(peer_id, "198.51.100.10", 8333)
            p2p = _make_minimal_p2p(storage)
            peer = SimpleNamespace(peer_id=peer_id, trust_level="TRUST_LEVEL_HIGH")

            pertype_limit = p2p._MSG_RATE_PERTYPE["GET_PEERS"]
            allowed = sum(
                1 for _ in range(pertype_limit * 10)
                if p2p._check_msg_rate(peer, "GET_PEERS")
            )
            assert allowed == pertype_limit
            assert storage.get_ban_score(peer_id) > 0

            peer_id_2 = "attacker_peer_global_flood"
            storage.save_peer(peer_id_2, "198.51.100.11", 8333)
            peer2 = SimpleNamespace(peer_id=peer_id_2, trust_level="TRUST_LEVEL_HIGH")
            for _ in range(p2p._MSG_RATE_GLOBAL * 3):
                p2p._check_msg_rate(peer2, "PING")
            assert storage.get_ban_score(peer_id_2) > 0
        finally:
            storage.close()


def test_reputation_manager_adjust_preserves_persisted_score_on_restart():
    """
    V4 Regression: PeerReputationManager._adjust() loads persisted SQLite score on
    cache miss so record_uptime() after restart does not clobber high reputation.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "visold.db")
        storage = Storage(db_path=db_path)
        try:
            peer_id = "good_peer_001"
            mgr1 = PeerReputationManager(storage)
            for _ in range(50):
                mgr1.record_fast_block(peer_id)
            mgr1._maybe_persist(force=True)
            high_score = mgr1.get_score(peer_id)
            assert high_score > 0.90

            mgr2 = PeerReputationManager(storage)
            mgr2.record_uptime(peer_id)
            mgr2._maybe_persist(force=True)

            mgr3 = PeerReputationManager(storage)
            reloaded_score = mgr3.get_score(peer_id)
            assert reloaded_score >= high_score
        finally:
            storage.close()


def test_handle_message_capability_adv_safe_when_reputation_mgr_is_none():
    """
    V4 Regression: _handle_message() for MSG_CAPABILITY_ADV safely handles
    _reputation_mgr is None without raising AttributeError.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "visold.db")
        storage = Storage(db_path=db_path)
        try:
            p2p = _make_minimal_p2p(storage)
            assert p2p._reputation_mgr is None
            peer = SimpleNamespace(
                peer_id="peer_cap_001",
                trust_level="TRUST_LEVEL_HIGH",
                last_seen=0.0,
            )
            msg = {"type": MSG_CAPABILITY_ADV, "capabilities": ["archive"]}
            p2p._handle_message(peer, msg)
            p2p._capability_router.handle_adv.assert_called_once_with("peer_cap_001", ["archive"])
        finally:
            storage.close()
