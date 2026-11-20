import os
import socket
import sys
import threading
from collections import defaultdict

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.kernel.config import Config
from visold.kernel.lru_cache import LRUCache
from visold.network.capabilities import MSG_CAPABILITY_ADV, CapabilityRouter
from visold.network.p2p import P2PNetwork
from visold.network.peer_connection import PeerConnection
from visold.network.reputation import PeerReputationManager
from visold.storage.storage import Storage


def _make_minimal_p2p(storage: Storage) -> P2PNetwork:
    """Create a minimal P2PNetwork instance backed by real Storage."""
    net = P2PNetwork.__new__(P2PNetwork)
    net.storage = storage
    net.node_id = "0" * 64
    net.port = 18333
    net._running = False
    net._lock = threading.RLock()
    net.peers = {}
    net._eager_peers = set()
    net._peer_admission_reservations = {}
    net._topology_lock = threading.Lock()
    net._topology_prune_cooldowns = {}
    net._pending_lock = threading.Lock()
    net._pending_connections = set()
    net._pending_peer_ids = set()
    net._outbound_fail_lock = threading.Lock()
    net._outbound_fail = {}
    net._callbacks = defaultdict(list)
    net._check_msg_rate = lambda *a, **kw: True
    net._seen_msgs = LRUCache(100)
    net._seen_lock = threading.Lock()
    net._reputation_mgr = None
    net._capability_router = CapabilityRouter(storage)

    class _DummyRouter:
        def update(self, *args, **kwargs):
            pass

    class _DummyBlockchain:
        def height(self):
            return 0

    class _DummyWallet:
        pub_hex = "02" + "11" * 32
        address = "VSDtest"

    net.router = _DummyRouter()
    net.blockchain = _DummyBlockchain()
    net.wallet = _DummyWallet()
    net._remember_node_info = lambda *a, **kw: None
    net._sync_request = lambda *a, **kw: None
    net._local_chain_tip_hash = lambda: "0" * 64
    return net


def test_add_ban_score_preserves_already_blacklisted_peer(tmp_path):
    """
    V4 Regression: Storage.add_ban_score() preserves blacklisted=1 when a
    blacklisted peer receives an infraction smaller than PEER_BAN_SCORE_THRESHOLD.
    """
    db_path = tmp_path / "ban_score.db"
    storage = Storage(str(db_path))
    peer_id = "a" * 64
    storage.save_peer(peer_id, "203.0.113.10", 8333)

    # Case A: Peer blacklisted via blacklist_peer()
    storage.blacklist_peer(peer_id)
    row_before = storage._conn().execute(
        "SELECT blacklisted, ban_score FROM peers WHERE peer_id=?", (peer_id,)
    ).fetchone()
    assert row_before["blacklisted"] == 1
    assert row_before["ban_score"] == 0

    new_score = storage.add_ban_score(peer_id, Config.PEER_SCORE_INVALID_MSG)
    assert new_score == Config.PEER_SCORE_INVALID_MSG
    row_after = storage._conn().execute(
        "SELECT blacklisted, ban_score FROM peers WHERE peer_id=?", (peer_id,)
    ).fetchone()
    assert row_after["blacklisted"] == 1

    # Case B: Peer auto-banned via add_ban_score >= threshold, then decayed
    storage.add_ban_score(peer_id, Config.PEER_BAN_SCORE_THRESHOLD)
    assert storage._conn().execute(
        "SELECT blacklisted FROM peers WHERE peer_id=?", (peer_id,)
    ).fetchone()["blacklisted"] == 1

    for _ in range(4):
        storage.decay_ban_scores()
    decayed = storage._conn().execute(
        "SELECT blacklisted, ban_score FROM peers WHERE peer_id=?", (peer_id,)
    ).fetchone()
    assert decayed["blacklisted"] == 1
    assert decayed["ban_score"] < Config.PEER_BAN_SCORE_THRESHOLD

    storage.add_ban_score(peer_id, 1)
    assert storage._conn().execute(
        "SELECT blacklisted FROM peers WHERE peer_id=?", (peer_id,)
    ).fetchone()["blacklisted"] == 1


def test_soft_ban_logic_hash_ban_written_and_enforced(tmp_path):
    """
    V4 Regression: PeerConnection exposes logic_hash and _soft_ban_record_failure()
    writes logic_hash_ban:<hash> at strike 3, which _is_logic_hash_banned() enforces.
    """
    db_path = tmp_path / "logic_hash_ban.db"
    storage = Storage(str(db_path))
    net = _make_minimal_p2p(storage)

    s1, s2 = socket.socketpair()
    try:
        peer = PeerConnection("b" * 64, "203.0.113.20", 8333, s1,
                              trust_level=PeerConnection.TRUST_LOW)
        assert hasattr(peer, "logic_hash")
        peer_lh = "ab" * 32
        peer.logic_hash = peer_lh
        storage.save_peer(peer.peer_id, peer.ip, peer.port)

        net._soft_ban_record_failure(peer, "MSG_TX")
        net._soft_ban_record_failure(peer, "MSG_TX")
        net._soft_ban_record_failure(peer, "MSG_TX")

        assert net._is_ip_banned("203.0.113.20") is True
        assert net._is_logic_hash_banned(peer_lh) is True
        rows = storage._conn().execute(
            "SELECT key FROM node_meta WHERE key LIKE 'logic_hash_ban:%'"
        ).fetchall()
        assert len(rows) == 1
    finally:
        s1.close()
        s2.close()


def test_blacklisted_peer_rejected_on_inbound_and_register_peer(tmp_path):
    """
    V4 Regression: Blacklisted peer_ids are rejected by _reserve_peer_admission()
    and _register_peer(), not just outbound _try_add_peer().
    """
    db_path = tmp_path / "inbound_blacklist.db"
    storage = Storage(str(db_path))
    net = _make_minimal_p2p(storage)

    bad_peer_id = "c" * 64
    storage.save_peer(bad_peer_id, "203.0.113.30", 8333)
    storage.add_ban_score(bad_peer_id, Config.PEER_BAN_SCORE_THRESHOLD)
    assert storage._conn().execute(
        "SELECT blacklisted FROM peers WHERE peer_id=?", (bad_peer_id,)
    ).fetchone()["blacklisted"] == 1

    assert net._try_add_peer("203.0.113.31", 8333, bad_peer_id) is False

    s1, s2 = socket.socketpair()
    try:
        token = net._reserve_peer_admission(
            bad_peer_id, "203.0.113.31", local_outbound=False
        )
        assert token is None

        peer = PeerConnection(bad_peer_id, "203.0.113.31", 8333, s1)
        net._register_peer(
            peer, bad_peer_id, "02" + "22" * 32, "",
            admission_token=None, local_outbound=False,
        )
        assert bad_peer_id not in net.peers
        peer.close()
    finally:
        s1.close()
        s2.close()


def test_reputation_manager_adjust_preserves_persisted_score_on_cache_miss(tmp_path):
    """
    V4 Regression: PeerReputationManager._adjust() loads persisted scores from
    SQLite on cache miss instead of resetting to NEUTRAL (0.5).
    """
    db_path = tmp_path / "reputation.db"
    storage = Storage(str(db_path))
    mgr1 = PeerReputationManager(storage)

    for _ in range(25):
        mgr1.record_fast_block("peer_good")
    high_score = mgr1.get_score("peer_good")
    assert high_score > 0.85
    mgr1._maybe_persist(force=True)

    mgr2 = PeerReputationManager(storage)
    assert "peer_good" not in mgr2._cache

    mgr2.record_uptime("peer_good")
    mgr2._maybe_persist(force=True)

    assert mgr2.get_score("peer_good") >= high_score
    row = storage._conn().execute(
        "SELECT score FROM reputation_extended WHERE peer_id=?", ("peer_good",)
    ).fetchone()
    assert float(row["score"]) >= high_score


def test_handle_message_capability_adv_safe_when_reputation_mgr_is_none(tmp_path):
    """
    V4 Regression: _handle_message() for MSG_CAPABILITY_ADV safely handles
    _reputation_mgr is None without raising AttributeError.
    """
    db_path = tmp_path / "cap_adv.db"
    storage = Storage(str(db_path))
    net = _make_minimal_p2p(storage)
    assert net._reputation_mgr is None

    s1, s2 = socket.socketpair()
    try:
        peer = PeerConnection("d" * 64, "203.0.113.40", 8333, s1)
        net._handle_message(
            peer, {"type": MSG_CAPABILITY_ADV, "capabilities": ["archive"]}
        )
        assert peer.peer_id in net._capability_router.find_peers_with("archive")
        peer.close()
    finally:
        s1.close()
        s2.close()
