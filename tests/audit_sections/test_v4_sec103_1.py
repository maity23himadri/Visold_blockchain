import hashlib
import os
import sys
import threading
from collections import defaultdict
from types import SimpleNamespace

os.environ.setdefault("VISOLD_STORAGE", "sqlite")

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.kernel.lru_cache import LRUCache
from visold.network.capabilities import CapabilityRouter, MSG_CAPABILITY_ADV
from visold.network.kademlia import KBucket, KademliaRouter
from visold.network.p2p import P2PNetwork
from visold.storage.storage import Storage


def _peer_id_for_bucket(router: KademliaRouter, desired_bucket: int, seed_start: int = 0):
    """Find a 64-char sha256 peer_id that maps to desired_bucket in router."""
    i = seed_start
    while True:
        pid = hashlib.sha256(f"node-{desired_bucket}-{i}".encode()).hexdigest()
        if router._bucket_idx(pid) == desired_bucket:
            return pid, i + 1
        i += 1


def test_kademlia_get_closest_no_duplicates_and_includes_neighbors():
    """
    V4 Regression: KademliaRouter.get_closest() visits offset=0 once, returning
    unique peer dicts and including peers from neighboring buckets.
    """
    local_id = hashlib.sha256(b"local-node").hexdigest()
    router = KademliaRouter(local_id)

    target_id = hashlib.sha256(b"target-key").hexdigest()
    primary_idx = router._bucket_idx(target_id)
    neighbor_idx = primary_idx - 1 if primary_idx > 0 else primary_idx + 1

    seed = 0
    primary_pids = []
    for j in range(10):
        pid, seed = _peer_id_for_bucket(router, primary_idx, seed)
        primary_pids.append(pid)
        router.update(pid, {"peer_id": pid, "ip": f"10.{j}.1.1", "port": 8338})

    neighbor_pids = []
    for j in range(10):
        pid, seed = _peer_id_for_bucket(router, neighbor_idx, seed)
        neighbor_pids.append(pid)
        router.update(pid, {"peer_id": pid, "ip": f"11.{j}.1.1", "port": 8338})

    closest = router.get_closest(target_id, k=20)
    returned_pids = [p["peer_id"] for p in closest]

    assert len(closest) == 20
    assert len(set(returned_pids)) == 20
    assert all(returned_pids.count(pid) == 1 for pid in primary_pids)
    assert all(pid in returned_pids for pid in neighbor_pids)


def test_kbucket_ipv6_subnet_diversity_enforced_across_noncanonical_forms():
    """
    V4 Regression: KBucket._subnet() canonicalizes IPv6 addresses to /48 via
    ipaddress.IPv6Address, enforcing MAX_NODES_PER_SUBNET (4).
    """
    bucket = KBucket(k=20)
    assert bucket.MAX_NODES_PER_SUBNET == 4

    same_48_ips = [
        "2001:db8::1",
        "2001:0db8::2",
        "2001:db8:0:1::3",
        "2001:0db8:0:2::4",
        "2001:db8:0000:3::5",
        "2001:0db8:0000:4::6",
        "2001:DB8:0:5::7",
        "2001:db8:0:6::8",
    ]

    for idx, ip in enumerate(same_48_ips):
        pid = hashlib.sha256(f"sybil-{idx}".encode()).hexdigest()
        bucket.add(pid, {"peer_id": pid, "ip": ip, "port": 8338})

    assert len(bucket.nodes) == bucket.MAX_NODES_PER_SUBNET


def test_capability_router_cleans_index_and_db_on_update_and_disconnect(tmp_path):
    """
    V4 Regression: CapabilityRouter.record_peer_capabilities() removes dropped
    capabilities from _cap_index and SQLite, and remove_peer() leaves no leaks.
    """
    storage = Storage(str(tmp_path / "visold_cap.db"))
    cap_router = CapabilityRouter(storage)

    peer_id = hashlib.sha256(b"peer-A").hexdigest()
    cap_router.record_peer_capabilities(peer_id, ["archive", "vvm"])
    assert peer_id in cap_router.find_peers_with("archive")
    assert peer_id in cap_router.find_peers_with("vvm")

    cap_router.record_peer_capabilities(peer_id, ["full_node"])
    assert peer_id not in cap_router.find_peers_with("archive")
    assert peer_id not in cap_router.find_peers_with("vvm")

    cap_router.remove_peer(peer_id)
    assert peer_id not in cap_router.find_peers_with("full_node")
    assert peer_id not in cap_router.find_peers_with("archive")
    assert peer_id not in cap_router.find_peers_with("vvm")


def test_capability_adv_validates_payload_and_ignores_invalid_types(tmp_path):
    """
    V4 Regression: P2PNetwork._handle_message() for MSG_CAPABILITY_ADV validates
    that capabilities is a list/set/tuple of strings without crashing or splitting strings.
    """
    storage = Storage(str(tmp_path / "visold_adv.db"))
    cap_router = CapabilityRouter(storage)

    net = P2PNetwork.__new__(P2PNetwork)
    net._lock = threading.Lock()
    net._capability_router = cap_router
    net._msg_rate_lock = threading.Lock()
    net._msg_rate = {}
    net._seen_lock = threading.Lock()
    net._seen_msgs = LRUCache(100)
    net._callbacks = defaultdict(list)

    peer = SimpleNamespace(
        peer_id=hashlib.sha256(b"peer-B").hexdigest(),
        ip="127.0.0.1",
        port=8338,
        connected=True,
    )

    net._handle_message(peer, {"type": MSG_CAPABILITY_ADV, "capabilities": "archive"})
    for ch in "archive":
        assert peer.peer_id not in cap_router.find_peers_with(ch)

    net._handle_message(peer, {"type": MSG_CAPABILITY_ADV, "capabilities": [{"bad": 1}]})
    assert cap_router._peer_caps.get(peer.peer_id, set()) == set()
