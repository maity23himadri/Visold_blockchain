"""Unit/regression tests for the tree-inspired adaptive peer topology policy."""
from __future__ import annotations

import hashlib
import time

from visold.crypto.ecc import ecdsa_keygen, ecdsa_sign, pub_to_hex, sig_to_hex
from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork
from visold.network.topology_policy import (
    choose_redundant_edge,
    list_redundant_edges,
    rank_topology_candidates,
    topology_component_digest,
    topology_component_view_diagnostic,
    topology_prune_initiator,
    topology_signing_bytes,
    verify_topology_report,
)


def _signed_report(neighbors, issued_at=None, seq=1):
    priv, pub = ecdsa_keygen()
    pub_hex = pub_to_hex(pub)
    node_id = hashlib.sha256(pub_hex.encode("ascii")).hexdigest()
    neighbors = sorted(neighbors)
    report = {
        "version": 1,
        "node_id": node_id,
        "pub_hex": pub_hex,
        "neighbors": neighbors,
        "degree": len(neighbors),
        "complete": True,
        "seed": False,
        "issued_at": int(time.time() if issued_at is None else issued_at),
        "seq": seq,
    }
    report["sig"] = sig_to_hex(ecdsa_sign(
        priv, hashlib.sha256(topology_signing_bytes(report)).digest()))
    return report


def test_topology_report_signature_binds_identity_and_adjacency():
    report = _signed_report(["node-b", "node-c"])
    assert verify_topology_report(report)

    tampered = dict(report)
    tampered["neighbors"] = ["node-z"]
    assert not verify_topology_report(tampered)
    tampered_seed = dict(report)
    tampered_seed["seed"] = True
    assert not verify_topology_report(tampered_seed)


def test_ranker_prefers_lower_degree_then_round_robins_ties():
    now = time.time()
    reports = {
        "a": {"degree": 2, "issued_at": now},
        "b": {"degree": 2, "issued_at": now},
        "c": {"degree": 1, "issued_at": now},
    }
    candidates = [
        {"peer_id": "a", "ip": "192.0.2.1", "port": 8338},
        {"peer_id": "b", "ip": "192.0.2.2", "port": 8338},
        {"peer_id": "c", "ip": "192.0.2.3", "port": 8338},
    ]
    first = rank_topology_candidates(candidates, reports, cursor=0, now=now)
    second = rank_topology_candidates(candidates, reports, cursor=1, now=now)
    assert [x["peer_id"] for x in first] == ["c", "a", "b"]
    assert [x["peer_id"] for x in second] == ["c", "b", "a"]


def test_pruner_selects_only_an_over_target_non_bridge_edge():
    now = time.time()
    graph = {
        "a": ["b", "c", "d"],
        "b": ["a", "c", "d"],
        "c": ["a", "b", "d"],
        "d": ["a", "b", "c"],
    }
    reports = {
        node_id: {
            "neighbors": sorted(neighbors),
            "degree": len(neighbors),
            "complete": True,
            "issued_at": now,
        }
        for node_id, neighbors in graph.items()
    }
    edge = choose_redundant_edge(
        reports, local_node_id="a", now=now, ttl_seconds=180, target_degree=2)
    assert edge is not None
    assert edge[0] < edge[1]

    # Once all nodes are at/below target, policy has no reason to prune.
    for report in reports.values():
        report["degree"] = 2
        report["neighbors"] = report["neighbors"][:2]
    # The truncated map is asymmetric/incomplete too, so fail-closed is expected.
    assert choose_redundant_edge(
        reports, local_node_id="a", now=now, ttl_seconds=180, target_degree=2) is None


def test_incomplete_or_stale_topology_never_authorizes_pruning():
    now = time.time()
    reports = {
        "a": {"neighbors": ["b", "c", "d"], "degree": 3,
              "complete": True, "issued_at": now},
        "b": {"neighbors": ["a", "c", "d"], "degree": 3,
              "complete": True, "issued_at": now},
        "c": {"neighbors": ["a", "b", "d"], "degree": 3,
              "complete": True, "issued_at": now},
        "d": {"neighbors": ["a", "b", "c"], "degree": 3,
              "complete": True, "issued_at": now - 1000},
    }
    assert choose_redundant_edge(
        reports, local_node_id="a", now=now, ttl_seconds=180, target_degree=2) is None


def test_topology_target_is_separate_and_does_not_rewrite_min_max(monkeypatch):
    original_min = Config.MIN_PEERS
    original_max = Config.MAX_PEERS
    monkeypatch.setattr(Config, "TOPOLOGY_POLICY_ENABLED", True, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_TARGET_PEERS", 3, raising=False)
    monkeypatch.setattr(Config, "SEED_NODE_MODE", False, raising=False)
    network = object.__new__(P2PNetwork)
    assert network._desired_peer_target() == 3
    assert network._below_minimum_peer_target(2) is True
    assert network._below_minimum_peer_target(3) is False
    assert Config.MIN_PEERS == original_min
    assert Config.MAX_PEERS == original_max


def test_local_adjacency_report_is_signed_and_paged():
    import threading
    from types import SimpleNamespace

    from visold.network.p2p import P2PNetwork

    priv, pub = ecdsa_keygen()
    pub_hex = pub_to_hex(pub)
    node_id = hashlib.sha256(pub_hex.encode("ascii")).hexdigest()
    network = object.__new__(P2PNetwork)
    network.node_id = node_id
    network.wallet = SimpleNamespace(priv=priv, pub_hex=pub_hex)
    network._lock = threading.RLock()
    network.peers = {}

    # With no direct peers, the report must say degree 0 and a complete view.
    report = network._local_topology_report()
    assert report["degree"] == 0
    assert report["neighbors"] == []
    assert report["complete"] is True
    assert verify_topology_report(report)

    page, total, next_cursor = network._topology_report_page(cursor=0, limit=8)
    assert total == 1
    assert next_cursor is None
    assert len(page) == 1
    assert page[0]["node_id"] == node_id
    assert "_observed_stable_since" not in page[0]


def test_designated_seed_keeps_existing_unbounded_discovery_semantics(monkeypatch):
    network = object.__new__(P2PNetwork)
    monkeypatch.setattr(Config, "TOPOLOGY_POLICY_ENABLED", True, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_TARGET_PEERS", 3, raising=False)
    monkeypatch.setattr(Config, "SEED_NODE_MODE", True, raising=False)
    monkeypatch.setattr(Config, "SEED_MIN_PEERS", None, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_SEED_PRUNING_ENABLED", False, raising=False)
    monkeypatch.setattr(Config, "MAX_PEERS", 30, raising=False)
    assert network._desired_peer_target() is None
    assert network._peer_capacity_limit() is None

    # The designated seed can opt in explicitly after bootstrap failover testing.
    monkeypatch.setattr(Config, "TOPOLOGY_SEED_PRUNING_ENABLED", True, raising=False)
    assert network._desired_peer_target() == 3
    assert network._peer_capacity_limit() is None


def test_component_digest_changes_when_adjacency_changes():
    from visold.network.topology_policy import topology_component_digest

    now = time.time()
    graph = {
        "a": ["b", "c", "d"],
        "b": ["a", "c", "d"],
        "c": ["a", "b", "d"],
        "d": ["a", "b", "c"],
    }
    reports = {
        node_id: {"neighbors": sorted(neighbors), "degree": len(neighbors),
                  "complete": True, "issued_at": now}
        for node_id, neighbors in graph.items()
    }
    first = topology_component_digest(reports, local_node_id="a", now=now)
    assert first
    reports["a"]["neighbors"] = ["b", "c"]
    reports["a"]["degree"] = 2
    second = topology_component_digest(reports, local_node_id="a", now=now)
    # The a-d claim is asymmetric, so it is ignored. The remaining reciprocal
    # graph is still connected and has a distinct digest.
    assert second is not None
    assert second != first


def test_seed_edge_is_pruned_by_ordinary_endpoint_not_designated_seed():
    reports = {
        "a-seed": {"seed": True},
        "z-client": {"seed": False},
        "m-other": {"seed": False},
    }
    assert topology_prune_initiator(("a-seed", "z-client"), reports) == "z-client"
    assert topology_prune_initiator(("m-other", "z-client"), reports) == "m-other"
    assert topology_prune_initiator(("a-seed", "m-other"), {
        "a-seed": {"seed": True}, "m-other": {"seed": True}
    }) is None


def test_seed_can_ack_client_initiated_seed_edge_prune_without_changing_role(monkeypatch):
    from types import SimpleNamespace

    network = object.__new__(P2PNetwork)
    network.node_id = "z-seed"
    monkeypatch.setattr(Config, "TOPOLOGY_POLICY_ENABLED", True, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_TARGET_PEERS", 3, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_SEED_PRUNING_ENABLED", False, raising=False)
    monkeypatch.setattr(Config, "SEED_NODE_MODE", True, raising=False)
    monkeypatch.setattr(Config, "SEED_MIN_PEERS", None, raising=False)
    network._topology_prune_preconditions_detail = lambda peer_id, target, expected_view_hash="": (
        {"edge": (peer_id, network.node_id), "view_hash": expected_view_hash}, "ok")
    sent = []
    peer = SimpleNamespace(peer_id="a-client", connected=True, send=lambda msg: sent.append(msg) or True)
    network._handle_topology_prune_proposal(peer, {
        "prune_protocol": 2,
        "nonce": "a" * 32,
        "edge": ["a-client", "z-seed"],
        "view_hash": "b" * 64,
        "target_degree": 3,
        "issued_at": int(time.time()),
    })
    assert sent and sent[0]["type"] == "TOPOLOGY_PRUNE_ACK"
    assert sent[0]["allow"] is True
    assert network._desired_peer_target() is None  # ACK does not alter seed discovery role


def test_prune_ack_ignores_wrong_peer_and_wrong_view_hash():
    import threading
    from types import SimpleNamespace

    network = object.__new__(P2PNetwork)
    network._ensure_topology_state()
    event = threading.Event()
    network._topology_pending_prunes["c" * 32] = {
        "peer_id": "peer-right", "view_hash": "d" * 64, "event": event, "allow": False
    }
    network._handle_topology_prune_ack(SimpleNamespace(peer_id="peer-wrong"), {
        "nonce": "c" * 32, "view_hash": "d" * 64, "allow": True
    })
    assert not event.is_set()
    network._handle_topology_prune_ack(SimpleNamespace(peer_id="peer-right"), {
        "nonce": "c" * 32, "view_hash": "e" * 64, "allow": True
    })
    assert not event.is_set()
    network._handle_topology_prune_ack(SimpleNamespace(peer_id="peer-right"), {
        "nonce": "c" * 32, "view_hash": "d" * 64, "allow": True
    })
    assert event.is_set()
    assert network._topology_pending_prunes["c" * 32]["allow"] is True


def test_seed_ack_accepts_sorted_edge_when_seed_id_is_lower(monkeypatch):
    from types import SimpleNamespace

    network = object.__new__(P2PNetwork)
    network.node_id = "a-seed"
    monkeypatch.setattr(Config, "TOPOLOGY_POLICY_ENABLED", True, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_TARGET_PEERS", 3, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_SEED_PRUNING_ENABLED", False, raising=False)
    monkeypatch.setattr(Config, "SEED_NODE_MODE", True, raising=False)
    monkeypatch.setattr(Config, "SEED_MIN_PEERS", None, raising=False)
    network._topology_prune_preconditions_detail = lambda peer_id, target, expected_view_hash="": (
        {"edge": (network.node_id, peer_id), "view_hash": expected_view_hash}, "ok")
    sent = []
    peer = SimpleNamespace(peer_id="z-client", connected=True, send=lambda msg: sent.append(msg) or True)
    network._handle_topology_prune_proposal(peer, {
        "prune_protocol": 2,
        "nonce": "f" * 32,
        "edge": ["a-seed", "z-client"],
        "view_hash": "e" * 64,
        "target_degree": 3,
        "issued_at": int(time.time()),
    })
    assert sent and sent[0]["allow"] is True


def test_seven_node_join_example_prunes_only_redundant_seed_edge():
    from visold.network.topology_policy import topology_prune_initiator

    now = time.time()
    graph = {
        "1": ["2", "3", "4", "7"],
        "2": ["1", "4", "7"],
        "3": ["1", "5", "6"],
        "4": ["1", "2"],
        "5": ["3", "6", "7"],
        "6": ["3", "5", "7"],
        "7": ["1", "2", "5", "6"],
    }
    reports = {
        node_id: {
            "neighbors": sorted(neighbors),
            "degree": len(neighbors),
            "complete": True,
            "seed": node_id == "1",
            "issued_at": now,
        }
        for node_id, neighbors in graph.items()
    }
    edge = choose_redundant_edge(
        reports, local_node_id="7", now=now, ttl_seconds=180, target_degree=3)
    assert edge == ("1", "7")
    assert topology_prune_initiator(edge, reports) == "7"

    # Removing the temporary seed edge leaves every node reachable, while
    # node 1 and node 7 both settle at degree three.
    reduced = {node_id: set(neighbors) for node_id, neighbors in graph.items()}
    reduced["1"].remove("7")
    reduced["7"].remove("1")
    visited = set()
    stack = ["1"]
    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)
        stack.extend(reduced[current] - visited)
    assert visited == set(graph)
    assert len(reduced["1"]) == 3
    assert len(reduced["7"]) == 3



def test_unrelated_partial_component_does_not_block_local_topology_view():
    now = time.time()
    reports = {
        "a": {"neighbors": ["b", "c"], "degree": 2, "complete": True, "issued_at": now},
        "b": {"neighbors": ["a", "c"], "degree": 2, "complete": True, "issued_at": now},
        "c": {"neighbors": ["a", "b"], "degree": 2, "complete": True, "issued_at": now},
        # A fresh-but-unrelated report advertises a neighbor missing from this
        # cache. It must not veto pruning in a-b-c's fully known component.
        "x": {"neighbors": ["missing-y"], "degree": 1, "complete": True, "issued_at": now},
    }
    view, reason = topology_component_view_diagnostic(
        reports, local_node_id="a", now=now, ttl_seconds=180)
    assert reason == "ok"
    assert view is not None
    assert view[2] == {"a", "b", "c"}


def test_topology_view_diagnostic_reports_reachable_missing_neighbor():
    now = time.time()
    reports = {
        "a": {"neighbors": ["b", "c"], "degree": 2, "complete": True, "issued_at": now},
        "b": {"neighbors": ["a", "c"], "degree": 2, "complete": True, "issued_at": now},
        "c": {"neighbors": ["a", "b", "d"], "degree": 3, "complete": True, "issued_at": now},
    }
    view, reason = topology_component_view_diagnostic(
        reports, local_node_id="a", now=now, ttl_seconds=180)
    assert view is None
    assert reason == "missing_report:d"


def test_redundant_edge_list_is_deterministic_and_choose_returns_first():
    now = time.time()
    graph = {node: [other for other in "abcde" if other != node]
             for node in "abcde"}
    reports = {
        node: {"neighbors": sorted(neighbors), "degree": len(neighbors),
               "complete": True, "issued_at": now}
        for node, neighbors in graph.items()
    }
    edges = list_redundant_edges(
        reports, local_node_id="a", now=now, ttl_seconds=180, target_degree=3)
    assert len(edges) == 10
    assert edges == list_redundant_edges(
        reports, local_node_id="e", now=now, ttl_seconds=180, target_degree=3)
    assert choose_redundant_edge(
        reports, local_node_id="a", now=now, ttl_seconds=180, target_degree=3) == edges[0]


def test_prune_tries_next_locally_initiated_edge_when_preferred_is_not_ready(monkeypatch):
    import threading
    from types import SimpleNamespace

    now_wall = time.time()
    now_mono = time.monotonic()
    ids = list("abcdef")
    graph = {node: [other for other in ids if other != node] for node in ids}
    reports = {
        node: {"neighbors": sorted(neighbors), "degree": len(neighbors),
               "complete": True, "seed": False, "issued_at": now_wall,
               "_observed_stable_since": now_mono - 600}
        for node, neighbors in graph.items()
    }
    edges = list_redundant_edges(
        reports, local_node_id="a", now=now_wall, ttl_seconds=180, target_degree=3)
    preferred = edges[0]
    local_id = topology_prune_initiator(preferred, reports)
    assert local_id in preferred
    eligible_local = [edge for edge in edges if local_id in edge
                      and topology_prune_initiator(edge, reports) == local_id]
    assert len(eligible_local) >= 2
    skipped_edge, fallback_edge = eligible_local[:2]

    network = object.__new__(P2PNetwork)
    network.node_id = local_id
    network._lock = threading.RLock()
    network._topology_lock = threading.RLock()
    network._topology_reports = {k: dict(v) for k, v in reports.items()}
    network._topology_seq = 0
    network._topology_rr_cursor = 0
    network._topology_last_rebalance_at = 0.0
    network._topology_pending_prunes = {}
    network._eager_peers = set()
    network.peers = {}
    network._is_seed_node_mode = lambda: False
    network._desired_peer_target = lambda: 3
    network._local_topology_report = lambda: reports[local_id]
    monkeypatch.setattr(Config, "TOPOLOGY_POLICY_ENABLED", True, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_SEED_PRUNING_ENABLED", False, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_TARGET_PEERS", 3, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_REPORT_TTL_SECONDS", 180, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_STABLE_SECONDS", 120, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_REBALANCE_INTERVAL", 60, raising=False)
    monkeypatch.setattr(Config, "TOPOLOGY_PRUNE_CANDIDATES_PER_PASS", 3, raising=False)

    local_peers = {}
    close_calls = []
    for peer_id in graph[local_id]:
        peer = SimpleNamespace(peer_id=peer_id, connected=True,
                               _topology_connected_since=now_mono - 600,
                               close=lambda peer_id=peer_id: close_calls.append(peer_id))
        local_peers[peer_id] = peer
    network.peers = dict(local_peers)

    view_hash = topology_component_digest(
        reports, local_node_id=local_id, now=now_wall, ttl_seconds=180)
    attempts = []

    def detailed_preconditions(peer_id, target, expected_view_hash=""):
        edge = tuple(sorted((local_id, peer_id)))
        attempts.append(edge)
        if edge == skipped_edge:
            return None, "connection_not_stable"
        peer = local_peers[peer_id]
        return {"edge": edge, "view_hash": view_hash, "peer": peer,
                "reports": reports}, "ok"

    network._topology_prune_preconditions_detail = detailed_preconditions

    def send_ack(peer_obj, message):
        nonce = message["nonce"]
        kind = message.get("type")
        if kind == "TOPOLOGY_PRUNE_PROPOSE":
            pending = network._topology_pending_prunes[nonce]
            pending["allow"] = True
            pending["event"].set()
        elif kind == "TOPOLOGY_PRUNE_COMMIT":
            pending = network._topology_pending_commits[nonce]
            pending["event"].set()
        elif kind == "TOPOLOGY_PRUNE_FINALIZE":
            pending = network._topology_pending_finalizes[nonce]
            pending["event"].set()
        return True

    fallback_peer_id = fallback_edge[1] if fallback_edge[0] == local_id else fallback_edge[0]
    local_peers[fallback_peer_id].send = lambda message: send_ack(local_peers[fallback_peer_id], message)
    assert network._maybe_prune_topology_edge() is True
    assert attempts[0] == skipped_edge
    assert fallback_edge in attempts
    assert fallback_peer_id not in network.peers
    assert close_calls == [fallback_peer_id]


def test_asymmetric_edge_is_quarantined_but_reciprocal_component_can_prune():
    """A one-sided claim must not veto a safe prune on verified mutual edges."""
    now = time.time()
    graph = {
        "a": ["b", "c", "d", "e"],  # claims a-e
        "b": ["a", "c", "d", "e"],
        "c": ["a", "b", "d", "e"],
        "d": ["a", "b", "c", "e"],
        "e": ["b", "c", "d"],       # does not reciprocate a-e
    }
    reports = {
        node: {"neighbors": sorted(neighbors), "degree": len(neighbors),
               "complete": True, "issued_at": now}
        for node, neighbors in graph.items()
    }
    view, reason = topology_component_view_diagnostic(
        reports, local_node_id="a", now=now, ttl_seconds=180)
    assert view is not None
    assert reason.startswith("ok_ignored_asymmetric_edges:1:")
    fresh, adjacency, component = view
    digest_from_a = topology_component_digest(
        reports, local_node_id="a", now=now, ttl_seconds=180)
    digest_from_e = topology_component_digest(
        reports, local_node_id="e", now=now, ttl_seconds=180)
    assert digest_from_a == digest_from_e
    assert component == set(graph)
    assert "e" not in adjacency["a"]
    assert "a" not in adjacency["e"]
    # a-e cannot be used as an edge, but safe reciprocal candidates among
    # b/c/d remain available in the verified graph.
    edges = list_redundant_edges(
        reports, local_node_id="a", now=now, ttl_seconds=180, target_degree=3)
    assert edges
    for left, right in edges:
        assert right in adjacency[left] and left in adjacency[right]
        assert len(adjacency[left] & component) > 3
        assert len(adjacency[right] & component) > 3



def test_remote_prune_is_not_removed_until_commit_and_finalize_are_received(monkeypatch):
    """The receiving node must explicitly participate in bilateral edge removal."""
    import threading
    from types import SimpleNamespace

    network = object.__new__(P2PNetwork)
    network.node_id = "node-41"
    network._lock = threading.RLock()
    network._eager_peers = set()
    network.peers = {}
    network._ensure_topology_state()
    nonce = "1" * 32
    view_hash = "2" * 64
    messages = []
    peer = SimpleNamespace(peer_id="node-38", connected=True, last_seen=time.time(),
                           send=lambda message: messages.append(message) or True,
                           close=lambda: setattr(peer, "connected", False))
    network.peers[peer.peer_id] = peer
    state = {
        "peer_id": peer.peer_id, "peer": peer, "view_hash": view_hash,
        "edge": ["node-38", "node-41"], "phase": "prepared",
        "expires_at": time.monotonic() + 20.0,
        "finalize_generation": 0, "expiry_timer": None,
    }
    network._topology_remote_prunes[nonce] = state
    cooldowns = []
    network._mark_topology_prune_cooldown = lambda peer_id: cooldowns.append(peer_id)
    removed = []

    def fake_finalize(peer_obj, reason="topology_prune"):
        peer_obj.connected = False
        peer_obj.close()
        with network._lock:
            if network.peers.get(peer_obj.peer_id) is peer_obj:
                network.peers.pop(peer_obj.peer_id, None)
            network._eager_peers.discard(peer_obj.peer_id)
        removed.append((peer_obj.peer_id, reason))

    network._finalize_topology_pruned_peer = fake_finalize

    network._handle_topology_prune_commit(peer, {
        "nonce": nonce, "view_hash": view_hash,
    })
    assert messages[-1]["type"] == "TOPOLOGY_PRUNE_COMMIT_ACK"
    assert peer.peer_id in network.peers
    assert state["phase"] == "committed"

    network._handle_topology_prune_finalize(peer, {
        "nonce": nonce, "view_hash": view_hash,
    })
    assert messages[-1]["type"] == "TOPOLOGY_PRUNE_FINALIZE_ACK"
    assert peer.peer_id in network.peers  # kept alive so ACK delivery can finish
    assert state["phase"] == "finalizing"
    assert cooldowns == [peer.peer_id]

    timer = state["finalize_timer"]
    timer.cancel()
    network._finish_remote_topology_prune(
        nonce, state, state["finalize_generation"])
    assert peer.peer_id not in network.peers
    assert removed == [(peer.peer_id, "remote_topology_prune")]


def test_pruned_peer_identity_is_suppressed_during_cooldown():
    import threading

    network = object.__new__(P2PNetwork)
    network._topology_lock = threading.RLock()
    network._topology_prune_cooldowns = {"node-41": time.monotonic() + 30.0}
    assert network._topology_prune_cooldown_active("node-41") is True
    # The outbound dial path must be blocked before it attempts network I/O.
    assert network._try_add_peer_impl("192.0.2.41", 8338, "node-41") is False
    network._topology_prune_cooldowns["node-41"] = time.monotonic() - 1.0
    assert network._topology_prune_cooldown_active("node-41") is False


def test_bilateral_prune_handshake_removes_peer_from_both_endpoints():
    """Exercise the actual prune handlers through a two-ended fake message link."""
    import threading
    from types import SimpleNamespace

    node38 = object.__new__(P2PNetwork)
    node41 = object.__new__(P2PNetwork)
    node38.node_id = "node-38"
    node41.node_id = "node-41"
    for network in (node38, node41):
        network._lock = threading.RLock()
        network._eager_peers = set()
        network.peers = {}
        network._ensure_topology_state()
        network._desired_peer_target = lambda: 3
        network._is_seed_node_mode = lambda: False
        network._topology_prune_preconditions_detail = (
            lambda peer_id, target, expected_view_hash="":
            ({"edge": tuple(sorted((peer_id, "node-38" if peer_id == "node-41" else "node-41"))),
              "view_hash": expected_view_hash}, "ok"))

    messages_38 = []
    messages_41 = []
    peer38 = SimpleNamespace(peer_id="node-41", connected=True, last_seen=time.time())
    peer41 = SimpleNamespace(peer_id="node-38", connected=True, last_seen=time.time())
    peer38.close = lambda: setattr(peer38, "connected", False)
    peer41.close = lambda: setattr(peer41, "connected", False)
    node38.peers[peer38.peer_id] = peer38
    node41.peers[peer41.peer_id] = peer41

    def send_from_38(message):
        messages_38.append(message)
        kind = message["type"]
        if kind == "TOPOLOGY_PRUNE_PROPOSE":
            node41._handle_topology_prune_proposal(peer41, message)
        elif kind == "TOPOLOGY_PRUNE_COMMIT":
            node41._handle_topology_prune_commit(peer41, message)
        elif kind == "TOPOLOGY_PRUNE_FINALIZE":
            node41._handle_topology_prune_finalize(peer41, message)
        return True

    def send_from_41(message):
        messages_41.append(message)
        kind = message["type"]
        if kind == "TOPOLOGY_PRUNE_ACK":
            node38._handle_topology_prune_ack(peer38, message)
        elif kind == "TOPOLOGY_PRUNE_COMMIT_ACK":
            node38._handle_topology_prune_commit_ack(peer38, message)
        elif kind == "TOPOLOGY_PRUNE_FINALIZE_ACK":
            node38._handle_topology_prune_finalize_ack(peer38, message)
        return True

    peer38.send = send_from_38
    peer41.send = send_from_41
    nonce, view_hash = "a" * 32, "b" * 64
    propose_event = threading.Event()
    commit_event = threading.Event()
    finalize_event = threading.Event()
    node38._topology_pending_prunes[nonce] = {
        "peer_id": "node-41", "view_hash": view_hash,
        "event": propose_event, "allow": False,
    }
    node38._topology_pending_commits[nonce] = {
        "peer_id": "node-41", "view_hash": view_hash, "event": commit_event,
    }
    node38._topology_pending_finalizes[nonce] = {
        "peer_id": "node-41", "view_hash": view_hash, "event": finalize_event,
    }
    proposal = {"type": "TOPOLOGY_PRUNE_PROPOSE", "prune_protocol": 2, "nonce": nonce,
                "edge": ["node-38", "node-41"], "view_hash": view_hash,
                "target_degree": 3, "issued_at": int(time.time())}
    assert peer38.send(proposal) is True
    assert propose_event.is_set()
    assert node38._topology_pending_prunes[nonce]["allow"] is True
    assert "node-41" in node38.peers and "node-38" in node41.peers

    assert peer38.send({"type": "TOPOLOGY_PRUNE_COMMIT", "nonce": nonce,
                        "view_hash": view_hash}) is True
    assert commit_event.is_set()
    assert "node-41" in node38.peers and "node-38" in node41.peers

    assert peer38.send({"type": "TOPOLOGY_PRUNE_FINALIZE", "nonce": nonce,
                        "view_hash": view_hash}) is True
    assert finalize_event.is_set()
    assert messages_41[-1]["type"] == "TOPOLOGY_PRUNE_FINALIZE_ACK"
    # Initiator removes itself only after FINALIZE_ACK.
    node38._finalize_topology_pruned_peer(peer38, reason="test_local_prune")
    assert "node-41" not in node38.peers
    # Receiver retains the transport briefly, then completes its normal cleanup.
    state = node41._topology_remote_prunes[nonce]
    state["finalize_timer"].cancel()
    if state.get("expiry_timer") is not None:
        state["expiry_timer"].cancel()
    node41._finish_remote_topology_prune(nonce, state, state["finalize_generation"])
    assert "node-38" not in node41.peers
    assert node38._topology_prune_cooldown_active("node-41") is True
    assert node41._topology_prune_cooldown_active("node-38") is True


def _make_remote_udp_prune_test_state(*, heartbeat_baseline, latest_heartbeat,
                                      any_packet_seen=None):
    import threading
    from types import SimpleNamespace

    network = object.__new__(P2PNetwork)
    network.node_id = "node-41"
    network._topology_lock = threading.RLock()
    network._topology_remote_prunes = {}
    network._topology_prune_cooldowns = {"node-38": time.monotonic() + 180.0}
    session = SimpleNamespace(
        # Generic liveness moves on FINALIZE itself; the real heartbeat signal
        # moves only when an actual UDP _F_HB packet arrives.
        _last_hb_recv=(time.monotonic() if any_packet_seen is None else any_packet_seen),
        _last_hb_packet_recv=latest_heartbeat,
    )
    peer = SimpleNamespace(peer_id="node-38", connected=True, _session=session,
                           last_seen=time.time())
    state = {"peer_id": "node-38", "peer": peer, "view_hash": "f" * 64,
             "phase": "finalizing", "expires_at": time.monotonic() + 60.0,
             "finalize_generation": 1, "finalize_last_seen": peer.last_seen,
             "finalize_hb_recv_baseline": heartbeat_baseline,
             "finalize_timer": None, "expiry_timer": None}
    network._topology_remote_prunes["e" * 32] = state
    finalized = []
    network._finalize_topology_pruned_peer = lambda *args, **kwargs: finalized.append(args)
    return network, peer, session, state, finalized


def test_udp_remote_prune_aborts_if_initiator_keeps_sending_heartbeats():
    """A true post-FINALIZE heartbeat means the initiator may have missed the ACK."""
    now = time.monotonic()
    network, peer, session, state, finalized = _make_remote_udp_prune_test_state(
        heartbeat_baseline=now - 2.0,
        latest_heartbeat=now,
        any_packet_seen=now)
    network._finish_remote_topology_prune("e" * 32, state, 1)
    assert peer.connected is True
    assert network._topology_remote_prunes["e" * 32]["phase"] == "committed"
    assert network._topology_prune_cooldown_active("node-38") is False
    assert not finalized
    timer = state.get("expiry_timer")
    if timer is not None:
        timer.cancel()


def test_udp_remote_prune_does_not_treat_finalize_packet_as_heartbeat():
    """FINALIZE refreshes generic activity but must not cause guaranteed abort."""
    now = time.monotonic()
    network, peer, session, state, finalized = _make_remote_udp_prune_test_state(
        heartbeat_baseline=now,
        latest_heartbeat=now,
        any_packet_seen=now)
    network._finish_remote_topology_prune("e" * 32, state, 1)
    # The finalize packet updated _last_hb_recv, but no actual heartbeat frame
    # arrived after the baseline, so receiver-side cleanup must complete.
    assert finalized == [(peer,)]
    assert "e" * 32 not in network._topology_remote_prunes


def test_udp_session_tracks_heartbeat_frames_separately_from_other_packets():
    """Control/data packet activity cannot masquerade as a keepalive heartbeat."""
    import threading
    from types import SimpleNamespace
    from visold.network.udp.session import UDPSession
    from visold.network.udp.wire import _F_ACK, _F_HB

    session = object.__new__(UDPSession)
    session._liveness_lock = threading.Lock()
    session._liveness_expired = False
    session._last_hb_recv = 0.0
    session._last_hb_packet_recv = 0.0
    session._window = SimpleNamespace(on_ack=lambda seq: None)
    session.send_ack = lambda seq: None

    UDPSession.on_packet(session, _F_ACK, 1, 0, 0, b"")
    any_packet_time = session._last_hb_recv
    assert any_packet_time > 0.0
    assert session._last_hb_packet_recv == 0.0

    UDPSession.on_packet(session, _F_HB, 2, 0, 0, b"")
    assert session._last_hb_recv >= any_packet_time
    assert session._last_hb_packet_recv >= any_packet_time


def test_duplicate_udp_finalize_does_not_reset_heartbeat_baseline_or_timer():
    """A retransmitted FINALIZE must be idempotent and preserve timeout evidence."""
    import threading
    from types import SimpleNamespace

    network = object.__new__(P2PNetwork)
    network.node_id = "node-41"
    network._topology_lock = threading.RLock()
    network._ensure_topology_state()
    baseline = time.monotonic() - 1.0
    session = SimpleNamespace(_last_hb_recv=baseline, _last_hb_packet_recv=baseline)
    sent = []
    peer = SimpleNamespace(peer_id="node-38", connected=True, _session=session,
                           last_seen=time.time(),
                           send=lambda message: sent.append(message) or True)
    nonce, view_hash = "c" * 32, "d" * 64
    state = {"peer_id": "node-38", "peer": peer, "view_hash": view_hash,
             "phase": "committed", "expires_at": time.monotonic() + 20.0,
             "finalize_generation": 0, "finalize_timer": None, "expiry_timer": None}
    network._topology_remote_prunes[nonce] = state

    message = {"type": "TOPOLOGY_PRUNE_FINALIZE", "nonce": nonce,
               "view_hash": view_hash}
    network._handle_topology_prune_finalize(peer, message)
    timer = state["finalize_timer"]
    first_generation = state["finalize_generation"]
    first_baseline = state["finalize_hb_recv_baseline"]

    session._last_hb_packet_recv = time.monotonic()
    network._handle_topology_prune_finalize(peer, message)
    try:
        assert len(sent) == 2
        assert all(item["type"] == "TOPOLOGY_PRUNE_FINALIZE_ACK" for item in sent)
        assert state["finalize_timer"] is timer
        assert state["finalize_generation"] == first_generation
        assert state["finalize_hb_recv_baseline"] == first_baseline
    finally:
        timer.cancel()
        expiry_timer = state.get("expiry_timer")
        if expiry_timer is not None:
            expiry_timer.cancel()


def test_legacy_unilateral_prune_proposal_is_denied_for_protocol_safety(monkeypatch):
    """Old nodes may close locally on ACK, so v2 must not ACK a legacy proposal."""
    from types import SimpleNamespace

    network = object.__new__(P2PNetwork)
    network.node_id = "node-41"
    network._ensure_topology_state()
    network._desired_peer_target = lambda: 3
    network._is_seed_node_mode = lambda: False
    network._topology_prune_preconditions_detail = lambda *args, **kwargs: (
        {"view_hash": "b" * 64}, "ok")
    sent = []
    peer = SimpleNamespace(peer_id="node-38", connected=True,
                           send=lambda message: sent.append(message) or True)
    # Deliberately omit prune_protocol: an old implementation would expect ACK
    # then close locally, so the new implementation must reject without preparing.
    network._handle_topology_prune_proposal(peer, {
        "nonce": "a" * 32, "edge": ["node-38", "node-41"],
        "view_hash": "b" * 64, "target_degree": 3, "issued_at": int(time.time()),
    })
    assert sent[-1]["type"] == "TOPOLOGY_PRUNE_ACK"
    assert sent[-1]["allow"] is False
    assert network._topology_remote_prunes == {}


def test_intentional_topology_prune_runs_disconnect_cleanup_without_peer_failure_penalty():
    import threading
    from types import SimpleNamespace

    network = object.__new__(P2PNetwork)
    network.node_id = "node-local"
    network._lock = threading.RLock()
    network._eager_peers = {"node-remote"}
    network._untrusted_rate_lock = threading.RLock()
    network._untrusted_rate = {"node-remote": 3}
    network._compact_stash_lock = threading.RLock()
    network._compact_stash = {"waiting": {"source_peer": "node-remote"}}
    calls = {"peer_fail": 0, "router_remove": [], "capability_remove": []}
    network.storage = SimpleNamespace(mark_peer_fail=lambda peer_id: calls.__setitem__(
        "peer_fail", calls["peer_fail"] + 1))
    network.router = SimpleNamespace(remove=lambda peer_id: calls["router_remove"].append(peer_id))
    network._capability_router = SimpleNamespace(remove_peer=lambda peer_id:
        calls["capability_remove"].append(peer_id))
    network._clear_msg_rate = lambda peer_id: None
    peer = SimpleNamespace(peer_id="node-remote", ip="192.0.2.41", port=8338,
                           connected=True, _fork_sync_buffer=[],
                           _fork_sync_buffer_bytes=0, _fork_sync_target_height=-1,
                           close=lambda: None, _intentional_topology_prune=True)
    network.peers = {peer.peer_id: peer}

    network._on_peer_disconnect(peer)

    assert peer.connected is False
    assert peer.peer_id not in network.peers
    assert peer.peer_id not in network._eager_peers
    assert calls["peer_fail"] == 0
    assert calls["router_remove"] == [peer.peer_id]
    assert calls["capability_remove"] == [peer.peer_id]
    assert network._untrusted_rate == {}
    assert network._compact_stash == {}
