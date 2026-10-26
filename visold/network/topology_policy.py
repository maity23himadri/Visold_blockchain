"""Tree-inspired, bounded-degree peer topology helpers for Visold.

Topology data is an advisory routing/discovery hint, not consensus state.
Automatic edge pruning is deliberately conservative: the signed reports must be
fresh, complete, mutually consistent, and prove an alternate path after removal.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


def topology_signed_payload(report: Mapping[str, Any]) -> dict:
    """Return exactly the canonical fields covered by a topology signature."""
    return {
        "version": int(report.get("version", 1)),
        "node_id": str(report.get("node_id", "")),
        "pub_hex": str(report.get("pub_hex", "")),
        "neighbors": list(report.get("neighbors", [])),
        "degree": int(report.get("degree", -1)),
        "complete": bool(report.get("complete", False)),
        "seed": bool(report.get("seed", False)),
        "issued_at": int(report.get("issued_at", 0)),
        "seq": int(report.get("seq", 0)),
    }


def topology_signing_bytes(report: Mapping[str, Any]) -> bytes:
    return json.dumps(topology_signed_payload(report), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def verify_topology_report(report: Any, *, now: Optional[float] = None,
                           ttl_seconds: int = 180,
                           max_neighbors: int = 500) -> bool:
    """Validate report shape, freshness, claimed identity, and ECDSA signature."""
    if not isinstance(report, dict):
        return False
    try:
        from visold.crypto.ecc import ecdsa_verify, pub_from_hex, sig_from_hex

        node_id = str(report.get("node_id", ""))
        pub_hex = str(report.get("pub_hex", ""))
        neighbors = report.get("neighbors")
        issued_at = int(report.get("issued_at", 0))
        seq = int(report.get("seq", -1))
        degree = int(report.get("degree", -1))
        complete = report.get("complete")
        seed_role = report.get("seed")
        version = int(report.get("version", 0))
        now_value = float(time.time() if now is None else now)
        if version != 1 or len(node_id) != 64 or len(pub_hex) != 66:
            return False
        if any(ch not in "0123456789abcdef" for ch in node_id.lower()):
            return False
        if hashlib.sha256(pub_hex.encode("ascii")).hexdigest() != node_id:
            return False
        if not isinstance(neighbors, list) or len(neighbors) > max_neighbors:
            return False
        if (not isinstance(complete, bool) or not isinstance(seed_role, bool)
                or degree < 0 or degree > 100000):
            return False
        if complete and degree != len(neighbors):
            return False
        if seq < 1 or issued_at <= 0 or issued_at > now_value + 30:
            return False
        if now_value - issued_at > max(30, int(ttl_seconds)):
            return False
        normalized = []
        for value in neighbors:
            if not isinstance(value, str) or not value or len(value) > 160:
                return False
            if value == node_id or value in normalized:
                return False
            normalized.append(value)
        if normalized != sorted(normalized):
            return False
        signature = sig_from_hex(str(report.get("sig", "")))
        digest = hashlib.sha256(topology_signing_bytes(report)).digest()
        return bool(ecdsa_verify(pub_from_hex(pub_hex), digest, signature))
    except Exception:
        return False


def rank_topology_candidates(candidates: Sequence[dict], reports: Mapping[str, dict],
                             cursor: int = 0, now: Optional[float] = None,
                             ttl_seconds: int = 180) -> List[dict]:
    """Least-reported-degree first, with round-robin rotation among ties.

    Unreported/stale peers remain eligible, but are tried after peers with a
    fresh signed degree report. Inputs are copied so caller data isn't mutated.
    """
    now_value = float(time.time() if now is None else now)
    groups: Dict[float, List[dict]] = {}
    for raw in candidates:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        pid = str(item.get("peer_id", "") or "")
        report = reports.get(pid)
        if (isinstance(report, dict)
                and now_value - float(report.get("issued_at", 0) or 0) <= max(30, ttl_seconds)
                and float(report.get("issued_at", 0) or 0) <= now_value + 30):
            try:
                degree = float(max(0, int(report.get("degree", 0))))
            except (TypeError, ValueError, OverflowError):
                degree = math.inf
        else:
            degree = math.inf
        groups.setdefault(degree, []).append(item)
    ranked: List[dict] = []
    for degree in sorted(groups):
        group = sorted(groups[degree], key=lambda p: (
            str(p.get("peer_id", "") or ""),
            str(p.get("ip", "") or ""),
            int(p.get("port", 0) or 0),
        ))
        if group:
            offset = int(cursor) % len(group)
            group = group[offset:] + group[:offset]
        ranked.extend(group)
    return ranked


def topology_component_view_diagnostic(reports: Mapping[str, dict], *, local_node_id: str,
                                      now: Optional[float] = None,
                                      ttl_seconds: int = 180):
    """Return ``(view, reason)`` for the local connected component.

    Reports cached for unrelated/stale components must not veto pruning in the
    local component. Every node traversed in the conservative, mutually-reported
    component must have a fresh, complete report. A one-sided adjacency claim is
    quarantined rather than treated as an edge: it cannot be used as a path for
    proving redundancy. Missing/stale reports for a neighbor named by a visited
    report still fail closed.
    """
    now_value = float(time.time() if now is None else now)
    ttl = max(30, int(ttl_seconds))
    fresh: Dict[str, dict] = {}
    raw: Dict[str, dict] = {str(nid): rec for nid, rec in reports.items()
                            if isinstance(rec, dict)}

    def report_problem(node_id: str) -> str:
        rec = raw.get(node_id)
        if rec is None:
            return f"missing_report:{node_id[:12]}"
        try:
            issued_at = float(rec.get("issued_at", 0) or 0)
            if issued_at > now_value + 30:
                return f"future_report:{node_id[:12]}"
            if now_value - issued_at > ttl:
                return f"stale_report:{node_id[:12]}"
            neighbors = rec.get("neighbors")
            if not isinstance(neighbors, list):
                return f"invalid_neighbors:{node_id[:12]}"
            if rec.get("complete") is not True:
                return f"incomplete_report:{node_id[:12]}"
            if int(rec.get("degree", -1)) != len(neighbors):
                return f"degree_mismatch:{node_id[:12]}"
        except (TypeError, ValueError, OverflowError):
            return f"invalid_report:{node_id[:12]}"
        return f"unusable_report:{node_id[:12]}"

    for node_id, report in raw.items():
        try:
            issued_at = float(report.get("issued_at", 0) or 0)
            neighbors = report.get("neighbors")
            if (issued_at <= now_value + 30 and now_value - issued_at <= ttl
                    and isinstance(neighbors, list)
                    and report.get("complete") is True
                    and int(report.get("degree", -1)) == len(neighbors)):
                fresh[node_id] = report
        except (TypeError, ValueError, OverflowError):
            continue

    local_id = str(local_node_id)
    if local_id not in fresh:
        return None, report_problem(local_id)
    if len(fresh) < 3:
        return None, "fewer_than_3_fresh_reports"

    adjacency: Dict[str, set] = {}
    component = set()
    # Signed reports can be fresh yet reflect different moments of a changing
    # mesh. Keep asymmetric claims out of the graph instead of letting one stale
    # edge veto every unrelated safe prune. Only reciprocal edges may be used
    # to prove an alternate path.
    asymmetric_edges = set()
    stack = [local_id]
    while stack:
        current = stack.pop()
        if current in component:
            continue
        report = fresh.get(current)
        if report is None:
            return None, report_problem(current)
        component.add(current)
        adjacency.setdefault(current, set())
        neighbors = report.get("neighbors", [])
        # A complete report is signed and normally sorted/deduplicated; repeat
        # the structural checks here because unit callers may supply raw maps.
        if len(set(neighbors)) != len(neighbors) or current in neighbors:
            return None, f"invalid_adjacency:{current[:12]}"
        for neighbor in neighbors:
            neighbor = str(neighbor)
            neighbor_report = fresh.get(neighbor)
            if neighbor_report is None:
                return None, report_problem(neighbor)
            other_neighbors = neighbor_report.get("neighbors", [])
            if current not in other_neighbors:
                asymmetric_edges.add((current, neighbor))
                continue
            adjacency[current].add(neighbor)
            adjacency.setdefault(neighbor, set()).add(current)
            if neighbor not in component:
                stack.append(neighbor)

    if len(component) < 3:
        if asymmetric_edges:
            return None, "local_component_smaller_than_3_after_ignoring_asymmetric_edges"
        return None, "local_component_smaller_than_3"
    reason = "ok"
    if asymmetric_edges:
        items = ",".join(f"{a[:12]}<->{b[:12]}" for a, b in sorted(asymmetric_edges)[:8])
        reason = f"ok_ignored_asymmetric_edges:{len(asymmetric_edges)}:{items}"
    return (fresh, adjacency, component), reason


def topology_component_view(reports: Mapping[str, dict], *, local_node_id: str,
                            now: Optional[float] = None,
                            ttl_seconds: int = 180):
    """Return (fresh reports, mutual adjacency, local component) or None.

    Only the local connected component is required to be complete. Fresh cache
    entries from unrelated components are ignored instead of accidentally
    blocking otherwise-safe pruning.
    """
    view, _reason = topology_component_view_diagnostic(
        reports, local_node_id=local_node_id, now=now, ttl_seconds=ttl_seconds)
    return view


def topology_component_digest(reports: Mapping[str, dict], *, local_node_id: str,
                              now: Optional[float] = None,
                              ttl_seconds: int = 180) -> Optional[str]:
    """Hash the shared component's signed adjacency fields, excluding report timestamps.

    Excluding issued-at/sequence/signature lets both endpoints agree on the
    same connectivity view even when each node signs a fresh report at a
    slightly different moment.
    """
    view = topology_component_view(
        reports, local_node_id=local_node_id, now=now, ttl_seconds=ttl_seconds)
    if view is None:
        return None
    fresh, adjacency, component = view
    canonical = [
        [node_id, int(fresh[node_id].get("degree", 0)), sorted(adjacency[node_id] & component)]
        for node_id in sorted(component)
    ]
    encoded = json.dumps(canonical, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def list_redundant_edges(reports: Mapping[str, dict], *, local_node_id: str,
                         now: Optional[float] = None, ttl_seconds: int = 180,
                         target_degree: int = 3) -> List[Tuple[str, str]]:
    """Return all safe over-target edges in deterministic priority order.

    The first entry is the globally preferred edge (same rule as the previous
    single-edge selector). Remaining entries allow that edge's designated
    initiator to try another incident edge if the preferred edge is locally
    not ready; callers must preserve the single-initiator rule.
    """
    view = topology_component_view(
        reports, local_node_id=local_node_id, now=now, ttl_seconds=ttl_seconds)
    if view is None:
        return []
    fresh, adjacency, component = view
    candidates: List[Tuple[str, str, str]] = []
    for a in sorted(component):
        for b in sorted(adjacency[a] & component):
            if a >= b:
                continue
            # Use only mutually confirmed degrees for pruning decisions. Raw
            # report degree may include one-sided/stale adjacency claims which
            # are intentionally not trusted as edges in this conservative view.
            degree_a = len(adjacency[a] & component)
            degree_b = len(adjacency[b] & component)
            if degree_a <= target_degree or degree_b <= target_degree:
                continue
            seen = {a}
            todo = [a]
            while todo:
                current = todo.pop()
                for neighbor in adjacency[current]:
                    if {current, neighbor} == {a, b}:
                        continue
                    if neighbor not in seen:
                        seen.add(neighbor)
                        todo.append(neighbor)
            if component.issubset(seen):
                score = hashlib.sha256((a + "\0" + b).encode("utf-8")).hexdigest()
                candidates.append((score, a, b))
    candidates.sort()
    return [(a, b) for _score, a, b in candidates]


def choose_redundant_edge(reports: Mapping[str, dict], *, local_node_id: str,
                          now: Optional[float] = None, ttl_seconds: int = 180,
                          target_degree: int = 3) -> Optional[Tuple[str, str]]:
    """Choose the globally preferred redundant over-target edge, if any."""
    edges = list_redundant_edges(
        reports, local_node_id=local_node_id, now=now, ttl_seconds=ttl_seconds,
        target_degree=target_degree)
    return edges[0] if edges else None


def topology_prune_initiator(edge: Tuple[str, str], reports: Mapping[str, dict]) -> Optional[str]:
    """Choose a deterministic edge pruner, preferring a non-seed endpoint.

    The designated seed remains passive by default so it can preserve its
    bootstrap role. If a redundant edge connects a seed and an ordinary node,
    the ordinary endpoint initiates the two-phase close and the seed only ACKs.
    For ordinary edges, the lexicographically lower node ID initiates.
    """
    if not isinstance(edge, (tuple, list)) or len(edge) != 2:
        return None
    a, b = str(edge[0]), str(edge[1])
    if not a or not b or a == b:
        return None
    report_a, report_b = reports.get(a), reports.get(b)
    if not isinstance(report_a, dict) or not isinstance(report_b, dict):
        return None
    seed_a = report_a.get("seed") is True
    seed_b = report_b.get("seed") is True
    if seed_a != seed_b:
        return b if seed_a else a
    if seed_a and seed_b:
        # Do not automatically prune between two designated seeds.
        return None
    return min(a, b)
