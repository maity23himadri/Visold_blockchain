# Visold Adaptive Peer Topology Policy (2026-10-26)

## Goal

Keep ordinary nodes near a **soft target of three direct peers** while maintaining a connected, redundant, self-healing P2P graph. This is *tree-inspired*, not a strict tree: cycles are useful because they provide alternate paths when a node or link fails.

## Behaviour

1. **Bootstrap/recovery:** try configured seed endpoints first so changed mobile IPs and the current peer directory can be refreshed; then try cached peers and PEX candidates.
2. **Candidate selection:** rank candidates by the degree in their freshest identity-signed topology report. Unknown/stale reports are still eligible, but after known lower-degree candidates. Rotate ties round-robin to avoid repeatedly favoring the same peer.
3. **Make before break:** if a current peer is reported over target and a lower-degree replacement is available, one temporary `target + 1` connection may be attempted. The current edge is not removed simply because a replacement connected.
4. **Topology exchange:** the PEX response includes paginated node-directory entries and signed adjacency reports (`node_id`, direct `neighbors`, `degree`, completeness, issue time, sequence, and whether the reporter is the configured seed). A report is only accepted when its identity and ECDSA signature validate. Reports are gossip hints, not consensus state.
5. **Safe pruning:** only a complete, fresh, mutually consistent *local connected-component* view can authorize a redundant-edge choice. Unrelated cached reports cannot veto that component, but any missing/stale/inconsistent report reachable from the local node still blocks pruning. The chosen edge must be a non-bridge; both endpoints must remain at or above the safety floor after removal; each endpoint must be over target; the connection and observed adjacency must be stable for the configured interval. The initiating endpoint sends a proposal, the other endpoint independently verifies and ACKs it, and the initiator re-checks the graph digest after the ACK before closing. If information is stale/incomplete, endpoints disagree, the ACK times out, or a guard fails, the connection is kept. The globally preferred edge is attempted first; if it is not ready, its designated initiator may try up to three deterministic alternative edges incident to itself, one proposal at a time.
6. **Cycles and recovery:** edge pruning cannot knowingly remove a bridge in the accepted shared graph. This avoids turning the design into a fragile strict tree. A future failure can be repaired by the normal seed-first + cached-peer + PEX reconnect process.

## Configuration

These are defaults; existing `MIN_PEERS` and `MAX_PEERS` values are not rewritten by this feature:

```json
{
  "topology_policy_enabled": true,
  "topology_target_peers": 3,
  "topology_seed_pruning_enabled": false,
  "topology_report_ttl_seconds": 180,
  "topology_stable_seconds": 120
}
```

- `MIN_PEERS` remains numerically `25` and `MAX_PEERS` remains numerically `30` in this source. **When adaptive topology is enabled, however, ordinary-node discovery uses `topology_target_peers` as its soft operational target**; so `MIN_PEERS` is a legacy/fallback target in this mode, not a hard runtime requirement to make every ordinary node keep 25 peers.
- `MAX_PEERS=30` remains the ordinary-node admission cap. The topology target does not raise that cap.
- A process explicitly configured as the designated seed keeps its previous unbounded discovery/admission role and does not initiate its own pruning by default. An ordinary client can still propose dropping a redundant seed link; the seed only ACKs if the same signed graph view independently proves it safe. `topology_seed_pruning_enabled=true` lets the designated seed initiate its own pruning, but should only be enabled after dedicated bootstrap/failover testing. Seed admission remains unbounded either way.
- The target is a soft goal. Missing/stale/incomplete reports for neighbors in the visited component still block pruning. A one-sided adjacency claim is quarantined: it is not used as an edge or alternate path. Pruning may proceed only inside the mutually reported component, and only if its own connectivity, degree, stability, and two-endpoint ACK checks pass. If the reciprocal component is too small or has no safe non-bridge edge, no prune is correct.
- Normal-level `[TopologyPolicy]` diagnostics identify ignored asymmetric edges, incomplete/stale reports, no over-target mutual edge, bridge-only candidates, unstable sessions, and proposal/ACK failures. See `TOPOLOGY_ASYMMETRIC_REPORT_FIX_2026-10-26.md` and `TOPOLOGY_PRUNING_DIAGNOSTICS_AND_FALLBACK_FIX_2026-10-26.md` for test evidence.

## Limitations / rollout notes

- Full topology knowledge is eventually discovered via paginated PEX; it is not an instantaneous global oracle. Large networks need time to exchange all pages. Pruning deliberately fails closed until all reports needed for the local component are fresh and consistent.
- Reports authenticate who made a claim, not whether the claimed adjacency is truthful. The two endpoints' mutual view, graph connectivity checks, stable observations and ACK reduce risk, but this is not a substitute for an 8-node and larger real-network test.
- This change does not repair TLS concurrency faults by itself. Keep the TLS I/O serialization fix and all existing duplicate-session/admission guards.
- Before a production rollout, run an 8-node test for at least 10–15 minutes with forced peer loss and mobile IP/seed reconnect. Confirm peer counts, topology report acceptance, proposal/ACK outcomes, graph connectivity, and absence of repeated prune/reconnect churn.
