# Topology Probe / Pruning Eligibility Fix — 2026-10-26

## Base and scope

Built from `V5_topology_asymmetric_report_fix.zip`. The TUI responsiveness patch was not used or included. This change is limited to adaptive topology pruning and replacement-probe eligibility.

## Runtime evidence being addressed

The live log showed:

- `prune deferred: reason=no_edge_has_both_endpoints_over_target active=4 target=3 ...`
- repeated `replacement probe available: active=4 target=3 ...`
- the operator had observed some links prune, while other nodes remained above target.

`no_edge_has_both_endpoints_over_target` means the *mutually reported reciprocal graph* had no edge whose two endpoints both had reciprocal degree greater than the soft target. The pruner correctly refused to remove an edge without sufficient reciprocal evidence. This does not, by itself, prove the physical network is broken; it indicates the policy's current graph view did not contain an eligible safe edge. One-sided/stale reports can make reciprocal degree lower than a node's raw active-peer count.

The code-level mismatch was in `_dial_pex_candidates()`: it could initiate a make-before-break replacement probe based on fresh reported degrees (an over-target incumbent and a lower/unknown-degree candidate) without first confirming that the current shared reciprocal graph had a safe, eligible edge this node was allowed to prune. Thus it could add a connection even though the pruning path had just concluded there was no eligible edge, allowing peer counts to remain elevated or grow.

## Change made

Before allowing an over-target PEX replacement probe, the code now:

1. Builds the current deterministic list of safely redundant edges from fresh reciprocal topology reports.
2. Requires a preferred eligible edge to exist.
3. Requires this node to be an endpoint of that preferred edge and the designated initiator for it.
4. Only then evaluates lower/unknown-degree replacement candidates and permits at most one probe, subject to existing stability, pending-dial, hard capacity, and cooldown gates.
5. Suppresses the extra outbound replacement probe when there is no locally initiatable safe prune edge. Suppression is logged at DEBUG to avoid repetitive INFO noise.

When pruning reports no degree-eligible edge, the INFO diagnostic now includes `local_reported_degree`, `local_reciprocal_degree`, and a bounded `reciprocal_degrees={node:degree,...}` summary. This makes it possible to distinguish active-peer count from the graph degree actually used by the pruning algorithm.

## What remains unchanged

- `TOPOLOGY_TARGET_PEERS` remains a soft steady-state goal (default 3), not an incoming-connection hard limit.
- Incoming peers can still be accepted under existing handshake/admission checks and `MAX_PEERS` hard cap. This is intentional to preserve make-before-break joining/recovery.
- A probe can still occur when the graph proves a safe local prune edge and this node is the designated initiator.
- No consensus, chain-sync, mining, balance, or TUI logic changed.
- No bridge edge is allowed to be removed; both endpoints must still validate and ACK the shared view.

## Tests and verification

- `py_compile` passed for modified P2P/topology/test modules.
- Selected networking regression suites: **107 passed**.
- Added/updated PEX tests verify:
  - a valid reciprocal graph with a safe preferred local edge can use one replacement probe;
  - an over-target active count with no pruneable reciprocal edge does not start an extra probe;
  - pending dials still suppress a second probe;
  - an unreported candidate may be probed only when an eligible local prune edge exists.
- ZIP integrity checked after packaging.

These are local unit/regression tests, not a live Android/Termux seven-node integration test. The new reciprocal-degree diagnostics should be used to confirm the deployed mesh's report consistency.
