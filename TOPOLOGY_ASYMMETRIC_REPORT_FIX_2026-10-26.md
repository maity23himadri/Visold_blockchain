# Topology asymmetric-report fix — 2026-10-26

## Observed failure

Runtime log showed `topology_view_asymmetric_edge:<A><-><B>` despite six fresh reports. A report for A claimed B as a direct neighbor, while B's own signed report did not claim A. The prior implementation aborted all pruning on the first one-sided edge.

## Fix

- One-sided adjacency claims are now quarantined and are never used as graph edges or alternate paths.
- The pruning graph is constructed only from mutually advertised edges.
- Candidate eligibility and safety-floor degree calculations use the degree in that reciprocal graph, not a raw degree that can count asymmetric claims.
- Missing/stale reports named by a visited report, incomplete reports, invalid adjacency, or a reciprocal component smaller than three nodes still fail closed.
- The policy logs the ignored asymmetric edges. This makes safe pruning elsewhere possible without trusting the mismatched edge as proof of connectivity.

## Validation

Added regression coverage for a connected five-node graph with one one-sided adjacency claim. The reciprocal component remains connected, the mismatched edge is excluded, and only redundant edges whose endpoints are above the target in the reciprocal graph can be candidates. Updated the adjacency-digest test to verify that quarantining an asymmetric edge produces a new usable digest when the remaining reciprocal graph stays connected.

This is unit/regression evidence. It does not prove that the live mobile mesh has no other causes of pruning deferral; the new log line should say `using reciprocal topology edges only: ok_ignored_asymmetric_edges:...` if this condition is encountered.

## Exact local runtime diagnostic

The user observed a repeated `topology_view_asymmetric_edge:<A><-><B>` with six fresh reports. This means A's signed neighbor list named B while B's signed neighbor list did not name A. A report can be within TTL but still come from a different topology moment; alternatively, the two live peer maps may actually disagree. The log alone cannot distinguish those cases.

The fix does not force-close the mismatched edge. It ignores that one-sided claim as a graph edge and proves safe redundancy only over reciprocal edges. If that leaves fewer than three mutually connected nodes, or if any visited neighbor's report is missing/stale, pruning remains deferred. This preserves the fail-closed behavior for uncertain connectivity.

## Tests run

- `tests/test_adaptive_peer_topology_policy.py`: 18 passed.
- Selected P2P mesh-admission, liveness/handshake, TCP stale-session, and peer-retry regression modules together with topology tests: 57 passed.
- These are local tests, not a live Android/Termux seven-node integration run.
