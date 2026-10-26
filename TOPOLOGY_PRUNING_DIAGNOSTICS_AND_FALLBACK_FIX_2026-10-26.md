# Adaptive Topology Pruning Diagnostics and Fallback Fix — 2026-10-26

## Scope

Applied to `V5_auto_dial_soft_target_fix.zip`. The TUI responsiveness patch was not used or included as the base for this build.

## Root causes addressed

1. `topology_component_view()` previously checked every fresh topology report in the local cache. A fresh report from an unrelated/disconnected component could advertise a neighbor whose report was absent and cause the entire local graph view to fail. The graph builder now walks only the component reachable from the local node. Missing/stale/incomplete reports for a visited node's advertised neighbor still fail closed; asymmetric claims are now quarantined and never used as graph edges or alternate paths. See `TOPOLOGY_ASYMMETRIC_REPORT_FIX_2026-10-26.md`.
2. `choose_redundant_edge()` only returned one deterministic candidate. If that edge failed a session-specific condition or its proposal was rejected/timed out, the rebalance pass ended without trying another edge. A deterministic ordered candidate list was added. Only the designated initiator of the globally preferred edge can drive fallback for that rebalance pass; fallback is limited to eligible edges incident to that same initiator. This avoids every node independently pruning a different edge at the same time.
3. Many pruning early exits were silent at normal log levels. New bounded INFO diagnostics report why pruning was deferred, why a candidate was skipped, and why a peer rejected a proposal. Examples include `topology_view_missing_report`, `using reciprocal topology edges only: ok_ignored_asymmetric_edges:...`, `no_edge_has_both_endpoints_over_target`, `all_degree_eligible_edges_are_bridges`, `connection_not_stable`, `ack_timeout`, and `peer_rejected_or_view_changed`.

## Safety properties retained

- No bridge edge is authorized for removal.
- Each endpoint must be over target, and the post-removal degree safety floor remains enforced.
- The selected edge must be directly connected at the initiator.
- Both endpoints must independently validate the same topology digest and agree via ACK.
- The initiator rechecks the view hash and all eligibility conditions after ACK before closing.
- At most three local-initiated candidates are attempted in one rebalance pass (`TOPOLOGY_PRUNE_CANDIDATES_PER_PASS = 3`); proposal waits remain bounded.
- Seed pruning defaults and `MIN_PEERS`/`MAX_PEERS` numerical values are unchanged.

## Regression tests added

- Unrelated cached component with an unreported neighbor does not veto the local complete component.
- A missing report for a neighbor reachable from the local component fails closed and reports the exact reason.
- Candidate edge order is deterministic and the legacy single-edge selector still returns the first candidate.
- If the preferred locally initiated candidate fails a session readiness gate, the next safe candidate can be proposed and pruned after a matching ACK.

## Verification in this environment

- `py_compile` for changed topology, P2P, config and test modules: passed.
- Selected networking regression suites: **97 passed** across adaptive topology, PEX dial budget, peer admission, handshake/liveness, network directory sync throttle, pruned block sync, peer retry cooldown, stale-session race, pruned resync, same-height reconnect sync, and sync gate.
- Tests were run locally against this source tree. This does **not** substitute for a live 7-node Android/Termux integration run.

## Expected runtime diagnosis

At most once per rebalance pass, inspect `[TopologyPolicy]` INFO messages. `topology_view_stale_report:<id>` means a required report must refresh. `using reciprocal topology edges only: ok_ignored_asymmetric_edges:...` means one-sided adjacency claims were excluded and never used as alternate paths. `no_edge_has_both_endpoints_over_target` means no edge meets the mutually reported degree rule; `all_degree_eligible_edges_are_bridges` means every otherwise eligible reciprocal edge would disconnect the verified component; and `candidate skipped ... reason=connection_not_stable` / `ack_timeout` identifies a per-edge readiness or coordination failure.
