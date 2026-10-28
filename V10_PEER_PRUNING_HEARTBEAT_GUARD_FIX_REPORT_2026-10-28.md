# Visold V10 — UDP peer-pruning heartbeat guard follow-up fix

Date: 2026-10-28

## Root cause

The previous bilateral-pruning patch used `UDPSession._last_hb_recv` to decide whether the initiator remained alive after receiving `TOPOLOGY_PRUNE_FINALIZE_ACK`. That field is intentionally updated for every inbound UDP packet, including the `TOPOLOGY_PRUNE_FINALIZE` control packet itself. With a 15-second receiver grace and a 22.5-second activity threshold, the finalize packet alone could make the receiver abort local cleanup, leaving exactly the asymmetric state observed in the live topology (the initiator removed the edge while the receiver retained it).

## Fixes applied

1. `visold/network/udp/session.py`
   - Kept `_last_hb_recv` semantics unchanged for existing session-liveness/GC behavior.
   - Added `_last_hb_packet_recv`, updated only for actual `_F_HB` heartbeat frames.

2. `visold/network/p2p.py`
   - The receiver captures a heartbeat-only baseline when the first valid FINALIZE arrives.
   - The UDP close grace is now longer than two heartbeat intervals, so an already-in-flight heartbeat cannot normally be confused with continued activity at the decision point.
   - The receiver aborts only if a real heartbeat frame arrived after the finalize baseline and is still recent. Unknown heartbeat history fails safe by preserving the edge.
   - Duplicate FINALIZE messages resend the ACK idempotently but do not reset the original baseline, generation, or timer.
   - Existing normal disconnect cleanup and peer-ID cooldown remain in use.

3. `tests/test_adaptive_peer_topology_policy.py`
   - Updated the live-heartbeat abort test to use actual heartbeat-only timestamps.
   - Added regressions proving that a FINALIZE/control packet alone does not cause an abort, heartbeat frames are tracked separately from general packet activity, and duplicate FINALIZE does not reset finalization state.

## Verification

Completed test runs after the patch:

- `tests/test_adaptive_peer_topology_policy.py`: 27 passed
- UDP recovery/self-heal/security/stale-reconnect suites: 18 passed
- P2P liveness/handshake, mesh-admission, peer-height, peer-retry and TCP stale-session suites: 46 passed
- Consensus finality/security suites: 25 passed
- Snapshot failure-atomicity suite: 5 passed
- Pruned-block sync-safety suite: 12 passed
- Offline recipient transfer/pruning/reconnect suite: 1 passed
- `python -m compileall -q visold tests`: passed

The test suite `tests/test_prune_rollback_recoverability_invariant_20261024.py` timed out without a final pytest summary when run alone, so its result is inconclusive and is not counted as passed. A combined run of some snapshot/pruning tests also timed out; those suites were then run separately as listed above. No full repository suite or real multi-node Android/Termux live UDP run was completed for this follow-up.

## Operational note

This patch fixes the deterministic false-abort caused by treating any UDP packet as a heartbeat. UDP is still best-effort; sustained packet loss or process termination can delay convergence. Validate this build on the user's real multi-node setup by collecting peer-list snapshots and prune logs from both endpoints for the same peer ID. Do not overwrite node data directories; take backups and test the ZIP as a separate copy.
