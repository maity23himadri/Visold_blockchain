# Visold V10 — Bilateral Peer-Pruning Fix Report

Date: 2026-10-28  
Baseline: `V10_consensus_pruning_sync_fixed_2026-10-28.zip`

## Finding and invariant

The previous topology-prune path closed and removed the peer only in the initiating node's local `self.peers` map after receiving a proposal ACK. The receiving handler only sent that ACK. TCP could eventually notify the other side through EOF, but UDP has no EOF, so the remote node could keep a stale peer entry or recreate the edge. This was consistent with the reported Node 38/Node 41 asymmetry.

The required invariant is now: **a peer edge is not intentionally removed on either endpoint based only on a proposal or prepare ACK. Both endpoints participate in a versioned commit/finalize exchange, and an incomplete exchange does not trigger a deliberate one-sided close.**

## Changes

1. **Versioned, bilateral handshake** — added connection-local message types in `visold/kernel/messages.py` and handling in `visold/network/p2p.py`:
   - `TOPOLOGY_PRUNE_PROPOSE` with `prune_protocol: 2`, then `TOPOLOGY_PRUNE_ACK`;
   - `TOPOLOGY_PRUNE_COMMIT` / `TOPOLOGY_PRUNE_COMMIT_ACK`;
   - `TOPOLOGY_PRUNE_FINALIZE` / `TOPOLOGY_PRUNE_FINALIZE_ACK`.
   Each ACK is correlated to the same nonce, peer identity, and topology-view hash. Duplicate commit/finalize messages are handled idempotently. All these message types bypass gossip-content deduplication because they are connection-local control messages.

2. **No silent downgrade to the old unilateral behavior** — the receiver rejects legacy prune proposals without `prune_protocol: 2`. If a new initiator talks to an old peer that does not understand COMMIT/FINALIZE, the initiator times out and preserves the edge rather than closing only its local side.

3. **UDP-safe close sequencing** — the receiver retains the connection long enough after `FINALIZE_ACK` for asynchronous UDP packet/application acknowledgements to travel. If UDP transport heartbeats show the initiator is still active (consistent with its not having received the finalize ACK), receiver-side teardown is aborted and the edge is retained. TCP continues to use ordinary EOF/disconnect cleanup.

4. **Normal disconnect cleanup on both endpoints** — successful finalization routes through the standard disconnect handler rather than directly popping `self.peers`. That removes router/capability records, message-rate state, and compact-stash references. Deliberate topology pruning does not count as a peer failure penalty.

5. **Reconnect cooldown** — both sides install a short-lived identity tombstone (`TOPOLOGY_PRUNE_COOLDOWN_SECONDS = 180`). Known-ID outbound dials are suppressed and post-handshake registration checks the tombstone again when the dial started from an IP-only endpoint. Expired tombstones are cleaned opportunistically.

6. **Regression coverage** — `tests/test_adaptive_peer_topology_policy.py` now covers both-endpoint state removal through the actual protocol handlers, ACK ordering, UDP finalize-timeout behavior, cooldown handling, legacy-protocol rejection, and intentional-disconnect cleanup.

## Verification

### Completed passing runs

- Peer/topology, admission/retry, TCP liveness, UDP recovery/reconnect/self-heal, directory-throttle, and UDP security batch: **91 passed**.
- `test_snapshot_prune_failure_atomicity_20261028.py`: **5 passed**.
- `test_pruned_block_sync_safety.py`: **12 passed**.
- `test_offline_recipient_transfer_pruning_reconnect_20261019.py`: **1 passed**.
- `test_prune_rollback_recoverability_invariant_20261024.py`: **3 passed**.
- `test_consensus_finality_security_fix_20261028.py` + `test_consensus_security_fixes.py`: **15 passed**.
- `python -m compileall -q visold tests`: passed.
- `python tools/check_architecture.py`: `ARCHITECTURE: OK - no cycles, layering respected` (125 modules, 475 import edges, 22 contexts).
- ZIP integrity check: passed.

### Inconclusive / not claimed as passing

`tests/test_pruning_authenticated_bootstrap.py` timed out in this environment after printing five progress dots without a final pytest summary. It is not counted as pass or failure. The complete repository suite was not run.

No live multi-machine or real multi-node UDP runtime was run in this repair. The new bilateral regression uses a two-ended simulated message link that calls the actual prune handlers, plus the existing UDP/TCP regression suites. Before deploying broadly, test this build on your usual two-node TCP and UDP setup and confirm both nodes remove the edge after a successful prune, while a missing finalize ACK leaves the edge active or allows normal transport timeout cleanup.

## Changed project files

- `visold/network/p2p.py`
- `visold/kernel/messages.py`
- `visold/kernel/config.py`
- `tests/test_adaptive_peer_topology_policy.py`

Earlier consensus, snapshot-recovery, and pruning safety changes from the baseline archive were retained. No guarantee of zero undiscovered defects is implied by these targeted tests.
