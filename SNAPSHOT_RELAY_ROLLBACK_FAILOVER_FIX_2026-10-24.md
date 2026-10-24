# Snapshot relay, rollback hygiene, and pruned-recovery failover fix — 2026-10-24

## Root causes fixed

1. **Authenticated snapshots were not transitive.** A node that successfully bootstrapped from a verified snapshot restored state but did not persist the verified snapshot blob/manifest entry, so it could not later bootstrap another fresh node.
2. **Rollback left stale future snapshots.** Rolling back below a stored snapshot height left `snap:<H>`/`snap_manifest` entries above the new tip. Such snapshots no longer had a local H+1 commitment and could be advertised even though they were not locally servable.
3. **Pruned recovery was pinned to the peer that exposed the gap.** If that peer was a rolled-back/pruned node with no usable committed snapshot ahead, recovery stopped even when another connected higher peer had a valid newer snapshot.

These three issues explain the observed topology where a node at ~1490 had previously synced successfully but could not bootstrap a new node, and where a node rolled back to ~892 could lead a fresh node to snapshot 600 and then strand it there despite a healthier ~1490 peer being connected.

## Fixes

- After successful authenticated bootstrap installation, persist the exact verified compressed snapshot blob and the independently verified commitment digest into the local snapshot cache/manifest.
- Only serve snapshots that are locally usable at the current canonical tip: blob present, H header present, and H+1 commitment block present.
- On rollback, remove cached/manifest snapshots above the new tip and clear restored/bootstrap checkpoint metadata that points above the new tip.
- On pruned-history recovery failure, try other connected peers, preferring higher advertised chain heights, instead of remaining pinned to the first insufficient peer.

## Security properties preserved

- No snapshot is relayed before its digest has been authenticated through the verified PoW/header chain and H+1 commitment.
- A snapshot at the current tip H is not advertised until local H+1 exists.
- Rollback never advertises state above the new canonical tip.
- Existing fast-forward-only prefix checks remain unchanged; this does not turn snapshot bootstrap into an implicit deep-reorg mechanism.

## Verification

New regressions:
- imported authenticated snapshot becomes relayable after H+1 arrives: PASS
- rollback removes future snapshots and never advertises them: PASS
- recovery fails over from an insufficient rolled-back peer to a higher peer: PASS

Existing relevant suites:
- bootstrap/pruning/same-height/queue/backpressure safety: 38/38 PASS
- two-node pruning-boundary reconnect: 2/2 PASS
- modified modules compile: PASS
