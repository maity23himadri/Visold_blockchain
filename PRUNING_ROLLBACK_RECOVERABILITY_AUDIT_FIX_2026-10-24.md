# Visold pruning / rollback recoverability audit and fix — 2026-10-24

## Required invariant
For a pruning-capable serving node, pruning must not create an arbitrary gap between the newest rollback-safe authenticated snapshot and the retained full-body suffix.

The pruner now advances only to a committed snapshot-aligned exclusive boundary. With default `ROLLING_PRUNE_WINDOW=600` and `BOOTSTRAP_SNAPSHOT_INTERVAL=600`, a tip around 1490 no longer prunes to arbitrary watermark 890; it retains the replay suffix after the previous committed snapshot, preventing a later rollback to ~892 from stranding newcomers at snapshot 600.

## Fixed defects

1. **Arbitrary rolling cutoff could destroy rollback/bootstrap recoverability.**
   Pruning is now aligned to the newest servable committed snapshot strictly below the raw rolling cutoff.

2. **Fixed-count snapshot eviction could delete an anchor before the pruning floor reached it.**
   Snapshot retention is now window-aware: configured newest snapshots, all snapshots inside the rollback horizon, and the newest snapshot immediately before that horizon are retained.

3. **Legacy/pre-fix DBs could still perform a locally valid rollback that produced an unservable pruned suffix.**
   Rollback now rejects such a target before mutation when no committed surviving snapshot connects to the retained full-body suffix.

4. **Rollback and background body pruning could race.**
   Rollback now defers if a rolling-prune pass is active and holds the pruner guard while removing blocks.

5. **Pruner cadence remained pinned to the pre-rollback high tip.**
   `_last_height` is reset after rollback so pruning can resume normally as the chain advances again.

6. **Authenticated bootstrap genesis exception could be misclassified as archival.**
   Bootstrap deliberately keeps genesis full while 1..H can be header-only. Reconciliation now preserves a positive historical-unavailability watermark for that valid shape.

7. **Reconciliation could jump from a safe snapshot-aligned boundary to the old raw cutoff.**
   It now extends only through blocks that are actually stored as header-only, allowing safe joining to an imported header-only suffix without leaping over retained full bodies.

8. **Direct snapshot/chunk requests could bypass servable-manifest filtering.**
   `GET_SNAPSHOT`, latest chunk-manifest selection, and chunk serving now require the requested snapshot to be currently authenticated/servable by the canonical tip.

9. **Pruned reorg boundary check was one block too strict.**
   Reorg replacement beginning exactly at the first retained full-body height is no longer rejected by an off-by-one watermark comparison.

## Verification performed

- New recoverability invariant tests: 3/3 PASS.
- Snapshot relay / mixed recovery / backpressure / same-height / two-node boundary batch: 15/15 PASS.
- Authenticated pruning + reconnect batch: 13/13 PASS.
- Confirmed/hidden pruning, rollback, watermark and snapshot regression batch: 11/11 PASS.
- Existing rollback metadata tests: 3/3 PASS.
- Python compileall for `visold/`: PASS.

A larger combined test invocation exceeded the execution environment timeout; it is not reported as a pass. The component suites above were run separately to obtain explicit results.

## Compatibility

No consensus hash format, transaction format, block format, database schema, snapshot payload format, or wire message type was changed. The change affects local retention/serving policy and rollback safety checks.
