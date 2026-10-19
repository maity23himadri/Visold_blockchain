# Visold — Pruning Boundary and Reconnect Fix

Date: 2026-10-19

## Summary

Fixed the authenticated-snapshot reconnect path where a recovering node could keep full bodies for old local blocks while its `rolling_pruned_until` metadata falsely claimed those blocks had already been pruned. Also fixed the associated missing `block_headers` index entries and a watermark regression that could move the retention boundary backwards after bootstrap.

## Root cause

`restore_authenticated_bootstrap()` wrote `rolling_pruned_until = snapshot_height` after importing header-only blocks. The imported suffix was pruned, but the node's existing local prefix was not necessarily pruned. The rolling pruner then used the overstated watermark as its starting point and could skip the old full bodies completely.

The pruner also skipped `block_headers` insertion for block rows that were already marked pruned. Therefore, authenticated bootstrap could leave valid header-only `blocks` rows without corresponding `block_headers` index rows.

## Production changes

- `visold/storage/snapshot.py`
  - Injects and calls the node's shared rolling pruner after authenticated bootstrap state installation.
  - Does not treat snapshot height as proof that every lower block body was pruned.
  - Leaves a conservative watermark if pruning reconciliation cannot complete.

- `visold/chain/blockchain.py`
  - Supplies the existing `RollingWindowPruner` instance to `StateSnapshotEngine`, avoiding a second independent pruner/lock.

- `visold/storage/rolling_window_pruner.py`
  - Reconciles stored `pruned` flags before trusting legacy watermark metadata.
  - Repairs missing `block_headers` rows for already-pruned blocks, including header-only history installed by previous bootstrap runs.
  - Completes rolling-window catch-up in bounded batches and keeps the watermark equal to the actual contiguous body-retention boundary.
  - Preserves authenticated `bootstrap_commitment` metadata when handling already-pruned blocks.
  - Does not clamp an accurate advanced watermark back to the rolling cutoff; doing so could move rollback protection backwards.
  - Serializes the one-time reconciliation check under the existing pruner lock to prevent concurrent background triggers from reconciling stale heights out of order.

## Regression tests

Added `tests/test_two_node_pruning_boundary_reconnect.py` with two cases:

1. A mines to height 10; B syncs and goes offline; A advances and prunes to height 25; B reconnects through authenticated snapshot recovery and syncs to the same tip. The test compares block `pruned` flags, the pruning watermark, the transaction projection, and `block_headers` rows.
2. Simulates a legacy database with old full bodies at 0–10, header-only/pruned blocks at 11–24, a full block 25, and a stale watermark of 24. A normal pruning trigger repairs the database without requiring another snapshot download.

## Observed results

At height 25 with a test rolling window of 9 blocks:

| Check | Node A | Node B after reconnect |
|---|---:|---:|
| Chain height | 25 | 25 |
| Tip hash/state root | Match | Match |
| Pruned block heights | 0–15 | 0–24 |
| `rolling_pruned_until` | 16 | 25 |
| `block_headers` rows | 0–15 | 0–24 |
| Transaction rows retained | 16–25 | 25 only |

Node B is intentionally more aggressively pruned immediately after bootstrap: the authenticated snapshot installs blocks 11–24 as header-only, and the fix now also prunes B's old local bodies 0–10. Its watermark of 25 truthfully means block 25 is the first full-body block currently retained.

The regression then advances and syncs both nodes to height 35. Both watermarks converge to **26**, both databases mark blocks 0–25 as pruned, and both retain full bodies for blocks 26–35. This confirms the watermark does not move backwards and that normal pruning resumes from the correct boundary.

## Verification

- `python -m compileall -q visold tests`: passed.
- Pruning/bootstrap/reconnect/safety targeted group: **36 passed**.
- Sync-import/PGX rollback/sync gate/history/supply/pruned-resync targeted group: **35 passed**.
- Focused rollback watermark safety test: **1 passed**.
- Total across those non-overlapping targeted runs: **72 passed**.

A full `python -m pytest -q` attempt and a combined run of all targeted files each exceeded the 120-second execution limit after reporting progress dots; neither produced a final summary. The affected test groups passed when run separately, as listed above, but the complete repository suite is therefore **not claimed as passed**. A standalone static verifier could not run because the uploaded source archive does not contain `visold_vsd_original.py`, which that utility expects.

## Test scope / limitation

The regression uses real Visold `Blockchain` objects, block application, SQLite storage, pruning, authenticated header verification and snapshot restore. Its peer transport is a deterministic local adapter, not a live TCP/UDP two-process test. Mining difficulty is overridden for test speed; this is not a proof-of-work performance or network interoperability test.
