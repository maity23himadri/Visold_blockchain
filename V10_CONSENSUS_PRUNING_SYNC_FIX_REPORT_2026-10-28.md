# Visold V10 — Snapshot Bootstrap & Pruning Failure-Safety Fix Report

Date: 2026-10-28  
Baseline: `V10_consensus_fixed_2026-10-28_patched.zip` (preserves prior consensus fixes C-01 through C-04)

## Summary

Fixed the two reproduced defects in the supplied build:

1. **Snapshot bootstrap rollback inconsistency:** If an authenticated snapshot install failed after mutating some state, the old implementation could remove imported headers without restoring the previous execution state. Bootstrap now creates a durable recovery journal before the first mutation, restores the previous state and affected metadata on failure, removes only headers it knows were absent before the install, and clears the marker/journal only after recovery has completed. Startup retries an interrupted journal; if recovery cannot complete or a marker has no usable journal, startup fails closed rather than serving potentially inconsistent state. Block application and reorganization also reject work while the recovery marker is present.
2. **Pruning after required archive failure:** If a transaction selected by the historical-archive policy could not be written to `permanent_history` (including an eligible transaction missing its transaction ID), the pruner previously logged the exception and continued to remove its authoritative body/projection. The pruner now stops at that block, rolls back the partial archive rows for that block, leaves the body and transaction projection intact, and does not advance the contiguous pruning watermark past the failed block. SQLite commits completed blocks individually so a later failure cannot make the watermark claim that rolled-back earlier work was committed.

## Implementation notes

### Snapshot bootstrap

- Added `bootstrap_restore_backup`, a durable journal containing a compressed backup of the prior local execution state, the metadata values overwritten by bootstrap, and the exact range of header-only blocks installed by the attempt.
- The journal and `bootstrap_restore_in_progress` marker are persisted together before the first block/state mutation.
- Recovery restores state, replay protection, governance records, metadata and inserted headers before clearing the marker. Recovery is idempotent and leaves the marker in place if any recovery step fails.
- The recovery payload preserves destroyed-contract tombstones plus contract code/storage that are omitted from ordinary peer snapshots, so rollback does not accidentally discard local tombstone records.
- SQLite recovery explicitly clears a failed implicit transaction before starting rollback transactions; the connection wrapper intentionally suppresses rollback calls while a Storage-owned atomic block is active, so recovery first refuses to interfere with such an atomic block.
- Once headers and execution state are consistently installed and the journal is cleared, snapshot relay caching and pruning reconciliation are post-commit housekeeping; a failure there does not incorrectly roll back an already committed install.

### Rolling-window pruning

- Required archive write failures are a hard stop before canonical body compaction and projection deletion.
- Any earlier archive rows written for the failing block are rolled back, and the body/projection remain retrievable for retry.
- The watermark advances only through blocks that successfully completed compaction and projection cleanup. SQLite commits each completed block individually to keep that watermark aligned with durable state.
- KV/RocksDB and PGX paths retain the canonical body unless archive work completes; canonical compaction failures still stop processing before projection cleanup.

### Earlier fixes preserved

Only the following existing source files were changed for this patch:

- `visold/chain/blockchain.py` — fail-closed guards while bootstrap recovery is pending, plus refresh of recovery metadata after snapshot-engine startup recovery.
- `visold/storage/rolling_window_pruner.py`
- `visold/storage/snapshot.py`
- `visold/storage/storage.py`

Added regression tests:

- `tests/test_snapshot_prune_failure_atomicity_20261028.py`

The baseline source was the previous consensus-patched ZIP, so its C-01–C-04 consensus changes and pre-existing tests were retained.

## Verification

### New fault-injection regressions

`PYTHONPATH=. pytest -q tests/test_snapshot_prune_failure_atomicity_20261028.py`

**5 passed**. Cases cover:

- injected post-state-install bootstrap failure restores prior balance, height, and metadata;
- interrupted journal is recovered on engine startup;
- required archive insert failure retains the real eligible transfer's block body and live projection and does not move the watermark past it;
- real SQLite trigger failure during `l2_history` metadata write is rolled back atomically;
- destroyed-contract tombstones, code, storage and tags survive local rollback.

### Existing relevant suites (run independently)

| Suite | Result |
|---|---:|
| `test_pruning_authenticated_bootstrap.py`, `test_pruned_reconnect_authenticated_bootstrap.py`, `test_pruned_block_sync_safety.py` | 25 passed |
| `test_offline_recipient_transfer_pruning_reconnect_20261019.py` | 1 passed |
| `test_prune_rollback_recoverability_invariant_20261024.py` | 3 passed |
| `test_same_height_bootstrap_recovery_dispatch.py` | 4 passed |
| `test_snapshot_relay_rollback_failover_20261024.py` | 3 passed |
| `test_consensus_finality_audit_regressions_20261028.py`, `test_consensus_finality_security_fix_20261028.py`, `test_consensus_security_fixes.py` | 25 passed |
| **Total across completed runs** | **66 passed** |

`python -m compileall -q visold tests` passed.

One combined invocation of the four pruning/recovery suites hit the execution timeout; each component suite was then run independently and completed successfully. The entire repository test suite was not run. The live multi-node runtime and a real PGX/RocksDB deployment were not tested in this environment; the verified fault-injection tests used the actual SQLite storage implementation.

## Deployment note

Use this as a separate build and retain a backup of the existing node data directory before deploying. The journal makes new interrupted bootstrap operations recoverable. A legacy database that already has `bootstrap_restore_in_progress` but no `bootstrap_restore_backup` cannot be safely reconstructed automatically from this patch; startup deliberately refuses to serve it because the previous state backup does not exist.
