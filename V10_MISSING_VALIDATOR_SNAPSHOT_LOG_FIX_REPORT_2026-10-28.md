# Visold V10 — Missing Historical Validator Snapshot Warning Deduplication

Date: 2026-10-28
Base: `V10_peer_prune_bilateral_fixed_2026-10-28_r2.zip`

## Scope

This is a logging-only change for repeated `eligible validator snapshot unavailable` warnings during legacy sync/pruned-history recovery. It does **not** change validator eligibility, quorum calculations, vote acceptance, finalization, rollback, pruning, or snapshot reconstruction rules.

## Change

`Blockchain` now tracks a contiguous missing-validator-snapshot episode in memory:

- The first unavailable height emits one `WARNING` with an explanation that repeated warnings will be suppressed until a trustworthy snapshot is available.
- Further unavailable heights/retries in the same episode are counted by unique height without another yellow warning.
- When a trustworthy snapshot becomes available at the current or a later height, one `INFO` message summarizes the number and range of heights covered by the suppressed warnings, and the episode clears.
- A later distinct missing-snapshot episode can emit a new warning.
- Finalization remains fail-closed: an unavailable historical validator snapshot still defers BFT finalization, and a validator vote without a trustworthy snapshot is still rejected.

The shared helper is used by the finalization, embedded-vote finality, and standalone validator-vote paths so these code paths do not each emit their own warning for the same episode.

## Regression coverage

Added `tests/test_missing_validator_snapshot_warning_dedup_20261028.py`:

1. Multiple distinct missing heights plus retries emit exactly one warning during an episode.
2. Snapshot availability closes the episode; a future missing-snapshot episode may warn again.
3. `ConsensusEngine.finalize_applied_block()` still returns failure and does not finalize the block when the snapshot is unavailable.

## Test results

Command:

```bash
PYTHONPATH=. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q \
  tests/test_missing_validator_snapshot_warning_dedup_20261028.py \
  tests/test_consensus_finality_security_fix_20261028.py \
  tests/test_consensus_security_fixes.py
```

Result: **18 passed in 3.67s**.

Python compilation of the changed modules and regression test also passed. ZIP CRC integrity was checked after packaging.

## Operational note

This change suppresses repeated yellow log alerts; it does **not** recreate missing historical validator snapshots or force the affected blocks to finalize. That is intentional: using the current validator set for an old height would be consensus-unsafe. One warning per unresolved episode remains visible, and finalization continues to fail closed until a trustworthy snapshot is available or legacy history is repaired through a protocol-safe process.
