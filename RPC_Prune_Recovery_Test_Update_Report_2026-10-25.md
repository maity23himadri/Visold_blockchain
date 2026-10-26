# Visold pruning/recovery test update and nonce-determinism fix

Date: 2026-10-25

## Why the original test failed

`tests/test_pruned_resync_integration.py` previously expected block 1 to be pruned at height 11 with a 3-block window while snapshot generation was disabled and the chain never reached a committed bootstrap snapshot boundary. Under the current safety policy, the pruner must fail closed when no servable/committed snapshot anchor exists. The old assertion tested the removed raw-window-only behavior, not the current recoverability contract.

## Changes in this patch

1. Split that scenario into two explicit cases:
   - no committed anchor -> no block-body deletion;
   - actual consensus-built/committed bootstrap anchors -> safe pruning, recent full-body sync succeeds, stale sync that needs a pruned block fails, and fresh full-history sync fails without partial application.
2. The commitment-backed test uses the real `ConsensusEngine` candidate builder at a test-only interval of 4 blocks and activates commitments at height 5. It does not bypass snapshot commitments with hand-built coinbase transactions.
3. The integration exposed a separate real issue: SQLite `restore_accounts()` can materialize `account_nonces` rows with nonce 0 for addresses that had no such row before `dry_run_state_root()`. The resulting local-only row was included in bootstrap snapshot serialization, so a different node could compute a different commitment digest. `dry_run_state_root()` now records and restores the exact SQLite nonce-row presence/value around its non-mutating simulation. Production pruning policy and snapshot commitment verification were not weakened.

## Verification performed

Passed, on the patched sandbox source:

- Python compilation of `visold/chain/blockchain.py` and `tests/test_pruned_resync_integration.py`.
- Targeted RPC/load, shutdown, port wiring, selected dry-run regression, pruning/reconnect, and snapshot failover tests: **36 passed in 5.07 seconds**.
- The revised integration tests specifically verify both no-anchor fail-closed behavior and actual committed-anchor pruning/recovery; all 2 passed within the 36-test run.
- Earlier RPC fix tests on this source: 23/23 passed; the updated targeted combined run includes those RPC tests.

Not fully verified:

- `tests/test_prune_rollback_recoverability_invariant_20261024.py` exceeded the 180-second sandbox command limit after showing one progress dot; no pass claim is made for the complete file.
- The complete project suite and a real Termux/Android run remain outstanding.

## Files changed

- `visold/chain/blockchain.py`
- `tests/test_pruned_resync_integration.py`

No production pruning cutoff, rollback fence, commitment requirement, or sync fail-closed condition was relaxed.
