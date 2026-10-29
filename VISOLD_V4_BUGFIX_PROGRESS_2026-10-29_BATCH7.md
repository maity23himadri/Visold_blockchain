# Visold V4 Bugfix Progress — Batch 7

Date: 2026-10-29
Baseline: `Visold_V4_Batch6_Fixed.zip`
Scope: BUG-34, BUG-35, BUG-36, BUG-37, BUG-38

## Verification policy

This batch followed the same verify-before-modify policy used in prior batches. Each finding was re-traced in the Batch-6 source, patched narrowly, given a targeted regression, and then the same regression file was run against the untouched Batch-6 baseline. A test is not counted as evidence merely because it passes on the patched tree.

## Summary

| Bug | Disposition | Root cause | Fix | Targeted evidence |
|---|---|---|---|---|
| BUG-34 | Confirmed, fixed | `CHAN_DISPUTE` treated every already-DISPUTED channel as force-close-only; `Storage.raise_dispute()` accepted only OPEN | Before timeout, allow only strictly higher-sequence counterparty-signed challenge; storage UPDATE is conditional/atomic for OPEN or newer DISPUTED state; timeout settlement uses newest state | Baseline fails; patched passes. Regression verifies seq 5 -> seq 6 challenge and force-close pays 20/80 from seq 6 |
| BUG-35 | Confirmed, fixed | Same-transaction pending deployments were invisible to CALL and EXTCODE* lookups | Overlay `frame.pending_deployments` on committed contract/code lookup in internal CALL, EXTCODESIZE, EXTCODECOPY, EXTCODEHASH | Baseline fails; patched passes. Pending child executes SSTORE and all three EXTCODE queries see runtime before persistence |
| BUG-36 | Confirmed latent, fixed | Missing OpenSSL RIPEMD-160 silently substituted truncated SHA-256 | Added deterministic portable RIPEMD-160 fallback; no alternate digest is returned | Forced unavailable-algorithm branch matches standard `abc` and empty-string vectors; baseline returns truncated SHA-256 |
| BUG-37 | Confirmed, fixed | POST `getblockheaders` missing from slow-method token class | Added `getblockheaders` to slow RPC set | Real localhost RPC: two 10-token calls succeed, immediate third is HTTP 429; baseline allows third |
| BUG-38 | Confirmed, fixed with rollback handling | Monitor checked only positive supply jumps; prior-branch sample could contaminate post-rollback comparison | Two-sided absolute-delta threshold; track sampled height and rebaseline when height moves backward/equal | Baseline misses 10,000 VSD decrease; patched reports it and rebaselines on rollback |

## Design notes

### BUG-34
The fix does not permit arbitrary dispute replacement. A challenge must be submitted before the current timeout, have a sequence strictly greater than `dispute_seq`, conserve the channel deposit, and carry the counterparty signature for that exact state. The storage update repeats the sequence condition atomically, avoiding a check-then-update race. After the refreshed challenge window expires, force-close settles the latest accepted challenged balances.

### BUG-35
No pending deployment is persisted early. The existing transaction-local `pending_deployments` overlay remains rollback-safe; lookup paths now see that overlay before committed storage. This preserves the earlier deferred-deployment protection while making a just-created contract callable and introspectable in the same transaction.

### BUG-36
Returning failure only on nodes without RIPEMD-160 would still be runtime-dependent consensus behavior. The fallback therefore computes RIPEMD-160 itself. The OpenSSL implementation remains the fast path when available.

### BUG-38
Visold records burns by crediting `BURN_ADDRESS`, and ordinary transfers, fees, and L2 escrow movement conserve the balance-table sum. A large negative balance-table jump is therefore not an expected burn mechanism. The monitor still uses the existing `SUPPLY_INFLATION` anomaly enum because there is no separate supply-loss enum and the decision engine already treats this conservation alarm as critical; direction is retained in signed `delta_sat` evidence and description.

## Targeted before/after evidence

Patched Batch-7 command:

```bash
PYTHONPATH=. pytest -q tests/test_bugfix_batch7_20261029.py
```

Result: **5 passed in 1.04s** (final focused rerun remained green).

Untouched Batch-6 baseline, same regression file:

```bash
PYTHONPATH=. pytest -q tests/test_bugfix_batch7_20261029.py
```

Result: **5 failed**. All five tests detect the pre-fix behavior.

## Previous-fix regression verification

Command:

```bash
PYTHONPATH=. pytest -q \
  tests/test_bugfix_batch1_20261029.py \
  tests/test_bugfix_batch2_20261029.py \
  tests/test_bugfix_batch3_20261029.py \
  tests/test_bugfix_batch4_20261029.py \
  tests/test_bugfix_batch5_20261029.py \
  tests/test_bugfix_batch6_20261029.py \
  tests/test_bugfix_batch7_20261029.py
```

Result: **58 passed in 16.07s**.

Final focused Batch-6 + Batch-7 rerun after the last comment-only cleanup:

```bash
PYTHONPATH=. pytest -q tests/test_bugfix_batch7_20261029.py tests/test_bugfix_batch6_20261029.py
```

Result: **12 passed in 1.62s**.

## Adjacent test results

A broad combined adjacent command was attempted with a 300-second cap. It printed 33 completed tests and then timed out. **This is not counted as a pass.** The suites were split afterward.

Completed module results:

- `tests/test_audit_fixes.py`: **11/11 passed**
- `tests/test_confirmed_bug_fixes.py`: **9/9 passed**
- `tests/test_consensus_security_fixes.py`: **9/9 passed**
- `tests/test_vvm_selfdestruct_regressions.py`: **4/4 passed in 20.65s**
- `tests/test_rpc_server_load_regressions_20261025.py`: **10/10 passed in 4.77s**
- `tests/test_supply_diagnostics.py`: aggregate invocation did not finish under its cap, but all six tests passed when executed individually (**6/6**, each about 0.09-0.11s)

`tests/test_vvm_rollback_regressions.py` aggregate execution again displayed order/termination trouble. Individual results:

- `test_reverted_call_value_rollback_is_supply_neutral`: passed, 10.27s
- `test_successful_call_value_rollback_remains_exact`: passed, 4.08s
- `test_deploy_value_rollback_removes_contract_and_value`: passed, 7.09s
- `test_same_block_deploy_then_call_is_valid_and_rolls_back_exactly`: passed, 3.47s
- `test_absent_contract_call_is_still_rejected_when_no_prior_deploy_exists`: one isolated attempt timed out at 90s; immediate later rerun on patched Batch 7 passed in 2.67s; untouched Batch 6 passed the same isolated test in 3.30s. This is recorded as an intermittent/order-related runner issue, not a deterministic code pass/failure from the timed-out attempt.
- `test_name_collision_value_deploy_rollback_restores_exact_state_root`: passed, 6.09s

Compilation:

```bash
python -m compileall -q visold
```

Result: **PASS**.

## Files modified in Batch 7

- `visold/storage/storage.py`
- `visold/vm/engine.py`
- `visold/vm/precompiles.py`
- `visold/api/rpc_server.py`
- `visold/selfhealing/supply_monitor.py`
- `tests/test_bugfix_batch7_20261029.py`

## Cumulative disposition after Batch 7

Verified fixed:

`BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-19, BUG-20, BUG-21, BUG-22, BUG-23, BUG-25, BUG-26, BUG-27, BUG-28, BUG-29, BUG-30, BUG-31, BUG-32, BUG-33, BUG-34, BUG-35, BUG-36, BUG-37, BUG-38, BUG-45`

Count: **36 / 46**.

Still pending:

`BUG-12, BUG-18, BUG-24, BUG-39, BUG-40, BUG-41, BUG-42, BUG-43, BUG-44, BUG-46`

BUG-12 remains a governance-protocol design item; do not lower quorum to make it green. BUG-18 and BUG-24 remain compatibility/specification-sensitive and must be resolved explicitly rather than patched blindly.

## Remaining risks / limitations

1. Full-suite execution has not completed as one monolithic command; several repository tests exhibit order/background-thread termination behavior. Timeouts are recorded, not counted as passes.
2. Portable RIPEMD-160 is verified against standard empty-string and `abc` vectors and through the forced fallback branch, but has not been exercised on a real OpenSSL/FIPS runtime that lacks RIPEMD-160.
3. PostgreSQL state-channel SQL was source-updated consistently with SQLite, but the current environment only exercised the SQLite backend end-to-end.
4. BUG-38 remains a backstop based on sampled aggregate balances, not a replacement for exact per-block conservation assertions.
