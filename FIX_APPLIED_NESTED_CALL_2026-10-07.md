# Visold — Confirmed Hidden Bug Fix — 2026-10-07

## Confirmed defect fixed

A genuine rollback defect existed in `visold/vm/engine.py` inside `VVMEngine._internal_call()`.

A nested contract-to-contract `CALL` could execute `CHAN_OPEN` successfully, directly mutating persistent state and debiting the caller, and then execute `REVERT`. The child VM frame's buffered writes were discarded, but the direct state-channel/account side effects were not journaled at the child-call boundary. Therefore the reverted child could leave an OPEN channel and a permanent balance debit behind while the parent call itself succeeded.

## Fix

`_internal_call()` now creates a child-scoped state-channel journal around the child execution.

- Child success: the child journal is closed without restoration, so successful direct channel/account mutations remain part of the enclosing transaction.
- Child revert: the child journal is closed and restored, removing only the child's direct state-channel/account side effects.
- Parent/top-level revert: the enclosing journal remains responsible for restoring the entire transaction, including successful child mutations.
- The journal boundary is exception-safe and the reentrancy guard is released in `finally`.

No other production logic was changed for this fix.

## Regression coverage added

`tests/test_audit_fixes.py` now covers:

1. nested `CALL -> CHAN_OPEN -> REVERT` leaves no channel and no balance debit;
2. child rollback does not erase a successful direct channel mutation made earlier by the parent;
3. successful child channel mutation is retained when the parent succeeds;
4. successful child channel mutation is rolled back when the parent later reverts;
5. journal stack is empty after execution.

An additional manual 3-level nested-call test (`parent -> child -> grandchild`) was executed successfully.

## Verification

Passed:

- `tests/test_audit_fixes.py` — 11 passed
- `tests/test_hidden_bugfixes_20261006.py` — 16 passed
- `tests/test_audit_findings_oct2026.py` — 8 passed
- `tests/test_bugfixes_oct2026.py` — 7 passed
- `tests/test_confirmed_audit_repairs_20261006.py` — 6 passed
- `tests/test_confirmed_audit_repairs_20261007.py` — 4 passed
- `tests/test_confirmed_bug_fixes.py` — 9 passed
- `tests/test_consensus_security_fixes.py` — 9 passed
- `tests/test_l2_read_and_failed_apply_regressions_20261006.py` — 4 passed
- `tests/test_pgx_compat.py` — 7 passed
- `tests/test_pgx_rollback_cleanup.py` — 2 passed

Also passed:

- `python -m py_compile` / `compileall` on `visold`, `tests`, and `tools`
- `tools/check_architecture.py` — architecture checks OK
- direct nested batch-proxy reproduction — PASS
- 3-level nested journal reproduction — PASS

## Test-suite limitation

A repository-wide `pytest` invocation did not complete because some pre-existing blockchain/process tests do not terminate within the execution window in this environment. The timeout itself was not treated as a product failure. The affected long-running tests were run separately where practical; the newly fixed nested-CALL behavior and its regression coverage completed successfully.

## Scope

This archive contains the confirmed bug fix above. No unverified suspicion was promoted to a production change.
