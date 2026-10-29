# Visold V4 Bug-Fix Progress — Batch 5

Date: 2026-10-29
Baseline: `Visold_V4_Batch4_Fixed.zip`

## Scope

This batch independently re-verified and fixed BUG-23, BUG-25, BUG-26, BUG-27 and BUG-28. It also reran the cumulative Batch 1–4 regressions to check that earlier fixes were not test-only or regressed by the new work.

## Dispositions

| Bug | Disposition | Root cause | Fix | Verification |
|---|---|---|---|---|
| BUG-23 | Confirmed | Slash evidence used an ordered `(A,B)` ID, while the slashed check and `Storage.slash()` mutation were a check-then-act sequence outside one atomic critical section. Reversed evidence could be accepted concurrently and the stake reduction could be applied twice. | Canonicalize the conflicting-hash pair; hold the protocol lock across eligibility + mutation + evidence record; make `Storage.slash()` a conditional one-row update and return whether it actually changed state. | Forced concurrent reversed-evidence regression; real SQLite idempotence test. Untouched Batch 4 fails, Batch 5 passes. |
| BUG-25 | Confirmed | CREATE address material lacked a cross-transaction identity; the execution-local sequence resets every transaction. CREATE2 never rejected an occupied destination. | CREATE now commits to the top-level execution/transaction identity plus the per-execution sequence, making different transactions produce different children without adding a new persistent nonce/rollback surface. CREATE and CREATE2 both reject occupied/nonzero-nonce/pending destinations. | Real VVM factory calls across two transactions; occupied CREATE2 storage remains unchanged. Baseline fails, patched passes. |
| BUG-26 | Confirmed | Nested `deploy()` reset `origin` to the factory because `sender=f.address`. | `deploy()` accepts an explicit origin; CREATE/CREATE2 pass the parent frame's original EOA. CALLER remains the factory. Execution identity is propagated through nested frames. | Real constructor stores ORIGIN and TXSENDER; both equal the top-level wallet word. Baseline stores the factory word. |
| BUG-27 | Confirmed | CREATE/CREATE2 computed child gas before deducting the init-code fee, and silently clamped parent overdraw to zero. | Deduct the init-code fee first, then compute the EIP-150-style child budget. If returned child usage exceeds the parent's remaining budget, raise out-of-gas rather than silently clamp. | Instrumented real VM frame verifies exact 64-byte init-code budget. Baseline fails. |
| BUG-28 | Confirmed | `Storage.get_validators()` did not exist. Five SHBS paths converted the resulting exception into false membership, empty participation, invented economics, or a fake one-validator quorum. | Add `Storage.get_validators()` backed by the exact canonical-tip BFT validator snapshot. Missing snapshot is a hard safety error, not `[]`. Membership/quorum/monitor/decision paths fail closed and log CRITICAL instead of inventing defaults. | Real three-validator snapshot + cryptographically signed rollback votes reaches 2/3 quorum; missing snapshot does not auto-approve. Baseline fails. |

## BUG-25 design note

The audit suggested a persistent per-contract creation counter. That would require new durable state plus exact block-failure, canonical-reorg, snapshot and dry-run rollback handling. Because the network will restart from genesis and Visold already derives deployment addresses from transaction material, this batch uses the top-level transaction/execution identity plus an execution-local CREATE sequence. This preserves deterministic replay of the same transaction, guarantees distinct CREATE addresses across distinct transactions absent a hash collision, preserves distinct repeated CREATE calls within one transaction, and introduces no new persistent rollback state. CREATE2 keeps its deterministic salt/code-hash address and now rejects occupied targets.

## Previous-fix quality recheck

No new garbage/incomplete prior fix was found in this batch. The risky prior fixes (including BUG-5, BUG-11 and BUG-22) were exercised through the cumulative regression suites. Batch 4 had already corrected two incomplete prior fixes (BUG-5 expected-difficulty preflight and BUG-11 verify-before-seen); those corrections remain green here.

## Exact verification results

### New Batch-5 regressions on patched tree

`PYTHONPATH=. pytest -q tests/test_bugfix_batch5_20261029.py`

Result: **8 passed in 0.44s**.

### Same Batch-5 regressions on untouched Batch-4 baseline

`PYTHONPATH=. pytest -q tests/test_bugfix_batch5_20261029.py`

Result: **8 failed**. Every new regression detects the pre-fix behavior.

### Cumulative Batch 1–5 regressions

`PYTHONPATH=. pytest -q tests/test_bugfix_batch1_20261029.py tests/test_bugfix_batch2_20261029.py tests/test_bugfix_batch3_20261029.py tests/test_bugfix_batch4_20261029.py tests/test_bugfix_batch5_20261029.py`

Result: **46 passed in 14.35s**.

### Existing adjacent suites

`PYTHONPATH=. pytest -q tests/test_audit_fixes.py tests/test_confirmed_bug_fixes.py tests/test_consensus_finality_audit_regressions_20261028.py`

Result: **30 passed in 0.56s**.

`PYTHONPATH=. pytest -q tests/test_audit_findings_oct2026.py`

Result: **8 passed in 0.45s**.

`PYTHONPATH=. pytest -q tests/test_consensus_hardening_regressions.py::test_ignored_register_rollback_does_not_unstake_or_unslash tests/test_consensus_hardening_regressions.py::test_orphaned_validator_votes_remain_visible_by_height`

Result: **2 passed in 10.99s**.

The six tests in `test_vvm_rollback_regressions.py` were also run individually after the grouped module run failed to terminate; all six completed successfully individually. The remaining selected `test_vvm_selfdestruct_regressions.py` and missing-validator-snapshot tests completed in the subsequent focused command (9 passed in 31.53s for that focused group).

### Compilation

`python -m compileall -q visold tests/test_bugfix_batch5_20261029.py`

Result: **PASS**.

## Timeouts / environment issues

1. The first cumulative invocation without `PYTHONPATH=.` failed during collection with `ModuleNotFoundError: visold`. This was a test-environment invocation error, not a product-code failure. Re-running from the repository root with `PYTHONPATH=.` produced the results above.
2. A grouped run containing `test_vvm_rollback_regressions.py`, `test_vvm_selfdestruct_regressions.py` and `test_missing_validator_snapshot_warning_dedup_20261028.py` did not terminate under its timeout after printing completed tests. It is **not counted as a pass**. The relevant tests were then isolated; the rollback cases all completed successfully individually and the remaining focused group passed.

## Files changed

- `visold/consensus/slashing.py`
- `visold/storage/storage.py`
- `visold/vm/frame.py`
- `visold/vm/engine.py`
- `visold/selfhealing/rollback.py`
- `visold/selfhealing/monitors.py`
- `visold/selfhealing/decision.py`
- `tests/test_bugfix_batch5_20261029.py`

## Cumulative completed findings

Verified fixed in the current code line:

**BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-19, BUG-20, BUG-21, BUG-22, BUG-23, BUG-25, BUG-26, BUG-27, BUG-28, BUG-45**

Total: **26 / 46**.

Still pending: **BUG-12, BUG-18, BUG-24, BUG-29–44 except BUG-45, and BUG-46**.

## Remaining limitations / risks

- PGX/PostgreSQL execution of the new conditional `Storage.slash()` path was source-reviewed but not exercised against a live PostgreSQL backend in this environment.
- SHBS now deliberately fails closed when the canonical-tip validator snapshot is missing. That can disable self-healing rollback until snapshot integrity is restored; it is preferable to auto-approving or fabricating a validator set.
- BUG-12 remains a design-level governance propagation/authentication problem and should not be "fixed" by reducing quorum.
- BUG-18 and BUG-24 require explicit compatibility/specification decisions before changing consensus/VM semantics.
