# Visold V4 Bug-Fix Progress — Batch 2 (2026-10-29)

## Scope

Batch 2 starts from the verified Batch-1 patched source, not from original V4. Batch-1 fixes for BUG-1, BUG-2, BUG-10, BUG-21 and BUG-45 were preserved and re-tested.

This batch processed **BUG-5, BUG-6, BUG-7 and BUG-8**.

## Summary

| Bug | Classification after current-source verification | Result | Root cause | Minimal fix | Verification |
|---|---|---|---|---|---|
| BUG-5 | Confirmed | FIXED | `accept_chain()` could enter `reorg()` with replacement blocks that had not passed state-independent integrity/PoW/linkage checks. Invalid PoW was discovered only after canonical rollback. Deep-fork work ranking likewise used un-preflighted peer blocks. | Added non-destructive fork preflight before reorg/work ranking: finite consensus numerics, strict replacement linkage, `integrity_check()`, actual PoW, and deterministic block-size bound. Full state/DAA validation remains in `apply_block()` after replacement parents exist. | Regression baseline calls `reorg()` on an unmined sealed fork; patched tree rejects `Invalid PoW` without calling `reorg()` and leaves tip unchanged. |
| BUG-6 | Confirmed | FIXED | `dry_run_state_root()` allowed direct calls with empty miner address. Reward simulation could mutate `""`, while account snapshot helpers intentionally omit falsey addresses, so restore missed it. | Reject invalid/empty miner address at dry-run entry, matching BUG-1 consensus invariant, before any simulation mutation. | Baseline accepts call and mutates; patched regression raises `ValueError` before mutation and confirms balances/issuance unchanged. |
| BUG-7 | Confirmed | FIXED | Replacement-loop `apply_block()` exceptions escaped `reorg()`. Existing unwind/L2 restore/old-chain replay ran only for `(False, msg)` returns. | Catch `BaseException` around each replacement `apply_block()` and convert it to the same failure path as an ordinary rejected replacement block. Existing critical-recovery handling remains authoritative if unwind/restore itself fails. | Injected `OverflowError` on second replacement block: baseline propagates exception; patched reorg returns failure, restores exact old tip/state root, and does not set critical recovery when restoration succeeds. |
| BUG-8 | Confirmed | FIXED for audited triggers | Transaction validation checked finiteness but not whether float→satoshi conversion fits the signed 64-bit consensus/storage domain. Coinbase amount had no finite/range check before `to_satoshi()`. Huge VVM gas price could similarly overflow conversion/accounting. | Added signed-64-bit satoshi-domain range checks for transaction amount/fee/gas_price, bounds total VVM gas fee, and validates coinbase amount before conversion. | Baseline: huge transfer and huge gas price validate; NaN coinbase raises. Patched: both transactions reject cleanly and NaN coinbase returns `(False, reason)`. |

## Intended invariants

### Fork admission before rollback
A peer fork may not trigger destructive rollback or cumulative-work ranking until each supplied replacement block passes checks that do not require replacement state to be canonical:
- strict index/prev-hash linkage;
- finite timestamp/difficulty;
- block/transaction cryptographic integrity;
- PoW against the block's committed difficulty;
- consensus block-size ceiling.

Full `validate_block()` is deliberately **not** run over the whole fork before rollback because block N+1 requires replacement block N to already be canonical for parent, MTP and branch-dependent DAA/state checks. Those checks remain in the tentative `apply_block()` sequence, with restoration on failure.

### Numeric domain
Consensus financial values must be finite and convertible to the signed 64-bit satoshi domain used by persistent balances/counters. Invalid numeric input is rejected, not allowed to raise through consensus validation.

### Reorg exception safety
Any replacement-block exception is semantically equivalent to a replacement-block rejection for reorg recovery. The old canonical suffix must either be restored exactly or the node must enter explicit critical-recovery mode.

## Source changes

- `visold/chain/blockchain.py`
  - BUG-8 coinbase finite/range validation before `to_satoshi()`.
  - BUG-6 dry-run empty-miner rejection before mutation.
  - BUG-7 exception containment in replacement apply loop.
  - BUG-5 cryptographic/PoW/linkage preflight for standard and deep fork paths.
- `visold/ledger/transaction.py`
  - BUG-8 signed-64-bit satoshi range checks for amount/fee/gas_price.
  - VVM total gas-fee range check.
- `tests/test_bugfix_batch2_20261029.py`
  - six targeted regression tests.

## Before/after regression evidence

The exact Batch-2 regression file was run against both the untouched Batch-1 baseline and the patched Batch-2 tree.

### Batch-1 baseline

```bash
cd /tmp
PYTHONPATH=/mnt/data/visold_v4_batch2_baseline/Visold_V4_Batch1_Fixed \
  pytest -q test_bugfix_batch2_20261029.py
```

Result: **6 failed in 1.72s**.

Observed failures:
- BUG-6: empty-miner dry run did not reject.
- BUG-8 huge transfer: `is_valid()` returned True.
- BUG-8 huge VVM gas price: `is_valid()` returned True.
- BUG-8 NaN coinbase: `validate_block()` raised `ValueError` from `to_satoshi()`.
- BUG-7: injected `OverflowError` escaped `reorg()`.
- BUG-5: spy recorded a `reorg()` call before invalid PoW was rejected.

### Patched Batch-2 tree

```bash
PYTHONPATH=. pytest -q tests/test_bugfix_batch2_20261029.py
```

Result: **6 passed in 1.69s**.

## Existing regression verification

### Batch-1 regressions

```bash
PYTHONPATH=. pytest -q tests/test_bugfix_batch1_20261029.py
```

Result: **8 passed in 2.99s**.

### Existing dry-run rejection suite

```bash
PYTHONPATH=. pytest -q tests/test_vsa_dry_run_rejections_20261014.py
```

Result: **3 passed in 0.37s**.

### Existing audit/security suites

```bash
PYTHONPATH=. pytest -q tests/test_audit_fixes.py tests/test_consensus_security_fixes.py
```

Result: **20 passed in 0.72s**.

### Existing failed-reorg restoration test

```bash
PYTHONPATH=. pytest -q \
  tests/test_vsa_reorg_consistency_20261014.py::test_failed_reorg_restores_the_old_chain_exactly
```

Result: **1 passed in 23.72s**.

### Compilation

```bash
python -m compileall -q visold tests/test_bugfix_batch2_20261029.py
```

Result: **PASS**.

## Timeouts / unresolved test-runner observations

These are **not passes**:

1. Full `tests/test_vsa_reorg_consistency_20261014.py` run printed one pass and then failed to terminate under the module cap.
2. `test_failed_restoration_marks_critical_recovery_and_refuses_writes` also failed to terminate under a 90-second isolated cap in this run sequence. This is recorded as a timeout/order/background-thread issue, not as success and not silently ignored.
3. The new targeted BUG-7 regression and the existing ordinary failed-reorg restoration test both complete and pass independently. The hanging critical-recovery test should be investigated in a later test-infrastructure/feature batch before declaring the entire reorg module green.

## Review notes / remaining risks

- BUG-5 preflight intentionally performs only state-independent checks before rollback. Expected DAA difficulty and state-root correctness are still checked by `apply_block()` after replacement parents become canonical. This avoids reintroducing the historical broken two-pass validation design.
- Deep-fork work is now ranked only after integrity+PoW preflight, so a self-reported difficulty must correspond to actual PoW. A dedicated branch-context DAA preflight without state mutation would be stronger but would require a separate branch-view abstraction and is not introduced casually here.
- BUG-8 fixes all audited triggers and adds a common numeric-domain boundary. This does not prove every arbitrary exception inside `validate_block()` has been transformed into a normal rejection; storage/runtime faults should still propagate rather than be mislabeled as peer-invalid data.
- BUG-7 catches `BaseException` only at the replacement application boundary so existing recovery machinery executes. It does not suppress restoration failures; those still trigger critical recovery.

## Persistent 46-finding status

**Fixed + verified through Batch 2:**
- BUG-1, BUG-2, BUG-5, BUG-6, BUG-7, BUG-8, BUG-10, BUG-21, BUG-45.

**Pending:**
- BUG-3, BUG-4, BUG-9, BUG-11 through BUG-20, BUG-22 through BUG-44, BUG-46.

No pending finding is considered fixed merely because the audit reports it.

## Recommended Batch 3

Process a small validation/networking batch:
1. BUG-3 — invalid REGISTER memo fallthrough.
2. BUG-4 — identity regex backslash acceptance.
3. BUG-9 — GET_CHAIN undefined `chain` / lost notification.
4. BUG-11 — rate-defection evidence canonical dedup.
5. If those are stable, BUG-13 or BUG-19 next because both affect transaction/mempool liveness.

Preserve all Batch-1 and Batch-2 tests and rerun them before packaging Batch 3.
