# Visold V4 Bug-Fix Progress — Batch 6

Date: 2026-10-29
Baseline: Visold_V4_Batch5_Fixed

## Scope

This batch independently re-verified and fixed BUG-29 through BUG-33. It also re-ran prior regression suites and found one pre-existing rollback guard-order regression unrelated to BUG-29..33; that regression was reproduced on the untouched Batch-5 baseline and corrected separately.

## Dispositions

| Bug | Classification | Root cause | Fix | Verification |
|---|---|---|---|---|
| BUG-29 | Confirmed | `BLOCKFINALIZED` read mutable post-apply `Block.finalized` metadata. BFT gossip/depth finality can alter that flag after the block's execution, so replay could depend on local timing. | Fail-closed deterministic semantics: consume the operand and return 0 until finality is represented by consensus-committed execution data. This intentionally disables positive finality answers rather than consulting mutable gossip state. | Targeted real VVM execution test fails on Batch-5 (returns 1 from injected finalized flag) and passes on Batch-6 (returns 0). |
| BUG-30 | Confirmed | `RESOLVE_RESP` cached arbitrary peer-supplied result and `resolve_user_id()` could return it as a payment destination. | A peer response is cached only when this node already has a canonical local on-chain claim and the response's wallet/public key match it. Canonical fields always win; remote multiaddrs may refresh liveness only after ownership verification. | Two targeted P2P handler tests fail on Batch-5 and pass on Batch-6: unknown-name poisoning and canonical-owner override. |
| BUG-31 | Confirmed | For v=28, recovery used `x = r + N`. In the supported Ethereum-style v=27/28 domain, v carries only Y parity; x remains r. Same defect existed in channel recovery and ECRECOVER. | Use `x = r` and `v-27` only as Y-parity bit in both paths. Existing curve/subgroup/range checks remain. | Independent cryptography-generated v=28 vector: Batch-5 channel recovery fails; Batch-6 recovers the expected signer. ECRECOVER also returns nonzero canonical address word. |
| BUG-32 | Confirmed | Global `ecdsa_sign()` preserves Visold's historical double-SHA convention, while channel recovery consumes an already-finalized digest directly. Using the ordinary signer therefore cannot produce a valid channel signature. | Added explicit `ecdsa_sign_digest()` and `Wallet.sign_digest()` for already-finalized 32-byte channel digests. Global transaction/network signing is intentionally unchanged. | Batch-5 lacks the digest-sign API and fails. Batch-6 digest signatures recover the correct channel signer. A control test confirms ordinary wallet signing remains intentionally distinct. |
| BUG-33 | Confirmed | SQLite channel close/dispute/force-close read `rowcount` from `sqlite3.Connection`, which has no such attribute. The UPDATE could commit while the method returned False, breaking VM settlement logic. | Capture the cursor returned by `execute()`, read `cursor.rowcount`, record rollback journal state when updated, then commit and return the captured result. | Real Storage test exercises create→close and create→dispute→force-close. Batch-5 commits then reports failure; Batch-6 reports success and has the correct status. |

## Previous-fix re-audit result

The cumulative Batch 1–5 targeted regression suite was rerun after these edits and passed 46/46. No previously fixed audit finding regressed in this batch.

During adjacent-suite verification, one older rollback test failed on both untouched Batch-5 and the initial Batch-6 tree:

`test_rollback_rejects_targets_below_pruned_watermark_without_mutation`

Root cause: `Blockchain.rollback()` recomputed/scanned the finality fence before checking the rolling-prune watermark. A target below the prune watermark is already unrecoverable and should be rejected from metadata alone; the earlier finality scan can need historical block reads that pruning may have removed. The watermark guard was moved before the finality scan. The test then passed. This is recorded as a pre-existing regression correction, not as one of BUG-29..33.

## Exact verification commands and results

### Batch-6 targeted regressions — patched tree

`PYTHONPATH=. pytest -q tests/test_bugfix_batch6_20261029.py`

Result: **7 passed in 0.66s** (earlier run before packaging: 7 passed in 1.08s).

### Same regressions on untouched Batch-5 baseline

`PYTHONPATH=. pytest -q tests/test_bugfix_batch6_20261029.py`

Result: **6 failed, 1 passed**. The one pass is an intentional control proving ordinary wallet signing remains distinct from direct channel-digest signing.

Failures on baseline: BUG-29, both BUG-30 cases, BUG-31, BUG-32 digest-sign path, BUG-33.

### Previous Batch 1–5 regressions

`PYTHONPATH=. pytest -q tests/test_bugfix_batch1_20261029.py tests/test_bugfix_batch2_20261029.py tests/test_bugfix_batch3_20261029.py tests/test_bugfix_batch4_20261029.py tests/test_bugfix_batch5_20261029.py`

Result: **46 passed in 12.53s**.

### Pre-existing rollback guard-order regression

`PYTHONPATH=. pytest -q tests/test_hidden_bugfixes_20261006.py::test_rollback_rejects_targets_below_pruned_watermark_without_mutation`

Untouched Batch-5 result: **1 failed**.
After correction: **1 passed in 0.10s**.

### Adjacent audit / channel / VM regression suites

`PYTHONPATH=. pytest -q tests/test_audit_fixes.py tests/test_audit_findings_oct2026.py tests/test_confirmed_bug_fixes.py tests/test_hidden_bugfixes_20261006.py`

Result after rollback-order correction: **44 passed in 0.70s**.

Focused channel rollback-sensitive tests were also run before the full adjacent rerun and passed **8/8**.

### Compilation

`python -m compileall -q visold`

Result: **PASS**.

## Timeout / runner notes

One combined command that mixed the rollback-order test with all Batch 1–6 regression files timed out after printing six completed-test dots. It is **not counted as a pass**. The same components were then split into independent commands; rollback-order passed 1/1, Batch-6 passed 7/7, and Batch 1–5 passed 46/46.

## Protocol / compatibility notes

- BUG-29 intentionally chooses fail-closed deterministic behavior instead of pretending mutable BFT gossip metadata is consensus-safe. Positive `BLOCKFINALIZED` answers remain disabled until finality is committed in execution-consensus data.
- BUG-32 deliberately does not change the historical global signing convention. State-channel callers must use `Wallet.sign_digest()` (or `ecdsa_sign_digest()`) for the already-finalized channel digest.
- Network restart from scratch means no old-chain compatibility migration was required for these changes.

## Cumulative audit status after Batch 6

Verified fixed: BUG-1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 25, 26, 27, 28, 29, 30, 31, 32, 33, 45.

Count: **31 / 46**.

Still pending: BUG-12, BUG-18, BUG-24, BUG-34, BUG-35, BUG-36, BUG-37, BUG-38, BUG-39, BUG-40, BUG-41, BUG-42, BUG-43, BUG-44, BUG-46.

## Remaining risks

1. BUG-34 is adjacent to BUG-33 and remains open: a DISPUTED channel still needs verified higher-sequence-state replacement during the challenge window.
2. BUG-35 pending-deployment visibility remains open and is transaction-local VM state sensitive.
3. BUG-36 is a latent consensus-split risk on platforms without RIPEMD-160 and should be handled before heterogeneous deployment.
4. BUG-12, BUG-18 and BUG-24 still require explicit protocol/compatibility decisions; they must not be 'fixed' by weakening safety or silently redefining semantics.
5. Passing these targeted/adjacent suites does not establish the entire repository is bug-free.
