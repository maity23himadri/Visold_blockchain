# Visold V10 — Consensus/Finality Fix Report

**Date:** 2026-10-28  
**Scope:** C-01 through C-04 from the supplied consensus audit, plus a related in-memory finality-fence rollback invariant discovered while hardening the failure path.

## Summary

The patch changes `visold/chain/blockchain.py` and adds `tests/test_consensus_finality_audit_regressions_20261028.py`. It does not intentionally change P2P, sync, mining, wallet, transaction-validation, or block-reward behavior.

### C-01 — Embedded vote accounting and equivocation

**Fixed.** Before embedded votes contribute stake, the implementation reads durable vote history for the same height. Every authenticated embedded vote is recorded inside the surrounding block transaction. If a validator already has a vote for a different block hash at that height, the new vote remains stored as equivocation evidence but is not counted toward quorum. The resulting slashing/evidence work is deferred until the enclosing block transaction commits; if block application is rejected or rolls back, the queued penalty is discarded along with the vote write.

**Trigger covered:** a block contains a valid embedded signature from validator A, while durable history already contains A's valid vote for another hash at the same height. A's conflicting stake must not help finalize the new block.

### C-02 — Finalized-block fast path

**Fixed.** `add_validator_sig()` no longer returns success merely because the target block is finalized before it checks vote history. It authenticates the signature and identity, checks for a same-height conflicting vote, durably records the second signed hash as evidence, and applies the common equivocation policy. An identical repeated vote remains idempotent. A non-conflicting valid vote does not bypass durable accounting just because the target has finalized.

**Trigger covered:** a validator submits a valid signature for a finalized block when the durable history already contains its vote for another block hash at that height. The call must detect the conflict and must not return success through a premature fast path.

### C-03 — PoW bootstrap finality with 0–2 validators

**Fixed.** The PoW-bootstrap branch is selected by the protocol activation threshold (`validator_count < MIN_VALIDATORS_FOR_BFT`), rather than only by whether the validator list is empty. The configured `BOOTSTRAP_POW_FINALITY_DEPTH` is therefore used with zero, one, or two active validators. The timeout-based degraded-participation fallback remains for chains where BFT is active but votes stall.

**Trigger covered:** `MIN_VALIDATORS_FOR_BFT = 3`, the chain has 1 or 2 active validators, BFT quorum is unavailable, and the tip reaches the bootstrap confirmation depth before the governance timeout. The depth rule now applies directly. Regression coverage also checks 0 and 3 validators.

**Configuration note:** with the supplied defaults, bootstrap depth and governance timeout are both 20, so the original reported additional delay was not reproduced under that exact configuration. The code-policy mismatch still existed when those settings differed and is now removed.

### C-04 — Manual rollback and irreversible finality

**Fixed under the strict-finality policy.** Before changing state, `rollback()` rebuilds the finality fence from the canonical chain. It rejects a target below the highest finalized height and fails closed if the canonical fence cannot be verified. Rolling back to the finalized height, thereby removing only an unfinalized suffix, remains allowed. After a successful rollback, the fence is recomputed again.

**Trigger covered:** height 1 is finalized, the chain tip is above height 1, and the operator requests `rollback(0)`. The rollback is rejected without deleting finalized history, even if the in-memory fence had been stale. An attempted rollback that only removes the unfinalized suffix is still accepted.

**Chosen policy:** no emergency override across finality is added. An override would require a separately specified administrative recovery protocol; silently deleting finalized history is not safe.

### Related fix — failed-apply finality reconciliation

If block application advances the in-memory finality fence and then fails/rolls back, the fence is reconciled against canonical storage. The failed candidate's `finalized` flag is cleared unless that exact block hash is present canonically. The common rejection path avoids a full chain scan when the fence did not change. Deferred equivocation entries from failed nested attempts are discarded without deleting events already queued by a parent transaction.

## Regression tests added

The new test file contains 10 tests covering:

1. embedded-vote conflict detection, durable history, quorum exclusion, and slashing;
2. rejected block does not leave embedded vote rows or finality changes;
3. valid conflicting live vote is detected after finalization;
4. bootstrap depth with 0, 1, 2, and 3 validators;
5. rollback cannot cross the finalized fence, even when the cached fence is stale;
6. rollback to genesis where genesis is the only finalized block;
7. rollback to the finalized height while removing only an unfinalized suffix;
8. penalty/evidence is discarded if block transaction rolls back;
9. automatic evidence is applied after the corresponding block transaction commits;
10. failure after BFT finalization restores the in-memory fence and candidate flag.

## Verification performed

- `python -m compileall -q visold tests` — passed.
- Targeted combined suite: **45 passed, 3 warnings** in 1.56 seconds. Suites included the new audit regressions, consensus finality security fix tests, consensus security fixes, audit findings, block-gossip signature-cache regressions, sync import optimizations, cooperative mining yield, and TUI rollback/bootstrap safety.
- Additional targeted check: **12 passed** in 2.10 seconds, including the new audit regressions, orphaned-validator-vote history, and SQLite transaction rollback on process-death simulation.

The three warnings are Python's `multiprocessing` deprecation warning about `fork()` from a multithreaded process in the existing sync-optimization tests; they are not test failures.

**Limitations:** the full `test_consensus_hardening_regressions.py` run and separate pruning/VVM rollback integration runs did not complete within the execution limits. They are not being reported as passing. The entire repository suite has not been certified, and passing targeted tests cannot prove consensus code bug-free.

## Files changed

- Modified: `visold/chain/blockchain.py`
- Added: `tests/test_consensus_finality_audit_regressions_20261028.py`
- Added: this report

No changes were made to existing sync, networking, or mining implementation files.
