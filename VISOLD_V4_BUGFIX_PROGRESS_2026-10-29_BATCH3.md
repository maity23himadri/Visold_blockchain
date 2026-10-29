# Visold V4 Bug-Fix Progress — Batch 3

Date: 2026-10-29
Baseline: `Visold_V4_Batch2_Fixed.zip`

## Scope

This batch independently re-verified and fixed BUG-3, BUG-4, BUG-9, BUG-11, BUG-13, and BUG-19. It preserves the verified fixes from Batches 1–2.

## Dispositions

| Bug | Classification | Root cause | Fix | Verification |
|---|---|---|---|---|
| BUG-3 | Confirmed | `Transaction.is_valid()` allowed any positive-value `TYPE_REGISTER` memo to fall through generic validation; apply-time code later interpreted unknown roles as `none` | `TYPE_REGISTER` now accepts only `miner`, `investor`, `none`, or a syntactically valid identity claim; malformed `identity:` and unknown role strings fail closed | Targeted malformed memo cases fail on Batch-2 baseline and pass after patch; valid miner/investor controls remain accepted |
| BUG-4 | Confirmed | Identity regex character class accidentally included literal backslash | Tightened regex to `[a-z0-9_.\-]` | `identity:ali\\ce` rejected; `identity:alice` accepted |
| BUG-9 | Confirmed | GET_CHAIN post-send logging referenced undefined `chain`; broad `except` swallowed the NameError and skipped notification | Count served blocks from `response["blocks"]`; isolate logging from sync notification | Real `_handle_message` branch with lightweight P2P harness sends 3 blocks and emits notification count 3 |
| BUG-11 | Confirmed | Evidence ID included unverified `actual_wins`; retention used an unordered `set` as if insertion-ordered | Dedup identity is `(miner, window_start, window_end)` only; `OrderedDict` provides deterministic oldest-first bounded retention | Replay with changed `actual_wins` is duplicate and offense count stays 1; baseline increments offense count |
| BUG-13 | Confirmed | Expected nonce used `chain_nonce + len(pending_set)`, assuming pending nonces are contiguous | Compute first free nonce starting at chain nonce by scanning actual pending nonce set | After removing nonce 0 from pending `{0,1,2}`, nonce 0 can be resubmitted while 1 and 2 remain pending |
| BUG-19 | Confirmed | Role preflight and mempool admission reserved stake but not the new REGISTER fee; candidate rejection left stale tx resident | Miner/investor preflight requires stake+fee; mempool admission reserves stake+fee; candidate builder evicts an unaffordable REGISTER that later becomes invalid | 10.05 VSD cannot submit 10 VSD miner registration; stale admitted REGISTER is evicted after balance falls; baseline reproduces all failures |

## Files changed in Batch 3

- `visold/ledger/transaction.py`
- `visold/network/p2p.py`
- `visold/consensus/rate_defection.py`
- `visold/mempool/pool.py`
- `visold/chain/roles.py`
- `visold/chain/consensus_engine.py`
- `tests/test_bugfix_batch3_20261029.py`
- `tests/test_audit_findings_oct2026.py` (two BUG-5-era assertions updated to require preflight PoW rejection rather than the obsolete rollback-first failure timing)

## Exact verification commands and results

### New Batch-3 regression suite

```bash
PYTHONPATH=. pytest -q tests/test_bugfix_batch3_20261029.py
```

Patched result: **14 passed**.

The same final regression file was copied unchanged to the untouched Batch-2 baseline:

```bash
PYTHONPATH=. pytest -q tests/test_bugfix_batch3_20261029.py
```

Baseline result: **13 failed, 1 passed**. The single pass is the valid REGISTER control; every defect-detection assertion fails on the unpatched baseline.

### Prior-batch and adjacent focused suites

```bash
PYTHONPATH=. pytest -q \
  tests/test_bugfix_batch1_20261029.py \
  tests/test_bugfix_batch2_20261029.py \
  tests/test_audit_fixes.py \
  tests/test_consensus_security_fixes.py \
  tests/test_bootstrap_rate_limit_backpressure.py
```

Result: **36 passed in 14.09s**.

```bash
PYTHONPATH=. pytest -q tests/test_audit_findings_oct2026.py
```

Initial result after Batch-2 BUG-5 fix: **6 passed, 2 failed** because two tests explicitly required the obsolete rollback-first error string (`Reorg apply block ...`). Their state-safety intent was retained and assertions were updated to require the stronger `Fork block N: Invalid PoW` preflight behavior. Final result: **8 passed in 0.40s**.

```bash
PYTHONPATH=. pytest -q tests/test_confirmed_bug_fixes.py
```

Result: **9 passed in 0.15s**.

```bash
PYTHONPATH=. pytest -q tests/test_consensus_hardening_regressions.py
```

Result: **TIMEOUT after 180s**, with four tests printed as completed (`....`) before termination. This is **not counted as a pass**. It remains an unresolved long/order-dependent suite issue and should be isolated further in a later batch.

```bash
python -m compileall -q visold tests
```

Result: **PASS**.

## Important engineering notes

1. BUG-3 was fixed at transaction validation, not by changing apply-time fallback semantics alone. Invalid REGISTER transactions now cannot enter consensus as valid transactions.
2. BUG-11 still retains the existing independent local-window verification. This patch changes only identity/dedup and deterministic retention; it does not weaken the consecutive-window safeguard.
3. BUG-13 keeps later pending transactions after a hole is created, but re-opens the missing nonce for resubmission. This preserves pending user intent while restoring liveness.
4. BUG-19 now has three layers of protection: UI/RoleManager preflight, mempool admission, and candidate-time eviction if state changes after admission.
5. The two updated `test_audit_findings_oct2026.py` assertions were not weakened. They previously asserted that an invalid fork must reach destructive reorg before rejection, which directly contradicted the verified BUG-5 fix. They now require rejection before rollback and retain the surrounding canonical-state invariants.

## Cumulative verified fixes after Batch 3

BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-13, BUG-19, BUG-21, BUG-45.

Total: **15 / 46 findings with a completed fix disposition in the current patched line**.

## Pending findings

BUG-12, BUG-14, BUG-15, BUG-16, BUG-17, BUG-18, BUG-20, BUG-22 through BUG-44 except BUG-45, and BUG-46.

## Remaining risks / limitations

- `tests/test_consensus_hardening_regressions.py` still does not complete as a module within 180 seconds. Four tests completed before timeout; the rest are not verified by that command.
- The complete repository-wide suite has not been declared green. Verification continues in manageable focused groups, per the audit requirements.
- BUG-12 is a governance design/integration issue and should not be patched as a trivial quorum-number change.
- BUG-18, BUG-24, BUG-32, BUG-38 and BUG-40 retain protocol/specification decisions that need explicit handling rather than blind compatibility changes.
