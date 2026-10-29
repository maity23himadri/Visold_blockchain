# Visold V4 Bug-Fix Progress — Batch 4

Date: 2026-10-29
Baseline: `Visold_V4_Batch3_Fixed.zip`

## Scope

This batch did two things before declaring any new fix complete:

1. Re-audited the 15 findings previously claimed fixed in Batches 1–3 by reviewing the actual source diffs against original V4 and rerunning their regression suites.
2. Fixed the next focused set: BUG-14, BUG-15, BUG-16, BUG-17, BUG-20, and BUG-22.

The re-audit found two prior fixes that were incomplete. They are explicitly corrected here rather than silently retaining the earlier completion claim.

## Previous-fix re-audit corrections

### BUG-5 — previous fix was incomplete; corrected in Batch 4

**Problem in Batch 2/3 fix:** fork preflight checked integrity, linkage and `validate_pow()` against the peer-supplied difficulty, but did not recompute the canonical expected DAA for the replacement branch before rollback. An attacker could therefore claim a very low difficulty, satisfy cheap PoW, reach `reorg()`, and only fail later when normal block validation recomputed the real difficulty.

**Batch-4 correction:** added a read-only fork-history overlay used by `_preflight_peer_branch()`. For each replacement block it now recomputes the expected difficulty from canonical history through the common ancestor plus the already-preflighted replacement prefix. Before any rollback it checks:

- strict index/linkage,
- finite timestamp/difficulty,
- block integrity,
- canonical expected difficulty,
- PoW at that difficulty,
- block-size limit,
- MTP/future timestamp rule.

The same preflight is used before deep-fork cumulative-work ranking.

**Regression:** a low-claimed-difficulty branch that satisfied its own cheap PoW reached reorg on Batch 3; Batch 4 rejects it with a difficulty mismatch and `reorg()` is never called.

### BUG-11 — previous fix was incomplete; corrected in Batch 4

**Problem in Batch 3 fix:** dedup identity was correctly changed to `(miner, window_start, window_end)`, but the ID was inserted into `_seen_evidence` before independent verification. A bad packet could therefore poison that canonical window and make a later genuine packet look like a duplicate.

**Batch-4 correction:**

- early duplicate lookup is read-only,
- invalid evidence never enters `_seen_evidence`,
- after complete independent verification the code acquires the lock again, rechecks dedup, records the verified ID, and increments the offense counter atomically,
- deterministic oldest-first retention remains intact.

**Regression:** on Batch 3 an invalid ratio followed by valid evidence for the same window was reported as duplicate; Batch 4 processes the genuine evidence exactly once.

## New findings fixed in this batch

| Finding | Classification | Root cause | Fix | Verification |
|---|---|---|---|---|
| BUG-14 | Confirmed | Gossip dedup hashed the whole envelope, so TTL and ignored extra fields changed identity; L2 duplicate relay could amplify | L2 dedup now hashes canonical signed payload fields only; generic dedup excludes mutable TTL; sequencer-known duplicate is not re-relayed | Baseline relayed three variants; patched relays one |
| BUG-15 | Confirmed | JSON values that parsed but were not objects raised `AttributeError`; NaN/Infinity raised `ValueError`; neither got invalid-message score | Explicit dict check with peer score/disconnect; non-finite JSON parse failures are handled as malformed input and scored | `[]` and NaN frames receive `PEER_SCORE_INVALID_MSG`; no unexpected-exception path |
| BUG-16 | Confirmed | NaN claimed ratio made tolerance arithmetic NaN and skipped the comparison | Reject non-finite claimed ratio during schema validation | NaN, +Inf and -Inf all reject; offense count remains zero |
| BUG-17 | Confirmed | `hmac.compare_digest(str, str)` raises on non-ASCII text | Compare UTF-8 bytes instead | Real threaded RPC request with `Bearer café` receives HTTP 401; Batch-3 baseline drops connection with TypeError |
| BUG-20 | Confirmed latent | GPU fallback methods referenced `max_hps_provider` not in their scope/signature | Add the optional parameter to CUDA/OpenCL methods and pass it from dispatcher to CPU fallback | Forced NumPy-unavailable CUDA and OpenCL fallback both preserve `max_hps` and provider |
| BUG-22 | Confirmed | Wire `l2_tx_id` was trusted and not bound to signed transaction content | Always compute canonical ID; if a provided wire ID differs, constructor/from_dict rejects | Forged copied ID raises; honest serialization round-trip preserves canonical ID |

## Regression evidence

### Exact Batch-4 tests

Patched tree:

```text
PYTHONPATH=. pytest -q tests/test_bugfix_batch4_20261029.py
10 passed in 0.75s
```

Untouched Batch-3 baseline with the same test file:

```text
10 failed in 0.80s
```

All ten tests therefore discriminate the buggy baseline from the corrected tree.

### Previous-batch regressions after Batch-4 changes

```text
PYTHONPATH=. pytest -q \
  tests/test_bugfix_batch1_20261029.py \
  tests/test_bugfix_batch2_20261029.py \
  tests/test_bugfix_batch3_20261029.py \
  tests/test_bugfix_batch4_20261029.py
```

Result: **38 passed in 4.08s**.

Two old BUG-5 tests initially failed only because they asserted the older rejection stage. Their safety assertions were retained. The tests were corrected as follows:

- the dedicated invalid-PoW regression now uses the correct branch difficulty and deliberately chooses a nonce/hash that fails PoW, so it still specifically proves PoW preflight;
- tests that deliberately claim `MAX_DIFFICULTY` now assert the stronger, earlier canonical DAA mismatch rejection.

No production validation was weakened to satisfy these tests.

### Adjacent existing suites

Run independently to avoid known grouped-suite/order issues:

```text
pytest -q tests/test_audit_findings_oct2026.py
# 8 passed in 0.41s

pytest -q tests/test_confirmed_bug_fixes.py
# 9 passed in 0.15s

pytest -q tests/test_consensus_security_fixes.py
# 9 passed in 0.18s

pytest -q tests/test_l2_read_and_failed_apply_regressions_20261006.py
# 4 passed in 0.12s

pytest -q tests/test_bootstrap_rate_limit_backpressure.py
# 2 passed in 0.10s

pytest -q tests/test_hashrate_governor_adaptive_20261026.py
# 15 passed in 1.38s

pytest -q tests/test_rpc_server_load_regressions_20261025.py
# 10 passed in 4.76s

pytest -q tests/test_tcp_eof_diagnostics_20261022.py
# 19 passed in 0.16s

python -m compileall -q visold tests/test_bugfix_batch4_20261029.py
# PASS
```

### Timeout / non-pass record

A large combined command containing multiple existing modules was attempted with a 240-second cap. It printed five completed tests and then timed out. It is **not counted as a pass**. The same relevant modules were subsequently run separately with the results above.

## Review of the other previous fixes

The source-level re-audit did not find another demonstrated incorrect patch among BUG-1, BUG-2, BUG-3, BUG-4, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-13, BUG-19, BUG-21, and BUG-45 in this session. Their Batch regression tests all still pass. This is not a claim that those subsystems are globally bug-free; it means no new contradiction was established during this focused re-audit.

## Cumulative disposition after Batch 4

Verified fixed in the current patched line:

`BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-19, BUG-20, BUG-21, BUG-22, BUG-45`

Total: **21 / 46**.

Still pending:

`BUG-12, BUG-18, BUG-23, BUG-24, BUG-25, BUG-26, BUG-27, BUG-28, BUG-29, BUG-30, BUG-31, BUG-32, BUG-33, BUG-34, BUG-35, BUG-36, BUG-37, BUG-38, BUG-39, BUG-40, BUG-41, BUG-42, BUG-43, BUG-44, BUG-46`

## Remaining risks / limits

- BUG-12 requires a real authenticated cross-node emergency-governance vote design; changing quorum from 2 to 1 would be a garbage fix and remains deliberately unmodified.
- BUG-18 is a legacy hash-compatibility policy issue and must not be removed blindly.
- GPU kernels remain disabled (`GPU_KERNELS_VERIFIED = False`); BUG-20 is fixed at the fallback interface, not a claim that GPU kernels are production-ready.
- The full repository suite has not been declared green. Only the exact commands and completed modules above are counted.

