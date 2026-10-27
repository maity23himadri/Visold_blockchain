# V4 Liveness and Mining Telemetry Fix Report
Date: 2026-10-27

## Summary

Applied a targeted fix to the V4 archive that already contains the Incoming Transfer Inbox feature. The changes address the reproduced liveness-to-breaker false trip and the measured multi-thread hashrate overstatement for Visold's short canonical block-header preimage. Consensus validation, block hash construction, transaction admission, difficulty rules, and finality rules were not changed.

## Changes

### 1. Short-header CPU mining no longer pretends that GIL-bound workers are parallel

Files: `visold/mining/parallel_miner.py`, `visold/mining/workers.py`, `visold/mining/engine.py`, `visold/cli/interactive.py`.

- The miner measures the minimum canonical header input length (nonce `0`, current candidate timestamp) before choosing the effective CPU worker count.
- For inputs of 2047 bytes or less, it uses one effective worker. `hashlib.sha256()` does not release the GIL for those short calls, so multiple Python workers serialize, add scheduling overhead, and produce independently timed rates that must not be summed as true aggregate throughput.
- Inputs larger than 2047 bytes may still use the configured worker count, because the exact minimum input for that candidate exceeds the GIL-release threshold.
- The miner logs this expected fallback once per instance at **INFO** level (not WARNING), and reports both `cpu_threads` (effective) and `configured_cpu_threads` (configured). This prevents a normal startup diagnostic from appearing as a red warning. CLI output displays the effective worker count rather than implying that the configured count is necessarily parallel.
- Per-block logs no longer compare whole-attempt wall-clock throughput to only the initial governor cap. The cap may change during an attempt, so the log now calls it `initial_cap` and separately records the sampled live-cap average/range. This removes a misleading `measured/cap` ratio when the live cap changes dynamically.

This is a conservative correctness fix, not a claim that Python-only Visold hashing is now multi-core parallel. A future native SHA-256 loop that releases the GIL is the appropriate route to genuine CPU parallelism without distorting rate telemetry.

### 2. Liveness remains visible but cannot trip the read-only breaker by itself

Files: `visold/resilience/safety_invariants.py`, `visold/state/engine.py`, `visold/resilience/panic_breaker.py`.

- A no-height-progress condition still appears as `LIVENESS VIOLATION` in the invariant report.
- One stalled episode increments the liveness event metric once and logs on entry, then at most once per 60 seconds until height advances or all peers disconnect. It no longer logs the same warning every one-second timer tick.
- `StateEngine` no longer forwards LIVENESS-only warnings to the circuit breaker.
- `PanicCircuitBreaker.record_violation()` independently rejects the LIVENESS prefix as defense in depth.
- Repeated real `SAFETY VIOLATION` reports continue to trip the breaker; the regression test verifies this.

The warning still signals a lack of chain progress and must be diagnosed. It is no longer misclassified as evidence of corrupt chain state that automatically stops mining.

## Verification

### Tests and checks passed

- Targeted combined regression suite: **59 passed in 5.93 seconds**.
  - New liveness/mining regression tests
  - Hashrate governor tests
  - P2P liveness/handshake tests
  - Incoming transfer inbox tests
  - TUI frame/input tests
  - Recipient fee/balance history regression tests
- Selected breaker/operator recovery tests: **5 passed, 5 deselected in 8.29 seconds**. The deselected tests include block-mining paths that were not part of this targeted run.
- `python -m compileall -q visold ...`: passed.
- `tools/check_architecture.py`: **ARCHITECTURE OK** — 125 modules, 475 import edges, 22 contexts; no cycles detected.
- `python visold_vsd_.py --help`: exit code 0.
- Direct mining smoke test, configured workers `1, 2, 4, 8`: all candidates had a 317-byte hash preimage and correctly selected one effective worker. Wall-clock measured H/s and worker telemetry were in the same range in that short run.

### Controlled patched-source multi-node smoke test

Three fresh local node processes ran for about 30 seconds with one miner configured for four workers and two non-mining peers. The tested source import was verified to be the patched V4 tree. All three nodes reached height 7, each reported two active peers, and all observed breakers remained `CLOSED`. The miner emitted the short-header single-worker informational notice and continued to mine/relay blocks. The harness terminated the processes at the end of the observation window; this was not a graceful-shutdown test and did not run for the 600-second liveness threshold.

### Not claimed as verified

- The complete test suite was **not** completed. One broad combined run exceeded its 120-second command timeout while executing mining-heavy integration tests; it is not counted as a pass or a code failure.
- The 1–2 hour Android unattended stall was not reproduced in this Linux sandbox. The local 30-second node run confirms short-run connectivity/progression only; Android background scheduling, thermal throttling, and device-specific effective rate still require a device-side long run.
- A previously documented pruning/receipt integration failure (`test_varr_receipt_relay.py::test_receipt_survives_body_pruning_and_preserves_sender`) also failed on the untouched original V4 baseline. This patch does not modify pruning; that baseline issue is outside this liveness/mining fix.

## Files changed

- `visold/mining/parallel_miner.py`
- `visold/mining/workers.py`
- `visold/mining/engine.py`
- `visold/cli/interactive.py`
- `visold/resilience/safety_invariants.py`
- `visold/resilience/panic_breaker.py`
- `visold/state/engine.py`
- `tests/test_hashrate_governor_adaptive_20261026.py` (updated expected live cap for the single effective worker)
- `tests/test_liveness_mining_regression_fix_20261027.py` (new; also asserts the short-header notice uses INFO level)

Reference for the hashlib GIL threshold: https://docs.python.org/3.11/library/hashlib.html


## Follow-up UX correction

The short-header fallback is expected behavior, not a warning condition. The initial patch used `log.warning`, which caused the TUI to show a red `!` immediately after mining began. It has been changed to `log.info`; the test now asserts the notice level is INFO. No mining, consensus, or liveness behavior was changed by this follow-up.
