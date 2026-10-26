# Visold RPC Load Fix Report

**Date:** 2026-10-25  
**Input:** `V.zip`  
**Output:** `Visold_RPC_Load_Fixes_2026-10-25.zip`  
**Scope:** Two load-test findings in `visold/api/rpc_server.py`; focused regression tests added. No production/user database was accessed.

## Changes applied

### 1. Expensive RPC methods now pay their intended rate-limit cost

The POST handler now reads and parses only the size-bounded request body, extracts the method safely, and passes that method to the existing atomic token-bucket check **before dispatch**. `analyzecontract`, `getmempool`, and `checkinvariants` cost 10 tokens; ordinary methods cost 1. The bucket remains shared across authenticated RPC POSTs, with capacity 20 and refill 20 tokens/second. Thus the slow-method budget is about 2 calls/second when token availability is sustained, subject to the shared bucket and its initial burst capacity.

The 64 KiB body cap remains. Oversized bodies, negative content lengths, and JSON parse failures consume a normal-rate token before their error response. A non-string method is treated as an ordinary request for rate-limiting purposes so unhashable JSON values do not break the rate limiter.

### 2. Concurrent connections are bounded and bursts receive back-pressure

The local RPC server now sets:

- `request_queue_size = 128` for the TCP listen backlog (subject to operating-system limits).
- A maximum of **32 active RPC handler workers**, enforced with a bounded semaphore.
- A 10-second socket I/O timeout to avoid incomplete local HTTP I/O occupying worker capacity indefinitely.
- Back-pressure when all worker slots are in use: the accept loop waits for a slot while new connections remain in the OS listen backlog, instead of spawning unbounded request threads or closing a socket before its request is consumed.
- A stop event that interrupts this wait, so server shutdown does not hang waiting for capacity.

This is not an unlimited-capacity guarantee: if offered connections exceed the OS backlog for long enough, clients can still fail or time out. The server is loopback-bound as before. The configured limits are module-level source constants, not new operator-facing settings.

## Test evidence

### Focused regression tests

Added `tests/test_rpc_server_load_regressions_20261025.py`, covering:

1. A slow method consumes 10 tokens: with a frozen test clock, two immediate `getmempool` calls return HTTP 200 and the third returns HTTP 429.
2. The standard bucket remains intact: 20 ordinary requests are admitted from the initial bucket and the 21st is rate-limited when the clock is frozen.
3. When a deliberately reduced test worker cap of two is saturated, a third request waits and succeeds after capacity is released; observed active RPC work never exceeds two.
4. The configured listen backlog and default worker cap are present.
5. A synchronized 24-client burst has no transport exceptions; responses are valid rate-limited/success responses.
6. Shutdown completes while the accept loop is waiting for an available worker.

Commands/results:

```text
python -m py_compile visold/api/rpc_server.py tests/test_rpc_server_load_regressions_20261025.py
# passed

PYTHONPATH=. pytest -q tests/test_rpc_server_load_regressions_20261025.py \
  tests/test_clean_shutdown_20261020.py \
  tests/test_network_port_settings.py \
  tests/test_node_effective_port_wiring.py
# 23 passed
```

### Live local-node verification

A fresh temporary data directory was used to construct a real `VisoldNode` from the archive. The RPC server was tested over loopback on Python 3.13.5 / Linux x86_64. The temporary chain was at genesis height 0, with no peers and an empty mempool; this is not a populated-chain or mobile-device benchmark.

| Test | Result |
|---|---|
| `getblockcount`, `getchaininfo`, `getpeerinfo`, `getmempool` smoke calls | HTTP 200 in the smoke run |
| Three immediate `getmempool` calls with a fresh bucket | HTTP 200, 200, 429; no transport errors |
| 24-client burst, trial 1 | 20 HTTP 200, 4 HTTP 429, 0 transport errors; p50 7.906 ms, p95 9.550 ms |
| 24-client burst, trial 2 | 20 HTTP 200, 4 HTTP 429, 0 transport errors; p50 10.218 ms, p95 16.462 ms |

The previous baseline on this same sandbox shape, with the inherited default listen backlog of 5, had 7–8 connection exceptions/resets and roughly 1.0–1.25 seconds p95 latency in two 24-client trials. After the patch, both trials returned a response for all 24 clients. These are local test results, not a promise of production throughput.

## Wider-suite status / limitations

The complete test suite collected **465 tests**, but a full run was terminated by the execution time limit at approximately 46% progress (about five minutes); it did not produce a final summary. A second verbose attempt was also stopped by the execution limit. Therefore **the full suite is not certified as passing**. All 23 tests in the focused RPC/shutdown/port/node-wiring run passed.

The load test does not prove behavior on Termux/Android, a populated database, real peer traffic, or sustained production load. Those should be checked before release. No source was changed outside `visold/api/rpc_server.py`; the new regression test and this report were added. Cache directories and compiled Python bytecode were omitted from the delivered ZIP to avoid stale generated artifacts.
