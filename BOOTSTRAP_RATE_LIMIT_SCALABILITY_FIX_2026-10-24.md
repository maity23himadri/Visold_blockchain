# Bootstrap GET_CHAIN Rate-Limit Scalability Fix — 2026-10-24

## Root cause
Authenticated bootstrap verifies the canonical header chain in 200-block `GET_CHAIN` pages. The receiver's existing DoS limiter allows 5 `GET_CHAIN` requests per 10 seconds. The sixth request was silently dropped by `_handle_message()` before the `GET_CHAIN` handler could return any response. For a snapshot at height 1200 this caused a deterministic 30-second timeout, rejection of the valid height-1200 snapshot candidate, fallback to height 600, and then failure at pruned block 601.

## Fix
1. Keep the existing `GET_CHAIN` DoS quota unchanged.
2. When a `GET_CHAIN` is rate-limited, return a correlated `MSG_CHAIN` busy response instead of silently dropping it.
3. Include a `retry_after_ms` computed from the actual sliding-window bucket reopening time.
4. Preserve the original `request_id`, so authenticated-bootstrap routing receives only its own backpressure response.
5. Authenticated bootstrap now respects the server-provided retry delay (up to the full rate-window duration) and retries the same page rather than abandoning a valid snapshot.
6. Added configurable `VISOLD_BOOTSTRAP_HEADER_BUSY_RETRIES` (default 8). The retry budget is per page, so it does not decrease as chain/snapshot height grows.
7. Kept DB-scan concurrency limits, global message limits, per-type message limits, and all snapshot/header authentication checks intact.

## Scalability property
There is no longer a hard ~1000-header ceiling caused by `5 requests × 200 blocks`. Any number of header pages can progress through the same bounded server quota: when a bucket is full, the sender receives explicit backpressure, waits for capacity, then continues the same page. Chain height increases transfer time according to the configured quota; it no longer turns the sixth page into a silent timeout.

## Verification performed
- `python -m py_compile visold/network/p2p.py visold/kernel/config.py` — PASS.
- New regression tests `tests/test_bootstrap_rate_limit_backpressure.py` — 2/2 PASS.
- Existing `test_all_pruning_nodes_can_bootstrap_fresh_node_from_authenticated_snapshot` — PASS.
- Real two-node test with the supplied V4 state database:
  - source node height: 1256
  - fresh node start height: 0
  - fresh node final height: 1256
  - final canonical tip hash on both nodes: `000072f11b0647d3e0d60b40431746e11bdab73d4b62890226eb4a64f891c6a4`
  - peer verified height on fresh node: 1256
  - final sync result: `ok=True`, `reason=OK`

The original source database/archive was not modified during testing; isolated copies were used.

## Operational behavior for larger chains
The fix changes failure semantics, not the configured DoS quota. A large bootstrap therefore progresses under backpressure instead of failing at a fixed page count.

Example with a source at height 20,000 and recent authenticated snapshots:
- a height-0 node may authenticate the snapshot header range, install the newest usable snapshot, then apply only the post-snapshot block bodies;
- a height-100 node can use the same bootstrap path when it is sufficiently far behind;
- both nodes are expected to converge to the source canonical height/tip if the required snapshot and post-snapshot data are available and valid.

At the current 200-header page size, verifying roughly 20,000 headers requires about 100 header-page requests. With the configured five-`GET_CHAIN`-per-10-second peer quota, the transport intentionally paces those pages. This affects elapsed time but no longer creates a correctness ceiling at about 1,000 headers.

## Archive scope
This fixed archive contains the Visold project/code, tests, and documentation. The supplied V4 runtime database, WAL/SHM files, wallet state, node identity, and TLS/runtime state used during verification are not included in the archive.
