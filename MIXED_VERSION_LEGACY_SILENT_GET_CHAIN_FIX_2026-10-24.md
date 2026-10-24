# Mixed-version legacy silent GET_CHAIN recovery fix — 2026-10-24

## Field symptom
A fixed node at height 600 connected to an older peer around height 1478/1479. Normal sync requested 601+ and correctly detected pruned block bodies. Authenticated recovery then started, but the first bootstrap header page (0-199) timed out after 30 seconds and recovery aborted.

## Root cause
Older peers enforce the GET_CHAIN per-peer quota but may silently drop an over-quota request. The fixed client already understood the newer explicit `MSG_CHAIN {busy, retry_after_ms}` response, but treated a silent timeout as a fatal snapshot-candidate failure. In a mixed-version recovery, ordinary gap/heartbeat sync could also compete with authenticated-bootstrap GET_CHAIN requests for the old peer's small request bucket.

## Fix
1. While authenticated pruned-history recovery owns a peer, ordinary heartbeat/gap GET_CHAIN requests for that peer are suppressed. The post-snapshot continuation request is explicitly allowed.
2. A bootstrap header page that receives no response is retried with a fresh request ID. This supports legacy peers that silently dropped the earlier request and prevents a late response from an old attempt from being mistaken for the new attempt.
3. Explicit `busy/retry_after_ms` handling remains unchanged for upgraded peers.
4. Production defaults: 30-second header response timeout, up to 3 timeout attempts per page. Both are environment-configurable.

## Compatibility
No consensus rule, block format, snapshot format, database schema, or wire message type changed. This is receiver-side mixed-version recovery behavior.

## Verification
- Exact regression: fake legacy peer silently drops the first bootstrap GET_CHAIN; authenticated pruned recovery retries and completes: PASS.
- Relevant pruning/bootstrap/same-height recovery suite: 39/39 PASS.
- Python compile checks for modified network/config modules: PASS.
