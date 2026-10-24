# Current Pruned-Node Sync Behavior — 2026-10-24

## Scope
This note describes the authenticated snapshot/bootstrap behavior of the fixed build after the `GET_CHAIN` backpressure regression was repaired.

## Fresh or far-behind node
When a node is substantially behind a peer whose historical block bodies have been pruned, it can use a recent authenticated bootstrap snapshot instead of requiring every historical block body from genesis.

The receiver:
1. discovers the peer height and available snapshot candidates;
2. authenticates the candidate by verifying the required canonical header range and snapshot commitment;
3. installs the newest usable authenticated snapshot;
4. downloads/applies the remaining post-snapshot blocks;
5. verifies normal canonical convergence at the final tip.

## Rate limiting
`GET_CHAIN` remains limited to protect peers from abusive header/database scans. If bootstrap temporarily exceeds the serving peer's current quota, the request is not silently discarded. The server returns `busy` plus `retry_after_ms`, and the receiver retries the same page after the indicated delay.

This means chain height affects transfer duration, not whether the sixth header page disappears. There is no fixed ~1000-header correctness ceiling from the five-request/10-second quota.

## Example: heights 20,000 / 100 / 0
Assume node A is canonical at height 20,000, nodes B and C are at heights 100 and 0, and A has a recent valid authenticated snapshot plus the post-snapshot block bodies required to reach its tip.

Both B and C may authenticate and install the recent snapshot, then apply the remaining blocks. Expected final convergence is:

- A = 20,000
- B = 20,000
- C = 20,000
- canonical tip hash equal on all three nodes

A node does not need all pruned historical block bodies if a sufficiently recent usable authenticated snapshot bridges that history.

## Performance characteristic
The current header page size is 200. Roughly 20,000 headers therefore correspond to about 100 page requests. The existing per-peer quota is five `GET_CHAIN` requests per 10 seconds, so a large bootstrap is intentionally paced by network backpressure. Actual elapsed time also depends on snapshot size, storage speed, CPU verification cost, network latency/bandwidth, and the number of post-snapshot blocks.

## Verification already performed
An isolated two-node test using the supplied V4 runtime state synchronized a fresh node from height 0 to source height 1256. Both nodes ended on canonical tip hash:

`000072f11b0647d3e0d60b40431746e11bdab73d4b62890226eb4a64f891c6a4`

The supplied runtime database/state was used only for verification and is not bundled in the fixed code archive.
