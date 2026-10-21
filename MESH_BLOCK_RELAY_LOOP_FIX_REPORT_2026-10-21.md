# Visold mesh block-relay loop fix — 2026-10-21

## Confirmed root cause

`P2PNetwork.broadcast_block()` sends newly mined/accepted blocks as `MSG_CMPCTBLOCK`. The message dispatcher also had an explicit canonical block-hash dedup branch for `MSG_CMPCTBLOCK`, sharing the `("BLOCK", block_hash)` key with `MSG_BLOCK`. However, `MSG_CMPCTBLOCK` was mistakenly included in `_GOSSIP_DEDUP_SKIP`, so the dispatcher skipped the entire branch. A compact block could therefore reach `StateEngine`, be accepted as an idempotent already-present block, and be broadcast again; mesh copies kept circulating.

## Changes made

1. Removed `MSG_CMPCTBLOCK` from `_GOSSIP_DEDUP_SKIP`, so compact-block gossip now goes through deterministic block-hash deduplication.
2. Added an atomic in-flight claim for block hashes. Concurrent copies received over different mesh edges cannot all enqueue/apply the same block before the first copy is recorded in the completed cache.
3. Applied the same claim/release rule to full `MSG_BLOCK`, reconstructed compact-block fast path, and completed `MSG_BLOCKTXN` slow path. Failed queue admission or failed fallback application releases the claim without caching a false success, so retries remain possible.
4. Marked a locally originated/canonical block as seen immediately before outbound fan-out. A copy returning to its origin through another peer is dropped rather than unnecessarily re-queued and relayed.
5. Kept the shared `("BLOCK", block_hash)` identity across full and compact transports so a second wire representation of the same block is deduplicated too.

## Regression evidence

- `python -m py_compile visold/network/p2p.py tests/test_mesh_block_relay_dedup_20261021.py`: passed.
- `python -m compileall -q visold`: passed.
- `PYTHONPATH=. pytest -q tests/test_mesh_block_relay_dedup_20261021.py tests/test_peer_height_poisoning_regressions_20261021.py`: **10 passed**.
- New tests cover repeated compact-block delivery, concurrent delivery of the same block from eight mesh edges, release/retry after `StateEngine.post()` rejects a block, atomic claim uniqueness, and suppression of an origin block that returns through the mesh.

A broader batch of existing tests exceeded the execution window before producing a final summary; it is **not** reported as passing. A live five-node network test was not run in this sandbox. The fix has focused deterministic regression coverage but should still be exercised on the five-node Android/Termux mesh before a production rollout.
