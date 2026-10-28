# Visold V10 security fixes — 2026-10-28

## Scope

This patch addresses the two demonstrated block-validation/gossip attacks:

1. A rejected block candidate could poison `MSG_BLOCK` deduplication because queue admission was treated as successful processing.
2. A mempool cache hit keyed only by `tx_id` could skip signature verification for an altered signature that preserved the same transaction ID.

The patch is deliberately limited to those code paths and their regression coverage. It does not claim to repair unrelated defects already present in the supplied archive.

## Fix 1 — gossip deduplication poisoning

### Triggering case

A peer sends a block message claiming hash `H`, but its body is invalid. The P2P handler posts a `NEW_BLOCK` event. The old logic caches `H` as soon as `StateEngine.post()` returns true, which means only “queued”, not “validated/applied”. If a genuine copy with hash `H` arrives while the first event is in flight, it can be discarded as a duplicate. The first event may then fail, while the poisoned cache suppresses later honest copies.

### Changes

- A block hash remains in the in-flight claim set while the StateEngine processes the event.
- The dedup cache is updated only if the event reports success **and** the same block hash is confirmed at its canonical chain height.
- Failed, refused, malformed, or merely orphaned candidates release the claim without caching the hash.
- If a different body for the same hash arrives while the first candidate is being processed, one bounded alternate candidate can be retried after the first candidate fails. This closes the in-flight race without creating an unbounded retry queue.
- The full-block, compact-block fast path, and `BLOCKTXN` reconstruction path use the same completion rule. The pre-StateEngine fallback also requires canonical-chain confirmation.

### Regression coverage

- Existing mesh dedup/relay tests updated for asynchronous processing outcome.
- New tests cover a rejected first candidate followed by a genuine candidate, and a genuine candidate arriving during the in-flight race.

## Fix 2 — signature-verification cache bypass

### Triggering case

A genuine transaction enters Node A's mempool, so its `tx_id` appears in the old `_verified` set. An attacker copies that transaction, changes `sig_hex` to an invalid signature, and keeps the same `tx_id` (the transaction ID intentionally excludes signature/public-key fields). The old block-integrity path trusted the ID-only cache hit and skipped ECDSA verification. Node A could accept the block while Node B and a fresh node rejected the same bytes, causing consensus divergence.

### Changes

- Added a bounded fingerprint cache alongside the legacy diagnostic `_verified` ID set.
- The fingerprint commits to the transaction ID, sender, public key, signature, and exact signing payload.
- Block consensus validation skips cryptographic verification only when the supplied transaction and signing payload match that exact fingerprint. A missing entry, ID-only marker, invalid cache state, altered signature/public key, or legacy-payload mismatch falls back to full verification.
- The later semantic-validation shortcut only receives IDs whose signatures were actually checked or were accepted by the exact-context cache.
- The one-argument `mempool.is_verified(tx_id)` remains available for diagnostics/compatibility, but it is not used as authorization to skip consensus signature verification.
- The package build-identity fingerprint was regenerated after source edits so source and sourceless deployments do not advertise a stale code hash.

### Regression coverage

- New two-node test reproduces the same-ID invalid-signature substitution: both cached and uncached nodes now reject the block and remain at height 0.
- Positive control confirms a correctly signed block remains valid on cached and fresh nodes.
- Existing crypto-acceleration regression tests cover the signature-verification fast path.

## Validation performed

- Mesh relay deduplication + new security regression tests: **9 passed**.
- Crypto-acceleration + October audit findings tests: **14 passed**.
- VSA remaining regression tests: **16 passed**.
- A cross-module run covering block application, mempool/crypto, pruning/reconnect, mesh relay, peer-height, and mining regressions previously completed with **58 passed** before the package identity manifest refresh. The code files were unchanged by that manifest-only refresh; the specific manifest test passed afterward.
- `TestLogicHashFallback::test_manifest_matches_full_source_tree`: **passed** after updating `_build_identity.json`.
- Python compilation checks passed for the modified source and new regression test.

## Explicit limitations / pre-existing baseline failures

The supplied, unmodified `V10.zip` reproduces these independent issues; they are **not represented as fixed by this patch**:

- `tests/test_tls_io_serialization_20261025.py::test_tls_recv_timeout_and_eof_semantics_are_preserved` — closing the test TLS peer without a TLS close-notify can yield `ConnectionResetError` instead of `b""`; the same failure occurs against the original archive.
- `tests/test_varr_receipt_relay.py::test_receipt_survives_body_pruning_and_preserves_sender` — the test expects block 8 to be pruned at height 20, but it is not; the same assertion failure occurs against the original archive.
- `tests/test_vsa_reorg_consistency_20261014.py::test_reorg_with_cold_cache_accepts_the_same_branch` can exceed a 30-second isolated test timeout in the original archive too. This is not claimed as fixed.

A full-suite green result is therefore **not claimed**. Several targeted suites pass, but the entire repository suite could not be certified as clean due to the above baseline failures/hang and variable-duration mining tests.

## Files changed

- `visold/network/p2p.py`
- `visold/mempool/pool.py`
- `visold/ledger/block.py`
- `visold/chain/blockchain.py`
- `visold/_build_identity.json`
- `tests/test_mesh_block_relay_dedup_20261021.py`
- `tests/test_block_gossip_poison_signature_cache_fix_20261028.py` (new)

## Release note

These changes close the two reproduced attack paths and add regression tests. They do not constitute a claim that every unrelated issue in the existing V10 codebase has been eliminated. Run the full test suite and test multi-node sync in a controlled environment before deploying to a live network.
