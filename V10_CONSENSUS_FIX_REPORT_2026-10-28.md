# Visold V10 — Consensus Security Fix Report

Date: 2026-10-28
Base: `V10_fixed_2026-10-28.zip` (preserves the previously applied gossip-poisoning and transaction-signature-cache fixes)

## Summary

This build addresses three consensus findings while preserving the existing fixes. It adds height/hash-bound validator-set snapshots, authenticates all embedded and live validator votes, enforces registration activation at N+1, and prevents tentative replacement branches from advancing finality before a reorg is committed.

## Finding 1 — Unauthenticated embedded BFT votes

**Fix:** `Blockchain._maybe_finalize_by_bft()` no longer counts validator addresses by themselves. Each embedded vote must have a well-formed public key and signature, the public key must derive the claimed validator address, the validator must belong to the eligible validator set for the exact block height, and the ECDSA signature over the block-hash digest must verify. Each eligible address counts at most once. Invalid and ineligible vote entries are removed from mutable `validator_sigs` metadata and never contribute stake. If the eligible set cannot be obtained safely, BFT finalization fails closed.

**Trigger before fix:** An otherwise-valid block carried fabricated `validator_sigs` entries whose claimed addresses represented quorum stake. The old finality routine counted those addresses without authenticating the attached signatures.

**Expected after fix:** A block can still be applied if its block body is otherwise valid, but unauthenticated entries cannot finalize it. Valid votes still finalize normally.

## Finding 2 — Registration-block self-voting

**Fix:** On successful block application, the eligible validator/stake set is captured from pre-block state and durably stored in `node_meta` under a height-and-block-hash-bound key. `ConsensusEngine.finalize_applied_block()`, `Blockchain.add_validator_sig()`, and embedded-vote processing all use that same per-block eligibility snapshot. A validator registered in block N is absent from N's snapshot and can become eligible starting at N+1.

The snapshot is persisted with the block-application transaction where the storage backend provides that transaction boundary. A missing or untrustworthy historical set does not fall back to the current live role table. For old databases without snapshots, a cautious legacy reconstruction is attempted only when canonical block history and durable role-undo data are available; ambiguous history (including slashing history that cannot be reconstructed) fails closed.

**Trigger before fix:** A registration transaction changed the live validator table during block N application; the post-apply finalizer then consulted that live table and let the newcomer vote on N itself.

**Expected after fix:** The newcomer cannot vote on N, but can vote on N+1 if otherwise eligible and holding a valid signing key.

## Finding 3 — Finality side effects during failed reorganization

**Fix:** Reorg application now calls `apply_block(..., defer_finality=True)` for tentative replacement blocks and old-chain restoration replay. These applications do not advance BFT or PoW-depth finality. If any replacement block fails, the previous canonical suffix is restored and its exact finalized flags and pre-reorg fence are restored only after successful identity-checked replay; failed restoration marks critical recovery. If the replacement chain succeeds completely, finality is reconciled on the now-canonical branch, and the fence is recomputed from canonical stored block flags rather than inherited as an in-memory maximum.

**Important design constraint:** The fix does not blindly lower a fence after an actually committed finality event. Tentative candidate finality is delayed until the candidate chain is accepted, preserving the invariant that a discarded branch cannot finalize blocks as a side effect.

**Trigger before fix:** Intermediate replacement blocks could become finalized and advance `_highest_finalized_height`, after which a later candidate failed. The old canonical chain was restored, but the tracker retained a height from the discarded replacement branch.

## Storage and source changes

- `visold/chain/blockchain.py`: validator snapshots, authenticated vote/quorum path, validator vote eligibility, deferred reorg finality and canonical fence reconciliation.
- `visold/chain/consensus_engine.py`: finalization uses a height-specific validator snapshot instead of the post-application live role table.
- `visold/storage/storage.py`: durable validator-set snapshots, safe retrieval/validation, legacy role enumeration and orphan-snapshot cleanup.
- `tests/test_consensus_finality_security_fix_20261028.py`: reproduced attack regressions for fabricated votes, insufficient authenticated quorum, N/N+1 eligibility and failed-reorg finality cleanup.
- `tests/test_vsa_reorg_consistency_20261014.py`: updated a test wrapper to forward the new optional `defer_finality` argument.
- `visold/_build_identity.json`: regenerated package source SHA-256 for this source build.

The previous gossip-poisoning fix and signature-cache bypass fix are retained from the prior fixed archive; their regression tests are still included and run below.

## Verification results

Individually completed test groups:

- New consensus-finality regressions (including successful and failed reorg paths) + prior gossip/signature-cache regressions: **8 passed**.
- Existing validator-finalization tests: **2 passed, 5 deselected**.
- Existing transaction/signature security tests: **9 passed**.
- Software identity tests: **10 passed**.
- Existing chain-lock/deadlock regression: **1 passed, 8 deselected**.
- PGX rollback cleanup tests: **2 passed**.
- Existing orphaned-validator-vote persistence regression: **1 passed**.
- Python compilation of changed source/tests: **passed**.

Some broader legacy test collections timed out before completion, including a failed-reorg test that mines several blocks at the repository's configured difficulty and a combined consensus/reorg group. Those runs did not complete, so they are **not reported as passing**. No live multi-node network test was performed on this build. Deploy only after completing the full project test suite and multi-node sync/finality verification in the target environment.

## Upgrade/recovery note

Existing databases do not have per-block validator snapshots. The code attempts conservative reconstruction from retained canonical block bodies and role-undo metadata. If the required history is pruned or ambiguous, it refuses to count BFT votes for that old block rather than guessing from today's validator set. This is a safety-first behavior and may require an operator-led resync/reindex or other migration procedure for old/pruned data; do not bypass the failure by substituting the live validator table.
