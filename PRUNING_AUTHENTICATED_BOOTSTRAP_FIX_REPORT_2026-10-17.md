# Visold Pruning-Safe Authenticated Bootstrap Fix

Date: 2026-10-17
Base: `Visold_5.zip`

## Problem fixed

With rolling pruning enabled on every reachable node, a fresh height-0 node previously required historical transaction bodies that peers had already deleted. The legacy snapshot path could not safely solve this because the existing L1 `state_root` does not authenticate all future-consensus-relevant auxiliary state.

## Protocol fix

The patch adds a consensus-authenticated snapshot checkpoint protocol without weakening ordinary block validation:

1. At each fixed 600-block boundary `K`, a complete deterministic snapshot of state at `K` is retained.
2. Block `K+1` MUST put `SHA256(canonical_snapshot_bytes(K))` in its coinbase memo.
3. Every validating node recomputes that digest from its own state at `K`; a missing or forged commitment makes block `K+1` invalid.
4. The coinbase commitment is authenticated by the existing transaction id -> Merkle root -> PoW block hash chain. When `K+1` is later pruned, the pruner retains only the coinbase plus its Merkle co-path, not the full body.
5. A fresh node verifies header linkage, exact block hashes, PoW, deterministic DAA and MTP from its locally-known deterministic genesis through `K+1`, verifies the commitment inclusion, downloads snapshot `K`, verifies its SHA-256 digest, installs the complete state, then resumes normal full-block validation at `K+1`.
6. Imported historical records remain explicitly `pruned` and cannot enter ordinary full-block validation, apply, or reorg paths.

## Snapshot state authenticated

Snapshot format v4 includes balances, nonces, live contract accounts, bytecode, storage, typed-storage tags, roles/stakes, name claims, state channels, permanent transaction replay guard, current L2 tree, L2 last batch id, cumulative issuance, and deterministic governance proposal lifecycle state. Recent protocol-version signaling metadata is reconstructed from the already-authenticated headers rather than trusted from the peer.

## Safety properties

- A peer cannot forge snapshot balances/nonces/etc. without changing the committed digest.
- A miner cannot commit an arbitrary snapshot digest: all full validators independently recompute and reject the block on mismatch.
- Pruned history is never treated as a full executable block.
- A mixed sync page containing a normal block followed by a pruned record fails before partial application.
- Bootstrap installation is restricted to a fresh height-0 chain; an already-running non-fresh node is not silently replaced by a remote snapshot.
- At least two snapshots are retained while rolling pruning is enabled, so a snapshot that has not yet received its `K+1` commitment cannot evict the previous committed bootstrap point.

## Consensus activation

Production constants are fixed (not operator/env-tunable):

- `BOOTSTRAP_SNAPSHOT_INTERVAL = 600`
- `BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT = 601`

This is a consensus protocol change. All consensus nodes must upgrade before block 601 on a new/current chain using these constants. If an already-deployed canonical chain has passed height 601 without these commitments, the activation height must instead be changed once to a future network-wide coordinated height before deployment; it must not be configured independently per node.

## Verification actually run

Syntax:

```bash
python -m compileall -q visold
```

Passed.

Combined relevant regression set:

```bash
PYTHONPATH=. pytest -q \
  tests/test_pruning_authenticated_bootstrap.py \
  tests/test_pruned_block_sync_safety.py \
  tests/test_pruned_resync_integration.py \
  tests/test_consensus_security_fixes.py \
  tests/test_sync_import_optimizations.py \
  tests/test_vsa_block_application_20261014.py
```

Result: **41 passed, 3 warnings**. Warnings are existing Python multiprocessing/fork deprecation warnings.

New adversarial/integration checks include:

- all-pruning source with old header-only blocks -> fresh height-0 authenticated bootstrap -> normal continuation: PASS;
- modified snapshot state with old committed digest: REJECTED;
- modified historical header: REJECTED;
- modified commitment coinbase: REJECTED;
- miner-created block carrying a forged snapshot digest: REJECTED by normal `validate_block()`;
- replay guard survives bootstrap;
- cumulative issuance and resulting chain state converge after post-snapshot block application;
- old pruned-block safety suite: 13/13 PASS.

A run of the entire 256-test project suite was attempted but did not complete within the execution limit, so this report does **not** claim a full-suite pass.

## Stale-node fast-forward extension (height 5 -> 11 regression)

The authenticated pruning-safe bootstrap path now also handles an already-synced
but stale node when its next required block body has been pruned. It is strictly
a fast-forward, never a reorg: every locally stored canonical block hash from
genesis through the local tip must exactly match the independently verified PoW
header chain, and the authenticated snapshot height must be ahead of the local
tip.

Regression scenario verified with test-scale interval/window values:
- stale node cloned at height 5;
- source advances to height 11;
- source prunes block 6;
- ordinary application of block 6 is rejected;
- stale node verifies headers/PoW and snapshot-10 commitment;
- exact local prefix 0..5 is verified;
- authenticated snapshot 10 is installed;
- full block 11 is normally validated/applied;
- stale node reaches the exact source block hash/state root at height 11.

A divergent local prefix is explicitly rejected before state installation.
