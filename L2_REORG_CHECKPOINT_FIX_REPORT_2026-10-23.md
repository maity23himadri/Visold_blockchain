# L2 reorg rollback no longer wipes valid L2 balances — 2026-10-23

## Problem
`Layer2State.rollback_to_height()` treated "no checkpoint at or before the fork height"
as "L2 was empty there" and reset the whole L2 tree. That is wrong when the checkpoint
existed but had been evicted: history is capped at `L2_ROOT_HISTORY_DEPTH` (128) entries,
and every bridge deposit/withdrawal and every batch adds one, so a few busy blocks could
push out the checkpoint a reorg needed. Valid L2 balances were wiped while the L1 bridge
escrow kept the money (L2 supply 0 vs escrow > 0). Nothing rebuilt it; the supply monitor
only reported it afterwards.

A node that never uses L2 also logged a yellow "no checkpoint ... resetting L2 tree"
warning on every reorg and rewrote an already-empty L2 record. That was harmless but misleading.

## Changes
`visold/rollup/l2_state.py`
- Trimming now drops first the entries a rollback can never choose (an entry followed by a
  later entry of the same or lower L1 height — rollback scans newest-first and takes the
  first match). Only if that is not enough are the oldest entries evicted. Rollback results
  are unchanged for every height that was answerable before.
- New persisted field `l2_history_first_height`: the lowest checkpoint height ever
  recorded. It survives eviction, so a rollback can tell "nothing ever existed there"
  (empty is correct) from "it existed and was evicted" (must not wipe). It is committed
  to memory only after the database write succeeds, and travels through
  `snapshot_full()` / `restore_full()`.
- `rollback_to_height()` now decides through one read-only `_rollback_plan()`:
  restore / no-l2-state (nothing to roll back: no write, debug log) / empty (as before) /
  lost (refuses with `(False, reason)` and changes nothing).
- New read-only `can_rollback_to_height()`.
- The empty-reset branch now restores the previous state if its write fails.

`visold/chain/blockchain.py`
- `reorg()` and `rollback()` call `can_rollback_to_height()` BEFORE changing any L1 state and
  refuse cleanly ("Reorg rejected: ..." / "Rollback rejected: ...") if L2 cannot follow.
  A failing pre-check call is logged and the old behaviour continues.
- The reorg hook logs "no-l2-state" at debug level instead of an INFO line.

`visold/_build_identity.json`: `package_source_sha256` updated
(`ddb9acbf0bd9f01b13473b6074c2ddf3d99533a1db7cc64098516f7987f26c93`, which also includes the snapshot fix below; the build with only the EOF fix was `dd79bb6b...`). Algorithm and file count (149) unchanged.

## Verified by running (no test suite was run)
- Real `Layer2State` on a real SQLite `Storage`, original vs patched: on the original the
  heavy-use case wipes Alice's valid 10 VSD and a deep reorg wipes everything; on the patched
  build Alice survives, supply equals escrow, a reorg deeper than retained history is refused
  with state untouched, and an ordinary reorg works.
- Persistence across restart, a database from before this change, a corrupt new key,
  `snapshot_full`/`restore_full`, and a failed database write all behave correctly.
- 1500 random histories x every height: the rollback decision always equals what an
  untrimmed history would give.
- Two real nodes, real reorg (fork at height 1): patched node adopted the longer chain and
  wrote no L2 record; the original build adopted it and wrote `l2_tree = {}` (the reset
  path). A patched node with seeded, evicted L2 history refused the reorg and kept the L2
  balances.

## Limits and notes
- A database written before this change has no `l2_history_first_height`. It cannot know
  whether its history was ever trimmed, so it keeps the old behaviour until the field is
  populated by new L2 activity.
- A reorg deeper than the retained history on a node with active L2 is now refused instead
  of corrupting L2. The peer keeps offering the chain, so the refusal is logged repeatedly
  (about every 4 s) until the node is resynced.
- The snapshot-bootstrap L2 checkpoint format bug found while verifying this is fixed in
  SNAPSHOT_L2_CHECKPOINT_FORMAT_FIX_REPORT_2026-10-23.md.
- All nodes must run the same build (any change under `visold/` changes the node logic hash).
