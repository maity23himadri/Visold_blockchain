# Snapshot-bootstrap L2 checkpoint format — 2026-10-23

## Problem
`SnapshotEngine.restore_authenticated_bootstrap()` (visold/storage/snapshot.py) stored its
single L2 rollback checkpoint as `{"height", "tree", "last_batch_id"}`. `Layer2State` reads
`{"l1_height", "l1_block_hash", "batch_id", "l2_root", "snapshot"}`. After a bootstrap, the
first rollback onto that checkpoint (a reorg or manual rollback at or above the snapshot
height) raised `KeyError: 'snapshot'`. The reorg hook only logged it, so L2 stayed un-rolled-back.
Confirmed on the unmodified build by driving the real bootstrap import with L2 state.

## Changes
`visold/storage/snapshot.py`: the bootstrap now writes the checkpoint in Layer2State's own
format (root computed from the authenticated tree; block hash from the verified anchor
header) and writes `l2_history_first_height = 0`, because L2 state below the snapshot height
is not retained. If the root cannot be computed it logs a warning and stores an empty root;
the import is not rejected (same acceptance behaviour as before).

`visold/rollup/l2_state.py`
- `_upgrade_bootstrap_history()`: databases already bootstrapped with the old format are
  converted in memory when loaded (written back in the new format on the next persist) and
  get first-height 0. It never raises; an entry it cannot convert is left alone.
- `_rollback_plan()`: a chosen checkpoint with no usable `snapshot` is refused
  ("lost") instead of raising or being skipped or wiped.
- Refusal message now says "missing or unreadable".

`visold/_build_identity.json`: fingerprint updated (see the L2 report).

## Verified by running (no test suite)
Real `restore_authenticated_bootstrap` on a real source chain whose snapshot carries an L2
balance (alice, batch id 7), same chain setup as tests/test_pruning_authenticated_bootstrap.py:
- Original: stored entry has the old keys; `rollback_to_height(4)` raises `KeyError`.
- Patched: entry has the new keys with the right height, batch id, root and anchor hash;
  rollback at the snapshot height and above succeeds with the balance intact; rollback below
  it is refused with the balance and history untouched.
- Legacy database (old format already stored): converted on load, rollback works, a later
  deposit persists and reloads in the new format. A damaged entry is refused with no exception
  and no change.

## Notes
- All nodes must run the same build (any change under `visold/` changes the node logic hash).
