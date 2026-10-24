# Mixed-Version Pruned Bootstrap Queue Handoff Fix — 2026-10-24

## Symptom
A newer node that had authenticated to height 600 against an older/pruned peer could repeatedly log:

- `accept_chain rejected ... 601-800`
- `Pruned block body rejected at local height 600`
- `Snapshot response queue already owned ...`
- `Authenticated pruned-history recovery did not complete`

The remote peer could be much higher (for example ~1471), but the local node remained at 600.

## Root cause
The legacy snapshot fast-sync path owned the peer's `_snap_response_queue` while authenticated bootstrap installed snapshot 600 and immediately requested the first post-snapshot block page. If that page was pruned, the chain handler launched authenticated pruned-history recovery before the legacy caller had released its snapshot queue.

Worse, legacy cleanup used a delayed thread that unconditionally assigned `_snap_response_queue = None` five seconds later. A new recovery could legitimately claim a replacement queue during that interval, only to have the old cleanup erase it.

This was a same-peer response-routing ownership race, not a slow-sync condition and not a bad snapshot.

## Fix
- Added atomic, identity-safe snapshot queue claim/release helpers under the peer sync-state lock.
- Authenticated bootstrap releases snapshot response routing immediately after snapshot traffic is complete and **before** sending the first post-snapshot `GET_CHAIN` request.
- Legacy fast-sync no longer uses delayed unconditional queue cleanup.
- Legacy, pruned-recovery, and same-height recovery paths use the same ownership helpers.
- Old owners cannot clear a newer owner's queue.

The wire protocol, consensus rules, block format, snapshot format, and database format are unchanged.

## Verification
Targeted regression suite:

- `tests/test_snapshot_queue_handoff_20261024.py`
- `tests/test_bootstrap_rate_limit_backpressure.py`
- `tests/test_pruned_reconnect_authenticated_bootstrap.py`
- `tests/test_pruned_block_sync_safety.py`
- `tests/test_pruning_authenticated_bootstrap.py`
- `tests/test_two_node_pruning_boundary_reconnect.py`

Result: **31 passed**.

The new regression specifically reproduces the dangerous handoff where a legacy bootstrap queue is released, pruned-history recovery immediately claims a new queue, and the legacy caller then unwinds. The newer queue remains intact.
