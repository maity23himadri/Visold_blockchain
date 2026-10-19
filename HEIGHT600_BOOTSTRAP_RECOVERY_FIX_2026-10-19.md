# Height-600 checkpoint recovery — follow-up fix (v2)

Date: 2026-10-19
Base: `Visold_8_FIXED_height600_bootstrap_recovery.zip`

## Why v1 could still fall back to genesis

The first patch dispatched authenticated same-height recovery only when the rejection text contained the exact phrase `Bootstrap snapshot commitment mismatch`. Other local checkpoint-state failures, such as `Bootstrap commitment parent state is unavailable` or `Cannot compute bootstrap commitment: unable to serialise deterministic bootstrap state`, did not match that predicate. The result handler could then fall through to the old `recovery blocks 0-199` request. The supplied TUI excerpt truncates the rejection reason, so it does not establish which exact validator reason occurred on the user's running node.

A `0-199` recovery request while local height is 600 proves the v1 recovery branch did not handle that request/result, but cannot alone distinguish a different error reason from running a stale/unpatched source tree.

## v2 changes

1. Trigger authenticated same-height recovery for the known local checkpoint-state failure reasons:
   - bootstrap snapshot commitment mismatch;
   - checkpoint parent state unavailable;
   - inability to compute the bootstrap commitment;
   - deterministic bootstrap-state serialization failure.
2. Restrict the path to a rejected batch whose first block is exactly `local_height + 1`, while local height is a configured snapshot boundary and has not advanced.
3. For a rejected checkpoint-boundary batch with an unrelated validation reason, do not request blocks 0-199. Emit the complete reason to the log, because genesis replay cannot repair a same-height checkpoint and broad state repair must not be triggered by unrelated invalid transactions.
4. Continue to require authenticated recovery: verify the PoW/header chain anchored at local genesis, the commitment at H+1, the downloaded snapshot digest, and every local canonical block hash through H before modifying state. Normal validation of H+1 remains mandatory.
5. Add regression coverage for all recognized local-state errors and for not triggering state repair on an unrelated invalid-block reason.

## Tests run on the packaged source

- `python -m compileall -q visold tests` — passed.
- Focused bootstrap/same-height/sync safety regression group — **25 passed**.
- Consensus security, sync-import optimization, MEV bootstrap, and receipt-relay group — **21 passed** (three Python multiprocessing/fork deprecation warnings).

A full repository suite is not claimed. The known separate SQLite-lock interaction from the previous report remains outside this narrow fix.

## Operational notes

- Do not delete the existing database to try this fix.
- Stop the node and back up the entire `.visold` database directory and wallet material before replacing code.
- Ensure the running process imports the patched `visold/network/p2p.py`. If the old behavior continues without the new `[BootstrapSync]` or `Checkpoint-boundary batch rejected` diagnostic, check the imported module path: extracting a ZIP into a directory can accidentally create a nested `Visold/Visold` folder while the launcher continues to run the previous tree.
- The current TUI snippet does not contain the unabridged validator rejection reason. v2 logs it explicitly, so the next runtime result can distinguish a recognized checkpoint-state mismatch from another failure without assuming the real database has been repaired.
