# Same-Height Pruned-Peer Auto-Sync Fix — 2026-10-20

## Problem reproduced from the node logs

A node at height 724/725 with a rolling-pruned prefix repeatedly initiated auto-sync for blocks `0-199`. Its peer also served that old range. Because the response contained header-only/pruned block records, `accept_chain()` rejected the batch, which triggered authenticated snapshot recovery. At equal or near-equal heights, the peer had no committed snapshot ahead of the local tip, so recovery did not complete. Auto-sync could then retry the same genesis range and repeat the warning/recovery path. Concurrent dashboard/manual sync requests made the activity harder to interpret.

## Changes

1. **Select a retained overlap for pruned nodes.** Archival nodes still begin at genesis so their existing deep-fork check remains intact. Nodes whose pruning watermark or genesis marker shows they are non-archival begin at the newest contiguous full-body overlap, bounded by the configured rolling window. The 200-block page reserves a slot above the local tip.
2. **Treat exact historical overlap as a safe no-op.** When every received block index is already canonical, the indices are contiguous, and every block hash matches the local stored hash, `accept_chain()` returns `Already have all these blocks`. This hash-only comparison also works for matching header-only/pruned records; it does not apply state or transactions. A mismatch is not accepted by this shortcut and continues through the pre-existing fork-validation/rejection path.
3. **Stop repeating successful no-op requests.** Auto-sync recognizes a completed, matching overlap when the peer tip is not ahead and stops retrying the same historical range.
4. **Respect in-flight work.** If another correlated chain request (for example, dashboard/manual sync or pagination) already owns the peer's request slot, auto-sync yields instead of logging a request it did not actually send.
5. **Record the last sync result per peer.** This supports correct coordination between the one-flight request mechanism and the auto-sync loop.

## Expected behavior for the reported height-725 case

With a 600-block rolling window and the normal cutoff at height 125, a pruned node around height 725 uses a recent retained overlap, e.g. `527-726`, rather than requesting `0-199`.

- If the peer has the same canonical tip at 725, the peer can serve `527-725`; the receiver checks the hashes and logs a successful canonical-overlap no-op. It should not emit `accept_chain rejected ... pruned/header-only` or start pointless pruned-history recovery for that matching range.
- If the peer is at 726, block 726 can be applied after the overlap matches, and pagination continues from the next range.
- If a hash differs inside the retained overlap, the new no-op shortcut does not accept it. Existing fork-choice / validation remains in control.
- A divergence older than retained local bodies cannot be safely re-executed from a body-pruned database. That case must remain fail-closed and use authenticated checkpoint/recovery rules; this patch does not pretend to reconstruct unavailable transaction bodies.

## Verification

Passed targeted tests:

```text
40 passed, 3 warnings in 2.92s
```

Included tests cover pruned-block safety, authenticated bootstrap/recovery, the prior two-node pruning-boundary regression, sync-import optimizations, UDP peer recovery, VSA sync gates, and five new same-height/pruned-overlap regressions. Modified Python modules and the new test file also compile with `py_compile`.

The three warnings are Python's multiprocessing `fork()` deprecation warnings from the existing sync-import optimization tests; no test failed.

## Scope and limitations

This was a source-level/unit regression run, not a live IPv6 TCP/UDP network benchmark. The separate `[TOFU] Cert fingerprint changed` message in the supplied log is not suppressed by this change; it is a separate peer-identity/security signal and should be investigated independently if it recurs unexpectedly.
