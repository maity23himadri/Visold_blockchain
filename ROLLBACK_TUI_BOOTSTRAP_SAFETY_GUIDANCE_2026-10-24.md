# Rollback TUI Bootstrap-Safety Guidance — 2026-10-24

The interactive Rollback Chain screen now derives a read-only bootstrap-safe rollback envelope from the live database state before asking for a target.

It reports:
- current height;
- lowest rollback target that preserves fresh-peer bootstrap service;
- maximum safe rollback depth in blocks;
- authenticated snapshot used as the recovery anchor, when applicable.

If the existing pruned layout is already a legacy/unrecoverable gap, the TUI does not invent a safe target. It warns that no bootstrap-safe rollback target is currently available and instructs the operator to repair/sync history first.

The calculation matches Blockchain.rollback() safety semantics: an authenticated snapshot H is a valid post-rollback anchor only when H+1 is retained at/after the pruning watermark and H+1 remains within the hypothetical post-rollback chain. Unpruned nodes can safely roll back to genesis from a bootstrap-serving perspective.

The TUI also blocks a target below the displayed safe floor before destructive confirmation. Blockchain.rollback() independently enforces the underlying invariant, so the UI is advisory plus early validation rather than the sole safety boundary.
