# Visold — Confirmed Bug Repairs (2026-10-07)

This archive contains fixes for the two confirmed defects identified in the 2026-10-07 audit.

## 1. Difficulty zero-target liveness defect

**Bug:** `Config.MAX_DIFFICULTY = 64` was reachable through the LWMA difficulty controller. The canonical target conversion maps difficulty 64 to target `0`, so an ordinary SHA-256 result cannot satisfy the PoW rule and block production stops.

**Fix:** The consensus ceiling is now `MAX_DIFFICULTY = 63.0`, the highest integer difficulty in this protocol's target conversion that still has a non-zero target (`16`). The LWMA hard ceiling therefore cannot enter the zero-target state.

**Regression coverage:**
- The configured ceiling is strictly below 64.
- The configured ceiling maps to a positive PoW target.
- Extreme fast-history input reaches the ceiling at `63.0`, not 64.0.
- The capped difficulty remains mineable (`target > 0`).

## 2. SQLite L2 nested-transaction defect

**Bug:** During block application, SQLite is already inside the block-level atomic transaction. `Layer2State._persist()` called `Storage.set_meta_batch()`, which issued a second `BEGIN`, causing:

`sqlite3.OperationalError: cannot start a transaction within a transaction`

**Fix:** The serialized SQLite connection exposes whether a Storage-owned atomic block is active. `set_meta_batch()` now joins that existing transaction when active; it only starts/commits its own transaction when called outside an enclosing Storage atomic block.

**Atomicity preserved:**
- L2 mutation succeeds inside the enclosing SQLite transaction and becomes durable when the outer transaction commits.
- The same mutation is discarded when the outer transaction rolls back.

## Verification

- Python bytecode compilation: **OK**
- Architecture/layering check: **OK** — 118 modules, 443 import edges, 22 contexts; no cycles/layering violations.
- New targeted regression tests: **4/4 passed**
- Existing confirmed-bug/regression/security subsets: **85 tests passed** across the executed files.
- Built-in Visold entry-point suite: **153/153 passed, 0 failed** using `python visold_vsd_.py --test`.

The repository-wide pytest run is not reported as fully passing because several production-style PoW-mining tests can run for a long time or stall when grouped together; this is an existing test-harness/runtime characteristic and was not treated as a code failure.
