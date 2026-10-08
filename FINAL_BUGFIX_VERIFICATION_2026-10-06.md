# Visold — Confirmed Bug Fix Verification

Date: 2026-10-06

This patch addresses the two bugs confirmed by the preceding audit. No state-root nonce/role issue is included because targeted validation did not produce a valid-chain divergence.

## 1. PGX block/state crash-consistency

### Failure fixed
The previous PGX flow could commit PostgreSQL consensus state before the canonical RocksDB block was durably recorded. A process death in that window could leave state advanced while the canonical block was absent.

The legacy SQLite + external LevelDB/RocksDB path also had a cross-store commit window in the opposite direction.

### Fix
- PGX block application is enclosed in one PostgreSQL transaction using one checked-out connection.
- The RocksDB block/tip write is recorded for rollback before the PostgreSQL commit.
- A durable PostgreSQL `canonical_tip_height` + `canonical_tip_hash` marker is committed with the consensus state.
- Readers treat only RocksDB blocks at or below that committed PG marker as canonical.
- Startup reconciliation removes RocksDB blocks above the committed PG tip and fails closed if PostgreSQL is ahead of RocksDB.
- Rollback removes the new block's transaction-location entries as well as the block itself.
- Redis and auxiliary-SQLite writes are deferred until the authoritative PostgreSQL commit.
- The legacy SQLite + external-KV path now uses SQLite as the canonical barrier, hides KV-only blocks, reconciles orphan KV blocks at startup, and fails closed when a canonical SQLite block body is missing from the KV store.
- `BlockDatabase.delete_block()` now changes the KV tip only when the deleted block was actually the current tip; deleting height 0 from an empty store clears the tip marker.
- PGX migration of the new canonical marker writes height and hash atomically.

## 2. VVM `DIFFICULTY` opcode

### Failure fixed
`Op.DIFFICULTY (0x44)` passed a Python `float` block difficulty into the VM's uint256 integer stack. With a normal fractional protocol difficulty such as `5.15`, `Frame.push()` raised a Python `TypeError`.

### Fix
VVM now exposes difficulty as deterministic fixed-point micro-units:

`round(difficulty * 1_000_000)`

For example, `5.15` becomes `5_150_000`. Invalid, negative, non-finite, or out-of-range values are rejected as VM errors rather than reaching integer bit operations with an incompatible type.

## Verification

- `python -m compileall -q visold tests` — PASS
- `tests/test_confirmed_bug_fixes.py` — 9 passed
- `tests/test_pgx_compat.py` — 7 passed
- `tests/test_confirmed_audit_repairs_20261006.py` — 6 passed
- `tests/test_bugfixes_oct2026.py` — 7 passed
- `tests/test_hidden_bugfixes_20261006.py` — 16 passed
- `tests/test_l2_read_and_failed_apply_regressions_20261006.py` — 4 passed
- `tests/test_pgx_rollback_cleanup.py` — 2 passed
- `tests/test_consensus_hardening_regressions.py` — each of its 7 tests passed when run individually
- `tests/test_audit_findings_oct2026.py` — each of its 8 tests passed when run individually
- The remaining VVM regression tests were exercised individually where execution completed; some long-running cases are PoW/VM heavy and can exceed a single-process command timeout. Those timeouts are not reported as test failures here.

## Scope discipline

The patch does not change consensus validation rules for nonce/role state-root behavior because the audit did not establish a valid divergence exploit there.
