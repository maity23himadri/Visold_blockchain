# Visold — Confirmed Bug Fixes Applied (2026-10-06)

This archive contains the source tree from `Visold_9.zip` with only the two
confirmed bugs from the 2026-10-06 audit repaired, plus regression tests for
those repairs.

## 1. Minimum miner/investor stake was not consensus-enforced

### Root cause
`RoleManager.register_miner()` / `register_investor()` already enforced the
configured minimum for the normal UI/API path, but a directly constructed and
signed `TYPE_REGISTER` transaction could bypass those checks. `Transaction.is_valid()`
has no storage context, so the original block validator did not enforce the
state-dependent minimum either.

### Fix
`visold/chain/blockchain.py` now enforces the minimum during block validation
using the canonical pre-block/in-block role shadow state:

- initial miner registration: at least `Config.MIN_MINER_STAKE` (10 VSD)
- initial investor registration: at least `Config.MIN_INVESTOR_STAKE` (200 VSD)
- existing same-role registrations remain additive top-ups and may be any
  positive amount
- existing same-block `UNREGISTER -> REGISTER` semantics are preserved
- slashed/opposite-role handling remains unchanged

`visold/mempool/pool.py` also rejects an obvious initial sub-minimum
registration before gossip/persistence.

## 2. VVM block gas limit was configured but not enforced

### Root cause
`Config.VVM_BLOCK_GAS_LIMIT` declared a maximum total VVM gas budget per block,
but block validation never compared the aggregate VVM `gas_limit` values against
that bound.

### Fix
`visold/chain/blockchain.py` now deterministically sums `gas_limit` for all
`TYPE_DEPLOY` / `TYPE_CALL` transactions and rejects the block when the total is
greater than `Config.VVM_BLOCK_GAS_LIMIT`.

The check uses the same quantity already tracked by block application
(`gas_limit`), so candidate-state-root semantics remain aligned.

## Upgrade safety

Two explicit activation-height configuration knobs were added:

- `Config.ROLE_STAKE_MIN_ACTIVATION_HEIGHT = 0`
- `Config.VVM_BLOCK_GAS_LIMIT_ACTIVATION_HEIGHT = 0`

`0` keeps the secure behavior active from genesis on fresh chains. For a live
chain that already contains pre-fix history, operators should coordinate a
future activation height across all nodes rather than retroactively invalidating
old blocks.

## Verification performed

### Compile
- `python -m compileall -q visold tests` — PASS

### New regression tests
- `tests/test_confirmed_audit_repairs_20261006.py` — **6 passed**

### Existing targeted regression groups
- `tests/test_confirmed_bug_fixes.py` — **4 passed**
- `tests/test_audit_findings_oct2026.py` — **4 passed**
- `tests/test_hidden_bugfixes_20261006.py` — **16 passed**
- `tests/test_consensus_security_fixes.py` — **9 passed**
- `tests/test_bugfixes_oct2026.py` — **7 passed**
- `tests/test_pgx_rollback_cleanup.py` — **2 passed**
- `tests/test_pgx_compat.py` — **7 passed**
- `tests/test_udp_security_fixes_20261006.py` — **6 passed**

Total targeted pytest coverage completed: **61 passed, 0 failed**.

### Full embedded Visold suite
`python visold_vsd_.py --test`

**153/153 passed, 0 failed**.

### Architecture
`python tools/check_architecture.py`

**ARCHITECTURE: OK — no cycles, layering respected**.

## Verification limitations

The external `tests/test_vvm_rollback_regressions.py` pytest invocation did not
finish within the audit runner timeout after several tests had passed. The
Visold embedded suite's VVM rollback section completed successfully, including
its deploy/call rollback checks. This timeout was not caused by the two patched
paths and was not treated as a new product bug.

The archive's PGX/RocksDB-specific runtime backend is also not available in this
environment; PGX compatibility/static tests were run where supported.

## Files changed for the repair

- `visold/chain/blockchain.py`
- `visold/mempool/pool.py`
- `visold/kernel/config.py`
- `tests/test_confirmed_audit_repairs_20261006.py`
- `FIX_APPLIED_2026-10-06.md`
