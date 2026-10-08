# Visold Hardening Fixes — 2026-10-06

This build contains targeted fixes for four confirmed consensus/state-integrity defects found during source audit of the supplied Visold implementation.

## Fixed defects

1. **Active-stake spend bypass**
   Block validation now reserves existing active miner/investor stake and simulates REGISTER mutations in transaction order. A transfer cannot consume coins that are locked as active stake. Same-block registration stake is also reserved, while valid transactions with sufficient backing remain accepted.

2. **SQLite block-application crash inconsistency**
   SQLite block application now runs inside one Storage-owned atomic transaction. Legacy inner `commit()`/`rollback()` calls are suppressed during the atomic section. Persistent state changes and the canonical block record therefore commit together or roll back together on process death or application failure.

3. **Validator double-sign evidence lost across reorgs**
   Validator votes now persist their target block height explicitly. Equivocation lookup uses that immutable height rather than joining against the current canonical block, so orphaned votes remain detectable after a reorg.

4. **REGISTER rollback not being a true inverse**
   Forward block application records an exact pre-block role snapshot, including stake, score, slashed flag, and `registered_at`. Rollback restores that snapshot before reward reversal. Missing snapshots fail closed rather than reconstructing potentially incorrect state.

## Verification performed

- Python compile check: passed.
- Built-in Visold test suite: **153/153 passed, 0 failed**.
- Targeted regression tests for the four defects: passed, including the process-death/restart regression.
- Additional regression: same-block REGISTER with sufficient backing remains valid.
- The VVM rollback tests can be slow/flaky when several PoW-mining pytest cases are executed in one process; the affected individual tests pass, and the built-in 153/153 suite completes successfully. This was not changed or classified as a new consensus defect.

## Scope note

The atomic crash-consistency fix covers the default SQLite persistence path used by this audit. PostgreSQL/PGX and optional external block-database backends were not represented as part of the reproduced crash boundary and were not altered beyond the role/vote persistence changes required by the audited logic.
