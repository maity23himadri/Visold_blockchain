# Visold V4 Bug-Fix Progress — Batch 1 (2026-10-29)

## Scope

This session processed BUG-1, BUG-2, BUG-10, BUG-21, and BUG-45 from the supplied 46-finding audit. The untouched source is preserved separately as `/mnt/data/visold_v4_baseline`; all edits were made in `/mnt/data/visold_v4_work`.

The network is expected to restart from genesis, so no old-chain compatibility workaround was added. Changes were kept narrowly scoped to the demonstrated defects.

## Batch summary

| Bug | Classification after V4 verification | Result | Root cause | Fix | Regression evidence |
|---|---|---|---|---|---|
| BUG-1 | Confirmed | FIXED in this batch | `validate_block()` accepted an empty `miner_address`; reward rollback also skipped proposer debits when the address was empty | Reject empty/whitespace miner addresses before deeper block validation; make reward rollback an exact inverse even for a legacy empty-miner block | New tests reject empty miner and verify reward distribute→rollback restores the empty-address balance exactly |
| BUG-2 | Confirmed | FIXED in this batch | `Transaction.is_valid()` did not validate ordinary transfer receiver shape, so arbitrary strings could become balance keys | Added canonical consensus address validation for `TYPE_TRANSFER` only; accepts canonical wallet addresses, canonical VVM contract addresses, and explicit protocol sentinel receivers | New test rejects `""`, `"x"`, garbage and malformed VSD strings; accepts wallet/contract/special receivers; separate regression proves REGISTER with empty receiver is unchanged |
| BUG-10 | Confirmed | FIXED in this batch | `_SerializedSQLiteConnection.commit_atomic()` cleared `_atomic` in `finally` even when COMMIT failed, leaving SQLite's transaction active and making rollback a no-op | On COMMIT exception, immediately call raw SQLite rollback before releasing atomic ownership, then re-raise original failure | Real rollback-journal lock conflict: baseline leaves `in_transaction=True` and later commits partial row; patched code leaves `in_transaction=False`, row absent, and same connection can start/commit a later atomic transaction |
| BUG-21 | Confirmed | FIXED in this batch | `L2Transaction.is_valid()` checked only non-empty sender/receiver, allowing malformed L2 receiver strings to become state accounts | Reuse canonical protocol address validation at the L2 transaction validation boundary | New test rejects malformed L2 receivers before apply and proves L2 root/balance do not change; valid wallet receiver remains accepted |
| BUG-45 | Confirmed | FIXED in this batch | Withdrawal was first processed as an ordinary L1 transfer to `L2_WITHDRAW_ADDRESS`, then the bridge hook debited escrow and credited the sender, leaving the routing transfer stranded and requiring L1 prefunding | Treat withdrawal as its own settlement branch: debit gross amount from L2 and bridge escrow; credit `amount - fee` to sender on L1; put fee in normal fee pool; never credit withdrawal sentinel; mirror same rule in validation, candidate dry-run, mempool pending-outflow accounting, node submission, and rollback | Real block build/mine/apply/rollback with user starting at 0 L1: user receives net payout, L2 and escrow decrease by gross amount, sentinel stays 0, supply invariant holds, rollback restores exact pre-state |

## Intended invariants established

### L1 address validation (BUG-2)
Only ordinary `TYPE_TRANSFER` receiver validation was changed. REGISTER semantics were deliberately not changed. A valid receiver is one of:

- canonical wallet address: `VSD` + canonical Base58 encoding of exactly 20 bytes;
- canonical deterministic contract address: `VSDc` + 36 hex characters;
- explicit protocol receiver used by the existing protocol: global market, burn address, L2 bridge, or L2 withdrawal sentinel.

### L2 withdrawal accounting (BUG-45)
For a gross withdrawal `A` and normal transaction fee `F`:

- L2 sender balance decreases by `A`;
- L1 bridge escrow decreases by `A`;
- L1 sender balance increases by `A - F`;
- the normal block fee pool increases by `F`;
- `L2_WITHDRAW_ADDRESS` receives **zero**;
- the sender does not need `A + F` already present on L1;
- rollback restores the exact pre-block L1/L2/escrow state.

## Source changes

- `visold/ledger/addressing.py` — new shared canonical address-shape helpers.
- `visold/ledger/transaction.py` — consensus receiver validation for ordinary L1 transfers.
- `visold/rollup/l2_state.py` — L2 receiver validation.
- `visold/storage/sqlite_serialized.py` — failed-COMMIT rollback/state fix.
- `visold/chain/blockchain.py` — empty miner rejection, reward rollback inverse, and corrected L2 withdrawal validation/dry-run/apply/rollback accounting.
- `visold/mempool/pool.py` — withdrawal pending-outflow no longer requires nonexistent L1 principal/fee prefunding.
- `visold/node/visold_node.py` — withdrawal submission now builds the correct settlement transaction without requiring L1 principal prefunding.
- `tests/test_bugfix_batch1_20261029.py` — targeted regression coverage.

## Before/after reproductions

Command used for both trees:

```bash
cd <tree> && PYTHONPATH=. python /mnt/data/probe_batch1_before_after.py <label>
```

### Untouched V4 baseline

- BUG-2 malformed L1 receiver: `(True, 'OK')`.
- BUG-21 malformed L2 receiver: validation and apply both succeeded; malformed account received 10 sat.
- BUG-10 failed COMMIT: `_atomic=False`, `in_transaction=True`; `rollback_atomic()` did nothing; later ordinary commit persisted the partial row.
- BUG-1 empty miner block: `validate (True, 'OK')`.
- BUG-45 with 5 VSD L1 pre-fund + 4 VSD L2 withdrawal: post-apply user L1 `4.96 VSD`, L2 `0`, bridge `0`, withdrawal sentinel `4.00 VSD` — gross amount stranded at sentinel.

### Patched tree

- BUG-2 malformed L1 receiver: rejected with `Invalid transfer receiver address`.
- BUG-21 malformed L2 receiver: validation/apply rejected; malformed account remained 0.
- BUG-10 failed COMMIT: `_atomic=False`, `in_transaction=False`; later commit did not persist the partial row.
- BUG-1 empty miner block: rejected with `Block miner_address must be non-empty`.
- BUG-45 same pre-funded probe: sentinel remains 0 and user receives an additional 3.96 VSD net withdrawal payout. The dedicated regression also verifies the more important zero-L1-prefund case.

## Test log

### New targeted regression module

```bash
cd /mnt/data/visold_v4_work
PYTHONPATH=. pytest -q tests/test_bugfix_batch1_20261029.py
```

Final result: **8 passed in 2.08s**.

An earlier version of this module was **7 passed in 18.21s** before the explicit REGISTER non-regression case was added.

### Existing focused suites

```bash
PYTHONPATH=. pytest -q tests/test_sqlite_atomic_begin_race.py
```
Result: **1 passed in 0.10s**.

```bash
PYTHONPATH=. pytest -q tests/test_l2_read_and_failed_apply_regressions_20261006.py
```
Result: **4 passed in 0.13s**.

```bash
PYTHONPATH=. pytest -q tests/test_audit_fixes.py
```
Result: **11 passed in 0.20s**.

```bash
PYTHONPATH=. pytest -q tests/test_consensus_security_fixes.py
```
Result: **9 passed in 0.17s**.

### Existing adjacent tests run individually

```bash
PYTHONPATH=. pytest -q tests/test_consensus_hardening_regressions.py::test_same_block_register_stake_is_also_reserved
```
Result: **1 passed in 10.28s**.

```bash
PYTHONPATH=. pytest -q tests/test_consensus_hardening_regressions.py::test_same_block_register_with_sufficient_backing_remains_valid
```
Result: **1 passed in 2.32s**.

```bash
PYTHONPATH=. pytest -q tests/test_consensus_hardening_regressions.py::test_unregister_rollback_restores_exact_prior_role_metadata
```
Result: **1 passed in 4.47s**.

```bash
PYTHONPATH=. pytest -q tests/test_consensus_hardening_regressions.py::test_ignored_register_rollback_does_not_unstake_or_unslash
```
Result: **1 passed in 14.05s**.

```bash
PYTHONPATH=. pytest -q tests/test_vsa_block_application_20261014.py::test_precheck_applies_cumulative_l2_balance_and_escrow_for_withdrawals
```
Result: **1 passed in 0.17s**.

### Syntax/import compilation

```bash
python -m compileall -q visold tests/test_bugfix_batch1_20261029.py
```
Result: **PASS (`COMPILEALL_OK`)**.

## Timeouts / environment observations

These are **not counted as passes**:

1. A grouped adjacent-test invocation timed out after printing one completed test. The same selected tests subsequently completed successfully when isolated.
2. Earlier in this session, the full `tests/test_vsa_block_application_20261014.py` module exceeded a 300-second limit. Its relevant L2 precheck test completes successfully alone. This remains an order/teardown/background-thread test-suite issue to investigate; no claim is made that the whole VSA module passed.
3. An earlier 90-second grouped run similarly timed out. It is retained as a timeout, not reclassified as success.

## Review notes / remaining risk for this batch

- BUG-10 was reproduced with a real SQLite rollback-journal lock conflict because that reliably causes COMMIT failure. Production uses WAL. The wrapper state-machine fix is backend-independent, but a real production-WAL disk-full/I/O-failure injection test remains desirable.
- BUG-45 is now covered through real `Blockchain`/`ConsensusEngine` block application and rollback, but additional reorg/reinclusion tests should be added in a later broader L2 acceptance pass.
- BUG-6 remains open. Rejecting empty miner blocks fixes the consensus trigger of BUG-1, but direct/local calls to `dry_run_state_root(..., miner_address="")` should still be handled explicitly under BUG-6.
- This batch does not claim any disposition for BUG-3 through BUG-46 except BUG-10, BUG-21, and BUG-45 listed above.

## Persistent 46-finding status

- **Fixed + verified in Batch 1:** BUG-1, BUG-2, BUG-10, BUG-21, BUG-45.
- **Pending verification/fix:** BUG-3–BUG-9 (except BUG-10), BUG-11–BUG-20, BUG-22–BUG-44, BUG-46.
- **Important:** no pending item is marked fixed merely because the audit says it exists. Each must still be re-verified against the patched source before modification.

## Recommended next batch

Continue with closely coupled consensus/state-safety issues: **BUG-6, BUG-7, BUG-8, BUG-5**, then **BUG-3/BUG-4** if time permits. BUG-7 and BUG-8 should be handled together only after independent reproduction because the exception path in BUG-8 amplifies BUG-7's reorg failure.
