# Visold L2 State Fix Report — 2026-10-06

## Confirmed defects repaired

### 1. Read-only L2 balance/nonce lookup mutated consensus state
`Layer2State.get_balance_sat()` and `get_nonce()` previously called `L2StateTree.get()`, whose missing-account behavior creates a zero-balance account. Querying an unknown address therefore changed `account_count()` and the L2 Merkle root.

**Fix:** added `L2StateTree.peek()` as a strictly non-mutating lookup primitive and switched both read methods to it. Missing accounts still return balance/nonce `0`, preserving the external API result while removing the state mutation.

### 2. Failed L2 transfer could mutate the state root
`Layer2State.apply_l2_tx()` previously called the mutating `get()` before checking nonce/balance. A validly signed transaction from an address with no L2 account therefore created a zero-balance account before being rejected for insufficient balance. Because the sequencer computes `batch.new_root` after trying all pending transactions, that ghost account could make the proposed root differ from replay of the transactions actually included in the batch.

**Fix:** `apply_l2_tx()` now uses `peek()` and immediately rejects an absent sender as insufficient balance. The failed path is state-free.

### 3. Failed L2 debit could create a ghost account
`L2StateTree.debit()` used the mutating `get()` before checking the account balance. A failed debit against a missing address therefore created a zero-balance account.

**Fix:** `debit()` now uses `peek()` and leaves the tree unchanged whenever the debit cannot succeed.

## Regression tests added

`tests/test_l2_read_and_failed_apply_regressions_20261006.py` covers:

- unknown-address balance/nonce reads do not change root or account count;
- failed transfer from a missing sender is state-free;
- failed debit from a missing account is state-free;
- a failed transaction cannot poison the root of a mixed batch, verified by clean replay equivalence.

## Verification

- New L2 regression tests: **4/4 passed**
- Previously audited targeted regression set: **65/65 passed**
- Built-in Visold suite: **153/153 passed, 0 failed**
- Python compilation: **passed**
- Architecture checker: **118 modules / 443 import edges / 22 contexts — OK**
- Original-snapshot reproduction: both confirmed mutations reproduced before the fix

## Full pytest-suite limitation

A repository-wide `pytest -q tests` run reached the long-running VVM/PoW portion without reporting a test failure, but exceeded the execution window before completing. It is therefore **not** reported as a full-suite pass.
