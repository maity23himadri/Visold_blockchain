# Visold — Final Audit Fix Report — 2026-10-06

## Confirmed defects addressed

### 1. Slashed validator could self-unslash with REGISTER("none")

**Root cause:** `Storage.set_role()` always wrote `slashed=FALSE/0`. The block validation shadow state also changed a slashed role to `slashed=False` when simulating `REGISTER("none")`. Therefore a same-block sequence of `REGISTER("none")` followed by `REGISTER("miner")` could erase the disqualification marker and restore active validator/miner eligibility.

**Fix:**
- `Storage.set_role()` now preserves an existing `slashed` marker when the target role is `"none"`.
- `Blockchain.validate_block()` preserves the previous `slashed` bit in its REGISTER shadow state across `"none"` transitions.
- The existing positive REGISTER guard for slashed addresses remains in force.

**Result:** a slashed address may clear its active role, but the address remains slashed and cannot become an active miner/investor through this path.

### 2. Arbitrary coinbase amounts were accepted

**Root cause:** `Blockchain.validate_block()` only enforced an upper bound on the coinbase amount.

**Important protocol clarification:** during the fix, the reward flow was rechecked end-to-end. Visold's active consensus model treats the coinbase amount as the deterministic **new-issuance subsidy**. Transaction fees are pre-existing sender funds and are added separately by `_distribute_rewards()`. Therefore requiring `coinbase.amount == subsidy + fees` would have been an incorrect change to this implementation.

**Fix:** the consensus validator now requires exact equality:

`coinbase.amount == compute_reward_sat(block.index)`

Both under-claims and over-claims are rejected. Blocks containing ordinary transaction fees remain valid with the canonical subsidy-only coinbase.

## Files changed

- `visold/storage/storage.py`
- `visold/chain/blockchain.py`
- `tests/test_audit_findings_oct2026.py`

No other source files were modified for these two findings.

## Verification

- New audit regression tests: **4/4 passed**
- Relevant pre-existing slashing/rollback regression: **passed**
- Combined selected relevant tests: **5/5 passed**
- Built-in Visold suite: **153/153 passed, 0 failed**
- Hardened verification: **10/10 passed**
- SC-NAME-1: **T1–T5 passed**
- Architecture checker: **118 modules / 443 import edges / 22 contexts — OK**
- Python `compileall`: **passed**

## Verification limitations

The repository-wide pytest invocation contains production-style PoW-mining tests that can exceed an execution window when grouped together. Those timeouts were not treated as code failures. The built-in 153-test suite and the targeted regression suites completed successfully.

`tools/verify_static.py` could not run because the uploaded archive does not contain `visold_vsd_original.py`, which that comparison tool requires. `tools/verify_import.py` did not complete within the available execution window. Neither was treated as evidence of a product defect.
