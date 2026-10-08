# Visold — October 2026 Bug-Fix Verification

This build applies only the defects that were confirmed by direct reproduction in the supplied codebase. No speculative warnings were converted into code changes.

## Fixed defects

### 1. Consensus block-size validation was node-local
`Blockchain.validate_block()` previously used `get_dynamic_block_size()`, whose result depends on local mempool depth and local network RTT. That could make identical blocks valid on one honest node and invalid on another.

**Fix:** consensus validation now uses the deterministic `Config.MAX_BLOCK_SIZE`. Dynamic sizing remains candidate-building policy only.

### 2. Unknown transaction types were fail-open
An unsupported `tx_type` could fall through into normal transfer validation.

**Fix:** `Transaction.is_valid()` now rejects every unsupported transaction type and also rejects malformed non-string type values without throwing.

### 3. Same-block unregister/re-register double-counted stake
The validation shadow state cleared the role but did not release the previous locked-stake reserve. A later REGISTER in the same block could therefore be rejected even though `apply_block()` would execute the sequence correctly.

**Fix:** the validation reserve is set to zero when the shadow role transitions to `none`.

### 4. Candidate block builder ignored complete block overhead
The builder budgeted only transaction bytes. Coinbase and block-level serialization overhead could push the completed candidate above the hard block cap.

**Fix:** after deterministic state-root calculation, the builder constructs the complete candidate and trims tail transactions until the complete serialized block is within `Config.MAX_BLOCK_SIZE`.

### 5. Fork choice used linear difficulty instead of cumulative PoW work
`Blockchain._cumulative_difficulty()` previously summed difficulty labels. Visold's consensus work model is proportional to `2 ** (4 * difficulty)`, so the old metric could select a lower-work chain.

**Fix:** fork-choice comparison now accumulates canonical PoW work using decimal arithmetic, avoiding binary-float overflow near `Config.MAX_DIFFICULTY`.

## Verification

- New targeted regression suite: **7/7 passed**.
- Existing non-PoW-heavy pytest suites selected for regression verification: **36/36 passed**.
- Built-in Visold verification suite: **153/153 passed, 0 failed**.
- Architecture checker: **118 modules, 443 import edges, 22 contexts — OK**.
- The new regression tests fail against the original ZIP on all five confirmed defects.
- Python compilation: **passed**.

## Test-suite note

Some existing pytest files contain intentionally real PoW-mining tests at the production bootstrap difficulty. Those tests can run long when invoked together in one process. A timeout in such a PoW loop was not treated as a product bug and was not changed merely to make the suite finish faster.

## Deployment note

The fork-choice implementation is consensus behavior. All nodes participating in the same network should run the fixed build together rather than mixing this implementation with nodes that still use the old linear-work fork-choice rule.
