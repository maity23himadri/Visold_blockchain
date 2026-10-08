# Visold Security Fixes

This archive contains the source fixes for the confirmed consensus/security defects found during the 2026-10-06 audit.

## Fixed defects

1. **Non-finite block difficulty (`NaN` / `Infinity`) could bypass PoW and difficulty comparison.**
   - Consensus validation now rejects non-finite block difficulty before arithmetic.
   - `DifficultyEngine.difficulty_to_target()` rejects non-finite values.
   - `validate_pow_target()` fails closed on non-finite difficulty and malformed hashes.
   - `Block.mine()` fails closed on malformed difficulty instead of raising.

2. **Non-finite block timestamp (`NaN` / `Infinity`) could bypass timestamp checks and poison the DAA.**
   - Consensus block validation rejects non-finite timestamps.
   - `DifficultyEngine.validate_timestamp()` rejects non-finite timestamp/network-clock inputs.

3. **Transaction signing / tx-id preimages were ambiguous because fields were concatenated without boundaries.**
   - New transactions use a domain-separated, length-delimited canonical encoding with canonical integer economic values.
   - Amount/fee are committed in satoshis; gas price is committed in satoshis per gas; data is committed by full SHA-256 hash.
   - Historical pre-canonical transactions can be revalidated only through an explicit, height-gated migration path.

## Migration safety

`Config.TXID_CANONICAL_V3_ACTIVATION_HEIGHT` defaults to `0`, and `Config.TXID_CANONICAL_V2_LEGACY_ENABLED` defaults to `False`, which is the secure configuration for a fresh chain.

For an existing live chain containing pre-canonical transaction ids/signatures, operators must coordinate an upgrade and explicitly configure a future V3 activation height plus legacy compatibility until that height. The legacy path reproduces the archive's previous tx-id rules rather than guessing at their format.

## Verification performed

- `compileall` / `py_compile` passed for modified runtime modules.
- Modified runtime modules imported successfully.
- New security regression suite: **9 passed**.
- Existing audit/fix suites: **11 passed**.
- PGX compatibility/rollback suites: **9 passed**.
- Long-running consensus/VVM regression cases were executed individually; the previously timeout-prone grouped commands were not counted as test failures.

The added regression tests specifically cover the original `NaN` PoW bypass, timestamp bypass, transaction field-boundary rewrite, canonical signature verification, mempool acceptance, legacy migration compatibility, and network non-finite JSON rejection.
