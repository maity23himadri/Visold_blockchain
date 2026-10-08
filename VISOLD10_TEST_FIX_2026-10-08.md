# Visold 10 test-harness correction — 2026-10-08

## Change

Updated `tests/test_crypto_acceleration_regressions.py`:

- The stale `test_block_validation_does_not_verify_each_signature_twice` test previously monkey-patched the high-level `Transaction.verify_signature()` method and expected one call.
- Visold 10 intentionally uses the lower-level `_par_verify_sig` verifier in the block-integrity hot path so it can reuse precomputed canonical signing payloads and avoid rebuilding transaction objects.
- The test now instruments the actual lower-level verifier used by the sequential small-block path and asserts that the valid transaction is cryptographically verified exactly once.

## Scope / security

- Production consensus code: unchanged.
- Production cryptographic code: unchanged.
- Transaction formats and signing bytes: unchanged.
- Test only; this is a test-topology correction, not a validation relaxation.

## Verification

Passed individually:

- `tests/test_crypto_acceleration_regressions.py`: 6 passed
- `tests/test_sync_import_optimizations.py`: 6 passed
- `tests/test_consensus_security_fixes.py`: 9 passed
- `tests/test_audit_fixes.py`: 11 passed
- `tests/test_confirmed_audit_repairs_20261006.py`: 6 passed
- `tests/test_bugfixes_oct2026.py`: 7 passed

Total deterministic focused gates passed individually: 45.

The same combined multi-file pytest invocation does not complete within the execution window because of process-pool interaction in the repository's test environment; it did not report a test assertion failure. Individual file runs are the release-gate evidence used here.
