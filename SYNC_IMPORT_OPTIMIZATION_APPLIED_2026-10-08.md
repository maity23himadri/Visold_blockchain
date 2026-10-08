# Visold 9 — Sync / Import Optimization

Date: 2026-10-08

## Scope

This patch targets historical block validation/import throughput while preserving the existing consensus and security model.

## Changes

1. **Single authoritative transaction-ID / Merkle integrity pass**
   - `Block.integrity_check()` can return the set of transaction IDs it actually checked.
   - `Blockchain.validate_block()` reuses that result instead of recomputing every transaction ID, the coinbase transaction ID, and the Merkle root a second time.
   - A fail-closed membership assertion rejects if a transaction lacks an integrity result.
   - The block transaction tuple is immutable after sealing and validation remains under the blockchain lock.

2. **Block-level account prefetching**
   - Sender balances for the entire block are fetched once with `get_balances_sat()`.
   - The validator continues to apply pending same-block debits locally, so the consensus calculation is unchanged.

3. **Block-level replay checks**
   - `existing_tx_ids()` checks both the canonical transaction table and the permanent replay-guard table in bounded batches.
   - The old per-transaction `tx_exists()` + `replay_guard_exists()` queries are no longer repeated for every transaction.
   - Query chunks are bounded to avoid SQLite parameter-limit issues.

4. **MTP timestamp projection**
   - The MTP window uses a timestamp-only indexed query instead of loading/deserializing every previous block in the window.
   - Missing heights remain omitted exactly as before.

5. **Hash-only previous-block lookup**
   - `prev_hash` validation reads the canonical stored block hash without constructing a full previous `Block` object.
   - SQLite external-KV and PGX paths retain the same canonical-body existence checks as their previous `get_block()` paths.
   - Duplicate-block idempotency uses the same hash-only path.

6. **Deserialization Merkle optimization**
   - A block loaded from a serialized representation can retain its authenticated stored Merkle root and defer recomputation to `integrity_check()`.
   - Ordinary `Block.seal()` retains its existing recomputation behavior.

## Security / consensus boundary

No signature verification was removed.

No transaction-ID verification was removed; its already-computed result is reused.

No Merkle verification was removed; its already-computed result is reused.

No replay protection, nonce rule, balance rule, PoW rule, block-size rule, state-root rule, timestamp rule, transaction validity rule, or block-order rule was relaxed.

No state mutation occurs during `validate_block()`. The new caches/prefetches are read-only consensus inputs.

## Verification

### Focused test results

- `tests/test_sync_import_optimizations.py`: **5 passed**
- `tests/test_crypto_acceleration_regressions.py`: **6 passed**
- `tests/test_consensus_security_fixes.py`: **9 passed**
- `tests/test_audit_fixes.py`: **11 passed**
- `tests/test_confirmed_bug_fixes.py`: **9 passed**
- `tests/test_hidden_bugfixes_20261006.py`: **16 passed**
- `tests/test_vvm_rollback_regressions.py`: **6 passed** (test process completed within the timeout)
- `compileall`: **passed**

The existing `tests/test_consensus_hardening_regressions.py` suite did not finish within the execution timeout in this environment, so it is **not** represented as a pass here.

`tests/test_vvm_selfdestruct_regressions.py` reported **4 passed** before its process teardown exceeded the execution timeout; this is also not counted as a clean suite pass.

The repository's `tools/verify_static.py` requires a missing legacy source file (`visold_vsd_original.py`) and therefore could not run against this archive; this is an existing tool/environment issue, not a patch diagnostic.

## Differential replay verification

A fixed 10-block / 100-transaction-per-block signed fixture was imported through both Visold 8 and Visold 9.

Both reached:

- height: **10**
- final block hash: `b5c8e758d5cb792358eea64ef772c2c3366b0fb9e4dc720176c950a9e30c96f6`
- final state root: `c3f5f8fa2f713c8354c533f0f8cead9022fe18a047c5423a846a06d264d93ccc`
- sender nonce: **1000**
- sender balance: **99,899,000,000,000 sat**
- receiver balance: **100,000,000,000 sat**

This is a direct compatibility check that the optimized import path produces the same committed chain state.

## Performance measurement

Same host, same pre-generated 10 linked blocks × 100 signed transactions, PoW bypassed only to isolate import/validation.

The timed benchmark included `Block.from_dict()` deserialization, validation, state application, and SQLite commits.

- Visold 8 median: **0.245657 s / 1000 tx ≈ 4,071 tx/s**
- Visold 9 median: **0.201094 s / 1000 tx ≈ 4,973 tx/s**
- Improvement: approximately **22% faster** on this fixture.

A separate benchmark that generated and signed the 1,000 transactions inside the timed interval was also faster, but that workload is not a pure sync/import benchmark because validators do not sign imported transactions. It measured approximately **1,329 → 1,459 tx/s**, about **10% faster**.

These are local benchmark results, not a claim of Bitcoin-equivalent protocol throughput.

## Deliberately not included

An authenticated state-snapshot / checkpoint synchronization protocol was **not** added in this patch. That is a protocol-level feature requiring an explicit trust/activation model, snapshot format, replay/fork rules, and cross-version interoperability tests. Adding it without those specifications would create significantly more consensus risk than the optimizations above.
