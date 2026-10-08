# Visold — Confirmed Bug Fix & Verification Report

## Scope

This patch addresses every defect confirmed during the prior repository audit. The changes are intentionally limited to the affected VM, state, storage, transaction-validation, PGX atomicity, and dependency-layer paths, plus regression tests.

## Confirmed defects fixed

1. **Persistent typed-storage metadata**
   - `TYPESET` metadata is staged with storage writes.
   - `TYPEDLOAD` sees staged metadata first and persisted metadata after a new frame.
   - Explicit tag `0` shadows an older persisted tag during the same execution.
   - SQLite/RocksDB persistence and snapshot/restore now carry typed-storage metadata.

2. **Nested CALL/CREATE value transfer**
   - Value-bearing nested calls/deployments use an execution-local balance overlay.
   - Source debit and recipient credit are committed only when the child succeeds.
   - Reverted children discard their transfer overlay.
   - `BALANCE`, `SELFBALANCE`, and `VSDBALANCE` include the in-flight overlay so contract code sees the correct balance during execution.

3. **Lossless VSD address encoding**
   - VM address words now round-trip canonical EOA addresses, canonical contract addresses, and legacy/precompile string addresses without hashing an address into an unrelated address.
   - Address-consuming opcodes therefore operate on the actual intended address.
   - ECRecover output now uses the same canonical VM address-word encoding for recovered EOAs.

4. **CREATE2 constructor storage address mismatch**
   - CREATE2 constructors execute under the deterministic published CREATE2 address.
   - Constructor storage therefore belongs to the deployed contract rather than a temporary nonce-derived address.

5. **PGX rejected-block issuance metadata**
   - Block application snapshots `cumulative_issued_sat` before mutation and restores it on every block-rejection/exception path.
   - The fix is specific to the confirmed PGX atomicity gap and does not duplicate the normal chain-rollback reversal logic.

6. **Legacy TX-ID migration validation**
   - Block validation now recomputes transaction IDs with the block height, matching the height-aware V1/V2 selection used by block integrity checking.

7. **Non-finite transaction numeric validation**
   - `NaN`, `+Infinity`, and `-Infinity` are rejected for amount, fee, and gas price during transaction validation.

8. **Architecture dependency violations**
   - Shared bounded decompression logic was moved into the kernel layer so rollup/storage no longer import upward into the network layer.

## Regression coverage added

`tests/test_audit_fixes.py` contains 7 focused tests covering:

- lossless address round-trips and real `ADDRESS -> BALANCE` behavior;
- persisted typed-storage tags and explicit default-tag clearing;
- successful and reverted nested value transfers;
- immediate `SELFBALANCE` visibility during value-bearing execution;
- CREATE2 constructor state at the published address;
- non-finite transaction rejection;
- snapshot rejection of orphan typed-storage metadata.

## Verification performed

- New audit-fix tests: **7 passed**
- Embedded Visold verification suite: **153/153 passed**
- Hardened verification suite: **10 passed, 0 failed**
- SC-NAME-1 checks: **T1–T5 passed**
- Architecture checker: **OK — no cycles, layering respected**
- Repository compile check: **passed**
- VVM rollback regression cases: **all 6 passed across individual runs**
- VVM self-destruct regression cases: **all 4 passed across individual runs**
- Direct ECRecover canonical-address regression: **passed**
- Direct legacy TX-ID migration check: **passed**
- Direct snapshot orphan-tag rejection check: **passed**

## Verification limitations

I did **not** claim a clean result for the entire pytest suite. The repository's broad pytest invocation exceeded the execution limit before producing a completed suite summary; the targeted cases and the embedded 153-test suite were run separately.

A live PGX/RocksDB adapter run was not possible because the uploaded environment is missing the `rocksdict` dependency. The PGX issuance fix was therefore verified by source-level control-flow inspection rather than a live PostgreSQL/RocksDB execution.

Two baseline-comparison verification scripts also expect `visold_vsd_original.py`, which is not present in the uploaded archive. Those tools were not treated as evidence of a code failure.

## Protocol/upgrade note

The typed-storage fix makes type metadata persistent and includes explicit typed metadata in the contract-storage state root when such metadata exists. The address-word fix also corrects VM-visible address semantics. These are intentional protocol corrections; validators/miners using this fixed implementation should be upgraded consistently rather than mixing implementations that disagree on these corrected semantics.
