# Visold batch-signature validation acceleration — 2026-10-08

## Change

The block-integrity signature path was changed from one `ProcessPoolExecutor` job per transaction to one coarse-grained batch job per worker. The batch worker calls the existing `_par_verify_sig()` implementation unchanged for every transaction and returns the first failing offset (or `-1` for success).

This is an execution-topology optimization only. It does not introduce a second signature-verification algorithm and does not change the accepted transaction/signature semantics.

## Security properties preserved

- Sender-to-public-key binding remains enforced by `_par_verify_sig()`.
- Signature range checks and cryptographic verification remain unchanged.
- Historical legacy-signature handling remains passed through the same per-transaction verifier.
- Invalid signatures fail closed and reject the block.
- A valid block requires every non-coinbase transaction in every batch to pass.
- `verified_txids` is populated only after an entire batch returns success.
- The optimization does not modify tx IDs, signing bytes, Merkle rules, block hashing, PoW, or transaction consensus rules.
- Small blocks continue to use the existing sequential path.

## Measured performance

Reference host, same 100-transaction block workload, PoW isolated by using difficulty 0 for the benchmark:

| Version | Median validation time | Throughput |
|---|---:|---:|
| Visold 7 before this change | ~23.39 ms / 100 tx | ~4,275 tx/s |
| Visold 8 after batching | ~14.37 ms / 100 tx | **~6,960 tx/s** |

Improvement: approximately **1.63x** for the real block-integrity workload.

An isolated synthetic worker benchmark reached approximately 8.1k tx/s with three coarse-grained worker batches; the end-to-end block figure is the more relevant production measurement.

The supplied Bitcoin comparison reported approximately 10,361.56 tx/s equivalent, so the remaining gap on this host is approximately 1.49x.

## Validation performed

- `tests/test_crypto_acceleration_regressions.py`: **6/6 passed**.
- `tests/test_consensus_security_fixes.py`: **9/9 passed**.
- Python compile/import validation: passed.
- Six-transaction block integrity with `verified_txids`: passed.
- Tampered signature at positions 0, 5, and 11: all rejected by block integrity.

The broader repository test selection contains long-running tests that timed out in this execution environment; therefore this report does not claim the entire repository suite passed.

## Coincurve status

The optional Coincurve/libsecp256k1 dependency was not installed in this sandbox because outbound package installation was unavailable. No unverified Coincurve performance claim is included here.

## Modified files

- `visold/crypto/parallel_verify.py`
- `visold/ledger/block.py`
- `tests/test_crypto_acceleration_regressions.py`
