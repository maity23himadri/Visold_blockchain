# Visold batch-validation acceleration — 2026-10-08

## Change

The block-validation pipeline previously performed ECDSA signature verification in `Block.integrity_check()` and then performed the same signature verification again inside `Transaction.is_valid()`.

This patch records the exact non-coinbase transaction IDs whose signatures were proven during the integrity pass and passes that fact into the subsequent semantic-validation pass. Only that redundant second ECDSA operation is skipped.

Normal callers of `Transaction.is_valid()` still verify signatures by default. The optimization is only enabled by `Blockchain.validate_block()` after the block integrity pass has established tx-id integrity and signature validity.

## Security properties preserved

- Consensus transaction encoding unchanged.
- Signature payload and historical-signature compatibility rules unchanged.
- Sender/public-key binding remains enforced in the integrity pass.
- Mempool verified-signature skipping remains bounded by the tx-id integrity check.
- No global trust flag or process-wide "verified" state was introduced.
- Ordinary `Transaction.is_valid()` callers still require signature verification unless the narrowly scoped block-validator flag is explicitly supplied.
- Optional Coincurve/libsecp256k1 acceleration remains independent of this change.

## Regression tests

Focused security/crypto/block-validation tests: **21 passed**.

The full repository pytest run did not complete within the execution timeout; no failure was reported before timeout. It is therefore not claimed as a full-suite pass.

## Performance measurements

On the same reference host, using an actual 100-transaction Visold block-validation workload with PoW computation bypassed only for benchmark isolation:

| Version | Median block validation | Effective throughput |
|---|---:|---:|
| Before this optimization | ~62.82 ms / 100 tx | ~1,592 tx/s |
| After this optimization | ~23.69 ms / 100 tx | **~4,221 tx/s** |

This is approximately **2.65× faster** for the full validation path.

A focused profile of the patched path measured approximately:

- Total: ~24.76 ms / 100 tx
- Integrity/signature pass: ~21.86 ms
- Remaining semantic validation: ~2.90 ms

Therefore the remaining bottleneck is predominantly ECDSA verification itself. The current process-pool OpenSSL path measured ~22.93 ms for the 100-signature integrity workload versus ~39.26 ms sequentially on the same host.

The earlier user-supplied comparison of Visold 6 (~1,825 tx/s) versus Bitcoin Core (~10,362 tx/s equivalent) was not protocol-equivalent, but the new measurement confirms that there was a real redundant-validation cost inside Visold that could be removed safely.

## Next performance target

The next optimization should target the native signature engine and cross-process overhead (Coincurve/libsecp256k1 or an equivalent audited native secp256k1 backend), while keeping the current OpenSSL implementation as a verified fallback. No consensus changes are required or proposed for that step.
