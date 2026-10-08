# Visold 10 — Sync/Import Optimization Report

Date: 2026-10-08

## Scope

This release continues the Visold 9 performance work. It does not change consensus rules, transaction wire encoding, Merkle rules, block limits, PoW, signature semantics, state-transition semantics, or the persistence model.

The changes are limited to eliminating duplicate computation in already-authoritative validation paths and reducing historical difficulty-calculation I/O.

## Changes

### 1. Header-only difficulty history reads

`DifficultyEngine` previously loaded and deserialized a full block object for each block in its rolling LWMA window. `Storage.get_block_consensus_window()` now retrieves only `(timestamp, difficulty)` rows for the required height range.

SQLite uses a single range query over the canonical `blocks` table. PGX uses the canonical RocksDB header index. A compatibility fallback remains for storage adapters that only expose `get_block()`.

This preserves the exact timestamp/difficulty sequence consumed by the DAA while avoiding block-body JSON/messagepack work.

### 2. Single construction of the canonical transaction preimage

`Block.integrity_check()` previously called both `_compute_id()` and `signing_bytes()`, which rebuilt the same canonical V2 byte sequence twice for each transaction.

The implementation now constructs the canonical signing preimage once, hashes that exact byte sequence for the tx-ID commitment, and reuses the same bytes for ECDSA verification.

For historical legacy blocks, the existing legacy fallback remains explicitly height-gated and uses its exact legacy signing payload when needed.

### 3. Sequential verifier uses the same precomputed payload

Small blocks use the same standalone verification function but now receive the precomputed canonical payload, eliminating another duplicate encoding step without weakening signature verification.

## Benchmark

Paired 15-run benchmark on the same host and the same pre-generated 10-block / 1,000-transaction fixture, with PoW bypassed only to isolate import performance:

| Version | Median import time | Median throughput |
|---|---:|---:|
| Visold 9 | 0.208590 s | 4,794.09 tx/s |
| Visold 10 | 0.199115 s | 5,022.21 tx/s |

Visold 10 therefore measured approximately 4.76% higher throughput and 4.54% lower median import time than the Visold 9 source tree used in this paired run.

The user's separate Visold 9 benchmark reported 4,009.66 tx/s. That result uses a different run/harness context, so it is not treated as a direct apples-to-apples figure for this release claim.

## Differential correctness replay

The same 10-block / 1,000-transaction fixture was replayed through Visold 9 and Visold 10 from genesis. Both reached:

- height: 10
- final block hash: `b5c8e758d5cb792358eea64ef772c2c3366b0fb9e4dc720176c950a9e30c96f6`
- final state root: `c3f5f8fa2f713c8354c533f0f8cead9022fe18a047c5423a846a06d264d93ccc`
- sender balance: `99899000000000` satoshi
- sender nonce: `1000`

The final consensus/state outputs were identical.

## Verification

Focused release gate after the final changes:

- 26/26 focused consensus/security/sync/bug-regression tests passed.
- Python compile checks passed for modified modules.
- Tampered-transaction rejection and signature-validation regression coverage remained passing through the focused suite.

The full repository test collection was not reported as fully passing because `tests/test_consensus_hardening_regressions.py` contains long-running tests that exceeded the execution window in this environment. This is reported as an execution-time limitation, not as a passed result.

## Security posture

No validation rule was removed. The patch reuses results that have already been established by the authoritative cryptographic integrity pass. The DAA still consumes the exact same historical timestamp and difficulty values; only the storage read path changed.

The optional Coincurve/libsecp256k1 backend remains optional and was not benchmarked in this environment because package installation was unavailable.
