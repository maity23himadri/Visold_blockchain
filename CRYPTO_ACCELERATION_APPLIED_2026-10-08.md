# Visold cryptographic acceleration patch — 2026-10-08

## Scope

This patch accelerates the ECDSA/signature hot path without changing Visold consensus rules or transaction wire formats.

### Implemented

1. **Wallet-local native private-key reuse**
   - The mandatory `cryptography`/OpenSSL private-key object is constructed once per wallet and reused for signing.
   - The optional Coincurve/libsecp256k1 private-key object is also wallet-local and reused when the optional backend passes its startup self-test.
   - Native key objects are excluded from pickle serialization and rebuilt after unpickling.

2. **Prehashed ECDSA path**
   - Visold's historical behavior signs/verifies `SHA256(SHA256(original_message))` because callers provide the first digest and the previous implementation applied SHA-256 again inside the ECDSA API.
   - The patch computes that exact effective digest explicitly and uses `Prehashed(SHA256)` so the cryptography backend does not hash the same bytes a second time.
   - Cross-version signatures were verified in both directions against the original archive.

3. **Bounded public-key caches**
   - OpenSSL public-key objects, optional libsecp256k1 public-key objects, and compressed-key decompression coordinates each use bounded 8192-entry LRU caches.
   - No global private-key cache is used.

4. **Optional libsecp256k1 acceleration**
   - `requirements-crypto-accelerated.txt` pins Coincurve 21.0.0 as an optional dependency.
   - The optional backend is enabled only after a startup self-test that checks valid signing/verification, invalid-signature rejection, and OpenSSL interoperability.
   - A failed self-test disables the optional backend and retains the mandatory cryptography/OpenSSL path.

## Consensus/security boundary

No block size, block interval, transaction canonicalization, signature payload, Merkle rule, address encoding, PoW rule, or validation acceptance rule was changed.

The Merkle optimization experiment was **not shipped** because it benchmarked slower than the existing implementation on the reference host.

## Verification performed

- Focused crypto/consensus/security regression set: **38 passed**.
- Original-build signature → patched-build verification: **PASS**.
- Patched-build signature → original-build verification: **PASS**.
- Wallet pickle/unpickle with native key cache: **PASS**.
- Optional-backend control-flow path: exercised with an API-compatible cryptographic stub; startup self-test passed and signature verification passed.

The container did not have Coincurve installed, and outbound package installation was unavailable, so the actual Coincurve/libsecp256k1 wheel was not benchmarked here. The production fallback remains mandatory and was fully exercised.

Some broad existing integration tests were long-running in this environment; they were not represented as successful merely because the focused tests passed.

## Reference-host microbenchmarks

The following medians were measured against a clean extraction of the supplied archive on the same host:

| Operation | Original | Patched | Change |
|---|---:|---:|---:|
| Wallet signing | ~1060.6 µs | ~351.9 µs | ~3.0× faster |
| Repeated transaction signature verification | ~478.7 µs | ~345.0 µs | ~1.39× faster |

These are local microbenchmarks, not a claim about every production hardware target. The optional libsecp256k1 backend is expected to provide the larger cryptographic acceleration when its verified binary is installed.
