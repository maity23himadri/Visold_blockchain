# Visold cryptographic acceleration

## Security boundary

Consensus transaction bytes, the historical double-SHA ECDSA digest rule,
public-key/address encoding, signature integer encoding, Merkle rules, block
limits, and validation decisions are unchanged by the acceleration layer.

The mandatory `cryptography` / OpenSSL implementation remains available as the
fallback. The optional Coincurve/libsecp256k1 backend is enabled only after a
startup compatibility self-test covering valid signing/verification, invalid
signature rejection, and OpenSSL interoperability. A failed self-test disables
the optional backend rather than lowering security or changing consensus.

## Optional installation

Install the pinned optional dependency from `requirements-crypto-accelerated.txt`
after verifying its provenance in the deployment supply-chain. Nodes remain
functional without it.

## Key lifetime and DoS controls

Native private-key objects are cached only on individual wallet objects and are
never serialized. Pickle reconstructs them after deserialization. Public-key
objects and compressed-key decompression results use bounded 8192-entry LRU
caches so attacker-controlled public keys cannot grow process memory without
bound.

## What was deliberately not shipped

An alternative V2 Merkle byte-buffer implementation was benchmarked but was
slower on the reference host, so it was reverted rather than adding complexity
without a measured win.
