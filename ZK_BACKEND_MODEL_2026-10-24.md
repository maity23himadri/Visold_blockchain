# Visold L2 ZK Backend Model — 2026-10-24

## Status

ZK proving is optional and externally supplied by capable/server operators. Visold does not require every node or consumer device to install a SNARK prover, circuit compiler, proving key, or trusted-setup toolchain.

The core codebase provides a fail-closed prover/verifier adapter and a deterministic witness/public-input contract. It does **not** bundle or claim a universal production circuit.

## External backend contract

A configured backend receives these public inputs:

- previous L2 root
- new L2 root
- canonical compressed-batch hash

The prover also receives the deterministic `visold_l2_witness_v1` JSON witness containing the pre-state snapshot, canonical transaction list, compressed batch bytes, and the corresponding roots/hash. This allows an external Rust, Go, C++, Circom/snarkjs, gnark, arkworks, or other implementation to construct its own proof system without importing Visold Python internals.

The subprocess adapter passes `--pk <path>` only to the prover and `--vk <path>` only to the verifier; executable names are not used to guess roles.

## Security boundary

An operator-provided circuit/prover is responsible for proving the validity statement it claims to implement. Deployments that treat a ZK proof as a trustless validity guarantee must use a circuit that constrains the complete intended L2 transition semantics. The core repository intentionally does not mandate one circuit for all users.

If no ZK backend is configured, the ordinary L2 path remains available according to the existing configuration. Backend failure is not silently treated as successful proof verification.

## Compatibility

The optional ZK integration does not make SNARK tooling mandatory for ordinary nodes or Android/consumer-hardware users. The existing bootstrap scalability/backpressure fix remains included in this build.
