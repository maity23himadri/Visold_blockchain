# Visold Final Build — 2026-10-24

This build combines the verified bootstrap scalability/backpressure fix with the optional external L2 ZK backend plumbing.

## Included
- Bootstrap GET_CHAIN rate-limit backpressure fix (no silent page loss on large authenticated header ranges).
- Optional external ZK prover/verifier subprocess adapter.
- Deterministic `visold_l2_witness_v1` witness supplied to configured external provers.
- Explicit `--pk` for prover and `--vk` for verifier.
- Documentation clarifying that SNARK circuits/provers are operator-supplied and are not mandatory for ordinary nodes.

## Not included
- No mandatory Circom/snarkjs/gnark/arkworks dependency.
- No bundled universal production ZK circuit.
- No user database, `.vd3`, `visold.db`, WAL/SHM, wallet runtime state, or private node state.

## Verification in this assembly
- Python compilation of modified ZK modules: PASS.
- `test_snark_backend_plumbing_20261024.py` + `test_bootstrap_rate_limit_backpressure.py`: 4/4 PASS.
- `test_l2_read_and_failed_apply_regressions_20261006.py`: 4/4 PASS.
- `test_confirmed_bug_fixes.py`: 9/9 PASS.
- Heavy authenticated-pruning integration suite exceeded the 120-second execution cap in this environment; no pass claim is made for that run. The underlying bootstrap-scalability base build had previously passed the real V4 two-node 0→1256 synchronization test with exact tip-hash convergence before these ZK-only module changes.
