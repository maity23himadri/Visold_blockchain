# Visold V5 — Hashrate Governor Fix Report

Date: 2026-10-26

> Formula semantics: `H_actual` in `C_i = H_actual_i × share_i` means the **local miner's own measured actual H/s**. Peer rates are used only to calculate the observed share denominator. Do not use `V5_hashrate_governor_aggregate_actual_fix.zip`; that later variant incorrectly substituted the sum of peer rates into this numerator.

## Scope

This build implements the requested per-miner cap policy, fixes the startup hashrate display and feedback loop, improves active-compute rate measurement, and makes miner-rate reports origin-authenticated and mesh-relayed. The governor remains advisory and does not change consensus difficulty, proof-of-work validation, block headers, or rewards.

## Implemented cap policy

Let `H_required = 2^(4D) / TARGET_BLOCK_TIME`, and let `H_i` be this miner's measured rate from active-compute telemetry. For each observed miner `j`, `w_j = H_j ** HASHRATE_SHARE_EXPONENT` (default exponent `0.5`). The local cap is:

- If local rate is not measured yet: `C_i = infinity` during startup calibration. This prevents a fake zero measurement from pausing mining.
- If `H_i < H_required`: `C_i = H_i`.
- Otherwise, `share_i = w_i / sum(w_j)` and `calculated_i = H_i * share_i * HASHRATE_HEADROOM_FACTOR`; `C_i = min(H_i, max(H_required, calculated_i))`.

This follows the user's requested change to use local `H_actual` instead of `H_required` as the formula multiplier and to floor a calculated cap at `H_required`, while never setting the cap above this machine's measured capacity.

### Important mathematical trade-off

The requested per-miner `H_required` floor does **not** preserve an aggregate cap of `H_required` when there are multiple miners: each miner may independently be floored to the global network target. A solo miner with `H_i > H_required` also has `share_i = 1`, so this rule returns `C_i = H_i` (no governor throttle). These are direct consequences of the requested formula, not hidden implementation behavior. They can make blocks arrive faster than the target; consensus difficulty itself remains unchanged and may later adapt as designed.

For the two-miner example in the prompt (`H_i=7588.3`, peer=`4055.2`, `H_required=3192.5`, exponent `0.5`, headroom `1.0`):

- Local share is about `0.577691`.
- Local calculated cap is about `4383.70 H/s`, so local cap is `4383.70 H/s`.
- The other miner's calculated cap with the same two observations is about `1712.55 H/s`, then the requested per-miner floor raises it to `3192.5 H/s`.

The two resulting caps sum to about `7576.2 H/s`, which is above the aggregate target. If the protocol requirement is that total network cap must never exceed `H_required`, this floor rule must be revisited before production.

## Changes

- `visold/consensus/hashrate_governor.py`: requested formula and floor; local-below-required branch; sequenced peer-report replay checks; peer report expiry based on origin timestamp to prevent relay-refresh; startup measurement state and diagnostics.
- `visold/consensus/hashrate_reports.py`: signed report creation and verification; binds origin node ID, public key, rate, timestamp, sequence. Signatures identify the reporter but cannot prove the claimed hardware rate is honest.
- `visold/network/p2p.py`: validate report signature/freshness, origin/sequence deduplication, relay newly accepted signed reports through the mesh; accept legacy unsigned reports only from the directly authenticated claimed peer and do not relay them.
- `visold/mining/workers.py`: measure attempted hashes per active-compute time, excluding intentional governor sleeps; flush metrics every 256 hashes even while dynamic throttling is enabled, instead of waiting for a 1024-hash throttle batch.
- `visold/mining/parallel_miner.py`: expose smoothed raw active-compute H/s before a block is solved and refresh the dynamic local cap while a candidate is being mined.
- `visold/mining/engine.py`: reset telemetry at a new session, poll live raw rate, send signed sequenced peer reports, refresh cap during a candidate, and show `measuring…` rather than `0 H/s` before the first sample.
- `visold/cli/interactive.py`: clarify actual rate, local cap, aggregate required rate, and that peer reports are authenticated self-reported observations from the mesh, not a guaranteed complete census.
- `visold/kernel/config.py`, `visold/kernel/messages.py`: update behavior/documentation without changing existing hard peer limits, target block time, exponent, or headroom value.
- `tests/test_hashrate_governor_adaptive_20261026.py`: add regression coverage for formula/floor, local rate below target, startup calibration, active-compute measurements before a block is solved, live cap refresh, signed report integrity, replay/freshness, and origin-timestamp decay.

## Measurement and report limits

- “Actual H/s” is the miner's observed attempted hashes per active-compute second, excluding deliberate governor sleeps. It is a useful estimate of unthrottled throughput; it is not a certified hardware benchmark.
- Peer rate reports are wallet-signed and timestamp/sequence checked. This proves which wallet signed a rate claim, not that the rate claim is physically true. Reports can still be incomplete if mesh gossip paths are unavailable, and malicious identities can lie about their own rate.
- GPU kernels currently do not implement this dynamic cap provider. In this build the known-unverified GPU paths are disabled/fall back to CPU as documented by the source; verify the backend in the live panel.
- During startup, the governor intentionally leaves mining unthrottled until a real local rate sample is collected. The UI shows a measuring/calibrating state during that interval.

## Verification performed

- Python compile check for the edited governor, reports, workers, parallel miner, mining engine, P2P, CLI, config/message modules and the new test module: **passed**.
- Selected hashrate-governor, mining lifecycle, adaptive-topology, TCP diagnostic, P2P liveness/handshake and mesh-admission regressions: **78 passed**.
- Separate `tests/test_tls_io_serialization_20261025.py`: **8 passed, 1 failed**. The failing unchanged TLS EOF test expects `b''` after closing the peer socket; under this Python 3.13 runtime it raises `ConnectionResetError` at `visold/network/peer_connection.py:151`. The TLS file was not changed in this hashrate patch. This suite is not reported as fully passing.
- Full repository suite and live multi-process/Android mesh tests were not run. Test evidence above is targeted unit/regression evidence, not a claim that real-world network behavior has been fully validated.

## Deployment caution

Test on a separate mesh first. Compare each node's local actual rate, cap, required aggregate rate, observed signed miner-report count, and block interval. In particular, review whether the requested per-miner floor causing the sum of local caps to exceed the aggregate target is acceptable for the intended block-time behavior.
