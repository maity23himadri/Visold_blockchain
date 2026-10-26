# Automatic Dial Soft-Target Fix — 2026-10-26

## Root cause

The adaptive peer target (`TOPOLOGY_TARGET_PEERS`, default 3) was not consistently enforced across every automatic dialing source:

1. `DNSSeeder._query_one()` called `P2PNetwork._try_add_peer()` directly, bypassing the target-aware PEX dial budget.
2. DHT capability responses also called `_try_add_peer()` directly.
3. PEX handlers can process messages concurrently. A per-message target budget alone is not a global atomic reservation, so simultaneous discovery callbacks could observe the same available slot.
4. The PEX path intentionally supports a single make-before-break topology replacement probe at/above target. Without a retry cooldown, a quickly failing candidate could be retried across several PEX pages/messages.

## Changes

- Added a centralized automatic-dial guard in `P2PNetwork._try_add_peer()`.
- Added `_auto_dial_lock` to serialize the target check with adding the endpoint to the pending set.
- Marked automatic PEX, DNS-seeder, DHT capability, bootstrap-seed, bootstrap-cache, and reconnect-cache calls as `auto_discovery=True`.
- Ordinary automatic dials are suppressed once active + pending reaches the soft target.
- Only an explicitly selected PEX topology replacement probe may go above target; it is refused while any connection is pending and is rate-limited by `TOPOLOGY_PROBE_INTERVAL_SECONDS` (default 60 seconds).
- Added optional `topology_probe_interval_seconds` config parsing (valid range 30–900 seconds).
- Manual/user-initiated `_try_add_peer()` calls keep existing behavior. `MAX_PEERS` remains the hard ordinary-node capacity cap.
- Dedicated seed nodes whose active target is unbounded retain their existing discovery behavior.
- Added regression tests for target enforcement, in-flight slot reservation, single extra topology probe, and manual-dial behavior.

## Expected behavior

With 3 connected peers and no replacement probe eligible, DNS, DHT, ordinary PEX, bootstrap, and reconnect discovery should not initiate additional automatic dials. If topology reports justify a replacement, the PEX policy may start one temporary probe so the graph can be rebalanced make-before-break; a failed probe cannot be retried more frequently than the configured interval.

The policy still treats 3 as a soft steady-state target, not a hard admission limit. Incoming peers can still be accepted up to existing admission limits. Manual/user-requested connection actions also remain available.

## Verification

- `compileall` over `visold/` and `tests/`: passed.
- Selected P2P, liveness/handshake, peer retry, PEX dial-budget, adaptive topology, new soft-target guard, and hashrate tests: **76 passed**.
- These are local regression tests. A real multi-node Android/Termux integration test is still required to confirm the live mesh stops making unwanted automatic connection attempts.
