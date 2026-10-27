# Visold V8 — IP-change / DNS-seed recovery fix

Date: 2026-10-27
Base archive: user-supplied `V8.zip`
Base SHA-256: `796c3b355218cabb1924f469f5decea44b9227d56b58d6c02c967fcfe525faae`

## What source inspection confirmed

The original DNS seeder queried hostnames immediately at startup and then only at `Config.DNS_SEED_INTERVAL` (600 seconds by default). The P2P reconnect loop retried `Config.SEED_PEERS` and cached peers, but `SEED_PEERS` is empty by default and the loop did not force a DNS re-resolution. Therefore, if a seed's first connection attempt failed during its IP migration/restart window, subsequent reconnect passes could keep trying stale cached addresses while the refreshed DNS endpoint was not reconsidered for up to ten minutes.

The old visible DNS log reported only A/AAAA counts, not the actual resolved endpoint, so the supplied logs alone cannot prove whether the Android resolver returned the new address at that exact moment or whether its first connection attempt reached a ready listener. The build did have a concrete recovery gap regardless: DNS was not coupled to the reconnect retry cycle.

A second scheduling weakness existed for dual-stack answers. IPv6 candidates were always started first, and an automatically scheduled dial consumes a pending peer-target slot. If the preferred family was unreachable, the alternative family could be repeatedly deferred by the soft-target guard without being tried on that recovery pass.

## Changes

### `visold/network/dns_seeder.py`

- Added a serialized, non-blocking `refresh_now()` path used during recovery, with a minimum 15-second throttle. The normal 600-second background interval remains unchanged for steady-state discovery.
- Logs the actual resolved IPv4/IPv6 endpoints and whether an outbound dial was scheduled; `scheduled=True` means a worker started, not that the peer authenticated. TCP socket-open failures now emit the OS exception class and message at INFO level instead of being silently reduced to `False`.
- Treats A/AAAA addresses for a hostname as alternative routes: one endpoint is scheduled per hostname per pass, and the preferred candidate rotates on the next refresh. If the first candidate is rejected by a scheduling guard, the remaining candidate(s) are tried in that pass.

### `visold/network/p2p.py`

- The reconnect loop now triggers a DNS refresh whenever it is below the active peer target, before falling back to static seeds and cached peers.
- DNS lookup errors remain non-fatal to reconnection; static seed and cached-peer fallback behavior remains in place.

### Build identity

Updated `visold/_build_identity.json` to the modified source tree so source and bytecode-only deployments can advertise the same logic fingerprint.

## Verification

- `compileall` on changed files: passed.
- Targeted networking regression batch: **139 passed** across DNS recovery, P2P target/cooldown logic, PEX dial budgeting, mesh admission, liveness/handshake, peer-height poisoning, TCP peer-decay race, UDP recovery/receiver/security, and peer security tests.
- Architecture checker: **OK** — 125 modules, 475 import edges, 22 contexts; no cycles, layering respected.
- The complete project test suite was not run.
- This is a source-level recovery fix. A real Android/Termux IP-migration test is still required. The new INFO logs intentionally report the runtime-resolved DNS addresses so a follow-up run can distinguish stale resolver results from a connection/handshake failure.

## Operational interpretation

After installing this build, wait for the first `DNSSeeder: ... resolved to ...` line after the IP switch. Confirm it contains the new endpoint. `scheduled=True` only confirms the dial worker started; a later `CONNECTED` event is required to confirm recovery. If the resolved address is new but the dial still fails, the next diagnostic target is the actual TCP/UDP connection or handshake error, not DNS freshness.
