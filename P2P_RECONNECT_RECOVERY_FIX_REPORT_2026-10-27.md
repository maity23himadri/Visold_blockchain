# Visold V4 — P2P Reconnect Recovery Fix

Date: 2026-10-27
Base: `V4_liveness_mining_fix_20261027_info_notice.zip`

## Reported symptom

With three local/mobile nodes initially in a full mesh (two peers per node), after a period of stability one node reported zero peers while the other two reported one each. Attempts to reconnect to the seed/other node failed; restarting the isolated node restored the full mesh.

Without the Android run's timestamped P2P logs, the exact initiating disconnect cannot be proven from this symptom alone. Source review found two recovery defects that can explain why reconnect could fail and why restarting (which clears transient in-memory state) could help.

## Changes

### 1. Bounded half-open recovery probe during endpoint cooldown

`visold/network/p2p.py`

- Ordinary outbound cooldown still applies after `OUTBOUND_FAIL_LIMIT` consecutive failures.
- If automatic discovery is trying to restore a node that is below its peer target, it may make one half-open probe to a cooled-down endpoint no more frequently than `RECONNECT_INTERVAL` (60 seconds by default).
- Failed probes retain the failure counter/cooldown state. A successful connection clears endpoint failure state through the existing success path.
- Manual dials and normal dials at/above the target retain the ordinary cooldown. This is not a global cooldown disable and does not change consensus or peer admission rules.

This prevents an in-memory 300-second cooldown from becoming a recovery dead-end that only a process restart clears, while keeping reconnection attempts bounded.

### 2. Do not treat stale UDP registry entries as a successful connection

`_udp_connect_to()` previously returned `True` merely because the endpoint key existed in `_udp_peers`. It now requires the mapped peer to be connected and its session to be alive. Stale entries are evicted with identity-safe cleanup and the expected old session is removed before a fresh handshake proceeds.

### 3. Identity-safe UDP teardown

`_udp_peer_message_loop()` previously removed `_udp_peers[addr]` unconditionally on exit. If a replacement session had already been installed at the same endpoint, an old reader loop could delete the new mapping. It now removes the entry only if it still points to that exact peer object.

The UDP heartbeat stale-session eviction path now runs standard peer-disconnect bookkeeping, keeping `self.peers`, router/capability state, and disconnect notification state aligned before removing the expected UDP session.

## Regression verification

- 101 selected P2P/topology/reconnect/security tests passed.
- `compileall` passed for `visold` and `tests`.
- Architecture check passed: 125 modules, 475 import edges, 22 contexts; no cycles detected.
- New regressions cover: half-open retry while under target, preserving the cooldown for manual dials, stale UDP mapping not returning false success, and old UDP cleanup not removing a replacement session.
- ZIP integrity was checked after packaging.

## Explicit limitations

- The full project test suite was not run in this verification batch.
- This environment cannot reproduce Android/Termux networking and power behavior exactly.
- The exact event that first broke the live 3-node mesh remains unconfirmed without the node logs covering the minute before/after disconnect. The patch addresses the identified reconnect/UDP cleanup defects; it does not claim to prove which socket/session event initiated the original drop.
