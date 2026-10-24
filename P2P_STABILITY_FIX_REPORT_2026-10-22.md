# Visold P2P stability fixes — 2026-10-22

## Evidence reviewed

Reviewed `5min-7to8-pex-test-evidence.zip`, including the production-PEX (60-second) run. It did **not** maintain an 8-node full mesh for the required 300 seconds: its maximum uninterrupted window was 40.64 seconds and final peer counts were `7, 6, 7, 7, 7, 7, 6, 7`. The trace contained 163 TCP-EOF message-loop exits, one PING-send failure, 22 `_register_peer` duplicate-session closes, and one generic handshake `REJECT` before shutdown. These observations do not prove that every EOF has the same initiating cause.

The run also had a **test configuration mismatch**: nodes 0–6 were launched with `min_peers=6`, node 7 with `min_peers=7`, while the monitor required all eight nodes to keep seven peers. An individual node configured to target six peers may stop recovery work once it has six; this test therefore did not apply a consistent seven-peer target. The product default was not changed. The next integration run should set `min_peers=7` on all eight test nodes.

The trace also showed 33 outbound TCP dials aborting after local admission reservation failed before `CHALLENGE_RESP`, with 33 corresponding inbound handshakes waiting for that response until timeout. The rejecting dialer closed without sending a protocol-level reason, so the other side waited up to eight seconds unnecessarily. The same silent-rejection pattern existed on UDP paths in source, though this particular count is TCP evidence.

## Fixes in this build

1. **Heartbeat messages bypass global content-hash gossip dedup.** `MSG_PING` and `MSG_PONG` are connection-local liveness traffic with intentionally repeated payloads. Treating them as globally deduplicated gossip could suppress valid later heartbeats or PONG callbacks. Per-peer rate limiting remains in force.

2. **Temporary handshake writer-thread leak fixed for both TCP and UDP.** Both transport paths create a temporary `PeerConnection`/`UDPPeerConnection` for synchronous handshake messages, then transfer the same socket/session to a final registered peer. The temporary constructor starts an idle writer thread. The handoff now calls `close_writer()` before creating the final wrapper; this stops only the temporary writer and does not close the transferred TCP socket or UDP session.

3. **Admission rejection is now explicit and reason-coded across TCP and UDP.** `_reserve_peer_admission()` accepts a per-call reason result (not shared mutable last-error state), with codes such as `MAX_PEERS_REACHED`, `SUBNET_LIMIT_REACHED`, `CANONICAL_SESSION_ALREADY_ACTIVE`, duplicate/in-flight reasons, invalid address, and self/empty identity. If a dialer declines its own admission before sending `CHALLENGE_RESP`, it sends `MSG_REJECT` and logs `REJECTED:LocalAdmission`; the receiving handshake exits without waiting for an eight-second response timeout. If the other side rejects after the challenge response, the dialer logs the remote reason and records `REJECTED:Remote` rather than treating it as an unexplained failure. Both transports recognize `MSG_REJECT` at the relevant handshake stages.

4. **The previous PEX dial-budget starvation fix is preserved.** The dial budget is spent only when `_try_add_peer()` actually starts a new dial worker; a connected/pending/ineligible candidate does not starve later eligible candidates. The seed PEX rate reservation is released when a candidate is skipped before a new attempt.

5. **An existing UDP test fixture was repaired.** `test_vsa_remaining_20261015.py` intended to verify that the UDP initiator opens the handshake before waiting for a challenge but did not supply `storage` and `blockchain` dependencies. The test failed on the unmodified baseline before it sent HELLO. The fixture now supplies the missing stubs; this is a test setup repair, not a production behavior change.

## Deliberately preserved behavior

- Canonical duplicate-session arbitration remains in place. Closing one of two simultaneous inbound/outbound sessions can be correct; the trace did not prove that these closes caused every TCP EOF.
- Existing `MAX_PEERS` and subnet admission policy are unchanged.
- No per-IP outbound concurrency cap was reintroduced.
- The prior 60-second reconnect configuration and existing cooldown behavior are unchanged.

## Verification performed

- `python -m compileall -q visold ...`: passed.
- 20 focused P2P, UDP, admission, PEX, reconnect, pruning and directory-related test modules: **137 passed**.
- New handoff/liveness regression module: **11 passed**. It covers repeated identical PING/PONG delivery, preservation of message-rate limiting, TCP/UDP temporary-writer shutdown without closing the transferred transport, both handoff call sites, per-call admission reason codes, and explicit rejection handling.
- Attempted the entire 67-file pytest suite with a 180-second limit. It timed out at about 22% progress without producing a test-failure summary; therefore the complete suite is **incomplete**, not passed.
- The 5-minute 8-node live test was **not rerun against this patch**. The uploaded archive contains evidence/logs rather than a runnable launch environment and node state.

## Remaining unproven item and next integration run

The 163 pre-shutdown TCP EOF events are not all matched to an initiating close caller. The fixes above address confirmed issues that can harm liveness or waste handshake time, but the current evidence does **not** prove that every EOF or disconnect is eliminated. Keep any remaining unmatched EOF as unresolved rather than automatically assigning it to duplicate-session arbitration.

For the next live run use the corrected build, production `PEX_INTERVAL=60s`, the same intended peer/subnet policy, and `min_peers=7` for **all eight nodes**. Require a continuous 300-second 8/8 full mesh. Capture the initiating `close()` caller, peer identity, local/remote direction, and session generation for each EOF/close so remaining disconnects can be attributed before making further behavior changes.
