# Visold TCP EOF origin-diagnostics build — 2026-10-22

## Scope

This is a diagnostic-only build based on `Visold_5_p2p_stability_fixed_20261022.zip`. It does **not** change `MAX_PEERS`, `MIN_PEERS`, subnet admission policy, `PEX_INTERVAL`, outbound concurrency, retry/cooldown values, duplicate-session arbitration, or the protocol's disconnect decisions.

## What it adds

1. `_peer_message_loop()` records a reason-coded exit (`remote_eof`, frame/bandwidth limit, ping-send failure, loop shutdown, or unexpected exception). Unexpected exceptions now include their traceback, peer endpoint/identity prefix, direction, and last parsed message type.
2. `PeerConnection.send()` reports the exception class and short error text when `sendall()`/serialization fails, without logging the message payload.
3. `PeerConnection.close()` logs the immediate local caller, thread name, peer identity prefix, endpoint, connection direction, prior `connected` state, and FD before closing. This helps pair a local close on node A with EOF on node B.
4. Added regression tests asserting that diagnostic branches fire while retaining previous close/return semantics.

## Why instrumentation first

The latest evidence proves eight `remote_eof` loop exits across four bilateral physical-link interruptions before shutdown. It does not prove the initiating local close path on the opposite node for those four links. Changing peer thresholds or connection arbitration before attributing those close origins could mask the evidence or create new failure modes. This build therefore adds observability without changing network policy or exit behavior.

## Verification

- Python `compileall`: PASS.
- Five focused P2P/retry/UDP/regression modules: **33 passed**.
- A fresh archive extraction was verified separately before release.
- No live multi-node test was run here. The next step is to run the existing 7→8, production-PEX=60s, all-nodes-min_peers=7 test and correlate `[PeerLoopExit]`, `[PeerSendFailure]`, and `[PeerSocketClose]` across both ends of each interrupted link.

## Privacy

Logs include peer ID prefixes and IP:port endpoints but no message payloads, wallet secrets, private keys, or transaction contents. Keep raw logs private or redact endpoint/identity data before sharing.
