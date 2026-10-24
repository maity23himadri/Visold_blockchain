# Visold P2P reliability fixes — final validation report

Date: 2026-10-22

## Executive summary

Three confirmed code-level defects or unsafe paths were addressed, with regression coverage:

1. **Unsafe full-frame retry after `sendall()` failure.** A failed `sendall()` does not report how much data reached the peer. Re-enqueueing the whole frame on the same TCP/TLS stream could corrupt framing. The async writer no longer retries a frame after a socket-write error; the session is marked unusable, further sends are rejected, queued messages for that old session are discarded, and socket shutdown is attempted to wake the reader. Synchronous send follows the same rule. Failure state is published before releasing the stream-write lock to prevent another sender entering the stream during cleanup. Pre-send serialization failures are treated separately.
2. **`BlockingIOError` from TLS `recv()` incorrectly ended an active peer loop.** The earlier trace recorded `BlockingIOError: [Errno 11] Resource temporarily unavailable` while the fd was open, TCP reported ESTABLISHED, and a valid message had just been received. The old catch-all path treated it as fatal. `_recv_with_blockingio_retry()` now treats EAGAIN as a readiness condition within a monotonic deadline; a true wait expiry uses the existing `socket.timeout`/PING liveness path rather than an immediate disconnect.
3. **A reader error after another thread had already closed the socket was misreported as an unexpected live-session exception.** Reader diagnostics now check the socket/connection state and label `EBADF` after close as `socket_already_closed_before_reader_exception:<type>`. This is a diagnostic classification fix; it does not claim that the prior close was caused by the reader error.

These are evidence-backed corrections, not a claim that every historical EOF shared one cause. Expected duplicate-session replacement and orderly shutdown may still generate reader exits; those are not equivalent to unexpected loss of a retained active link.

## Relevant code changes

### `visold/network/peer_connection.py`

- Removed retries of an ambiguously partially transmitted message on the same stream.
- A socket write error marks the session unusable under the stream write lock before releasing it, avoiding a second sender racing into the stream.
- Stops writer/queue admission, drops remaining frames for the failed session, resets pending-byte accounting, logs the actual exception type, and attempts `shutdown(SHUT_RDWR)` to wake the reader.
- Does not poison a healthy socket when local JSON serialization/compression fails before network I/O.
- Keeps writer startup, queue admission, and stopping coordinated with a lifecycle lock.

### `visold/network/p2p.py`

- Added a bounded TLS receive helper for `BlockingIOError`, waiting for readability under a monotonic deadline and preserving the existing heartbeat path for a true timeout.
- Avoids sending a late PING after another thread marked that session disconnected.
- Preserves local transport failure as the cause of follow-up reader EOF/exception logs.
- Separates a reader exception caused by an already closed descriptor from an exception on an apparently active socket.

### Previously validated fixes preserved

- PEX dial budget is only consumed when a new dial worker actually starts.
- PING/PONG is not suppressed by global duplicate-message suppression.
- Handshake temporary writer cleanup and explicit rejection diagnostics remain in place.
- Canonical duplicate-session arbitration remains in place; it was not removed speculatively.
- Existing retry/cooldown, endpoint discovery, reconnect cadence, UDP protections and peer-admission policy remain unchanged.

`visold/kernel/config.py` is byte-for-byte identical to the uploaded baseline. No `MAX_PEERS`, `MIN_PEERS`, subnet limit, PEX/reconnect interval, or per-IP behavior was changed.

## Same-configuration 7→8-node live reproduction

Run directory: `live_7to8_after_blockingio_fix/` (included as separate evidence archive).

- The harness first waited until seven nodes each had six peers, then launched node 8. No manual peer dial was used.
- After the eight-node full mesh was achieved, it observed the network for 300 seconds.
- There were 296 topology samples. Every sample had all 8 nodes at 7 peers, a symmetric 28-link mesh, and unchanged session IDs.
- Summary flags: `criteria_passed=true`, `all_sampled_meshes_symmetric=true`, `session_ids_stayed_constant=true`, `peer_counts_stayed_full=true`, `policy_values_consistent=true`.
- The captured event logs contained no `BlockingIOError`, no `[PeerSendFailure]`, no `[PeerTransportAbort]`, and no `Peer disconnected` event during this run's reported observation.
- The effective settings remained `PEX_INTERVAL=60s`, `RECONNECT_INTERVAL=60s`, `MAX_PEERS=30`, `MIN_PEERS=25`, `PEER_DECAY_SECS=3600`, and per-IP inbound rate limit 12 per 60 seconds. No settings were changed to obtain the result.
- Startup/canonical-session cleanup and orderly shutdown can still emit `PeerLoopExit`/`PeerSocketClose` diagnostics; these are reported separately from a loss of the retained 8-node full mesh.

**Result: PASS for this particular 300-second localhost 7→8 reproduction.** This is meaningful evidence that the previously observed `BlockingIOError` disconnect path did not recur in this test after the receive fix, but a single localhost run is not proof against every historical EOF or mobile/NAT network condition.

## Automated validation

- Focused regression tests, including TCP writer safety, TLS `BlockingIOError`, EOF diagnostics, stale-session race, PEX dial budget, cooldown/reconnect, mesh admission, clean shutdown, UDP recovery/security and logic-hash identity: **91 passed**.
- `python -m compileall`: PASS.
- `tools/check_architecture.py`: PASS — 123 modules, 469 import edges, 22 contexts; no cycles/layering violations.
- Current `visold/_build_identity.json` matches the deterministic source blob: SHA-256 `cd097c2fbd76d9c3739ba273d922af13ecb14ea4ee2a1c5b9ca86c4390e27a61`, 149 Python files.
- Baseline/current `visold/kernel/config.py` SHA-256 matches: `9a3f87a67d34d69460970770bb0e093bae4a2e26d4d4f9d72c946431ba148708`.
- Full project test suite was attempted with a 240-second limit; it timed out (exit 124) at around 81% progress, without a final pytest summary. It is therefore **incomplete**, not a pass. The 91 focused tests are the completed automated validation.

## Remaining limits

The 300-second run passed and did not reproduce the old active-link interruption. The earlier trace evidence supports the `BlockingIOError` catch-all path as a real initiating failure mode, and the `sendall()` retry was a confirmed protocol-integrity risk; both are now addressed. However, the available logs do not establish that these were the initiating cause of every historical EOF. Keep per-session writer/reader/close-origin diagnostics on future Android/mobile/NAT runs and treat unmatched historical EOFs as unresolved until paired endpoint evidence identifies their initiating event.
