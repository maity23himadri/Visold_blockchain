# V4 UDP Receiver / Peer-Disconnect Root-Cause Fix

Date: 2026-10-27  
Base: `V4_peer_reconnect_recovery_fix_20261027.zip`

## Summary

The highest-confidence source-level cause found for the reported topology collapse was a silent UDP receive-loop exit. In `visold/network/udp/transport.py`, the previous `_recv_loop()` exited on any `OSError` from `recvfrom()` while the transport could still have `_running == True`; no supervisor restarted that sole receive/demultiplex thread. The process could continue mining and appear running while incoming UDP traffic and heartbeats were no longer dispatched. Restarting recreated the socket/receive thread, matching the user's reported recovery pattern.

This defect was reproduced with an isolated failing socket and then verified against a real local UDP socket: forcibly closing the socket while transport remained running led the updated transport to recreate it on the same bound port, and it successfully received a subsequent valid heartbeat datagram. The Android report did not include the actual socket exception, so this establishes a matching code defect and recovery path—not proof that this exact exception was the initiating event on the phone.

## Changes applied

### 1. UDP receive-loop self-healing (`visold/network/udp/transport.py`)

- Fatal receive errors (`EBADF`, `ENOTSOCK`, `EINVAL`) trigger socket replacement instead of terminating the receiver.
- Repeated consecutive non-fatal receive errors trigger recovery after three failures. A single transient error is logged and retried without immediately churning the socket.
- Socket rebuild attempts use bounded exponential backoff (250 ms to 5 s) if binding fails.
- Recovery preserves the bound endpoint, including when initial construction used `port=0`, and preserves session objects so normal heartbeats can resume.
- A socket lock serializes sends, socket replacement, and shutdown; session send code now uses the transport's protected `sendto()` method.
- Packet parser/admission/session-dispatch exceptions are logged and isolated to that datagram rather than silently killing the receiver thread.
- IPv6 socket setup failures now close the partially-created IPv6 socket before attempting IPv4 fallback.

### 2. Atomic UDP session expiry (`visold/network/udp/session.py`, `visold/network/p2p.py`)

- `UDPSession.expire_if_silent()` atomically marks an overdue session expired under the same lock used by inbound packet timestamp updates.
- A late packet cannot revive a session after it has been atomically marked expired for teardown.
- The transport GC loop, stale-session reuse path, UDP message loop, and P2P UDP heartbeat cleanup use the atomic expiration method where available. Lightweight test doubles retain compatibility through `is_alive()` fallback.
- GC removes only the exact session object seen in its snapshot, not a replacement that has taken over the same endpoint.

### 3. Preserve a replacement handshake's admission slot (`visold/network/udp/transport.py`)

Identity-scoped cleanup no longer clears `_pending_inbound` if the registry entry is absent or belongs to a different session. An old, delayed cleanup therefore cannot release the address reservation belonging to a newer in-flight inbound handshake.

### 4. Regression coverage (`tests/test_udp_receiver_self_heal_20261027.py`)

Added tests cover fatal receive error recovery, repeated transient receive errors, packet-handler exception isolation, stale-GC snapshot replacement safety, late packets after atomic expiry, and preservation of a newer inbound admission reservation.

## Verification

- Architecture checker: **OK** — 125 modules, 475 import edges, 22 contexts; no cycles and layering respected.
- Compile check: **passed** for project sources and tests.
- UDP receiver/session/reconnect/security tests: **18 passed** after the final added transient-error test.
- P2P/topology/reconnect/UDP/security plus mining-governor/liveness/incoming-transfer suites: **140 passed** in the final combined selection.
- Real-socket recovery smoke test: **passed** — a deliberately closed receiver socket was recreated, the same UDP port was preserved, and a subsequent valid heartbeat datagram was received and dispatched.
- ZIP integrity: verified after packaging.

The entire project test suite was not run; only the targeted combined regression selection listed above was run. The Android/Termux long-duration scenario must still be validated on-device. The source-level defect is confirmed, but the exact initiating exception from the user's original phone run remains unobserved without that run's timestamped logs.
