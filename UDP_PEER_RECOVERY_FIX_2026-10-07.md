# Visold UDP Peer-Recovery Fix — 2026-10-07

## Confirmed defects repaired

1. `UDPPeerConnection` was missing synchronization state required by the shared `P2PNetwork` layer:
   - `_auto_sync_active`
   - `_fork_sync_buffer`
   - `_fork_sync_buffer_bytes`
   - `_fork_sync_target_height`
   - `chain_height`
   - `capabilities`
   - `_block_chunk_queue`
   - `_snap_response_queue`

   These fields are now initialized to the same safe defaults used by `PeerConnection`.

2. UDP handshake failures could close a `UDPSession` without removing it from `UDPTransport._sessions`. A later retry could therefore reuse the closed session. Failed inbound and outbound handshakes now remove the exact session they used.

3. `UDPTransport.remove_session()` now supports identity-checked removal through `expected_session`, preventing cleanup from closing a newer replacement session for the same endpoint.

4. A rejected UDP registration could leave a stale entry in `_udp_peers`, causing the fast "already connected" check to suppress recovery. Failed registrations now remove only their exact failed peer entry.

5. UDP message-loop cleanup now removes only the exact session owned by that peer, preventing an older connection from tearing down a replacement session.

6. UDP heartbeat eviction now retains the exact stale peer object observed during the scan and evicts it only if that same object is still registered, preventing reconnect races from destroying a fresh session.

## Verification

- Python compilation: passed.
- Architecture check: passed (`118` modules, `443` import edges, `22` contexts; no cycles/layering violations).
- Existing fast-running regression suite: `93 passed`.
- New UDP peer-recovery regression tests: `4 passed`.
- Combined UDP regression tests: `10 passed`.

The complete project suite collects `110` tests. Two pre-existing heavy test files (`test_consensus_hardening_regressions.py` and `test_vvm_rollback_regressions.py`) did not complete within the available execution windows in this environment; their timeout was not treated as a pass or converted into a failure claim.
