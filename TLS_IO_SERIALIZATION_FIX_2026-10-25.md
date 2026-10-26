# TLS peer I/O serialization fix — 2026-10-25

## Problem
Healthy TCP/TLS peer sessions dropped at random with no network cause
(`remote_eof`, `SSLEOFError`, `BAD_RECORD_MAC`). The earlier EOF reports
(2026-10-22) left the initiating cause unresolved: local error first, TCP state
still ESTABLISHED, no remote FIN/RST or TLS alert before it.

## Root cause (reproduced, not assumed)
Each peer connection is one OpenSSL TLS object. The node used it from two threads
at the same time with no lock shared between them:

| Thread | Code | Lock held |
|---|---|---|
| reader | `p2p._peer_message_loop` -> `_recv_with_blockingio_retry` -> `sock.recv` | none |
| async writer | `PeerConnection._raw_send` -> `sock.sendall` | `PeerConnection._lock` |
| sync writer | `PeerConnection.send` -> `sock.sendall` | `PeerConnection._lock` |

`PeerConnection._lock` only serializes writers against each other; the reader never
takes it. OpenSSL does not support overlapping SSL_read/SSL_write on one connection
(they share per-connection state, e.g. the socket-BIO retry flags). The overlap
corrupts that state and surfaces as a spurious EOF or a bad-record-MAC error on a
live socket. The `BlockingIOError` retry helper added 2026-10-22 is consistent with
this race but does not address it.

## Fix
`visold/network/peer_connection.py` (new helpers) and `visold/network/p2p.py` (call sites):

* For a TLS socket every SSL read/write is ONE NON-BLOCKING attempt made while
  holding a single per-socket lock (`tls_recv`, `tls_sendall`). Waiting for
  readability/writability happens outside the lock (poll(), select() fallback;
  poll() has no 1024-descriptor limit), so an idle reader never blocks a writer.
* The lock is stored on the socket object, so the temporary handshake
  `PeerConnection` and the final registered one share it. A second per-socket
  write lock keeps one frame write at a time (an interrupted SSL_write must be
  retried with the same buffer).
* Call sites switched: `_raw_send`, `send`, `recv_line` (handshake), the reader
  helper, and the `ssl_pending` diagnostic. The reader no longer re-applies
  `settimeout(30)` to TLS sockets.
* Timeout/EOF/error contract is unchanged: `socket.timeout` after 30 s idle (PING
  path), `b""` on EOF, `OSError(EBADF)` on a closed socket, send failure = session
  aborted exactly as before. Plain (non-TLS) sockets use the original code path.
* No change to consensus, wire format, peer limits, admission, PEX or reconnect policy.

## Evidence
All numbers from the same sandbox (1 core, Python 3.12, OpenSSL 3.0.13, loopback).
Tool: `tools/tls_io_stress_repro.py` (real `PeerConnection`, real TLS contexts, real
reader helper, production socket mode).

| Test | Original V4 | Fixed |
|---|---|---|
| Stress, 4 pairs, 60 s, heavy | 4/8 sessions lost (EOF) | 0/8 lost (183k messages) |
| Stress, 6 pairs, 150 s, light | 2/12 lost (BAD_RECORD_MAC) | 0/12 lost |
| Live: 4 real nodes, 100 s observed | mesh stable; startup duplicate arbitration only | mesh stable 3/3 peers; startup duplicate arbitration only; no SSL errors, send failures or transport aborts |
| New test: SSL operations overlapping on one connection | max 2 concurrent -> FAIL | max 1 -> PASS |

The failure is probabilistic. Original code also survived some short or light runs,
so a clean short run proves little; the overlap test above is the deterministic check.

New tests: `tests/test_tls_io_serialization_20261025.py` (9 tests, all pass on the
fix; the overlap test fails on the original). Runs under pytest and under
`tools/run_tests_shim.py`.

Regression sweep (79 test files, repo shim, 40 s per-file cap, 1 core): every file
that passes on the original also passes on the fix. Items that do NOT pass are
identical on the original V4 and are not caused by this change:
* `test_varr_receipt_relay::test_receipt_survives_body_pruning_and_preserves_sender` fails on the original.
* 7 modules fail to import here (`pytest.mark` etc. missing in this sandbox).
* `test_tui_frame_buffer`, `test_tui_input_synchronization`, `test_vsa_block_application`,
  `test_vsa_reorg_consistency` exceed the time cap on the original too.
* `test_tofu_endpoint_and_logic_hash_fix::test_manifest_matches_full_source_tree`
  failed on the original (stale `_build_identity.json`); it passes now.
`compileall` and `tools/check_architecture.py` pass (123 modules, 469 edges).

## Build identity / deployment
`visold/_build_identity.json` was already stale in the supplied V4 and is regenerated:
`package_source_sha256` = `7c38d4194b5ba447...` (149 source files), node logic hash
`7c38d4194b5ba447986b4ce61add3898`. This changes the advertised build fingerprint,
so nodes still running the previous build see this one as TRUST_LOW (see README /
MIGRATION_LOG section 5). Update all nodes together.

## Not verified / limits
* Not run on Android/Termux (Python 3.14). The hazard is in OpenSSL's design and
  should apply there; the fix uses only standard `ssl`/`select` calls.
* Loopback only. Real NAT / mobile-network drops, and the UDP path, were not audited
  and can still cause disconnects unrelated to this bug.
* The full suite was not completed in one run (several tests exceed the time cap here).
* Reader threads of sockets closed by duplicate-session arbitration now exit within
  about a second instead of lingering until the 30 s idle timeout. Cleanup is
  unchanged and safe: `_on_peer_disconnect` only removes the exact session object.
