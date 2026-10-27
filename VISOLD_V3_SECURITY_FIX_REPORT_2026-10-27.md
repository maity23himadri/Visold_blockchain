# Visold V3 — Security Fix & Verification Report

**Date:** 2026-10-27  
**Input:** `V3.zip`  
**Fixed artifact:** `V3_fixed.zip`  
**Scope:** The two security findings reproduced during the isolated pentest: P2P compressed-message expansion and RPC `GET /headers` rate-limit bypass.

## Result

Both reported findings are mitigated in this build and their reproduction checks pass against the patched source. This is a targeted fix and regression run, not a claim that the full protocol has been formally verified or that every possible vulnerability has been ruled out.

## Fix 1 — Bound compressed P2P messages (32 MiB)

- Reduced `Config.MAX_MESSAGE_SIZE` from 1 GiB to **32 MiB**.
- Enforced output bounds while decompressing. The zlib path uses bounded incremental decompression; the zstd path now reads through `ZstdDecompressor.stream_reader()` in bounded chunks instead of a single unbounded-result call.
- Added `DecompressedSizeLimitError`, so an oversized expanded message is rejected explicitly rather than returned as raw compressed bytes and failing later during text decoding.
- The P2P receive loop applies the oversized-message ban score and disconnects that peer before message dispatch. The handshake/control `recv_line()` path also treats this size-limit error as terminal.
- Clamped `MAX_PARTIAL_FRAME_BYTES` so an environment override cannot raise it above the absolute message-size ceiling.
- Byte-budgeted `MSG_CHAIN` replies, reserving one byte for the newline delimiter, so sync pages remain below the receiver's frame ceiling. Pagination remains forward-progressing in the regression test.

### Live attack reproduction

The isolated socketpair test built a **67,108,888-byte (64 MiB) JSON payload** with a **390,515-byte compressed frame** (about **171.8×** expansion). Against the patched receive/decompression/parse path:

- The message handler was **not called**.
- The peer was disconnected.
- One oversized-message ban-score event was recorded.
- The reader thread exited.

The attack test is included as `visold_v3_p2p_compression_regression.py` and only uses a local socketpair.

## Fix 2 — Rate-limit RPC `GET /headers`

- Added `getheaders` to the existing expensive-RPC token bucket (10 tokens per request).
- Applied the rate check after authentication but before parsing query parameters or reading block storage.
- Added bounded query parsing and rejects for negative start heights, counts outside `1..100`, malformed parameters, and excessive query-field counts.
- Added deterministic unit tests for rate limiting, authentication, invalid ranges, and no block lookups on rejected requests.

### Live attack reproduction

A local-only flood sent **40 concurrent authenticated** `GET /headers?from=0&count=100` requests:

- **2** returned HTTP 200.
- **38** returned HTTP 429.
- Only the two accepted calls performed block lookups (**200** lookups total); rejected requests did not reach storage.

The executable regression is `visold_v3_rpc_headers_rate_regression.py` and binds only to `127.0.0.1`.

## Verification

All of these were run against the patched tree:

| Test group | Result |
|---|---:|
| Focused compression / chain-frame / RPC rate-limit regressions | **16 passed** |
| TLS-I/O (excluding the known baseline EOF case), P2P liveness, mesh admission, topology, compression and RPC regression tests | **70 passed, 1 deselected** |
| Sync import, pruning, reconnect, bootstrap, snapshot rollback/failover and peer-height regression tests | **46 passed** |
| Live P2P compressed-expansion regression | **PASS** |
| Live 40-request RPC `/headers` flood | **PASS** |
| Live RPC authentication, body-size limit, malformed JSON, slow-header and post-attack recovery checks | **6/6 PASS** |

The focused tests exercise exact-limit payload acceptance and over-limit rejection. The zstd streaming branch is covered with a bounded fake reader because the sandbox does **not** have the optional `zstandard` Python package installed (`_ZSTD_AVAILABLE=False`); the actual live compressed attack used the available zlib fallback. A deployment where zstd is enabled should run these same regression tests in that environment before release.

## Known baseline test failure (not caused by this patch)

`tests/test_tls_io_serialization_20261025.py::test_tls_recv_timeout_and_eof_semantics_are_preserved` expects a TLS peer close to produce `b""`, but this environment raises `ConnectionResetError: [Errno 104] Connection reset by peer`. I ran the same test against the **unmodified extracted `V3.zip`**, and it fails there in the same way. I have not changed this unrelated TLS behavior as part of these two fixes.

## Files changed

Production code:
- `visold/kernel/config.py`
- `visold/kernel/compression_utils.py`
- `visold/network/compression.py`
- `visold/network/p2p.py`
- `visold/network/peer_connection.py`
- `visold/api/rpc_server.py`

Regression coverage:
- `tests/test_compression_and_chain_frame_hardening_20261027.py` (new)
- `tests/test_rpc_server_load_regressions_20261025.py` (extended)
- `visold_v3_p2p_compression_regression.py` (manual local-only verification)
- `visold_v3_rpc_headers_rate_regression.py` (manual local-only verification)

## Deployment note

The original `V3.zip` was not overwritten. Use `V3_fixed.zip` as the patched source snapshot. This patch should be reviewed and tested on the actual target runtime before replacing a production node; the 32 MiB cap and `MSG_CHAIN` pagination change are deliberately tested together to avoid fixing the memory limit at the expense of sync progress.
