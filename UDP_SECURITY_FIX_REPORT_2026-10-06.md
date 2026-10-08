# Visold UDP Security Fix Report — 2026-10-06

## Scope

This patch addresses the two confirmed UDP resource-exhaustion vulnerabilities identified in the current Visold build:

1. **Pre-authentication UDP session allocation** — a new source address could allocate a `UDPSession` and its retransmission thread before the P2P admission/rate-limit checks ran.
2. **Unbounded UDP FEC symbol retention** — FEC symbols were stored without the fragment-offset and payload bounds already applied to ordinary data fragments.

No consensus, transaction, balance, cryptographic, VM, or storage behavior was intentionally changed.

## Fixes

### 1. Admission before session allocation

`UDPTransport` now performs a pre-session admission gate for previously unseen source addresses. The gate is executed before creating `UDPSession` and maintains a hard limit on simultaneously admitted but unauthenticated inbound endpoints.

`P2PNetwork` supplies the admission predicate, so the existing per-IP connection-rate limit and persistent IP soft-ban are now enforced at the correct trust boundary. The pre-authentication reservation is released on handshake success, handshake failure, worker-start failure, external session removal, and transport shutdown.

The transport also detects the rare race where an outbound path creates the session between admission and inbound allocation, avoiding a duplicate inbound handshake.

### 2. FEC bounds

FEC symbols are now rejected when:

- their fragment offset is outside the same bounded range used for normal reassembly;
- their payload is larger than the protocol's 1389-byte per-packet payload limit;
- the per-reassembler symbol bound has been reached.

The UDP wire decoder also rejects datagrams larger than the protocol's 1400-byte MTU, ensuring oversized payloads cannot reach reassembly/FEC code.

## Verification

### New regression tests

`tests/test_udp_security_fixes_20261006.py`

**6/6 passed**, covering:

- rejection before any UDP session allocation;
- hard cap on pre-authentication session allocation across many source ports;
- exact-MTU acceptance and oversized-datagram rejection;
- FEC offset/payload bounds;
- bounded FEC-group count;
- successful FEC recovery after hardening.

### Existing regression tests

The non-VM regression suites run after the patch passed **62/62** tests in a combined run.

The seven consensus-hardening cases were also exercised individually; the individual cases completed successfully, including the process-death rollback case. The aggregate consensus test process can become excessively long in this environment, so its aggregate run is not counted as a pass.

The VM rollback/selfdestruct suites were not used as evidence for this UDP patch because their aggregate processes also exhibit the same long-running behavior in the unmodified supplied archive.

### Static/structural verification

- `python -m compileall -q visold tests` — passed.
- `tools/check_architecture.py` — **118 modules / 443 import edges / 22 contexts — OK**.
- The supplied `tools/verify_static.py` and `tools/verify_runtime.py` could not run because the archive does not contain their required baseline file `visold_vsd_original.py`; this is a repository/tooling limitation, not a test failure caused by this patch.

## Files changed

- `visold/network/udp/wire.py`
- `visold/network/udp/reliability.py`
- `visold/network/udp/transport.py`
- `visold/network/p2p.py`
- `tests/test_udp_security_fixes_20261006.py`
- `UDP_SECURITY_FIX_REPORT_2026-10-06.md`

The patch does not alter the blockchain's consensus rules or economic parameters.
