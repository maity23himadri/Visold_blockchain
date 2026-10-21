# Visold Peer Retry / Cooldown Fix Report — 2026-10-21

## Reported behavior addressed

- A failed listener port on a shared mobile IPv4/IPv6 address caused other ports on the same IP to enter cooldown.
- Discovery could dial an already-connected peer again when the peer was advertised at a stale or alternate endpoint.
- Several ports from the same IP could be dialed concurrently, creating bursts when peer records were stale.
- Repeated discovery checks appended duplicate `COOLDOWN` rows to Peer Activities.
- A historical verified record could make a disconnected peer appear `VERIFIED` with an old height, while a new PEX endpoint was discarded to protect the old verified record.

## Changes applied

1. **Endpoint-scoped failure cooldown:** failure counters are now keyed by `(ip, port)`, not only `ip`. A failing `IP:port` no longer suppresses a healthy listener at another port on the same address.
2. **Pending-dial deduplication:** repeated attempts to the same endpoint or advertised peer ID are suppressed while a dial is in flight. Distinct endpoints, including different ports on the same IP, remain eligible for parallel attempts; this snapshot does not impose a same-IP concurrency cap.
3. **Peer-ID duplicate suppression:** do not dial an authenticated connected identity again, and do not have multiple outbound attempts for one advertised peer ID in flight at the same time.
4. **Reconnect budgeting:** reconnect/bootstrap discovery counts pending attempts as well as connected peers, avoiding large bursts just because handshakes have not finished yet.
5. **Cooldown activity deduplication:** Peer Activities now records a cooldown transition once per endpoint until the endpoint's state changes again.
6. **Dynamic endpoint discovery:** keep the directly verified endpoint intact, but retain a different PEX-announced address separately as an unverified candidate. When several endpoints are known for one ID, the most recently advertised candidate is tried first. A direct handshake then promotes the current endpoint.
7. **Directory clarity:** a previously authenticated but currently disconnected entry is labeled `OFFLINE`; its displayed chain height is labeled `Last height`, not a current connected height.

## Validation

- `py_compile` passed for the changed networking, configuration, notification, CLI and regression-test files.
- In the repository checkout receiving this update, `py_compile` passed for the changed Python files and 78 focused tests passed across peer retry/cooldown, reconnect interval, directory, mesh admission, peer-height poisoning, block-relay deduplication, TUI, UDP recovery, peer security and port settings.
- The remaining tests in `test_vsa_remaining_20261015.py` passed: **15 passed, 1 deselected**.
- The full test suite did not finish within a 120-second test run. One test in the supplied baseline, `test_udp_initiator_opens_the_handshake_before_waiting_for_the_challenge`, fails on the original unmodified ZIP as well; it is unrelated to these peer retry changes.

## Limitation

These are local regression tests; they do not prove real-world reachability through carrier NAT/firewalls or replace a live multi-node mesh test. After installing this build, validate with at least three nodes on the same mobile IP and one node on a changing IP, recording peer activity and connection attempts for several reconnect intervals.
