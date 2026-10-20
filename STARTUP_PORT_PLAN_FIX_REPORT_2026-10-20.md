# Visold Startup Port-Plan Fix Report — 2026-10-20

## Summary

Investigated the report that Auto mode selected P2P port 8340 even though a standalone Python bind probe showed TCP/UDP 8338 available.

The supplied output establishes that TCP/UDP 8338 were available at the time of that separate probe, but it does not establish that the full port plan was available. The configured architecture pairs P2P port `P` with local JSON-RPC TCP `127.0.0.1:P+1`. The TUI explicitly reported that `127.0.0.1:8339` was unavailable. Therefore Auto selecting a different port was expected if RPC 8339 was genuinely occupied; the earlier 8338-only test did not test the conflicting port.

## Changes made

- Changed both runtime RPC port availability checking and the Network & Ports preflight to probe the exact production RPC bind address, IPv4 loopback `127.0.0.1`, rather than a wildcard dual-stack address. RPC remains local-only.
- Matched `SO_REUSEADDR` behavior in port preflight to the actual TCP/UDP listeners to reduce false conflicts from differences between probe and production socket setup.
- Made Auto mode log requested port, selected actual P2P/RPC pair, and skipped-candidate reasons so operators can see why 8338 was not selected.
- Removed an unnecessary reserved candidate exclusion from the Auto scan. Each candidate is evaluated as its own P2P/RPC pair.
- Improved the TUI messages to explicitly explain that P2P `8338` may be free while its paired RPC endpoint `127.0.0.1:8339` is occupied.
- Updated network-port documentation and the source identity manifest.
- Added tests for RPC localhost binding, unrelated specific-interface bindings, and separately reporting a busy RPC port while P2P TCP/UDP are free.

## Validation

- Python compile check passed for the changed modules and tests.
- `PYTHONPATH=. python -m pytest -q tests/test_network_port_settings.py tests/test_node_effective_port_wiring.py tests/test_clean_shutdown_20261020.py tests/test_udp_security_fixes_20261006.py tests/test_udp_peer_recovery_regressions_20261007.py tests/test_vsa_peer_security_20261014.py`: **40 passed**.
- Source identity manifest test passed in the targeted run.
- The complete repository test suite was not run to completion; no claim is made that every project test passes.
- This does not force Visold to use port 8338 when its paired RPC port is truly occupied. In that case choosing another Auto port or releasing the process holding `127.0.0.1:8339` is the correct behavior. There remains an unavoidable small race between a preflight probe and a later bind unless RPC sockets are reserved/handed off atomically.

## Files changed

- `visold/network/port_settings.py`
- `visold/network/p2p.py`
- `visold/cli/interactive.py`
- `visold/_build_identity.json`
- `tests/test_network_port_settings.py`
- `docs/NETWORK_PORTS.md`
