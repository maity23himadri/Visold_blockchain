# Visold Seed Unbounded Minimum-Peer Target Update

Date: 2026-10-20

## Base archive

Applied directly to `Visold_SATURATION_SEED_MIN_TARGET_FIX.zip`, retaining its mesh admission/saturation changes and seed-only unlimited active-peer/subnet capacity behavior.

## Behavior

- Ordinary nodes: `MIN_PEERS=3`, `MAX_PEERS=30`; unchanged.
- Explicit seed node: `SEED_MIN_PEERS=None`; `minimum_peer_target()` returns `None`, interpreted as an unbounded peer-discovery target.
- The seed's bootstrap/reconnect code does not stop at 30 (or any finite peer count): it continues exploring the known-peer list and configured seed peers on the existing retry cadence. Peer-exchange messages also feed candidates to the existing outbound connection logic.
- Every affected comparison is `None`-safe; the CLI health suggestion does not compare an integer count to `None`.
- The existing saturation-fix behavior is retained: only the explicitly designated seed bypasses the active-peer cap and subnet cap. Ordinary nodes remain capped at 30.
- This is an unbounded discovery target, not a guarantee of infinitely many actual connections. Only reachable/discovered peers can connect; CPU, RAM, sockets, and bandwidth still constrain the live peer count. Existing duplicate suppression, outbound cooldowns, handshake proof-of-work, per-IP protections, and bounded pending inbound queue remain in place.
- `visold/_build_identity.json` was regenerated to match all Python source files (149 source files).

## Validation

Passed:
- `python -m compileall -q visold`
- `PYTHONPATH=. pytest -q tests/test_p2p_mesh_admission_regressions_20261020.py tests/test_tofu_endpoint_and_logic_hash_fix.py tests/test_udp_security_fixes_20261006.py tests/test_udp_peer_recovery_regressions_20261007.py tests/test_network_port_settings.py tests/test_node_effective_port_wiring.py tests/test_clean_shutdown_20261020.py`
- Result: 54 passed.
- ZIP integrity check passed after packaging.

Limitations:
- A broader 5-file sync/bootstrap integration test batch did not finish within the 180-second timeout; it is not claimed as passing.
- No live Android six-node end-to-end run was performed in this environment.
