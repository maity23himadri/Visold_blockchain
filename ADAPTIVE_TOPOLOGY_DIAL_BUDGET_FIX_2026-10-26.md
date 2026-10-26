# Adaptive Topology Dial-Budget Fix — 2026-10-26

## Observed behaviour

The dashboard showed 5 active peers while the adaptive topology target was 3. Peer Activity showed repeated historical attempts to the configured seed, and no recent replacement dials. Existing links continued relaying blocks.

## Root cause confirmed in source

In `P2PNetwork._dial_pex_candidates()`, the old make-before-break logic set:

```python
dial_target = target + 1 if replacement_available else target
```

With `target=3` and `active_count=5`, even when a lower-degree replacement candidate existed, the computed dial target was 4. `max(0, 4 - 5 - pending_count)` therefore yielded a dial budget of 0. The node could not attempt a replacement peer; without that replacement, topology rebalancing could remain stuck above target.

The dashboard's Peer Activity panel is a bounded event history. Its latest seed attempt was at 11:45–11:46; block relays at 11:52–11:53 show the established mesh was still working, but do not mean a seed dial was still running at that time.

## Fix applied

`_dial_pex_candidates()` now:

- preserves normal target-based dialing when active + pending peers are below target;
- when at/over target, allows exactly one make-before-break replacement probe only if a fresh over-target incumbent is known, a distinct lower-degree or unreported candidate exists, no other dial is pending, all current links have remained stable for `TOPOLOGY_STABLE_SECONDS`, and hard peer capacity permits it;
- restricts this one-slot probe to eligible candidate IDs;
- waits for the new link to be stable before allowing another replacement probe, preventing an unbounded over-target connection ramp;
- emits an INFO diagnostic when a replacement probe is available and a DEBUG diagnostic when no probe can be started.

No numeric settings were changed: `MIN_PEERS` remains 25, `MAX_PEERS` remains 30, and `TOPOLOGY_TARGET_PEERS` remains 3 by default. The target is a soft topology goal; max capacity remains the hard cap.

## Regression evidence

The added test `test_over_target_mesh_allows_one_replacement_probe` was run against the prior ZIP's source and failed as expected (`started == 0`, expected 1). Against the patched source it passes. Additional tests verify that a pending dial blocks a second probe and that an unreported candidate may be tried once to learn its signed topology report.

Commands:

```bash
python -m py_compile visold/network/p2p.py tests/test_pex_dial_budget_starvation_20261021.py
PYTHONPATH=. pytest -q \
  tests/test_pex_dial_budget_starvation_20261021.py \
  tests/test_adaptive_peer_topology_policy.py \
  tests/test_p2p_liveness_and_handshake_handoff_20261022.py \
  tests/test_tcp_peer_decay_stale_session_race_20261022.py \
  tests/test_tcp_eof_diagnostics_20261022.py \
  tests/test_reconnect_interval_1min_20261021.py \
  tests/test_two_node_pruning_boundary_reconnect.py
```

Result: **60 passed**. This is targeted unit/regression evidence only; no live seven-node Android/Termux mesh was available in this test run. It does not prove that the current running node has reloaded this source or that every topology report is complete/fresh.

## Rollout note

Deploy this source to the ordinary nodes and restart them consistently. Watch for `[TopologyPolicy] replacement probe available` in the node log; if it never appears, use the DEBUG skip reason and verify current topology reports, peer IDs and runtime configuration. Do not infer a live root cause from Peer Activity alone.
