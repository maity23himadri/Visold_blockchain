# Visold Saturation + Seed-Only Peer Target Fix — 2026-10-20

## Base archive

This release is based on `Visold_MESH_ADMISSION_SYNC_FIX_2.zip` (the saturation/seed-cap version), not on the earlier `Visold_SEED_CAP_UNLIMITED_MIN30_FIX.zip` branch.

## Requested policy implemented

- **Ordinary nodes:** `MIN_PEERS=3` by default and finite `MAX_PEERS=30` by default.
- **Explicitly designated seed node only:** unbounded minimum-peer discovery target (`SEED_MIN_PEERS=None`) and unlimited active-peer count cap (no configured total-cap or subnet-cap rejection).
- `MAX_PEERS` remains `30` in global/default configuration. It has not been globally made unlimited.
- Seed designation is explicit: set `VISOLD_SEED_NODE=1` when launching the seed process or use `"seed_node": true` in only that seed's own `config.json`. An ordinary node that merely lists a seed in its bootstrap list is not elevated.

## Meaning of “minimum peer”

`MIN_PEERS` is a **desired peer target** for the reconnect/bootstrap loop, not an upper capacity. For ordinary nodes it stays finite at 3. For the explicitly designated seed, `minimum_peer_target()` returns `None`, meaning an unbounded discovery target: the reconnect/bootstrap loop never treats a finite peer count as having satisfied the seed target and continues exploring known and peer-exchange-discovered candidates at the existing retry cadence. Code paths use `None`-safe helper comparisons; they do not compare `None` directly to an integer. Seed admission remains unlimited separately, while duplicate suppression, peer failure cooldowns, per-IP protections, proof-of-work, and bounded inbound pending queue remain enabled. This is an operationally unbounded target, not a mathematical guarantee of infinitely many connections: availability, routing, finite candidate discovery, CPU, RAM, sockets, and bandwidth still constrain real peers.

## Saturation / admission behavior retained

- Only the explicit seed bypasses the total active-peer cap and subnet-diversity cap, so reaching 30 peers or having many peers from one mobile carrier subnet does not itself block a valid newcomer.
- Peer admission is reserved before `ACCEPT`; both sides should not report a completed connection unless the accepting side can register it.
- Deterministic duplicate-connection arbitration and stale-peer cleanup remain in place.
- Seed mode keeps the UDP pending-handshake queue bounded (256 pending inbound handshakes), with existing per-IP throttling and peer proof-of-work. “Unlimited” refers to the active-peer count cap, not infinite device resources or unlimited pending handshakes.
- Bootstrap/reconnect and the CLI network-health suggestion use the role-appropriate peer target: 30 for the designated seed, 3 for ordinary nodes by default.

## Validation

- `python -m compileall -q visold tests/test_p2p_mesh_admission_regressions_20261020.py` — passed.
- Mesh admission, role-specific targets, source identity/hash, port settings, effective port wiring, and clean shutdown test batch — **43 passed**.
- UDP recovery/security, peer security and listener admission batch — **29 passed**.
- Total across fully completed test batches: **72 passed**.
- An additional extended sync/bootstrap batch did not finish within its time limit; it stalled at `test_same_height_checkpoint_repair_recovers_aux_state_and_resumes_validation`. Its run is not counted as a passing suite.
- Source build identity checksum was recomputed and its manifest-consistency test passed in the 43-test batch.
- Archive integrity is checked separately after packaging.

## Device verification still required

This environment cannot run the user's Android/Termux six-node live mesh. Deploy the exact same updated source to the intended Python nodes, restart them, set the seed flag on **only one** seed process, and verify both endpoints show the new peer and that the newcomer advances its chain height. Old APKs do not receive this Python source patch unless rebuilt with it.
