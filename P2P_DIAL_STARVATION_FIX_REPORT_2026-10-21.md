# Visold P2P dial starvation and connection-churn audit — 2026-10-21

## Scope / baseline

This patch is based on `Visold_5_peer_retry_fixed_1min_reconnect.zip`. The prior fixes are retained, including the 60-second reconnect base with jitter, no per-IP outbound concurrency cap, endpoint-scoped cooldowns, duplicate identity/pending guards, dynamic endpoint candidate handling, and offline directory status. The existing subnet-admission policy is intentionally unchanged, per operator instruction.

## Findings grounded in the supplied `manual-7-to-8-evidence.zip`

1. The 7-node stage had `MIN_PEERS=6`; node 8 had `MIN_PEERS=7`. These are different discovery targets. A minimum-peer target is not a full-mesh guarantee. This is a test/configuration asymmetry, not a reason to raise every production node's target automatically.
2. During the 8-node automatic stage, peer counts were `7, 7, 7, 7, 6, 7, 6, 5`. Three manual dials subsequently produced a stable full mesh for 15 seconds. This shows connectivity was possible, but automatic discovery did not converge within its 120-second window.
3. In the PEX `MSG_PEERS` handler, the `dialed` counter was incremented after `_try_add_peer()` regardless of whether a new connection worker was actually started. The candidate may already be connected/pending, cooling down, banned, blacklisted, or rejected by capacity checks. With stable candidate ordering, those no-op candidates consumed the four-attempt PEX budget and starved later eligible peers. This is a confirmed source-level defect.
4. On seed nodes, `_allow_pex_auto_dial()` also consumed a per-minute quota slot before knowing whether `_try_add_peer()` started any worker. Skipped candidates could spend scarce seed discovery quota. This is the same eligibility/accounting defect in the seed-specific rate limiter.
5. `_try_add_peer()` marked endpoints/identities pending before querying persistent blacklist state and before starting a thread. An exception at either point could leave the pending marker behind, making later attempts falsely appear duplicate/pending. The method also published `CONNECTING` after starting the worker, allowing a fast worker's `CONNECTED`/`FAILED` activity to be followed by an out-of-order `CONNECTING` status.
6. Six socket closes were directly traced to `_register_peer` duplicate-session arbitration. The report found eight pre-shutdown EOF exits, but did not map every EOF one-to-one to those six closes. Canonical arbitration itself is expected when both peers dial simultaneously; disabling it would risk retaining mismatched sockets. The patch keeps the arbitration and improves its debug explanation instead of changing its tie-break behavior without stronger evidence.
7. The first successful manual socket that was not retained cannot be attributed conclusively to one specific close from the supplied records. The code's duplicate-session paths now produce explicit debug reasons to help correlate a rerun.
8. The cap-30 same-subnet 11-node run is constrained by the configured subnet policy. The policy is not changed by this patch. It should not be used as proof that connection establishment is broken in a run whose intended topology exceeds that configured diversity limit.

## Code changes

- `_try_add_peer()` now returns `True` only if its connection worker successfully starts and `False` for skipped/rejected candidates.
- PEX candidate handling is factored into `_dial_pex_candidates()`. It charges the per-message dial budget only for real worker starts, continues past no-op candidates, and skips malformed, self, and source-peer candidates.
- Seed PEX rate slots are reserved with unique tokens and returned if a candidate does not start. Concurrent handlers cannot accidentally refund another handler's slot.
- Persistent blacklist lookup failure fails closed and always clears pending endpoint/identity state.
- Thread construction/start failure now clears pending state and emits a final `FAILED` activity.
- `CONNECTING` activity is emitted before the worker starts, preventing out-of-order UI state if the handshake completes quickly.
- Duplicate-session branches now log whether the new socket is non-canonical or whether the existing canonical socket was retained/replaced. Existing canonical direction and stale-disconnect safeguards remain unchanged.
- Added focused regression tests for PEX starvation, seed-rate-slot refund, pending-state leak prevention, activity ordering, and stale-session cleanup.

## Verification

- `python -m compileall -q Visold_1`: PASS.
- Focused networking regression set: **60 passed** (P2P admission, peer retry/cooldown, PEX rate policy, network directory, port settings, peer-height handling, mesh relay dedup, reconnect interval, and new PEX/pending-state tests).
- A whole-suite `pytest -q` run did not finish within 240 seconds. This is recorded as incomplete, not as a pass or a test failure diagnosis.
- No live 8-process / Android-Termux test was run against this patch in this sandbox. The supplied traces are pre-fix evidence. A fresh 7→8 (and ideally 11→12 with cap configured to permit the topology) integration rerun remains required before claiming the live-mesh problem is fully resolved.

## Why subnet policy was not altered

The operator explicitly stated that the subnet limit was changed intentionally. This patch does not modify `_peer_subnet_limit()`, `MAX_PEERS`, `MIN_PEERS`, or `RECONNECT_INTERVAL`.
