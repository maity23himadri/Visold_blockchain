# Visold Economic Monitor Fix Report — 2026-10-19

## Changes made

1. **Removed the false inference that a public block streak proves selfish mining.** The consecutive-block check is now a no-op compatibility hook; consecutive public blocks by themselves do not establish private-chain withholding.
2. **Recorded actual reward distributions.** `_distribute_rewards()` now returns a per-address allocation map matching its existing satoshi credits. `apply_block()` passes that map to the economic monitor, so reward-share checks no longer assume the proposer receives the whole block subsidy when registered miners or validators receive allocations.
3. **Narrowed and de-duplicated concentration notices.** A concentration notice now requires a complete recent ten-block payout window and repeated production by at least two producer addresses (at least two blocks each) within the latest six blocks. This makes stale producer history insufficient by itself. A continuing condition is logged once, and the text explicitly says concentration alone does not prove an attack.
4. **Reconciled monitor history after rollback/reorg.** After a block is removed from canonical storage, the monitor rebuilds its producer history from the remaining canonical tip. It discards old payout/fee samples instead of trying to infer historical distributions from today's role table, which might differ from the roles active at those heights.
5. **Reduced repeat fee-spike messages.** Fee-spike evaluation requires a complete two-window sample and latches an ongoing condition so it does not emit the same warning on every new block.
6. **Added regression coverage** for solo-miner false positives, reward-alert de-duplication, rollback history reset, fee-alert de-duplication, exact reward allocation accounting, and canonical-history rebuilding.

## Validation results

- `python -m compileall -q visold` — passed.
- `PYTHONPATH=. python -m pytest -q tests/test_economic_monitor_regressions_20261019.py` — **8 passed**.
- `test_reorg_with_cold_cache_accepts_the_same_branch` — passed when run individually.
- `test_failed_reorg_restores_the_old_chain_exactly` — passed when run individually.
- `test_failed_commit_does_not_leave_block_marked_applied_in_memory` — passed when run individually.

Some larger legacy test bundles exceeded the execution time limit in this environment. One broad run printed 38 passing-test markers before timeout; the complete legacy suite was **not** verified. A bundle of the block-application tests printed eight passing-test markers before timing out, while its final failed-commit-retry test passed when run separately. These timeouts are not reported as test failures, but they prevent claiming a full-suite pass.

## Scope and limitation

The monitor now avoids calling a producer streak an attack without direct evidence. Reward concentration remains a statistical signal based on the measured recent payout window; it does not identify an attacker or prove withholding. After a rollback/reorg, payout history is intentionally warmed up again over subsequent successfully applied blocks because reconstructing old reward allocations using the current role table would be inaccurate.
