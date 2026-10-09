# Supply-invariant evidence — 2026-10-09

## What the screenshot establishes

The latest supplied screenshot shows chain height `30`, dashboard total `302.00000000 VSD`, spendable balance `282.00000000 VSD`, and stake `20.0000 VSD`. The total displayed by the dashboard is balance plus locked stake; the stake is not an additional balance to add when checking issuance.

In the reviewed source, `Config.INITIAL_REWARD` is `1_000_000_000` satoshi (10 VSD), `Config.REWARD_DECAY_BLOCKS` is `20_000`, and genesis premine is configured as zero. `Blockchain.compute_reward_sat(height)` therefore returns the initial 10 VSD reward for each block through height 30. Scheduled issuance at height 30 is 300 VSD.

`SafetyInvariantChecker._check_balance_conservation()` sums account balances in satoshi while excluding the burn and L2 sink addresses, then compares the sum with `sum(compute_reward_sat(h), h=1..height)`. It does not add `roles.stake` to the balance sum because stake is modeled as a lock within balance. Therefore, under the current source rules, the screenshot's invariant reading of 302 VSD held versus 300 VSD issued represents a 2 VSD excess.

## What this does not establish

The screenshot does not identify which operation produced the excess. In this test sequence the user was still running an older diagnostic build, so we must not attribute the result to changes that had not been installed. The newer diagnostic-only build removes the old automatic stake-credit heuristic, but that alone does not prove which write caused this later discrepancy.

The earlier input log also came from the old reader version. It records repeated terminal mode repairs caused by a `VMIN`/`VTIME` type mismatch, 1,110.758 seconds waiting with no bytes read, followed by a carriage-return Enter that completed the line. That is a confirmed bug in that older reader; it does not itself explain the VSD excess.

## Next evidence to collect

The diagnostic build records:

- each direct and buffered balance mutation, requested satoshi amount, hashed account ID, result, and source call site;
- absolute account values written by block batches and recovery/restore paths;
- canonical held-vs-issued supply snapshots before and after each attempted block;
- the first block transition where `excess_sat` becomes positive.

Do not use these diagnostics to correct balances automatically. If the excess predates the start of tracing, the logs can establish that it already existed, but cannot reconstruct the mutation that happened earlier. Recovery should be based on a verified canonical-chain replay or a known-good backup, not an arbitrary wallet debit.
