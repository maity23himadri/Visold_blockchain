# Process-death rollback test timeout adjustment — 2026-10-25

## Finding

`tests/test_consensus_hardening_regressions.py::test_process_death_before_block_save_rolls_back_sqlite_transaction` starts a child process which constructs and mines a real block before replacing `Storage.save_block` with `os._exit(77)`. On a fresh SQLite chain, the next-block difficulty is `Config.INITIAL_DIFFICULTY` (5.15), which implies roughly 2^(4 × 5.15) ≈ 1.58 million hash attempts on average. That work is platform-speed dependent and can exceed the test's hard-coded 60-second child-process timeout on Android/Termux.

## Change

The embedded test child now sets `Config.INITIAL_DIFFICULTY = 0.001` after constructing `Blockchain(st)` and before it asks for the next difficulty. This applies only inside the isolated child process used by this regression test. It does not modify production configuration, chain code, or consensus defaults. The test still mines a valid block against that child process's configured first-block difficulty, then forces process death at `save_block` and verifies persisted rollback invariants from the parent process.

## Verification

- On the Linux sandbox, the adjusted isolated test passed in 0.87 seconds.
- The relevant targeted set, including this test, passed: **37 passed in 7.98 seconds**.
- This is not a claim that the complete project test suite has passed on Android/Termux. Run the targeted set and then the remaining suite on the target device to verify there.
