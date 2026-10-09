# Visold fix report — Android/Termux terminal resume, SQLite block-start race, and supply-repair safety

## Confirmed symptoms reviewed

- After leaving Visold in the Android background, some interactive prompts accepted visible keystrokes but did not return to the menu.
- Mining logs showed `SQLite connection already has an active transaction` while starting a block-application transaction.
- A prior database showed an issuance invariant violation (held VSD greater than scheduled issuance). The earlier startup repair heuristic could have caused over-crediting.

## Changes in this package

1. **TTY input is nonblocking and recoverable.** Interactive line input prefers a fresh `/dev/tty` descriptor when the process has a controlling terminal; the descriptor is nonblocking. The reader polls, repairs raw input mode, retries `EAGAIN` after mode transitions, and accepts CR/LF. This closes the select/read race where a mode change could otherwise leave `os.read()` blocked.
2. **Hidden-secret prompts use the same resilient reader.** TTY secret entry disables manual echo and restores terminal line mode afterward. Non-TTY fallback remains `getpass`.
3. **Background networking no longer writes directly to the TUI's stdout.** The DNS seeder's per-address diagnostic uses the queue-backed logger, the redundant direct sync-reject print was removed, and the P2P message logger no longer falls back to raw stdout from a background thread.
4. **SQLite atomic block start safely yields to an unfinished ordinary write.** If `BEGIN IMMEDIATE` sees a pending *non-atomic* transaction, block startup releases the shared API lock and retries for up to `SQLITE_BUSY_TIMEOUT_MS`. This allows the original writer to commit/rollback. It does not forcibly commit/rollback another thread's work. An already-active Storage-owned atomic block or other error still fails immediately.
5. **Unsafe startup stake credit remains removed.** Startup diagnoses a possible legacy aggregate shortfall but does not credit balances without account-level evidence. Existing inconsistent data is not automatically debited or “repaired.”
6. Added/cleaned regression tests for PTY mode changes during input, the select/read race, secret-input no-echo, background stdout safety, the shared-SQLite-connection transaction race, and non-mutating supply diagnostics.

## Verification

- Python compilation of all modified source and test files: passed.
- Targeted regression group: **21 passed** (input synchronization, TUI frame buffer, stake-repair safety, SQLite atomic-begin race, background stdout safety).
- Additional files passed when run individually: `test_confirmed_bug_fixes.py` (9), `test_bugfixes_oct2026.py` (7), `test_confirmed_audit_repairs_20261006.py` (6), and `test_confirmed_audit_repairs_20261007.py` (4). `test_consensus_hardening_regressions.py` passed in one standalone run (7 tests), but later repeated runs were inconsistent/time-limited.
- A broad combined regression selection did **not** finish within its time limit, despite the tests that completed showing no assertion failures. Therefore, this report does not certify the full suite.
- Android/Termux device-level validation has not been performed. Host-side PTY tests model the relevant line-discipline transitions but cannot guarantee the terminal app behaves identically on the user's device.

## Database safety note

This package prevents the unsafe automatic stake-credit heuristic from running again. It does **not** correct legacy over-issued balances in an existing database. Do not arbitrarily debit a wallet. Back up the database, then reconcile the ledger and account state by replaying a verified canonical chain or restoring a known-good backup. A fresh database reaching height 10 with a total of 100 VSD is consistent with a 10 VSD reward per block; the earlier height-25/260 VSD observation remains a separate historical-state issue and should be checked against that database's canonical block/reward history.
