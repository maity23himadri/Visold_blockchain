# Visold TUI Resume/Input Fix — 2026-10-09 (superseded by current package)

## Updated failure analysis

The earlier polling reader still had a narrow race: terminal mode could change after `select()` reported input readiness but before `os.read()`. If the descriptor were blocking and the terminal had switched back to canonical mode, a read could remain stuck waiting for a line terminator. In addition, background network workers had direct `print()` calls that bypassed the UI lock and could displace the visible prompt/cursor.

## Current package changes

See `VISOLD_FIX_REPORT.md` for the authoritative report. In addition to the prior polling reader:

- TTY input prefers a fresh `/dev/tty` descriptor and uses nonblocking reads.
- A select/read race returns to the polling loop rather than blocking indefinitely.
- Hidden-secret TTY prompts use the same polling reader with echo disabled.
- Background DNS-seed and peer-sync diagnostics go through the queued logger instead of direct stdout writes.
- SQLite block startup yields the API lock and retries when it finds an ordinary writer's pending transaction, without forcibly committing or rolling back that work.
- The earlier unsafe startup stake credit is still removed.

## Verification and limitations

The focused regression group passed 21 tests. Some broader combined regression runs timed out or behaved inconsistently, although several affected files passed when run individually. The full suite is not certified. Host-side PTY tests model the relevant terminal transitions but do not replace an actual background/resume test on Android/Termux.
