# Input Diagnostic Build — Change Log

- Based on the previous Visold background-resume / SQLite v3 package.
- Added `visold/cli/input_diagnostics.py` for capped JSONL events, input wait heartbeats, and bounded thread stack snapshots.
- Instrumented the shared CLI line-reader and hidden-secret reader without recording actual entered text or secret contents.
- Added events for UI-lock acquisition, TTY-vs-stdin source selection, terminal mode repairs, `select` readiness, reads, Enter detection, EOF/errors, line return, and main-menu dispatch boundaries.
- Added tests for privacy guarantees and log-size rotation.
- No further consensus, reward, transaction, or database-repair behavior was changed specifically for this diagnostic package.

This package is for reproducing and diagnosing the user-reported Android/Termux input stall. A device-level reproduction and review of the resulting log are still required.

- Log review (2026-10-09) found a concrete termios bug on the reported Android/Python 3.14 runtime: `tcgetattr()` returned integer `VMIN`/`VTIME` values, while the reader rewrote them as bytes. The equality check therefore treated an already-correct terminal mode as changed and reapplied `tcsetattr()` on every 250 ms poll. The reader now preserves the platform's native value representation, and a regression test verifies stable raw mode is not repeatedly reconfigured.
- Added descriptor/TTY metadata to timeout heartbeats: descriptor stat identity, TTY name, foreground process group, process group/session, window size, and stdin TTY state. This does not log typed contents.
