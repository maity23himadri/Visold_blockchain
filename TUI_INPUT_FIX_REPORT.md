# Visold terminal input and startup-accounting safety fix

This report is superseded by `VISOLD_FIX_REPORT.md`, which describes the latest package changes and verification.

The current implementation routes interactive CLI prompts through the shared reader, uses nonblocking/polling TTY input that can recover from PTY mode changes, keeps secret input hidden, pauses dashboard rendering while prompts are active, and prevents background network diagnostic writes from bypassing the TUI logger. It also keeps the refresh-thread lifecycle guard and the non-mutating startup supply diagnostic.

The unsafe startup stake-credit heuristic remains removed. The current release additionally handles the SQLite ordinary-write/block-BEGIN race without committing or rolling back another thread's transaction.

Verification should be read from `VISOLD_FIX_REPORT.md`; the full suite and Android/Termux device-level test are not certified as passing.
