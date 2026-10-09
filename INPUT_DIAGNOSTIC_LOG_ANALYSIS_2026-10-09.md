# Analysis of uploaded Visold input log (2026-10-09)

## Observed stall

The first logged process (`pid=10835`, active input operation `read_id=42`) spent 852.524 seconds in the line reader. Its main thread stack points to `select.select()` in `_read_tty_line()`. The log records 3,334 polls, 0 ready results until the final Enter, 0 read calls until that event, and then 1 byte read. That byte was CR; the reader recorded `enter_detected`, completed the line, restored terminal line mode, and returned to the main loop. This rules out Enter decoding as the reason for this particular 14-minute interval: the application had no bytes to decode during the interval.

The reader's `ui_lock_locked=true` is consistent with the main thread deliberately holding the UI lock while awaiting input; the refresh thread is waiting for that lock. The stack shows the main thread polling, not stuck in a menu operation.

## Confirmed source defect

The log repeatedly reports `tty_mode_repair_needed` and `tty_mode_repair_applied`, with `suppressed_repeats` around 19 over the rate-limit interval. In the same records, the observed `VMIN`/`VTIME` values are rendered as `"1"`/`"0"`, while the intended values are rendered as `"b'\\x01'"`/`"b'\\x00'"`. The source assigned byte strings to these control-character slots even though the reported Android/Python 3.14.6 runtime returns integers for them. The reader's `attrs != original` check therefore remained true on every 250 ms polling cycle despite the effective flags already matching the intended raw mode, repeatedly reapplying `tcsetattr()`.

This defect is fixed in this build by preserving each platform's native representation of `VMIN`/`VTIME`. A deterministic regression test simulates integer-valued slots, verifies repeated stable-mode calls do not reconfigure the terminal, and verifies repair still happens after a simulated terminal reset.

## What remains unproven

The log does not prove that repeated `tcsetattr()` calls were the sole cause of the no-input interval. It does prove that no bytes reached the selected FD until CR arrived. The updated log records TTY descriptor identity, TTY name, foreground process group, process group/session, window size, and stdin TTY state during a stall. If the failure recurs with this build, those fields should help distinguish a PTY/descriptor/session condition from a remaining reader problem.

The first log also contains a restarted process (`pid=32063`) where several input operations succeeded before a later read began waiting again. This agrees with the user's report that the failure is intermittent.

No changes were made to blockchain consensus, account balances, mining, or persisted state in this follow-up patch.
