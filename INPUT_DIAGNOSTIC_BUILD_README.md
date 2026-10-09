# Visold Input Diagnostic Build v2

## Purpose

This is a diagnostic build, not another proposed fix. It adds privacy-preserving, bounded logging around the existing v3 terminal input path so we can determine what happens when the UI stops accepting input after Android/Termux backgrounding.

The instrumentation observes input-loop state, terminal flags, read readiness, Enter detection, UI-lock waits, refresh-thread state, and Python thread stacks during prolonged reads. It **does not record the text typed, key values, passwords, private keys, or secret contents**. Stack snapshots contain source frames only; they do not include local variables.

The build also retains the prior v3 changes. Based on the first uploaded log, it fixes one confirmed input-reader defect: on Android/Python 3.14, `termios.tcgetattr()` exposed `VMIN` and `VTIME` as integers but the code rewrote them as bytes, causing terminal attributes to compare unequal and making the reader call `tcsetattr()` on every 250 ms poll. The revised reader preserves the native representation and applies a change only if the actual mode differs. It additionally records non-sensitive TTY/descriptor/process-group metadata at input stalls. This is a confirmed defect, but the log does not prove that it was the only cause of the missing input bytes. The build does not automatically repair any existing supply-invariant violation or reconcile an existing database.

## Where the log is written

By default, the file is created in the current working directory from which Visold is launched:

`visold_input_diagnostics.log`

If that directory is not writable, the fallback is:

`~/.visold/visold_input_diagnostics.log`

You can override the location by setting `VISOLD_INPUT_DIAG_PATH` before launching Visold. The log is JSON Lines and rotates at 256 KiB, keeping at most one rotated file (`visold_input_diagnostics.log.1`), so the two files together remain approximately 512 KiB or less.

## Reproduction procedure

1. Back up the source and database first. Prefer a disposable/test database for reproduction; the prior screenshots showed a supply-invariant warning, which this diagnostic build does not repair.
2. Extract this ZIP into a separate directory so the previous source is preserved.
3. Launch Visold in the same way you normally do. Confirm that `visold_input_diagnostics.log` appears in the launch directory.
4. Reproduce the usual sequence. Leave the app in the Android background for around 10–15 minutes, return to it, and test a harmless menu choice.
5. If input appears stuck, type one harmless character and press Enter once. Do not type any secret information into the unresponsive prompt. Wait at least 35 seconds before force-closing or killing the process: the watchdog writes a stack snapshot when a read has remained active for 30 seconds. You may wait another minute for a follow-up snapshot.
6. If the screen will not respond, open another Termux session and retrieve the log from the original launch directory. If the fallback path was used, retrieve it from `~/.visold/`. Include the `.1` rotated file if present.

Example commands from the launch directory:

```sh
ls -lh visold_input_diagnostics.log*
tail -n 160 visold_input_diagnostics.log
```

Please send the log file(s) back for inspection. Do not send database files or wallet secrets with them unless specifically requested for a separate, carefully scoped review.

## Interpreting the main signals

- `input_ui_lock_acquired` absent after `input_read_started`: investigate a lock wait or deadlock.
- `input_fd_selected` shows `stdin_readline` fallback instead of a TTY FD: the app is using the stream path rather than the nonblocking terminal reader.
- `input_wait_heartbeat` keeps appearing but `bytes_read` remains zero after you type: the input bytes are not reaching this reader, or terminal/PTY delivery is failing. In this build, the same event also records TTY descriptor identity, foreground/process/session group and window-size metadata, plus the stdin terminal state, to help distinguish a descriptor/session mismatch from an input-parser problem.
- `input_bytes_received` appears but `enter_detected` does not: inspect delivered control bytes and the terminal-mode-repair events.
- `enter_detected` and `input_line_returned_to_caller` appear but `main_menu_input_returned` or `main_menu_dispatch_start` does not: inspect the main-thread stack and control flow immediately after the read.
- `input_watchdog_stack_snapshot` records the thread stacks if a prompt remains active for at least 30 seconds. The `stacks` values are code frames only; typed text and locals are omitted.
- `tty_mode_repair_needed` should now appear only when the terminal flags genuinely differ from the expected raw-input state; it should not repeat on every poll just because this runtime represents VMIN/VTIME as integers.

## Safety and limitations

This build is intentionally instrumented and writes small periodic diagnostics while a prompt is waiting. It may have a small timing effect, so the results should be interpreted alongside the exact reproduction steps. It does not guarantee a fix and must not be described as one. The full project's test suite is not certified by the targeted tests alone.

If the app is busy inside a menu action rather than waiting for input, the diagnostic build also tracks the dispatch as a UI activity. After 30 seconds without completion, it records `ui_activity_watchdog_stack_snapshot`; this helps distinguish a blocked handler from a stalled terminal read. A nested read suppresses the duplicate parent snapshot because its stack already includes the menu-dispatch frames.

For a clean reproduction run, close the node and remove the previous log plus its rotated copy before restarting:

```sh
rm -f visold_input_diagnostics.log visold_input_diagnostics.log.1
```

Use the actual fallback path instead if the log was written under `~/.visold/`.
