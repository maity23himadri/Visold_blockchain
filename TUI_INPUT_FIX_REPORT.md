# Visold terminal input synchronization fix

## Changes

- Serialize the main menu's blocking `input()` read with the same lock used by the live terminal renderer. A refresh or terminal-resize redraw can no longer move the cursor or clear the prompt while the menu line editor is active.
- Signal refresh shutdown before releasing the input lock, so a queued refresh cannot write stale cursor-control output immediately after a command is submitted.
- Recheck the shutdown signal before resize and incremental writes.
- Keep track of a refresh thread when its two-second join times out. A replacement thread is not started, and the shared stop event is not cleared, until the previous worker has actually exited.
- Add regression tests for input/render synchronization, resize redraws, and refresh-thread lifecycle.

## Behavior note

Incremental cursor-based dashboard updates are suspended while the main menu is waiting for input. The full dashboard is refreshed after a command is processed. This deliberately prioritizes reliable input over concurrent terminal writes, which can corrupt the prompt on terminal emulators such as Android/Termux.

## Verification

- `python -m compileall -q visold tests`: passed.
- `PYTHONPATH=. pytest -q tests/test_tui_frame_buffer.py tests/test_tui_input_synchronization.py`: 9 passed.
- The full test suite was attempted but exceeded the 120-second execution limit after 45 tests had completed; no failure was printed before timeout. Therefore, the full suite is not certified as passing by this run.
- The fix has not been exercised on a physical Android/Termux device in this environment.
