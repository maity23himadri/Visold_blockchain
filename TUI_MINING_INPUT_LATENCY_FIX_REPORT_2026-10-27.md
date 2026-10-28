# V8/latest — Mining-active TUI latency fix report

Date: 2026-10-27
Base: `V8_ip_change_auto_reconnect_fix_20261027.zip`

## Reported symptom

When one Visold node is mining, pressing Enter on a TUI/menu input is followed by a 5–10 second wait before the next page/TUI appears. The lag is reportedly absent when mining is stopped. The fix is based on the latest V8 build containing the IP-change recovery fix; no older VI build was modified.

## Source findings and changes

### 1. Foreground menu input could wait up to two seconds for the refresh worker

`CLI._stop_refresh_thread()` joined the UI refresh worker with `timeout=2.0`. The refresh worker gathers mining, wallet, peer, and chain data before the last stop-event check, so if a node read is slow under mining load the input path can spend time waiting for the worker. The join bound is now 100 ms. If the worker has not exited, its thread reference is retained and `_start_refresh_thread()` still prevents overlapping workers.

`_redraw_live()` now checks the stop event before starting and after each potentially expensive node read. Once the user has submitted input, it stops doing further stats reads and will not write a stale frame over the prompt.

### 2. TUI repeated chain difficulty and height reads

`MiningEngine.status()` already returns both `difficulty` and `chain_height`. The dashboard, mining page, and background live-refresh path then queried `blockchain.get_difficulty()` and `blockchain.height()` again. Those duplicate calls have been removed; the TUI reuses the status snapshot and only falls back to direct reads when a status provider does not supply those fields. This does not alter mining or consensus behavior.

### 3. Stage-level and data-call diagnostics

The main loop records only stages taking at least 100 ms as `tui_stage_slow`, using static labels such as `stop_refresh_thread`, `dispatch_including_handler_prompts`, and `post_input_full_render`.

Dashboard/wallet/mining/nodes data reads now record `tui_data_call_slow` when a call takes at least 100 ms. Mining prewarm candidate construction logs `[MiningPrewarm] candidate_build_slow` only when the candidate build itself takes at least 1 second. These diagnostics record operation labels and elapsed time, not entered command contents, wallet secrets, or input text.

### 4. Cooperative yield for long hash loops

The miner now checks a cheap counter every 1024 hashes and invokes `time.sleep(0)` only when at least 10 ms elapsed since the previous yield. This preserves nonce/hash behavior and does not introduce a fixed sleep on every batch. An earlier yield-every-512-hashes experiment reduced throughput by about 20% in the local microbenchmark and was not retained. The time-based cadence showed no meaningful throughput regression in the local microbenchmark, but plain-CPython synthetic UI-wakeup latency was essentially unchanged; this is a fairness safeguard, not proof that the user's full 5–10 second symptom is solved.

## Verification

- Python compileall for `visold/` and `tests/`: passed.
- Architecture check: **OK — 125 modules, 475 import edges, 22 contexts; no cycles, layering respected**.
- Selected TUI, input-diagnostics, worker-yield, hashrate-governor, liveness/mining, mining lifecycle, pending-outcome, and remaining-regression tests: **77 passed in 11.77 seconds** (verified from the extracted final ZIP).
- Source build manifest updated and verified: `449b5323aa8fe9f1fe3f63152243fa1a0f2440365461ce037c4382923866a9e4` (151 `visold` Python files).
- ZIP CRC/integrity is checked after packaging.

## Important limitation

The full test suite was not run, and the 5–10 second Android/Termux lag could not be reproduced here. This patch removes confirmed avoidable waits and duplicate chain reads, and adds evidence to identify the remaining slow stage on the actual device. It does **not** claim the live-device symptom is fully verified as fixed. If a slow transition remains, `tui_stage_slow`, `tui_data_call_slow`, and `[MiningPrewarm] candidate_build_slow` logs identify whether the time is spent stopping refresh, inside the selected action, reading node state, or rendering the page.
