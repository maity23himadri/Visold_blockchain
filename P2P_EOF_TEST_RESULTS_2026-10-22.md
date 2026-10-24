# P2P EOF fix — validation results (2026-10-22)

## Completed checks

- Focused regression tests: **91 passed**.
- Python `compileall`: **PASS**.
- Architecture: **PASS** — 123 modules, 469 import edges, 22 contexts; no cycles/layering violations.
- Source-identity manifest verification: **PASS** — `cd097c2fbd76d9c3739ba273d922af13ecb14ea4ee2a1c5b9ca86c4390e27a61`, 149 Python files.
- `visold/kernel/config.py` is unchanged from the uploaded baseline (SHA-256 `9a3f87a67d34d69460970770bb0e093bae4a2e26d4d4f9d72c946431ba148708`).
- Patch dry-run against the uploaded baseline: **PASS**.

## Live 7→8-node run

- 7-node baseline gate passed; node 8 joined automatically without manual dialing.
- 300-second observation completed, with 296 topology samples.
- Strict criteria: **PASS**. All samples reported eight nodes at seven peers each; 28 symmetric physical links; session IDs remained constant.
- The event logs had no `BlockingIOError`, `[PeerSendFailure]`, `[PeerTransportAbort]`, or `Peer disconnected` record during this run.
- Effective node policy reported by the harness was unchanged: `MAX_PEERS=30`, `MIN_PEERS=25`, `PEX_INTERVAL=60s`, `RECONNECT_INTERVAL=60s`, `PEER_DECAY_SECS=3600`, and per-IP inbound rate limit 12/60s.

Note: the live processes were started before the final diagnostic-only reclassification for “socket already closed before reader exception.” That final logging branch was covered by the focused regression tests; it does not change transport behavior.

## Full project suite

A full `pytest -q` attempt was stopped by its **240-second timeout** with exit code 124 at approximately 81% progress. Pytest did not emit its final summary. This result is **incomplete**, not PASS and not a confirmed test failure. Do not infer that the full suite passed from the focused 91-test run.
