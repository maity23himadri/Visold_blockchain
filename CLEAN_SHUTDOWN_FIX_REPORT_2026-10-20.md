# Visold clean-exit fix report — 2026-10-20

## Scope

This patch fixes shutdown/resource-lifecycle gaps in the Visold Python codebase used by the Network & Ports update. It does not change consensus rules, block validation, wallet derivation, or the P2P wire protocol.

## Changes

- **CLI exit path:** menu option `0` now ends the UI loop naturally after requesting cleanup. `main()` also calls the same idempotent shutdown hook from `finally`, covering signal-driven and exception-driven exits.
- **Node orchestrator:** `VisoldNode.stop()` is idempotent and best-effort. A failing optional subsystem no longer prevents subsequent listener, state-engine, process-pool, or storage cleanup.
- **Startup timers:** delayed capability/genesis broadcasts are tracked, made daemon threads, and cancelled/joined during shutdown so a five-second timer cannot keep a Termux session alive after Exit.
- **P2P listener:** the listening TCP socket is explicitly shut down and closed; its accept thread is retained and joined. UDP and connected peer sessions are also stopped/closed.
- **JSON-RPC:** shutdown now stops the server loop, calls `server_close()` to release the bound socket, and joins the worker thread. Previously only `shutdown()` was called.
- **ICE relay subprocess:** stop is synchronized against relay startup, terminates the child, waits to reap it, and kills/reaps it if it does not terminate in time. The ICE gathering thread is tracked and joined briefly.
- **Signature worker process pool:** the lazy `ProcessPoolExecutor` has an explicit shutdown path so worker processes are not left for interpreter finalization alone.
- **Storage:** node shutdown now closes the block database and the main storage backends (PostgreSQL/RocksDB/auxiliary SQLite where enabled).
- **DNS seeder:** the worker is signalled and joined briefly.

## Validation

- `python -m compileall -q visold visold_vsd_.py tests/test_clean_shutdown_20261020.py` — passed.
- Targeted shutdown, port-configuration, node effective-port, TUI/input and background-stdout tests — **31 passed**.
- UDP peer recovery/security, mining lifecycle and peer-security regression tests — **26 passed**.
- Total targeted regression cases passing across these runs: **57**.
- `unzip -t` is run on the generated archive before delivery.

The complete repository test suite was not run as part of this patch. Runtime testing on the user's Termux/Pydroid devices is still required to confirm no process or port remains after the real-world `0` exit path.
