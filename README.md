# Visold (VSD) - modular edition

Run it exactly as before (Pydroid: open `visold_vsd_.py` and press Run):

    python visold_vsd_.py                 # interactive node
    python visold_vsd_.py --test          # embedded test suite
    python visold_vsd_.py --cli --help    # command-line wallet / node tools

Keep `visold_vsd_.py` and the `visold/` folder side by side.

| Path | What it is |
|---|---|
| `visold_vsd_.py` | entry point + backward-compatible flat namespace (no implementation, no legacy loader) |
| `visold/` | the code: 22 bounded contexts, 117 modules, layered so import cycles cannot occur |
| `docs/ARCHITECTURE.md` | context map, layering rule, "where does X live", module index with original line ranges |
| `docs/MIGRATION_LOG.md` | what changed (3 declared edits), proof it is equivalent, strangler-fig waves, limits |
| `tools/` | `check_architecture.py` (run after every edit), `gen_docs.py`, and the verification / migration tooling |

Before replacing your old file read **MIGRATION_LOG.md section 5** (the logic hash changes, so mixed old/new networks
treat each other as TRUST_LOW) and run your usual multi-node test.

## Android / Termux terminal experience

The TUI uses standard ANSI terminal colors and adapts to narrow terminal widths.
For clean command help, clipboard notes, and a `tmux` session helper for detaching
and returning to the interactive UI, see [`docs/ANDROID_TERMUX_GUIDE.md`](docs/ANDROID_TERMUX_GUIDE.md).

```sh
python visold_vsd_.py --help
python visold_vsd_.py --version
python visold_vsd_.py
```

Within the TUI, `H` opens keyboard/clipboard help and `B` detaches the UI from a
`tmux` client without deliberately stopping the node. Outside a `tmux` session, `B`
explains how to enable it.

Optional Termux session commands (after installing `tmux` and the Python dependencies):

```sh
bash scripts/visold-termux.sh start
bash scripts/visold-termux.sh attach
bash scripts/visold-termux.sh status
bash scripts/visold-termux.sh stop
```

The TUI's full-screen frame is buffered and written in one operation; frequently
changing dashboard rows are still updated incrementally. Actual responsiveness and
background reliability should be measured on each supported Android device. A
`tmux` session does not override Android's process-killing or power-management rules.


### Seed peer target policy (2026-10-20)

Only a node explicitly enabled with `VISOLD_SEED_NODE=1` or `seed_node: true` uses the unbounded peer-discovery target. Internally its `minimum_peer_target()` is `None`, which means discovery keeps exploring known and PEX-discovered candidates instead of stopping at a numeric peer count. Ordinary nodes retain `MIN_PEERS=3` and `MAX_PEERS=30`. The seed's unbounded target does not guarantee infinite real connections; reachable peers and device/network resources remain finite.

## Authenticated pruned-node bootstrap scalability (2026-10-24)

Fresh and far-behind nodes can bootstrap from a recent authenticated snapshot even when the serving node has already pruned old block bodies. Snapshot authentication still verifies the canonical header chain before state is accepted.

`GET_CHAIN` remains protected by the existing per-peer DoS quota. If that quota is temporarily full, the serving peer now returns a correlated `busy` response with `retry_after_ms`; the bootstrap client waits for that capacity and retries the same header page. This removes the previous effective ~1000-header failure boundary caused by silently dropping the sixth request in a 10-second rate window.

The behavior is therefore height-scalable rather than page-count fragile: larger snapshot heights require more paced header pages, but they do not fail merely because more than five pages are needed. All existing header, PoW/consensus, snapshot-digest, request-correlation, global message-rate, and DB-scan concurrency checks remain active.

Real isolated two-node verification with the supplied V4 runtime state completed from a fresh height-0 node to source height 1256 with an identical canonical tip hash:

`000072f11b0647d3e0d60b40431746e11bdab73d4b62890226eb4a64f891c6a4`

See `BOOTSTRAP_RATE_LIMIT_SCALABILITY_FIX_2026-10-24.md` and `docs/CURRENT_SYNC_BEHAVIOR_2026-10-24.md` for the protocol behavior and verification details. Runtime databases/wallet state are not bundled in this code archive.

### 2026-10-24 mixed-version pruned-bootstrap handoff fix
When authenticated snapshot bootstrap lands on a checkpoint whose following block bodies are already pruned on an older peer, the snapshot-response routing slot is now handed off atomically to pruned-history recovery. Legacy delayed cleanup can no longer erase a newer recovery queue. This preserves mixed-version recovery without changing consensus, wire formats, or database formats. See `MIXED_VERSION_PRUNED_BOOTSTRAP_QUEUE_FIX_2026-10-24.md`.

## Adaptive topology probe eligibility fix (2026-10-26)

See `TOPOLOGY_PROBE_PRUNING_ELIGIBILITY_FIX_2026-10-26.md`. Over-target replacement probes now require a safe reciprocal edge that this node is designated to prune; otherwise the extra outbound probe is suppressed. Incoming peer admission remains governed by the existing hard cap and handshake checks.
