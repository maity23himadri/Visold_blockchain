# Migration log - monolith to modular package

Source: `visold_vsd_.py`, 55,370 lines, 522 top-level statements. Target: `visold/` package, 117 modules in 22 bounded contexts on 12 layers, plus a thin `visold_vsd_.py` entry/facade. Scope was **modularization only**: no bug fixing, no behaviour change, no class splitting.

## 1. Method

1. **Analyse, do not read.** A scope-aware AST analyser (cross-checked against CPython's own `symtable` on all 491 definitions, 0 mismatches) computed, for every top-level statement, which module-level names it needs at import time (decorators, bases, defaults, class bodies) and which only when a function runs.
2. **Design the domains** from the author's section banners and the dependency graph, then iterate until the module graph and the context graph were both acyclic (one genuine cycle, `VisoldNode` <-> `UserAccount`, is kept together in `node/visold_node.py`; several contexts were split along the real dependency seams, e.g. `ledger` / `storage` / `chain`, `consensus` rules / chain-bound consensus engine, `rollup` core / sequencer).
3. **Move mechanically.** Every statement is copied verbatim (comments and section banners travel with it) into its module by a script, never by hand. Import lines are generated from the analysis. Original relative order inside a module is preserved, so import-time evaluation order is unchanged.
4. **Prove it** (section 3), then **strangle in waves** (section 4).

## 2. The only edited code (3 declared patches)

Everything else is byte-for-byte identical. These three constructs depended on *where* the code lives and cannot be moved unchanged:

| # | Where | Was | Now |
|---|---|---|---|
| P1 | `kernel/source_identity.py` | `open(__file__)` -> SHA-256 of the monolith file (`_NODE_LOGIC_HASH`) | SHA-256 of all `visold/**/*.py` (sorted relative path + bytes) via new helper `package_source_blob()` |
| P2 | `node/security_gate.py`, `SecurityGate.hash_self()` | `open(__file__)` | `sha256(package_source_blob())` |
| P3 | `network/block_download.py`, `ParallelBlockDownloader` | `sys.modules[__name__].Block` | plain import of `Block` |

## 3. Evidence

| Check | Result |
|---|---|
| Statements moved | 488 into modules (485 AST-identical, 3 patched); module docstring -> `docs/`; 2 `__main__` blocks -> facade verbatim |
| Line audit (comments + code) | 48,559 non-blank lines in moved bodies: **0 lost, 0 unexpected** (after the declared patch delta) |
| Import graph | 117 modules, 437 import edges, **0 module cycles, 0 context cycles**, no relative imports, every imported name exists |
| Bytecode | 1,417 functions/methods: identical instruction streams between original and package (CPython 3.12 call-form flag normalised - it only changes when code moves into a module where a name is an imported module-level name) |
| Linking | every global name used by every function (executed or not) resolves to the same kind of entity as in the original; 0 new unresolved names |
| Namespace | 2,877 records (names, classes, attributes, methods, properties, defaults) compared; 2,873 identical; the 4 expected differences are P1, P2, P3 and a time-derived start value (`GlobalSequencer._counter`) |
| Import behaviour | every module imports alone in a fresh interpreter; 6 random import orders; import-time side effects (threads, log handlers, signal handlers, atexit, env, files, recursion limit, socket timeout) identical |
| Behaviour A/B (original vs package: stdout, stderr, exit code, files written) | identical in 8 scenarios: `--version`, `--test-sc-name-1`, `--verify-hardened`, `--test` (138/138 embedded tests pass in both), `--cli --help`, `--cli wallet create`, and 2 scripted interactive sessions (first-run account creation -> full node start-up -> menu panels -> exit) |
| Process pool | parallel signature verification identical under `fork`, `spawn` and `forkserver` (the worker function now lives in `visold.crypto.parallel_verify`) |
| Lint mutation test | injected cycle, upward import and missing name are all caught by `tools/check_architecture.py` |

## 4. Strangler-fig waves

The monolith was shrunk context by context in dependency order. After each wave the *remainder* is the original file with the extracted units cut out and replaced by imports (a seam), so the program is complete and was re-verified (compile, bytecode/linking vs original, A/B behaviour incl. node start-up). The last wave leaves only the entry blocks - the final `visold_vsd_.py`. There is no loader for legacy code at any stage.

| Wave | Contexts extracted | Modules | Monolith left | Compile | Bytecode+linking | A/B behaviour |
|---:|---|---:|---:|:--:|:--:|:--:|
| 1 | kernel | 13 | 53,090 lines (95.9%) | ok | OK | OK |
| 2 | crypto, economics, governance | 24 | 50,741 lines (91.6%) | ok | OK | OK |
| 3 | consensus, rollup, selfhealing | 49 | 41,833 lines (75.6%) | ok | OK | OK |
| 4 | resilience, vm, wallet | 64 | 35,763 lines (64.6%) | ok | OK | OK |
| 5 | ledger | 66 | 34,760 lines (62.8%) | ok | OK | OK |
| 6 | state, storage | 75 | 28,504 lines (51.5%) | ok | OK | OK |
| 7 | mempool | 77 | 27,409 lines (49.5%) | ok | OK | OK |
| 8 | chain | 81 | 21,648 lines (39.1%) | ok | OK | OK |
| 9 | network | 102 | 12,112 lines (21.9%) | ok | OK | OK |
| 10 | api, identity, mining, testing | 111 | 8,116 lines (14.7%) | ok | OK | OK |
| 11 | node | 113 | 6,847 lines (12.4%) | ok | OK | OK |
| 12 | cli | 117 | 2,600 lines (4.7%) | ok | OK | OK |

Re-run any time: `python tools/strangle.py` (needs the original file, see section 7).

## 5. Behaviour you can observe

- **Logic hash changes (P1/P2).** `_NODE_LOGIC_HASH` is sent in the P2P HELLO/ACCEPT handshake. It is a *performance hint*, not a security gate: a peer whose hash is neither ours nor in `Config.KNOWN_GOOD_LOGIC_HASHES` is treated as `TRUST_LOW`. A package node and a monolith node therefore see each other as TRUST_LOW (as they would after *any* edit of the old file). Upgrade all nodes together, or add the new hash to `Config.KNOWN_GOOD_LOGIC_HASHES`. The new hash covers every `.py` file under `visold/` (not the facade) and is identical on all nodes with identical sources.
- **Class/function `__module__`** is now `visold.<context>.<module>` instead of `__main__`; tracebacks show the new file paths. The code base does not use `pickle`, so nothing persisted depends on the old module name.
- **Three import-time temporaries** (`_f`, `_h`, `_oc`: loop / `with` variables) are no longer leaked into the top-level namespace.
- **Start-up is lighter.** Only the tiny facade is compiled on each start; modules are cached as `.pyc`.
- **Unchanged on purpose:** every direct run still prints the architecture diagram and integration guide (the old `if __name__ == "__main__"` block at original line 53336 is kept verbatim in the facade).

## 6. Observed, deliberately not changed (no bug fixing today)

- Largest modules are whole classes moved intact: `network/p2p` (5.2k lines), `chain/blockchain` (4.8k), `cli/interactive` (3.7k), `storage/storage` (3.4k). Splitting a class (mixins) is a separate, riskier step - good next candidates once you are happy with this one.
- Not referenced by any other module (only re-exported by the facade; dead code or API for external tools): `economics/rewards`, `kernel/serialization`, `vm/abi`, `vm/assembler`, `selfhealing/hardening/failure_analysis`.
- `RollbackExecutor._dict_to_block/_dict_to_tx` find `Block`/`Transaction` by scanning `sys.modules` (works in the package; fragile by design).
- `UDPTransport._create_socket`: if IPv6 is unavailable the IPv4 fallback re-binds the configured `"::"` address and fails (seen in my IPv6-less sandbox, identical in both builds; irrelevant on hosts with an IPv6 stack).
- The relay helper process (`relay_server.py`) is started in its own session and outlives the node (both builds).
- The only name rebound at run time through `global` is `_SIG_POOL`; it stays in `crypto/parallel_verify` next to its accessor `_get_sig_pool()`.

## 7. Limits of what I could test, and how to re-verify

My sandbox has no network, no GPU and none of the optional back-ends (RocksDB, PostgreSQL, Redis, zstd, OpenCL). Real multi-node networking (NAT traversal, UPnP, STUN, relay), long mining/reorg runs and those back-ends are therefore verified **structurally** (identical bytecode, every global resolves, clean imports) but not executed. Run your usual multi-node test before replacing the old file, and keep the old file as the fallback.

If you compile with Cython, compile each module of the package (each carries the original directive header).

To re-run the full verification put the original file at `tools/visold_vsd_original.py` (or set `VISOLD_ORIG`):

```
python tools/check_architecture.py     # no original needed; run after every edit
python tools/verify_static.py          # AST identity, line audit, import graph
python tools/verify_runtime.py         # bytecode + linking vs the original, as loaded by CPython
python tools/verify_import.py          # isolated / random-order imports, import-time side effects
python tools/ab_run.py                 # behaviour A/B incl. scripted node start-up
python tools/strangle.py               # rebuild and verify every wave
python tools/split.py --out build      # regenerate the package from the original + tools/domain_map.py
```
