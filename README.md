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
