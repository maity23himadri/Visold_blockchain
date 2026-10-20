# Option 29 TUI Visibility and Dispatch Fix

Date: 2026-10-20
Base: `Visold_NETWORK_DIRECTORY_SYNC_BACKPRESSURE_FIX.zip`

## What was wrong

The screenshot provided by the user shows a runtime menu containing only `Network & Ports` at option 28, followed immediately by `Help & Session`. That menu does not match the code in the previously delivered archive, whose dispatcher already included `"29": self._network_directory`. This suggests the running folder/process was using an older or mixed source tree; the screenshot alone cannot identify precisely how that happened.

## Change in this package

- Keep option 28 (`Network & Ports`) in its own section.
- Render option 29 (`Network-wide Node Directory`) in a separate, explicit section and as its own row. This is easier to see on narrow Android portrait terminals and cannot be hidden by pairing it with option 28.
- Preserve the explicit `"29": self._network_directory` dispatcher mapping and searchable directory handler.
- Add regression tests for menu visibility, narrow-screen rendering, and dispatch of input `29` to the directory handler.
- Refresh `visold/_build_identity.json` so bytecode-only/source-mixed deployments can detect the updated package identity.

## How to apply

Extract this ZIP to a **new clean folder** (do not overlay just `visold_vsd_.py` or only part of the `visold/` package), then start the entry point from that folder:

```sh
python visold_vsd_.py
```

Before launching, verify the source contains both the standalone section and handler:

```sh
grep -n 'NETWORK-WIDE NODE DIRECTORY' visold/cli/interactive.py
grep -n '"29": self._network_directory' visold/cli/interactive.py
```

Both commands should print a matching line. Stop older running Visold processes before testing, since a running Python process keeps its already-imported source in memory.

## Verification performed

- Python compile check passed.
- TUI tests: menu visible, dispatch maps option 29 correctly, and narrow mobile layout keeps it visible.
- Network directory and sync/backpressure tests passed in the same targeted run.
- Archive integrity and source-manifest hash checked after packaging.
- This archive has not been run on the user's Android device; live PEX discovery and manual connection still require on-device validation.
