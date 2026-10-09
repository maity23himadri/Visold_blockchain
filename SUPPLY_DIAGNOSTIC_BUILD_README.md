# Visold Supply Diagnostic Build — 2026-10-09

## Purpose

This is a temporary diagnostic build, not a supply repair. It observes likely
balance-mutation paths and records aggregate held-vs-issued totals immediately
before and after each `apply_block` operation. It does **not** credit, debit,
restore, commit, roll back, or repair any account.

It is intended to identify the first block or balance mutation where the
conservation invariant diverges. Remove this diagnostic build after collecting
the reproduction evidence; it adds I/O to balance mutation paths and an
aggregate balance scan before and after each attempted block.

## Where the log is stored

The log is written to the configured `Config.DATA_DIR`, which defaults to:

`~/.visold/visold_supply_diagnostics.log`

A single rotated file is kept beside it as `visold_supply_diagnostics.log.1`.
If the environment variable `VISOLD_DATA_DIR` is set, use that directory
instead. This is separate from the input trace, which is written to the launch
working directory as `visold_input_diagnostics.log` unless
`VISOLD_INPUT_DIAG_PATH` overrides it.

The two files are individually limited to 256 KiB (about 512 KiB total).
Diagnostics are append-only JSON Lines. The input-diagnostic log remains
separate as `visold_input_diagnostics.log`.

## Privacy

Raw account addresses and wallet/private-key material are not recorded. Account
identifiers are SHA-256 prefixes. Balance amounts, signed mutation amounts,
block heights, call-site file/line/function labels, operation result types, and
aggregate supply values are recorded because they are necessary to locate a
supply discrepancy. Do not publish the logs publicly; send them only to the
reviewer debugging this source.

## Reproduction procedure

1. Back up the entire Visold data directory and source tree.
2. Extract this ZIP into a separate source directory. Do not merge files with
   other patch packages.
3. In Termux, select a **new, disposable data directory** before starting the
   process, for example:

   `export VISOLD_DATA_DIR="$HOME/.visold_supply_diag_run1"`

   Choose a different suffix if that directory already exists. Set this before
   launching Python so Visold creates a fresh test database and wallet there;
   this prevents the diagnostic run from using or repairing your existing
   data. The supply log will be written inside this test data directory.
4. Launch Visold using the same command you normally use, from the extracted
   diagnostic source directory. Reproduce the same short mining run from height
   zero. Watch for the first height where the startup invariant check or trace
   reports non-zero `excess_sat`.
5. Stop the test run cleanly if possible, then collect both supply log files
   and the input diagnostic log(s). Keep your original data directory intact.

## Events to inspect

- `balance_mutation`: direct `Storage.credit_sat` / `debit_sat` request, hashed
  account identifier, amount in satoshis and source call site.
- `batch_balance_mutation`: per-account buffered credit/debit operations during
  block application.
- `storage_set_balance`, `storage_restore_account`, and
  `storage_wipe_all_balances`: absolute changes and recovery/reset paths.
- `storage_balance_batch_account`: final absolute balances flushed by a block.
- `block_apply_started` / `block_apply_finished`: aggregate balances and
  scheduled issuance before/after each attempted block, plus deltas and result.

Search for the first record with `excess_sat` greater than zero. If the excess
appears during a block, inspect records for that block and account identifier.
If it exists before the first block, examine earlier direct writes or persisted
rows: the trace cannot reconstruct mutations that occurred before the diagnostic
build was launched.

## Verification and limitations

This diagnostic code is not consensus code and does not alter consensus rules,
but its extra I/O changes timing. The full project test suite has not been
certified. The focused tests validate issuance summation at epoch boundaries,
burn-address exclusion, privacy of account identifiers, and bounded logging.
It must still be tested against the specific Android/Termux runtime and the
reproducible scenario. A diagnostic trace is evidence for the next audit; it is
not itself a fix.
