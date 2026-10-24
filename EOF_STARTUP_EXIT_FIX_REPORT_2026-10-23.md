# Closed-stdin startup exit fix — 2026-10-23

## Problem
When standard input is closed (redirected from `/dev/null`, a detached or containerised
process, or Ctrl-D) while the node is waiting for an answer, `CLI._read_input()` raises
`EOFError` by design. During first-run account setup nothing catches it, so it reached
the generic handler in `visold/cli/entry.py`, which printed `Fatal error:` (an
`EOFError` has no message text) followed by a full traceback.

## Change
`visold/cli/entry.py`, `main()`: one new `except EOFError:` clause placed before the
generic `except Exception`. It restores the terminal, prints a short explanation to
stderr, and exits with code **1**. The `finally` block still runs `shutdown_node()`.
Exit code 1 is kept deliberately: the node could not continue, and a service manager
must see that. (A `SystemExit` raised deeper in the code would be swallowed by the
existing `except SystemExit: pass` and turn into exit 0, so the exit is made in this
handler, using the same pattern as the existing Fatal-error branch.)

`visold/_build_identity.json`: `package_source_sha256` updated to the new source hash
(`dd79bb6bd5f2fd37204167fc5f63c29356a314368a48cdd9be0a86f0c82e6f7e`; was
`cd097c2fbd76d9c3739ba273d922af13ecb14ea4ee2a1c5b9ca86c4390e27a61`). The algorithm and
file count (149) are unchanged. The method was first checked by reproducing the old
hash from the unmodified source.

No other file was changed. Menu behaviour, the main-loop tolerance of closed stdin once
an account exists, and `--version` / `--help` / `--cli` are untouched.

## Verified by running the node (no test suite was run)
- First run, stdin `/dev/null`: message printed, no traceback, exit 1.
- First run, input closes after choosing option 1: same.
- Normal account creation reaches the dashboard; closing input at the main menu keeps
  the node running; SIGTERM stops it cleanly (exit 0, no warnings).
- Existing account, stdin `/dev/null`: auto-login, keeps running, clean SIGTERM stop, exit 0.
- Closing input inside a menu prompt (Send Coins): node stays up, as before.
- `--version`, `--help`, `--cli --help`, `--cli`: identical output and exit codes to the
  original build.
- Runtime node logic hash equals the manifest hash.

## Consequence to plan for
Any change under `visold/` changes the node logic hash. Nodes running this build and
nodes running the previous build treat each other as TRUST_LOW. Restart all nodes on
this build together (the network is not public yet, so this is expected).
