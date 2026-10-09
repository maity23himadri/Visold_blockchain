# ─────────────────────────────────────────────────────────────────────────────
#  Visold (VSD) Blockchain Protocol
#  Copyright (c) 2025 Visold Contributors
#  Licensed under the MIT License.
#
#  The original and canonical source is maintained by the Visold Project.
#  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#  the license agreement.
# ─────────────────────────────────────────────────────────────────────────────
# cython: language_level=3
# cython: boundscheck=True
# cython: wraparound=True
# cython: cdivision=True
# cython: nonecheck=True
# cython: initializedcheck=False
# cython: infer_types=True
# cython: optimize.use_switch=True
# cython: optimize.unpack_method_calls=True
"""visold.cli.entry

Original section: SECTION 22: ENTRY POINT

Defines: main
Origin: visold_vsd_.py L50039-50135
"""

import signal
import sys
import traceback

from visold.cli.handler import CLIHandler
from visold.cli.interactive import CLI
from visold.cli.terminal import RED, YELLOW, _ANSI_OK, clr
from visold.kernel.config import Config
from visold.testing.suite import TestSuite


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 22: ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    cli_ref: dict = {"cli": None}

    def _restore_terminal():
        """Guarantee the terminal is returned to a clean state on any exit."""
        try:
            cli = cli_ref.get("cli")
            if cli is not None:
                cli._leave_alt_screen()
        except Exception:
            pass
        try:
            if _ANSI_OK:
                sys.stdout.write('\033[?25h\033[0m')
                sys.stdout.flush()
        except Exception:
            pass

    def handle_sig(sig, frame):
        _restore_terminal()
        try:
            print(clr("\n\n  Interrupted. Shutting down...", YELLOW))
        except Exception:
            pass
        sys.exit(0)

    # SIGINT is universal; SIGTERM exists on POSIX (and on modern Windows).
    try:
        signal.signal(signal.SIGINT, handle_sig)
    except Exception:
        pass
    try:
        signal.signal(signal.SIGTERM, handle_sig)
    except Exception:
        pass
    # SIGHUP / SIGWINCH are POSIX-only — ignore if unavailable (e.g. Windows).
    try:
        signal.signal(signal.SIGHUP, handle_sig)   # type: ignore[attr-defined]
    except Exception:
        pass

    # ── Friendly top-level help (without intercepting --cli --help) ──────────
    if "--cli" not in sys.argv and any(arg in ("-h", "--help") for arg in sys.argv[1:]):
        print("""Visold (VSD) — consumer-node interface

Usage:
  python visold_vsd_.py                 Start the interactive node and TUI
  python visold_vsd_.py --version       Show version and chain ID
  python visold_vsd_.py --test          Run the embedded test suite
  python visold_vsd_.py --cli --help    Show wallet/RPC command help

Interactive TUI:
  Enter a menu number and press Enter. Tabs accept F1–F5, t1–t5, or
  :dash, :wallet, :mining, :nodes, :activity. On Android, the terminal
  emulator provides text selection and clipboard paste; key gestures vary
  by emulator. See docs/ANDROID_TERMUX_GUIDE.md for setup and background use.

Safety:
  Back up your wallet/keystore before changing installations or data folders.
  Do not share keystore files, recovery secrets, or RPC token files.""")
        sys.exit(0)

    # ── --test / --version flags ──────────────────────────────────────────────
    if "--version" in sys.argv:
        print(f"Visold (VSD) v{Config.VERSION} | Chain: {Config.CHAIN_ID}")
        sys.exit(0)

    if "--test" in sys.argv:
        Config.ensure_dirs()
        ok = TestSuite().run_all()
        sys.exit(0 if ok else 1)

    # ── v7.5.0-OPT --cli subcommand mode ──────────────────────────────────
    # Dispatches to CLIHandler when the user invokes:
    #     python visold_vsd.py --cli <subcommand> [options...]
    # Anything after --cli is consumed by CLIHandler.run(); the daemon is
    # NOT started in this mode.  (wallet create works offline; all other
    # subcommands talk to a running daemon's RPC server.)
    if "--cli" in sys.argv:
        cli_idx = sys.argv.index("--cli")
        cli_argv = sys.argv[cli_idx + 1:]
        if not cli_argv:
            print("Usage: python visold_vsd.py --cli <command> [options]")
            print("Run `python visold_vsd.py --cli -h` for help.")
            sys.exit(2)
        # Handle the bare help case cleanly.
        if cli_argv[0] in ("-h", "--help"):
            cli_argv = ["--help"]
        try:
            rc = CLIHandler.run(cli_argv)
        except SystemExit as se:
            # argparse emits SystemExit on --help / bad args.  Preserve code.
            rc = se.code if isinstance(se.code, int) else 1
        except KeyboardInterrupt:
            print("Interrupted.", file=sys.stderr)
            rc = 130
        sys.exit(int(rc) if rc is not None else 0)

    port = Config.DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    cli = CLI()
    cli_ref["cli"] = cli
    try:
        cli.run()
    except SystemExit:
        pass
    except Exception as e:
        _restore_terminal()
        print(clr(f"\nFatal error: {e}", RED))
        traceback.print_exc()
        sys.exit(1)
    finally:
        _restore_terminal()
