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
"""visold.cli.terminal

Original section: SECTION 20: CLI

Defines: clr, bold
Origin: visold_vsd_.py L44864-44907, L44911-44935
"""

import ctypes
import os
import sys


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 20: CLI
# ─────────────────────────────────────────────────────────────────────────────
# ─── Cross-platform ANSI / TTY support ──────────────────────────────────────
# Enables VT100 escape processing on Windows 10+ consoles (cmd, PowerShell)
# via the Win32 SetConsoleMode API. Degrades silently on any failure so the
# CLI still runs (without colour / cursor tricks) on:
#   • Old Windows consoles without VT support
#   • Pipes / redirected stdout (non-TTY)
#   • CI environments, log files, nohup, etc.
#   • Restricted Android / embedded shells
_WIN_VT_ENABLED = False


def _enable_windows_ansi() -> bool:
    """Enable VT100 processing on Windows. Returns True on success."""
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        STD_OUTPUT_HANDLE  = -11
        STD_ERROR_HANDLE   = -12
        ENABLE_VT          = 0x0004
        for handle_id in (STD_OUTPUT_HANDLE, STD_ERROR_HANDLE):
            h = kernel32.GetStdHandle(handle_id)
            if h in (0, -1):
                continue
            mode = ctypes.c_ulong()
            if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                continue
            kernel32.SetConsoleMode(h, mode.value | ENABLE_VT)
        return True
    except Exception:
        return False


_WIN_VT_ENABLED = _enable_windows_ansi()


def _stdout_is_tty() -> bool:
    """True only when stdout is a real terminal that can render ANSI."""
    try:
        if not sys.stdout.isatty():
            return False
    except Exception:
        return False
    # Respect common env vars that disable colour
    if os.environ.get("NO_COLOR"):
        return False
    term = os.environ.get("TERM", "").lower()
    if term in ("dumb", ""):
        # On Windows, TERM is often unset but VT may still be enabled
        if os.name == "nt" and _WIN_VT_ENABLED:
            return True
        if os.name == "nt":
            # Fall back to True for Windows 10+; SetConsoleMode either worked or not
            return _WIN_VT_ENABLED
        return False
    return True


# Determine once at import time whether ANSI is safe to emit.
# (UI code re-checks at render time via CLI._ansi_ok() for dynamic safety.)
_ANSI_OK = _stdout_is_tty()


if _ANSI_OK:
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    WHITE   = "\033[97m"
else:
    # Non-TTY / redirected output: strip all colour so logs stay readable.
    CYAN = GREEN = YELLOW = RED = BOLD = DIM = RESET = MAGENTA = BLUE = WHITE = ""


def clr(text, color):
    if not color:
        return str(text)
    return f"{color}{text}{RESET}"


def bold(text):
    if not BOLD:
        return str(text)
    return f"{BOLD}{text}{RESET}"
