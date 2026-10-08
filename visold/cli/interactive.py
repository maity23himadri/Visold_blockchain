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
"""visold.cli.interactive


Defines: CLI
Origin: visold_vsd_.py L44937-48568
"""

import getpass
import json
import math
import os
import random
import re
import shutil
import signal
import sys
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from visold.cli.terminal import (
    BLUE,
    CYAN,
    DIM,
    GREEN,
    MAGENTA,
    RED,
    RESET,
    YELLOW,
    _ANSI_OK,
    bold,
    clr,
)
from visold.kernel.config import Config
from visold.kernel.events import Event, EventType
from visold.kernel.logging_setup import _flush_log_queue, log
from visold.kernel.messages import MSG_CHAIN, MSG_GET_CHAIN
from visold.kernel.netutil import _format_peer_addr, _parse_peer_addr
from visold.kernel.notifications import (
    _notify_buf,
    _notify_buf_lock,
    _peer_activity_buf,
    _peer_activity_lock,
)
from visold.kernel.units import VSD_GLOBAL_MARKET, from_satoshi, to_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.node.security_gate import SecurityGate
from visold.node.visold_node import UserAccount, VisoldNode
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS
from visold.rollup.proofs import (
    ProofRegistry,
    UnsafeBackendOnMainnetError,
    _is_mainnet,
    _is_unsafe_backend,
)
from visold.vm.engine import VVMEngine
from visold.vm.naming import (
    derive_contract_address,
    normalize_contract_name,
    validate_contract_name,
)
from visold.wallet.hd import derive_wallet_from_secret


class CLI:
    # ── Layout constants: lines ABOVE the › prompt ────────────────────────────
    # _full_render() prints exactly 50 rows before input() is called.
    # If you add or remove printed lines in _full_render() you MUST update
    # these offsets, or the live cursor-positioning will land on wrong rows.
    #
    #  Row layout (0 = prompt, counting UP):
    #   0  : "  ›" prompt line
    #   1  : blank  (trailing blank, end of _print_menu — 28 lines total)
    #   2  : separator ─────
    #   3  : [0] Exit
    #   4  : separator ─────
    #   5  : blank
    #   6  : blank
    #   7  : [23] Gov Propose   /  [25] Smart Contracts — Call
    #   8  : [22] Gov Status    /  [24] Smart Contracts — Deploy
    #   9  : ── GOVERNANCE & CONTRACTS ──
    #  10  : blank
    #  11  : [20] AI Suggestions (single item)
    #  12  : [ 9] All Txns     /  [17] Resolve User ID
    #  13  : [ 6] Mempool      /  [16] Register Identity
    #  14  : [ 2] Explore      /  [15] Personal Info
    #  15  : ── EXPLORE & IDENTITY ──
    #  16  : blank
    #  17  : [21] Unstake      /  [14] Your Orders
    #  18  : [10] Balance      /  [13] Watch Orders
    #  19  : [11] Send Coins   /  [12] Give Order
    #  20  : ── WALLET & TRADING ──
    #  21  : blank
    #  22  : [ 8] Reg Miner    /  [ 7] Reg Investor
    #  23  : [ 5] Pause        /  [18] Mining Panel
    #  Dashboard row map (lines above the › prompt, bottom-to-top):
    #  ── existing rows ──────────────────────────────────────────────
    #  24  : [ 4] Stop Mining  /  [ 1] Add Peer
    #  25  : [ 3] Start Mining /  [19] Sync Chain
    #  26  : ── MINING & SYNC ──
    #  27  : blank
    #  28  : ══ MAIN MENU ══
    #  29  : blank  (between peer-activity panel and menu)
    #  30  : ──── (notif footer)
    #  32  : notif line 5 — newest  ← _UP_NOTIF[4]
    #  33  : notif line 4           ← _UP_NOTIF[3]
    #  34  : notif line 3           ← _UP_NOTIF[2]
    #  35  : notif line 2           ← _UP_NOTIF[1]
    #  36  : notif line 1 — oldest  ← _UP_NOTIF[0]
    #  37  : ─── Recent Activity ───
    #  38  : blank
    #  ── NEW: Peer Activity panel ────────────────────────────────────
    #  39  : ──── (peer-activity footer)
    #  40  : peer event 8 — newest ← _UP_PA[7]
    #  41  : peer event 7          ← _UP_PA[6]
    #  42  : peer event 6          ← _UP_PA[5]
    #  43  : peer event 5          ← _UP_PA[4]
    #  44  : peer event 4          ← _UP_PA[3]
    #  45  : peer event 3          ← _UP_PA[2]
    #  46  : peer event 2          ← _UP_PA[1]
    #  47  : peer event 1 — oldest ← _UP_PA[0]
    #  48  : ─── Peer Activity ───
    #  49  : blank
    #  ── shifted stats rows ──────────────────────────────────────────
    #  50  : Role / Stake line       ← _UP_ROLE
    #  51  : Mining / Mempool line   ← _UP_MINING
    #  52  : Peers / Hashrate line   ← _UP_PEERS
    #  53  : Height / Difficulty     ← _UP_HEIGHT
    #  54  : Balance                 ← _UP_BALANCE
    #  55  : separator ─────
    #  56  : Address  (static)
    #  57  : User ID  (static)
    #  58  : ╚══╝
    #  59  : ║ VISOLD NODE DASHBOARD ║
    #  60  : ╔══╗
    #  61  : blank (very top)
    # ── Tab definitions ───────────────────────────────────────────────────────
    # Tabs replace the monolithic 50-row layout with focused views.  Each tab
    # is responsible for rendering its own live-refresh region; the stats are
    # only live-refreshed on tabs where they make sense.
    TAB_DASHBOARD = 0
    TAB_WALLET    = 1
    TAB_MINING    = 2
    TAB_NODES     = 3
    TAB_ACTIVITY  = 4
    _TABS: List[Tuple[str, str]] = [
        ("Dashboard", "F1"),
        ("Wallet",    "F2"),
        ("Mining",    "F3"),
        ("Nodes",     "F4"),
        ("Activity",  "F5"),
    ]

    # ── Dynamic row-offset storage ────────────────────────────────────────────
    # These defaults are overwritten each render by _full_render() with values
    # computed from the CURRENT terminal size and actual rows printed, so the
    # live-update ANSI cursor positioning adapts to any screen height.
    _UP_BALANCE = 13
    _UP_HEIGHT  = 12
    _UP_PEERS   = 11
    _UP_MINING  = 10
    _UP_ROLE    = 9
    _UP_NOTIF: List[int] = [8, 7, 6, 5, 4]
    _UP_PA:    List[int] = [8, 7, 6, 5, 4, 3, 2, 1]

    def __init__(self):
        self.node: Optional[VisoldNode]             = None
        self.user_id: Optional[str]                 = None
        self._running                               = True
        # Live-UI concurrency state
        self._ui_lock       = threading.Lock()          # serialises stdout writes
        self._refresh_stop  = threading.Event()         # signals refresh thread to exit
        self._refresh_thread: Optional[threading.Thread] = None
        # Dynamic layout state — populated every _full_render().
        # Each _up_* holds "lines above the prompt" (passed to \033[{N}A).
        self._up_balance: int         = 13
        self._up_height:  int         = 12
        self._up_peers:   int         = 11
        self._up_mining:  int         = 10
        self._up_role:    int         = 9
        self._up_notif:   List[int]   = [8, 7, 6, 5, 4]
        self._up_pa:      List[int]   = [8, 7, 6, 5, 4, 3, 2, 1]
        self._layout:     dict        = {"W": 80, "H": 24,
                                          "pa_n": 8, "notif_n": 5,
                                          "menu_cols": 2}
        # Alt-screen state — only entered when stdout is a real TTY.
        self._alt_screen_on: bool     = False
        # Resize detection — POSIX sets this via SIGWINCH; Windows relies on
        # the refresh loop comparing cached size against current size.
        self._resize_pending: bool    = False
        self._last_term_size: Tuple[int, int] = (0, 0)
        # ── Tabbed UI state ───────────────────────────────────────────────────
        # Current tab: 0=Dashboard, 1=Wallet, 2=Mining, 3=Nodes, 4=Activity.
        self._tab: int                = 0
        # Activity tab pagination: scroll_offset is measured from NEWEST entry
        # (0 = latest page at bottom). Increased by `p` (prev/older), decreased
        # by `n` (next/newer).  `t`=oldest, `b`=newest.
        self._activity_scroll: int    = 0
        self._activity_page_size: int = 20  # recomputed per render

    def run(self):
        self._splash()
        Config.ensure_dirs()

        if not UserAccount.is_registered():
            self._first_run()
        else:
            self.user_id = UserAccount.get_user_id()
            print(clr(f"  Auto-login as {self.user_id}", GREEN))

        port = Config.DEFAULT_PORT
        self.node = VisoldNode(port=port)
        self.node.start()

        if self.user_id:
            # Do not submit a new on-chain claim automatically during startup.
            # Before the uniqueness fix this call only wrote local directory
            # metadata; after the fix it creates a fee-bearing mempool tx.
            # Automatic submission caused zero-balance nodes to retain a
            # REGISTER claim that mining could not dry-run. Users explicitly
            # register through menu option 18. If a claim already exists,
            # refresh only its local reachability metadata.
            try:
                claim = self.node.storage.resolve_name_claim(self.user_id)
                if claim and claim.get("pub_hex") == self.node.wallet.pub_hex:
                    self.node.identity.register(
                        self.user_id, "127.0.0.1", self.node.port)
                elif not claim:
                    log.info(
                        "Identity not claimed on-chain; use Register Identity / "
                        "Domain when you are ready to submit a fee-bearing claim.")
            except Exception as exc:
                log.debug("Startup identity directory refresh skipped: %s", exc)

        # Install SIGWINCH handler (POSIX only) so terminal-resize triggers a
        # full re-render with freshly-computed offsets.  Silently unavailable
        # on Windows, which has no SIGWINCH — resize events there are detected
        # by the refresh loop comparing cached size to the current size.
        try:
            signal.signal(signal.SIGWINCH, self._on_resize)   # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            pass

        self._main_loop()

    def _on_resize(self, *_a, **_kw) -> None:
        """SIGWINCH handler — flag for the refresh loop to re-render."""
        self._resize_pending = True

    def _splash(self):
        lines = [
            "",
            "  ╔══════════════════════════════════════════════════════╗",
            "  ║          V I S O L D  (VSD)  BLOCKCHAIN              ║",
            "  ║     Decentralized | Secure | Hybrid PoW+PoS          ║",
            "  ╚══════════════════════════════════════════════════════╝",
            "",
        ]
        for l in lines:
            print(clr(l, CYAN))

    def _first_run(self):
        """
        Entry-point when no local account.json is found (fresh device).
        Offers two paths:
          [1] Create a brand-new account.
          [2] Restore an existing account from another device using
              User ID + Secret Key.
        """
        print(clr("\n  ═══ FIRST RUN SETUP ═══", YELLOW))
        print("  No account found on this device.\n")
        print(f"  {clr('[1]', CYAN)} Create a new account")
        print(f"  {clr('[2]', CYAN)} Restore my existing account "
              f"{clr('(I have my User ID & Secret Key)', DIM)}")
        print()
        while True:
            choice = input("  Select [1/2]: ").strip()
            if choice == "1":
                self._create_account()
                break
            elif choice == "2":
                if self._recover_account():
                    break
                # _recover_account() returns False → loop back to this menu
                print(clr("\n  ─── Back to setup menu ───\n", DIM))
                print(f"  {clr('[1]', CYAN)} Create a new account")
                print(f"  {clr('[2]', CYAN)} Restore my existing account "
                      f"{clr('(I have my User ID & Secret Key)', DIM)}")
                print()
            else:
                print(clr("  Please enter 1 or 2.", RED))

    def _create_account(self):
        """Prompt for a username, register a new account, and display credentials."""
        print(clr("\n  ─── Create New Account ───", CYAN))
        print()
        while True:
            username = input(
                "  Choose a username (3–32 chars, letters/numbers/_): "
            ).strip()
            if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
                print(clr("  ✗ Invalid username format. "
                           "Use only letters, numbers, and underscores (3–32 chars).",
                           RED))
                continue
            ok, user_id, secret = UserAccount.register(username)
            if ok:
                print(clr("\n  ✓ Account created!", GREEN))
                print(f"  User ID   : {bold(user_id)}")
                print(f"  Secret Key: {bold(secret)}")
                # v7.5.x: show the deterministically-derived wallet address
                # so the user can verify cross-device recovery later.
                try:
                    _wdata = json.load(open(UserAccount.ACCOUNTS_FILE))
                    _waddr = _wdata.get("wallet_addr", "")
                    if _waddr:
                        print(f"  Wallet    : {bold(_waddr)}")
                except Exception:
                    pass
                print()
                print(clr(
                    "  ⚠  Write down BOTH your User ID and Secret Key.\n"
                    "     Either alone is not enough — you need both to\n"
                    "     restore your wallet on a new device.\n"
                    "     Your Secret Key is shown ONCE and cannot be recovered.",
                    RED
                ))
                print()
                self.user_id = user_id
                input("  Press Enter to continue...")
                break
            else:
                # user_id field carries the error message on failure
                print(clr(f"\n  ✗ Account creation failed: {user_id}", RED))
                input("  Press Enter to retry...")

    def _recover_account(self) -> bool:
        """
        Prompt for User ID + Secret Key, restore the account on this device,
        and return True on success or False if the user wants to go back.
        F-15 FIX: Derives and displays the wallet address BEFORE writing
        account.json so the user can confirm it matches their expected address.
        A wrong secret produces a visibly different address — the user can abort.
        """
        print(clr("\n  ─── Restore Existing Account ───", CYAN))
        print("  Enter the credentials you saved when you created your account.\n")

        user_id = input("  User ID   (e.g. HIMADRI#d43e705790): ").strip()
        if not user_id:
            print(clr("  Cancelled.", DIM))
            return False

        # getpass hides the key while typing (safe on shared screens)
        try:
            secret = getpass.getpass("  Secret Key: ").strip()
        except Exception:
            secret = input("  Secret Key: ").strip()

        if not secret:
            print(clr("  Secret Key cannot be empty.", RED))
            return False

        # F-15 FIX: Confirm entry by re-prompting
        try:
            secret2 = getpass.getpass("  Confirm Secret Key: ").strip()
        except Exception:
            secret2 = input("  Confirm Secret Key: ").strip()

        if secret != secret2:
            print(clr("\n  ✗ Secret keys do not match — please try again.", RED))
            return False

        # v7.5.x: derive the wallet address using the SAME canonical HKDF
        # derivation that UserAccount.recover() will use.  This means the
        # address shown here is exactly the wallet that will be installed
        # on this device — no preview/install drift possible.
        try:
            _w = derive_wallet_from_secret(secret, user_id)
            _derived_addr = _w.address
            print(f"\n  Derived wallet address: {bold(_derived_addr)}")
            confirm = input(
                "  Does this address match your expected address? [y/N]: "
            ).strip().lower()
            if confirm != 'y':
                print(clr("  Recovery cancelled — please check your User ID and Secret Key.", YELLOW))
                return False
            confirmed_address = _derived_addr
        except Exception as _de:
            print(clr(f"  Address derivation failed: {_de}", RED))
            confirmed_address = ""

        ok, msg = UserAccount.recover(user_id, secret,
                                      confirmed_address=confirmed_address)
        if ok:
            print(clr(f"\n  ✓ {msg}", GREEN))
            print(f"  Logged in as: {bold(user_id)}")
            print()
            self.user_id = user_id
            input("  Press Enter to continue...")
            return True
        else:
            print(clr(f"\n  ✗ {msg}", RED))
            print()
            return False

    def _sign_in(self):
        print(clr("\n  ═══ SIGN IN ═══", YELLOW))
        user_id = input("  User ID: ").strip()
        secret  = getpass.getpass("  Secret Key: ")
        ok, msg = UserAccount.login(user_id, secret)
        if ok:
            self.user_id = user_id
            print(clr(f"  ✓ {msg}", GREEN))
        else:
            print(clr(f"  ✗ {msg}", RED))
        return ok

    # ── Dashboard & live-UI helpers ───────────────────────────────────────────

    # ── Cross-platform responsive terminal sizing ─────────────────────────────
    # These helpers replace the previous hard-coded layout so the dashboard
    # adapts to any device / OS / DPI:
    #   • Android Termux portrait  : ~40–55 columns, 20–30 rows  -> compact
    #   • Android Termux landscape : ~80–120 columns             -> normal
    #   • Linux/macOS xterm        : 80–400+ columns             -> expands
    #   • Windows Terminal / cmd   : 80–200 columns              -> normal
    #   • SSH / CI / no TTY        : fallback (80,24), plain text
    #
    # Width is clamped to a minimum of _MIN_COLS so extremely narrow shells
    # still render (wrapped) but has no artificial upper cap — wide terminals
    # use their full width.  Height is also read and used to adapt the
    # dashboard's dynamic row counts (notifications, peer activity).
    _MIN_COLS = 32
    _MIN_ROWS = 10

    @staticmethod
    def _ansi_ok() -> bool:
        """Dynamic TTY/ANSI safety check (re-evaluated per render)."""
        return _ANSI_OK

    @staticmethod
    def _term_size() -> Tuple[int, int]:
        """Return (columns, lines) adapted for the current terminal.
        Works on Android/Termux, Windows, Linux, macOS. Never raises."""
        try:
            size = shutil.get_terminal_size(fallback=(80, 24))
            cols = int(size.columns) if size.columns else 80
            rows = int(size.lines)   if size.lines   else 24
        except Exception:
            cols, rows = 80, 24
        # Environment overrides (useful for Termux / CI where ioctl may lie)
        try:
            env_cols = os.environ.get("COLUMNS")
            if env_cols and env_cols.isdigit():
                cols = int(env_cols)
            env_rows = os.environ.get("LINES") or os.environ.get("ROWS")
            if env_rows and env_rows.isdigit():
                rows = int(env_rows)
        except Exception:
            pass
        if cols < CLI._MIN_COLS: cols = CLI._MIN_COLS
        if rows < CLI._MIN_ROWS: rows = CLI._MIN_ROWS
        return cols, rows

    @staticmethod
    def _term_width() -> int:
        """Responsive column count (see _term_size)."""
        return CLI._term_size()[0]

    @staticmethod
    def _term_height() -> int:
        """Responsive row count (see _term_size)."""
        return CLI._term_size()[1]

    @staticmethod
    def _compute_layout() -> dict:
        """
        Decide how many dynamic rows to render based on available terminal
        height, so the dashboard never exceeds the viewport.

        Budget (all values are line counts):
            blank(1) + title(3) + static(2) + sep(1) + stats(5) = 12
            blank(1) + pa_header(1) + pa_n + pa_footer(1)       = 3 + pa_n
            blank(1) + notif_header(1) + notif_n + notif_footer(1) = 3 + notif_n
            blank(1) + menu_n + prompt(1)                       = 2 + menu_n

        On very small terminals we shrink pa_n/notif_n to their floors, and
        the menu switches to single-column + compressed form.
        """
        W, H = CLI._term_size()
        FIXED_TOP   = 12           # title+static+stats area
        PA_FRAME    = 3            # header + footer + blank
        NOTIF_FRAME = 3
        MENU_MIN    = 6            # at least "Exit" + a few items visible

        max_pa, min_pa       = 8, 2
        max_notif, min_notif = 5, 2

        # Start with maximum dynamic rows, shrink if terminal too short.
        pa_n    = max_pa
        notif_n = max_notif

        def total() -> int:
            return FIXED_TOP + PA_FRAME + pa_n + NOTIF_FRAME + notif_n + 2 + MENU_MIN

        # Shrink notif_n first (less event-dense), then pa_n.
        while total() > H and notif_n > min_notif:
            notif_n -= 1
        while total() > H and pa_n > min_pa:
            pa_n -= 1

        # If still overflowing (tiny terminal), allow the menu to clip below
        # viewport — the live region must remain intact.
        menu_cols = 2 if W >= 60 else 1

        return {
            "W": W, "H": H,
            "pa_n": pa_n, "notif_n": notif_n,
            "menu_cols": menu_cols,
        }

    @staticmethod
    def _ansi_len(s: str) -> int:
        """Visible character length of *s*, stripping ANSI escape codes."""
        return len(re.sub(r'\033\[[0-9;]*m', '', s))

    def _live_line(self, label: str, val1: str,
                   label2: str = "", val2: str = "", W: int = 80) -> str:
        """
        Build one stat line padded to *W* visible characters so that when
        the refresh thread overwrites the terminal row with \033[2K the
        old (potentially longer) value is fully erased.
        """
        if label2:
            raw = f"  {clr(label, DIM)} {val1}   {clr(label2, DIM)} {val2}"
        else:
            raw = f"  {clr(label, DIM)} {val1}"
        return raw + " " * max(0, W - self._ansi_len(raw))

    def _fmt_notif(self, msg: str, W: int) -> str:
        """Format one notification line with severity colour, padded to *W* visible chars.

        Entries written by _QueueHandler embed a severity tag:
          [HH:MM:SS|ERR]  -> red
          [HH:MM:SS|WRN]  -> yellow
          [HH:MM:SS|INF]  -> dim cyan (default)
        Empty slots (padding) are returned as blank space.
        """
        if not msg:
            return " " * W
        if '|ERR]' in msg:
            color  = RED
            bullet = clr('x', RED)
        elif '|WRN]' in msg:
            color  = YELLOW
            bullet = clr('!', YELLOW)
        else:
            color  = DIM
            bullet = clr('>', DIM)
        # Strip the |SEV tag from visible text so the panel stays clean
        display   = re.sub(r'\|(?:ERR|WRN|INF)\]', ']', msg)
        truncated = display[:W - 6]
        raw = f"  {bullet} {clr(truncated, color)}"
        return raw + " " * max(0, W - self._ansi_len(raw))

    def _fmt_peer_activity(self, entry: Optional[dict], W: int) -> str:
        """Format one peer-activity entry for the dashboard panel.

        entry fields: ts, dir ('IN'/'OUT'), ip, port, status
        Empty slots (padding) are returned as blank space.

        Colour coding:
          CONNECTED  → green
          ARRIVING   → cyan   (inbound handshake in progress)
          CONNECTING → cyan   (outbound attempt in progress)
          BANNED     → red
          FAILED     → yellow
          REJECTED:* → yellow
        """
        if entry is None:
            return " " * W
        ts     = entry.get("ts", "")
        dir_   = entry.get("dir", "?")
        ip     = entry.get("ip", "")
        port   = entry.get("port", 0)
        status = entry.get("status", "")

        arrow  = clr("→", CYAN) if dir_ == "OUT" else clr("←", GREEN)
        addr   = f"{ip}:{port}"

        if status == "CONNECTED":
            sc = clr(status, GREEN)
            bl = clr("●", GREEN)
        elif status in ("CONNECTING", "ARRIVING"):
            sc = clr(status, CYAN)
            bl = clr("◌", CYAN)
        elif status == "BANNED":
            sc = clr(status, RED)
            bl = clr("✕", RED)
        elif status == "COOLDOWN":
            sc = clr(status, MAGENTA)
            bl = clr("⏸", MAGENTA)
        else:  # FAILED / REJECTED:*
            sc = clr(status, YELLOW)
            bl = clr("!", YELLOW)

        # Reserve addr column proportional to panel width so narrow mobile
        # terminals don't overflow and wide terminals don't waste space.
        # Overhead: 2 (margin) + 1 (bullet) + 1 + 8 (ts) + 1 + 1 (arrow) + 1
        # + addr + 1 + status(~10) ≈ 26 chars of non-addr content.
        addr_w = max(14, min(42, W - 26))
        raw = f"  {bl} {clr(ts, DIM)} {arrow} {addr:<{addr_w}} {sc}"
        return raw + " " * max(0, W - self._ansi_len(raw))

    # ── Tab bar & header ──────────────────────────────────────────────────────
    def _render_tab_bar(self, emit) -> None:
        """Render the tab bar (F1–F5 tab shortcuts) using the supplied emit()."""
        W = self._layout["W"]
        parts: List[str] = []
        for i, (name, key) in enumerate(self._TABS):
            label = f" {key} {name} "
            if i == self._tab:
                # Inverse-video for active tab (gracefully degrades on non-TTY)
                if _ANSI_OK:
                    parts.append(f"\033[7m{label}\033[0m")
                else:
                    parts.append(f"[{label.strip()}]")
            else:
                parts.append(clr(label, DIM))
        bar = "  " + "".join(parts)
        vis = self._ansi_len(bar)
        emit(bar + " " * max(0, W - vis))
        emit(f"  {clr('─' * max(10, W - 4), DIM)}")

    def _render_header(self, emit) -> None:
        """Compact identity header shown on every tab."""
        W     = self._layout["W"]
        inner = max(10, W - 4)
        _hbar = '\u2550'  # ═  (box-drawing horizontal; extracted to avoid backslash-in-f-string SyntaxError on Python < 3.12)
        emit(clr(f"  \u2554{_hbar * inner}\u2557", CYAN))
        emit(clr(f"  \u2551{'VISOLD NODE':^{inner}}\u2551", CYAN))
        emit(clr(f"  \u255a{_hbar * inner}\u255d", CYAN))
        # User/Address: join onto one line when wide enough, else two.
        n = self.node
        uid  = self.user_id or 'N/A'
        addr = n.wallet.address if n else ''
        one  = f"  {clr('User', DIM)} {bold(uid)}    {clr('Address', DIM)} {addr}"
        if self._ansi_len(one) <= W:
            emit(one)
        else:
            emit(f"  {clr('User   ', DIM)} : {bold(uid)}")
            emit(f"  {clr('Address', DIM)} : {addr}")

    # ── Tab 0: Dashboard ──────────────────────────────────────────────────────
    def _render_tab_dashboard(self, emit, get_row) -> None:
        """Compact overview: stats + small peer + notif panels."""
        n = self.node
        W       = self._layout["W"]
        pa_n    = self._layout["pa_n"]
        notif_n = self._layout["notif_n"]
        try:
            ms    = n.mining.status()
            bal   = n.storage.get_balance(n.wallet.address)
            role  = n.roles.get_my_role()
            peers = len(n.network.active_peer_count())
            diff  = n.blockchain.get_difficulty()
            ht    = n.blockchain.height()
            mplen = n.blockchain.mempool.size()
        except Exception:
            return

        mining_str = clr("\u2588\u2588 ON ", GREEN) if ms['running'] else clr("   OFF", RED)
        role_name  = (role['role'] if role else 'none').upper()
        # Show stake as a lock on balance: spendable = balance - stake.
        # Matches the enforcement rule in send_transaction (line ~24590).
        staked_amt = float(role['stake']) if role and role.get('role') in ('miner', 'investor') else 0.0
        # v7.2.x: also subtract pending mempool outflows (pending REGISTER
        # stake + pending transfers + pending fees) so the displayed
        # spendable drops the moment a tx hits the mempool, instead of
        # only after the block is mined.
        pending_reg_vsd = 0.0
        pending_xfer_vsd = 0.0
        pending_fee_vsd = 0.0
        try:
            p_reg_sat, p_xfer_sat, p_fee_sat = \
                n.blockchain.mempool.pending_outflow_sat(n.wallet.address)
            pending_reg_vsd  = from_satoshi(p_reg_sat)
            pending_xfer_vsd = from_satoshi(p_xfer_sat)
            pending_fee_vsd  = from_satoshi(p_fee_sat)
        except Exception:
            pass
        total_pending_vsd = pending_reg_vsd + pending_xfer_vsd + pending_fee_vsd
        spendable  = max(0.0, bal - staked_amt - total_pending_vsd)
        # "Stake" field shows confirmed stake only (pending REGISTER stake
        # is shown in the Pending line so balance+staked+pending == total).
        stake_display = staked_amt + pending_reg_vsd
        if pending_reg_vsd > 0:
            stake_str = f"{stake_display:.4f} VSD ({pending_reg_vsd:.4f} pending reg)"
        else:
            stake_str = f"{staked_amt:.4f} VSD" if role else "0.0000 VSD"
        # Pending line covers pending transfers + fees (excluding REGISTER
        # stake which is already folded into stake_display above).
        pending_xfer_fee_vsd = pending_xfer_vsd + pending_fee_vsd

        # Bootstrap indicator: shows DAA lock status for first 10 blocks
        _boot_n = Config.DIFF_BOOTSTRAP_BLOCKS
        _in_bootstrap = (ht < _boot_n)
        if _in_bootstrap:
            _boot_label = clr(f"[LOCKED {ht}/{_boot_n}]", YELLOW)
        else:
            _boot_label = clr("[DAA LIVE]", GREEN)

        emit(f"  {clr('─' * max(10, W - 4), DIM)}")
        self._row_balance = get_row()
        if staked_amt > 0 or total_pending_vsd > 0:
            emit(self._live_line("Balance  :", f"{spendable:.8f} VSD",
                                 "Total     :", f"{bal:.8f} VSD", W=W))
        else:
            emit(self._live_line("Balance  :", f"{bal:.8f} VSD", W=W))
        self._row_height  = get_row()
        _diff_str = f"{diff:.6f} {_boot_label}" if _in_bootstrap else f"{diff:.6f} {_boot_label}"
        emit(self._live_line("Height   :", str(ht), "Difficulty:", _diff_str, W=W))
        self._row_peers   = get_row()
        emit(self._live_line("Peers    :", str(peers), "Hashrate  :", ms['hashrate'], W=W))
        self._row_mining  = get_row()
        emit(self._live_line("Mining   :", mining_str, "Mempool   :", f"{mplen} TXs", W=W))
        self._row_role    = get_row()
        emit(self._live_line("Role     :", bold(role_name), "Stake     :", stake_str, W=W))
        if pending_xfer_fee_vsd > 0:
            pending_str = (f"{pending_xfer_fee_vsd:.8f} VSD"
                           f"  (xfer={pending_xfer_vsd:.4f}"
                           f"  fee={pending_fee_vsd:.4f})")
            emit(self._live_line("Pending  :", clr(pending_str, YELLOW), W=W))
        emit()
        emit(f"  {clr('─── Peer Activity ' + '─' * max(0, W - 22), DIM)}")
        with _peer_activity_lock:
            pa_entries = list(_peer_activity_buf)
        pa_entries = pa_entries[-pa_n:] if len(pa_entries) > pa_n else pa_entries
        while len(pa_entries) < pa_n:
            pa_entries.insert(0, None)
        for entry in pa_entries:
            self._rows_pa.append(get_row())
            emit(self._fmt_peer_activity(entry, W))
        emit(f"  {clr('─' * max(10, W - 4), DIM)}")
        emit()
        emit(f"  {clr('─── Recent Activity ' + '─' * max(0, W - 24), DIM)}")
        with _notify_buf_lock:
            notifs = list(_notify_buf)
        notifs = notifs[-notif_n:] if len(notifs) > notif_n else notifs
        while len(notifs) < notif_n:
            notifs.insert(0, "")
        for msg in notifs:
            self._rows_notif.append(get_row())
            emit(self._fmt_notif(msg, W))
        emit(f"  {clr('─' * max(10, W - 4), DIM)}")
        emit(clr("  Tip: press F5 (or type 5t) for the full scrollable Activity log.", DIM))

    # ── Tab 1: Wallet ─────────────────────────────────────────────────────────
    def _render_tab_wallet(self, emit, get_row) -> None:
        """Wallet overview: balance, address, pending & recent transactions."""
        n = self.node
        W = self._layout["W"]
        emit(f"  {clr('─' * max(10, W - 4), DIM)}")
        try:
            bal  = n.storage.get_balance(n.wallet.address)
            role = n.roles.get_my_role()
        except Exception:
            bal, role = 0.0, None
        staked_amt = float(role['stake']) if role and role.get('role') in ('miner', 'investor') else 0.0
        # v7.2.x: include pending mempool outflows in spendable display
        pending_reg_vsd = 0.0
        pending_xfer_vsd = 0.0
        pending_fee_vsd = 0.0
        try:
            p_reg_sat, p_xfer_sat, p_fee_sat = \
                n.blockchain.mempool.pending_outflow_sat(n.wallet.address)
            pending_reg_vsd  = from_satoshi(p_reg_sat)
            pending_xfer_vsd = from_satoshi(p_xfer_sat)
            pending_fee_vsd  = from_satoshi(p_fee_sat)
        except Exception:
            pass
        total_pending_vsd = pending_reg_vsd + pending_xfer_vsd + pending_fee_vsd
        spendable  = max(0.0, bal - staked_amt - total_pending_vsd)
        # "Stake" shows confirmed stake only; pending REGISTER stake shown
        # in Pending line so balance + staked + pending == total always.
        stake_display = staked_amt + pending_reg_vsd
        if pending_reg_vsd > 0:
            stake_str = f"{stake_display:.4f} VSD ({pending_reg_vsd:.4f} pending reg)"
        else:
            stake_str = f"{staked_amt:.4f} VSD" if role else "0.0000 VSD"
        # Pending xfer+fee line (separate from stake so the user can verify
        # that balance + staked + pending == total at a glance).
        pending_xfer_fee_vsd = pending_xfer_vsd + pending_fee_vsd
        self._row_balance = get_row()
        if staked_amt > 0 or total_pending_vsd > 0:
            emit(self._live_line("Balance :", f"{spendable:.8f} VSD",
                                 "Total   :", f"{bal:.8f} VSD", W=W))
        else:
            emit(self._live_line("Balance :", f"{bal:.8f} VSD", W=W))
        if pending_xfer_fee_vsd > 0:
            pending_str = (f"{pending_xfer_fee_vsd:.8f} VSD"
                           f"  (xfer={pending_xfer_vsd:.4f}"
                           f"  fee={pending_fee_vsd:.4f})")
            emit(self._live_line("Pending :", clr(pending_str, YELLOW), W=W))
        self._row_role = get_row()
        emit(self._live_line("Stake   :", stake_str,
                             "Role    :", (role['role'] if role else 'none').upper(), W=W))
        emit(f"  {clr('Address', DIM)} : {clr(n.wallet.address, YELLOW)}")
        emit()
        emit(f"  {clr('─── Recent Transactions ' + '─' * max(0, W - 28), DIM)}")
        # Pull last ~10 txs involving this wallet from storage.
        txs = []
        try:
            txs = n.storage.get_address_txs(n.wallet.address)[:10]
        except Exception:
            txs = []
        if not txs:
            emit(clr("  (no transactions yet — your sends & receives will appear here)", DIM))
        else:
            for tx in txs[:10]:
                try:
                    d = tx if isinstance(tx, dict) else (tx.to_dict()
                                                         if hasattr(tx, "to_dict") else {})
                    sender   = d.get("sender", "")[:12] + "…"
                    receiver = d.get("receiver", "")[:12] + "…"
                    amt      = d.get("amount", 0.0)
                    arrow = clr("→", RED if d.get("sender") == n.wallet.address else GREEN)
                    emit(f"  {sender} {arrow} {receiver}   {amt:.8f} VSD")
                except Exception:
                    continue
        emit(f"  {clr('─' * max(10, W - 4), DIM)}")
        emit()
        emit(clr("  Actions: [9] Send Coins   [10] Give Order   [11] Balance History", DIM))

    # ── Tab 2: Mining ─────────────────────────────────────────────────────────
    def _render_tab_mining(self, emit, get_row) -> None:
        n = self.node
        W = self._layout["W"]
        emit(f"  {clr('─' * max(10, W - 4), DIM)}")
        try:
            ms   = n.mining.status()
            diff = n.blockchain.get_difficulty()
            ht   = n.blockchain.height()
            mpl  = n.blockchain.mempool.size()
        except Exception:
            return
        status_str = clr(" ● RUNNING ", GREEN) if ms.get('running') else clr(" ○ STOPPED ", RED)
        if ms.get('paused'):
            status_str = clr(" ‖ PAUSED  ", YELLOW)
        self._row_mining = get_row()
        emit(self._live_line("Status   :", status_str,
                             "Backend :", ms.get('backend', 'CPU'), W=W))
        self._row_peers  = get_row()
        emit(self._live_line("Hashrate :", ms.get('hashrate', '—'),
                             "Blocks  :", str(ms.get('blocks_found', 0)), W=W))
        # Bootstrap indicator for mining tab
        _boot_n2 = Config.DIFF_BOOTSTRAP_BLOCKS
        _in_boot2 = (ht < _boot_n2)
        if _in_boot2:
            _boot_tag2 = clr(f" [LOCKED {ht}/{_boot_n2}]", YELLOW)
        else:
            _boot_tag2 = clr(" [DAA LIVE]", GREEN)
        self._row_height = get_row()
        emit(self._live_line("Height   :", str(ht),
                             "Difficulty:", f"{diff:.6f}{_boot_tag2}", W=W))
        self._row_balance = get_row()
        emit(self._live_line("Mempool  :", f"{mpl} TXs",
                             "Chain Ht :", str(ms.get('chain_height', ht)), W=W))
        emit()
        # Backend specifics if present
        backend = ms.get('backend', 'CPU')
        if backend == 'CUDA':
            emit(clr(f"  GPU device {ms.get('gpu_device','?')}, "
                     f"batch {ms.get('gpu_batch',0):,}", GREEN))
        elif backend == 'OpenCL':
            emit(clr(f"  OpenCL device {ms.get('gpu_device','?')}", GREEN))
        emit()
        emit(clr("  Actions: [1] Start   [3] Stop   [5] Pause/Resume   [6] Panel", DIM))

    # ── Tab 3: Nodes ──────────────────────────────────────────────────────────
    def _render_tab_nodes(self, emit, get_row) -> None:
        n = self.node
        W = self._layout["W"]
        emit(f"  {clr('─' * max(10, W - 4), DIM)}")
        try:
            with n.network._lock:
                peers = list(n.network.peers.values())
        except Exception:
            peers = []
        connected = [p for p in peers if getattr(p, "connected", False)]
        self._row_peers = get_row()
        emit(self._live_line("Peers    :",
                             f"{len(connected)} active / {len(peers)} known", W=W))
        emit()
        emit(f"  {clr('─── Connected Peers ' + '─' * max(0, W - 24), DIM)}")
        if not connected:
            emit(clr("  (no peers connected — use [4] Add Peer)", DIM))
        else:
            # Header row
            emit(clr(f"  {'Dir':<4}{'Address':<28}{'Ht':>6}  {'Rep':>5}  Status", DIM))
            for p in connected[:20]:
                try:
                    ip   = getattr(p, "ip", "?")
                    port = getattr(p, "port", 0)
                    out  = getattr(p, "outbound", False)
                    dir_ = clr("OUT", CYAN) if out else clr("IN ", GREEN)
                    ht_r = getattr(p, "last_known_height", None) or 0
                    rep  = int(getattr(p, "reputation", 0))
                    addr = f"{ip}:{port}"[:26]
                    emit(f"  {dir_} {addr:<26}{ht_r:>6}  {rep:>5}  {clr('CONNECTED', GREEN)}")
                except Exception:
                    continue
        emit(f"  {clr('─' * max(10, W - 4), DIM)}")
        emit()
        emit(clr("  Actions: [4] Add Peer   [2] Sync Chain", DIM))

    # ── Tab 4: Activity (scrollable log) ──────────────────────────────────────
    def _render_tab_activity(self, emit, get_row) -> None:
        """Full scrollable activity log: notifications + peer events merged."""
        W = self._layout["W"]
        H = self._layout["H"]
        # Build the combined log: notifications prefixed with "LOG",
        # peer events prefixed with "NET".  Most recent last.
        entries: List[Tuple[str, str]] = []   # (kind, formatted_line)
        with _peer_activity_lock:
            pa_snapshot = list(_peer_activity_buf)
        with _notify_buf_lock:
            notif_snapshot = list(_notify_buf)
        # Peer activity
        for e in pa_snapshot:
            try:
                ts  = e.get("ts", "")
                ip  = e.get("ip", "")
                port = e.get("port", 0)
                status = e.get("status", "")
                dir_ = "→" if e.get("dir") == "OUT" else "←"
                color = GREEN if status == "CONNECTED" else (
                        RED if status == "BANNED" else (
                        YELLOW if status in ("FAILED",) else CYAN))
                entries.append((ts, f"{clr('NET', CYAN)}  {clr(ts, DIM)}  "
                                     f"{dir_} {ip}:{port}  {clr(status, color)}"))
            except Exception:
                continue
        # Notifications
        for msg in notif_snapshot:
            if not msg:
                continue
            # Extract timestamp-like prefix [HH:MM:SS|SEV] for sort key
            m = re.match(r'\[(\d{2}:\d{2}:\d{2})\|', msg)
            ts = m.group(1) if m else ""
            color = RED if '|ERR]' in msg else (YELLOW if '|WRN]' in msg else DIM)
            display = re.sub(r'\|(?:ERR|WRN|INF)\]', ']', msg)
            # Strip leading [HH:MM:SS] from display (we show ts separately)
            display = re.sub(r'^\[\d{2}:\d{2}:\d{2}\]\s*', '', display)
            entries.append((ts, f"{clr('LOG', MAGENTA)}  {clr(ts or '--------', DIM)}  "
                                 f"{clr(display, color)}"))
        # Sort by timestamp (HH:MM:SS string sort is fine within a day)
        entries.sort(key=lambda t: t[0])
        total = len(entries)

        # Pagination
        # Budget content rows based on terminal height.
        # Fixed overhead: header(3: box) + identity(1-2) + tab bar(2)
        # + content frame(3: sep+title+footer+hints) + menu(~20) ≈ reserve 35
        content_rows = max(5, H - 18)   # leave some room for menu
        self._activity_page_size = content_rows
        # Clamp scroll
        max_scroll = max(0, total - content_rows)
        if self._activity_scroll < 0:
            self._activity_scroll = 0
        if self._activity_scroll > max_scroll:
            self._activity_scroll = max_scroll
        # Slice: self._activity_scroll counts from OLDEST end (0 = oldest);
        # display window = entries[scroll : scroll + content_rows]
        start = self._activity_scroll
        end   = start + content_rows
        window = entries[start:end]

        page_num   = (start // max(1, content_rows)) + 1
        page_count = max(1, (total + content_rows - 1) // max(1, content_rows))

        emit(f"  {clr('─── Activity Log ' + '─' * max(0, W - 20), DIM)}")
        emit(clr(f"  {total} entries   page {page_num}/{page_count}   "
                 f"(n=newer  p=older  t=oldest  b=newest)", DIM))
        emit(f"  {clr('─' * max(10, W - 4), DIM)}")
        if not window:
            emit(clr("  (no activity yet — logs and peer events will appear here)", DIM))
            for _ in range(content_rows - 1):
                emit()
        else:
            for _, line in window:
                # Pad to W so terminal resize doesn't leave tails
                vis = self._ansi_len(line)
                emit(line + " " * max(0, W - vis))
            # Pad remaining space with blanks so layout is stable across pages
            for _ in range(content_rows - len(window)):
                emit()
        emit(f"  {clr('─' * max(10, W - 4), DIM)}")

    # ── Unified render dispatcher ─────────────────────────────────────────────
    def _full_render(self) -> None:
        """
        Clear the terminal and render the current tab (header + tab bar +
        tab-specific content + menu).  Dynamically computes ANSI offsets for
        every live-refreshable row so the layout adapts to any terminal
        size, and the _up_* offsets match THIS render exactly.

        Replaces the former monolithic 50-row layout with a tabbed interface:
          F1  Dashboard — stats + compact panels (live-refresh)
          F2  Wallet    — balance, address, recent transactions
          F3  Mining    — mining status, hashrate, backend details
          F4  Nodes     — connected peers list
          F5  Activity  — scrollable full history (n/p/t/b paging)
        """
        self._layout = self._compute_layout()
        W = self._layout["W"]

        # ── Non-TTY fallback: plain text snapshot, no cursor tricks ────────────
        if not self._ansi_ok():
            n = self.node
            try:
                ms    = n.mining.status()
                bal   = n.storage.get_balance(n.wallet.address)
                role  = n.roles.get_my_role()
                peers = len(n.network.active_peer_count())
                diff  = n.blockchain.get_difficulty()
                ht    = n.blockchain.height()
                mplen = n.blockchain.mempool.size()
            except Exception:
                return
            tab_name = self._TABS[self._tab][0] if 0 <= self._tab < len(self._TABS) else 'Dashboard'
            print()
            print(f"  VISOLD NODE — tab: {tab_name}")
            print(f"  User ID : {self.user_id or 'N/A'}")
            print(f"  Address : {n.wallet.address}")
            print(f"  Balance : {bal:.8f} VSD")
            print(f"  Height  : {ht}    Difficulty: {diff:.6f}")
            print(f"  Peers   : {peers}    Hashrate  : {ms['hashrate']}")
            print(f"  Mining  : {'ON' if ms['running'] else 'OFF'}    Mempool : {mplen} TXs")
            role_name = (role['role'] if role else 'none').upper()
            stake_str = f"{role['stake']:.4f} VSD" if role else "0.0000 VSD"
            print(f"  Role    : {role_name}    Stake     : {stake_str}")
            print()
            self._print_menu()
            # No valid ANSI offsets in non-TTY mode — zero them so
            # _redraw_live() short-circuits cleanly.
            self._up_balance = self._up_height = self._up_peers = 0
            self._up_mining  = self._up_role = 0
            self._up_notif   = []
            self._up_pa      = []
            return

        # ── TTY: clear + re-render current tab ────────────────────────────────
        sys.stdout.write('\033[?25h\033[0m\033[H\033[2J')
        sys.stdout.flush()

        printed = 0
        # Tab renderers write per-row indices into these scratch slots.
        self._row_balance = self._row_height = self._row_peers = -1
        self._row_mining  = self._row_role = -1
        self._rows_notif:  List[int] = []
        self._rows_pa:     List[int] = []

        def _out(line: str = "") -> None:
            nonlocal printed
            print(line)
            printed += 1

        def _row() -> int:
            return printed

        # Global: blank + identity header + tab bar
        _out()
        self._render_header(_out)
        self._render_tab_bar(_out)

        # Tab-specific content
        if self._tab == self.TAB_DASHBOARD:
            self._render_tab_dashboard(_out, _row)
        elif self._tab == self.TAB_WALLET:
            self._render_tab_wallet(_out, _row)
        elif self._tab == self.TAB_MINING:
            self._render_tab_mining(_out, _row)
        elif self._tab == self.TAB_NODES:
            self._render_tab_nodes(_out, _row)
        elif self._tab == self.TAB_ACTIVITY:
            self._render_tab_activity(_out, _row)
        else:
            self._tab = self.TAB_DASHBOARD
            self._render_tab_dashboard(_out, _row)

        _out()
        # Menu
        menu_lines  = self._print_menu()
        printed    += menu_lines

        # ── Compute "lines up from prompt" for every recorded dynamic row ──
        def _up(r: int) -> int:
            return 0 if r < 0 else max(1, printed - r)
        self._up_balance = _up(self._row_balance)
        self._up_height  = _up(self._row_height)
        self._up_peers   = _up(self._row_peers)
        self._up_mining  = _up(self._row_mining)
        self._up_role    = _up(self._row_role)
        self._up_notif   = [_up(r) for r in self._rows_notif]
        self._up_pa      = [_up(r) for r in self._rows_pa]

    def _redraw_live(self, update_stats: bool = True) -> None:
        """
        Update only the changing rows using ANSI cursor save/restore with
        DYNAMICALLY-computed offsets from the last _full_render().  Never
        redraws the static header, separator, menu, or prompt.

        Silently becomes a no-op on non-TTY stdout so piping/redirection
        stays clean.
        """
        n = self.node
        if n is None:
            return
        if not self._ansi_ok():
            return   # no live refresh on piped / dumb output

        layout  = self._layout
        W       = layout.get("W", 80)
        notif_n = layout.get("notif_n", len(self._up_notif))
        pa_n    = layout.get("pa_n",    len(self._up_pa))

        updates: "OrderedDict[int, str]" = OrderedDict()

        # ── Stat rows ──────────────────────────────────────────────────────────
        if update_stats:
            try:
                ms    = n.mining.status()
                bal   = n.storage.get_balance(n.wallet.address)
                role  = n.roles.get_my_role()
                peers = len(n.network.active_peer_count())
                diff  = n.blockchain.get_difficulty()
                ht    = n.blockchain.height()
                mplen = n.blockchain.mempool.size()
            except Exception:
                return   # tolerate transient errors during node shutdown

            mining_str = clr("\u2588\u2588 ON ", GREEN) if ms['running'] else clr("   OFF", RED)
            role_name  = (role['role'] if role else 'none').upper()
            stake_str  = f"{role['stake']:.4f} VSD" if role else "0.0000 VSD"

            if self._up_balance > 0:
                updates[self._up_balance] = self._live_line(
                    "Balance  :", f"{bal:.8f} VSD", W=W)
            if self._up_height > 0:
                _boot_n3 = Config.DIFF_BOOTSTRAP_BLOCKS
                if ht < _boot_n3:
                    _diff_live = f"{diff:.6f} " + clr(f"[LOCKED {ht}/{_boot_n3}]", YELLOW)
                else:
                    _diff_live = f"{diff:.6f} " + clr("[DAA LIVE]", GREEN)
                updates[self._up_height]  = self._live_line(
                    "Height   :", str(ht), "Difficulty:", _diff_live, W=W)
            if self._up_peers > 0:
                updates[self._up_peers]   = self._live_line(
                    "Peers    :", str(peers), "Hashrate  :", ms['hashrate'], W=W)
            if self._up_mining > 0:
                updates[self._up_mining]  = self._live_line(
                    "Mining   :", mining_str, "Mempool   :", f"{mplen} TXs", W=W)
            if self._up_role > 0:
                updates[self._up_role]    = self._live_line(
                    "Role     :", bold(role_name), "Stake     :", stake_str, W=W)

        # ── Notification rows (event-driven) ──────────────────────────────────
        with _notify_buf_lock:
            notifs = list(_notify_buf)
        if len(notifs) > notif_n:
            notifs = notifs[-notif_n:]
        while len(notifs) < notif_n:
            notifs.insert(0, "")
        for up, msg in zip(self._up_notif, notifs):
            if up > 0:
                updates[up] = self._fmt_notif(msg, W)

        # ── Peer Activity rows ────────────────────────────────────────────────
        with _peer_activity_lock:
            pa_entries = list(_peer_activity_buf)
        if len(pa_entries) > pa_n:
            pa_entries = pa_entries[-pa_n:]
        while len(pa_entries) < pa_n:
            pa_entries.insert(0, None)
        for up, entry in zip(self._up_pa, pa_entries):
            if up > 0:
                updates[up] = self._fmt_peer_activity(entry, W)

        if not updates:
            return

        # ── Atomic ANSI write ─────────────────────────────────────────────────
        out = ["\033[?25l\033[s"]
        for up, line in updates.items():
            out.append(f"\033[u\033[{up}A\033[2K\033[1G{line}")
        out.append("\033[u\033[?25h")

        with self._ui_lock:
            try:
                sys.stdout.write("".join(out))
                sys.stdout.flush()
            except Exception:
                pass   # never crash the UI thread

    def _start_refresh_thread(self) -> None:
        """Launch the background 1-second UI refresh thread."""
        self._refresh_stop.clear()
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop, daemon=True, name="visold-ui-refresh"
        )
        self._refresh_thread.start()

    def _stop_refresh_thread(self) -> None:
        """Signal the refresh thread to stop and join it (max 2 s)."""
        self._refresh_stop.set()
        if self._refresh_thread is not None:
            self._refresh_thread.join(timeout=2.0)
            self._refresh_thread = None

    def _refresh_loop(self) -> None:
        """
        Dedicated UI refresh loop with two independent cadences:

        Every 1 second   → redraw notification panel (Recent Activity) and
                           Peer Activity panel only.  These rows reflect
                           event-driven pushes (_push_block_notif,
                           _push_peer_notif) that may arrive at any moment, so
                           they are surfaced immediately without waiting.

        Every 10 seconds → also redraw the five live-stat rows (Balance,
                           Height, Peers, Mining, Role/Stake).  These values
                           change at block cadence (~tens of seconds), so a
                           10-second poll is sufficient and avoids unnecessary
                           DB reads on every tick.

        Any exception is silently swallowed so a transient node error never
        terminates the UI thread.
        """
        _stats_tick = 0          # counts 1-second sleeps; resets at 10
        _STATS_INTERVAL = 10     # seconds between full stat redraws

        # Seed the cached size so the first tick doesn't falsely fire a resize.
        try:
            self._last_term_size = self._term_size()
        except Exception:
            self._last_term_size = (80, 24)

        while not self._refresh_stop.wait(1.0):
            _stats_tick += 1
            redraw_stats = (_stats_tick >= _STATS_INTERVAL)
            if redraw_stats:
                _stats_tick = 0

            # Detect terminal resize:
            #   • POSIX: self._resize_pending is set by SIGWINCH handler.
            #   • Windows / platforms without SIGWINCH: compare cached size.
            cur_size = (80, 24)
            try:
                cur_size = self._term_size()
            except Exception:
                pass
            resized = self._resize_pending or (cur_size != self._last_term_size)
            if resized:
                self._resize_pending   = False
                self._last_term_size   = cur_size
                # A resize invalidates every stored row offset, so a full
                # re-render is the only safe recovery path.  Skip it on
                # non-TTY to avoid spamming logs with escape sequences.
                if self._ansi_ok():
                    try:
                        with self._ui_lock:
                            self._full_render()
                    except Exception:
                        pass
                continue   # skip the incremental redraw this tick

            try:
                self._redraw_live(update_stats=redraw_stats)
            except Exception:
                pass   # never crash the UI thread

    # ── Main menu ─────────────────────────────────────────────────────────────
    MENU = [
        # Numbers follow visual reading order: left→right, top→bottom per section
        # ── MINING & SYNC ────────────────────────────────────────────────────
        ("1",  "Start Auto Mining"),
        ("2",  "Sync Chain"),
        ("3",  "Stop Mining"),
        ("4",  "Add Peer (manual)"),
        ("5",  "Pause/Resume Mining"),
        ("6",  "Mining Panel"),
        ("7",  "Register as Miner"),
        ("8",  "Register as Investor"),
        # ── WALLET & TRADING ─────────────────────────────────────────────────
        ("9",  "Send Coins"),
        ("10", "Give Order (Place TX)"),
        ("11", "Balance History"),
        ("12", "Watch Orders"),
        ("13", "Unstake"),
        ("14", "Your Orders"),
        # ── EXPLORE & IDENTITY ───────────────────────────────────────────────
        ("15", "Explore Blockchain"),
        ("16", "Personal Info"),
        ("17", "Mempool Viewer"),
        ("18", "Register Identity / Domain"),
        ("19", "All Transactions"),
        ("20", "Resolve User ID"),
        ("21", "AI Suggestions"),
        # ── GOVERNANCE & CONTRACTS ───────────────────────────────────────────
        ("22", "Governance — Upgrade Status"),
        ("23", "Smart Contracts — Deploy"),
        ("24", "Governance — Propose Upgrade"),
        ("25", "Smart Contracts — Call / Inspect"),
        # ── LAYER-2 GATEWAY ──────────────────────────────────────────────────
        # v7.5.0-OPT: enter the L2 sub-dashboard.  Keeps the L1 dashboard
        # clean and gives L2 its own focused command set (deposit, send,
        # rollup status, etc.).  Selecting "0" inside the L2 dashboard
        # returns here.
        ("26", "L2 Dashboard ▶"),
        ("99", "Diagnose Sync (live trace)"),
        # ── MAINTENANCE ─────────────────────────────────────────────────────
        ("R",  "Rollback Chain"),
        ("0",  "Exit"),
    ]

    def _enter_alt_screen(self) -> None:
        """Enter the alternate-screen buffer so the dashboard doesn't pollute
        the user's scroll-back.  No-op on non-TTY."""
        if self._alt_screen_on:
            return
        if not self._ansi_ok():
            return
        try:
            sys.stdout.write('\033[?1049h\033[?25h\033[H\033[2J')
            sys.stdout.flush()
            self._alt_screen_on = True
        except Exception:
            pass

    def _leave_alt_screen(self) -> None:
        """Leave the alternate-screen buffer and restore the user's shell."""
        if not self._alt_screen_on:
            return
        try:
            sys.stdout.write('\033[?25h\033[0m\033[?1049l')
            sys.stdout.flush()
        except Exception:
            pass
        self._alt_screen_on = False

    def _main_loop(self) -> None:
        """
        Main interactive loop.

        Architecture
        ────────────
        1. Enter alternate-screen buffer (TTY only) so the dashboard is
           isolated from the user's shell scrollback.
        2. _full_render()         — clears screen, prints fully adaptive
                                    layout, and stores per-row offsets that
                                    match THIS terminal's size.
        3. _start_refresh_thread()— daemon refresh (TTY only).
        4. input("  › ")          — blocks for user input.
        5. On a valid choice      — stop refresh → screen-hygiene → dispatch
                                    → re-render → restart refresh.
        6. On exit                — leave alternate-screen buffer.
        """
        self._enter_alt_screen()
        try:
            self._full_render()
            if self._ansi_ok():
                self._start_refresh_thread()
            while self._running:
                try:
                    choice = input(clr("  › ", CYAN)).strip()
                except KeyboardInterrupt:
                    choice = "0"
                except EOFError:
                    # AUDIT-FIX (cross-batch, surfaced from batch J's
                    # _log_queue check, lives in CLI/batch N): EOFError
                    # here means stdin is not an interactive TTY (headless
                    # service, detached/containerised process, closed or
                    # redirected stdin) — not an operator pressing Ctrl-D.
                    # main()'s only way to start the node (the default,
                    # no-special-argv path) always goes through this loop,
                    # so treating EOF the same as Ctrl-D previously shut
                    # the node down on its very first iteration in any
                    # non-interactive deployment. SIGTERM/SIGINT (handled
                    # in main()) remain the real way to stop the node;
                    # sleep briefly and keep looping instead so a
                    # permanently-EOF stdin doesn't spin at 100% CPU.
                    time.sleep(1.0)
                    continue
                self._stop_refresh_thread()
                # Terminal hygiene — only emit ANSI if TTY; otherwise just a newline.
                if self._ansi_ok():
                    sys.stdout.write('\033[?25h\033[0m\033[9999;1H')
                    sys.stdout.flush()
                    _flush_log_queue()
                    sys.stdout.write('\033[H\033[2J')
                    sys.stdout.flush()
                else:
                    print()
                    _flush_log_queue()
                self._dispatch(choice)
                if self._running:
                    self._full_render()
                    if self._ansi_ok():
                        self._start_refresh_thread()
        finally:
            self._stop_refresh_thread()
            self._leave_alt_screen()

    def _print_menu(self) -> int:
        """
        Colour-coded menu, grouped by category.  Returns the number of lines
        printed so _full_render can compute prompt offset dynamically.

        Layout mode
        ───────────
        • 2 columns when terminal width ≥ 60 (desktop / landscape mobile)
        • 1 column when width < 60          (mobile portrait / narrow SSH)
        """
        W         = self._term_width()
        menu_cols = self._layout.get("menu_cols", 2 if W >= 60 else 1)
        col       = max(28, (W - 4) // 2)

        _lookup: dict = {k: v for k, v in self.MENU}

        printed = 0
        def _emit(line: str = "") -> None:
            nonlocal printed
            print(line); printed += 1

        def _item(key: str, color: str) -> str:
            return f"  [{clr(key.rjust(2), color)}] {_lookup.get(key, '?')}"

        def _row2(k1: str, c1: str, k2: str, c2: str) -> None:
            if menu_cols == 1:
                _emit(_item(k1, c1))
                _emit(_item(k2, c2))
                return
            left = _item(k1, c1)
            pad  = max(0, col - self._ansi_len(left))
            _emit(left + " " * pad + _item(k2, c2))

        def _row1(key: str, color: str) -> None:
            _emit(_item(key, color))

        def _sec(label: str, color: str) -> None:
            inner   = max(10, W - 4)
            bar_len = max(0, inner - len(label) - 4)
            _emit(f"  {clr('── ' + label + ' ' + '─' * bar_len, color)}")

        # ── Header ────────────────────────────────────────────────────────────
        inner = max(10, W - 4)
        mid   = "  MAIN MENU  "
        wings = "═" * max(0, (inner - len(mid)) // 2)
        _emit(clr(f"  {wings}{mid}{wings}", YELLOW))
        _emit()

        _sec("MINING & SYNC", GREEN)
        _row2("1",  GREEN,   "2", CYAN)
        _row2("3",  RED,     "4", CYAN)
        _row2("5",  YELLOW,  "6", GREEN)
        _row2("7",  GREEN,   "8", GREEN)
        _emit()

        _sec("WALLET & TRADING", YELLOW)
        _row2("9",  YELLOW, "10", YELLOW)
        _row2("11", YELLOW, "12", CYAN)
        _row2("13", YELLOW, "14", CYAN)
        _emit()

        _sec("EXPLORE & IDENTITY", CYAN)
        _row2("15", CYAN,   "16", DIM)
        _row2("17", CYAN,   "18", DIM)
        _row2("19", CYAN,   "20", DIM)
        _row1("21", MAGENTA)
        _emit()

        _sec("GOVERNANCE & CONTRACTS", MAGENTA)
        _row2("22", MAGENTA, "23", BLUE)
        _row2("24", MAGENTA, "25", BLUE)
        _emit()

        # ── L2 GATEWAY ────────────────────────────────────────────────────────
        # Single-row section pointing into the L2 sub-dashboard.  A separate
        # section header makes the entry-point obvious to the user.
        _sec("LAYER-2 ROLLUP", BLUE)
        _row1("26", BLUE)
        _emit()

        _sec("MAINTENANCE", RED)
        _row1("R", RED)
        _emit()

        sep = f"  {clr('─' * max(10, W - 4), DIM)}"
        _emit(sep)
        _row1("0", RED)
        _emit(sep)
        _emit()

        return printed

    def _dispatch(self, choice: str) -> None:
        # ── Tab-switch shortcuts (F1–F5, t1–t5, :dash, :wallet, …) ─────────────
        # We handle these BEFORE the menu so they don't get treated as invalid.
        # The lookup covers every reasonable way a user might type a tab:
        #   • Literal function-key names : F1, F2, F3, F4, F5 (case-insensitive)
        #   • Shorthand with 't' prefix  : t1, t2, t3, t4, t5  — works in any
        #                                  terminal that doesn't send F-keys
        #                                  (Termux portrait, minimal SSH, etc.)
        #   • Colon-commands             : :dashboard, :dash, :wallet, :w,
        #                                  :mining, :m, :nodes, :n, :activity,
        #                                  :log, :a
        _norm = choice.strip().lower()
        _tab_map = {
            "f1": 0, "t1": 0, ":dashboard": 0, ":dash": 0, ":d": 0,
            "f2": 1, "t2": 1, ":wallet":    1, ":w":    1,
            "f3": 2, "t3": 2, ":mining":    2, ":m":    2,
            "f4": 3, "t4": 3, ":nodes":     3, ":n":    3,
            "f5": 4, "t5": 4, ":activity":  4, ":log":  4, ":a":  4,
        }
        if _norm in _tab_map:
            new_tab = _tab_map[_norm]
            if new_tab != self._tab:
                self._tab = new_tab
                # Reset activity scroll to newest when (re)entering the tab.
                if new_tab == self.TAB_ACTIVITY:
                    self._activity_scroll = max(0, self._activity_scroll)
            # Caller (_main_loop) will re-render after we return.
            return

        # ── Activity-tab paging shortcuts ──────────────────────────────────────
        # These ONLY fire when the user is viewing the Activity tab, so they
        # don't collide with any menu key.
        if self._tab == self.TAB_ACTIVITY and _norm in ("n", "p", "t", "b", ""):
            total = max(0, len(_notify_buf) + len(_peer_activity_buf))
            page  = max(1, self._activity_page_size or 20)
            if _norm == "n":       # newer entries (scroll forward)
                self._activity_scroll = min(total - page, self._activity_scroll + page)
                if self._activity_scroll < 0: self._activity_scroll = 0
            elif _norm == "p":     # older entries (scroll back)
                self._activity_scroll = max(0, self._activity_scroll - page)
            elif _norm == "t":     # oldest
                self._activity_scroll = 0
            elif _norm == "b":     # newest (bottom)
                self._activity_scroll = max(0, total - page)
            # Empty Enter in Activity tab = just refresh (no-op here)
            return

        # ── Auto-sync on every dashboard interaction ───────────────────────────
        # Whenever the user presses Enter (blank), types a menu number, or
        # returns from any sub-menu, fire a lightweight background chain-sync
        # request to all connected peers.  This ensures the local chain,
        # balances, and mempool are always up-to-date before the user reads
        # any output — without adding any delay to the UI.
        def _bg_sync():
            # Incremental sync: only request blocks above our current tip.
            # Requesting from_idx=1 on every keypress sent the full chain
            # (500 blocks) every time the user pressed Enter — causing large
            # message timeouts and artificial peer disconnects.
            # FIX: request only strictly new blocks (from_idx = my_h + 1)
            # so this is a lightweight delta-sync, not a full-chain replay.
            # max(0,...) guards the fresh-node case where height() == -1.
            # v7.0.0.0: window reduced from 500 → 200 to match server cap.
            try:
                net  = self.node.network
                my_h = self.node.blockchain.height()
                fi   = max(0, my_h + 1)
                with net._lock:
                    peers = [p for p in net.peers.values() if p.connected]
                for p in peers:
                    try:
                        net._sync_request(
                            p, fi, fi + 199,
                            kind="manual-dashboard", force=False)
                    except Exception:
                        pass
            except Exception:
                pass
        threading.Thread(target=_bg_sync, daemon=True).start()

        actions = {
            # Numbers match visual reading order in _print_menu
            "1":  self._start_mining,
            "2":  self._sync_chain,
            "3":  self._stop_mining,
            "4":  self._add_peer,
            "5":  self._pause_mining,
            "6":  self._mining_panel,
            "7":  self._register_miner,
            "8":  self._register_investor,
            "9":  self._send_coins,
            "10": self._give_order,
            "11": self._balance_history,
            "12": self._watch_orders,
            "13": self._unstake,
            "14": self._your_orders,
            "15": self._explore_blockchain,
            "16": self._personal_info,
            "17": self._mempool_viewer,
            "18": self._register_identity,
            "19": self._all_transactions,
            "20": self._resolve_user,
            "21": self._ai_suggestions,
            "22": self._governance_status,
            "23": self._vvm_deploy,
            "24": self._governance_propose,
            "25": self._vvm_inspect,
            "26": self._l2_dashboard,
            "99": self._diagnose_sync,
            "R":  self._rollback_chain,
            "r":  self._rollback_chain,
            "0":  self._exit,
        }
        fn = actions.get(choice)
        if fn:
            try:
                fn()
            except Exception as e:
                print(clr(f"\n  Error: {e}", RED))
        else:
            # Blank Enter (empty choice) is a deliberate "just refresh"
            # action — silently accepted so the user can tap Enter to
            # force a redraw + sync without seeing an error message.
            if choice:
                print(clr("  Invalid choice.", RED))
        print()
        # Pause here so the user can read the command's output before the
        # dashboard redraws.  _exit() sets self._running = False so we skip.
        if self._running:
            try:
                input(clr("  Press Enter to return to dashboard...", DIM))
            except KeyboardInterrupt:
                self._running = False
            except EOFError:
                # AUDIT-FIX (cross-batch, CLI): same reasoning as the main
                # loop — EOF means no interactive stdin is available, not
                # that the operator asked to exit. Skip the pause instead
                # of shutting the node down.
                pass

    # ── Menu handlers ─────────────────────────────────────────────────────────

    def _add_peer(self):
        print(clr("\n  ── Add Peer ──", YELLOW))
        addr = input("  Enter peer IP:port, [ipv6]:port, or user_id: ").strip()
        # Detect whether the input is a network address or a bare user_id.
        #
        # Three valid address forms:
        #   1. "[2401:db8::1]:8338"  — bracketed IPv6 with port  (startswith "[")
        #   2. "1.2.3.4:8338"        — IPv4 with port             (exactly one colon)
        #   3. "2401:db8::1"         — bare IPv6, no port         (more than one colon,
        #                                                           no bracket)
        #
        # Anything else (no colon at all) is treated as a user_id / display name
        # and sent to the identity resolver.
        #
        # The previous condition used `addr.count(":") == 1` as the sole colon
        # guard, which caused bare IPv6 addresses (multiple colons, no bracket)
        # to fall through to the identity resolver and produce "name resolve" errors.
        is_addr = (
            addr.startswith("[")                               # bracketed IPv6:port
            or addr.count(":") == 1                           # IPv4:port
            or (addr.count(":") > 1 and not addr.startswith("["))  # bare IPv6
        )
        if is_addr:
            try:
                ip, port = _parse_peer_addr(addr)
                # [v7.0.0.3 UX] tell user we're working before the blocking call
                print(clr(f"  Connecting to {ip}:{port}...", YELLOW),
                      flush=True)
                ok, msg = self.node.add_peer_manual(ip, port)
            except (ValueError, Exception) as _e:
                print(clr(f"  Invalid address format: {_e}", RED)); return
        else:
            identity = self.node.identity.resolve(addr)
            if not identity:
                print(clr("  Cannot resolve user_id", RED)); return
            maddr = identity["multiaddrs"][0] if identity.get("multiaddrs") else ""
            if not maddr:
                print(clr("  No address found", RED)); return
            parts = maddr.split("/")
            ip   = parts[2] if len(parts) > 2 else "127.0.0.1"
            port = int(parts[4]) if len(parts) > 4 else Config.DEFAULT_PORT
            ok, msg = self.node.add_peer_manual(ip, port)
        print(clr(f"  {msg}", GREEN if ok else RED))

    def _explore_blockchain(self):
        print(clr("\n  ── Blockchain Explorer ──", YELLOW))
        h = self.node.blockchain.height()
        print(f"  Chain height: {bold(str(h))}")
        n_str = input(f"  Show last N blocks [default 5]: ").strip() or "5"
        try: n = int(n_str)
        except ValueError: n = 5
        blocks = self.node.storage.get_last_n_blocks(n)
        for b in blocks:
            print(clr(f"\n  Block #{b.index}", CYAN))
            print(f"    Hash       : {b.block_hash[:32]}...")
            print(f"    Prev       : {b.prev_hash[:32]}...")
            print(f"    Miner      : {b.miner_address}")
            print(f"    Difficulty : {b.difficulty}")
            print(f"    Nonce      : {b.nonce}")
            print(f"    Txs        : {len(b.transactions)}")
            print(f"    Size       : {b.size_human()} ({b.size():,} bytes)")
            print(f"    Finalized  : {b.finalized}")
            ts = datetime.fromtimestamp(b.timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            print(f"    Time       : {ts}")

    def _start_mining(self):
        role = self.node.roles.get_my_role()
        if role and role["role"] == "investor":
            print(clr("  Investors cannot mine.", RED)); return
        ok, msg = self.node.mining.start()
        print(clr(f"  {msg}", GREEN if ok else RED))

    def _stop_mining(self):
        ok, msg = self.node.mining.stop()
        print(clr(f"  {msg}", GREEN if ok else RED))

    def _pause_mining(self):
        if self.node.mining._paused:
            ok, msg = self.node.mining.resume()
        else:
            ok, msg = self.node.mining.pause()
        print(clr(f"  {msg}", YELLOW))

    def _mempool_viewer(self):
        print(clr("\n  ── Mempool ──", YELLOW))
        txs = self.node.blockchain.mempool.all_txs()
        print(f"  Pending transactions: {bold(str(len(txs)))}")
        for tx in txs[:20]:
            print(f"  {tx.tx_id[:16]}... | {tx.sender[:12]} → {tx.receiver[:12]} | "
                  f"{tx.amount:.4f} VSD | fee={tx.compute_fee():.6f}")
        if len(txs) > 20:
            print(f"  ... and {len(txs)-20} more")

    def _register_investor(self):
        print(clr("\n  ── Register as Investor (PoS Validator) ──", YELLOW))
        role = self.node.roles.get_my_role()
        if role and role["role"] == "miner":
            print(clr("  Miners cannot become investors (strict rule).", RED)); return
        # v7.5.x: warn the user about BFT activation threshold so they know
        # whether their stake will actively participate in BFT finality.
        # A registered investor below the threshold still earns the 35%
        # validator reward share once active, but their BFT votes are not
        # counted until the network has at least MIN_VALIDATORS_FOR_BFT
        # registered investors.
        try:
            current_investors = self.node.storage.get_all_by_role("investor")
            n_inv = len(current_investors)
            min_inv = Config.MIN_VALIDATORS_FOR_BFT
            if n_inv + 1 < min_inv:
                print(clr(
                    f"  Heads up: BFT finality requires at least {min_inv} "
                    f"registered investors network-wide.\n"
                    f"  This network currently has {n_inv} (your registration "
                    f"would make it {n_inv + 1}).\n"
                    f"  Until the threshold is met, the chain finalizes via "
                    f"PoW depth instead of BFT, but you\n"
                    f"  will still receive validator-share rewards once your "
                    f"REGISTER tx is mined.",
                    DIM))
        except Exception:
            pass
        bal = self.node.storage.get_balance(self.node.wallet.address)
        # BUG-FIX: MIN_INVESTOR_STAKE is in satoshi; convert to VSD for display
        # AND for comparison against user-entered float VSD values.  Without
        # this conversion the prompt showed "Minimum stake: 20000000000 VSD"
        # (the raw satoshi integer) and the gate `stake < MIN_INVESTOR_STAKE`
        # rejected every legitimate VSD-denominated entry.
        min_investor_vsd = from_satoshi(Config.MIN_INVESTOR_STAKE)
        # Top-up flag — an existing investor may add any positive amount.
        _is_top_up = bool(role and role.get("role") == "investor")
        print(f"  Your balance: {bal:.8f} VSD")
        if _is_top_up:
            print(f"  Current stake: {role.get('stake', 0.0):.8f} VSD "
                  f"(top-up — any positive amount allowed)")
        else:
            print(f"  Minimum stake: {min_investor_vsd:.8f} VSD")
            # ── Sub-minimum balance early-out (helpful before prompting) ──
            if bal < min_investor_vsd:
                print(clr(
                    f"  You need at least {min_investor_vsd:.8f} VSD to register as investor.",
                    RED))
                return
        # [v7.0.0.3 UX] friendly retry on bad numeric input + restored call
        for _try in range(3):
            s = input("  Stake amount (or blank to cancel): ").strip()
            if not s:
                print("  Cancelled."); return
            try:
                stake = float(s)
                break
            except ValueError:
                print(clr("  Not a valid number, please try again.", RED))
        else:
            print(clr("  Too many invalid entries — cancelled.", RED)); return
        # BUG-FIX: compare VSD float against VSD float (was comparing against
        # raw satoshi int — silently rejected every legitimate stake).
        # Top-ups are not subject to the minimum.
        if (not _is_top_up) and stake < min_investor_vsd:
            print(clr(f"  Minimum stake is {min_investor_vsd:.8f} VSD.",
                      RED)); return
        if stake <= 0:
            print(clr("  Stake must be positive.", RED)); return
        if stake > bal:
            print(clr(f"  Insufficient balance ({bal:.8f} VSD).", RED)); return
        ok, msg = self.node.roles.register_investor(stake)
        print(clr(f"  {msg}", GREEN if ok else RED))

    def _register_miner(self):
        print(clr("\n  ── Register as Miner ──", YELLOW))
        role = self.node.roles.get_my_role()
        if role and role["role"] == "investor":
            print(clr("  Investors cannot become miners (strict rule).", RED)); return
        bal = self.node.storage.get_balance(self.node.wallet.address)
        print(f"  Your balance: {bal:.8f} VSD")
        print(f"  Minimum stake: {from_satoshi(Config.MIN_MINER_STAKE):.8f} VSD")
        s = input("  Stake amount: ").strip()
        try: stake = float(s)
        except ValueError: print(clr("  Invalid amount.", RED)); return
        ok, msg = self.node.roles.register_miner(stake)
        if ok:
            print(clr(f"  {msg}", GREEN))
            auto = input("  Start auto mining now? (y/n): ").strip().lower()
            if auto == 'y':
                self.node.mining.start()
                print(clr("  Mining started.", GREEN))
        else:
            print(clr(f"  {msg}", RED))

    def _all_transactions(self):
        print(clr("\n  ── All Transactions (Your Address) ──", YELLOW))
        txs = self.node.storage.get_address_txs(self.node.wallet.address)
        if not txs:
            print("  No transactions found.")
            return
        for d in txs[:30]:
            direction = "OUT" if d["sender"] == self.node.wallet.address else "IN"
            col = RED if direction == "OUT" else GREEN
            ts  = datetime.fromtimestamp(d["timestamp"], tz=timezone.utc).strftime('%m-%d %H:%M')
            archived_tag = clr(" [ARCH]", DIM) if d.get("_archived") else ""
            print(f"  [{clr(direction, col)}] {ts} | {d['tx_id'][:16]}...{archived_tag} | "
                  f"{d['amount']:.4f} VSD | memo: {d.get('memo','')[:20]}")
        if len(txs) > 30:
            print(f"  ... {len(txs)-30} more")
        # v7.5.x: hint about pruning when the rolling-window pruner has run.
        try:
            pruned_until = self.node.storage.get_meta("rolling_pruned_until")
            if pruned_until:
                _puv = int(pruned_until)
                if _puv > 0:
                    arc_thresh = Config.ROLLING_PRUNE_ARCHIVE_THRESHOLD
                    print(clr(
                        f"\n  Note: this node has pruned full transaction "
                        f"data for blocks ≤ {_puv}.\n"
                        f"  Transactions ≥ {arc_thresh:.2f} VSD and all VVM/system "
                        f"txs in those blocks are still shown\n"
                        f"  (tagged [ARCH]).  Smaller transfers below that "
                        f"threshold are no longer\n"
                        f"  individually retained on this node — your live "
                        f"BALANCE remains exact.",
                        DIM))
        except Exception:
            pass

    def _balance_history(self):
        my_addr = self.node.wallet.address
        storage = self.node.storage

        # ── helpers ──────────────────────────────────────────────────────────
        def _uid(addr: str) -> str:
            """Return user_id#short if known, else first16...last4 of address."""
            if not addr or addr == "COINBASE":
                return "Network"
            try:
                uid = storage.get_uid_by_wallet(addr)
                if uid:
                    return uid
            except Exception:
                pass
            return f"{addr[:16]}...{addr[-4:]}"

        TX_TYPE_NAMES = {
            0: "Transfer",
            1: "Deploy",
            2: "Contract Call",
            3: "Stake",
            4: "Unstake",
        }

        # ── fetch & page ─────────────────────────────────────────────────────
        all_txs = storage.get_address_txs(my_addr)

        # Map string tx_type values (used by VVM txs) to integer codes
        _TX_TYPE_STR_MAP = {
            "transfer": 0,
            "deploy":   1,
            "call":     2,
        }

        def _parse_tx_type(raw) -> int:
            """Safely convert tx_type to int regardless of whether it is stored
            as an integer (0-4) or as a VVM string ('transfer', 'deploy', 'call')."""
            if raw is None:
                return 0
            if isinstance(raw, int):
                return raw
            s = str(raw).strip().lower()
            return _TX_TYPE_STR_MAP.get(s, 0)

        # ── merge same-block tx+reward pairs ─────────────────────────────────
        # When the same block both delivers an incoming transaction to my_addr
        # AND a block reward (COINBASE) to my_addr, collapse them into a single
        # synthetic entry so the user sees one "All" row instead of two.
        # All other entries (reward-only, tx-only, outgoing) pass through unchanged.
        def _merge_block_pairs(txs):
            """Return a new list where any block_idx that has exactly one COINBASE
            entry AND at least one non-COINBASE incoming entry for my_addr are
            merged into a single combined record.  Everything else is kept as-is
            and in its original order."""
            # Group by block_idx; None/pending entries are never merged.
            from collections import OrderedDict
            by_block = OrderedDict()
            pending  = []
            for d in txs:
                blk = d.get("block_idx")
                if blk is None:
                    pending.append(("solo", d))
                    continue
                by_block.setdefault(blk, []).append(d)

            merged = []
            for blk, entries in by_block.items():
                # Separate coinbase from non-coinbase entries for this block
                coinbase_entries  = [e for e in entries if (e.get("sender") or "") == "COINBASE"]
                regular_entries   = [e for e in entries if (e.get("sender") or "") != "COINBASE"]

                # Incoming regular entries that credit my_addr
                incoming_regular  = [e for e in regular_entries
                                     if (e.get("receiver") or "") == my_addr
                                     and (e.get("sender")   or "") != my_addr]

                # Condition: exactly one reward AND at least one incoming tx in same block
                if len(coinbase_entries) == 1 and len(incoming_regular) >= 1:
                    cb  = coinbase_entries[0]
                    inc = incoming_regular[0]   # representative tx (first / only)

                    # Build a synthetic merged entry tagged with a special marker
                    combined = dict(inc)        # base: the incoming tx record
                    combined["_merged_coinbase"] = cb   # attach the reward record
                    merged.append(("merged", combined))

                    # Any additional same-block incoming txs (rare) → solo rows
                    for extra in incoming_regular[1:]:
                        merged.append(("solo", extra))
                    # Outgoing txs in the same block are always solo rows
                    for out_tx in regular_entries:
                        if out_tx not in incoming_regular:
                            merged.append(("solo", out_tx))
                else:
                    # Normal path: no merging, preserve order within block
                    for e in entries:
                        merged.append(("solo", e))

            # Append pending (unconfirmed) entries at the end
            merged.extend(pending)
            return merged   # list of ("solo"|"merged", dict)

        display_rows = _merge_block_pairs(all_txs)
        total   = len(display_rows)
        page_sz = 15
        page    = 0

        while True:
            start = page * page_sz
            end   = start + page_sz
            page_rows = display_rows[start:end]   # already sorted newest-first

            # Row numbers count DOWN from `total` so the newest entry is row 1
            row_start = total - start

            print(clr(f"\n  ── Balance History  (showing {start+1}–{min(end,total)} of {total}) ──", YELLOW))
            print(clr(
                f"  {'#':<4} {'Date & Time':<17} {'Cause':<14} {'Block':<9} "
                f"{'Change (VSD)':<18} {'Counterparty':<30} {'Memo'}", DIM))
            print(clr("  " + "─" * 110, DIM))

            for idx, (row_kind, d) in enumerate(page_rows):
                i = row_start - idx
                try:
                    # ── merged row: same block had both a tx-credit AND a reward ──
                    if row_kind == "merged":
                        cb = d["_merged_coinbase"]

                        # ── incoming tx side ──────────────────────────────────
                        sender_tx  = d.get("sender",   "") or ""
                        receiver_tx= d.get("receiver", "") or ""
                        amount_tx  = float(d.get("amount", 0) or 0)
                        fee_raw_tx = float(d.get("fee",    0) or 0)
                        memo_tx    = (d.get("memo", "") or "").strip()
                        tx_type    = _parse_tx_type(d.get("tx_type"))
                        blk_idx    = d.get("block_idx")
                        ts_raw     = d.get("timestamp", 0) or 0
                        ts_str     = (datetime.fromtimestamp(ts_raw, tz=timezone.utc)
                                      .strftime('%Y-%m-%d %H:%M') if ts_raw else "unknown time")
                        blk_str    = f"#{blk_idx}" if blk_idx is not None else "pending"

                        fee_deducted_tx = round(fee_raw_tx, 8) if fee_raw_tx else round(amount_tx * Config.TX_FEE_RATE, 8)
                        net_tx          = round(amount_tx - fee_deducted_tx, 8)
                        fee_note_tx     = f"(net of {fee_deducted_tx:.8f} fee)" if fee_deducted_tx else ""
                        tx_change_str   = f"+{net_tx:.8f}" + (f" {fee_note_tx}" if fee_note_tx else "")
                        tx_counterpart  = f"← {_uid(sender_tx)}"

                        # ── reward side ───────────────────────────────────────
                        amount_cb      = float(cb.get("amount", 0) or 0)
                        cb_change_str  = f"+{amount_cb:.8f}"
                        cb_counterpart = "Network (Block Reward)"

                        # ── combined fields ───────────────────────────────────
                        cause       = "All"
                        cause_clr   = GREEN
                        # Comma-separated change values: tx amount first, then reward
                        sign_str    = clr(f"{tx_change_str},{cb_change_str}", GREEN)
                        # Comma-separated counterparties only when both sides present
                        counterpart = f"{tx_counterpart},{cb_counterpart}"

                        # Memo: use the tx memo (hide coinbase tag from reward)
                        if memo_tx.startswith("coinbase:"):
                            memo_disp = ""
                        elif memo_tx.startswith("ORDER:"):
                            memo_disp = f"[Order] {memo_tx[6:30]}{'…' if len(memo_tx) > 36 else ''}"
                        else:
                            memo_disp = memo_tx[:40] + ("…" if len(memo_tx) > 40 else "")

                        cause_disp = clr(f"{cause:<14}", cause_clr)
                        print(f"  {i:<4} {ts_str:<17} {cause_disp} {blk_str:<9} "
                              f"{sign_str:<27} {counterpart:<30} {memo_disp}")

                    # ── solo row: standard single-entry display (unchanged) ───
                    else:
                        ts_raw = d.get("timestamp", 0) or 0
                        ts_str = (datetime.fromtimestamp(ts_raw, tz=timezone.utc)
                                  .strftime('%Y-%m-%d %H:%M') if ts_raw else "unknown time")

                        sender   = d.get("sender",   "") or ""
                        receiver = d.get("receiver", "") or ""
                        amount   = float(d.get("amount", 0) or 0)
                        fee_raw  = float(d.get("fee",    0) or 0)
                        memo     = (d.get("memo", "") or "").strip()
                        blk_idx  = d.get("block_idx")
                        tx_type  = _parse_tx_type(d.get("tx_type"))
                        blk_str  = f"#{blk_idx}" if blk_idx is not None else "pending"

                        # ── classify cause & direction ────────────────────────
                        if sender == "COINBASE":
                            cause       = "Rewarded"
                            change      = amount
                            counterpart = "Network (Block Reward)"
                            cause_clr   = YELLOW
                            sign_str    = clr(f"+{change:.8f}", GREEN)
                        elif sender == my_addr:
                            # outgoing
                            total_cost = round(amount + fee_raw, 8)
                            change     = -total_cost
                            if memo.startswith("ORDER:"):
                                cause = "Order Sent"
                            elif tx_type == 3:
                                cause = "Staked"
                            elif tx_type == 4:
                                cause = "Unstaked"
                            elif tx_type == 1:
                                cause = "Deploy"
                            elif tx_type == 2:
                                cause = "Contract"
                            else:
                                cause = "Sent"
                            cause_clr   = RED
                            counterpart = f"→ {_uid(receiver)}"
                            fee_note    = f" (fee {fee_raw:.8f})" if fee_raw else ""
                            sign_str    = clr(f"-{total_cost:.8f}{fee_note}", RED)
                        else:
                            # incoming
                            fee_deducted = round(fee_raw, 8) if fee_raw else round(amount * Config.TX_FEE_RATE, 8)
                            net          = round(amount - fee_deducted, 8)
                            change       = net
                            if memo.startswith("ORDER:"):
                                cause = "Order Recv"
                            elif tx_type == 3:
                                cause = "Stake In"
                            elif tx_type == 4:
                                cause = "Unstake In"
                            elif tx_type == 1:
                                cause = "Deploy In"
                            elif tx_type == 2:
                                cause = "Contract In"
                            else:
                                cause = "Received"
                            cause_clr   = GREEN
                            counterpart = f"← {_uid(sender)}"
                            fee_note    = f" (net of {fee_deducted:.8f} fee)" if fee_deducted else ""
                            sign_str    = clr(f"+{net:.8f}{fee_note}", GREEN)

                        # ── memo display (truncate if long, hide coinbase tag) ─
                        if memo.startswith("coinbase:"):
                            memo_disp = ""
                        elif memo.startswith("ORDER:"):
                            memo_disp = f"[Order] {memo[6:30]}{'…' if len(memo) > 36 else ''}"
                        else:
                            memo_disp = memo[:40] + ("…" if len(memo) > 40 else "")

                        cause_disp = clr(f"{cause:<14}", cause_clr)
                        print(f"  {i:<4} {ts_str:<17} {cause_disp} {blk_str:<9} "
                              f"{sign_str:<27} {counterpart:<30} {memo_disp}")

                except Exception as _err:
                    print(clr(f"  [row {i} parse error: {_err}]", RED))

            # ── summary line ─────────────────────────────────────────────────
            cur = storage.get_balance(my_addr)
            print(clr("  " + "─" * 110, DIM))
            print(f"\n  Current Balance : {bold(f'{cur:.8f} VSD')}")
            if total > page_sz:
                print(clr(f"  Page {page+1}/{(total+page_sz-1)//page_sz}  "
                           f"| total {total} entries", DIM))

            # ── paging controls ───────────────────────────────────────────────
            pages_total = (total + page_sz - 1) // page_sz
            if pages_total <= 1:
                break
            nav_parts = []
            if page > 0:              nav_parts.append("[P] Prev page")
            if page < pages_total-1:  nav_parts.append("[N] Next page")
            nav_parts.append("[Q] Back")
            choice = input(f"\n  {' | '.join(nav_parts)}: ").strip().lower()
            if choice == 'n' and page < pages_total - 1:
                page += 1
            elif choice == 'p' and page > 0:
                page -= 1
            else:
                break

    def _send_coins(self):
        print(clr("\n  ── Send Coins ──", YELLOW))
        to   = input("  To (user_id or VSD address): ").strip()
        amt  = input("  Amount (VSD): ").strip()
        memo = input("  Memo (optional): ").strip()
        try: amount = float(amt)
        except ValueError: print(clr("  Invalid amount.", RED)); return
        if amount <= 0:
            print(clr("  Amount must be positive.", RED)); return
        fee = round(amount * Config.TX_FEE_RATE, 8)
        print(f"  Transaction fee (sender-side): {fee:.8f} VSD")
        print(f"  Total deducted from you     : {amount + fee:.8f} VSD")
        print(f"  Recipient receives           : {amount:.8f} VSD")
        confirm = input("  Confirm? (y/n): ").strip().lower()
        if confirm != 'y':
            print("  Cancelled."); return
        ok, msg = self.node.send_transaction(to, amount, memo)
        print(clr(f"  {msg}", GREEN if ok else RED))

    def _give_order(self):
        print(clr("\n  ── Give Order ──", YELLOW))
        print(clr("  Leave 'To' blank to broadcast as an open market order.", DIM))
        to    = input("  To (user_id or VSD address, blank=broadcast): ").strip()
        amt   = input("  Amount: ").strip()
        order = input("  Order details/memo: ").strip()
        try: amount = float(amt)
        except ValueError: print(clr("  Invalid amount.", RED)); return
        if not to:
            # Broadcast order — any peer can accept
            fee = round(amount * Config.TX_FEE_RATE, 8)
            print(f"  Broadcast order fee: {fee:.8f} VSD (paid by you)")
            confirm = input("  Confirm broadcast order? (y/n): ").strip().lower()
            if confirm != 'y':
                print("  Cancelled."); return
        ok, msg = self.node.send_transaction(to, amount, f"ORDER:{order}")
        if ok and not to:
            print(clr(f"  Broadcast order posted. Any peer can accept it via 'Watch Orders'.", GREEN))
        print(clr(f"  {msg}", GREEN if ok else RED))

    def _watch_orders(self):
        print(clr("\n  ── Watch Orders (Incoming + Broadcast) ──", YELLOW))
        my_addr = self.node.wallet.address

        # Targeted orders sent directly to this address
        txs = self.node.storage.get_address_txs(my_addr)
        targeted = [d for d in txs if d.get("memo","").startswith("ORDER:") and
                    d["receiver"] == my_addr]

        # Broadcast orders visible to all (receiver == VSD_GLOBAL_MARKET)
        # Fetched from the DB via a helper that queries the receiver field
        broadcast = self.node.storage.get_broadcast_orders()

        orders = targeted + [d for d in broadcast if d not in targeted]
        if not orders:
            print("  No incoming orders."); return
        for d in orders[:20]:
            ts = datetime.fromtimestamp(d["timestamp"], tz=timezone.utc).strftime('%m-%d %H:%M')
            memo = d["memo"][6:]
            tag  = clr("[BROADCAST]", YELLOW) if d["receiver"] == VSD_GLOBAL_MARKET else clr("[DIRECT]", GREEN)
            print(f"  {tag} [{ts}] From: {d['sender'][:16]}... | {d['amount']:.4f} VSD | {memo}")

    def _your_orders(self):
        print(clr("\n  ── Your Orders (Outgoing) ──", YELLOW))
        txs = self.node.storage.get_address_txs(self.node.wallet.address)
        orders = [d for d in txs if d.get("memo","").startswith("ORDER:") and
                  d["sender"] == self.node.wallet.address]
        if not orders:
            print("  No outgoing orders."); return
        for d in orders[:20]:
            ts = datetime.fromtimestamp(d["timestamp"], tz=timezone.utc).strftime('%m-%d %H:%M')
            memo = d["memo"][6:]
            if d["receiver"] == VSD_GLOBAL_MARKET:
                dest = clr("[BROADCAST]", YELLOW)
            else:
                dest = f"To: {d['receiver'][:16]}..."
            print(f"  [{ts}] {dest} | {d['amount']:.4f} VSD | {memo}")

    def _personal_info(self):
        print(clr("\n  ── Personal Info ──", YELLOW))
        n = self.node
        w = n.wallet
        role = n.roles.get_my_role()
        print(f"  User ID      : {self.user_id}")
        print(f"  Wallet Addr  : {w.address}")
        print(f"  Public Key   : {w.pub_hex[:40]}...")
        print(f"  Node ID      : {n.node_id[:32]}...")
        print(f"  Balance      : {n.storage.get_balance(w.address):.8f} VSD")
        print(f"  Role         : {(role['role'] if role else 'none').upper()}")
        print(f"  Stake        : {(role['stake'] if role else 0.0):.4f} VSD")
        print(f"  Honesty Score: {(role['score'] if role else 1.0):.3f}")
        print(f"  Data Dir     : {Config.DATA_DIR}")
        print(f"  Crypto Lib   : cryptography/OpenSSL; optional libsecp256k1 accelerator")
        print(f"  Node Script  : {SecurityGate.hash_self()[:32]}...")

    def _register_identity(self):
        print(clr("\n  ── Register Identity / Domain ──", YELLOW))
        uid = input("  Choose username/domain (e.g. alice, alice.nexa): ").strip()
        ok, msg = self.node.identity.register(uid, "127.0.0.1", self.node.port)
        print(clr(f"  {msg}", GREEN if ok else RED))

    def _resolve_user(self):
        print(clr("\n  ── Resolve User ID ──", YELLOW))
        uid = input("  Enter user_id (e.g. alice#1a2b3c4d5e or alice.nexa): ").strip()
        if not uid:
            return

        # ── Format validation — fast-fail before hitting the network ──────────
        _is_account = bool(re.match(r'^[a-zA-Z0-9_]{3,32}#[0-9a-f]{10}$', uid))
        _is_domain  = bool(re.match(r'^[a-zA-Z0-9_.\-]{3,32}$', uid))
        if not (_is_account or _is_domain):
            print(clr(
                "  Invalid format.\n"
                "  Account ID : USERNAME#<10 hex chars>  e.g. alice#1a2b3c4d5e\n"
                "  Domain     : alphanumeric 3–32 chars  e.g. alice.nexa",
                RED))
            return

        print(clr("  Querying local DB then network peers...", DIM))

        # Check local DB first — tag the source so user knows where result came from
        local    = self.node.storage.resolve_identity(uid)
        source   = "local"
        identity = local
        if not identity:
            identity = self.node.identity.resolve(uid)
            source   = "network"

        if not identity:
            print(clr("  User ID not found locally or on the network.", RED))
            return

        # ── Live online status ────────────────────────────────────────────────
        pid = identity.get("peer_id", "")
        with self.node.network._lock:
            live_peer = self.node.network.peers.get(pid)
        online = live_peer is not None and getattr(live_peer, "connected", False)

        # ── Reputation from peers table ───────────────────────────────────────
        rep_str = "—"
        if pid:
            try:
                row = self.node.storage._conn().execute(
                    "SELECT reputation, fail_count FROM peers WHERE peer_id=?",
                    (pid,)).fetchone()
                if row:
                    rep_str = (f"{row['reputation']:.2f}  "
                               f"(fail_count={row['fail_count']})")
            except Exception:
                pass

        # ── Last-seen: UTC + human delta ──────────────────────────────────────
        raw_ts = identity.get("last_seen", 0)
        if raw_ts:
            ago = int(time.time()) - int(raw_ts)
            if ago < 60:
                ago_str = f"{ago}s ago"
            elif ago < 3600:
                ago_str = f"{ago // 60}m ago"
            elif ago < 86400:
                ago_str = f"{ago // 3600}h ago"
            else:
                ago_str = f"{ago // 86400}d ago"
            ts_fmt = (datetime.fromtimestamp(int(raw_ts), tz=timezone.utc)
                      .strftime("%Y-%m-%d %H:%M UTC"))
            last_seen_str = f"{ts_fmt}  ({ago_str})"
        else:
            last_seen_str = "unknown"

        # ── Multiaddrs normalisation (may be JSON string or list) ─────────────
        maddrs = identity.get("multiaddrs") or []
        if isinstance(maddrs, str):
            try:
                maddrs = json.loads(maddrs)
            except Exception:
                maddrs = [maddrs]

        # ── Pretty print ──────────────────────────────────────────────────────
        _w  = self._term_width()
        sep = clr("  " + "─" * max(20, _w - 4), DIM)
        print(sep)
        print(f"  {clr('user_id', DIM):<28} {identity.get('user_id', uid)}")
        print(f"  {clr('source', DIM):<28} {clr(source.upper(), CYAN)}")
        online_tag = clr("● ONLINE", GREEN) if online else clr("○ OFFLINE", DIM)
        print(f"  {clr('status', DIM):<28} {online_tag}")
        print(f"  {clr('wallet_addr', DIM):<28} {clr(identity.get('wallet_addr', '—'), YELLOW)}")
        pid_disp = f"{pid[:36]}{'...' if len(pid) > 36 else ''}" if pid else "—"
        print(f"  {clr('peer_id', DIM):<28} {pid_disp}")
        print(f"  {clr('reputation', DIM):<28} {rep_str}")
        print(f"  {clr('last_seen', DIM):<28} {last_seen_str}")
        if maddrs:
            print(f"  {clr('multiaddrs', DIM)}")
            for ma in maddrs:
                print(f"    {clr('↳', DIM)} {ma}")
        else:
            print(f"  {clr('multiaddrs', DIM):<28} —")
        print(sep)

    def _mining_panel(self):
        print(clr("\n  ── Mining Panel ──", YELLOW))
        s = self.node.mining.status()

        # ── Status ────────────────────────────────────────────────────────────
        print(f"  Status     : {clr('RUNNING', GREEN) if s['running'] else clr('STOPPED', RED)}")
        print(f"  Paused     : {s['paused']}")
        print(f"  Hashrate   : {bold(s['hashrate'])}")
        print(f"  Blocks     : {s['blocks_found']}")
        print(f"  Difficulty : {s['difficulty']}")
        print(f"  Height     : {s['chain_height']}")

        # ── v7.6.0 Hashrate Optimization (governor) ───────────────────────────
        # Show the four governor fields so the operator can see what the
        # local cap is, what the network "should" be running at, and how
        # many peers are reporting their actual hashrate.
        actual_hr   = s.get('actual_hashrate',            '—')
        opt_hr      = s.get('optimized_hashrate',         '—')
        req_hr      = s.get('required_network_hashrate',  '—')
        peer_n      = s.get('live_peer_hr_reports',       0)
        print()
        print(clr("  ── Hashrate Optimization ──", CYAN))
        print(f"  Actual H/s    : {bold(actual_hr)}      "
              f"(raw hardware speed)")
        print(f"  Optimized H/s : {bold(opt_hr)}      "
              f"(governor cap; 'unlimited' if solo / disabled)")
        print(f"  Required H/s  : {bold(req_hr)}      "
              f"(network target at current difficulty)")
        if peer_n == 0:
            # When solo and our hardware can't keep up with the required
            # rate, the cap is clamped to actual — show that explicitly so
            # the operator understands why "Optimized == Actual" instead of
            # "Optimized == Required".
            try:
                actual_v = float(actual_hr.split()[0])
                req_v    = float(req_hr.split()[0])
                if actual_v > 0 and actual_v < req_v:
                    print(clr(
                        f"  Peer reports  : 0  — solo mining; hardware below "
                        f"network target, cap clamped to actual",
                        DIM))
                else:
                    print(clr(
                        f"  Peer reports  : 0  — solo mining, governor "
                        f"inactive (cap = required H/s)", DIM))
            except (ValueError, IndexError, AttributeError):
                print(clr(
                    f"  Peer reports  : 0  — solo mining, governor inactive "
                    f"(cap = required H/s)", DIM))
        else:
            print(f"  Peer reports  : {bold(str(peer_n))} miner(s) reporting "
                  f"actual H/s")

        # ── Parallel mining backend ───────────────────────────────────────────
        print()
        backend = s.get('backend', 'CPU')
        if backend == 'CUDA':
            backend_str = clr(f"CUDA  (GPU device {s['gpu_device']}, "
                               f"batch {s['gpu_batch']:,})", GREEN)
        elif backend == 'OPENCL':
            backend_str = clr(f"OpenCL  (GPU device {s['gpu_device']}, "
                               f"batch {s['gpu_batch']:,})", CYAN)
        else:
            backend_str = clr(f"CPU  ({s['cpu_threads']} threads × all cores)", YELLOW)
        print(f"  Backend    : {backend_str}")

        # GPU availability hint
        cuda_ok = s.get('cuda_avail', False)
        ocl_ok  = s.get('opencl_avail', False)
        if not s.get('gpu_enabled'):
            hint = "off"
            if cuda_ok or ocl_ok:
                avail = "/".join(filter(None, [
                    "CUDA" if cuda_ok else "", "OpenCL" if ocl_ok else ""
                ]))
                hint = clr(
                    f"available ({avail}) — set VISOLD_MINING_GPU=1 to enable",
                    DIM)
            else:
                hint = clr(
                    "not installed — pip install pycuda  OR  pip install pyopencl",
                    DIM)
            print(f"  GPU        : {hint}")
        else:
            avail = "/".join(filter(None, [
                "CUDA" if cuda_ok else "", "OpenCL" if ocl_ok else ""
            ])) or "none detected"
            print(f"  GPU libs   : {avail}")

        # ── Candidate block ───────────────────────────────────────────────────
        if s['running'] and self.node.mining.current_candidate:
            b = self.node.mining.current_candidate
            print(f"\n  Candidate Block #{b.index}")
            print(f"    Txs : {len(b.transactions)}")
            print(f"    Diff: {b.difficulty}")

        print(f"\n  Reward     : "
              f"{self.node.blockchain.compute_reward(s['chain_height']):.8f} VSD/block")
        print(clr("\n  Controls: [1] Start  [3] Stop  [5] Pause/Resume", DIM))
        print(clr(  "  GPU env : VISOLD_MINING_GPU=1  VISOLD_MINING_THREADS=N"
                    "  VISOLD_GPU_DEVICE=N", DIM))

    def _sync_chain(self):
        # [v7.0.0.3 UX] live progress display instead of silent fire-and-forget
        n = self.node
        peer_n = len(n.network.active_peer_count())             if callable(getattr(n.network, "active_peer_count", None)) else 0
        if peer_n == 0:
            print(clr("\n  No connected peers — add a peer first (option 4).", RED))
            return
        start_h = n.blockchain.height()
        print(clr(f"\n  ── Chain Sync ──", YELLOW))
        print(f"  Connected peers : {bold(str(peer_n))}")
        print(f"  Local height    : {bold(str(start_h))}")
        print(clr("  Requesting chain from peers...", YELLOW))
        try:
            n.network.sync_chain()
        except Exception as _e:
            print(clr(f"  Sync request failed: {_e}", RED))
            return
        # Poll for up to ~12 seconds, showing height advancement live.
        spinner = "|/-\\"
        last_h  = start_h
        stalled = 0
        for i in range(48):           # 48 * 0.25s = 12s
            time.sleep(0.25)
            cur_h = n.blockchain.height()
            delta = cur_h - start_h
            sym   = spinner[i % 4]
            msg   = (f"  {sym} height {cur_h}"
                     f"  (+{delta} blocks)" if delta else
                     f"  {sym} waiting for peer response...")
            # Carriage return + clear-to-EOL for inline ticker (TTY only)
            if _ANSI_OK:
                print(f"\r{msg}\033[K", end="", flush=True)
            else:
                print(msg, flush=True)
            if cur_h > last_h:
                last_h, stalled = cur_h, 0
            else:
                stalled += 1
                # If we got SOME progress and have been stalled 2s, assume done
                if delta > 0 and stalled >= 8:
                    break
        print()  # newline after ticker
        end_h = n.blockchain.height()
        if end_h > start_h:
            print(clr(f"  Sync complete: {start_h} → {end_h} "
                      f"(+{end_h - start_h} blocks)", GREEN))
        else:
            # v7.0.1.2 — clearer UX.  The old message implied peers might
            # be at height 0, which was misleading when THIS node was the
            # one at height 0 (ghost-peer scenario — inbound side never
            # requested sync).  We now distinguish the two common cases.
            if start_h == 0:
                print(clr("  No new blocks received. If a connected peer has "
                          "a taller chain, they may not have responded yet — "
                          "wait a few seconds and try again. If the problem "
                          "persists, disconnect and reconnect the peer to "
                          "re-trigger the two-way auto-sync.", YELLOW))
            else:
                print(clr("  No new blocks received. Peers appear to be on "
                          "the same height as this node, or sync is still "
                          "running in the background (check menu again in "
                          "a few seconds).", YELLOW))

    # ── DIAGNOSTIC: step-by-step live trace of a single sync attempt ─────────
    # Menu option 99 — prints every stage of a forced MSG_GET_CHAIN round-trip
    # so the exact failure point is visible without grepping log files.
    # Safe to run at any time — installs a temporary interceptor that is
    # always removed in the finally block.
    def _diagnose_sync(self):
        import threading as _th
        n = self.node
        print(clr("\n  ── Diagnose Sync (live trace) ──", YELLOW))
        # ── 1. Pick a peer ────────────────────────────────────────────────────
        with n.network._lock:
            peers = [p for p in n.network.peers.values() if p.connected]
        if not peers:
            print(clr("  [FAIL] No connected peers.", RED))
            print("  → Add a peer first (menu 4), then re-run diagnose.")
            return
        peer = peers[0]
        print(f"  Peer          : {peer.peer_id[:12]}…  "
              f"{_format_peer_addr(peer.ip, peer.port)}")
        tlvl = getattr(peer, "trust_level", "?")
        print(f"  Trust level   : {tlvl}  "
              f"(LOW=0 HIGH=1; LOW triggers Full Audit Mode)")
        try:
            bscore = n.storage.get_ban_score(peer.peer_id)
            print(f"  Ban score     : {bscore}")
        except Exception:
            pass
        start_h = n.blockchain.height()
        print(f"  Local height  : {start_h}")

        # ── 2. Local genesis hash (for comparison against peer's block 0) ────
        local_gen = n.storage.get_block(0)
        if local_gen is None:
            print(clr("  [FAIL] No local genesis block — chain DB is empty.",
                      RED))
            return
        print(f"  Local genesis : {local_gen.block_hash}")

        # ── 3. Install one-shot interceptor on _handle_message ───────────────
        captured = {"msg": None}
        got_response = _th.Event()
        orig_handle = n.network._handle_message

        def _intercept(p, msg):
            try:
                mt = msg.get("type", "")
                if (mt == MSG_CHAIN
                        and p.peer_id == peer.peer_id
                        and captured["msg"] is None):
                    captured["msg"] = msg
                    got_response.set()
                    # Swallow this one message so we can inspect without the
                    # regular handler also calling accept_chain in parallel.
                    return
            except Exception:
                pass
            return orig_handle(p, msg)

        n.network._handle_message = _intercept
        try:
            # ── 4. Send MSG_GET_CHAIN directly ────────────────────────────────
            req = {"type": MSG_GET_CHAIN, "from_idx": 0, "to_idx": 199}
            print(clr("  → Sending MSG_GET_CHAIN(from=0, to=199)…", CYAN))
            ok_send = peer.send(req)
            print(f"    send() returned: {ok_send}  "
                  f"(peer.connected={peer.connected})")
            if not ok_send:
                print(clr("  [FAIL] send() returned False — socket is dead.",
                          RED))
                return

            # ── 5. Wait for the reply ────────────────────────────────────────
            print(clr("  ⏳ Waiting up to 20 s for MSG_CHAIN response…",
                      YELLOW))
            if not got_response.wait(20.0):
                print(clr("  [FAIL] No MSG_CHAIN received within 20 s.", RED))
                print("  Possible causes:")
                print("    • Peer rate-limited our GET_CHAIN "
                      "(limit is 5 per 10 s).")
                print("    • Peer's rate-limit ban-scored us to disconnect.")
                print("    • Peer's TLS / writer thread is stalled.")
                print("    • Peer is Full Audit Mode and throttling.")
                print("    • NAT / CGNAT dropped the one-way flow.")
                print(f"    Check peer connected={peer.connected} "
                      f"trust={tlvl}.")
                return
            msg = captured["msg"]

            # ── 6. Inspect the response ──────────────────────────────────────
            blocks_data = msg.get("blocks", []) or []
            srv_h       = msg.get("server_height", -1)
            print(clr(f"  ✓ Received MSG_CHAIN: {len(blocks_data)} block(s), "
                      f"server_height={srv_h}", GREEN))
            if not blocks_data:
                print(clr("  [FAIL] Peer sent an EMPTY block list.", RED))
                print("  → Peer has no blocks at or above from_idx=0, "
                      "which is impossible unless peer is also at height<0.")
                print(f"  → Peer's reported server_height = {srv_h}")
                return
            b0 = blocks_data[0]
            bL = blocks_data[-1]
            print(f"    first block: index={b0.get('index')}  "
                  f"hash={b0.get('block_hash','')[:32]}…")
            print(f"    last  block: index={bL.get('index')}  "
                  f"hash={bL.get('block_hash','')[:32]}…")

            # ── 7. Genesis comparison ────────────────────────────────────────
            peer_gen_hash = b0.get('block_hash', '')
            if b0.get('index') != 0:
                print(clr(f"  [NOTE] Peer did not include block 0 in response "
                          f"(first index = {b0.get('index')}). "
                          f"Skipping genesis comparison.", YELLOW))
            elif peer_gen_hash == local_gen.block_hash:
                print(clr("  ✓ Genesis hash matches (full 64-char compare).",
                          GREEN))
            else:
                print(clr("  [FAIL] GENESIS HASH MISMATCH.", RED))
                print(f"    local: {local_gen.block_hash}")
                print(f"    peer : {peer_gen_hash}")
                print("  → This is the root cause. The explorer shows only")
                print("    the first 32 chars; the FULL hashes differ.")
                print("  → Fix: stop both nodes, delete the chain DB on")
                print("    one device, restart. It will re-create the")
                print("    deterministic v7.1.2 genesis and re-sync.")
                return

            # ── 8. Parse and call accept_chain manually ──────────────────────
            try:
                blocks = [Block.from_dict(d) for d in blocks_data]
            except Exception as e:
                print(clr(f"  [FAIL] Block.from_dict error: {e}", RED))
                return
            print(clr(f"  → Calling accept_chain({len(blocks)} blocks)…",
                      CYAN))
            t0 = time.time()
            ok, reason = n.blockchain.accept_chain(blocks)
            dt = time.time() - t0
            end_h = n.blockchain.height()
            color = GREEN if ok else RED
            print(clr(f"    accept_chain → ok={ok}  ({dt:.2f}s)", color))
            print(f"    reason: '{reason}'")
            print(f"  Local height after : {end_h}  "
                  f"(was {start_h}, Δ={end_h - start_h})")
            if ok and end_h > start_h:
                print(clr("  ✓ SYNC WORKS from this peer. If the normal "
                          "auto-sync does not advance height, the bug is in "
                          "the auto-sync retry loop or the rate limiter, "
                          "NOT in accept_chain.", GREEN))
            elif ok and end_h == start_h:
                print(clr("  [NOTE] accept_chain returned OK but height did "
                          "not advance — blocks were already present.",
                          YELLOW))
            else:
                print(clr("  [FAIL] accept_chain REJECTED the peer's chain.",
                          RED))
                print(f"  → Reason above is the exact error. Send me this "
                      f"line and I can point to the precise check.")
        finally:
            # Always restore the original handler, even on exception
            n.network._handle_message = orig_handle

    def _ai_suggestions(self):
        print(clr("\n  ── AI Suggestions ──", YELLOW))
        n   = self.node
        bal = n.storage.get_balance(n.wallet.address)
        role = n.roles.get_my_role()
        peers = len(n.network.active_peer_count())
        height = n.blockchain.height()
        extra = []
        # BUG-FIX: bal is float VSD, MIN_INVESTOR_STAKE is satoshi int.
        # Without conversion the comparison was always True (any small
        # VSD float < 20_000_000_000 satoshi int) so the suggestion fired
        # for every user, including those well above the actual minimum.
        # Also the displayed threshold (100 VSD) did not match the real
        # minimum (200 VSD = MIN_INVESTOR_STAKE / SATOSHI_PER_VSD).
        _min_investor_vsd = from_satoshi(Config.MIN_INVESTOR_STAKE)
        if bal < _min_investor_vsd and (not role or role["role"] == "none"):
            extra.append(
                f"Accumulate {_min_investor_vsd:.0f} VSD to qualify as an Investor.")
        if peers < Config.MIN_PEERS:
            extra.append("Add more peers to improve network health.")
        if height < 10 and not (role and role["role"] in ("miner","investor")):
            extra.append("Register as a Miner to earn block rewards.")
        all_tips = Config.AI_TIPS + extra
        for i, t in enumerate(random.sample(all_tips, min(3, len(all_tips))), 1):
            print(f"  {clr(str(i), CYAN)}. {t}")

    def _unstake(self):
        print(clr("\n  ── Unstake ──", YELLOW))
        role = self.node.roles.get_my_role()
        if not role or role["role"] == "none":
            print("  No active stake."); return
        confirm = input(f"  Unstake {role['stake']:.4f} VSD? (y/n): ").strip().lower()
        if confirm != 'y':
            print("  Cancelled."); return
        ok, msg = self.node.roles.unstake()
        print(clr(f"  {msg}", GREEN if ok else RED))

    def _governance_status(self):
        """Display the current state of all upgrade governance proposals."""
        print(clr("\n  ── Governance — Upgrade Status ──", YELLOW))
        proposals = self.node.governance_status()
        active_ver = self.node.blockchain._governance.get_active_version()
        print(f"  Active protocol version : {bold(str(active_ver))}")
        print(f"  Current config version  : {Config.PROTOCOL_VERSION}")
        print()
        if not proposals:
            print(clr("  No upgrade proposals on record.", DIM))
            return
        for p in proposals:
            phase     = p["phase"]
            phase_clr = {
                "DORMANT":   DIM,
                "SIGNALING": YELLOW,
                "LOCKED_IN": MAGENTA,
                "ACTIVE":    GREEN,
                "FAILED":    RED,
            }.get(phase, RESET)
            print(clr(f"  ┌─ Proposal: protocol v{p['version']} ─────────────────────────", CYAN))
            print(f"  │  Phase            : {clr(phase, phase_clr)}")
            print(f"  │  Signal window    : blocks {p['signal_start_height']} – {p['signal_end_height']}")
            print(f"  │  Lock-in height   : {p['lock_in_height'] or '(pending)'}")
            print(f"  │  Activation height: {p['activation_height'] or '(pending)'}")
            print(f"  │  Threshold        : {p['threshold']*100:.0f}%")
            print(f"  │  Rollback window  : {p['rollback_window']} blocks after activation")
            if p.get("disabled"):
                print(clr("  │  ⚠  DISABLED by emergency kill-switch", RED))
            print(clr("  └────────────────────────────────────────────────────", CYAN))
            print()
        current_h = self.node.blockchain.height()
        print(f"  Current chain height    : {current_h}")

    def _governance_propose(self):
        """Propose a new protocol upgrade through the governance lifecycle."""
        print(clr("\n  ── Governance — Propose Upgrade ──", YELLOW))
        current_ver = self.node.blockchain._proto_mgr.current_version()
        next_ver    = current_ver + 1
        print(f"  Current protocol version : {current_ver}")
        print(f"  Proposed next version    : {next_ver}")
        print()
        print(clr("  After proposing, miners signal by embedding the new", DIM))
        print(clr("  protocol_version in their mined blocks.  Once ≥75%", DIM))
        print(clr("  of miners signal, the upgrade auto-locks and activates.", DIM))
        print()

        current_h = self.node.blockchain.height()
        default_start = current_h + 1
        raw = input(
            f"  Signal start height [default {default_start}]: ").strip()
        try:
            signal_start = int(raw) if raw else default_start
        except ValueError:
            print(clr("  Invalid height.", RED)); return

        raw_thr = input(
            f"  Signal threshold 0.0–1.0 [default {Config.FORK_SIGNAL_THRESHOLD}]: "
        ).strip()
        try:
            threshold = float(raw_thr) if raw_thr else Config.FORK_SIGNAL_THRESHOLD
            if not (0.5 <= threshold <= 1.0):
                print(clr("  Threshold must be between 0.50 and 1.00.", RED)); return
        except ValueError:
            print(clr("  Invalid threshold.", RED)); return

        print()
        print(f"  Proposing upgrade to v{next_ver}")
        print(f"  Signaling starts at block {signal_start}")
        print(f"  Threshold: {threshold*100:.0f}%")
        confirm = input("  Confirm? (y/n): ").strip().lower()
        if confirm != 'y':
            print("  Cancelled."); return

        ok, msg = self.node.propose_upgrade(next_ver, signal_start, threshold)
        print(clr(f"\n  {msg}", GREEN if ok else RED))
        if ok:
            print(clr(
                f"\n  ✓ Upgrade to v{next_ver} announced.\n"
                f"  Update Config.PROTOCOL_VERSION to {next_ver} in your mined\n"
                f"  blocks to start signaling.",
                GREEN))

    # ── VVM / Smart Contract CLI handlers ────────────────────────────────────

    def _vvm_deploy(self):
        """Interactive contract deployment."""
        print(clr("\n  ── Smart Contracts — Deploy ──", YELLOW))
        print(clr("  Paste contract bytecode as a hex string.", DIM))
        print(clr("  Example init code (stores 42, returns empty runtime):", DIM))
        print(clr("    6042600055600060006000f3", DIM))
        print()
        bytecode_hex = input("  Bytecode (hex): ").strip()
        if not bytecode_hex:
            print(clr("  Cancelled.", RED)); return
        try:
            raw = bytes.fromhex(bytecode_hex)
        except ValueError:
            print(clr("  Invalid hex string.", RED)); return
        if len(raw) > Config.VVM_MAX_BYTECODE_SIZE:
            print(clr(f"  Bytecode too large: {len(raw)} bytes "
                      f"(max {Config.VVM_MAX_BYTECODE_SIZE}).", RED)); return

        # SC-NAME-1: optional contract name
        raw_cname = input("  Contract name (optional, leave blank for unnamed): ").strip()
        if raw_cname:
            norm_cname = normalize_contract_name(raw_cname)
            ok_cn, reason_cn = validate_contract_name(norm_cname)
            if not ok_cn:
                print(clr(f"  Invalid contract name: {reason_cn}", RED))
                return
            # Pre-flight: warn if name is already taken (non-binding; consensus
            # is the final authority, but this saves a wasted tx fee).
            if self.node.storage.contract_name_exists(norm_cname):
                print(clr(
                    f"  ✗ Name '{norm_cname}' is already registered to "
                    f"another contract.  Choose a different name.", RED))
                return
            print(clr(f"  Name: '{norm_cname}'", GREEN))
        else:
            norm_cname = ""

        default_gas  = 200_000
        default_gp   = Config.VVM_MIN_GAS_PRICE
        try:
            gas_raw = input(f"  Gas limit [default {default_gas}]: ").strip()
            gas_limit = int(gas_raw) if gas_raw else default_gas
            gp_raw  = input(f"  Gas price VSD/gas [default {default_gp}]: ").strip()
            gas_price = float(gp_raw) if gp_raw else default_gp
        except ValueError:
            print(clr("  Invalid gas parameter.", RED)); return

        max_gas_fee = round(gas_limit * gas_price, 8)
        bal = self.node.storage.get_balance(self.node.wallet.address)
        print(f"\n  Max gas cost  : {max_gas_fee:.8f} VSD")
        print(f"  Your balance  : {bal:.8f} VSD")
        if bal < max_gas_fee:
            print(clr("  Insufficient balance for gas.", RED)); return

        confirm = input("  Deploy? (y/n): ").strip().lower()
        if confirm != 'y':
            print("  Cancelled."); return

        # Build deploy tx
        sender      = self.node.wallet.address
        chain_nonce = self.node.storage.get_nonce(sender)
        pending_cnt = len(self.node.blockchain.mempool._pending_nonces.get(sender, set()))
        nonce       = chain_nonce + pending_cnt
        tx = Transaction(
            sender        = sender,
            receiver      = "",
            amount        = 0.0,
            fee           = max_gas_fee,
            memo          = "VVM:deploy",
            nonce         = nonce,
            tx_type       = Transaction.TYPE_DEPLOY,
            data          = bytecode_hex,
            gas_limit     = gas_limit,
            gas_price     = gas_price,
            contract_name = norm_cname,   # SC-NAME-1
        )
        tx.sign(self.node.wallet)
        predicted = derive_contract_address(sender, nonce, tx.tx_id)

        evt = Event(EventType.NEW_TX, {"tx": tx.to_dict()})
        ok, msg = self.node.state_engine.post_sync(evt)
        if ok:
            self.node.network.broadcast_tx(tx)
            print(clr(f"\n  ✓ Deploy TX submitted!", GREEN))
            print(f"  TX ID            : {tx.tx_id}")
            print(f"  Predicted address: {bold(predicted)}")
            if norm_cname:
                print(f"  Contract name    : {clr(norm_cname, CYAN)}")
            print(clr("  Contract will be active after the next mined block.", DIM))
        else:
            print(clr(f"\n  ✗ Deploy failed: {msg}", RED))

    def _vvm_inspect(self):
        """Inspect a deployed contract or simulate a call."""
        print(clr("\n  ── Smart Contracts — Call / Inspect ──", YELLOW))
        print("  [1] List deployed contracts")
        print("  [2] Inspect contract")
        print("  [3] Call contract (on-chain)")
        print("  [4] Simulate call (read-only, no TX)")
        print("  [0] Back")
        sub = input(clr("  › ", CYAN)).strip()

        if sub == "1":
            # SC-NAME-1: include contract_name; join vvm_receipts for deploy tx_id.
            rows = self.node.storage._conn().execute(
                """SELECT ca.address, ca.creator, ca.created_at,
                          ca.contract_name,
                          vr.tx_id AS deploy_tx_id
                     FROM contract_accounts ca
                     LEFT JOIN vvm_receipts vr
                          ON vr.contract_addr = ca.address
                         AND vr.success = 1
                   WHERE ca.destroyed = 0
                   ORDER BY ca.created_at DESC
                   LIMIT 20"""
            ).fetchall()
            if not rows:
                print(clr("  No contracts deployed yet.", DIM)); return
            print(clr(f"\n  {'NAME':<24} {'ADDRESS':<44} DEPLOYED", CYAN))
            print("  " + "─" * 80)
            for r in rows:
                ts     = datetime.fromtimestamp(
                    r["created_at"], tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
                cname  = r["contract_name"] if r["contract_name"] else clr("(unnamed)", DIM)
                addr   = r["address"]
                print(f"  {cname:<24} {addr:<44} {ts}")
                creator = (r["creator"] or "")
                tx_id   = (r["deploy_tx_id"] or "")[:20]
                print(f"  {clr('Creator:', DIM)} {creator}  {clr('TX:', DIM)} {tx_id}...")
            return

        elif sub == "2":
            addr = input("  Contract address: ").strip()
            rec  = self.node.storage.get_contract(addr)
            if not rec:
                print(clr("  Contract not found.", RED)); return
            code = self.node.storage.get_contract_code(rec["code_hash"])
            slots = self.node.storage.get_all_contract_slots(addr)
            ts = datetime.fromtimestamp(
                rec["created_at"], tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
            print(clr(f"\n  Contract: {addr}", CYAN))
            # SC-NAME-1: display name
            cname_display = rec.get("contract_name") or clr("(unnamed)", DIM)
            print(f"  Name         : {cname_display}")
            print(f"  Code hash    : {rec['code_hash'][:16]}...")
            print(f"  Bytecode size: {len(code) if code else 0} bytes")
            print(f"  Storage root : {rec['storage_root'][:16]}...")
            print(f"  Creator      : {rec['creator']}")
            print(f"  Deployed at  : {ts}")
            print(f"  Storage slots: {len(slots)}")
            if slots:
                for k, v in list(slots.items())[:5]:
                    print(f"    {k[:16]}... = {v}")
                if len(slots) > 5:
                    print(f"    ... and {len(slots)-5} more")
            return

        elif sub == "3":
            addr = input("  Contract address: ").strip()
            if not self.node.storage.get_contract(addr):
                print(clr("  Contract not found.", RED)); return
            calldata_hex = input("  Calldata (hex, or empty): ").strip()
            if calldata_hex:
                try:
                    bytes.fromhex(calldata_hex)
                except ValueError:
                    print(clr("  Invalid hex.", RED)); return
            try:
                gas_limit = int(input(f"  Gas limit [default 100000]: ").strip() or "100000")
                gas_price = float(input(f"  Gas price [default {Config.VVM_MIN_GAS_PRICE}]: ").strip()
                                  or str(Config.VVM_MIN_GAS_PRICE))
                call_value = float(input("  VSD value to send [default 0]: ").strip() or "0")
            except ValueError:
                print(clr("  Invalid parameter.", RED)); return

            sender      = self.node.wallet.address
            chain_nonce = self.node.storage.get_nonce(sender)
            pending_cnt = len(self.node.blockchain.mempool._pending_nonces.get(sender, set()))
            nonce       = chain_nonce + pending_cnt
            tx = Transaction(
                sender    = sender,
                receiver  = addr,
                amount    = call_value,
                fee       = round(gas_limit * gas_price, 8),
                memo      = "VVM:call",
                nonce     = nonce,
                tx_type   = Transaction.TYPE_CALL,
                data      = calldata_hex,
                gas_limit = gas_limit,
                gas_price = gas_price,
            )
            tx.sign(self.node.wallet)
            evt = Event(EventType.NEW_TX, {"tx": tx.to_dict()})
            ok, msg = self.node.state_engine.post_sync(evt)
            if ok:
                self.node.network.broadcast_tx(tx)
                print(clr(f"\n  ✓ Call TX submitted: {tx.tx_id}", GREEN))
                print(clr("  Result will be in next mined block receipt.", DIM))
            else:
                print(clr(f"\n  ✗ Call failed: {msg}", RED))
            return

        elif sub == "4":
            addr = input("  Contract address: ").strip()
            if not self.node.storage.get_contract(addr):
                print(clr("  Contract not found.", RED)); return
            calldata_hex = input("  Calldata (hex, or empty): ").strip()
            try:
                gas_limit = int(input("  Gas limit [default 500000]: ").strip() or "500000")
            except ValueError:
                print(clr("  Invalid gas limit.", RED)); return

            calldata = bytes.fromhex(calldata_hex) if calldata_hex else b""
            latest   = self.node.blockchain.latest_block()

            vvm = VVMEngine(storage=self.node.storage)
            # AUDIT-FIX-N1: this branch is labeled "read-only, no TX" but
            # was calling vvm.call() — the real, state-mutating execution
            # path (is_static=False, storage_ref=real storage). Native
            # opcodes that write straight through to storage (e.g.
            # CHAN_OPEN) bypass the normal storage_writes staging and
            # commit immediately and permanently. simulate() is the
            # existing dry-run method (is_static=True, routed through a
            # storage proxy that discards writes) — it takes no `tx` arg
            # and hardcodes gas_price=0 internally, so _StubTx is no
            # longer needed.
            result = vvm.simulate(
                caller     = self.node.wallet.address,
                contract   = addr,
                calldata   = calldata,
                call_value = 0,
                gas_limit  = min(gas_limit, Config.VVM_TX_GAS_CAP),
                block_ctx  = latest,
            )
            status = clr("SUCCESS", GREEN) if result.success else clr("REVERT", RED)
            print(f"\n  Status      : {status}")
            print(f"  Gas used    : {result.gas_used}")
            if result.success:
                print(f"  Return data : 0x{result.return_data.hex()}")
                if result.logs:
                    print(f"  Logs emitted: {len(result.logs)}")
                    for lg in result.logs[:3]:
                        print(f"    topics={lg['topics']} data={lg['data'][:32]}...")
            else:
                print(f"  Revert reason: {result.revert_reason}")
            return

        elif sub == "0":
            return
        else:
            print(clr("  Invalid choice.", RED))

    # ═══════════════════════════════════════════════════════════════════════
    # LAYER-2 DASHBOARD (v7.5.0-OPT)
    # ═══════════════════════════════════════════════════════════════════════
    # Sub-dashboard for L2 rollup operations.  Entered from L1 menu option 26.
    # Lives entirely inside the existing CLI process — no fork, no new
    # threads, shares the same Node/Layer2State/Sequencer instances.  Stays
    # text-based (no fancy cursor positioning) to keep the implementation
    # simple and avoid the row-offset complexity of the L1 live dashboard.
    #
    # Selecting "0" inside the L2 dashboard returns to the L1 dashboard;
    # the L1 _full_render() runs again on return so the user sees their
    # familiar live panel.

    def _l2_dashboard(self) -> None:
        """L2 sub-dashboard.  Loops on input until user picks 0 (back to L1)."""
        layer2 = getattr(self.node.blockchain, "layer2", None)
        if layer2 is None:
            print(clr("  L2 subsystem not initialised on this node.", RED))
            return

        # Local exit flag — separate from self._running so we can return to
        # L1 cleanly without exiting the whole node.
        l2_running = True
        while l2_running:
            try:
                self._l2_render_panel()
                self._l2_print_menu()
                try:
                    choice = input(clr("  L2 › ", BLUE)).strip()
                except (KeyboardInterrupt, EOFError):
                    # Treat Ctrl-C as "go back" rather than exiting the node.
                    print()
                    return

                if choice == "0":
                    l2_running = False
                    continue
                # Dispatch — wrap individual handlers so an exception in
                # one of them doesn't dump the user back to L1.
                action = self._l2_actions().get(choice)
                if action is None:
                    if choice:
                        print(clr("  Invalid L2 choice.", RED))
                else:
                    try:
                        action()
                    except Exception as e:
                        print(clr(f"  L2 handler error: {e}", RED))
                # Pause so the user can read output before the panel redraws.
                try:
                    input(clr("  Press Enter to continue...", DIM))
                except (KeyboardInterrupt, EOFError):
                    return
            except Exception as e:
                # Catch-all: never let the L2 loop crash and abandon the
                # node.  Print and continue.
                print(clr(f"  L2 dashboard error: {e}", RED))
                try:
                    input(clr("  Press Enter to continue...", DIM))
                except (KeyboardInterrupt, EOFError):
                    return

    def _l2_actions(self) -> dict:
        """Return the L2 menu number → handler map.  Built fresh each call
        so handlers always bind to the current self (defensive against
        live module reloads in dev)."""
        return {
            "1": self._l2_show_status,
            "2": self._l2_show_balance,
            "3": self._l2_deposit,
            "4": self._l2_send,
            "5": self._l2_view_account,
            "6": self._l2_sequencer_status,
            "7": self._l2_trigger_rollup,
            "8": self._l2_withdraw,
        }

    def _l2_render_panel(self) -> None:
        """Print the L2 status panel above the L2 menu.  Keep it short —
        we redraw it every loop iteration."""
        if self._ansi_ok():
            try:
                sys.stdout.write('\033[H\033[2J')
                sys.stdout.flush()
            except Exception:
                pass
        node   = self.node
        layer2 = node.blockchain.layer2
        wallet = node.wallet
        try:
            st = layer2.status()
        except Exception as e:
            st = {"root": "?", "account_count": 0, "l2_supply_sat": 0,
                  "l1_bridge_sat": 0, "invariant_ok": False,
                  "last_batch_id": -1, "history_depth": 0,
                  "_err": str(e)}
        try:
            l2_bal = layer2.get_balance_sat(wallet.address)
            l2_nce = layer2.get_nonce(wallet.address)
        except Exception:
            l2_bal, l2_nce = 0, 0
        try:
            l1_bal_sat = node.storage.get_balance_sat(wallet.address)
        except Exception:
            l1_bal_sat = 0
        seq = getattr(node, "sequencer", None)
        seq_running = bool(seq and getattr(seq, "_running", False))

        # Header
        W = max(60, self._term_width())
        title = "  LAYER-2 ROLLUP DASHBOARD  "
        wings = "═" * max(0, (W - len(title)) // 2)
        print(clr(f"  {wings}{title}{wings}", BLUE))
        print()
        # State summary
        invc = GREEN if st.get("invariant_ok") else RED
        print(f"  State root      : {clr(st['root'][:32], CYAN)}...")
        print(f"  L2 accounts     : {st['account_count']}")
        print(f"  L2 supply (sat) : {st['l2_supply_sat']:,}")
        print(f"  L1 escrow (sat) : {st['l1_bridge_sat']:,}")
        print(f"  Invariant       : {clr('OK' if st['invariant_ok'] else 'MISMATCH', invc)}")
        print(f"  Last batch id   : {st['last_batch_id']}")
        print(f"  Snapshot depth  : {st['history_depth']}")
        if "_err" in st:
            print(clr(f"  (status error: {st['_err']})", RED))
        print()
        # Wallet summary
        print(f"  My address      : {clr(wallet.address, CYAN)}")
        print(f"  My L1 (sat)     : {l1_bal_sat:,}")
        print(f"  My L2 (sat)     : {l2_bal:,}   nonce={l2_nce}")
        print()
        # Sequencer summary
        if seq is None:
            print(f"  Sequencer       : {clr('not constructed', DIM)}")
        else:
            try:
                ss = seq.status()
                state_color = GREEN if seq_running else YELLOW
                state_text  = "running" if seq_running else "stopped"
                print(f"  Sequencer       : {clr(state_text, state_color)}  "
                      f"pending={ss['pending']}  next_batch={ss['next_batch_id']}")
                print(f"  Proof backend   : {ss['backend']}  "
                      f"({clr(ss['backend_security'], YELLOW)})")
            except Exception as e:
                print(f"  Sequencer       : {clr(f'status error: {e}', RED)}")
        print()
        # Sentinel banner — surface backend posture honestly.
        try:
            backend = ProofRegistry.get_configured()
            backend_name = backend.name()
            backend_sec  = backend.security()
            prod_ready   = backend.is_production_ready()
            mainnet      = _is_mainnet()
            unsafe       = _is_unsafe_backend(backend)
            if unsafe:
                # Loud warning regardless of network — operator should see this.
                print(clr("  ⚠  Proof backend is NOT production-safe "
                          f"(name={backend_name!r}, security={backend_sec!r}). "
                          "It is HMAC, not zero-knowledge.  A real SNARK "
                          "backend (IProofBackend implementation) must be "
                          "registered via ProofRegistry.register() and "
                          "selected by Config.L2_PROOF_BACKEND before any "
                          "mainnet deployment.  Set VISOLD_NETWORK=mainnet "
                          "to make the node refuse to start with an unsafe "
                          "backend.", YELLOW))
                print()
            elif not mainnet and prod_ready:
                # Production-ready backend on a non-mainnet node — fine,
                # just inform.
                print(clr("  ℹ  Proof backend is production-ready "
                          f"({backend_name}, {backend_sec}).  "
                          "VISOLD_NETWORK is not 'mainnet' — running in "
                          "dev/test mode.", DIM))
                print()
        except UnsafeBackendOnMainnetError as e:
            print(clr(f"  ✗  Mainnet refused to load proof backend: {e}", RED))
            print()
        except Exception:
            pass

    def _l2_print_menu(self) -> None:
        W = max(60, self._term_width())
        sep = "─" * max(10, W - 4)
        print(clr(f"  {sep}", DIM))
        print(f"  [{clr('1', CYAN)}] L2 Status (refresh)")
        print(f"  [{clr('2', CYAN)}] My L2 Balance")
        print(f"  [{clr('3', GREEN)}] Deposit L1 → L2")
        print(f"  [{clr('4', GREEN)}] Send L2 Transaction")
        print(f"  [{clr('5', CYAN)}] View any L2 Account")
        print(f"  [{clr('6', YELLOW)}] Sequencer Status")
        print(f"  [{clr('7', MAGENTA)}] Trigger Manual Rollup (admin)")
        print(f"  [{clr('8', GREEN)}] Withdraw L2 → L1")
        print(clr(f"  {sep}", DIM))
        print(f"  [{clr('0', RED)}] ◀ Back to L1 Dashboard")
        print(clr(f"  {sep}", DIM))

    # ── L2 sub-handlers ────────────────────────────────────────────────────

    def _l2_show_status(self) -> None:
        """Refresh L2 state — _l2_render_panel will redraw on next loop iter."""
        print(clr("\n  ── L2 Status (refreshed on next render) ──", BLUE))
        st = self.node.blockchain.layer2.status()
        for k, v_ in st.items():
            print(f"    {k:<18} : {v_}")

    def _l2_show_balance(self) -> None:
        wallet = self.node.wallet
        layer2 = self.node.blockchain.layer2
        bal = layer2.get_balance_sat(wallet.address)
        nce = layer2.get_nonce(wallet.address)
        l1_bal = self.node.storage.get_balance_sat(wallet.address)
        print(clr("\n  ── L2 Balance ──", BLUE))
        print(f"    Address     : {wallet.address}")
        print(f"    L1 balance  : {l1_bal:,} sat")
        print(f"    L2 balance  : {bal:,} sat")
        print(f"    L2 nonce    : {nce}")

    def _l2_deposit(self) -> None:
        """L1 → L2 bridge.  Sends an L1 transfer to L2_BRIDGE_ADDRESS;
        Blockchain.apply_block's deposit hook then auto-credits the L2 tree."""
        print(clr("\n  ── L1 → L2 Deposit ──", BLUE))

        # v7.5.x: warn the user up-front if NO local sequencer is running.
        # Without a running sequencer somewhere on the network, deposited
        # funds can still be withdrawn back to L1 (option 8: Withdraw —
        # routed through the L1 mempool / apply_block hook), but L2-internal
        # sends (option 4: Send L2 tx) will accumulate without ever settling.
        # Many honest users won't spot this until their L2 sends "go nowhere".
        seq = getattr(self.node, "sequencer", None)
        seq_running = bool(seq and getattr(seq, "_running", False))
        if not seq_running:
            print(clr(
                "  ⚠ No local sequencer is running on this node.\n"
                "    • Deposits still credit your L2 balance.\n"
                "    • Withdrawals (option 8) still work — they route through L1.\n"
                "    • L2-internal sends (option 4) will gossip to the network\n"
                "      but cannot settle unless some node on the network has\n"
                "      a sequencer running with a production proof backend.\n"
                "    On mainnet (Config.L2_PROOF_BACKEND='local-dev' default),\n"
                "    sequencers refuse to start at all — L2 sends will sit\n"
                "    indefinitely until a proper SNARK backend is configured.",
                YELLOW))
            cont = input("  Continue with deposit anyway? (y/n): ").strip().lower()
            if cont != 'y':
                print("  Cancelled."); return

        amt_str = input("  Amount (VSD): ").strip()
        try:
            amount = float(amt_str)
        except ValueError:
            print(clr("  Invalid amount.", RED)); return
        if not math.isfinite(amount) or amount <= 0:
            print(clr("  Amount must be a positive finite number.", RED)); return
        # Cap satoshi to prevent overflow far before consensus paths see it.
        try:
            amount_sat = to_satoshi(amount)
        except Exception as e:
            print(clr(f"  Amount conversion failed: {e}", RED)); return
        if amount_sat <= 0 or amount_sat >= (1 << 62):
            print(clr("  Amount out of allowed range.", RED)); return

        # Show confirmation including the standard L1 fee that send_transaction
        # will deduct so the user knows the real total cost.
        fee = round(amount * Config.TX_FEE_RATE, 8)
        print(f"  Bridge address   : {L2_BRIDGE_ADDRESS}")
        print(f"  Deposit amount   : {amount:.8f} VSD ({amount_sat:,} sat)")
        print(f"  L1 fee (sender)  : {fee:.8f} VSD")
        print(f"  Total deducted   : {amount + fee:.8f} VSD")
        print(clr("  Note: L2 credit appears once the deposit tx is mined "
                  "into a block and apply_block runs the deposit hook.", DIM))
        confirm = input("  Confirm deposit? (y/n): ").strip().lower()
        if confirm != 'y':
            print("  Cancelled."); return
        memo = "L2_DEPOSIT"
        ok, msg = self.node.send_transaction(L2_BRIDGE_ADDRESS, amount, memo)
        print(clr(f"  {msg}", GREEN if ok else RED))

    def _l2_send(self) -> None:
        """Sign an L2 tx and gossip it / hand it to the local sequencer.

        UX parity with L1's _send_coins:
        • Accepts either a user_id (registered identity) OR a raw VSD address
        • Same confirm-then-send flow
        • Same colour scheme on result lines

        Notes on differences (these are protocol, not UX):
        • L2Transaction has no memo field by design (kept minimal for
          rollup compression).  See class comment at L2Transaction.
        • L2 txs carry no per-tx fee; the cost is paid by the sequencer at
          settlement time.  We tell the user that explicitly so they aren't
          surprised by the missing fee line.
        """
        print(clr("\n  ── Send L2 Transaction ──", BLUE))
        wallet = self.node.wallet
        layer2 = self.node.blockchain.layer2

        l2_bal = layer2.get_balance_sat(wallet.address)
        if l2_bal <= 0:
            print(clr("  Your L2 balance is 0.  Use option 3 (Deposit) first.",
                      YELLOW))
            return

        # Match L1: accept user_id OR VSD address.  Resolve user_id via
        # the same identity service that node.send_transaction uses (line
        # 33895 in this file).
        raw = input("  To (user_id or VSD address): ").strip()
        if not raw:
            print(clr("  Recipient required.", RED)); return
        # Bound length defensively before any lookup.
        if len(raw) > 128:
            print(clr("  Input too long.", RED)); return
        if any(c.isspace() or ord(c) < 0x20 for c in raw):
            print(clr("  Input contains whitespace/control chars.", RED))
            return

        # Resolve.  Same logic as VisoldNode.send_transaction:
        #   • Empty / global-market not allowed for L2 (no broadcast L2 path)
        #   • If it doesn't start with "VSD", treat as user_id
        #   • Otherwise treat as raw address
        if raw == VSD_GLOBAL_MARKET:
            print(clr("  Broadcast orders are L1-only — not supported on L2.",
                      RED))
            return
        if not raw.startswith("VSD"):
            try:
                resolved = self.node.identity.get_wallet_address(raw)
            except Exception as e:
                print(clr(f"  Identity lookup failed: {e}", RED)); return
            if not resolved:
                print(clr(f"  Cannot resolve user_id '{raw}' — not registered.",
                          RED))
                return
            print(f"  Resolved {raw} → {resolved}")
            to_addr = resolved
        else:
            to_addr = raw

        # Address sanity (post-resolution).
        if len(to_addr) < 4 or len(to_addr) > 128:
            print(clr("  Resolved address has bad length.", RED)); return
        if to_addr == wallet.address:
            print(clr("  Cannot send to yourself.", RED)); return

        amt_str = input("  Amount (VSD): ").strip()
        try:
            amount = float(amt_str)
        except ValueError:
            print(clr("  Invalid amount.", RED)); return
        if not math.isfinite(amount) or amount <= 0:
            print(clr("  Amount must be a positive finite number.", RED)); return
        try:
            amount_sat = to_satoshi(amount)
        except Exception as e:
            print(clr(f"  Amount conversion failed: {e}", RED)); return
        if amount_sat <= 0 or amount_sat >= (1 << 62):
            print(clr("  Amount out of allowed range.", RED)); return
        if amount_sat > l2_bal:
            print(clr(f"  Insufficient L2 balance "
                      f"({l2_bal:,} sat available, {amount_sat:,} sat requested).",
                      RED))
            return

        nonce = layer2.get_nonce(wallet.address)
        # Confirmation panel — mirror L1's layout so the user sees a
        # familiar form, but reflect L2's no-fee semantics honestly.
        print(f"  Recipient        : {to_addr}")
        print(f"  Amount           : {amount:.8f} VSD ({amount_sat:,} sat)")
        print(f"  L2 fee (per-tx)  : 0  (L2 txs have no individual fee — "
              f"sequencer pays at settlement)")
        print(f"  Nonce            : {nonce}")
        print(clr("  L2 txs are off-chain until a rollup batch settles. "
                  "Settlement adds the proof to L1.", DIM))
        confirm = input("  Confirm send? (y/n): ").strip().lower()
        if confirm != 'y':
            print("  Cancelled."); return

        # Sign.
        try:
            l2tx = wallet.sign_l2_tx(receiver=to_addr,
                                      amount_sat=amount_sat,
                                      nonce=nonce)
        except Exception as e:
            print(clr(f"  Sign failed: {e}", RED)); return

        # Validate before sending.
        ok_v, msg_v = l2tx.is_valid()
        if not ok_v:
            print(clr(f"  Local validation failed: {msg_v}", RED)); return

        # Local sequencer admit + gossip.
        local_msg = "no local sequencer running"
        seq = getattr(self.node, "sequencer", None)
        if seq is not None and getattr(seq, "_running", False):
            ok_a, local_msg = seq.add_l2_tx(l2tx)
            local_msg = f"local seq: {ok_a} ({local_msg})"
        try:
            if self.node.network is not None:
                self.node.network.broadcast_l2_tx(l2tx)
                gossip_msg = "broadcast OK"
            else:
                gossip_msg = "no network"
        except Exception as e:
            gossip_msg = f"broadcast error: {e}"

        # Match L1's green-on-success / red-on-fail message convention.
        ok_overall = ok_v and ("broadcast" in gossip_msg or "local seq" in local_msg)
        print(clr(f"  L2 tx submitted: {l2tx.l2_tx_id}",
                  GREEN if ok_overall else YELLOW))
        print(f"  {local_msg}")
        print(f"  Gossip: {gossip_msg}")

    def _l2_view_account(self) -> None:
        print(clr("\n  ── View L2 Account ──", BLUE))
        addr = input("  Address (blank = self): ").strip()
        if not addr:
            addr = self.node.wallet.address
        if len(addr) > 128:
            print(clr("  Address too long.", RED)); return
        layer2 = self.node.blockchain.layer2
        bal = layer2.get_balance_sat(addr)
        nce = layer2.get_nonce(addr)
        print(f"    Address : {addr}")
        print(f"    Balance : {bal:,} sat")
        print(f"    Nonce   : {nce}")

    def _l2_sequencer_status(self) -> None:
        print(clr("\n  ── L2 Sequencer Status ──", BLUE))
        seq = getattr(self.node, "sequencer", None)
        if seq is None:
            print(clr("  Sequencer not constructed on this node.", YELLOW))
            return
        try:
            st = seq.status()
        except Exception as e:
            print(clr(f"  Status error: {e}", RED)); return
        for k, v_ in st.items():
            print(f"    {k:<22} : {v_}")
        if not st.get("running"):
            print(clr("\n  Sequencer is constructed but NOT running. "
                      "Start it via the dedicated start command — running it "
                      "from inside the dashboard would block this thread.",
                      DIM))
        # Honest reminder about the simulated backend.
        sec = st.get("backend_security", "")
        if "simulated" in sec or "trust-sequencer" in sec:
            print(clr("\n  ⚠  Active proof backend is simulated (HMAC). "
                      "Not zero-knowledge.  Swap to a real SNARK backend "
                      "via ProofRegistry.register() before production.",
                      YELLOW))

    def _l2_withdraw(self) -> None:
        """L2 → L1 bridge withdrawal.

        Debits the user's L2 balance and immediately credits their L1 wallet
        from the bridge escrow.  No block / mempool required.
        """
        print(clr("\n  ── L2 → L1 Withdrawal ──", BLUE))
        wallet = self.node.wallet
        layer2 = self.node.blockchain.layer2

        l2_bal = layer2.get_balance_sat(wallet.address)
        if l2_bal <= 0:
            print(clr("  Your L2 balance is 0.  Nothing to withdraw.", YELLOW))
            return
        print(f"  Your L2 balance  : {l2_bal:,} sat"
              f"  ({from_satoshi(l2_bal):.8f} VSD)")

        amt_str = input("  Amount to withdraw (VSD): ").strip()
        try:
            amount = float(amt_str)
        except ValueError:
            print(clr("  Invalid amount.", RED)); return
        if not math.isfinite(amount) or amount <= 0:
            print(clr("  Amount must be a positive finite number.", RED)); return
        try:
            amount_sat = to_satoshi(amount)
        except Exception as e:
            print(clr(f"  Amount conversion failed: {e}", RED)); return
        if amount_sat <= 0 or amount_sat >= (1 << 62):
            print(clr("  Amount out of allowed range.", RED)); return
        if amount_sat > l2_bal:
            print(clr(f"  Exceeds your L2 balance ({l2_bal:,} sat).", RED))
            return

        l1_bal_sat = self.node.storage.get_balance_sat(wallet.address)
        print(f"  Withdraw amount  : {amount:.8f} VSD ({amount_sat:,} sat)")
        print(f"  Destination      : {wallet.address}")
        print(f"  Your L1 balance  : {l1_bal_sat:,} sat  (before withdrawal)")
        print(clr("  Note: L1 credit appears once the withdrawal tx is mined "
                  "into a block (same as deposit). Your L2 balance is debited "
                  "at the same time, inside the block.",
                  DIM))
        confirm = input("  Confirm withdrawal? (y/n): ").strip().lower()
        if confirm != 'y':
            print("  Cancelled."); return

        ok, msg = self.node.withdraw_from_l2(amount)
        print(clr(f"  {msg}", GREEN if ok else RED))

    def _l2_trigger_rollup(self) -> None:
        """Admin: force the local sequencer to seal whatever it has now."""
        print(clr("\n  ── Trigger Manual Rollup (admin) ──", MAGENTA))
        seq = getattr(self.node, "sequencer", None)
        if seq is None:
            print(clr("  Sequencer not constructed on this node.", YELLOW))
            return
        if not getattr(seq, "_running", False):
            print(clr("  Sequencer is not running — start it first.", YELLOW))
            return
        try:
            pending = seq.status().get("pending", 0)
        except Exception:
            pending = "?"
        print(f"  Current pending L2 txs: {pending}")
        confirm = input("  Force-seal a batch now? (y/n): ").strip().lower()
        if confirm != 'y':
            print("  Cancelled."); return
        try:
            sealed = seq._seal_one()
        except Exception as e:
            print(clr(f"  Seal failed: {e}", RED)); return
        if sealed is None:
            print(clr("  Nothing to seal (pending pool empty).", YELLOW))
            return
        tx, batch_id, applied = sealed
        # AUDIT-FIX-G3: only finalize (remove from pending / advance
        # batch_id) once submission is confirmed — on any failure below,
        # seq._finalize_seal() is simply never called, so this batch is
        # retried automatically on the sequencer's next cycle instead of
        # being silently lost.
        try:
            evt = Event(EventType.NEW_TX, {"tx": tx})
            ok_p, msg_p = self.node.state_engine.post_sync(evt, timeout=5.0)
            if ok_p:
                seq._finalize_seal(batch_id, applied)
                print(clr(f"  Rollup tx submitted: {tx.tx_id}", GREEN))
                print(f"  StateEngine: {msg_p}")
            else:
                seq._abandon_seal()   # AUDIT-FIX-L4
                print(clr(f"  Submit failed: {msg_p}", RED))
                print(f"  Sealed tx_id (NOT submitted): {tx.tx_id} — "
                      f"batch left pending, will be retried automatically")
        except Exception as e:
            seq._abandon_seal()   # AUDIT-FIX-L4
            print(clr(f"  Submit error: {e}", RED))
            print(f"  Sealed tx_id (NOT submitted): {tx.tx_id} — "
                  f"batch left pending, will be retried automatically")

    # ── ROLLBACK HANDLER ──────────────────────────────────────────────────
    def _rollback_chain(self):
        """Interactive rollback: delete blocks above a user-chosen height.

        Safety measures
        ---------------
        * Mining is force-paused before any blocks are deleted.
        * The mempool is flushed to discard transactions that would
          reference now-invalid state.
        * The user must confirm twice (target height + "yes" confirmation)
          before any data is destroyed.
        * All changes are committed to the database before returning.
        """
        bc  = self.node.blockchain
        cur = bc.height()

        print(clr("\n  +============================+", RED))
        print(clr("  |    BLOCKCHAIN ROLLBACK     |", RED))
        print(clr("  +============================+", RED))
        print(clr("  |  Current height: {:<10s}|".format(str(cur)), YELLOW))
        print(clr("  +============================+\n", RED))

        # ── Prompt for target height ──────────────────────────────────
        raw = input(clr("  Target height to rollback to: ", CYAN)).strip()
        try:
            target = int(raw)
        except ValueError:
            print(clr("  [X] Invalid input — must be an integer.", RED))
            input(clr("  Press Enter to return...", DIM))
            return

        if target < 0 or target >= cur:
            print(clr("  [X] Target must be in range [0, {}].".format(
                cur - 1), RED))
            input(clr("  Press Enter to return...", DIM))
            return

        blocks_to_delete = cur - target
        print(clr("\n  WARNING: This will DELETE {} block(s) "
                  "(height {}–{})".format(
                      blocks_to_delete, target + 1, cur), RED))
        print(clr("  WARNING: The mempool will be flushed.", RED))
        print(clr("  WARNING: Mining will be paused during the "
                  "operation.\n", RED))

        confirm = input(clr("  Type 'yes' to confirm: ", YELLOW)).strip().lower()
        if confirm != "yes":
            print(clr("  Rollback cancelled.", GREEN))
            input(clr("  Press Enter to return...", DIM))
            return

        # ── 1. Force-stop mining ──────────────────────────────────────
        was_mining = False
        mining_eng = getattr(self.node, "mining", None)
        if mining_eng is not None:
            was_mining = getattr(mining_eng, "_running", False)
            if was_mining:
                try:
                    mining_eng.stop()
                    # Give the mining thread a moment to notice the flag.
                    time.sleep(0.5)
                except Exception:
                    pass
            print(clr("  [*] Mining stopped.", YELLOW))

        # ── 2. Flush mempool ──────────────────────────────────────────
        try:
            bc.mempool.clear_all()
            print(clr("  [*] Mempool flushed.", YELLOW))
        except Exception as exc:
            print(clr("  [!] Mempool flush error: {}".format(exc), RED))

        # ── 3. Execute rollback ───────────────────────────────────────
        print(clr("  [*] Rolling back from {} -> {}...".format(
            cur, target), CYAN))
        ok, msg = bc.rollback(target)

        if ok:
            print(clr("  [OK] {}".format(msg), GREEN))
        else:
            print(clr("  [FAIL] {}".format(msg), RED))

        # ── 4. Optionally restart mining ──────────────────────────────
        if was_mining and ok:
            restart = input(
                clr("  Restart mining? (y/N): ", CYAN)).strip().lower()
            if restart == "y":
                try:
                    mining_eng.start()
                    print(clr("  [>] Mining resumed.", GREEN))
                except Exception:
                    pass

        input(clr("\n  Press Enter to return to dashboard...", DIM))

    def _exit(self):
        # Stop the live refresh thread before tearing down the node so it
        # cannot call into a half-stopped node and raise exceptions.
        self._stop_refresh_thread()
        print(clr("\n  Shutting down Visold node...", YELLOW))
        if self.node:
            self.node.stop()
        print(clr("  Goodbye!\n", CYAN))
        self._running = False
        sys.exit(0)
