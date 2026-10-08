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
"""visold.cli.handler

Original section: SECTION 21B: ARGPARSE CLI HANDLER

Defines: CLIHandler
Origin: visold_vsd_.py L49620-50033
"""

import json
import math
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional, Tuple

from visold.kernel.config import Config
from visold.kernel.units import to_satoshi
from visold.wallet.wallet import Wallet


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 21B: ARGPARSE CLI HANDLER
#
# Lightweight command-line subcommand dispatcher that sits alongside the
# existing interactive TUI (class CLI).  Activated by the --cli flag:
#
#     python visold_vsd.py --cli wallet create [--out <path>]
#     python visold_vsd.py --cli status                 [--rpc-port N]
#     python visold_vsd.py --cli send-l2 --to <addr> --amount <val>
#     python visold_vsd.py --cli deposit --amount <val>
#     python visold_vsd.py --cli rollup-trigger        (admin token required)
#
# Design
# ──────
#   • `wallet create` runs STANDALONE — no running node needed.  Generates a
#     keypair, writes a keystore file, prints the address.
#   • All OTHER commands are JSON-RPC clients: they POST to the local RPC
#     server on 127.0.0.1:<rpc_port>, using the Bearer token that the
#     RPCServer writes to ~/.visold/rpc_token on first start.  This means
#     the daemon must already be running — consistent with how bitcoin-cli
#     / geth attach work, and avoids spinning up a whole node for simple
#     read-only queries.
#   • All integer conversions (satoshi) are validated with explicit
#     int/float range checks before leaving the CLI.  to_satoshi() is the
#     only path used for VSD→sat conversions; it raises on NaN / negative /
#     out-of-range.
#
# Security
# ────────
#   • The token file is read with exclusive access (no network fetch).
#   • Admin-gated commands (rollup-trigger) send both Bearer and X-Admin-Token;
#     if the admin token file is absent, the server refuses the operation
#     and prints a clear message.
#   • All user input reaching the satoshi-math paths passes through
#     _parse_amount_vsd() which rejects non-finite values and enforces a
#     hard 2**62 satoshi ceiling.
# ═════════════════════════════════════════════════════════════════════════════
class CLIHandler:
    """Argparse-backed command-line client.  Standalone for wallet create;
    JSON-RPC client for everything else."""

    # Hard cap for any single VSD amount accepted via CLI.  2**62 sat is
    # astronomically larger than any realistic value but still far inside
    # Python's int precision and any downstream `int` accumulator bounds.
    _MAX_SAT = (1 << 62)

    def __init__(self):
        # Defer RPC/token setup until actually needed — `wallet create`
        # must not require a running node nor a pre-existing token file.
        pass

    # ── Static helpers ────────────────────────────────────────────────────

    @staticmethod
    def _parse_amount_vsd(raw) -> Tuple[float, int]:
        """Validate a user-supplied VSD amount.  Returns (vsd_float, sat_int).

        Rejects: non-numeric, NaN, infinity, <= 0, > _MAX_SAT / SATOSHI_PER_VSD.
        Uses the existing to_satoshi() helper so the satoshi conversion
        matches every other call site in the codebase (prevents drift).
        """
        try:
            vsd = float(raw)
        except (TypeError, ValueError):
            raise SystemExit("ERROR: --amount must be numeric")
        # math.isfinite rejects both NaN and +/- inf.
        if not math.isfinite(vsd):
            raise SystemExit("ERROR: --amount must be a finite number")
        if vsd <= 0.0:
            raise SystemExit("ERROR: --amount must be positive")
        sat = to_satoshi(vsd)
        if sat <= 0 or sat >= CLIHandler._MAX_SAT:
            raise SystemExit(
                f"ERROR: --amount converts to {sat} sat, outside the "
                f"allowed range (0, {CLIHandler._MAX_SAT}).")
        return vsd, sat

    @staticmethod
    def _validate_address(addr: str) -> str:
        """Basic address-shape validation for CLI inputs.  Consensus
        verification still happens at the node — this is just to catch
        obvious typos early."""
        if not isinstance(addr, str) or not addr:
            raise SystemExit("ERROR: address must be a non-empty string")
        addr = addr.strip()
        if len(addr) < 4 or len(addr) > 128:
            raise SystemExit("ERROR: address length out of sensible range")
        # Addresses in this chain are ASCII base58/hex-ish — reject
        # whitespace / control chars which are always wrong.
        if any(c.isspace() or ord(c) < 0x20 for c in addr):
            raise SystemExit("ERROR: address contains whitespace or "
                             "control characters")
        return addr

    # ── Token loading (shared with the daemon) ────────────────────────────
    @staticmethod
    def _read_token_file(path: str, label: str) -> Optional[str]:
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r") as f:
                tok = f.read().strip()
            return tok or None
        except Exception as e:
            sys.stderr.write(f"CLI: cannot read {label} at {path}: {e}\n")
            return None

    @classmethod
    def _load_bearer_token(cls) -> str:
        tok = cls._read_token_file(
            os.path.join(Config.DATA_DIR, "rpc_token"), "RPC token")
        if not tok:
            raise SystemExit(
                "ERROR: RPC token not found.  Start the node once so it "
                "writes ~/.visold/rpc_token, or check DATA_DIR.")
        return tok

    @classmethod
    def _load_admin_token(cls) -> Optional[str]:
        return cls._read_token_file(
            os.path.join(Config.DATA_DIR, "rpc_admin_token"),
            "admin token")

    # ── JSON-RPC client ───────────────────────────────────────────────────
    @classmethod
    def _rpc_call(cls, rpc_port: int, method: str, params: list,
                  admin: bool = False, timeout: float = 10.0) -> Any:
        """Fire one JSON-RPC request and return the "result" field.

        Raises SystemExit on transport / auth / RPC errors with an exit
        status distinct enough for scripts to branch on.
        """
        try:
            bearer = cls._load_bearer_token()
        except SystemExit:
            raise
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id":      1,
            "method":  method,
            "params":  params,
        }).encode("utf-8")
        url = f"http://127.0.0.1:{int(rpc_port)}/"
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {bearer}")
        if admin:
            admin_tok = cls._load_admin_token()
            if not admin_tok:
                raise SystemExit(
                    "ERROR: admin token not configured on this node "
                    "(~/.visold/rpc_admin_token missing).  Ask the "
                    "operator to enable admin operations.")
            req.add_header("X-Admin-Token", admin_tok)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 – URL is always http://127.0.0.1:{port}/
                raw = resp.read()
        except urllib.error.HTTPError as he:
            body = ""
            try:
                body = he.read().decode("utf-8", "replace")[:256]
            except Exception:
                pass
            raise SystemExit(
                f"ERROR: RPC HTTP {he.code}: {he.reason} {body}")
        except urllib.error.URLError as ue:
            raise SystemExit(
                f"ERROR: cannot connect to RPC at {url} — is the node "
                f"running?  ({ue.reason})")
        try:
            obj = json.loads(raw)
        except Exception as e:
            raise SystemExit(f"ERROR: malformed RPC response: {e}")
        if "error" in obj and obj["error"] is not None:
            err = obj["error"]
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            raise SystemExit(f"ERROR: RPC {method}: {msg}")
        return obj.get("result")

    # ── Subcommand implementations ────────────────────────────────────────
    @classmethod
    def cmd_wallet_create(cls, args) -> int:
        """Generate a keypair and save.  STANDALONE — no RPC needed."""
        if args.out:
            out_path = args.out
        else:
            Config.ensure_dirs()
            out_path = os.path.join(Config.DATA_DIR, "wallet_cli.json")
        if os.path.exists(out_path) and not args.force:
            print(f"ERROR: {out_path} already exists.  Use --force to overwrite.",
                  file=sys.stderr)
            return 2
        w = Wallet.generate()
        try:
            if args.password:
                w.save_keystore(out_path, args.password)
                try:
                    os.chmod(out_path, 0o600)
                except Exception:
                    pass
                print(f"Encrypted keystore written to {out_path}")
            else:
                w.save(out_path)
                try:
                    os.chmod(out_path, 0o600)
                except Exception:
                    pass
                print(f"Plain keystore written to {out_path}")
                print("WARNING: unencrypted keystore — re-run with "
                      "--password to encrypt.")
        except Exception as e:
            print(f"ERROR: cannot write keystore: {e}", file=sys.stderr)
            return 1
        print(f"Address:  {w.address}")
        print(f"Pub key:  {w.pub_hex[:32]}...  ({len(w.pub_hex)} chars)")
        return 0

    @classmethod
    def cmd_status(cls, args) -> int:
        """Display height, L2 root, peer count, and sequencer status."""
        # getchaininfo (existing RPC) + vsd_getL2StateRoot + getpeerinfo
        chain = cls._rpc_call(args.rpc_port, "getchaininfo", [])
        try:
            l2 = cls._rpc_call(args.rpc_port, "vsd_getL2StateRoot", [])
        except SystemExit as e:
            # L2 may be unavailable on an older node; show chain anyway.
            l2 = {"root": "unavailable", "note": str(e)}
        try:
            peers = cls._rpc_call(args.rpc_port, "getpeerinfo", [])
            peer_count = len(peers) if isinstance(peers, list) else 0
        except SystemExit:
            peer_count = 0
        print("── VISOLD NODE STATUS ──────────────────────────────")
        print(f"Chain ID   : {chain.get('chain_id', '?')}")
        print(f"Version    : {chain.get('version', '?')}")
        print(f"Height     : {chain.get('height', '?')}")
        print(f"Difficulty : {chain.get('difficulty', '?')}")
        print(f"Peers      : {peer_count}")
        print(f"L2 root    : {l2.get('root', '?')}")
        if "account_count" in l2:
            print(f"L2 accts   : {l2['account_count']}")
        if "l2_supply_sat" in l2:
            print(f"L2 supply  : {l2['l2_supply_sat']} sat")
            print(f"L1 escrow  : {l2.get('l1_bridge_sat', 0)} sat")
            print(f"Invariant  : {'OK' if l2.get('invariant_ok') else 'MISMATCH'}")
        if "last_batch_id" in l2:
            print(f"Last batch : {l2['last_batch_id']}")
        return 0

    @classmethod
    def cmd_balance(cls, args) -> int:
        addr = cls._validate_address(args.address) if args.address else None
        params = [addr] if addr else []
        r = cls._rpc_call(args.rpc_port, "vsd_getBalance", params)
        print(f"Address : {r['address']}")
        print(f"L1      : {r['l1_vsd']:.8f} VSD  ({r['l1_sat']} sat)")
        print(f"L2      : {r['l2_vsd']:.8f} VSD  ({r['l2_sat']} sat)")
        print(f"L2 nonce: {r['l2_nonce']}")
        return 0

    @classmethod
    def cmd_deposit(cls, args) -> int:
        vsd, sat = cls._parse_amount_vsd(args.amount)
        r = cls._rpc_call(args.rpc_port, "vsd_depositToL2",
                          [vsd, args.memo or ""])
        if r.get("ok"):
            print(f"Deposit initiated: {vsd} VSD ({sat} sat) → L2 bridge")
            print(f"Bridge  : {r.get('bridge')}")
            print(f"Status  : {r.get('msg')}")
            return 0
        print(f"Deposit failed: {r.get('msg')}", file=sys.stderr)
        return 1

    @classmethod
    def cmd_withdraw(cls, args) -> int:
        """L2 → L1 withdrawal via the forced-exit bridge."""
        vsd, sat = cls._parse_amount_vsd(args.amount)
        r = cls._rpc_call(args.rpc_port, "vsd_withdrawFromL2", [vsd])
        if r.get("ok"):
            print(f"Withdrawal complete: {vsd} VSD ({sat} sat) → L1 wallet")
            print(f"Status : {r.get('msg')}")
            return 0
        print(f"Withdrawal failed: {r.get('msg')}", file=sys.stderr)
        return 1

    @classmethod
    def cmd_send_l2(cls, args) -> int:
        """Sign an L2 transaction locally and submit via RPC.

        Signing requires the wallet's private key — the CLI loads it from
        the keystore file (same file format produced by `wallet create`).
        The nonce is fetched from the running node so that the user
        doesn't have to track it manually.
        """
        # Load wallet — prefer explicit --keystore, fall back to node's
        # default location.
        keystore_path = args.keystore or os.path.join(
            Config.DATA_DIR, "wallet.json")
        if not os.path.exists(keystore_path):
            # Try cli-created keystore too.
            alt = os.path.join(Config.DATA_DIR, "wallet_cli.json")
            if os.path.exists(alt):
                keystore_path = alt
            else:
                print(f"ERROR: keystore not found (looked at {keystore_path}, "
                      f"{alt}).  Run `wallet create` or pass --keystore.",
                      file=sys.stderr)
                return 2
        try:
            if args.password:
                wallet = Wallet.load_keystore(keystore_path, args.password)
            else:
                wallet = Wallet.load(keystore_path)
        except Exception as e:
            print(f"ERROR: cannot load keystore: {e}", file=sys.stderr)
            return 1

        to_addr = cls._validate_address(args.to)
        if to_addr == wallet.address:
            print("ERROR: cannot send L2 tx to self", file=sys.stderr)
            return 2
        vsd, sat = cls._parse_amount_vsd(args.amount)

        # Fetch the L2 nonce for this sender.
        bal = cls._rpc_call(args.rpc_port, "vsd_getBalance",
                            [wallet.address])
        nonce = int(bal.get("l2_nonce", 0))
        if sat > int(bal.get("l2_sat", 0)):
            print(f"ERROR: insufficient L2 balance ({bal['l2_sat']} sat available, "
                  f"{sat} sat requested).  Deposit first via `deposit`.",
                  file=sys.stderr)
            return 1

        l2tx = wallet.sign_l2_tx(
            receiver   = to_addr,
            amount_sat = sat,
            nonce      = nonce,
        )
        r = cls._rpc_call(args.rpc_port, "vsd_sendL2Transaction",
                          [l2tx.to_dict()])
        print(f"L2 tx submitted: {l2tx.l2_tx_id}")
        print(f"Amount  : {vsd} VSD ({sat} sat)")
        print(f"From    : {wallet.address}")
        print(f"To      : {to_addr}")
        print(f"Nonce   : {nonce}")
        print(f"Local   : {r.get('accepted_locally')} "
              f"({r.get('sequencer_msg')})")
        print(f"Gossip  : {r.get('gossiped')}")
        return 0 if r.get("ok") else 1

    @classmethod
    def cmd_rollup_trigger(cls, args) -> int:
        """Admin-only: force the sequencer to seal + submit a batch now."""
        r = cls._rpc_call(args.rpc_port, "vsd_triggerManualRollup",
                          [], admin=True)
        if r.get("ok"):
            print(f"Rollup submitted: tx_id={r.get('tx_id')}")
            print(f"Submit msg: {r.get('submit_msg')}")
            return 0
        print(f"Rollup failed: {r.get('msg')}", file=sys.stderr)
        return 1

    # ── Entry point ───────────────────────────────────────────────────────
    @classmethod
    def run(cls, argv: list) -> int:
        """Parse argv and dispatch to the matching subcommand.  Returns
        the process exit code (0 on success)."""
        import argparse

        parser = argparse.ArgumentParser(
            prog="visold --cli",
            description="Visold (VSD) command-line client — L1 + L2 ops")
        parser.add_argument(
            "--rpc-port", type=int,
            default=Config.DEFAULT_PORT + Config.RPC_PORT_OFFSET,
            help=f"JSON-RPC port (default: "
                 f"{Config.DEFAULT_PORT + Config.RPC_PORT_OFFSET})")
        sub = parser.add_subparsers(dest="cmd", required=True,
                                    metavar="COMMAND")

        # wallet ------------------------------------------------------------
        p_w = sub.add_parser("wallet", help="wallet management")
        sub_w = p_w.add_subparsers(dest="wcmd", required=True)
        p_wc = sub_w.add_parser("create",
                                help="generate a new keypair and save")
        p_wc.add_argument("--out", type=str, default=None,
                          help="keystore output path "
                               "(default: ~/.visold/wallet_cli.json)")
        p_wc.add_argument("--password", type=str, default=None,
                          help="encrypt keystore with this password "
                               "(strongly recommended)")
        p_wc.add_argument("--force", action="store_true",
                          help="overwrite existing file")

        # status ------------------------------------------------------------
        sub.add_parser("status", help="display node + L2 status")

        # balance -----------------------------------------------------------
        p_b = sub.add_parser("balance",
                             help="show L1 + L2 balances for an address")
        p_b.add_argument("--address", type=str, default=None,
                         help="address (default: node's own wallet)")

        # send-l2 -----------------------------------------------------------
        p_s = sub.add_parser("send-l2",
                             help="sign and submit an L2 transaction")
        p_s.add_argument("--to", type=str, required=True,
                         help="recipient L1/L2 address")
        p_s.add_argument("--amount", type=str, required=True,
                         help="amount in VSD")
        p_s.add_argument("--keystore", type=str, default=None,
                         help="path to keystore file (default: node's wallet.json)")
        p_s.add_argument("--password", type=str, default=None,
                         help="decrypt keystore (if encrypted)")

        # deposit -----------------------------------------------------------
        p_d = sub.add_parser("deposit",
                             help="transfer L1 VSD into the L2 bridge")
        p_d.add_argument("--amount", type=str, required=True,
                         help="amount in VSD to lock into L2")
        p_d.add_argument("--memo", type=str, default="",
                         help="optional memo")

        # withdraw ----------------------------------------------------------
        p_wd = sub.add_parser("withdraw",
                              help="withdraw L2 VSD back to your L1 wallet")
        p_wd.add_argument("--amount", type=str, required=True,
                          help="amount in VSD to withdraw from L2")

        # rollup-trigger (admin) --------------------------------------------
        p_r = sub.add_parser("rollup-trigger",
                             help="[admin] force immediate rollup settlement")

        args = parser.parse_args(argv)

        if args.cmd == "wallet" and args.wcmd == "create":
            return cls.cmd_wallet_create(args)
        if args.cmd == "status":
            return cls.cmd_status(args)
        if args.cmd == "balance":
            return cls.cmd_balance(args)
        if args.cmd == "send-l2":
            return cls.cmd_send_l2(args)
        if args.cmd == "deposit":
            return cls.cmd_deposit(args)
        if args.cmd == "withdraw":
            return cls.cmd_withdraw(args)
        if args.cmd == "rollup-trigger":
            return cls.cmd_rollup_trigger(args)
        parser.print_help()
        return 2
