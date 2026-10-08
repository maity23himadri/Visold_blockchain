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
"""visold.network.message_logger

Original section: SECTION 13B: P2P MESSAGE LOGGER  (symmetric inbound + outbound visibility)

Defines: P2PMessageLogger
Origin: visold_vsd_.py L31653-31809, L31815-31822
"""

import json
import os
import threading
from collections import Counter

from visold.kernel.logging_setup import log


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 13B: P2P MESSAGE LOGGER  (symmetric inbound + outbound visibility)
# ─────────────────────────────────────────────────────────────────────────────
# Disabled by default.  Activate at runtime via one of:
#
#     P2PMessageLogger.enable()                  # compact one line per message
#     P2PMessageLogger.enable(verbose=True)      # also include payload preview
#     P2PMessageLogger.disable()                 # silence
#
# Or at startup via environment variable:
#
#     export VISOLD_P2P_LOG=1         → compact mode
#     export VISOLD_P2P_LOG=verbose   → verbose mode
#
# Output format (compact):
#     [P2P →] <peer_id_prefix>  <MSG_TYPE>  <size>B
#     [P2P ←] <peer_id_prefix>  <MSG_TYPE>  <size>B
#
# Verbose mode appends a 160-character payload preview (sensitive fields such
# as signatures and private keys are redacted).  Counters are maintained per
# direction and per message type and can be inspected via
# P2PMessageLogger.stats().
# ─────────────────────────────────────────────────────────────────────────────
class P2PMessageLogger:
    """Thread-safe symmetric P2P message logger.  Zero overhead when disabled
    (a single attribute read returns False and the call returns immediately)."""

    _enabled: bool = False
    _verbose: bool = False
    _lock = threading.Lock()
    _counts_out: "Counter" = Counter()
    _counts_in:  "Counter" = Counter()
    _bytes_out:  int = 0
    _bytes_in:   int = 0

    # Fields scrubbed from the verbose payload preview.  Added to the set
    # rather than removed because leaking any of these to a shared log file
    # is a security regression — not a feature request.
    _REDACT_KEYS = frozenset((
        "signature", "sig", "privkey", "private_key", "secret",
        "password", "passphrase", "challenge_resp", "pow_nonce_reveal",
    ))

    @classmethod
    def enable(cls, verbose: bool = False) -> None:
        with cls._lock:
            cls._enabled = True
            cls._verbose = bool(verbose)
        try:
            log.info(
                "[P2P] message logger enabled (verbose={})".format(bool(verbose)))
        except Exception:
            pass

    @classmethod
    def disable(cls) -> None:
        with cls._lock:
            cls._enabled = False
            cls._verbose = False
        try:
            log.info("[P2P] message logger disabled")
        except Exception:
            pass

    @classmethod
    def is_enabled(cls) -> bool:
        return cls._enabled

    @classmethod
    def log_out(cls, peer, msg, size_bytes) -> None:
        """Record an outbound frame.  Called from PeerConnection.send."""
        if not cls._enabled:
            return
        try:
            cls._emit("→", peer, msg, size_bytes, outbound=True)
        except Exception:
            # Logging MUST NOT raise out of the send path.
            pass

    @classmethod
    def log_in(cls, peer, msg, size_bytes) -> None:
        """Record an inbound frame.  Called from _peer_message_loop."""
        if not cls._enabled:
            return
        try:
            cls._emit("←", peer, msg, size_bytes, outbound=False)
        except Exception:
            pass

    @classmethod
    def _emit(cls, arrow, peer, msg, size_bytes, outbound):
        mtype = ""
        try:
            mtype = str(msg.get("type", "") if isinstance(msg, dict) else "")
        except Exception:
            mtype = "?"
        if not mtype:
            mtype = "UNKNOWN"

        peer_tag = "?"
        try:
            pid = getattr(peer, "peer_id", "") or ""
            if pid:
                peer_tag = pid[:12]
            else:
                peer_tag = "{}:{}".format(
                    getattr(peer, "host", "?"), getattr(peer, "port", "?"))
        except Exception:
            pass

        # Update counters atomically so stats() is always consistent.
        with cls._lock:
            if outbound:
                cls._counts_out[mtype] += 1
                cls._bytes_out += int(size_bytes or 0)
            else:
                cls._counts_in[mtype] += 1
                cls._bytes_in += int(size_bytes or 0)
            verbose = cls._verbose

        line = "[P2P {}] {:<14} {:<22} {}B".format(
            arrow, peer_tag, mtype, size_bytes)

        if verbose and isinstance(msg, dict):
            preview = cls._redacted_preview(msg)
            line = "{}  {}".format(line, preview)

        try:
            log.info(line)
        except Exception:
            # Last-resort fallback when the logger is not yet initialised.
            try:
                print(line)
            except Exception:
                pass

    @classmethod
    def _redacted_preview(cls, msg: dict) -> str:
        try:
            safe = {}
            for k, v in msg.items():
                if k in cls._REDACT_KEYS:
                    safe[k] = "<redacted>"
                elif isinstance(v, (dict, list)):
                    # Collapse nested structures to a short marker so one huge
                    # MSG_CHAIN does not flood the log.
                    safe[k] = "<{}:{} items>".format(
                        type(v).__name__,
                        len(v) if hasattr(v, "__len__") else "?")
                else:
                    s = str(v)
                    safe[k] = s if len(s) <= 48 else s[:45] + "..."
            preview = json.dumps(safe, sort_keys=True, separators=(",", ":"))
            return preview if len(preview) <= 160 else preview[:157] + "..."
        except Exception:
            return "<preview_error>"

    @classmethod
    def stats(cls) -> dict:
        """Return a snapshot of per-direction per-type counters."""
        with cls._lock:
            return {
                "enabled":    cls._enabled,
                "verbose":    cls._verbose,
                "bytes_out":  cls._bytes_out,
                "bytes_in":   cls._bytes_in,
                "count_out":  dict(cls._counts_out),
                "count_in":   dict(cls._counts_in),
                "total_out":  sum(cls._counts_out.values()),
                "total_in":   sum(cls._counts_in.values()),
            }

    @classmethod
    def reset(cls) -> None:
        """Zero all counters.  Does not change enabled/verbose state."""
        with cls._lock:
            cls._counts_out.clear()
            cls._counts_in.clear()
            cls._bytes_out = 0
            cls._bytes_in  = 0


# Auto-enable from environment variable so operators can turn logging on
# without touching code.  Checked at import time; runtime changes are still
# possible via enable()/disable().
try:
    _p2p_log_env = os.environ.get("VISOLD_P2P_LOG", "").strip().lower()
    if _p2p_log_env in ("1", "true", "yes", "on"):
        P2PMessageLogger.enable(verbose=False)
    elif _p2p_log_env in ("2", "verbose", "debug", "full"):
        P2PMessageLogger.enable(verbose=True)
except Exception:
    pass
