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
"""visold.kernel.notifications


Origin: visold_vsd_.py L3636, L3641, L3653-3690, L3693-3711, L3714-3733
"""

import re
import threading
from collections import deque
from datetime import datetime

_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]+")


def _sanitize_notif_text(value: object, max_len: int = 0) -> str:
    """Strip ANSI escape sequences and control characters for single-line TUI rows."""
    text = str(value) if value is not None else ""
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _CONTROL_CHAR_RE.sub(" ", text).strip()
    if max_len > 0:
        return text[:max_len]
    return text


# Ring-buffer for the "Recent Activity" panel + scrollable Activity tab.
# Holds up to 500 entries; the compact dashboard shows only the last few,
# while the full-screen Activity tab lets the user page through all of them.
# Background threads write here via _QueueHandler.emit(); the UI refresh
# thread reads it without touching the main thread.
_notify_buf: deque = deque(maxlen=500)


# BUG-FIX: _notify_buf is written from multiple background threads (logging
# handlers). CPython's GIL makes deque.append atomic in practice, but for
# correctness and portability (Jython, PyPy) we protect it with a lock,
# consistent with _peer_activity_buf which already uses _peer_activity_lock.
_notify_buf_lock = threading.Lock()


# ── Peer Activity ring-buffer ─────────────────────────────────────────────────
# Captures every outbound connection request and inbound connection attempt with
# direction, IP, port, and outcome.  Written from _try_add_peer and
# _handle_inbound; read by the dashboard refresh thread and the Activity tab.
# Each entry is a dict:
#   ts      str   HH:MM:SS
#   dir     str   'OUT' (we dialled) or 'IN' (they dialled us)
#   ip      str   remote IP
#   port    int   remote port
#   status  str   CONNECTING | CONNECTED | REJECTED | FAILED | BANNED
_peer_activity_buf: deque = deque(maxlen=500)


_peer_activity_lock = threading.Lock()
_peer_activity_last_status: dict = {}


def _pa_push(dir_: str, ip: str, port: int, status: str) -> None:
    """Append one peer-activity entry, collapsing repeated cooldown notices.

    A reconnect/PEX tick can inspect the same cooling-down endpoint many times.
    Those checks are not new network events, so keep only the first COOLDOWN row
    until the endpoint changes state again. Other status transitions (including
    a new CONNECTING/FAILED cycle) remain visible.
    """
    # BUG-FIX: removed inner `from datetime import datetime as _dt` that shadowed
    # the module-level alias and re-imported on every call. Use module-level datetime.
    try:
        with _peer_activity_lock:
            key = (str(dir_), str(ip).casefold(), int(port))
            previous = _peer_activity_last_status.get(key)
            if status == "COOLDOWN" and previous == "COOLDOWN":
                return
            _peer_activity_last_status[key] = status
            # Bound metadata independently from the ring buffer so a long-lived
            # node discovering many transient endpoints cannot grow without end.
            if len(_peer_activity_last_status) > 2048:
                _peer_activity_last_status.pop(next(iter(_peer_activity_last_status)))
            _peer_activity_buf.append({
                "ts":     datetime.now().strftime("%H:%M:%S"),
                "dir":    dir_,
                "ip":     ip,
                "port":   port,
                "status": status,
            })
    except Exception:
        pass


def _push_block_notif(height: int, miner: str, source: str = "network") -> None:
    """Push an instant block-mined notification to the live Recent Activity panel.

    Called immediately when any block is accepted — either mined locally
    (source='local') or received from a peer (source='network').  This fires
    independently of the logging pipeline so the dashboard updates within the
    same second the event occurs, rather than waiting for the next refresh tick.

    Thread-safe; never raises.
    """
    try:
        ts      = datetime.now().strftime('%H:%M:%S')
        origin  = "YOU" if source == "local" else "NET"
        clean_miner = _sanitize_notif_text(miner)
        mshort  = (clean_miner[:12] + "...") if len(clean_miner) > 12 else clean_miner
        entry   = f'[{ts}|INF] ⛏ Block #{int(height)} mined [{origin}] by {mshort}'
        with _notify_buf_lock:
            _notify_buf.append(entry)
    except Exception:
        pass


def _push_incoming_transfer_notif(sender_label: str, sender_address: str,
                                 amount_vsd: float) -> None:
    """Push a just-admitted incoming VSD transfer to the live activity panel.

    The caller must invoke this only after the transaction has successfully
    entered the local mempool.  This is an *unconfirmed* notification, not a
    payment receipt; confirmation is determined from the canonical chain.
    Sender-provided memos are deliberately not displayed here.
    """
    try:
        ts = datetime.now().strftime("%H:%M:%S")
        label = _sanitize_notif_text(sender_label or "", max_len=32)
        address = _sanitize_notif_text(sender_address or "", max_len=24)
        entry = (f"[{ts}|INF] ↓ Incoming transfer: {label} ({address}) sent you "
                 f"{float(amount_vsd):.8f} VSD — NOT CONFIRMED")
        with _notify_buf_lock:
            _notify_buf.append(entry)
    except Exception:
        pass


def _push_peer_notif(event: str, ip: str, port: int) -> None:
    """Push an instant peer connection/disconnection notification to the live panel.

    Called immediately on peer connect and disconnect so the dashboard reflects
    network topology changes without waiting for a full redraw.

    Thread-safe; never raises.
    """
    try:
        ts    = datetime.now().strftime('%H:%M:%S')
        clean_ip = _sanitize_notif_text(ip, max_len=64)
        addr  = f"{clean_ip}:{int(port)}"
        if event == "connected":
            entry = f'[{ts}|INF] ● Peer connected: {addr}'
        else:
            entry = f'[{ts}|INF] ○ Peer disconnected: {addr}'
        with _notify_buf_lock:
            _notify_buf.append(entry)
    except Exception:
        pass


def _push_sync_request_notif(peer_id: str, from_idx: int, to_idx: int,
                             blocks_sent: int) -> None:
    """Push an instant notification for an INBOUND chain-sync request.

    Called from the MSG_GET_CHAIN inbound handler each time a peer asks this
    node to serve a range of blocks.  Surfaces the event in the dashboard's
    "Recent Activity" panel so the operator can see in real time which peers
    are syncing from their node and how many blocks were served per request.

    Thread-safe; never raises.
    """
    try:
        ts    = datetime.now().strftime('%H:%M:%S')
        clean_pid = _sanitize_notif_text(peer_id or "")
        pid   = (clean_pid[:12] + "…") if clean_pid and len(clean_pid) > 12 else (clean_pid or "?")
        entry = (f'[{ts}|INF] ⇄ Sync req from {pid}: '
                 f'blocks {int(from_idx)}-{int(to_idx)} (served {int(blocks_sent)})')
        with _notify_buf_lock:
            _notify_buf.append(entry)
    except Exception:
        pass
