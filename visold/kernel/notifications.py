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

import threading
from collections import deque
from datetime import datetime


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


def _pa_push(dir_: str, ip: str, port: int, status: str) -> None:
    """Append one peer-activity entry (thread-safe, never raises)."""
    # BUG-FIX: removed inner `from datetime import datetime as _dt` that shadowed
    # the module-level alias and re-imported on every call. Use module-level datetime.
    try:
        with _peer_activity_lock:
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
        mshort  = (miner[:12] + "...") if len(miner) > 12 else miner
        entry   = f'[{ts}|INF] ⛏ Block #{height} mined [{origin}] by {mshort}'
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
        addr  = f"{ip}:{port}"
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
        pid   = (peer_id[:12] + "…") if peer_id and len(peer_id) > 12 else (peer_id or "?")
        entry = (f'[{ts}|INF] ⇄ Sync req from {pid}: '
                 f'blocks {from_idx}-{to_idx} (served {blocks_sent})')
        with _notify_buf_lock:
            _notify_buf.append(entry)
    except Exception:
        pass
