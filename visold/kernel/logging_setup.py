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
"""visold.kernel.logging_setup

Original section: SECTION 1D (EARLY): STRUCTURED LOGGING FORMATTER  (Problem #11)

Origin: visold_vsd_.py L3595-3606, L3629, L3736-3769, L3772-3785, L3788-3793, L3796-3814
"""

import json
import logging
import os
import queue
from datetime import datetime

from visold.kernel.notifications import _notify_buf, _notify_buf_lock


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1D (EARLY): STRUCTURED LOGGING FORMATTER  (Problem #11)
# Must be defined BEFORE the logging-handler setup below so that the
# JSON formatter can be instantiated when VISOLD_LOG_FORMAT=json is set
# at import time.  The full class docstring is retained in Section 1D.
# ─────────────────────────────────────────────────────────────────────────────
class _StructuredFormatter(logging.Formatter):
    """Emit log records as JSON lines when LOG_FORMAT=json."""
    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "ts":      self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     record.getMessage(),
        }
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj)


# Thread-safe queue used to decouple background log output from the
# foreground input() prompt.  Background threads (mining, P2P) push
# formatted log lines here; the CLI drains and prints them *before*
# each input() call so they never interleave with user keystrokes.
#
# AUDIT-FIX-J3: this queue previously had no maxsize. It's attached to
# the ROOT logger (every log.*() call anywhere in the process feeds
# it), and its only consumer, _flush_log_queue(), runs solely from
# inside CLI's input()-driven loop — once per keypress. But the CLI is
# explicitly designed to be left open and watched live via its own
# background refresh thread, which updates the dashboard without
# input() ever returning. For as long as an operator does exactly
# that — the tool's intended usage — nothing drained this queue, so it
# grew without bound for the whole idle/watching duration.
# _QueueHandler.emit() already uses put_nowait() wrapped in a bare
# except-Exception (queue.Full included), so bounding it here is
# enough on its own: once full, new entries are dropped exactly the
# way _flush_log_queue() already discards them unread — this queue's
# only real purpose (see its docstring below) — so behaviour for the
# operator is unchanged, just capped.
_log_queue: queue.Queue = queue.Queue(maxsize=10000)


class _QueueHandler(logging.Handler):
    """Logging handler that routes records to _log_queue for deferred printing."""
    def emit(self, record: logging.LogRecord):
        try:
            # AUDIT-FIX-J3: _log_queue is now bounded (see its definition
            # above), so put_nowait() can raise queue.Full. That must not
            # abort the rest of this method — the _notify_buf update
            # below is the mechanism the live dashboard actually reads
            # from, and has nothing to do with _log_queue filling up.
            try:
                _log_queue.put_nowait(self.format(record))
            except queue.Full:
                pass
            # Also push a compact entry to the live notification ring-buffer
            # so the UI refresh thread can surface it immediately, without
            # waiting for the main thread to call _flush_log_queue().
            if record.levelno >= logging.INFO:
                ts    = datetime.now().strftime('%H:%M:%S')
                short = record.getMessage()[:72]
                # Severity tag embedded so _fmt_notif() can colour-code it
                if record.levelno >= logging.ERROR:
                    sev = 'ERR'
                elif record.levelno >= logging.WARNING:
                    sev = 'WRN'
                else:
                    sev = 'INF'
                # BUG-FIX: use _notify_buf_lock for thread safety (consistent
                # with _peer_activity_buf which uses _peer_activity_lock).
                with _notify_buf_lock:
                    _notify_buf.append(f'[{ts}|{sev}] {short}')
        except Exception:
            pass  # never let a logging failure crash a background thread


_queue_handler = _QueueHandler()


# Choose formatter based on LOG_FORMAT env var (set before Config.ensure_dirs)
_log_format = os.environ.get("VISOLD_LOG_FORMAT", "text")


if _log_format == "json":
    _queue_handler.setFormatter(_StructuredFormatter())
else:
    _queue_handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))


logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)


# Remove the default StreamHandler added by basicConfig and replace it with
# our queue-backed handler so all background output is deferred.
root_logger = logging.getLogger()


for _h in list(root_logger.handlers):
    root_logger.removeHandler(_h)


root_logger.addHandler(_queue_handler)


log = logging.getLogger("VISOLD")


def _flush_log_queue():
    """
    Drain all pending log messages from the queue (without printing).

    Log records are already routed to _notify_buf by _QueueHandler.emit()
    and displayed live in the dashboard's "Recent Activity" panel via
    _redraw_live() / _full_render().  Printing them to stdout here would
    corrupt the terminal layout because the cursor position after an ANSI
    cursor-restore sequence (\033[u) is mid-screen, not at the bottom.

    This function MUST stay a no-print drain so the caller can safely
    call os.system('cls'/'clear') immediately afterward without garbage
    lines appearing above the fresh dashboard.
    """
    while True:
        try:
            _log_queue.get_nowait()   # discard — dashboard panel is the display
        except queue.Empty:
            break
