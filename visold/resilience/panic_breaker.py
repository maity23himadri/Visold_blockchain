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
"""visold.resilience.panic_breaker

Original section: SECTION 17B: PANIC CIRCUIT BREAKER — WATCHDOG & SELF-HEALING

Defines: PanicCircuitBreaker
Origin: visold_vsd_.py L41695-41860
"""

import threading
import time
from collections import deque
from typing import Optional, Tuple

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 17B: PANIC CIRCUIT BREAKER — WATCHDOG & SELF-HEALING
# Automatically puts the node into "Read-Only" mode when a critical
# consistency error is detected, preventing corrupted data from spreading.
# ─────────────────────────────────────────────────────────────────────────────
class PanicCircuitBreaker:
    """
    Watchdog and self-healing circuit breaker for critical node errors.

    States
    ──────
    CLOSED  (normal)  — all operations permitted; monitoring active
    OPEN    (tripped) — node is in Read-Only mode; all state mutations
                        blocked; mining stopped; peers notified

    Trip conditions
    ───────────────
    The circuit breaker trips automatically when any of these occur:
      • SafetyInvariantChecker reports ≥ Config.CIRCUIT_BREAKER_VIOLATIONS
        invariant violations in a rolling window
      • Chain linkage is broken (prev_hash mismatch detected)
      • Double-finality: two blocks finalized at same height

    Read-Only mode effects
    ──────────────────────
    • Mining is paused (MiningEngine.pause())
    • StateEngine drops all NEW_BLOCK and MINE_RESULT events
    • P2P block propagation is suppressed (node acts as watcher only)
    • RPC still responds to read-only methods (getblock, getbalance, etc.)
    • An alert is logged at CRITICAL level every ALERT_INTERVAL seconds

    Recovery
    ────────
    An operator must manually reset the circuit breaker via the RPC
    method 'resetcircuitbreaker' after investigating and resolving the
    root cause.  Auto-reset is intentionally NOT provided — a human
    must confirm safety before resuming writes.

    Thread safety: all state changes are protected by a lock.
    """

    CLOSED  = "CLOSED"
    OPEN    = "OPEN"

    ALERT_INTERVAL   = 60    # seconds between repeated CRITICAL log alerts
    VIOLATION_WINDOW = 300   # seconds: rolling window for violation count

    def __init__(self, mining_engine=None, state_engine=None):
        self._lock          = threading.Lock()
        self._state         = self.CLOSED
        self._trip_reason   = ""
        self._trip_time     = 0.0
        self._violation_log: deque = deque(maxlen=50)  # (timestamp, reason)
        self._alert_thread: Optional[threading.Thread] = None
        self._stop_evt      = threading.Event()
        self._mining        = mining_engine   # injected after construction
        self._state_engine  = state_engine    # injected after construction
        self._last_alert    = 0.0

    def inject(self, mining_engine, state_engine):
        """Inject references after construction (avoids circular deps)."""
        self._mining       = mining_engine
        self._state_engine = state_engine

    # ── State queries ─────────────────────────────────────────────────────────

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._state == self.OPEN

    @property
    def is_closed(self) -> bool:
        return not self.is_open

    def state(self) -> str:
        with self._lock:
            return self._state

    def trip_info(self) -> dict:
        with self._lock:
            return {
                "state":       self._state,
                "trip_reason": self._trip_reason,
                "trip_time":   self._trip_time,
                "violations":  list(self._violation_log),
            }

    # ── Trip (open the breaker) ───────────────────────────────────────────────

    def record_violation(self, reason: str):
        """
        Record a safety violation.  If the violation count in the rolling
        window exceeds Config.CIRCUIT_BREAKER_VIOLATIONS, trip the breaker.
        """
        if not Config.CIRCUIT_BREAKER_ENABLED:
            return
        now = time.time()
        with self._lock:
            self._violation_log.append((now, reason))
            # Count violations in the rolling window
            cutoff = now - self.VIOLATION_WINDOW
            recent = sum(1 for ts, _ in self._violation_log if ts >= cutoff)
            if (self._state == self.CLOSED and
                    recent >= Config.CIRCUIT_BREAKER_VIOLATIONS):
                self._trip(reason)

    def _trip(self, reason: str):
        """Internal: actually trip the circuit breaker (must hold lock)."""
        self._state       = self.OPEN
        self._trip_reason = reason
        self._trip_time   = time.time()
        log.critical(
            f"🔴 CIRCUIT BREAKER TRIPPED — NODE IN READ-ONLY MODE\n"
            f"   Reason: {reason}\n"
            f"   Mining and block writes are SUSPENDED.\n"
            f"   Run 'checkinvariants' to diagnose, then 'resetcircuitbreaker' to resume.")
        metrics.inc("circuit_breaker_trips")
        # Pause mining without holding our lock (MiningEngine has its own lock)
        if self._mining:
            try:
                self._mining.pause()
            except Exception:
                pass
        if not self._alert_thread or not self._alert_thread.is_alive():
            self._alert_thread = threading.Thread(
                target=self._alert_loop, daemon=True, name="circuit-breaker-alert")
            self._alert_thread.start()

    def _alert_loop(self):
        """Periodically emit CRITICAL alerts while the breaker is open."""
        while self.is_open and not self._stop_evt.wait(self.ALERT_INTERVAL):
            log.critical(
                f"🔴 CIRCUIT BREAKER STILL OPEN — node in Read-Only mode. "
                f"Reason: {self._trip_reason}")

    # ── Reset (close the breaker) ─────────────────────────────────────────────

    def reset(self, authorized_by: str = "operator") -> Tuple[bool, str]:
        """
        Manually reset the circuit breaker.  Only allowed by authenticated
        RPC callers (bearer token required).
        """
        with self._lock:
            if self._state == self.CLOSED:
                return False, "Circuit breaker is already CLOSED"
            self._state       = self.CLOSED
            self._trip_reason = ""
            self._violation_log.clear()
        # Resume mining
        if self._mining:
            try:
                self._mining.resume()
            except Exception:
                pass
        log.warning(
            f"⚠️  Circuit breaker RESET by {authorized_by}. "
            f"Node resuming normal operation. Monitor carefully.")
        metrics.inc("circuit_breaker_resets")
        return True, "Circuit breaker CLOSED — node resumed normal operation"

    def check_allows_write(self) -> Tuple[bool, str]:
        """Return (True, "") if writes are allowed, (False, reason) if not."""
        if self.is_open:
            return False, (
                f"Circuit breaker OPEN (Read-Only mode). "
                f"Reason: {self._trip_reason}")
        return True, ""

    def stop(self):
        self._stop_evt.set()
