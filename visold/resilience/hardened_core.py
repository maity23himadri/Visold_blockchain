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
"""visold.resilience.hardened_core

Original section: SECTION 17B-HARD: HARDENED CORE OVERLAY

Defines: HardenedBaseError, ImmediateAbort, InvariantViolation, StateRootMismatch, ConservationViolation, TimestampAnomalyError, RecursionLimitExceeded, SystemInvariantGate ...
Origin: visold_vsd_.py L41881-41895, L41900-41901, L41904-41907, L41910-41929, L41932-41940, L41946-42128, L42131, L42134-42201, L42204, L42207-42348, L42351, L42354-42437, L42440-42547, L42550-42593, L42596-42718, L42721-42744, L42747-42753, L42756-42763, L42766-42775, L42778-42878
"""

import contextlib
import functools
import os
import resource
import sys
import threading
import time
import enum as _hc_enum
from typing import Any, Dict, List, Optional, Set, Tuple

from visold.kernel.compat import _NTPLIB_AVAILABLE, _ntplib
from visold.kernel.logging_setup import log


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 17B-HARD: HARDENED CORE OVERLAY
#  Security Engineering Layer: Absolute Stability & State Integrity
#
#  Six orthogonal safety layers injected at node startup via
#  apply_hardened_overlay(blockchain_instance):
#    1. _HardenedCBSingleton  — NORMAL / READ_ONLY / SAFE_SHUTDOWN state machine
#    2. SystemInvariantGate   — pre-condition checks (no write before verify)
#    3. AtomicStateTransition — Prepare → Verify → Commit pattern
#    4. _NTPClock             — NTP-median deterministic clock
#    5. ResourceCap           — memory ceilings, recursion guards, timeouts
#    6. GracefulDegradation   — secondary component isolation
#
#  All patches are instance-level — zero class-level mutations.
#  This section is self-contained; it references only stdlib + _ntplib.
# ─────────────────────────────────────────────────────────────────────────────

# ── Hardened constants ────────────────────────────────────────────────────────
_HC_MAX_BALANCE_SAT: int         = 21_000_000 * 100_000_000


_HC_MAX_SATOSHI_SUPPLY: int      = _HC_MAX_BALANCE_SAT


_HC_MIN_TIMESTAMP_UNIX: int      = 1_600_000_000


_HC_MAX_TIMESTAMP_DRIFT_SEC: int = 7_200


_HC_MAX_BLOCK_TX_COUNT: int      = 10_000


_HC_MAX_RECURSION_DEPTH: int     = 64


_HC_MAX_HEAP_MB: int             = 2_048


_HC_CB_FAILURE_THRESHOLD: int    = 5


_HC_CB_HALF_OPEN_DELAY_SEC: float = 60.0


_HC_NTP_SERVERS: List[str]       = ["pool.ntp.org", "time.cloudflare.com",
                                     "time.google.com", "time.apple.com"]


_HC_NTP_SAMPLE_COUNT: int        = 4


_HC_NTP_REFRESH_INTERVAL: int    = 300


_HC_NTP_MAX_DRIFT_SEC: float     = 1.5


_HC_OP_TIMEOUT_SEC: float        = 30.0


# FIX-4: Corruption event window.  Only corruption-level events that occur
# within _HC_CORRUPTION_WINDOW_SEC of each other count toward the trip
# threshold.  A single isolated state-root mismatch ages out and does NOT
# permanently sensitise the node to shutdown.
_HC_CORRUPTION_WINDOW_SEC: float = 300.0   # 5-minute rolling window


_HC_CORRUPTION_TRIP_COUNT: int   = 2       # shutdown after 2 within window


# ── Hardened system mode enum ─────────────────────────────────────────────────
class _HardenedSystemMode(_hc_enum.Enum):
    NORMAL        = "NORMAL"
    READ_ONLY     = "READ_ONLY"
    SAFE_SHUTDOWN = "SAFE_SHUTDOWN"


# ── Hardened exception hierarchy ──────────────────────────────────────────────
class HardenedBaseError(RuntimeError):
    """Base for all hardened-layer exceptions."""


class ImmediateAbort(HardenedBaseError):
    """Non-recoverable: raised when a system invariant is violated BEFORE any write."""


class InvariantViolation(HardenedBaseError):
    """Raised when a mathematical/consensus invariant check fails."""


class StateRootMismatch(InvariantViolation):
    """Expected state root != computed state root after apply."""


class ConservationViolation(InvariantViolation):
    """sum(balances) + burned != total_issued."""


class TimestampAnomalyError(InvariantViolation):
    """Block or transaction timestamp outside acceptable bounds."""


class RecursionLimitExceeded(ImmediateAbort):
    """VVM call depth or Python recursion ceiling reached."""


# ── Circuit-breaker record ────────────────────────────────────────────────────
class _HCCircuitBreakerRecord:
    __slots__ = ("failure_count", "last_failure_ts", "last_failure_msg",
                 "tripped_at", "half_open_attempts")
    def __init__(self):
        self.failure_count: int      = 0
        self.last_failure_ts: float  = 0.0
        self.last_failure_msg: str   = ""
        self.tripped_at: float       = 0.0
        self.half_open_attempts: int = 0


# ── _HardenedCBSingleton ──────────────────────────────────────────────────────
# Distinct from the existing PanicCircuitBreaker (CLOSED/OPEN state machine).
# This singleton provides NORMAL → READ_ONLY → SAFE_SHUTDOWN transitions and
# is wired into apply_block, debit_sat, and credit_sat.
class _HardenedCBSingleton:
    """
    Node-wide hardened circuit breaker (singleton).

    State machine
    ─────────────
    NORMAL → READ_ONLY  when:
        • Any subsystem exceeds _HC_CB_FAILURE_THRESHOLD failures.
        • A CORRUPTION-level invariant violation occurs.
    READ_ONLY → SAFE_SHUTDOWN if:
        • A second corruption violation occurs while already in READ_ONLY.
        • Operator calls force_shutdown().
    """
    _instance: Optional['_HardenedCBSingleton'] = None
    _class_lock: threading.Lock = threading.Lock()

    # Instance attributes set in __new__ — declared here for mypy
    _mode: '_HardenedSystemMode'
    _mode_lock: threading.RLock
    _subsystems: Dict[str, '_HCCircuitBreakerRecord']
    _mode_change_callbacks: List
    _corruption_count: int
    _corruption_timestamps: List[float]

    def __new__(cls) -> '_HardenedCBSingleton':
        with cls._class_lock:
            if cls._instance is None:
                inst = object.__new__(cls)
                inst._mode = _HardenedSystemMode.NORMAL  # type: ignore[misc]
                inst._mode_lock = threading.RLock()  # type: ignore[misc]
                inst._subsystems: Dict[str, _HCCircuitBreakerRecord] = {}  # type: ignore[misc]
                inst._mode_change_callbacks: List = []  # type: ignore[misc]
                inst._corruption_count: int = 0  # type: ignore[misc]
                # FIX-4: rolling list of monotonic timestamps for corruption
                # events within the active window.  Replaces the bare counter
                # so stale events age out and don't cause spurious shutdown.
                inst._corruption_timestamps: List[float] = []  # type: ignore[misc]
                cls._instance = inst
            return cls._instance

    @property
    def mode(self) -> _HardenedSystemMode:
        return self._mode

    def is_writable(self) -> bool:
        return self._mode == _HardenedSystemMode.NORMAL

    def assert_writable(self, context: str = "") -> None:
        if self._mode != _HardenedSystemMode.NORMAL:
            raise ImmediateAbort(
                f"[HCB] Write rejected — system is in {self._mode.value} mode. "
                f"Context: {context}")

    def record_failure(self, subsystem: str, error: Exception,
                       corruption_level: bool = False) -> None:
        with self._mode_lock:
            rec = self._subsystems.setdefault(subsystem, _HCCircuitBreakerRecord())
            rec.failure_count      += 1
            rec.last_failure_ts     = time.monotonic()
            rec.last_failure_msg    = str(error)[:256]
            if corruption_level:
                # FIX-4: Count only corruption events that fall within the
                # _HC_CORRUPTION_WINDOW_SEC time window.  A single transient
                # state-root mismatch (e.g. caused by a late-arriving block
                # during a momentary fork) previously incremented
                # _corruption_count permanently; any second corruption event
                # (even days later) then triggered SAFE_SHUTDOWN.  The fix
                # ages-out old corruption events so isolated incidents don't
                # permanently sensitise the node.
                now_mt = time.monotonic()
                # Evict timestamps older than the rolling window.
                self._corruption_timestamps = [
                    t for t in self._corruption_timestamps
                    if now_mt - t <= _HC_CORRUPTION_WINDOW_SEC
                ]
                self._corruption_timestamps.append(now_mt)
                self._corruption_count = len(self._corruption_timestamps)
                log.critical("[HCB] CORRUPTION-level error in %s "
                             "(window_count=%d/%d): %s",
                             subsystem, self._corruption_count,
                             _HC_CORRUPTION_TRIP_COUNT, error)
                new_mode = (_HardenedSystemMode.SAFE_SHUTDOWN
                            if self._corruption_count >= _HC_CORRUPTION_TRIP_COUNT or
                               self._mode == _HardenedSystemMode.READ_ONLY
                            else _HardenedSystemMode.READ_ONLY)
                self._transition(new_mode, f"CORRUPTION in {subsystem}: {error}")
                return
            if rec.failure_count >= _HC_CB_FAILURE_THRESHOLD:
                rec.tripped_at = time.monotonic()
                log.critical("[HCB] Circuit breaker TRIPPED for '%s' after %d failures. "
                             "→ READ_ONLY.", subsystem, rec.failure_count)
                self._transition(_HardenedSystemMode.READ_ONLY,
                                 f"CB trip: {subsystem} @ {rec.failure_count} failures")
            else:
                log.warning("[HCB] %s failure %d/%d: %s",
                            subsystem, rec.failure_count, _HC_CB_FAILURE_THRESHOLD, error)

    def record_success(self, subsystem: str) -> None:
        with self._mode_lock:
            if subsystem in self._subsystems:
                rec = self._subsystems[subsystem]
                rec.failure_count = 0
                rec.half_open_attempts += 1
            # FIX-4: prune stale corruption timestamps on every success.
            now_mt = time.monotonic()
            self._corruption_timestamps = [
                t for t in self._corruption_timestamps
                if now_mt - t <= _HC_CORRUPTION_WINDOW_SEC
            ]
            self._corruption_count = len(self._corruption_timestamps)
            # BUG-FIX (sync-fix-5): _HC_CB_HALF_OPEN_DELAY_SEC and
            # half_open_attempts were defined but never wired into any
            # recovery logic. record_success() cleared failure_count but
            # never restored NORMAL mode, so once READ_ONLY was entered it
            # was permanent -- every apply_block raised '[HCB] Write rejected'.
            # Fix: after clearing failures, if ALL subsystems are below
            # threshold, no corruption events exist in the window, and the
            # half-open delay has elapsed, auto-restore to NORMAL.
            # SAFE_SHUTDOWN is never auto-recovered (operator must act).
            if self._mode == _HardenedSystemMode.READ_ONLY:
                all_clear = not any(
                    r.failure_count >= _HC_CB_FAILURE_THRESHOLD
                    for r in self._subsystems.values()
                )
                if all_clear and self._corruption_count == 0:
                    latest_trip = max(
                        (r.tripped_at for r in self._subsystems.values()
                         if r.tripped_at > 0.0),
                        default=0.0,
                    )
                    elapsed = now_mt - latest_trip
                    if elapsed >= _HC_CB_HALF_OPEN_DELAY_SEC or latest_trip == 0.0:
                        self._transition(
                            _HardenedSystemMode.NORMAL,
                            f"auto-recovery: all subsystems clear after "
                            f"{elapsed:.0f}s half-open delay")

    def reset_subsystem(self, subsystem: str) -> None:
        with self._mode_lock:
            self._subsystems.pop(subsystem, None)
            log.warning("[HCB] Operator reset subsystem '%s'", subsystem)
            # FIX-4: prune stale corruption timestamps so an operator reset
            # also clears aged-out events from the rolling window.
            now_mt = time.monotonic()
            self._corruption_timestamps = [
                t for t in self._corruption_timestamps
                if now_mt - t <= _HC_CORRUPTION_WINDOW_SEC
            ]
            self._corruption_count = len(self._corruption_timestamps)
            if (self._mode == _HardenedSystemMode.READ_ONLY and
                    not any(r.failure_count >= _HC_CB_FAILURE_THRESHOLD
                            for r in self._subsystems.values())):
                log.warning("[HCB] All subsystems clean — half-open; "
                            "next successful block apply restores NORMAL.")

    def force_shutdown(self, reason: str = "operator request") -> None:
        with self._mode_lock:
            self._transition(_HardenedSystemMode.SAFE_SHUTDOWN, reason)

    def on_mode_change(self, callback) -> None:
        self._mode_change_callbacks.append(callback)

    def _transition(self, new_mode: _HardenedSystemMode, reason: str) -> None:
        if self._mode == new_mode:
            return
        old_mode = self._mode
        self._mode = new_mode
        log.critical("[HCB] MODE CHANGE: %s → %s | %s",
                     old_mode.value, new_mode.value, reason)
        # Write flag file for external watchdogs
        try:
            flag_dir = os.path.expanduser("~/.visold")
            os.makedirs(flag_dir, exist_ok=True)
            flag_path = os.path.join(flag_dir, f"PANIC_{new_mode.value}.flag")
            with open(flag_path, "w") as _f:
                _f.write(f"{reason}\ntimestamp={time.time()}\npid={os.getpid()}\n")
        except Exception:
            pass
        for cb in self._mode_change_callbacks:
            try:
                cb(new_mode, reason)
            except Exception:
                pass


# Module-level hardened CB singleton
_hc_panic_cb = _HardenedCBSingleton()


# ── NTP Clock ─────────────────────────────────────────────────────────────────
class _NTPClock:
    """
    Network-adjusted median clock for deterministic consensus timestamps.
    Falls back to system clock if ntplib is unavailable or all servers fail.
    """
    def __init__(self) -> None:
        self._offset_sec: float = 0.0
        self._last_sync: float  = 0.0
        self._sync_lock          = threading.Lock()
        self._client             = _ntplib.NTPClient() if _NTPLIB_AVAILABLE else None
        self._sync_thread: Optional[threading.Thread] = None
        self._alive: bool        = True

    def start(self) -> None:
        self._sync_now()
        self._sync_thread = threading.Thread(
            target=self._bg_sync_loop, daemon=True, name="ntp-clock-sync")
        self._sync_thread.start()

    def stop(self) -> None:
        self._alive = False

    def now(self) -> int:
        return int(time.time() + self._offset_sec)

    def now_float(self) -> float:
        return time.time() + self._offset_sec

    @property
    def offset_sec(self) -> float:
        return self._offset_sec

    def _bg_sync_loop(self) -> None:
        while self._alive:
            time.sleep(_HC_NTP_REFRESH_INTERVAL)
            if self._alive:
                self._sync_now()

    def _sync_now(self) -> None:
        if self._client is None:
            return  # ntplib not installed — use system clock silently
        offsets: List[float] = []
        for srv in _HC_NTP_SERVERS:
            try:
                resp = self._client.request(srv, version=3, timeout=2)
                offsets.append(resp.offset)
            except Exception:
                pass
        with self._sync_lock:
            self._last_sync = time.monotonic()
            if len(offsets) >= 2:
                offsets.sort()
                mid = len(offsets) // 2
                median_off = ((offsets[mid - 1] + offsets[mid]) / 2.0
                              if len(offsets) % 2 == 0 else offsets[mid])
                if abs(median_off) > _HC_NTP_MAX_DRIFT_SEC:
                    log.warning("[NTP] Large clock offset: %.3fs — applying correction.",
                                median_off)
                self._offset_sec = median_off
                log.debug("[NTP] Synced from %d servers; offset=%.4fs",
                          len(offsets), median_off)
            elif offsets:
                self._offset_sec = offsets[0]
                log.warning("[NTP] Only 1 NTP source; offset=%.4fs", offsets[0])
            else:
                log.warning("[NTP] All NTP servers unreachable; "
                            "using system clock (offset unchanged at %.4fs)",
                            self._offset_sec)


# Singleton NTP clock — started by apply_hardened_overlay()
_hc_ntp_clock = _NTPClock()


# ── System Invariant Gate ─────────────────────────────────────────────────────
class SystemInvariantGate:
    """
    Stateless pre-condition guard functions.
    Every method raises ImmediateAbort or InvariantViolation if violated.
    Nothing is written before a guard passes.
    """

    @staticmethod
    def assert_balance_non_negative(address: str, amount_sat: int,
                                    context: str = "") -> None:
        if not isinstance(amount_sat, int):
            raise ImmediateAbort(
                f"[INV] Balance for {address[:16]} is non-integer "
                f"type {type(amount_sat).__name__}. Context: {context}")
        if amount_sat < 0:
            raise ImmediateAbort(
                f"[INV] Negative balance: address={address[:16]} "
                f"amount_sat={amount_sat}. Context: {context}")

    @staticmethod
    def assert_debit_safe(address: str, current_sat: int,
                          debit_sat: int, context: str = "") -> None:
        SystemInvariantGate.assert_balance_non_negative(address, current_sat, context)
        if debit_sat < 0:
            raise ImmediateAbort(
                f"[INV] Negative debit for {address[:16]}: "
                f"debit_sat={debit_sat}. Context: {context}")
        if current_sat < debit_sat:
            raise ImmediateAbort(
                f"[INV] Insufficient balance: address={address[:16]} "
                f"current={current_sat} debit={debit_sat}. Context: {context}")

    @staticmethod
    def assert_credit_safe(address: str, credit_sat: int,
                           context: str = "") -> None:
        if credit_sat < 0:
            raise ImmediateAbort(
                f"[INV] Negative credit for {address[:16]}: "
                f"credit_sat={credit_sat}. Context: {context}")

    @staticmethod
    def assert_supply_cap(total_issued_sat: int, context: str = "") -> None:
        if total_issued_sat > _HC_MAX_SATOSHI_SUPPLY:
            raise InvariantViolation(
                f"[INV] SUPPLY CAP EXCEEDED: total_issued_sat={total_issued_sat} "
                f"> MAX={_HC_MAX_SATOSHI_SUPPLY}. Context: {context}")

    @staticmethod
    def assert_timestamp_valid(timestamp_unix, context: str = "") -> None:
        if not isinstance(timestamp_unix, (int, float)):
            raise TimestampAnomalyError(
                f"[INV] Timestamp is not numeric: {timestamp_unix!r}. "
                f"Context: {context}")
        ts = int(timestamp_unix)
        if ts < _HC_MIN_TIMESTAMP_UNIX:
            raise TimestampAnomalyError(
                f"[INV] Timestamp too old: {ts} < floor {_HC_MIN_TIMESTAMP_UNIX}. "
                f"Context: {context}")
        now_adjusted = _hc_ntp_clock.now()
        drift = ts - now_adjusted
        if abs(drift) > _HC_MAX_TIMESTAMP_DRIFT_SEC:
            raise TimestampAnomalyError(
                f"[INV] Timestamp drift too large: ts={ts} "
                f"ntp_now={now_adjusted} drift={drift:+}s "
                f"(max ±{_HC_MAX_TIMESTAMP_DRIFT_SEC}s). Context: {context}")

    @staticmethod
    def assert_block_index_monotonic(expected_idx: int,
                                     actual_idx: int, context: str = "") -> None:
        if actual_idx != expected_idx:
            raise ImmediateAbort(
                f"[INV] Block index discontinuity: "
                f"expected={expected_idx} actual={actual_idx}. Context: {context}")

    @staticmethod
    def assert_prev_hash_matches(stored_hash: str, incoming_prev: str,
                                 context: str = "") -> None:
        if stored_hash != incoming_prev:
            raise ImmediateAbort(
                f"[INV] prev_hash mismatch: "
                f"stored_tip={stored_hash[:16]}... "
                f"incoming_prev={incoming_prev[:16]}... Context: {context}")

    @staticmethod
    def assert_state_root_matches(expected: str, computed: str,
                                  block_idx: int) -> None:
        if expected and expected != computed:
            _hc_panic_cb.record_failure(
                "state_root_verify",
                StateRootMismatch(
                    f"block={block_idx} expected={expected[:16]} "
                    f"computed={computed[:16]}"),
                corruption_level=True)
            raise StateRootMismatch(
                f"[INV] STATE ROOT MISMATCH at block {block_idx}: "
                f"expected={expected[:16]}... computed={computed[:16]}...")

    @staticmethod
    def assert_tx_count_bounded(tx_count: int, context: str = "") -> None:
        if tx_count > _HC_MAX_BLOCK_TX_COUNT:
            raise ImmediateAbort(
                f"[INV] Excessive tx count: {tx_count} "
                f"> max {_HC_MAX_BLOCK_TX_COUNT}. Context: {context}")

    @staticmethod
    def assert_tx_id_length(tx_id: str, context: str = "") -> None:
        if len(tx_id) != 64:
            raise ImmediateAbort(
                f"[INV] tx_id invalid length {len(tx_id)} "
                f"(expected 64 hex chars). tx_id={tx_id[:32]}... Context: {context}")

    @staticmethod
    def assert_conservation(storage: Any, context: str = "") -> None:
        """
        O(n) conservation check: sum(balances) == total_issued.
        Call ONLY at block boundaries. Any violation is corruption-level.

        AUDIT-FIX-16: burns are tracked by crediting Config.BURN_ADDRESS
        (never destroyed outright), so BURN_ADDRESS's balance is already
        part of sum_all_balances_satoshi()'s total — adding
        get_burned_satoshi() again here double-counted it. Also, all three
        original inputs queried tables that were never created on either
        backend and silently returned 0, making this "corruption-level"
        check pass vacuously (0==0) on every deployment regardless of
        actual state. Both are fixed: see conservation_check() above (the
        free-function twin of this method) for the full explanation.
        """
        try:
            total_balances = storage.sum_all_balances_satoshi()
            total_issued   = storage.get_total_issued_satoshi()
            if total_balances != total_issued:
                err = ConservationViolation(
                    f"CONSERVATION VIOLATION @ {context}: "
                    f"balances={total_balances} "
                    f"!= issued={total_issued} "
                    f"(delta={total_balances - total_issued} sat)")
                _hc_panic_cb.record_failure(
                    "conservation_check", err, corruption_level=True)
                raise err
        except (AttributeError, TypeError) as e:
            log.warning("[INV] Conservation check unavailable (%s) — "
                        "storage may lack required methods.", e)


# Module-level invariant gate singleton
_hc_inv = SystemInvariantGate()


# ── Atomic State Transition ───────────────────────────────────────────────────
class AtomicStateTransition:
    """
    Prepare → Verify → Commit wrapper for any state-mutating operation.
    Any exception inside the `with` block rolls back automatically.

    Usage:
        with AtomicStateTransition(storage, block_idx) as txn:
            txn.prepare(plan)
            txn.verify_pre_conditions()
            txn.commit()
    """

    def __init__(self, storage: Any, block_idx: int,
                 post_conservation_check: bool = False) -> None:
        self._storage    = storage
        self._block_idx  = block_idx
        self._plans: List = []
        self._snap        = None
        self._role_snap   = None
        self._committed   = False
        self._post_check  = post_conservation_check
        self._touched: Set[str] = set()

    def __enter__(self) -> 'AtomicStateTransition':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is not None and not self._committed:
            self._rollback()
        return False

    def prepare(self, plan: Any) -> None:
        _hc_panic_cb.assert_writable(
            f"AtomicStateTransition.prepare block={self._block_idx}")
        self._plans.append(plan)
        sender   = getattr(plan, 'sender', None)
        receiver = getattr(plan, 'receiver', None)
        touches  = getattr(plan, 'touches', set())
        if sender:   self._touched.add(sender)
        if receiver: self._touched.add(receiver)
        for addr in (touches or set()):
            self._touched.add(addr)

    def verify_pre_conditions(self) -> None:
        for plan in self._plans:
            sender     = getattr(plan, 'sender', None)
            receiver   = getattr(plan, 'receiver', None)
            amount_sat = getattr(plan, 'amount_sat', 0)
            fee_sat    = getattr(plan, 'fee_sat', 0)
            desc       = getattr(plan, 'description', '')
            if sender and sender != "COINBASE":
                current_sat = self._storage.get_balance_sat(sender)
                _hc_inv.assert_balance_non_negative(sender, current_sat, desc)
                _hc_inv.assert_debit_safe(sender, current_sat,
                                          amount_sat + fee_sat, desc)
            if receiver and amount_sat > 0:
                _hc_inv.assert_credit_safe(receiver, amount_sat, desc)
        self._snap      = self._storage.snapshot_accounts(self._touched)
        self._role_snap = self._storage.snapshot_roles(list(self._touched))

    def commit(self) -> None:
        self._committed = True
        if self._post_check:
            try:
                _hc_inv.assert_conservation(
                    self._storage, f"block={self._block_idx} post-commit")
            except ConservationViolation:
                self._rollback()
                raise

    def _rollback(self) -> None:
        if self._snap is not None:
            try:
                self._storage.restore_accounts(self._snap)
            except Exception as e:
                _hc_panic_cb.record_failure("restore_accounts", e,
                                            corruption_level=True)
        if self._role_snap is not None:
            try:
                self._storage.restore_roles(self._role_snap)
            except Exception as e:
                _hc_panic_cb.record_failure("restore_roles", e,
                                            corruption_level=True)
        log.warning("[AST] Rolled back state for block=%d", self._block_idx)


# ── Resource Cap ──────────────────────────────────────────────────────────────
class ResourceCap:
    """
    Guards against VVM recursion overflow, memory pressure, and timeout.
    """
    _recursion_tls     = threading.local()
    _memory_alert_sent = False

    @classmethod
    def enter_call_frame(cls, caller: str, callee: str) -> None:
        depth = getattr(cls._recursion_tls, "depth", 0)
        if depth >= _HC_MAX_RECURSION_DEPTH:
            raise RecursionLimitExceeded(
                f"[RES] VVM recursion limit ({_HC_MAX_RECURSION_DEPTH}) "
                f"exceeded: {caller[:20]} → {callee[:20]}")
        cls._recursion_tls.depth = depth + 1

    @classmethod
    def exit_call_frame(cls) -> None:
        depth = getattr(cls._recursion_tls, "depth", 0)
        cls._recursion_tls.depth = max(0, depth - 1)

    @classmethod
    @contextlib.contextmanager
    def call_frame(cls, caller: str, callee: str):
        cls.enter_call_frame(caller, callee)
        try:
            yield
        finally:
            cls.exit_call_frame()

    @staticmethod
    def check_memory_pressure() -> None:
        try:
            rss_bytes = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            rss_mb = (rss_bytes / (1024 * 1024) if sys.platform == "darwin"
                      else rss_bytes / 1024)
            if rss_mb > _HC_MAX_HEAP_MB:
                if not ResourceCap._memory_alert_sent:
                    log.critical(
                        "[RES] MEMORY PRESSURE: RSS=%.0fMB > cap=%dMB.",
                        rss_mb, _HC_MAX_HEAP_MB)
                    ResourceCap._memory_alert_sent = True
                    _hc_panic_cb.record_failure(
                        "memory_cap",
                        RuntimeError(f"RSS {rss_mb:.0f}MB exceeds {_HC_MAX_HEAP_MB}MB"),
                        corruption_level=False)
        except Exception:
            pass

    @staticmethod
    def timeout(seconds: float = _HC_OP_TIMEOUT_SEC):
        """Decorator: raises TimeoutError if the wrapped call exceeds `seconds`.

        AUDIT-FIX-K6 — READ THIS BEFORE APPLYING THIS DECORATOR TO ANYTHING:
        the background thread running the wrapped call is NOT stopped,
        joined, or cancelled when the timeout fires -- Python cannot forcibly
        kill a running thread. It keeps executing `fn(*args, **kwargs)` after
        this decorator has already raised TimeoutError to the caller and the
        caller has moved on (e.g. treated the operation as failed and taken
        some other recovery action). If `fn` mutates any shared/persistent
        state (a write), a late completion after that point is a silent,
        unsynchronized write racing with whatever the caller did next.

        Only apply this decorator to functions that are read-only, or that
        are safely idempotent against a late, out-of-band completion. Do NOT
        apply it to anything that writes without first making the wrapped
        call cooperatively cancellable (e.g. the wrapped function itself
        polling a cancellation flag/event at safe points) -- a true fix for
        the write case needs to happen inside whatever function gets
        decorated, not in this wrapper, since the wrapper alone cannot make
        an arbitrary callee stop early.

        (Confirmed unused anywhere in this file as of this fix -- there is
        no live trigger today, but fix the contract now, while it's cheap,
        before anyone reaches for this on something that writes.)
        """
        def decorator(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                result: list = [None]
                exc:    list = [None]
                done = threading.Event()

                def _run():
                    try:
                        result[0] = fn(*args, **kwargs)
                    except Exception as e:
                        exc[0] = e
                    finally:
                        done.set()

                t = threading.Thread(target=_run, daemon=True,
                                     name=f"hc-timeout-{fn.__name__}")
                t.start()
                if not done.wait(timeout=seconds):
                    _hc_panic_cb.record_failure(
                        f"timeout:{fn.__name__}",
                        TimeoutError(
                            f"{fn.__name__} timed out after {seconds}s"),
                        corruption_level=False)
                    raise TimeoutError(
                        f"[RES] Operation '{fn.__name__}' timed out after "
                        f"{seconds}s — system entering READ_ONLY.")
                if isinstance(exc[0], BaseException):
                    raise exc[0]
                return result[0]
            return wrapper
        return decorator


# ── Graceful Degradation ──────────────────────────────────────────────────────
class GracefulDegradation:
    """
    Wraps non-critical subsystem calls so failures are isolated from the
    consensus critical path.
    Non-critical: ContractEventIndex, Redis cache, PG projections, metrics.
    """
    _degraded: Dict[str, Tuple[int, float]] = {}
    _lock = threading.Lock()

    @classmethod
    def run(cls, subsystem: str, fn, *args,
            default=None, critical_on_n_failures: int = 10, **kwargs):
        try:
            result = fn(*args, **kwargs)
            with cls._lock:
                cls._degraded.pop(subsystem, None)
            return result
        except Exception as e:
            with cls._lock:
                count, _ = cls._degraded.get(subsystem, (0, 0.0))
                count += 1
                cls._degraded[subsystem] = (count, time.monotonic())
            log.warning("[DEG] Non-critical subsystem '%s' failed "
                        "(count=%d): %s", subsystem, count, e)
            if count >= critical_on_n_failures:
                _hc_panic_cb.record_failure(
                    subsystem,
                    RuntimeError(
                        f"{subsystem} degraded {count}× consecutively"),
                    corruption_level=False)
            return default

    @classmethod
    def wrap(cls, subsystem: str, default=None,
             critical_on_n_failures: int = 10):
        def decorator(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                return cls.run(subsystem, fn, *args,
                               default=default,
                               critical_on_n_failures=critical_on_n_failures,
                               **kwargs)
            return wrapper
        return decorator


# ── Hardened apply_block factory ──────────────────────────────────────────────
def _make_hardened_apply_block(original_apply_block):
    """
    Wraps Blockchain.apply_block() with all hardening layers:
      Req-1 Invariant Safety Gate    — pre-conditions before any write
      Req-2 Panic Circuit Breaker    — corruption trips READ_ONLY
      Req-3 Atomic State Transition  — Prepare → Verify → Commit
      Req-4 Deterministic Clock      — NTP median for drift validation
      Req-5 Resource Cap             — recursion + memory pressure check
      Req-6 Graceful Degradation     — secondary component isolation
    """
    @functools.wraps(original_apply_block)
    def hardened_apply_block(self_bc, block) -> Tuple[bool, str]:
        # Gate 0: Hardened CB write gate
        try:
            _hc_panic_cb.assert_writable(f"apply_block idx={block.index}")
        except ImmediateAbort as e:
            log.warning("[HAB] apply_block blocked by hardened CB: %s", e)
            return False, str(e)

        # Gate 1: Resource check
        ResourceCap.check_memory_pressure()

        # Gate 2: Block pre-conditions (all checked before any write)
        try:
            # Timestamp drift check — only for genuinely live blocks.
            #
            # BUG-FIX (sync-fix-6): The old logic treated ANY block whose
            # index > our current tip as 'live', including ALL blocks received
            # during initial sync on a fresh node (tip = -1 or 0).
            # Scenario: Node B (fresh, tip=-1) syncs from Node A which mined
            # 9 blocks 3 hours ago.  Block 1 arrives: index(1) > max(0,-1)=0
            # → flagged as live → timestamp check fires → drift = 3 hours >
            # 2-hour limit → TimestampAnomalyError → apply_block fails →
            # sync impossible.
            #
            # Correct definition of 'live block':
            #   A block is live only when its timestamp is AHEAD of (or very
            #   close to) now — i.e. it was just mined.  A block whose
            #   timestamp is already in the past (even by many hours) is
            #   historical/sync data and must never be rejected for drift.
            #
            # New rule:
            #   - Always skip genesis (index == 0).
            #   - For all other blocks: only run the drift check if the
            #     block's timestamp is >= (now - 2*max_drift).  Blocks
            #     clearly in the past are historical sync data; blocks
            #     at or ahead of now are live and must be checked.
            #   - Future-dated blocks (drift > +max_drift) are still
            #     rejected exactly as before.
            _our_tip = self_bc.storage.chain_height()
            _now_ts  = _hc_ntp_clock.now()
            _is_past_block = (int(block.timestamp) < _now_ts - _HC_MAX_TIMESTAMP_DRIFT_SEC)
            if block.index != 0 and not _is_past_block:
                _hc_inv.assert_timestamp_valid(
                    block.timestamp,
                    context=f"apply_block idx={block.index}")
            _hc_inv.assert_tx_count_bounded(
                len(block.transactions),
                context=f"apply_block idx={block.index}")
            for tx in block.transactions:
                if getattr(tx, 'sender', '') == "COINBASE":
                    continue
                _hc_inv.assert_tx_id_length(
                    tx.tx_id,
                    context=f"block={block.index} tx={tx.tx_id[:16]}")
            for tx in block.transactions:
                if getattr(tx, 'sender', '') == "COINBASE":
                    continue
                sender_sat = self_bc.storage.get_balance_sat(tx.sender)
                _hc_inv.assert_balance_non_negative(
                    tx.sender, sender_sat,
                    context=f"pre-apply tx={tx.tx_id[:16]}")
        except (ImmediateAbort, InvariantViolation) as pre_err:
            log.error("[HAB] PRE-CONDITION FAILURE for block %d: %s",
                      block.index, pre_err)
            _hc_panic_cb.record_failure("apply_block_pre", pre_err,
                                        corruption_level=False)
            return False, f"Pre-condition violated: {pre_err}"

        # Gate 3: Delegate to original implementation
        try:
            ok, msg = original_apply_block(self_bc, block)
        except (ImmediateAbort, InvariantViolation, StateRootMismatch) as abort:
            _hc_panic_cb.record_failure("apply_block_exec", abort,
                                        corruption_level=True)
            return False, f"Invariant abort during apply: {abort}"
        except Exception as exc:
            _hc_panic_cb.record_failure("apply_block_exec", exc,
                                        corruption_level=False)
            log.exception("[HAB] Unexpected exception in apply_block idx=%d",
                          block.index)
            return False, f"Unexpected error: {exc}"

        if not ok:
            _hc_panic_cb.record_success("apply_block_exec")
            return False, msg

        # Gate 4: Post-apply state root verification
        try:
            computed_root = (self_bc.storage.compute_state_root()
                             if hasattr(self_bc.storage, 'compute_state_root') else "")
            expected_root = getattr(block, "state_root", "")
            if expected_root and computed_root:
                _hc_inv.assert_state_root_matches(
                    expected_root, computed_root, block.index)
        except StateRootMismatch as srm:
            log.critical("[HAB] STATE ROOT MISMATCH — block %d rejected. %s",
                         block.index, srm)
            return False, str(srm)

        # Gate 5: Periodic conservation check (every 100 blocks)
        if block.index % 100 == 0:
            try:
                _hc_inv.assert_conservation(
                    self_bc.storage,
                    context=f"block={block.index} periodic")
            except ConservationViolation as cv:
                return False, str(cv)

        _hc_panic_cb.record_success("apply_block_exec")
        return True, msg

    return hardened_apply_block


# ── Hardened debit_sat / credit_sat factories ─────────────────────────────────
def _make_hardened_debit_sat(original_debit_sat):
    @functools.wraps(original_debit_sat)
    def hardened_debit_sat(self_storage, address: str, amount_sat: int):
        _hc_panic_cb.assert_writable(f"debit_sat({address[:16]}, {amount_sat})")
        current = self_storage._get_balance_satoshi(address)
        _hc_inv.assert_balance_non_negative(address, current, context="pre-debit")
        if amount_sat < 0:
            raise ImmediateAbort(
                f"[INV] Negative debit_sat({address[:16]}, {amount_sat})")
        if current < amount_sat:
            return False
        result = original_debit_sat(self_storage, address, amount_sat)
        post = self_storage._get_balance_satoshi(address)
        if post < 0:
            _hc_panic_cb.record_failure(
                "post_debit_negative",
                InvariantViolation(
                    f"Post-debit balance negative: {address[:16]}={post}"),
                corruption_level=True)
            raise InvariantViolation(
                f"[INV] CORRUPTION: debit left negative balance "
                f"for {address[:16]}: {post}")
        return result
    return hardened_debit_sat


def _make_hardened_credit_sat(original_credit_sat):
    @functools.wraps(original_credit_sat)
    def hardened_credit_sat(self_storage, address: str, amount_sat: int):
        _hc_panic_cb.assert_writable(f"credit_sat({address[:16]}, {amount_sat})")
        _hc_inv.assert_credit_safe(address, amount_sat, context="pre-credit")
        return original_credit_sat(self_storage, address, amount_sat)
    return hardened_credit_sat


# ── Hardened VVM internal call factory ───────────────────────────────────────
def _make_hardened_vvm_internal_call(original_internal_call):
    @functools.wraps(original_internal_call)
    def hardened_internal_call(self_vvm, *args, **kwargs):
        caller = getattr(self_vvm, "_current_contract", "?")
        callee = args[0] if args else "?"
        with ResourceCap.call_frame(str(caller), str(callee)):
            return original_internal_call(self_vvm, *args, **kwargs)
    return hardened_internal_call


# ── Hardened ContractEventIndex factory ──────────────────────────────────────
def _make_degraded_event_index_save(original_save):
    @functools.wraps(original_save)
    def degraded_save(self_idx, *args, **kwargs):
        return GracefulDegradation.run(
            "contract_event_index",
            original_save,
            self_idx, *args, **kwargs,
            default=None,
            critical_on_n_failures=20)
    return degraded_save


# ── Master overlay function ───────────────────────────────────────────────────
def apply_hardened_overlay(blockchain_instance,
                            storage_instance=None,
                            vvm_engine_instance=None,
                            event_index_instance=None,
                            start_ntp_clock: bool = True) -> None:
    """
    Inject all hardening layers onto live instances.

    MUST be called AFTER Blockchain.__init__ completes and BEFORE
    StateEngine.start() is called.

    Parameters
    ──────────
    blockchain_instance   : The Blockchain object (required).
    storage_instance      : Storage object; defaults to blockchain.storage.
    vvm_engine_instance   : VVMEngine; defaults to blockchain._vvm_engine.
    event_index_instance  : ContractEventIndex; defaults to
                            blockchain._event_index.
    start_ntp_clock       : Whether to start the NTP sync daemon thread.
    """
    import types as _types
    log.info("[HARDENED] Applying hardened overlay to Visold node…")

    # 1. Start NTP clock
    if start_ntp_clock:
        try:
            _hc_ntp_clock.start()
            log.info("[HARDENED] NTP clock started (offset=%.4fs)",
                     _hc_ntp_clock.offset_sec)
        except Exception as e:
            log.warning("[HARDENED] NTP clock failed to start (%s); "
                        "falling back to system clock.", e)

    # 2. Resolve instances
    storage = storage_instance or getattr(blockchain_instance, "storage", None)
    vvm     = vvm_engine_instance or getattr(
        blockchain_instance, "_vvm_engine", None)
    ei      = event_index_instance or getattr(
        blockchain_instance, "_event_index", None)

    # 3. Patch Blockchain.apply_block
    original_apply = blockchain_instance.__class__.apply_block
    hardened_apply = _make_hardened_apply_block(original_apply)
    blockchain_instance.apply_block = _types.MethodType(
        hardened_apply, blockchain_instance)
    log.info("[HARDENED] apply_block patched with full invariant safety gates.")

    # 4. Inject NTP clock reference onto blockchain instance
    blockchain_instance._hc_ntp_now       = _hc_ntp_clock.now
    blockchain_instance._hc_ntp_now_float = _hc_ntp_clock.now_float
    log.info("[HARDENED] NTP clock injected onto blockchain instance.")

    # 5. Patch Storage.debit_sat / credit_sat
    if storage is not None:
        if hasattr(storage, 'debit_sat') and hasattr(storage, 'credit_sat'):
            orig_debit  = storage.__class__.debit_sat
            orig_credit = storage.__class__.credit_sat
            storage.debit_sat  = _types.MethodType(
                _make_hardened_debit_sat(orig_debit),  storage)
            storage.credit_sat = _types.MethodType(
                _make_hardened_credit_sat(orig_credit), storage)
            log.info("[HARDENED] debit_sat / credit_sat patched with "
                     "pre-condition invariant guards.")
        else:
            log.warning("[HARDENED] Storage missing debit_sat/credit_sat — "
                        "balance guards not applied.")

    # 6. Patch VVMEngine._internal_call (recursion guard)
    if vvm is not None and hasattr(vvm, '_internal_call'):
        orig_icall = vvm.__class__._internal_call
        vvm._internal_call = _types.MethodType(
            _make_hardened_vvm_internal_call(orig_icall), vvm)
        log.info("[HARDENED] VVMEngine._internal_call patched with "
                 "recursion depth guard (max=%d frames).", _HC_MAX_RECURSION_DEPTH)

    # 7. Patch ContractEventIndex.index_logs (graceful degradation)
    if ei is not None and hasattr(ei, "index_logs"):
        orig_save = ei.__class__.index_logs
        ei.index_logs = _types.MethodType(
            _make_degraded_event_index_save(orig_save), ei)
        log.info("[HARDENED] ContractEventIndex.index_logs wrapped with "
                 "graceful degradation.")

    # 8. Expose hardening status API on blockchain instance
    def _hardened_status() -> dict:
        return {
            "circuit_breaker_mode":     _hc_panic_cb.mode.value,
            "ntp_offset_sec":           _hc_ntp_clock.offset_sec,
            "subsystem_failure_counts": {
                k: v.failure_count
                for k, v in _hc_panic_cb._subsystems.items()
            },
            "degraded_subsystems": {
                k: {"failures": c, "last_ts": ts}
                for k, (c, ts) in GracefulDegradation._degraded.items()
            },
        }

    blockchain_instance.hardened_status = _hardened_status
    log.info("[HARDENED] Overlay fully applied. "
             "Node operating under hardened invariant enforcement.")
