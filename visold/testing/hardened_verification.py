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
"""visold.testing.hardened_verification


Defines: HardenedVerificationSuite
Origin: visold_vsd_.py L42882-42990
"""

from visold.resilience.hardened_core import (
    GracefulDegradation,
    ImmediateAbort,
    RecursionLimitExceeded,
    ResourceCap,
    StateRootMismatch,
    TimestampAnomalyError,
    _HC_CB_FAILURE_THRESHOLD,
    _HC_MAX_RECURSION_DEPTH,
    _HC_MIN_TIMESTAMP_UNIX,
    _HardenedSystemMode,
    _hc_inv,
    _hc_ntp_clock,
    _hc_panic_cb,
)


# ── Hardened verification suite ───────────────────────────────────────────────
class HardenedVerificationSuite:
    """
    Offline tests to verify that the hardening layer is functioning correctly.
    Called from main() with --verify-hardened flag.
    """
    def __init__(self):
        self._pass = 0
        self._fail = 0

    def _assert(self, condition: bool, name: str, detail: str = "") -> None:
        if condition:
            self._pass += 1
            print(f"  PASS  {name}")
        else:
            self._fail += 1
            print(f"  FAIL  {name}  [{detail}]")

    def run(self) -> bool:
        print("\n" + "═" * 72)
        print("  HARDENED CORE — VERIFICATION SUITE")
        print("═" * 72)

        # 1. Negative balance gate
        try:
            _hc_inv.assert_balance_non_negative("alice", -1, "test")
            self._assert(False, "Neg-balance gate", "Should have raised")
        except ImmediateAbort:
            self._assert(True, "Neg-balance gate raises ImmediateAbort")

        # 2. Overdraft gate
        try:
            _hc_inv.assert_debit_safe("bob", 100, 200, "test")
            self._assert(False, "Overdraft gate", "Should have raised")
        except ImmediateAbort:
            self._assert(True, "Overdraft gate raises ImmediateAbort")

        # 3. Old timestamp gate
        try:
            _hc_inv.assert_timestamp_valid(1_000_000, "test")
            self._assert(False, "Old-timestamp gate", "Should have raised")
        except TimestampAnomalyError:
            self._assert(True, "Old-timestamp raises TimestampAnomalyError")

        # 4. State root mismatch trips CB
        _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
        _hc_panic_cb._corruption_count = 0
        _hc_panic_cb._subsystems.clear()
        try:
            _hc_inv.assert_state_root_matches("aaa" + "0" * 61, "bbb" + "0" * 61, 999)
            self._assert(False, "State-root mismatch gate", "Should have raised")
        except StateRootMismatch:
            self._assert(True, "State-root mismatch raises StateRootMismatch")
        _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
        _hc_panic_cb._corruption_count = 0
        _hc_panic_cb._subsystems.clear()

        # 5. CB trips to READ_ONLY after N failures
        for _ in range(_HC_CB_FAILURE_THRESHOLD):
            _hc_panic_cb.record_failure("test_sub", RuntimeError("boom"))
        self._assert(_hc_panic_cb.mode == _HardenedSystemMode.READ_ONLY,
                     "CB trips after N failures → READ_ONLY")
        _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
        _hc_panic_cb._subsystems.clear()

        # 6. Recursion guard
        try:
            for _ in range(_HC_MAX_RECURSION_DEPTH + 1):
                ResourceCap.enter_call_frame("A", "B")
            self._assert(False, "Recursion guard", "Should have raised")
        except RecursionLimitExceeded:
            self._assert(True, "Recursion guard raises RecursionLimitExceeded")
        finally:
            ResourceCap._recursion_tls.depth = 0

        # 7. GracefulDegradation swallows non-critical errors
        def boom():
            raise RuntimeError("secondary failure")
        result = GracefulDegradation.run("test_deg", boom, default="FALLBACK")
        self._assert(result == "FALLBACK",
                     "GracefulDegradation returns default on error")
        GracefulDegradation._degraded.clear()

        # 8. GracefulDegradation passes through success
        def good():
            return 42
        result2 = GracefulDegradation.run("test_good", good, default=0)
        self._assert(result2 == 42, "GracefulDegradation passes through result")

        # 9. NTPClock.now() sanity
        ts = _hc_ntp_clock.now()
        self._assert(isinstance(ts, int) and ts > _HC_MIN_TIMESTAMP_UNIX,
                     "NTPClock.now() returns plausible integer timestamp")

        # 10. assert_writable raises in READ_ONLY
        _hc_panic_cb._mode = _HardenedSystemMode.READ_ONLY
        try:
            _hc_panic_cb.assert_writable("test")
            self._assert(False, "assert_writable in READ_ONLY", "Should raise")
        except ImmediateAbort:
            self._assert(True, "assert_writable raises ImmediateAbort in READ_ONLY")
        finally:
            _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
            _hc_panic_cb._subsystems.clear()
            _hc_panic_cb._corruption_count = 0

        print("─" * 72)
        print(f"  RESULT: {self._pass} passed, {self._fail} failed")
        print("═" * 72 + "\n")
        return self._fail == 0
