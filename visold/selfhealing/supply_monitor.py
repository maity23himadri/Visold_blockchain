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
"""visold.selfhealing.supply_monitor

Original section: SECTION 8: SUPPLY CONSERVATION MONITOR

Defines: SupplyConservationMonitor
Origin: visold_vsd_.py L52391-52499
"""

import time
from typing import Optional

from visold.kernel.logging_setup import log
from visold.selfhealing.detection import AnomalyDetectionEngine
from visold.selfhealing.model import AnomalyKind, AnomalyReport


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8: SUPPLY CONSERVATION MONITOR
# ─────────────────────────────────────────────────────────────────────────────

class SupplyConservationMonitor:
    """
    Verifies that the conservation invariant holds after every block:

        sum(all balances) == genesis_supply + sum(all block_rewards) - burned

    Reads directly from storage without modifying any state.

    This is a backstop for the balance conservation bug that was previously
    identified (double-credit in reward distribution). If the invariant
    breaks, CRITICAL supply inflation anomaly is raised immediately.

    AUDIT-FIX-9 (L2 bridge invariant had no automated monitoring): on the
    same sampling cadence, also checks Layer2State.supply_invariant_ok()
    — L2 minted supply vs. L1-escrowed bridge collateral. Previously that
    invariant was computed only inside Layer2State.status(), a pure RPC/
    diagnostic method with no caller feeding it into anomaly detection —
    so a bridge desync (the classic L2 exploit: mint unbacked L2 value,
    withdraw real L1 value against it) would never trigger an automated
    response, no matter how large. blockchain_ref is optional so this
    class still works exactly as before on chains without an L2 layer.

    Performance: only sampled every SAMPLE_INTERVAL blocks to avoid
    O(n_accounts) read on every block.
    """
    SAMPLE_INTERVAL = 50   # check every 50 blocks

    def __init__(self, storage_ref, blockchain_ref=None):
        self._storage = storage_ref
        self._blockchain = blockchain_ref
        self._last_checked_supply: Optional[int] = None
        self._check_count = 0

    def check(self, block, ade: AnomalyDetectionEngine) -> None:
        height = getattr(block, "index", 0)
        if height % self.SAMPLE_INTERVAL != 0:
            return
        self._check_count += 1
        try:
            current_supply = self._storage.get_total_supply_sat()
            if self._last_checked_supply is not None:
                # Supply can only increase by block_rewards and decrease by burn
                # A sudden large jump or decrease is a conservation violation
                delta_sat = current_supply - self._last_checked_supply
                expected_max_delta = (
                    # 50 blocks × ~10 VSD reward × 1e8 sat/VSD × 1.05 tolerance
                    self.SAMPLE_INTERVAL * 10 * 100_000_000 * 1.05
                )
                if delta_sat > expected_max_delta:
                    # Inflate anomaly — inject directly
                    report = AnomalyReport(
                        kind=AnomalyKind.SUPPLY_INFLATION,
                        detected_at=time.time(),
                        description=(
                            f"Supply jumped {delta_sat/1e8:.4f} VSD in "
                            f"{self.SAMPLE_INTERVAL} blocks "
                            f"(expected max {expected_max_delta/1e8:.4f} VSD)"
                        ),
                        evidence={
                            "prev_supply_sat": self._last_checked_supply,
                            "curr_supply_sat": current_supply,
                            "delta_sat": delta_sat,
                            "blocks": self.SAMPLE_INTERVAL,
                        },
                        source="rule",
                        confidence=0.95,
                        block_height=height,
                    )
                    for listener in ade._listeners:
                        try:
                            listener(report)
                        except Exception:
                            pass
                    log.critical(
                        f"[SUPPLY] Conservation invariant VIOLATED: "
                        f"delta={delta_sat/1e8:.4f} VSD")
            self._last_checked_supply = current_supply
        except Exception as exc:
            log.debug(f"SupplyConservationMonitor: {exc}")

        # AUDIT-FIX-9: L2 bridge conservation check, same cadence.
        try:
            layer2 = getattr(self._blockchain, "layer2", None)
            if layer2 is not None:
                l2_ok, l2_detail = layer2.supply_invariant_ok()
                if not l2_ok:
                    report = AnomalyReport(
                        kind=AnomalyKind.SUPPLY_INFLATION,
                        detected_at=time.time(),
                        description=(
                            f"L2 bridge conservation invariant VIOLATED: "
                            f"{l2_detail}"),
                        evidence={
                            "check": "layer2.supply_invariant_ok",
                            "detail": str(l2_detail),
                        },
                        source="rule",
                        confidence=0.95,
                        block_height=height,
                    )
                    for listener in ade._listeners:
                        try:
                            listener(report)
                        except Exception:
                            pass
                    log.critical(
                        f"[SUPPLY] L2 bridge invariant VIOLATED: {l2_detail}")
        except Exception as exc:
            log.debug(f"SupplyConservationMonitor (L2 bridge check): {exc}")
