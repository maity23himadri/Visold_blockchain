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
"""visold.selfhealing.detection

Original section: SECTION 4: LAYER 2 — ANOMALY DETECTION ENGINE

Defines: StatisticalDetector, AnomalyDetectionEngine
Origin: visold_vsd_.py L50962-51017, L51020-51094
"""

import threading
import time
from typing import Callable, Dict, List, Tuple

from visold.kernel.logging_setup import log
from visold.selfhealing.model import AnomalyKind, AnomalyReport
from visold.selfhealing.monitors import (
    GasMonitor,
    MonitorBus,
    ReentrancyPatternDetector,
    TransactionMonitor,
    ValidatorMonitor,
)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4: LAYER 2 — ANOMALY DETECTION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class StatisticalDetector:
    """
    Statistical anomaly detector using z-score and EWMA deviation.

    For each monitored metric, if z_score > ALERT_THRESHOLD, an anomaly
    is raised. Thresholds are metric-specific to tune false-positive rate.
    """

    ALERT_THRESHOLDS: Dict[str, Tuple[float, AnomalyKind]] = {
        "tps":             (3.5, AnomalyKind.TPS_SPIKE),
        "block_gas":       (4.0, AnomalyKind.GAS_SPIKE),
        "mempool_size":    (3.0, AnomalyKind.MEMPOOL_FLOOD),
        "vvm_gas_per_tx":  (4.5, AnomalyKind.GAS_SPIKE),
    }

    def __init__(self, bus: MonitorBus):
        self._bus = bus

    def detect(self, height: int) -> List[AnomalyReport]:
        anomalies = []
        now = time.time()
        snap = self._bus.snapshot()

        for metric, (threshold, kind) in self.ALERT_THRESHOLDS.items():
            if metric not in snap:
                continue
            stats = snap[metric]
            baseline_tracker = self._bus.get_baseline(metric)
            if baseline_tracker is None or not baseline_tracker.is_warmed:
                continue

            latest = stats.get("latest", 0.0)
            z = baseline_tracker.current_zscore(latest)
            if abs(z) > threshold:
                anomalies.append(AnomalyReport(
                    kind=kind,
                    detected_at=now,
                    description=(
                        f"Statistical anomaly in '{metric}': "
                        f"current={latest:.2f}, z-score={z:.2f} "
                        f"(threshold={threshold})"
                    ),
                    evidence={
                        "metric": metric,
                        "value": latest,
                        "z_score": z,
                        "baseline_mean": stats["mean"],
                        "baseline_std": stats["std"],
                    },
                    source="stat",
                    confidence=min(0.4 + 0.1 * abs(z), 0.95),
                    block_height=height,
                    z_score=z,
                ))

        return anomalies


class AnomalyDetectionEngine:
    """
    Aggregates all detection subsystems into a single ADE interface.

    Architecture:
      - Rule engine fires on hard rule violations (always active)
      - Statistical engine fires on z-score deviations (after warm-up)
      - Pattern engine fires on execution path patterns

    Deduplication: identical (kind, affected_addr) pairs within
    DEDUP_WINDOW seconds are suppressed to avoid alert storms.
    """
    DEDUP_WINDOW = 30.0  # seconds

    def __init__(
        self,
        bus: MonitorBus,
        tx_monitor: TransactionMonitor,
        gas_monitor: GasMonitor,
        validator_monitor: ValidatorMonitor,
        reentrancy_detector: ReentrancyPatternDetector,
        stat_detector: StatisticalDetector,
    ):
        self._bus = bus
        self._tx_mon   = tx_monitor
        self._gas_mon  = gas_monitor
        self._val_mon  = validator_monitor
        self._reen_det = reentrancy_detector
        self._stat_det = stat_detector
        self._seen: Dict[Tuple[str, str], float] = {}   # (kind, addr) → last_seen_ts
        self._seen_lock = threading.Lock()
        self._listeners: List[Callable[[AnomalyReport], None]] = []

    def add_listener(self, fn: Callable[[AnomalyReport], None]):
        """Register a callback invoked for every non-deduplicated anomaly."""
        self._listeners.append(fn)

    def observe_block(self, block) -> List[AnomalyReport]:
        """
        Main entry point — called after every block is applied by the node.
        Returns the de-duplicated anomaly list and fires all listeners.
        """
        all_anomalies: List[AnomalyReport] = []
        all_anomalies += self._tx_mon.observe_block(block)
        all_anomalies += self._gas_mon.observe_block(block)
        all_anomalies += self._val_mon.observe_block(block)
        all_anomalies += self._reen_det.observe_block(block)

        height = getattr(block, "index", 0)
        all_anomalies += self._stat_det.detect(height)

        # Deduplicate
        filtered = self._dedup(all_anomalies)

        # Notify listeners
        for report in filtered:
            for listener in self._listeners:
                try:
                    listener(report)
                except Exception as exc:
                    log.error(f"ADE listener error: {exc}")

        return filtered

    def _dedup(self, reports: List[AnomalyReport]) -> List[AnomalyReport]:
        now = time.time()
        result = []
        with self._seen_lock:
            for r in reports:
                key = (r.kind.value, r.affected_addr or "")
                last = self._seen.get(key, 0.0)
                if now - last >= self.DEDUP_WINDOW:
                    self._seen[key] = now
                    result.append(r)
        return result
