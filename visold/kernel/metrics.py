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
"""visold.kernel.metrics

Original section: SECTION 1C: METRICS COLLECTOR  (Problem #11 — Monitoring / Observability)

Defines: MetricsCollector
Origin: visold_vsd_.py L5586-5661, L5665
"""

import re
import threading
from collections import deque
from typing import Dict


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1C: METRICS COLLECTOR  (Problem #11 — Monitoring / Observability)
# ─────────────────────────────────────────────────────────────────────────────
class MetricsCollector:
    """
    Thread-safe Prometheus-compatible metrics store.

    Exposes:
    ════════
    • Gauges   — current value (peers, mempool size, hashrate, difficulty)
    • Counters — monotonically increasing (blocks mined, txs processed)
    • Histograms (simple) — block time buckets

    Prometheus text format is served via the /metrics endpoint on the RPC port.
    """
    def __init__(self):
        self._lock      = threading.Lock()
        self._gauges:   Dict[str, float] = {}
        self._counters: Dict[str, float] = {}
        self._block_times: deque         = deque(maxlen=1000)

    @staticmethod
    def _sanitize_metric_name(name: str) -> str:
        """F-20 FIX: Replace non-Prometheus-safe chars with underscores.
        Valid chars: [a-zA-Z0-9_]. Reject empty names after sanitization."""
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        if not sanitized:
            raise ValueError(f"Metric name '{name}' is empty after sanitization")
        return sanitized

    # ── Gauge (set absolute value) ────────────────────────────────────────────
    def set_gauge(self, name: str, value: float):
        name = self._sanitize_metric_name(name)
        with self._lock:
            self._gauges[name] = value

    def get_gauge(self, name: str, default: float = 0.0) -> float:
        name = self._sanitize_metric_name(name)
        with self._lock:
            return self._gauges.get(name, default)

    # ── Counter (increment) ───────────────────────────────────────────────────
    def inc(self, name: str, amount: float = 1.0):
        name = self._sanitize_metric_name(name)
        with self._lock:
            self._counters[name] = self._counters.get(name, 0.0) + amount

    def get_counter(self, name: str) -> float:
        name = self._sanitize_metric_name(name)
        with self._lock:
            return self._counters.get(name, 0.0)

    # ── Block time histogram ───────────────────────────────────────────────────
    def record_block_time(self, seconds: float):
        with self._lock:
            self._block_times.append(seconds)

    def avg_block_time(self) -> float:
        with self._lock:
            if not self._block_times:
                return 0.0
            return sum(self._block_times) / len(self._block_times)

    # ── Prometheus text export ────────────────────────────────────────────────
    def render_prometheus(self) -> str:
        lines = []
        with self._lock:
            for name, val in self._gauges.items():
                lines.append(f"# TYPE visold_{name} gauge")
                lines.append(f"visold_{name} {val}")
            for name, val in self._counters.items():
                lines.append(f"# TYPE visold_{name} counter")
                lines.append(f"visold_{name}_total {val}")
            if self._block_times:
                avg = sum(self._block_times) / len(self._block_times)
                lines.append("# TYPE visold_block_time_seconds summary")
                lines.append(f"visold_block_time_seconds{{quantile=\"0.5\"}} {avg:.3f}")
                lines.append(f"visold_block_time_seconds_count {len(self._block_times)}")
        return "\n".join(lines) + "\n"


# Global singleton metrics instance
metrics = MetricsCollector()
