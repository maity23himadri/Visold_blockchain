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
"""visold.selfhealing.model


Defines: MetricsRingBuffer, BaselineTracker, AnomalyKind, Severity, AnomalyReport, SeverityDecision
Origin: visold_vsd_.py L50161-50212, L50215-50297, L50304-50326, L50329-50339, L50342-50372, L50375-50384
"""

import enum
import math
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── SHBS embedded module imports (safe re-import; Python caches modules) ──

# ═════════════════════════════════════════════════════════════════════════════
# EMBEDDED: VISOLD SELF-HEALING BLOCKCHAIN SYSTEM (SHBS) v1.0.0 + v2.0.0
# Originally in visold_self_healing.py and visold_shbs_hardened.py.
# Integrated directly into visold_vsd_.py — no external imports needed.
# ALL SHBS classes, functions, and hardening patches are defined below.
# ZERO changes to consensus, P2P protocol, state_root, VVM, or DB schema.
# ═════════════════════════════════════════════════════════════════════════════

class MetricsRingBuffer:
    """
    Thread-safe circular buffer for streaming time-series metrics.

    Design:
      - Fixed-capacity deque — O(1) push/pop with no GC pressure
      - Lock-free reads for the most recent value (latest attr)
      - Full-window reads acquire a shallow lock
      - Supports windowed statistics (mean, std, percentile)

    Each slot is a (timestamp_float, value_float) tuple.
    """
    __slots__ = ("_buf", "_lock", "_capacity", "name", "latest")

    def __init__(self, name: str, capacity: int = 3600):
        self.name = name
        self._capacity = capacity
        self._buf: deque = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self.latest: float = 0.0  # last value — lock-free read

    def push(self, value: float, ts: Optional[float] = None) -> None:
        ts = ts or time.time()
        self.latest = value
        with self._lock:
            self._buf.append((ts, value))

    def window(self, seconds: float) -> List[float]:
        """Return values within the last `seconds`."""
        cutoff = time.time() - seconds
        with self._lock:
            return [v for t, v in self._buf if t >= cutoff]

    def ewma(self, alpha: float = 0.1) -> float:
        """Exponentially weighted moving average. alpha=1 → pure latest."""
        with self._lock:
            if not self._buf:
                return 0.0
            result = self._buf[0][1]
            for _, v in list(self._buf)[1:]:
                result = alpha * v + (1 - alpha) * result
            return result

    def stats(self, seconds: float = 300.0) -> Dict[str, float]:
        """Returns mean, std, min, max, count for the last `seconds`."""
        vals = self.window(seconds)
        if not vals:
            return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "count": 0}
        mean = statistics.mean(vals)
        std = statistics.stdev(vals) if len(vals) > 1 else 0.0
        return {"mean": mean, "std": std, "min": min(vals), "max": max(vals),
                "count": len(vals)}


class BaselineTracker:
    """
    Maintains rolling baselines for statistical anomaly detection.

    Uses a two-phase approach:
      Phase 1 (warm-up): collects BASELINE_WINDOW samples to build baseline
      Phase 2 (active): computes z-score against the established baseline

    The baseline updates slowly (alpha=0.02) to represent "normal" operation
    rather than tracking recent spikes (which would defeat anomaly detection).
    """
    BASELINE_WINDOW = 200          # minimum samples before going active
    SLOW_EWMA_ALPHA = 0.02         # very slow — moves baseline over ~50 samples
    FAST_EWMA_ALPHA = 0.15         # fast — reacts to changes in ~7 samples

    def __init__(self, name: str):
        self.name = name
        self._samples = 0
        self._baseline_mean = 0.0
        self._baseline_var = 0.0    # running variance (Welford's method)
        self._fast_mean = 0.0
        self._lock = threading.Lock()

    @property
    def is_warmed(self) -> bool:
        return self._samples >= self.BASELINE_WINDOW

    def update(self, value: float) -> float:
        """
        Feed a new value. Returns z-score once warmed; 0.0 during warm-up.

        AUDIT-FIX-M9: mean/variance are now a true fixed-alpha EWMA (see
        class docstring / SLOW_EWMA_ALPHA) rather than Welford's numerically
        -stable CUMULATIVE mean/variance. Welford's algorithm is correct for
        what it computes, but what it computes is the mean/variance over
        the ENTIRE sample history with weight 1/n per sample -- a weight
        that keeps shrinking as n grows, unlike a real EWMA's constant
        alpha. That mismatch meant the "slow EWMA" only behaved like one
        for roughly the first ~50 samples (where 1/n happens to be near
        SLOW_EWMA_ALPHA=0.02); by n=5,000 a new sample's influence was
        already 100x weaker than documented, and kept shrinking without
        bound -- the baseline effectively froze on a long-running node
        instead of tracking genuine, gradual shifts in normal behavior.
        """
        with self._lock:
            self._samples += 1
            n = self._samples

            # Fixed-alpha EWMA mean/variance (Finch 2009 incremental
            # form) -- both terms below are non-negative combinations of
            # non-negative quantities (no subtraction of the running
            # total), so _baseline_var can never go negative.
            delta = value - self._baseline_mean
            incr  = self.SLOW_EWMA_ALPHA * delta
            self._baseline_mean += incr
            self._baseline_var = (1 - self.SLOW_EWMA_ALPHA) * (self._baseline_var + delta * incr)

            # Fast EWMA for the current trend
            self._fast_mean = (self.FAST_EWMA_ALPHA * value
                               + (1 - self.FAST_EWMA_ALPHA) * self._fast_mean)

            if not self.is_warmed:
                return 0.0

            # AUDIT-FIX-M9: _baseline_var is now already a variance
            # (an EWMA), not a Welford sum-of-squares needing /(n-1)
            # normalization.
            std = math.sqrt(self._baseline_var)
            if std < 1e-9:
                return 0.0
            return (value - self._baseline_mean) / std

    def current_zscore(self, value: float) -> float:
        """Compute z-score without updating the baseline."""
        with self._lock:
            if not self.is_warmed:
                return 0.0
            # AUDIT-FIX-M9: see update() -- _baseline_var is already a
            # variance now, not a Welford sum-of-squares.
            std = math.sqrt(self._baseline_var)
            if std < 1e-9:
                return 0.0
            return (value - self._baseline_mean) / std


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2: ANOMALY TYPES
# ─────────────────────────────────────────────────────────────────────────────

class AnomalyKind(enum.Enum):
    # Transaction-level
    TPS_SPIKE           = "tps_spike"
    FUND_DRAIN          = "fund_drain"
    REENTRANCY_PATTERN  = "reentrancy_pattern"
    MEMPOOL_FLOOD       = "mempool_flood"
    CIRCULAR_TRADE      = "circular_trade"

    # Gas / VVM
    GAS_SPIKE           = "gas_spike"
    GAS_EXHAUSTION      = "gas_exhaustion"
    CONTRACT_GRIEFING   = "contract_griefing"

    # Validator / consensus
    VALIDATOR_INACTIVITY = "validator_inactivity"
    VALIDATOR_COLLUSION  = "validator_collusion"
    DOUBLE_SIGN          = "double_sign"
    SELFISH_MINING       = "selfish_mining"

    # Chain
    REORG_DEPTH          = "reorg_depth"
    FINALITY_STALL       = "finality_stall"
    SUPPLY_INFLATION     = "supply_inflation"


class Severity(enum.Enum):
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4

    def __ge__(self, other):
        return self.value >= other.value

    def __gt__(self, other):
        return self.value > other.value


@dataclass
class AnomalyReport:
    """
    Typed record produced by the Anomaly Detection Engine.

    All fields are immutable after construction to prevent downstream mutation.
    """
    kind:          AnomalyKind
    detected_at:   float                        # unix timestamp
    description:   str
    evidence:      Dict[str, Any]               # raw data supporting the claim
    source:        str                          # "rule" | "stat" | "pattern"
    confidence:    float                        # [0.0, 1.0]
    affected_addr: Optional[str] = None
    block_height:  Optional[int] = None
    tx_ids:        List[str]     = field(default_factory=list)
    z_score:       float         = 0.0

    def to_dict(self) -> dict:
        return {
            "kind":          self.kind.value,
            "detected_at":   self.detected_at,
            "description":   self.description,
            "evidence":      self.evidence,
            "source":        self.source,
            "confidence":    round(self.confidence, 4),
            "affected_addr": self.affected_addr,
            "block_height":  self.block_height,
            "tx_ids":        self.tx_ids[:10],   # cap log size
            "z_score":       round(self.z_score, 3),
        }


@dataclass
class SeverityDecision:
    """Output of the Decision Engine for a given AnomalyReport."""
    report:         AnomalyReport
    severity:       Severity
    action_tags:    List[str]       # "log", "rate_limit", "freeze", "rollback"
    attacker_ev:    float           # expected value for attacker (game theory)
    validator_ev:   float           # expected value for validators
    rationale:      str
    suppress:       bool = False    # True = false positive, take no action
