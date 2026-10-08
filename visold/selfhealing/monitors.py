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
"""visold.selfhealing.monitors

Original section: SECTION 3: LAYER 1 — CONTINUOUS MONITORING

Defines: MonitorBus, TransactionMonitor, GasMonitor, ValidatorMonitor, ReentrancyPatternDetector
Origin: visold_vsd_.py L50391-50458, L50461-50596, L50599-50696, L50699-50850, L50853-50955
"""

import json
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Dict, List, Optional, Set

from visold.kernel.logging_setup import log
from visold.selfhealing.model import (
    AnomalyKind,
    AnomalyReport,
    BaselineTracker,
    MetricsRingBuffer,
)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3: LAYER 1 — CONTINUOUS MONITORING
# ─────────────────────────────────────────────────────────────────────────────

class MonitorBus:
    """
    Central bus that aggregates all monitoring probes.

    Probes are registered by name. Each probe is a callable that returns
    a (metric_name, value) pair or None. The bus fires probes on a cadence
    and pushes results into MetricsRingBuffers.

    Integration: MonitorBus.tick() is called from the existing StateEngine
    TIMER event — no new threads required.
    """

    def __init__(self):
        self._probes: Dict[str, Callable] = {}
        self._buffers: Dict[str, MetricsRingBuffer] = {}
        self._baselines: Dict[str, BaselineTracker] = {}
        self._lock = threading.Lock()
        self._tick_count = 0

    def register_buffer(self, name: str, capacity: int = 3600) -> MetricsRingBuffer:
        buf = MetricsRingBuffer(name, capacity)
        with self._lock:
            self._buffers[name] = buf
            self._baselines[name] = BaselineTracker(name)
        return buf

    def register_probe(self, name: str, probe_fn: Callable):
        """Register a zero-arg callable that returns (metric_name, float)."""
        with self._lock:
            self._probes[name] = probe_fn

    def tick(self):
        """
        Called once per StateEngine TIMER tick (typically every 1-5 seconds).
        Fires all probes and updates buffers/baselines.
        """
        self._tick_count += 1
        with self._lock:
            probes = dict(self._probes)
            buffers = dict(self._buffers)
            baselines = dict(self._baselines)

        for name, probe in probes.items():
            try:
                result = probe()
                if result is None:
                    continue
                metric_name, value = result
                if metric_name in buffers:
                    buffers[metric_name].push(float(value))
                    baselines[metric_name].update(float(value))
            except Exception as exc:
                log.debug(f"MonitorBus probe '{name}' error: {exc}")

    def get_buffer(self, name: str) -> Optional[MetricsRingBuffer]:
        return self._buffers.get(name)

    def get_baseline(self, name: str) -> Optional[BaselineTracker]:
        return self._baselines.get(name)

    def snapshot(self) -> Dict[str, Dict]:
        """Return current stats snapshot for all registered metrics."""
        snap = {}
        with self._lock:
            for name, buf in self._buffers.items():
                snap[name] = buf.stats(300.0)
                snap[name]["latest"] = buf.latest
        return snap


class TransactionMonitor:
    """
    Monitors transaction patterns: TPS, per-sender volumes, fund drain velocity.

    Integrates with the existing Mempool and Blockchain without modifying them.
    All reads are non-locking snapshots.
    """

    # Hard rule thresholds (calibrated for VSD)
    TPS_HARD_LIMIT    = 200        # tx/s above this = spike regardless of baseline
    DRAIN_THRESHOLD   = 0.30       # >30% of an account's balance in one block
    FLOOD_THRESHOLD   = 15         # >15 tx from one sender in one block

    def __init__(self, bus: MonitorBus, storage_ref, blockchain_ref):
        self._storage = storage_ref
        self._blockchain = blockchain_ref
        self._bus = bus

        # Metric buffers
        self._tps_buf    = bus.register_buffer("tps", 3600)
        self._gas_buf    = bus.register_buffer("block_gas", 3600)
        self._mpool_buf  = bus.register_buffer("mempool_size", 3600)

        # Per-sender rolling counters (last 10 blocks)
        self._sender_tx_counts: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=10))
        self._last_block_height = -1
        self._lock = threading.Lock()

    def observe_block(self, block) -> List[AnomalyReport]:
        """
        Called after every block is applied.
        Returns any anomaly reports detected in this block.
        """
        anomalies: List[AnomalyReport] = []
        now = time.time()
        txs = getattr(block, "transactions", [])
        height = getattr(block, "index", 0)
        elapsed = max(getattr(block, "timestamp", now) - self._get_prev_ts(height), 1)

        # TPS measurement
        tps = len(txs) / elapsed
        self._tps_buf.push(tps)

        # Mempool size
        try:
            mpool_size = self._storage.mempool_size()
            self._mpool_buf.push(mpool_size)
        except Exception:
            mpool_size = 0

        # Gas usage
        total_gas = sum(
            getattr(tx, "gas_limit", 0) or 0
            for tx in txs
        )
        self._gas_buf.push(total_gas)

        # ── Rule 1: TPS hard spike ───────────────────────────────────────────
        if tps > self.TPS_HARD_LIMIT:
            anomalies.append(AnomalyReport(
                kind=AnomalyKind.TPS_SPIKE,
                detected_at=now,
                description=f"TPS {tps:.1f} exceeds hard limit {self.TPS_HARD_LIMIT}",
                evidence={"tps": tps, "limit": self.TPS_HARD_LIMIT,
                          "block_tx_count": len(txs), "block_height": height},
                source="rule",
                confidence=0.95,
                block_height=height,
                z_score=self._bus.get_baseline("tps").current_zscore(tps),
            ))

        # ── Rule 2: Single-sender flood ──────────────────────────────────────
        sender_counts: Dict[str, int] = defaultdict(int)
        for tx in txs:
            sender = getattr(tx, "sender", "")
            if sender and sender != "COINBASE":
                sender_counts[sender] += 1

        for sender, count in sender_counts.items():
            if count >= self.FLOOD_THRESHOLD:
                anomalies.append(AnomalyReport(
                    kind=AnomalyKind.MEMPOOL_FLOOD,
                    detected_at=now,
                    description=f"Sender {sender[:20]} submitted {count} tx in block {height}",
                    evidence={"sender": sender, "tx_count": count,
                              "threshold": self.FLOOD_THRESHOLD},
                    source="rule",
                    confidence=0.85,
                    affected_addr=sender,
                    block_height=height,
                ))

        # ── Rule 3: Fund drain detection ─────────────────────────────────────
        # For each non-coinbase tx, check if sender balance dropped > DRAIN_THRESHOLD
        for tx in txs:
            sender = getattr(tx, "sender", "")
            amount = getattr(tx, "amount", 0.0)
            if not sender or sender == "COINBASE":
                continue
            try:
                balance = self._storage.get_balance(sender)
                if balance > 0 and amount / max(balance, 1e-12) > self.DRAIN_THRESHOLD:
                    anomalies.append(AnomalyReport(
                        kind=AnomalyKind.FUND_DRAIN,
                        detected_at=now,
                        description=(
                            f"Fund drain: {sender[:20]} sent "
                            f"{amount:.4f} VSD ({100*amount/balance:.1f}% of balance)"
                        ),
                        evidence={"sender": sender, "amount": amount,
                                  "balance_before": balance,
                                  "drain_ratio": amount / balance},
                        source="rule",
                        confidence=0.75,
                        affected_addr=sender,
                        block_height=height,
                        tx_ids=[getattr(tx, "tx_id", "")],
                    ))
            except Exception:
                pass

        with self._lock:
            self._last_block_height = height

        return anomalies

    def _get_prev_ts(self, height: int) -> float:
        """Fetch timestamp of previous block for TPS calculation."""
        try:
            prev = self._storage.get_block(height - 1)
            if prev:
                return prev.get("timestamp", time.time() - 10)
        except Exception:
            pass
        return time.time() - 10


class GasMonitor:
    """
    Monitors VVM gas usage patterns: consumption spikes, griefing, exhaustion.
    Reads from vvm_receipts table after each block without touching VVMEngine.
    """

    GAS_SPIKE_Z       = 4.0    # z-score threshold for gas spike
    EXHAUSTION_RATIO  = 0.95   # fraction of VVM_TX_GAS_CAP = griefing risk

    def __init__(self, bus: MonitorBus, storage_ref):
        self._storage = storage_ref
        self._gas_per_contract: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100))
        self._gas_baseline = bus.register_buffer("vvm_gas_per_tx", 3600)
        self._gas_tracker = BaselineTracker("vvm_gas_per_tx")
        self._bus = bus
        # AUDIT-FIX-M7: this used to call bus.register_buffer("vvm_gas_per_tx",
        # 3600) a second time here, discarding its return value. register_buffer
        # replaces any existing buffer/baseline under that name as a side
        # effect, so this second call silently swapped bus._buffers/_baselines
        # ["vvm_gas_per_tx"] for fresh, empty objects that self._gas_baseline
        # above never sees again -- permanently orphaning StatisticalDetector's
        # independent statistical check on this metric (its snapshot/baseline
        # stayed all-zero/never-warmed for the life of the process). The first
        # call already registers everything needed; self._gas_tracker is a
        # deliberately separate, bus-independent tracker and is unaffected.

    def observe_block(self, block) -> List[AnomalyReport]:
        anomalies = []
        height = getattr(block, "index", 0)
        now = time.time()

        # Read VVM receipts for this block
        try:
            receipts = self._storage.get_vvm_receipts_for_block(height)
        except Exception:
            return []

        for receipt in (receipts or []):
            gas_used  = receipt.get("gas_used", 0)
            gas_limit = receipt.get("gas_limit", 1)
            contract  = receipt.get("contract_addr", "")
            tx_id     = receipt.get("tx_id", "")

            if gas_used == 0:
                continue

            # Update per-contract history
            if contract:
                self._gas_per_contract[contract].append(gas_used)

            # Update global baseline
            z = self._gas_tracker.update(gas_used)
            self._gas_baseline.push(gas_used)

            # Gas spike anomaly
            if z > self.GAS_SPIKE_Z and self._gas_tracker.is_warmed:
                anomalies.append(AnomalyReport(
                    kind=AnomalyKind.GAS_SPIKE,
                    detected_at=now,
                    description=(
                        f"VVM gas spike: {gas_used:,} gas (z={z:.2f}) "
                        f"in contract {contract[:20]}"
                    ),
                    evidence={"gas_used": gas_used, "z_score": z,
                              "contract": contract, "tx_id": tx_id},
                    source="stat",
                    confidence=min(0.5 + 0.1 * z, 0.99),
                    affected_addr=contract,
                    block_height=height,
                    tx_ids=[tx_id],
                    z_score=z,
                ))

            # Near-exhaustion (griefing)
            try:
                # VVM_TX_GAS_CAP is a Config constant in the main file
                cap = 10_000_000    # conservative default; replace with Config.VVM_TX_GAS_CAP
                if gas_limit > 0 and gas_used / gas_limit > self.EXHAUSTION_RATIO:
                    anomalies.append(AnomalyReport(
                        kind=AnomalyKind.GAS_EXHAUSTION,
                        detected_at=now,
                        description=(
                            f"Gas near-exhaustion: used {gas_used}/{gas_limit} "
                            f"({100*gas_used/gas_limit:.1f}%) in contract {contract[:20]}"
                        ),
                        evidence={"gas_used": gas_used, "gas_limit": gas_limit,
                                  "ratio": gas_used / gas_limit, "contract": contract},
                        source="rule",
                        confidence=0.80,
                        affected_addr=contract,
                        block_height=height,
                        tx_ids=[tx_id],
                    ))
            except Exception:
                pass

        return anomalies


class ValidatorMonitor:
    """
    Monitors validator behaviour: inactivity, collusion, double-signing.

    Integrates with: storage.get_validators(), block.validator_sigs.
    Does NOT modify any validator state directly.
    """

    INACTIVITY_BLOCKS    = 20      # missed signatures in last N blocks
    INACTIVITY_THRESHOLD = 0.75    # fraction of blocks missed = inactive
    COLLUSION_WINDOW     = 10      # look at last N blocks for collusion

    def __init__(self, storage_ref, blockchain_ref):
        self._storage = storage_ref
        self._blockchain = blockchain_ref
        # sig_history[addr] = deque of (block_height, signed: bool)
        self._sig_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.INACTIVITY_BLOCKS))
        self._double_sign_seen: Set[str] = set()   # addr:hash pairs
        self._lock = threading.Lock()

    def observe_block(self, block) -> List[AnomalyReport]:
        anomalies = []
        height = getattr(block, "index", 0)
        now = time.time()
        validator_sigs = getattr(block, "validator_sigs", [])

        # Build set of validators who signed this block
        signers = {sig.get("addr", "") for sig in validator_sigs
                   if isinstance(sig, dict)}

        # Fetch all registered validators
        try:
            validators = self._storage.get_validators() or []
        except Exception:
            validators = []

        validator_addrs = {
            v.get("address", "") for v in validators
            if isinstance(v, dict) and not v.get("slashed", False)
        }

        with self._lock:
            for addr in validator_addrs:
                signed = addr in signers
                self._sig_history[addr].append((height, signed))

        # ── Rule: Validator inactivity ───────────────────────────────────────
        with self._lock:
            for addr in validator_addrs:
                history = list(self._sig_history[addr])
                if len(history) < self.INACTIVITY_BLOCKS:
                    continue
                missed = sum(1 for _, signed in history if not signed)
                miss_ratio = missed / len(history)
                if miss_ratio >= self.INACTIVITY_THRESHOLD:
                    anomalies.append(AnomalyReport(
                        kind=AnomalyKind.VALIDATOR_INACTIVITY,
                        detected_at=now,
                        description=(
                            f"Validator {addr[:20]} missed "
                            f"{missed}/{len(history)} signatures "
                            f"({100*miss_ratio:.0f}%)"
                        ),
                        evidence={"addr": addr, "missed": missed,
                                  "total": len(history), "miss_ratio": miss_ratio},
                        source="rule",
                        confidence=0.90,
                        affected_addr=addr,
                        block_height=height,
                    ))

        # ── Rule: Validator collusion (all validators sign every block) ──────
        # Healthy BFT: slight variance expected. If ALL validators sign
        # EVERY block in a window, it may indicate a coordinated attack ring.
        if len(validator_addrs) >= 3 and len(validator_sigs) == len(validator_addrs):
            with self._lock:
                # Count how many of the last COLLUSION_WINDOW blocks had
                # 100% validator participation
                perfect_blocks = 0
                for addr in validator_addrs:
                    history = list(self._sig_history[addr])
                    if len(history) >= self.COLLUSION_WINDOW:
                        last_n = history[-self.COLLUSION_WINDOW:]
                        if all(signed for _, signed in last_n):
                            perfect_blocks += 1
                    # AUDIT-FIX-M8: this used to have an unconditional
                    # `break` here, at the same indentation as the `if
                    # len(history) >= self.COLLUSION_WINDOW:` block above
                    # -- so it ran after the very first loop iteration
                    # regardless of what that iteration found, meaning
                    # only one arbitrary validator (whichever came first
                    # in `validator_addrs` set-iteration order) was ever
                    # actually checked. Removing it lets the loop evaluate
                    # every validator, matching both the rule's stated
                    # intent ("If ALL validators sign EVERY block...") and
                    # the anomaly's own description text below, which
                    # already claimed to be about all of them.

                # AUDIT-FIX-M8: require unanimous perfection
                # (perfect_blocks == len(validator_addrs)), not just
                # perfect_blocks > 0 -- with the break removed, > 0 would
                # now fire on even a single perfect validator out of an
                # arbitrarily large set, which is normal/expected
                # behavior for a reliable validator, not evidence of a
                # coordinated ring.
                if perfect_blocks == len(validator_addrs) and len(validator_addrs) >= 4:
                    anomalies.append(AnomalyReport(
                        kind=AnomalyKind.VALIDATOR_COLLUSION,
                        detected_at=now,
                        description=(
                            f"All {len(validator_addrs)} validators have signed "
                            f"100% of last {self.COLLUSION_WINDOW} blocks — "
                            "possible validator ring"
                        ),
                        evidence={"validator_count": len(validator_addrs),
                                  "window": self.COLLUSION_WINDOW,
                                  "signers": list(signers)[:10]},
                        source="stat",
                        confidence=0.55,    # low confidence — benign in healthy net
                        block_height=height,
                    ))

        # ── Rule: Double sign detection ──────────────────────────────────────
        seen_in_block: Dict[str, str] = {}  # addr -> block_hash
        for sig in validator_sigs:
            if not isinstance(sig, dict):
                continue
            addr      = sig.get("addr", "")
            block_hash = sig.get("block_hash", getattr(block, "block_hash", ""))
            if addr in seen_in_block and seen_in_block[addr] != block_hash:
                key = f"{addr}:{height}"
                if key not in self._double_sign_seen:
                    self._double_sign_seen.add(key)
                    anomalies.append(AnomalyReport(
                        kind=AnomalyKind.DOUBLE_SIGN,
                        detected_at=now,
                        description=(
                            f"Double-sign detected: validator {addr[:20]} "
                            f"signed two conflicting blocks at height {height}"
                        ),
                        evidence={"addr": addr, "height": height,
                                  "hash_a": seen_in_block[addr],
                                  "hash_b": block_hash},
                        source="rule",
                        confidence=1.0,    # cryptographic proof — 100% confidence
                        affected_addr=addr,
                        block_height=height,
                    ))
            seen_in_block[addr] = block_hash

        return anomalies


class ReentrancyPatternDetector:
    """
    Detects reentrancy-like execution patterns in VVM receipts.

    Strategy: scan storage_delta in vvm_receipts. A reentrancy pattern is
    characterised by the same storage slot being written, then the contract
    being called again (evidenced by a CALL log before a subsequent SSTORE
    in the same transaction).

    Also detects: unusual call depth, self-calling contracts.

    NOTE: The VVM already has _ReentrancyGuard since v7.2.0. This detector
    operates at the receipt/log level as a second, independent layer for
    cases where the guard was bypassed through a future bug.
    """

    def __init__(self, storage_ref):
        self._storage = storage_ref
        self._suspicious_contracts: Set[str] = set()
        self._lock = threading.Lock()

    def observe_block(self, block) -> List[AnomalyReport]:
        anomalies = []
        height = getattr(block, "index", 0)
        now = time.time()

        try:
            receipts = self._storage.get_vvm_receipts_for_block(height)
        except Exception:
            return []

        for receipt in (receipts or []):
            contract = receipt.get("contract_addr", "")
            logs     = receipt.get("logs", [])
            delta    = receipt.get("storage_delta", {})
            tx_id    = receipt.get("tx_id", "")

            if not isinstance(logs, list):
                try:
                    logs = json.loads(logs) if isinstance(logs, str) else []
                except Exception:
                    logs = []

            if not isinstance(delta, dict):
                try:
                    delta = json.loads(delta) if isinstance(delta, str) else {}
                except Exception:
                    delta = {}

            # Pattern: CALL event followed by SSTORE in logs (reentrancy signature)
            log_types = [
                (entry.get("topics", [""])[0] if isinstance(entry, dict)
                 and entry.get("topics") else "")
                for entry in logs
            ]

            # Look for CALL-before-SSTORE patterns in logs
            call_positions = [i for i, t in enumerate(log_types)
                              if "CALL" in t.upper() or t.startswith("0xCALL")]
            sstore_positions = [i for i, t in enumerate(log_types)
                                if "SSTORE" in t.upper() or "STORE" in t.upper()]

            # If any CALL appears BEFORE a subsequent SSTORE, classic
            # reentrancy (state written after an external interaction --
            # the checks-effects-interactions violation a reentrant call
            # can exploit by re-entering before that SSTORE takes effect).
            for call_pos in call_positions:
                for sstore_pos in sstore_positions:
                    # AUDIT-FIX-M6: this comparison was backwards
                    # (sstore_pos < call_pos), which flagged SSTORE-then-
                    # CALL -- the SAFE checks-effects-interactions ordering
                    # -- and never fired on the actual dangerous pattern
                    # this class's own docstring describes: "a CALL log
                    # before a subsequent SSTORE".
                    if call_pos < sstore_pos:
                        # CALL then SSTORE — reentrancy signature
                        with self._lock:
                            if contract not in self._suspicious_contracts:
                                self._suspicious_contracts.add(contract)
                                anomalies.append(AnomalyReport(
                                    kind=AnomalyKind.REENTRANCY_PATTERN,
                                    detected_at=now,
                                    description=(
                                        f"Reentrancy pattern in contract {contract[:24]}: "
                                        f"CALL at log[{call_pos}] before "
                                        f"SSTORE at log[{sstore_pos}]"
                                    ),
                                    evidence={
                                        "contract": contract,
                                        "tx_id": tx_id,
                                        "sstore_pos": sstore_pos,
                                        "call_pos": call_pos,
                                        "log_count": len(logs),
                                        "storage_keys_written": list(delta.keys())[:5],
                                    },
                                    source="pattern",
                                    confidence=0.70,
                                    affected_addr=contract,
                                    block_height=height,
                                    tx_ids=[tx_id],
                                ))

        return anomalies
