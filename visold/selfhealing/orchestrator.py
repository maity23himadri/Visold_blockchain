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
"""visold.selfhealing.orchestrator

Original section: SECTION 10: MAIN SHBS ORCHESTRATOR

Defines: SelfHealingSystem
Origin: visold_vsd_.py L52592-52866
"""

import threading
import time
from typing import List, Tuple

from visold.kernel.logging_setup import log
from visold.selfhealing.decision import DecisionEngine, GameTheoryModel
from visold.selfhealing.detection import AnomalyDetectionEngine, StatisticalDetector
from visold.selfhealing.healing import (
    FreezeRegistry,
    HealingActionLayer,
    HealingActionLog,
    RateLimiter,
    ValidatorAlerter,
)
from visold.selfhealing.model import AnomalyReport, SeverityDecision
from visold.selfhealing.monitors import (
    GasMonitor,
    MonitorBus,
    ReentrancyPatternDetector,
    TransactionMonitor,
    ValidatorMonitor,
)
from visold.selfhealing.rollback import RollbackExecutor, SnapshotStore
from visold.selfhealing.state_hook import StateEngineHook
from visold.selfhealing.supply_monitor import SupplyConservationMonitor


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10: MAIN SHBS ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class SelfHealingSystem:
    """
    ┌──────────────────────────────────────────────────────────────┐
    │            VISOLD SELF-HEALING BLOCKCHAIN SYSTEM            │
    │                         v1.0.0                              │
    │                                                             │
    │  Instantiation:                                             │
    │    shbs = SelfHealingSystem(blockchain, storage,            │
    │                             state_engine, p2p, governance)  │
    │    shbs.start()                                             │
    │                                                             │
    │  After each block is applied in StateEngine:                │
    │    shbs.on_block_applied(block)                             │
    │                                                             │
    │  RPC integration (add to existing RPC handler):             │
    │    "shbs_status"   → shbs.get_status()                     │
    │    "shbs_log"      → shbs.get_action_log(n=50)             │
    │    "shbs_unfreeze" → shbs.unfreeze(addr)                   │
    │    "shbs_vote"     → shbs.receive_vote(proposal, addr, ...) │
    └──────────────────────────────────────────────────────────────┘

    PERFORMANCE CHARACTERISTICS:
      - observe_block(): O(T) where T = tx count in block
      - MetricsRingBuffer: O(1) push, O(W) window query
      - BaselineTracker: O(1) update (Welford's algorithm)
      - AnomalyDetectionEngine dedup: O(1) per anomaly (hash map)
      - RollbackExecutor: O(D × T) where D = depth, T = txs/block
        (uses existing _rollback_block — no additional DB work)
      - FreezeRegistry: O(1) lookup (hash map)
      - Total overhead per block: ~1-5ms on modern hardware,
        ~5-15ms on Android/Termux (Pydroid3 target environment)
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        blockchain,
        storage,
        state_engine,
        p2p,
        governance=None,
        data_dir: str = "",  # default resolved at runtime via tempfile.gettempdir()
    ):
        self._blockchain  = blockchain
        self._storage     = storage
        self._se          = state_engine
        self._p2p         = p2p
        self._governance  = governance
        # Resolve data_dir at runtime so we get the correct platform temp dir
        # (Android/Pydroid3 may not have /tmp; tempfile.gettempdir() is safe everywhere)
        import tempfile as _tempfile
        self._data_dir    = data_dir if data_dir else \
                            _tempfile.gettempdir() + "/shbs"
        self._running     = False
        self._lock        = threading.Lock()

        # ── Build the pipeline ───────────────────────────────────────────────
        self.bus = MonitorBus()

        # Layer 1: Monitors
        self.tx_monitor      = TransactionMonitor(self.bus, storage, blockchain)
        self.gas_monitor     = GasMonitor(self.bus, storage)
        self.validator_mon   = ValidatorMonitor(storage, blockchain)
        self.reentrancy_det  = ReentrancyPatternDetector(storage)
        self.supply_monitor  = SupplyConservationMonitor(storage, blockchain)

        # Layer 2: ADE
        self.stat_detector   = StatisticalDetector(self.bus)
        self.ade = AnomalyDetectionEngine(
            bus=self.bus,
            tx_monitor=self.tx_monitor,
            gas_monitor=self.gas_monitor,
            validator_monitor=self.validator_mon,
            reentrancy_detector=self.reentrancy_det,
            stat_detector=self.stat_detector,
        )

        # Layer 3: Decision Engine
        self.game_model   = GameTheoryModel(storage)
        self.decision_eng = DecisionEngine(self.game_model)

        # Layer 4: HAL
        self.action_log    = HealingActionLog(storage)
        self.rate_limiter  = RateLimiter()
        self.freeze_reg    = FreezeRegistry()
        self.alerter       = ValidatorAlerter(p2p)
        self.snapshot_store = SnapshotStore(data_dir)
        self.rollback_exec  = RollbackExecutor(blockchain, storage,
                                               self.snapshot_store)
        # Get circuit breaker reference from state engine
        _cb = getattr(state_engine, "_circuit_breaker", None)
        self.hal = HealingActionLayer(
            action_log=self.action_log,
            rate_limiter=self.rate_limiter,
            freeze_registry=self.freeze_reg,
            alerter=self.alerter,
            rollback_executor=self.rollback_exec,
            circuit_breaker_ref=_cb,
            storage_ref=storage,
            blockchain_ref=blockchain,
        )

        # StateEngine hook (installed on start())
        self.se_hook = StateEngineHook(state_engine, self.rate_limiter,
                                       self.freeze_reg)

        # Wire ADE listener → decision engine → HAL
        self.ade.add_listener(self._on_anomaly)

        # Statistics
        self._stats = {
            "blocks_observed": 0,
            "anomalies_detected": 0,
            "actions_taken": 0,
            "rollbacks_initiated": 0,
            "false_positives_suppressed": 0,
            "started_at": 0.0,
        }

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._stats["started_at"] = time.time()

        # Install StateEngine hook
        try:
            self.se_hook.install()
        except Exception as exc:
            log.error(f"[SHBS] StateEngine hook install failed: {exc}")

        log.info(
            f"[SHBS] Self-Healing Blockchain System v{self.VERSION} started. "
            f"Monitoring: TPS, gas, validators, reentrancy, supply conservation.")

    def stop(self) -> None:
        with self._lock:
            self._running = False
        log.info("[SHBS] Stopped.")

    # ── Main hook: called after every block is applied ────────────────────────

    def on_block_applied(self, block) -> List[SeverityDecision]:
        """
        CALL THIS after every successful StateEngine._handle_new_block /
        _handle_mine_result.

        Integration point in StateEngine._handle_new_block:
            # After ok = blockchain.apply_block(block):
            if ok and hasattr(node, 'shbs'):
                node.shbs.on_block_applied(block)

        Returns list of decisions made (for RPC/dashboard display).
        """
        if not self._running:
            return []

        self._stats["blocks_observed"] += 1

        # Layer 1: Monitor tick
        self.bus.tick()

        # Layer 2: ADE observe (anomalies trigger _on_anomaly via listener)
        anomalies = self.ade.observe_block(block)

        # Supply conservation (periodic)
        self.supply_monitor.check(block, self.ade)

        return []  # decisions are dispatched via _on_anomaly callback

    def _on_anomaly(self, report: AnomalyReport) -> None:
        """
        Callback registered with ADE. Runs the Decision Engine and HAL.
        Executes on the StateEngine thread — must be fast.
        """
        if not self._running:
            return

        self._stats["anomalies_detected"] += 1
        height = self._blockchain.height()

        try:
            decision = self.decision_eng.decide(report, height)
        except Exception as exc:
            log.error(f"[SHBS] DecisionEngine error: {exc}")
            return

        if decision.suppress:
            self._stats["false_positives_suppressed"] += 1
            log.debug(
                f"[SHBS] Suppressed: {report.kind.value} "
                f"(conf={report.confidence:.2f})")
            return

        self._stats["actions_taken"] += len(decision.action_tags)
        if "rollback" in decision.action_tags:
            self._stats["rollbacks_initiated"] += 1

        try:
            self.hal.execute(decision)
        except Exception as exc:
            log.error(f"[SHBS] HAL.execute error: {exc}", exc_info=True)

    # ── RPC Interface ─────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        """RPC: shbs_status — full system status snapshot."""
        uptime = time.time() - self._stats["started_at"]
        return {
            "version":    self.VERSION,
            "running":    self._running,
            "uptime_secs": round(uptime, 1),
            "stats":      dict(self._stats),
            "frozen":     self.freeze_reg.all_frozen(),
            "metrics":    self.bus.snapshot(),
            "baselines_warmed": {
                name: tracker.is_warmed
                for name, tracker in self.bus._baselines.items()
            },
        }

    def get_action_log(self, n: int = 50) -> List[dict]:
        """RPC: shbs_log — recent actions taken by SHBS."""
        return self.action_log.recent(n)

    def unfreeze(self, address: str) -> Tuple[bool, str]:
        """RPC: shbs_unfreeze — manually unfreeze an address."""
        if not address:
            return False, "address required"
        self.freeze_reg.unfreeze(address)
        self.rate_limiter.unlimit(address)
        return True, f"Unfrozen: {address}"

    def receive_vote(
        self,
        proposal_id: str,
        validator_addr: str,
        approve: bool,
        sig_hex: str = "",
        pub_hex: str = "",
    ) -> Tuple[bool, str]:
        """RPC: shbs_vote — cast a validator vote for a rollback proposal."""
        result = self.hal.receive_validator_vote(
            proposal_id, validator_addr, approve, sig_hex, pub_hex)
        return result == "accepted", result

    def confirm_rollback_preview(
        self,
        confirm_id: str,
        validator_addr: str,
        approve: bool,
        sig_hex: str = "",
        pub_hex: str = "",
    ) -> Tuple[bool, str]:
        """
        AUDIT-FIX-6: RPC: shbs_confirm_rollback — cast a SECOND-round vote
        explicitly confirming a rollback preview before it executes.

        Only meaningful once v2 hardening is active (rollback_exec.execute
        is patch_rollback_executor's _hardened_execute, which is what
        actually creates and waits on these confirmations — see that
        function's docstring). If hardening hasn't been applied,
        confirm_preview won't exist on rollback_exec and this returns a
        clear "not_available" rather than silently doing nothing.
        """
        confirm_fn = getattr(self.rollback_exec, "confirm_preview", None)
        if confirm_fn is None:
            return False, "not_available (SHBS v2 hardening not active)"
        result = confirm_fn(confirm_id, validator_addr, approve,
                            sig_hex, pub_hex)
        return result == "accepted", result
