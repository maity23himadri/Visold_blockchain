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
"""visold.selfhealing.healing

Original section: SECTION 7: LAYER 4 — SELF-HEALING ACTION LAYER (HAL)

Defines: HealingActionLog, RateLimiter, FreezeRegistry, ValidatorAlerter, HealingActionLayer
Origin: visold_vsd_.py L51830-51902, L51905-51951, L51954-52022, L52025-52069, L52072-52384
"""

import hashlib
import json
import threading
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

from visold.kernel.logging_setup import log
from visold.selfhealing.model import AnomalyKind, Severity, SeverityDecision
from visold.selfhealing.rollback import GovernanceRollbackVote, RollbackExecutor
from visold.selfhealing.storage_patch import _fmt_time


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7: LAYER 4 — SELF-HEALING ACTION LAYER (HAL)
# ─────────────────────────────────────────────────────────────────────────────

class HealingActionLog:
    """
    Immutable audit log of all actions taken by the SHBS.
    Persisted to a dedicated table in aux-SQLite.
    """

    CREATE_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS shbs_action_log (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ts           REAL    NOT NULL,
        severity     TEXT    NOT NULL,
        anomaly_kind TEXT    NOT NULL,
        actions      TEXT    NOT NULL,
        rationale    TEXT    NOT NULL,
        affected_addr TEXT   DEFAULT '',
        block_height  INTEGER DEFAULT -1,
        attacker_ev   REAL    DEFAULT 0,
        suppressed    INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS shbs_idx_ts ON shbs_action_log(ts DESC);
    CREATE INDEX IF NOT EXISTS shbs_idx_kind ON shbs_action_log(anomaly_kind);
    """

    def __init__(self, storage_ref):
        self._storage = storage_ref
        self._ensure_table()

    def _ensure_table(self):
        try:
            c = self._storage._conn()
            c.executescript(self.CREATE_TABLE_SQL)
            c.commit()
        except Exception as exc:
            log.debug(f"HealingActionLog init: {exc}")

    def record(self, decision: SeverityDecision) -> None:
        try:
            c = self._storage._conn()
            c.execute(
                """INSERT INTO shbs_action_log
                   (ts, severity, anomaly_kind, actions, rationale,
                    affected_addr, block_height, attacker_ev, suppressed)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    decision.report.detected_at,
                    # Duck-typed: SeverityDecision has .severity.name,
                    # HardenedDecision has .action_stage (str, no .severity)
                    (decision.severity.name
                     if hasattr(decision, "severity")
                     else getattr(decision, "action_stage", "UNKNOWN")),
                    decision.report.kind.value,
                    json.dumps(decision.action_tags),
                    decision.rationale,
                    decision.report.affected_addr or "",
                    decision.report.block_height or -1,
                    decision.attacker_ev,
                    1 if decision.suppress else 0,
                )
            )
            c.commit()
        except Exception as exc:
            log.debug(f"HealingActionLog.record: {exc}")

    def recent(self, n: int = 50) -> List[dict]:
        try:
            c = self._storage._conn()
            rows = c.execute(
                "SELECT * FROM shbs_action_log ORDER BY ts DESC LIMIT ?",
                (n,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []


class RateLimiter:
    """
    Per-address rate limiter for MEDIUM severity actions.

    Integration: RateLimiter.limit(addr) is called before StateEngine
    processes a transaction from that address. Returns (allow: bool, msg: str).

    Uses a sliding window counter stored in memory (not DB) — resets on restart.
    This is intentional: a node restart clears rate limits (avoids permanent
    punishment from false positives).
    """
    WINDOW_SECS  = 60
    DEFAULT_LIMIT = 3      # tx per window when limited

    def __init__(self):
        self._windows: Dict[str, deque] = defaultdict(deque)
        self._limited: Set[str] = set()
        self._lock = threading.Lock()

    def limit(self, address: str):
        """Apply rate limiting to an address."""
        with self._lock:
            self._limited.add(address)
            log.warning(f"[HAL] Rate limiting activated for {address[:24]}")

    def unlimit(self, address: str):
        with self._lock:
            self._limited.discard(address)

    def check(self, address: str) -> Tuple[bool, str]:
        """
        Returns (allow: bool, reason: str).
        Called from a hooked StateEngine._handle_new_tx.
        """
        with self._lock:
            if address not in self._limited:
                return True, "ok"
            now = time.time()
            window = self._windows[address]
            while window and now - window[0] > self.WINDOW_SECS:
                window.popleft()
            if len(window) >= self.DEFAULT_LIMIT:
                return False, (
                    f"SHBS rate limit: max {self.DEFAULT_LIMIT} tx/"
                    f"{self.WINDOW_SECS}s during anomaly response")
            window.append(now)
            return True, "limited but allowed"


class FreezeRegistry:
    """
    Registry of frozen contracts and accounts.

    HIGH severity actions freeze contracts/accounts.

    AUDIT-FIX-8 (corrected scope): freeze state is LOCAL and per-node —
    it is never persisted, never gossiped as a binding decision, and is
    NOT part of consensus. A frozen entity's transactions are rejected by
    THIS node's StateEngine hook (gossip admission into ITS mempool), and
    excluded from candidate blocks THIS node proposes
    (ConsensusEngine.build_candidate_block), but they can still confirm
    on-chain via any OTHER node — one that hasn't independently reached
    the same freeze decision, doesn't run SHBS, or already had the
    transaction pooled before the freeze landed. Treat this as relay/
    mining-policy friction that slows a suspected-malicious sender down
    on freezing nodes, not as a network-wide guarantee that a frozen
    sender's transactions cannot be confirmed at all.

    Freezes are time-limited (default 10 minutes) to prevent permanent
    service denial from false positives.

    Integration: FreezeRegistry.is_frozen(addr) is called from the
    StateEngine._handle_new_tx hook (gossip admission) and from
    ConsensusEngine.build_candidate_block (this node's own mining
    selection). It is deliberately NEVER called from
    Blockchain.apply_block/validate_block — doing so would make block
    validity depend on per-node freeze state, which differs node to node,
    and would let honest nodes disagree about whether the same block is
    valid.
    """
    DEFAULT_FREEZE_SECS = 600   # 10 minutes

    def __init__(self):
        self._frozen: Dict[str, float] = {}   # addr → unfreeze_at
        self._lock = threading.Lock()

    def freeze(self, address: str, duration_secs: Optional[float] = None):
        duration_secs = duration_secs or self.DEFAULT_FREEZE_SECS
        until = time.time() + duration_secs
        with self._lock:
            self._frozen[address] = until
        log.warning(
            f"[HAL] FROZEN: {address[:28]} for {duration_secs:.0f}s "
            f"(until {_fmt_time(until)})")

    def unfreeze(self, address: str):
        with self._lock:
            self._frozen.pop(address, None)
        log.info(f"[HAL] UNFROZEN: {address[:28]}")

    def is_frozen(self, address: str) -> bool:
        with self._lock:
            until = self._frozen.get(address)
            if until is None:
                return False
            if time.time() >= until:
                del self._frozen[address]
                return False
            return True

    def all_frozen(self) -> Dict[str, float]:
        with self._lock:
            now = time.time()
            # Clean expired
            expired = [a for a, u in self._frozen.items() if now >= u]
            for a in expired:
                del self._frozen[a]
            return dict(self._frozen)


class ValidatorAlerter:
    """
    Broadcasts anomaly alerts to all connected validators via P2P.

    Uses a custom message type MSG_SHBS_ALERT to avoid interfering with
    existing gossip deduplication. Validators that receive this message
    can inspect the evidence and optionally cast a governance vote.

    Integration: calls P2PNetwork._gossip() with the alert payload.
    The P2P layer does NOT need modification — MSG_SHBS_ALERT is treated
    as an application-layer message and is not dedup'd (it is not in
    the gossip dedup cache by default for unknown types).
    """
    MSG_TYPE = "SHBS_ALERT"

    def __init__(self, p2p_ref):
        self._p2p = p2p_ref

    def alert(self, decision) -> None:
        """Broadcast alert to all connected peers/validators.
        Accepts both SeverityDecision (has .severity enum) and
        HardenedDecision (has .action_stage str, no .severity)."""
        try:
            # Duck-typed severity string works for both decision types:
            #   SeverityDecision → decision.severity.name  (Severity enum)
            #   HardenedDecision → decision.action_stage   (plain str)
            sev_str = (
                decision.severity.name
                if hasattr(decision, "severity")
                else getattr(decision, "action_stage", "UNKNOWN")
            )
            payload = {
                "type":    self.MSG_TYPE,
                "alert":   decision.report.to_dict(),
                "severity": sev_str,
                "actions":  decision.action_tags,
                "rationale": decision.rationale,
                "ts":       time.time(),
            }
            self._p2p._gossip(payload, exclude=None)
            log.info(
                f"[HAL] Alert broadcast: {decision.report.kind.value} "
                f"severity={sev_str}")
        except Exception as exc:
            log.error(f"[HAL] ValidatorAlerter failed: {exc}")


class HealingActionLayer:
    """
    Orchestrates all healing actions based on a SeverityDecision.

    Action dispatch table:
      "log"               → HealingActionLog.record()
      "rate_limit"        → RateLimiter.limit(affected_addr)
      "freeze_account"    → FreezeRegistry.freeze(affected_addr, 600s)
      "freeze_contract"   → FreezeRegistry.freeze(affected_addr, 600s)
      "freeze_chain"      → PanicCircuitBreaker.trip()
      "alert_validators"  → ValidatorAlerter.alert()
      "alert_network"     → ValidatorAlerter.alert() + extra priority
      "slash_validator"   → trigger existing SlashingEvidenceProtocol
      "rollback"          → GovernanceRollbackVote + RollbackExecutor

    Each action is idempotent and guarded by a try/except so a failure
    in one action does not prevent subsequent actions from running.
    """

    # Maximum rollback depth for different severity levels
    ROLLBACK_DEPTH: Dict[Severity, int] = {
        Severity.CRITICAL: 10,
        Severity.HIGH:     3,
    }

    def __init__(
        self,
        action_log: HealingActionLog,
        rate_limiter: RateLimiter,
        freeze_registry: FreezeRegistry,
        alerter: ValidatorAlerter,
        rollback_executor: RollbackExecutor,
        circuit_breaker_ref,
        storage_ref,
        blockchain_ref,
    ):
        self._log       = action_log
        self._rl        = rate_limiter
        self._freeze    = freeze_registry
        self._alerter   = alerter
        self._rollback  = rollback_executor
        self._cb        = circuit_breaker_ref
        self._storage   = storage_ref
        self._blockchain = blockchain_ref

        # Active rollback proposals (proposal_id → GovernanceRollbackVote)
        self._active_votes: Dict[str, GovernanceRollbackVote] = {}
        self._votes_lock = threading.Lock()

    def execute(self, decision: SeverityDecision) -> None:
        """
        Execute all actions prescribed by the decision.
        Called synchronously from SHBS.process_anomaly().
        """
        if decision.suppress:
            log.debug(
                f"[HAL] Suppressed (false positive gate): "
                f"{decision.report.kind.value}")
            return

        # Always log — even LOW severity
        try:
            self._log.record(decision)
        except Exception as exc:
            log.error(f"[HAL] action_log failed: {exc}")

        log.warning(
            f"[HAL] {(decision.severity.name if hasattr(decision, 'severity') else getattr(decision, 'action_stage', 'UNKNOWN'))} | {decision.report.kind.value} | "
            f"actions={decision.action_tags} | "
            f"attacker_ev={decision.attacker_ev:.2f} VSD | "
            f"confidence={decision.report.confidence:.2f}")

        for action in decision.action_tags:
            try:
                self._dispatch_action(action, decision)
            except Exception as exc:
                log.error(f"[HAL] action '{action}' error: {exc}", exc_info=True)

    def _dispatch_action(self, action: str, decision) -> None:
        addr = decision.report.affected_addr
        # Duck-typed: SeverityDecision has .severity (Severity enum),
        # HardenedDecision has .action_stage (str) and no .severity.
        sev_str = (
            decision.severity.name
            if hasattr(decision, "severity")
            else getattr(decision, "action_stage", "UNKNOWN")
        )
        block_height = decision.report.block_height or self._blockchain.height()

        if action == "log":
            pass   # already logged above

        elif action == "rate_limit":
            if addr:
                self._rl.limit(addr)

        elif action in ("freeze_account", "freeze_contract"):
            if addr:
                # HIGH = 10min, CRITICAL = 30min
                duration = 1800 if sev_str == "CRITICAL" else 600
                self._freeze.freeze(addr, duration)

        elif action == "freeze_chain":
            # Use existing PanicCircuitBreaker
            try:
                if self._cb and not self._cb.is_open:
                    self._cb.trip(
                        reason=f"SHBS CRITICAL: {decision.report.description[:80]}")
                    log.critical("[HAL] Circuit breaker tripped — chain in READ-ONLY mode")
            except Exception as exc:
                log.error(f"[HAL] circuit_breaker.trip failed: {exc}")

        elif action in ("alert_validators", "alert_network"):
            self._alerter.alert(decision)

        elif action == "slash_validator":
            # Use existing SlashingEvidenceProtocol
            if addr:
                try:
                    self._trigger_slash(addr, decision)
                except Exception as exc:
                    log.error(f"[HAL] slash failed: {exc}")

        elif action == "rollback":
            self._initiate_governance_rollback(decision, block_height)

    def _trigger_slash(self, validator_addr: str, decision: SeverityDecision) -> None:
        """
        Trigger slashing via existing SlashingEvidenceProtocol.
        Only applicable for DOUBLE_SIGN anomalies where evidence contains sigs.
        """
        if decision.report.kind != AnomalyKind.DOUBLE_SIGN:
            log.warning(
                f"[HAL] Slash requested for non-double-sign anomaly "
                f"({decision.report.kind.value}) — skipping")
            return

        evidence = decision.report.evidence
        # SlashingEvidenceProtocol.submit() is called from existing code
        # when add_validator_sig() detects a double-sign.
        # Here we log for the governance audit trail.
        log.warning(
            f"[HAL] Slash evidence recorded for validator {validator_addr[:24]}: "
            f"double-sign at block {evidence.get('height', '?')}")

        try:
            # Mark validator as slashed in storage (existing method)
            self._storage.slash_validator(validator_addr)
            log.warning(f"[HAL] Validator {validator_addr[:24]} SLASHED")
        except Exception as exc:
            log.error(f"[HAL] storage.slash_validator failed: {exc}")

    def _initiate_governance_rollback(
        self,
        decision: SeverityDecision,
        current_height: int,
    ) -> None:
        """
        Start a governance vote for rollback.
        The vote window is VOTE_WINDOW_SECS. If quorum is reached,
        RollbackExecutor.execute() is called.
        """
        # AUDIT-FIX-M4: an explicit operator-requested target height (set by
        # submit_rollback_proposal) takes priority over the severity-based
        # lookup below. Previously this was always recomputed from
        # action_stage/ROLLBACK_DEPTH, which silently discarded the
        # caller's actual requested depth (submit_rollback_proposal hardcodes
        # action_stage="CRITICAL" regardless of what depth was asked for,
        # so depth always came out as ROLLBACK_DEPTH[CRITICAL]==10).
        _explicit_target = getattr(decision, "explicit_rollback_target_height", None)
        if _explicit_target is not None:
            target_height = max(0, _explicit_target)
            depth = max(0, current_height - target_height)
        else:
            # Duck-typed: SeverityDecision has .severity (Severity enum),
            # HardenedDecision has .action_stage (str). Map action_stage to
            # a Severity-like key for ROLLBACK_DEPTH lookup.
            _sev_key = (decision.severity
                        if hasattr(decision, "severity")
                        else {
                            "CRITICAL": Severity.CRITICAL,
                            "HIGH":     Severity.HIGH,
                        }.get(getattr(decision, "action_stage", ""), None))
            depth = self.ROLLBACK_DEPTH.get(_sev_key, 5) if _sev_key is not None else 5
            target_height = max(0, current_height - depth)

        proposal_id = hashlib.sha256(
            f"{current_height}:{decision.report.kind.value}:{time.time()}".encode()
        ).hexdigest()[:16]

        vote = GovernanceRollbackVote(
            storage_ref=self._storage,
            proposal_id=proposal_id,
            rollback_depth=depth,
            evidence=decision.report.evidence,
        )

        with self._votes_lock:
            self._active_votes[proposal_id] = vote

        log.critical(
            f"[HAL] Governance rollback initiated: proposal={proposal_id} "
            f"depth={depth} target_height={target_height}")

        # Check quorum immediately (handles solo-node / no-validators scenario)
        status = vote.quorum_status()
        if status.get("auto_approve") or status["reached"]:
            self._execute_rollback(vote, target_height, decision)
            return

        # Otherwise, start a background timer thread to wait for votes
        def _vote_monitor():
            deadline = time.time() + GovernanceRollbackVote.VOTE_WINDOW_SECS
            while time.time() < deadline:
                time.sleep(1.0)
                status = vote.quorum_status()
                if status["fast_track"] or status["reached"]:
                    log.warning(
                        f"[HAL] Quorum reached for rollback {proposal_id}: "
                        f"{status['approve_count']}/{status['total_validators']}")
                    # AUDIT-FIX-M5 (Piece A): recompute target_height from
                    # the chain height NOW, right before executing --
                    # rather than reusing the value captured before this
                    # (up to VOTE_WINDOW_SECS-long) wait. `depth` is the
                    # quantity actually shown/approved and stays fixed;
                    # only its derived absolute target_height is refreshed,
                    # so the executed rollback doesn't silently reach
                    # further back than what was approved just because new
                    # blocks were mined during the vote.
                    _fresh_height = self._blockchain.height()
                    target_height = max(0, _fresh_height - depth)
                    self._execute_rollback(vote, target_height, decision)
                    return
            # Timed out — log failure
            log.error(
                f"[HAL] Rollback {proposal_id} failed: quorum not reached "
                f"within {GovernanceRollbackVote.VOTE_WINDOW_SECS}s. "
                f"Votes: {vote.quorum_status()}")
            vote.close()
            with self._votes_lock:
                self._active_votes.pop(proposal_id, None)

        t = threading.Thread(target=_vote_monitor, daemon=True,
                             name=f"shbs-vote-{proposal_id[:8]}")
        t.start()

    def _execute_rollback(
        self,
        vote: GovernanceRollbackVote,
        target_height: int,
        decision: SeverityDecision,
    ) -> None:
        vote.close()
        with self._votes_lock:
            self._active_votes.pop(vote.proposal_id, None)

        flagged = set()
        if decision.report.affected_addr:
            flagged.add(decision.report.affected_addr)

        # AUDIT-FIX-O4a: patch_rollback_executor() replaces self._rollback's
        # bound .execute with a hardened version (rate limit, depth cap,
        # preview-confirmation quorum round, staleness re-check, post-verify)
        # -- but the documented deployment order is shbs.start() THEN,
        # separately, apply_hardening_patch(shbs). start() installs the
        # StateEngine hook immediately, so HAL is live and able to reach this
        # method before the patch has run. Before that patch runs,
        # self._rollback.execute is still the raw, unhardened
        # RollbackExecutor.execute. confirm_preview is only ever set by the
        # same patch (see patch_rollback_executor), so its absence is a
        # reliable "not hardened yet" signal -- this is the same check
        # SelfHealingSystem.confirm_rollback_preview already uses for the
        # same reason.
        if getattr(self._rollback, "confirm_preview", None) is None:
            log.critical(
                "[HAL] ROLLBACK REFUSED: hardening (patch_rollback_executor) "
                "has not been applied to this rollback executor yet -- "
                "refusing to auto-execute through the unprotected path. "
                "Call apply_hardening_patch(shbs) before shbs.start(), or "
                "before any block can trigger an anomaly-driven rollback.")
            return

        ok, msg = self._rollback.execute(
            target_height=target_height,
            flagged_addresses=flagged,
            replay_safe=True,
        )

        if ok:
            log.critical(
                f"[HAL] ROLLBACK COMPLETE: {msg}")
        else:
            log.critical(
                f"[HAL] ROLLBACK FAILED: {msg}")

    def receive_validator_vote(
        self,
        proposal_id: str,
        validator_addr: str,
        approve: bool,
        sig_hex: str = "",
        pub_hex: str = "",
    ) -> str:
        """Called when a validator vote arrives via P2P MSG_SHBS_VOTE."""
        with self._votes_lock:
            vote = self._active_votes.get(proposal_id)
        if vote is None:
            return "no_active_proposal"
        result = vote.add_vote(validator_addr, approve, sig_hex, pub_hex)
        log.info(
            f"[HAL] Vote {result}: validator={validator_addr[:20]} "
            f"approve={approve} proposal={proposal_id}")
        return result
