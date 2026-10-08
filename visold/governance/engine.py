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
"""visold.governance.engine

Original section: SECTION 1E2: GOVERNANCE ENGINE — Full Upgrade Lifecycle

Defines: UpgradePhase, UpgradeProposal, GovernanceEngine
Origin: visold_vsd_.py L5983-5997, L6000-6078, L6081-6732
"""

import threading
import time
import enum as _enum
from collections import deque
from typing import Dict, List, Optional, TYPE_CHECKING, Tuple

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.governance.versioning import ProtocolVersionManager
    from visold.ledger.block import Block
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1E2: GOVERNANCE ENGINE — Full Upgrade Lifecycle
# ─────────────────────────────────────────────────────────────────────────────

class UpgradePhase(_enum.Enum):
    """
    State machine phases for a protocol upgrade proposal.

    DORMANT    — Proposal announced; signaling not yet started.
    SIGNALING  — Miners embed new protocol_version; engine counts fraction.
    LOCKED_IN  — ≥threshold fraction reached; activation_height committed.
    ACTIVE     — activation_height passed; new rules enforced.
    FAILED     — Rollback triggered or emergency disable invoked.
    """
    DORMANT   = "DORMANT"
    SIGNALING = "SIGNALING"
    LOCKED_IN = "LOCKED_IN"
    ACTIVE    = "ACTIVE"
    FAILED    = "FAILED"


class UpgradeProposal:
    """
    Immutable record of a protocol upgrade proposal.

    All heights are deterministic — given the same chain history, every honest
    node independently arrives at the same phase and the same heights with no
    extra coordination.

    Fields
    ──────
    version             : target protocol version being upgraded to
    signal_start_height : block height at which signaling begins counting
    signal_end_height   : last block in the signaling window
                          (signal_start + FORK_SIGNAL_WINDOW)
    lock_in_height      : height at which we check the final signal fraction
    activation_height   : height after which new rules are enforced
                          (lock_in_height + GOVERNANCE_ACTIVATION_DELAY)
    threshold           : fraction of blocks that must signal (default 0.75)
    rollback_window     : number of blocks after activation to watch for failure
    """
    __slots__ = ("version", "phase", "signal_start_height", "signal_end_height",
                 "lock_in_height", "activation_height", "threshold",
                 "rollback_window", "disabled")

    def __init__(self, version: int, phase: UpgradePhase,
                 signal_start_height: int, signal_end_height: int,
                 lock_in_height: int, activation_height: int,
                 threshold: float = 0.75, rollback_window: int = 100,
                 disabled: bool = False):
        self.version             = version
        self.phase               = phase
        self.signal_start_height = signal_start_height
        self.signal_end_height   = signal_end_height
        self.lock_in_height      = lock_in_height
        self.activation_height   = activation_height
        self.threshold           = threshold
        self.rollback_window     = rollback_window
        self.disabled            = disabled

    def to_dict(self) -> dict:
        return {
            "version":             self.version,
            "phase":               self.phase.value,
            "signal_start_height": self.signal_start_height,
            "signal_end_height":   self.signal_end_height,
            "lock_in_height":      self.lock_in_height,
            "activation_height":   self.activation_height,
            "threshold":           self.threshold,
            "rollback_window":     self.rollback_window,
            "disabled":            self.disabled,
        }

    @classmethod
    def from_db_row(cls, row: dict) -> 'UpgradeProposal':
        return cls(
            version             = row["version"],
            phase               = UpgradePhase(row["phase"]),
            signal_start_height = row["signal_start_height"],
            signal_end_height   = row["signal_end_height"],
            lock_in_height      = row["lock_in_height"],
            activation_height   = row["activation_height"],
            threshold           = row["threshold"],
            rollback_window     = row["rollback_window"],
            disabled            = bool(row["disabled"]),
        )

    def _persist(self, storage: 'Storage'):
        """Write current state to database (called after every phase transition)."""
        storage.save_upgrade_proposal(
            version         = self.version,
            phase           = self.phase.value,
            signal_start    = self.signal_start_height,
            signal_end      = self.signal_end_height,
            lock_in_height  = self.lock_in_height,
            activation_height = self.activation_height,
            threshold       = self.threshold,
            rollback_window = self.rollback_window,
            disabled        = self.disabled,
        )


class GovernanceEngine:
    """
    Full protocol-upgrade governance engine for Visold (VSD).

    ═══════════════════════════════════════════════════════════════════════════
    Four-phase lifecycle
    ────────────────────
    Phase 1 — DORMANT (Announcement)
      A new UpgradeProposal is created via propose_upgrade().
      Nodes begin embedding the new protocol_version in blocks they mine.
      No enforcement yet; old and new version blocks are both accepted.

    Phase 2 — SIGNALING
      Starting at signal_start_height, on every applied block the engine
      counts how many of the last FORK_SIGNAL_WINDOW blocks carry a
      protocol_version >= the proposed version.

    Phase 3 — LOCKED_IN
      Once the signaling fraction meets or exceeds `threshold` at any block
      height H within [signal_start, signal_end]:
        lock_in_height    = H
        activation_height = H + GOVERNANCE_ACTIVATION_DELAY
      These are committed deterministically — all nodes independently compute
      the same heights.

    Phase 4 — ACTIVE
      After activation_height:
        • Blocks with protocol_version < activation_version are REJECTED.
        • The rollback monitor runs for `rollback_window` more blocks.

    Rollback
    ────────
    Within `rollback_window` blocks after activation, if any of these fires:
      (a) invalid_block_rate > GOVERNANCE_ROLLBACK_INVALID_RATE
      (b) no BFT-finalized block in last GOVERNANCE_FINALITY_TIMEOUT blocks
      (c) chain height gap (orphan storm)
    → Phase is set to FAILED and the PREVIOUS version's rules are restored.

    Fork choice
    ───────────
    fork_choice(chain_a, chain_b) returns the canonical preferred chain
    using four deterministic tiebreakers in priority order:
      1. Highest finalized height
      2. Highest justified height (latest BFT vote)
      3. Highest cumulative PoW work
      4. Lowest tip block_hash (lexicographic)

    Safety
    ──────
    emergency_disable(version) can be called by operators.  It immediately
    sets phase=FAILED and records a blacklist entry.  Shadow validation runs
    pre-activation to surface compatibility problems early.

    ═══════════════════════════════════════════════════════════════════════════
    Thread safety
    ─────────────
    All public methods acquire _lock.  The engine is only called from the
    StateEngine thread (single writer), but defensive locking is retained
    for any diagnostic calls from CLI/RPC threads.
    """

    def __init__(self, storage: 'Storage', proto_mgr: 'ProtocolVersionManager'):
        self.storage   = storage
        self.proto_mgr = proto_mgr
        self._lock     = threading.RLock()
        # In-memory proposals dict: version → UpgradeProposal
        self._proposals: Dict[int, UpgradeProposal] = {}
        # Blacklisted versions (emergency kill-switch)
        self._blacklist: set = set()
        # Last finalized height seen (for finality timeout check)
        self._last_finalized_height: int = -1
        # AUDIT-FIX-K4: per-instance emergency-disable vote tracker
        # (version -> {operator_id: timestamp}). This used to be a
        # class-level dict, so every GovernanceEngine instance shared the
        # exact same object -- votes registered against one instance's
        # emergency_disable() would leak into and count toward another
        # instance's quorum (e.g. across multiple nodes/engines in the
        # same process, such as in tests).
        self._emergency_votes: Dict[int, Dict[str, float]] = {}

        # ── Fix #4 — Governance Control Instability ───────────────────────────
        # Track rollback events to detect oscillation loops (rapid repeated
        # rollback → re-proposal → rollback → ...).  If more than
        # _ROLLBACK_LIMIT rollbacks occur within _ROLLBACK_WINDOW_BLOCKS
        # blocks, governance is locked for _GOVERNANCE_COOLDOWN_BLOCKS to
        # prevent the chain from thrashing between two incompatible versions.
        #
        # Additionally, a rapid upgrade cycle (propose → activate → rollback
        # in less than _MIN_UPGRADE_SPACING_BLOCKS) is refused to prevent
        # governance instability from being exploited as a DoS vector.
        self._ROLLBACK_LIMIT            = 3    # max rollbacks before lock
        self._ROLLBACK_WINDOW_BLOCKS    = 500  # window size (blocks)
        self._GOVERNANCE_COOLDOWN_BLOCKS = 200 # blocks to wait after lock
        self._MIN_UPGRADE_SPACING_BLOCKS = 50  # min blocks between upgrades
        # Rolling log of (block_height, version) for each rollback
        self._rollback_log: deque = deque(maxlen=20)
        # Block height at which the governance cooldown expires (0 = not locked)
        self._cooldown_until_height: int = 0

        # Load persisted proposals from DB on startup
        self._load_persisted_proposals()

    # ── Startup ───────────────────────────────────────────────────────────────

    def _load_persisted_proposals(self):
        """Restore governance state from the database after a restart."""
        try:
            rows = self.storage.get_all_upgrade_proposals()
            for row in rows:
                p = UpgradeProposal.from_db_row(row)
                self._proposals[p.version] = p
                if p.disabled:
                    self._blacklist.add(p.version)
            if self._proposals:
                log.info(
                    f"GovernanceEngine: loaded {len(self._proposals)} proposal(s) "
                    f"from DB: " +
                    ", ".join(f"v{v}={p.phase.value}"
                              for v, p in sorted(self._proposals.items())))
        except Exception as e:
            log.warning(f"GovernanceEngine: failed to load proposals: {e}")

    # ── Public API ────────────────────────────────────────────────────────────

    def propose_upgrade(self, version: int,
                        signal_start_height: int,
                        threshold: Optional[float] = None,
                        rollback_window: Optional[int] = None) -> Tuple[bool, str]:
        """
        Announce a new protocol upgrade proposal.

        Parameters
        ──────────
        version             : target protocol version (must be current + 1)
        signal_start_height : first block at which signaling is counted
        threshold           : fraction required for lock-in (default 75%)
        rollback_window     : blocks after activation to watch for failure

        Returns (True, description) on success, (False, reason) on failure.
        """
        with self._lock:
            current = self.proto_mgr.current_version()
            if version != current + 1:
                return False, (
                    f"Can only propose next version (current={current}, "
                    f"proposed={version})")
            if version in self._blacklist:
                return False, f"Version {version} is blacklisted"
            if version in self._proposals:
                p = self._proposals[version]
                if p.phase not in (UpgradePhase.FAILED,):
                    return False, (
                        f"Proposal for version {version} already exists "
                        f"(phase={p.phase.value})")

            # ── Fix #4: governance cooldown check ────────────────────────────
            # After repeated rollbacks the governance engine enters a cooldown
            # period during which no new upgrade can be proposed.  This prevents
            # oscillation loops (propose → rollback → propose → rollback → ...).
            if self._cooldown_until_height > 0:
                current_h = signal_start_height  # best proxy for current chain tip
                if current_h < self._cooldown_until_height:
                    return False, (
                        f"Governance cooldown active until block "
                        f"{self._cooldown_until_height} (currently at ~"
                        f"{current_h}).  Too many recent rollbacks — wait for "
                        f"network conditions to stabilize before re-proposing.")

            # ── Fix #4: minimum upgrade spacing check ─────────────────────────
            # Find the most recent non-FAILED proposal to check spacing.
            prior_activations = [
                p for p in self._proposals.values()
                if p.phase in (UpgradePhase.ACTIVE, UpgradePhase.LOCKED_IN)
                   and p.activation_height > 0
            ]
            if prior_activations:
                last_activation = max(p.activation_height
                                      for p in prior_activations)
                if signal_start_height < last_activation + self._MIN_UPGRADE_SPACING_BLOCKS:
                    return False, (
                        f"Upgrade proposed too soon after last activation at "
                        f"height {last_activation}.  Minimum spacing: "
                        f"{self._MIN_UPGRADE_SPACING_BLOCKS} blocks.")

            thr = threshold if threshold is not None else Config.FORK_SIGNAL_THRESHOLD
            rw  = rollback_window if rollback_window is not None else Config.GOVERNANCE_ROLLBACK_WINDOW
            win = Config.FORK_SIGNAL_WINDOW
            sig_end = signal_start_height + win

            proposal = UpgradeProposal(
                version             = version,
                phase               = UpgradePhase.SIGNALING,
                signal_start_height = signal_start_height,
                signal_end_height   = sig_end,
                lock_in_height      = 0,   # determined when threshold hit
                activation_height   = 0,   # determined at lock-in
                threshold           = thr,
                rollback_window     = rw,
            )
            self._proposals[version] = proposal
            proposal._persist(self.storage)

            log.info(
                f"GOVERNANCE: Upgrade to v{version} proposed. "
                f"Signaling window: [{signal_start_height}, {sig_end}]. "
                f"Threshold: {thr*100:.0f}%.")
            metrics.inc("governance_proposals")
            return True, (
                f"Upgrade to protocol v{version} announced. "
                f"Signal window: blocks {signal_start_height}–{sig_end}.")

    def on_block_applied(self, block: 'Block'):
        """
        Called by the StateEngine after every successfully applied block.
        Drives the governance state machine forward and runs the rollback check.
        """
        with self._lock:
            height = block.index

            # Track finality for rollback check
            if block.finalized:
                self._last_finalized_height = max(
                    self._last_finalized_height, height)

            # Drive each non-terminal proposal
            for version, proposal in list(self._proposals.items()):
                if proposal.phase in (UpgradePhase.ACTIVE,
                                      UpgradePhase.FAILED):
                    # Active: run rollback monitor
                    if proposal.phase == UpgradePhase.ACTIVE:
                        self._rollback_check(proposal, height)
                    continue

                if proposal.phase == UpgradePhase.SIGNALING:
                    self._check_lock_in(proposal, height)
                elif proposal.phase == UpgradePhase.LOCKED_IN:
                    self._check_activation(proposal, height)

    def validate_block_version(self, proto_ver: int,
                                block_height: int) -> Tuple[bool, str]:
        """
        Version-aware block validation.

        Before ACTIVE:  accept both current and proposed versions (tolerant).
        After  ACTIVE:  reject any block below the activated version.
        Hard fork guard: always reject versions more than 1 ahead.
        """
        with self._lock:
            current = self.proto_mgr.current_version()

            # Hard-fork guard: reject versions far in the future
            if proto_ver > current + 1:
                return False, (
                    f"Block protocol_version {proto_ver} too far ahead "
                    f"(current {current}) — hard fork?")

            # AUDIT-FIX-K3: previously this rejected on the FIRST active
            # proposal found in dict-iteration order once its
            # activation_height was reached -- with only one proposal ever
            # able to reach ACTIVE (see K3), that "first" was also always
            # the only one. Now that _current_ver can advance and further
            # upgrades can activate, use the highest version among all
            # ACTIVE proposals whose activation_height has been reached, so
            # validation always enforces the latest activated rule set.
            active_versions_reached = [
                proposal.version
                for proposal in self._proposals.values()
                if proposal.phase == UpgradePhase.ACTIVE
                   and block_height >= proposal.activation_height
            ]
            if active_versions_reached:
                required = max(active_versions_reached)
                if proto_ver < required:
                    return False, (
                        f"Block version {proto_ver} rejected: "
                        f"upgrade to v{required} is ACTIVE")

            # Tolerant pre-activation: both current and +1 are fine
            return True, "OK"

    def get_active_version(self) -> int:
        """
        Return the currently enforced protocol version.
        This is Config.PROTOCOL_VERSION unless an upgrade is ACTIVE.
        """
        with self._lock:
            # AUDIT-FIX-K3: return the highest ACTIVE (non-disabled)
            # version rather than the first one dict iteration encounters
            # -- see validate_block_version above for the same fix and why
            # more than one ACTIVE proposal is now possible over the
            # chain's life.
            active_versions = [
                version for version, proposal in self._proposals.items()
                if proposal.phase == UpgradePhase.ACTIVE
                   and not proposal.disabled
            ]
            if active_versions:
                return max(active_versions)
            return self.proto_mgr.current_version()

    def shadow_validate(self, block: 'Block') -> List[str]:
        """
        Run next-version validation rules against `block` without rejecting it.
        Returns a list of warning strings (empty = no issues found).
        Called during the SIGNALING and LOCKED_IN phases so operators can
        identify compatibility issues before activation.
        """
        warnings: List[str] = []
        with self._lock:
            for version, proposal in self._proposals.items():
                if proposal.phase not in (UpgradePhase.SIGNALING,
                                          UpgradePhase.LOCKED_IN):
                    continue
                # Shadow rule: new version requires explicit protocol_version
                if block.protocol_version < version:
                    warnings.append(
                        f"[shadow v{version}] Block at height {block.index} "
                        f"uses protocol_version={block.protocol_version} "
                        f"but upgrade to v{version} is pending activation "
                        f"at height {proposal.activation_height}.")
        return warnings

    def fork_choice(self, storage: 'Storage',
                    tip_a: 'Block', tip_b: 'Block') -> 'Block':
        """
        Deterministic fork-choice rule.

        Priority order (all nodes arrive at the same decision):
          1. Highest finalized height   — irreversible BFT safety
          2. Highest justified height   — latest BFT vote seen
          3. Highest cumulative PoW     — most accumulated work
          4. Lowest tip block_hash      — lexicographic tie-break

        Fix #3 — Consensus Layer Coupling Conflict:
        Under partial failure (e.g. validators offline, PoW racing ahead of
        BFT), the four-level priority is strictly applied with no short-circuit.
        The rule is:
          • BFT finality ALWAYS beats raw PoW length — a chain with a higher
            finalized height is preferred regardless of cumulative PoW.
          • BFT justification beats PoW — even a chain without full finality
            is preferred over a pure-PoW chain if it has more BFT votes.
          • PoW is the tiebreaker only when BFT metrics are equal — this
            ensures liveness (chain grows via PoW) without sacrificing BFT
            safety (finalized blocks are never rolled back).
          • The lexicographic tiebreaker is deterministic and requires no
            coordination, so all honest nodes choose the same chain.

        Edge cases handled explicitly:
          • tip_a == tip_b (same block): returns tip_a (arbitrary, deterministic)
          • One chain has no finalized blocks (fin = -1): the other wins on
            finality; if both have no finalized blocks, BFT/PoW decide.
          • Overflow in cumulative PoW (extreme difficulty): guarded with
            try/except to prevent float overflow crashing the node.
        """

        def _finalized_height(tip: 'Block') -> int:
            """Walk backward from tip to find the highest finalized block."""
            idx   = tip.index
            count = 0
            # AUDIT-FIX-K5: capped at 500, matching _cumulative_pow below.
            # This closure previously had no cap at all -- it walked all
            # the way to genesis if no finalized block was ever found.
            # fork_choice is reachable via the "forkchoice" RPC method
            # (bearer-token-authenticated but not admin-only), so if BFT
            # finality ever stalls, repeated calls become an unbounded
            # O(chain-height) storage scan per call, per tip.
            while idx >= 0 and count < 500:
                blk = storage.get_block(idx)
                if blk is None:
                    break
                if blk.finalized:
                    return blk.index
                idx   -= 1
                count += 1
            return -1

        def _justified_height(tip: 'Block') -> int:
            """
            Return the highest block height that has any BFT validator vote,
            even if not yet meeting the finality threshold.
            """
            idx   = tip.index
            count = 0
            # AUDIT-FIX-K5: capped at 500 -- see _finalized_height above.
            while idx >= 0 and count < 500:
                blk = storage.get_block(idx)
                if blk is None:
                    break
                if blk.validator_sigs:
                    return blk.index
                idx   -= 1
                count += 1
            return -1

        def _cumulative_pow(tip: 'Block') -> float:
            """
            Approximate cumulative PoW as the sum of 2^(difficulty*4) for each
            block in the chain.  Higher difficulty = more work per block.
            This is equivalent to Bitcoin's chainwork metric.

            Uses float arithmetic (2.0 ** x) because difficulty is now a float
            and Python's bit-shift operator (<<) requires integer operands.
            """
            total = 0.0
            idx   = tip.index
            count = 0
            while idx >= 0 and count < 500:   # cap scan for performance
                blk = storage.get_block(idx)
                if blk is None:
                    break
                # work ∝ 2^(difficulty * 4) — use float exponentiation, not <<
                try:
                    total += 2.0 ** (float(blk.difficulty) * 4.0)
                except (OverflowError, ValueError):
                    total += 1.0   # guard for extreme difficulty values
                idx   -= 1
                count += 1
            return total

        # Identical tip — deterministic short-circuit (Fix #3: no ambiguity)
        if tip_a.block_hash == tip_b.block_hash:
            return tip_a

        # Priority 1: finalized height (BFT safety — always beats PoW)
        fin_a = _finalized_height(tip_a)
        fin_b = _finalized_height(tip_b)
        if fin_a != fin_b:
            return tip_a if fin_a > fin_b else tip_b

        # Priority 2: justified height (BFT liveness signal beats pure PoW)
        jus_a = _justified_height(tip_a)
        jus_b = _justified_height(tip_b)
        if jus_a != jus_b:
            return tip_a if jus_a > jus_b else tip_b

        # Priority 3: cumulative PoW (liveness tiebreaker)
        pow_a = _cumulative_pow(tip_a)
        pow_b = _cumulative_pow(tip_b)
        if pow_a != pow_b:
            return tip_a if pow_a > pow_b else tip_b

        # Priority 4: lowest hash (deterministic tie-break — no coordination needed)
        return tip_a if tip_a.block_hash <= tip_b.block_hash else tip_b

    # VSD-M04 FIX: emergency_disable requires 2-of-N operator approvals.
    # Each call registers one vote keyed by operator_id.  The disable only
    # executes once EMERGENCY_DISABLE_QUORUM distinct operators have voted.
    EMERGENCY_DISABLE_QUORUM = 2      # minimum distinct approvals required
    # AUDIT-FIX-K4: _emergency_votes moved to a per-instance attribute,
    # initialized in __init__ — see there for why. (It used to be declared
    # here as a class-level dict, shared by every instance.)
    _EMERGENCY_VOTE_TTL = 300         # votes expire after 5 minutes

    def emergency_disable(self, version: int,
                          operator_id: str = "default") -> Tuple[bool, str]:
        """
        Operator emergency kill-switch for a faulty upgrade version.
        VSD-M04 FIX: Requires EMERGENCY_DISABLE_QUORUM distinct operator IDs
        to call this method within EMERGENCY_VOTE_TTL seconds of each other.

        This does NOT reorg the chain — it only stops enforcing new-version
        rules going forward.  Blocks already applied are unaffected.
        """
        with self._lock:
            if version not in self._proposals:
                return False, f"No proposal for version {version}"

            # Register this operator's vote
            now = time.time()
            if version not in self._emergency_votes:
                self._emergency_votes[version] = {}
            votes = self._emergency_votes[version]
            # Expire stale votes
            expired = [op for op, ts in votes.items() if now - ts > self._EMERGENCY_VOTE_TTL]
            for op in expired:
                del votes[op]
            votes[operator_id] = now

            quorum = self.EMERGENCY_DISABLE_QUORUM
            if len(votes) < quorum:
                log.warning(
                    f"GOVERNANCE EMERGENCY DISABLE: Version {version} — "
                    f"vote registered from '{operator_id}' "
                    f"({len(votes)}/{quorum} approvals). "
                    f"Waiting for {quorum - len(votes)} more operator(s).")
                return False, (
                    f"Vote registered ({len(votes)}/{quorum}). "
                    f"Need {quorum - len(votes)} more operator approval(s) "
                    f"within {self._EMERGENCY_VOTE_TTL}s.")

            # Quorum reached — execute disable
            del self._emergency_votes[version]   # clear votes
            proposal = self._proposals[version]
            proposal.phase    = UpgradePhase.FAILED
            proposal.disabled = True
            self._blacklist.add(version)
            proposal._persist(self.storage)
            log.critical(
                f"GOVERNANCE EMERGENCY DISABLE: Version {version} disabled "
                f"by {quorum}-operator quorum.  Reverting to previous rules.")
            metrics.inc("governance_emergency_disables")
            return True, f"Version {version} disabled — previous rules restored."

    def get_proposal(self, version: int) -> Optional[UpgradeProposal]:
        with self._lock:
            return self._proposals.get(version)

    def all_proposals(self) -> List[dict]:
        with self._lock:
            return [p.to_dict() for p in self._proposals.values()]

    # ── Internal state-machine transitions ───────────────────────────────────

    def _check_lock_in(self, proposal: UpgradeProposal, height: int):
        """
        Check signaling fraction at `height`.
        If threshold met within the signaling window → transition to LOCKED_IN.
        If window ended without threshold → transition to FAILED.
        """
        if height < proposal.signal_start_height:
            return   # signaling hasn't started yet

        # Count fraction of last FORK_SIGNAL_WINDOW blocks signaling new version
        win   = Config.FORK_SIGNAL_WINDOW
        start = max(0, height - win)
        versions = []
        for h in range(start, height + 1):
            raw = self.storage.get_meta(f"proto_sig:{h}")
            if raw:
                try:
                    versions.append(int(raw))
                except ValueError:
                    pass

        if not versions:
            return

        fraction = sum(1 for v in versions
                       if v >= proposal.version) / len(versions)
        metrics.set_gauge(f"upgrade_v{proposal.version}_signal_fraction",
                          fraction)

        if fraction >= proposal.threshold:
            # Lock in!
            proposal.phase            = UpgradePhase.LOCKED_IN
            proposal.lock_in_height   = height
            proposal.activation_height = height + Config.GOVERNANCE_ACTIVATION_DELAY
            proposal._persist(self.storage)
            log.info(
                f"GOVERNANCE LOCK-IN: Version {proposal.version} locked in at "
                f"height {height} ({fraction*100:.1f}% signaled). "
                f"Activation at height {proposal.activation_height}.")
            metrics.inc("governance_lock_ins")
            return

        # Window expired without threshold
        if height > proposal.signal_end_height:
            proposal.phase = UpgradePhase.FAILED
            proposal._persist(self.storage)
            log.warning(
                f"GOVERNANCE FAILED: Version {proposal.version} signaling "
                f"ended at height {height} without reaching {proposal.threshold*100:.0f}% "
                f"threshold (reached {fraction*100:.1f}%).")
            metrics.inc("governance_signal_failures")

    def _check_activation(self, proposal: UpgradeProposal, height: int):
        """Transition LOCKED_IN → ACTIVE once activation_height is reached."""
        if height < proposal.activation_height:
            return
        proposal.phase = UpgradePhase.ACTIVE
        proposal._persist(self.storage)
        # AUDIT-FIX-K3: advance the persistent version counter so
        # propose_upgrade's "version != current + 1" check (and
        # current_version() generally) reflects this activation, instead of
        # current_version() staying pinned at Config.PROTOCOL_VERSION for
        # the life of the chain and permanently blocking any upgrade
        # proposal after the first one activates.
        self.proto_mgr.advance_version(proposal.version)
        log.info(
            f"GOVERNANCE ACTIVE: Protocol version {proposal.version} "
            f"is NOW ENFORCED at height {height}. "
            f"Old-version blocks will be rejected.")
        metrics.inc("governance_activations")

    def _rollback_check(self, proposal: UpgradeProposal, height: int):
        """
        Monitor for failure conditions in the rollback window.
        Called every block while proposal.phase == ACTIVE.

        Conditions that trigger rollback:
          (a) invalid_block_rate > ROLLBACK_INVALID_RATE in the window
          (b) no BFT-finalized block in last GOVERNANCE_FINALITY_TIMEOUT blocks
          (c) height gap (chain continuity broken)
        """
        rollback_end = proposal.activation_height + proposal.rollback_window
        if height > rollback_end:
            return  # rollback window has closed; upgrade is stable

        # (a) Invalid block rate
        window  = min(proposal.rollback_window, height - proposal.activation_height + 1)
        inv_rate = self.storage.get_block_invalid_rate(
            proposal.activation_height, window)
        if inv_rate > Config.GOVERNANCE_ROLLBACK_INVALID_RATE:
            self._trigger_rollback(
                proposal,
                f"invalid block rate {inv_rate*100:.1f}% exceeds "
                f"{Config.GOVERNANCE_ROLLBACK_INVALID_RATE*100:.0f}% threshold")
            return

        # (b) Finality timeout
        blocks_since_finality = height - self._last_finalized_height
        if blocks_since_finality > Config.GOVERNANCE_FINALITY_TIMEOUT:
            self._trigger_rollback(
                proposal,
                f"no BFT finality for {blocks_since_finality} blocks "
                f"(timeout={Config.GOVERNANCE_FINALITY_TIMEOUT})")
            return

    def _trigger_rollback(self, proposal: UpgradeProposal, reason: str):
        """
        Revert an active upgrade to FAILED and restore previous rules.

        Fix #4 — Governance Oscillation Guard:
        After triggering a rollback, record it in the rolling log.  If the
        log accumulates more than _ROLLBACK_LIMIT rollbacks within
        _ROLLBACK_WINDOW_BLOCKS, enter a cooldown period during which no new
        upgrade proposal is accepted.  This bounds the governance instability
        loop to at most _ROLLBACK_LIMIT cycles before a mandatory pause.
        """
        current_height = proposal.lock_in_height  # best available proxy
        proposal.phase = UpgradePhase.FAILED
        proposal._persist(self.storage)
        log.critical(
            f"GOVERNANCE ROLLBACK: Version {proposal.version} REVERTED. "
            f"Reason: {reason}. Previous rules restored.")
        metrics.inc("governance_rollbacks")

        # ── Oscillation guard ─────────────────────────────────────────────────
        self._rollback_log.append((current_height, proposal.version))
        # Count rollbacks within the sliding window
        window_start = current_height - self._ROLLBACK_WINDOW_BLOCKS
        recent_rollbacks = sum(
            1 for h, _ in self._rollback_log if h >= window_start)
        if recent_rollbacks >= self._ROLLBACK_LIMIT:
            cooldown_end = current_height + self._GOVERNANCE_COOLDOWN_BLOCKS
            self._cooldown_until_height = cooldown_end
            log.critical(
                f"GOVERNANCE COOLDOWN: {recent_rollbacks} rollbacks in last "
                f"{self._ROLLBACK_WINDOW_BLOCKS} blocks. No new upgrades "
                f"accepted until block {cooldown_end}. "
                f"Investigate chain stability before re-proposing.")
            metrics.inc("governance_cooldowns")
