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
"""visold.consensus.rate_defection

Original section: SECTION 1H-EXT — RATE DEFECTION AUDITOR

Defines: RateDefectionAuditor
Origin: visold_vsd_.py L9823-10320
"""

import hashlib
import threading
import time
from typing import Dict, List, Optional, TYPE_CHECKING, Tuple

from visold.kernel.config import Config
from visold.kernel.logging_setup import log

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.chain.blockchain import Blockchain
    from visold.storage.storage import Storage


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1H-EXT — RATE DEFECTION AUDITOR
#
# Statistical detection of miners ignoring the throttle and producing blocks
# faster than their share-of-the-budget allows.  Complements (does not
# replace) the existing double-sign SlashingEvidenceProtocol.
#
# Math
# ────
# For each miner over a window of W blocks:
#     expected_wins = W × (their_cap / total_cap)
#     actual_wins   = blocks they actually mined in the window
#     ratio         = actual_wins / expected_wins
# Miners with share < MIN_AUDIT_SHARE are exempt (variance dominates;
# can't reliably distinguish defection from luck for tiny shares).
# Miners with ratio > THRESHOLD over CONSECUTIVE windows are slashed.
#
# Conservative tuning rationale
# ─────────────────────────────
# Threshold = 2.0× and W = 500 means an honest miner with 10% share
# (expected 50 wins) would have to actually win 100+ blocks in 500 to be
# flagged — about 7σ above their natural mean.  Probability of false
# positive per window: < 1e-11.  Per year of windows: still negligible.
#
# Independent verification (no trust)
# ───────────────────────────────────
# The auditor produces evidence packets that include only data already
# present on every node's local chain (block index, miner address,
# claimed cap at the time).  Receiving nodes re-run the audit on their
# own chain and apply the slash only if their independent computation
# matches the evidence within VERIFY_TOLERANCE.  An attacker forging
# evidence cannot produce a hash that matches independently-computed
# values, because every node has the same blocks.
#
# Cap snapshot strategy (gossip-based)
# ────────────────────────────────────
# This auditor needs to know what each miner's CAP was at audit time.
# The HashrateGovernor is local-only — different nodes may have
# different views of peer caps.  To converge on a single shared view,
# every mining node opts into network-wide hashrate gossip (flooded,
# not point-to-point) so all nodes maintain an identical registry.
# Light/non-mining nodes do not participate in this gossip and do not
# run the auditor — they trust the slashing evidence after their own
# (sparse) verification.
#
# Observe-only initial deployment
# ───────────────────────────────
# When Config.AUTO_SLASH_RATE_DEFECTION is False, the auditor still
# runs every cycle, broadcasts advisory evidence, and logs would-be-
# slashed addresses — but no slash is actually applied.  Operators run
# the network in observe mode for several weeks, verify no false
# positives in the logs, then flip the flag to True.  This is the safe
# default for any new statistical detector.
# ═════════════════════════════════════════════════════════════════════════════

class RateDefectionAuditor:
    """
    Statistical auditor for hashrate-throttle defection.

    Owned by the consensus engine.  Runs every RATE_AUDIT_CADENCE blocks.
    Produces RATE_DEFECTION_EVIDENCE packets that other nodes verify
    independently before applying any slash.

    Thread safety: all public methods take an internal lock.  Audit cycles
    run from the consensus thread, evidence verification runs from the
    network message handler thread.
    """

    # Message-type string for the evidence packets.  We inline the literal
    # here (instead of referencing the MSG_RATE_DEFECTION_EVIDENCE module
    # constant) because this class is defined BEFORE the message-constant
    # block in this file, and a class-level name lookup at class-definition
    # time would raise NameError.  The literal must stay in sync with the
    # MSG_RATE_DEFECTION_EVIDENCE constant defined further down — both are
    # the string "RATE_DEFECTION_EVIDENCE".
    EVIDENCE_TYPE = "RATE_DEFECTION_EVIDENCE"

    def __init__(self,
                 storage: 'Storage',
                 blockchain: 'Blockchain'):
        self._storage    = storage
        self._blockchain = blockchain
        self._lock       = threading.Lock()

        # Per-miner consecutive flagged-window counter.
        # Resets to 0 the first time a miner is observed to be within
        # threshold for a window.  When it reaches RATE_AUDIT_CONSECUTIVE,
        # an evidence packet is emitted.
        self._consecutive_flags: Dict[str, int] = {}

        # Per-miner offense counter — survives node restarts via storage.
        # Decays gradually so a single old offense does not haunt a miner
        # forever (see RATE_AUDIT_OFFENSE_DECAY_BLOCKS).
        self._offense_counts:    Dict[str, int]  = {}
        self._last_offense_block: Dict[str, int] = {}

        # Cache of recently-emitted evidence to avoid double-broadcast.
        # Key: (miner_address, window_end_height) → ts of broadcast
        self._emitted_evidence: Dict[Tuple[str, int], float] = {}

        # Cache of recently-received-and-verified evidence to dedup
        # incoming messages from multiple peers.
        self._seen_evidence:    set = set()

        # Permanent-ban list — populated when a miner exceeds the slash
        # schedule.  Persisted via storage if available.
        self._banned: set = set()

        # Last block height the audit ran on (so we don't re-run on the
        # same window when called repeatedly).
        self._last_audit_height: int = -1

        # Hook into storage if it has the persistence helpers; tolerate
        # absence (e.g. during early bootstrap or in unit tests).
        try:
            persisted = self._storage.get_rate_defection_state()
            if isinstance(persisted, dict):
                self._offense_counts.update(persisted.get("offenses", {}))
                self._last_offense_block.update(
                    persisted.get("last_offense_block", {}))
                self._banned.update(persisted.get("banned", []))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────
    # Public: run one audit cycle.  Called from the consensus engine
    # whenever a new block is applied AND the height is divisible by
    # RATE_AUDIT_CADENCE.  Returns a list of evidence packets to broadcast.
    # ─────────────────────────────────────────────────────────────────────
    def run_audit_cycle(self,
                        current_height: int,
                        cap_registry: Dict[str, float]
                        ) -> List[dict]:
        """
        Audit the last RATE_AUDIT_WINDOW blocks ending at current_height.

        Parameters
        ──────────
        current_height : the height of the most recently applied block.
        cap_registry   : { miner_address: claimed_cap_hps } — the network's
                         shared view of every miner's claimed cap.  Must be
                         the SAME on every node for evidence to verify.

        Returns
        ───────
        A list of evidence packets (dicts).  Empty if no flags this cycle.
        Caller is responsible for broadcasting them.
        """
        with self._lock:
            # Don't re-run on the same block twice
            if current_height <= self._last_audit_height:
                return []
            self._last_audit_height = current_height

        # Need at least one full window
        if current_height < int(Config.RATE_AUDIT_WINDOW):
            return []

        # Only run on cadence boundaries
        if current_height % int(Config.RATE_AUDIT_CADENCE) != 0:
            return []

        window_start = current_height - int(Config.RATE_AUDIT_WINDOW) + 1
        window_end   = current_height

        # Count blocks per miner in the window
        block_counts: Dict[str, int] = {}
        for h in range(window_start, window_end + 1):
            blk = self._storage.get_block(h)
            if blk is None:
                # Missing block — skip this audit cycle, can't trust the result
                log.warning(f"[RateAudit] Missing block {h}; aborting audit")
                return []
            miner = getattr(blk, "miner", None) or getattr(blk, "miner_address", None)
            if not miner:
                continue
            block_counts[miner] = block_counts.get(miner, 0) + 1

        # Compute total cap (sum of all reported caps in the registry)
        total_cap = sum(v for v in cap_registry.values() if v > 0)
        if total_cap <= 0:
            # No registry data yet — observation period.  Skip silently.
            return []

        threshold     = float(Config.RATE_AUDIT_THRESHOLD)
        min_share     = float(Config.RATE_AUDIT_MIN_SHARE)
        consec_needed = int(Config.RATE_AUDIT_CONSECUTIVE)
        window_size   = int(Config.RATE_AUDIT_WINDOW)

        evidence_to_broadcast: List[dict] = []

        # Decay old offenses
        self._decay_offenses(current_height)

        # Iterate over miners present in the registry (not just block_counts —
        # a miner with claimed cap but zero wins would have ratio 0 and
        # shouldn't be flagged, but absence from block_counts means actual=0)
        for miner, claimed_cap in cap_registry.items():
            if claimed_cap <= 0:
                continue
            share = claimed_cap / total_cap
            if share < min_share:
                # Too small to audit reliably — exempt
                continue

            expected_wins = share * window_size
            actual_wins   = block_counts.get(miner, 0)
            if expected_wins <= 0:
                continue
            ratio = actual_wins / expected_wins

            if ratio > threshold:
                # Flag this window
                with self._lock:
                    self._consecutive_flags[miner] = (
                        self._consecutive_flags.get(miner, 0) + 1)
                    streak = self._consecutive_flags[miner]

                log.warning(
                    f"[RateAudit] Miner {miner[:12]}… flagged: "
                    f"expected={expected_wins:.1f} actual={actual_wins} "
                    f"ratio={ratio:.2f} streak={streak}/{consec_needed} "
                    f"window=[{window_start}..{window_end}]"
                )

                if streak >= consec_needed:
                    # Build evidence and prepare to broadcast
                    ev = self._build_evidence(
                        miner=miner,
                        window_start=window_start,
                        window_end=window_end,
                        expected_wins=expected_wins,
                        actual_wins=actual_wins,
                        ratio=ratio,
                        consecutive=streak,
                    )
                    if ev is not None:
                        evidence_to_broadcast.append(ev)
                        # Reset streak; we just emitted an offense
                        with self._lock:
                            self._consecutive_flags[miner] = 0
            else:
                # Reset streak on a clean window
                with self._lock:
                    if miner in self._consecutive_flags:
                        self._consecutive_flags[miner] = 0

        return evidence_to_broadcast

    def _build_evidence(self, miner: str,
                        window_start: int, window_end: int,
                        expected_wins: float, actual_wins: int,
                        ratio: float, consecutive: int) -> Optional[dict]:
        """Build an evidence packet, deduping against recent emissions."""
        key = (miner, window_end)
        with self._lock:
            now = time.time()
            # Drop entries older than 1 hour
            stale = [k for k, t in self._emitted_evidence.items()
                     if now - t > 3600]
            for k in stale:
                self._emitted_evidence.pop(k, None)
            if key in self._emitted_evidence:
                return None
            self._emitted_evidence[key] = now

        own_address = ""
        try:
            # Best-effort lookup of our own address for the submitted_by field
            # (storage may not have a "self_address" notion; it's purely
            # informational and not used in verification).
            own_address = getattr(self._storage, "self_address", "") or ""
        except Exception:
            pass

        return {
            "type":          self.EVIDENCE_TYPE,
            "miner":         str(miner),
            "window_start":  int(window_start),
            "window_end":    int(window_end),
            "expected_wins": float(expected_wins),
            "actual_wins":   int(actual_wins),
            "ratio":         float(ratio),
            "consecutive":   int(consecutive),
            "submitted_by":  str(own_address),
            "ts":            int(time.time()),
        }

    # ─────────────────────────────────────────────────────────────────────
    # Helper shared by handle_received_evidence() below: re-derive a
    # miner's win ratio for one window purely from local chain data.
    # ─────────────────────────────────────────────────────────────────────
    def _independent_window_ratio(self, miner: str, w_start: int, w_end: int,
                                  cap_registry: Dict[str, float]
                                  ) -> Optional[float]:
        """
        Recompute `miner`'s win ratio for the window [w_start, w_end] purely
        from local chain data and the given cap registry — the same
        technique 'Independent recomputation' below uses for an evidence
        packet's own window.  Returns None if the window can't be verified
        (bad size, missing block, no/zero cap data) rather than raising, so
        callers can treat "unverifiable" and "verified but below threshold"
        uniformly as rejection.

        AUDIT-FIX-19 (Batch F, Finding 2): factored out so the same
        verification logic can also be applied to the PRIOR windows a
        'consecutive' claim depends on — see handle_received_evidence().
        """
        if w_start < 0 or w_end - w_start + 1 != int(Config.RATE_AUDIT_WINDOW):
            return None
        actual = 0
        for h in range(w_start, w_end + 1):
            blk = self._storage.get_block(h)
            if blk is None:
                return None
            blk_miner = (getattr(blk, "miner", None)
                        or getattr(blk, "miner_address", None))
            if blk_miner == miner:
                actual += 1
        if miner not in cap_registry or cap_registry[miner] <= 0:
            return None
        total_cap = sum(v for v in cap_registry.values() if v > 0)
        if total_cap <= 0:
            return None
        expected = (cap_registry[miner] / total_cap) * (w_end - w_start + 1)
        if expected <= 0:
            return None
        return actual / expected

    # ─────────────────────────────────────────────────────────────────────
    # Public: verify and apply (or just log) a received evidence packet.
    # ─────────────────────────────────────────────────────────────────────
    def handle_received_evidence(self,
                                 ev: dict,
                                 cap_registry: Dict[str, float]
                                 ) -> Tuple[bool, str]:
        """
        Independently verify an inbound evidence packet against our local
        block history.  Apply slashing only if Config.AUTO_SLASH_RATE_DEFECTION
        is True AND the audit reproduces locally within VERIFY_TOLERANCE.

        Returns (accepted, reason).  accepted=True means evidence was
        processed (dedup or slash).  accepted=False means rejected
        (malformed, unverifiable, or stale).
        """
        # Schema validation
        try:
            miner         = str(ev["miner"])
            window_start  = int(ev["window_start"])
            window_end    = int(ev["window_end"])
            claimed_ratio = float(ev["ratio"])
            consecutive   = int(ev.get("consecutive", 1))
        except (KeyError, ValueError, TypeError) as exc:
            return False, f"Malformed evidence: {exc}"

        if window_end <= window_start:
            return False, "Invalid window range"
        if window_end - window_start + 1 != int(Config.RATE_AUDIT_WINDOW):
            return False, "Window size mismatch"

        # AUDIT-FIX-19 (Batch F, Finding 2): 'consecutive' is a plain
        # integer supplied by whoever built this packet.  It used to be
        # trusted purely because it met the config minimum, while only
        # THIS packet's own window was ever independently re-derived
        # (below).  A single genuinely-verifiable window — which, per the
        # false-positive-rate math in this class's header comment, will
        # occur by chance across enough (miner, window) trials over the
        # network's lifetime — was therefore sufficient to forge a claim
        # of a long streak and get an honest miner slashed.  We now
        # independently re-derive the (consecutive-1) PRIOR windows too,
        # spaced by RATE_AUDIT_CADENCE (matching how run_audit_cycle
        # actually accumulates a streak), and require every one of them to
        # also independently exceed threshold for this same miner.  Only
        # the config MINIMUM is ever re-derived — never the raw claimed
        # value — so inflating 'consecutive' cannot be used to force an
        # unbounded verification loop.
        required = int(Config.RATE_AUDIT_CONSECUTIVE)
        if consecutive < required:
            return False, "Insufficient consecutive flags"
        _cadence   = int(Config.RATE_AUDIT_CADENCE)
        _threshold = float(Config.RATE_AUDIT_THRESHOLD)
        for _prior_i in range(1, required):
            _p_end   = window_end - _prior_i * _cadence
            _p_start = _p_end - int(Config.RATE_AUDIT_WINDOW) + 1
            _p_ratio = self._independent_window_ratio(
                miner, _p_start, _p_end, cap_registry)
            if _p_ratio is None or _p_ratio <= _threshold:
                return False, (
                    f"Consecutive-window claim unverifiable: prior window "
                    f"[{_p_start}..{_p_end}] does not independently "
                    f"confirm a violation")

        # Dedup by content hash
        ev_id = self._evidence_id(ev)
        with self._lock:
            if ev_id in self._seen_evidence:
                return True, "Duplicate (already processed)"
            self._seen_evidence.add(ev_id)
            # Cap the dedup set to avoid unbounded growth
            if len(self._seen_evidence) > 4096:
                # Drop oldest half (set ordering is insertion-order in py3.7+)
                self._seen_evidence = set(
                    list(self._seen_evidence)[-2048:])

        # Independent recomputation
        local_actual = 0
        for h in range(window_start, window_end + 1):
            blk = self._storage.get_block(h)
            if blk is None:
                return False, f"Cannot verify: missing block {h}"
            blk_miner = (getattr(blk, "miner", None)
                         or getattr(blk, "miner_address", None))
            if blk_miner == miner:
                local_actual += 1

        if miner not in cap_registry or cap_registry[miner] <= 0:
            return False, "No cap data for miner — cannot verify"
        total_cap = sum(v for v in cap_registry.values() if v > 0)
        if total_cap <= 0:
            return False, "Empty cap registry"
        local_share    = cap_registry[miner] / total_cap
        local_expected = local_share * (window_end - window_start + 1)
        if local_expected <= 0:
            return False, "Local expected wins is zero"
        local_ratio = local_actual / local_expected

        # Tolerance check
        tol = float(Config.RATE_AUDIT_VERIFY_TOLERANCE)
        if abs(local_ratio - claimed_ratio) / max(claimed_ratio, 1e-9) > tol:
            return False, (f"Ratio mismatch: claimed={claimed_ratio:.2f} "
                           f"local={local_ratio:.2f} (tol={tol:.0%})")

        # Threshold re-check (defends against maliciously low threshold)
        if local_ratio <= float(Config.RATE_AUDIT_THRESHOLD):
            return False, "Local ratio does not exceed threshold"

        # All checks pass — record the offense
        offense_block = window_end
        with self._lock:
            prev_count = self._offense_counts.get(miner, 0)
            self._offense_counts[miner] = prev_count + 1
            self._last_offense_block[miner] = offense_block
            new_count = self._offense_counts[miner]

        # Decide slash percentage
        schedule = Config.RATE_SLASH_SCHEDULE
        if new_count > len(schedule):
            slash_pct = 1.0    # implies ban
            ban       = True
        else:
            slash_pct = schedule[new_count - 1]
            ban       = False

        log.warning(
            f"[RateAudit] Verified evidence for {miner[:12]}…  "
            f"offense #{new_count}  slash={slash_pct:.0%}  "
            f"ratio={local_ratio:.2f}  ban={ban}  "
            f"AUTO_SLASH={'ON' if Config.AUTO_SLASH_RATE_DEFECTION else 'OFF (observe)'}"
        )

        # Apply enforcement only if config flag is on
        if Config.AUTO_SLASH_RATE_DEFECTION:
            self._apply_slash(miner, slash_pct, ban)
        else:
            log.info(
                f"[RateAudit] OBSERVE-ONLY: would slash {miner[:12]}… "
                f"by {slash_pct:.0%} (ban={ban}); enable "
                f"Config.AUTO_SLASH_RATE_DEFECTION to enforce"
            )

        # Persist offense state if storage supports it
        try:
            self._persist_state()
        except Exception as exc:
            log.debug(f"[RateAudit] Persist failed: {exc}")

        return True, ("slashed" if Config.AUTO_SLASH_RATE_DEFECTION
                      else "observed")

    def _apply_slash(self, miner: str, slash_pct: float, ban: bool) -> None:
        """Apply the slash via storage; idempotent on failure."""
        try:
            # Use the existing storage.slash() but with a configurable rate.
            # If storage.slash_with_rate is unavailable, fall back to slash()
            # which uses Config.SLASH_RATE — in that case the schedule is
            # approximate.
            if hasattr(self._storage, "slash_with_rate"):
                self._storage.slash_with_rate(miner, slash_pct)
            else:
                # Use the standard slash() — this applies SLASH_RATE (10%
                # by default), which differs from the schedule but is at
                # least a real slash.  Operators wanting exact schedule
                # semantics should add storage.slash_with_rate.
                self._storage.slash(miner)
            if ban:
                with self._lock:
                    self._banned.add(miner)
                log.warning(f"[RateAudit] {miner[:12]}… added to permanent ban list")
        except Exception as exc:
            log.error(f"[RateAudit] Slash application failed for {miner[:12]}…: {exc}")

    def _decay_offenses(self, current_height: int) -> None:
        """Halve the offense counter for any miner who has had no offense
        for OFFENSE_DECAY_BLOCKS blocks.  Caller need not hold lock; we
        acquire it ourselves."""
        decay_blocks = int(Config.RATE_AUDIT_OFFENSE_DECAY_BLOCKS)
        with self._lock:
            for miner in list(self._offense_counts.keys()):
                last = self._last_offense_block.get(miner, 0)
                if current_height - last >= decay_blocks:
                    new_count = self._offense_counts[miner] // 2
                    if new_count <= 0:
                        self._offense_counts.pop(miner, None)
                        self._last_offense_block.pop(miner, None)
                    else:
                        self._offense_counts[miner] = new_count
                        # Reset clock so we don't decay again immediately
                        self._last_offense_block[miner] = current_height

    def _persist_state(self) -> None:
        """Persist offense + ban state if storage supports it."""
        if not hasattr(self._storage, "set_rate_defection_state"):
            return
        with self._lock:
            payload = {
                "offenses":           dict(self._offense_counts),
                "last_offense_block": dict(self._last_offense_block),
                "banned":             list(self._banned),
            }
        try:
            self._storage.set_rate_defection_state(payload)
        except Exception as exc:
            log.debug(f"[RateAudit] Persist failed: {exc}")

    @staticmethod
    def _evidence_id(ev: dict) -> str:
        """Stable ID for dedup — hash of the canonical fields."""
        try:
            payload = (f"{ev.get('miner','')}|"
                       f"{ev.get('window_start',0)}|"
                       f"{ev.get('window_end',0)}|"
                       f"{ev.get('actual_wins',0)}")
            return hashlib.sha256(payload.encode()).hexdigest()
        except Exception:
            return str(ev)

    def is_banned(self, miner: str) -> bool:
        with self._lock:
            return miner in self._banned

    def offense_count(self, miner: str) -> int:
        with self._lock:
            return self._offense_counts.get(miner, 0)
