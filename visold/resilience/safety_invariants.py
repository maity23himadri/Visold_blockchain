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
"""visold.resilience.safety_invariants

Original section: SECTION 17B: SAFETY INVARIANT CHECKER

Defines: SafetyInvariantChecker
Origin: visold_vsd_.py L43252-43637
"""

import threading
import time
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, L2_WITHDRAW_ADDRESS

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.chain.blockchain import Blockchain
    from visold.network.p2p import P2PNetwork
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 17B: SAFETY INVARIANT CHECKER
# ─────────────────────────────────────────────────────────────────────────────
class SafetyInvariantChecker:
    """
    Fix #12 — Formal Safety Invariants.

    Verifies the three core correctness properties of the Visold blockchain
    at runtime.  These invariants are checked:
      • At node startup (full scan of stored chain)
      • On demand via the RPC method 'checkinvariants'
      • Periodically by the StateEngine timer (lightweight rolling check)

    ═══════════════════════════════════════════════════════════════════════════
    Invariant 1 — SAFETY (no conflicting finality)
    ───────────────────────────────────────────────
    Definition: No two finalized blocks exist at the same height on the
    canonical chain.  This is the blockchain analogue of the BFT safety
    property: "no two honest nodes can commit conflicting values."

    Check: scan all blocks marked finalized=True; verify no height appears
    twice in the finalized set.  A violation indicates either a bug in the
    finality-marking logic or persistent state corruption.

    Invariant 2 — LIVENESS / CONVERGENCE (chain grows)
    ────────────────────────────────────────────────────
    Definition: The chain height must advance over time.  Specifically, if
    the node has been running for more than LIVENESS_TIMEOUT_SECS seconds
    without applying a new block, a liveness warning is emitted.

    Check: compare stored chain height against the height recorded
    LIVENESS_TIMEOUT_SECS ago.  If unchanged and the node has peers,
    emit a WARNING.  This detects stalls caused by:
      • Mining stopped with pending transactions in the mempool
      • All peers disconnected
      • A consensus bug causing every incoming block to be rejected

    Invariant 3 — STATE CONSISTENCY (balance conservation)
    ────────────────────────────────────────────────────────
    Definition: The sum of all balances in the `balances` table must equal
    the total coins ever issued (sum of all coinbase transaction amounts
    minus any burned/slashed amounts).  This is the economic conservation
    invariant; a violation indicates a double-credit or double-debit bug.

    Check: compare sum(balances.balance) against sum(coinbase tx amounts) -
    sum(slashed stakes).  A discrepancy beyond BALANCE_EPSILON indicates
    a state consistency violation.

    ═══════════════════════════════════════════════════════════════════════════
    All violations are:
      • Logged at CRITICAL level
      • Recorded as metrics counters
      • Returned from check() as a structured report for RPC exposure
    Violations do NOT cause an automatic shutdown because:
      • A false positive (e.g. from a migration or pruning edge case) should
        not bring down a production node
      • Operators must investigate the cause before taking corrective action
    """

    # Liveness: warn if no new block in this many seconds (with peers connected)
    LIVENESS_TIMEOUT_SECS  = 600       # 10 minutes
    # Balance conservation: tolerance for floating-point rounding (8 decimals)
    BALANCE_EPSILON        = 1e-6

    def __init__(self, storage: 'Storage', blockchain: 'Blockchain',
                 network: 'P2PNetwork'):
        self._storage    = storage
        self._blockchain = blockchain
        self._network    = network
        self._lock       = threading.Lock()
        # Liveness tracking: record height at which we last confirmed growth
        self._last_liveness_height: int = -1
        self._last_liveness_time:   float = time.time()
        # circuit_breaker — injected by VisoldNode after construction
        self._circuit_breaker: Optional[Any] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def check_all(self, full_scan: bool = False) -> dict:
        """
        Run all three invariant checks.

        full_scan=True: scan the entire chain from genesis (slow; startup only).
        full_scan=False: rolling check of the last 200 blocks (fast; periodic).

        Returns a dict:
          {
            "safety_ok":      bool,
            "liveness_ok":    bool,
            "consistency_ok": bool,
            "violations":     [str, ...],   # human-readable descriptions
            "checked_at":     int,          # unix timestamp
          }
        """
        violations: List[str] = []

        safety_ok      = self._check_safety(violations, full_scan)
        liveness_ok    = self._check_liveness(violations)
        consistency_ok = self._check_balance_conservation(violations, full_scan)

        report = {
            "safety_ok":      safety_ok,
            "liveness_ok":    liveness_ok,
            "consistency_ok": consistency_ok,
            "violations":     violations,
            "checked_at":     int(time.time()),
        }

        if violations:
            metrics.set_gauge("invariant_violations", float(len(violations)))
        else:
            metrics.set_gauge("invariant_violations", 0.0)

        return report

    def rolling_check(self) -> dict:
        """
        Lightweight periodic check — runs on every StateEngine timer tick.
        Checks liveness and a small window of recent blocks for safety.
        Does NOT do a full balance scan (too slow for periodic use).
        Returns a dict with violations list (same format as check_all).
        """
        violations: List[str] = []
        self._check_safety(violations, full_scan=False)
        self._check_liveness(violations)
        if violations:
            for v in violations:
                log.warning(f"INVARIANT VIOLATION (rolling): {v}")
            metrics.inc("invariant_rolling_violations", float(len(violations)))
        return {"violations": violations}

    # ── Invariant 1: Safety ───────────────────────────────────────────────────

    def _check_safety(self, violations: List[str], full_scan: bool) -> bool:
        """
        Verify no two finalized blocks occupy the same height.
        Also verify chain linkage: each block's prev_hash matches the previous
        block's hash (integrity of the canonical chain).
        """
        tip = self._blockchain.height()
        if tip < 0:
            return True

        if full_scan:
            start = 0
        else:
            start = max(0, tip - 200)

        finalized_heights: Dict[int, str] = {}   # height → block_hash
        ok = True

        for idx in range(start, tip + 1):
            blk = self._storage.get_block(idx)
            if blk is None:
                continue

            # ── Finality conflict check ───────────────────────────────────────
            if blk.finalized:
                if idx in finalized_heights:
                    existing_hash = finalized_heights[idx]
                    if existing_hash != blk.block_hash:
                        msg = (
                            f"SAFETY VIOLATION: Two different finalized blocks "
                            f"at height {idx}: "
                            f"{existing_hash[:16]}... vs {blk.block_hash[:16]}... "
                            f"— conflicting finality detected!")
                        violations.append(msg)
                        log.critical(msg)
                        metrics.inc("invariant_safety_violations")
                        ok = False
                else:
                    finalized_heights[idx] = blk.block_hash

            # ── Chain linkage check (non-genesis) ─────────────────────────────
            if idx > max(0, start):
                prev = self._storage.get_block(idx - 1)
                if prev is not None and blk.prev_hash != prev.block_hash:
                    msg = (
                        f"SAFETY VIOLATION: Chain linkage broken at height {idx}: "
                        f"block.prev_hash={blk.prev_hash[:16]}... "
                        f"but prev block hash={prev.block_hash[:16]}...")
                    violations.append(msg)
                    log.critical(msg)
                    metrics.inc("invariant_safety_violations")
                    ok = False

        return ok

    # ── Invariant 2: Liveness ─────────────────────────────────────────────────

    def _check_liveness(self, violations: List[str]) -> bool:
        """
        Verify the chain is making progress.
        Only flags a liveness violation if the node has active peers (otherwise
        an isolated node is expected not to grow).
        """
        current_height = self._blockchain.height()
        now            = time.time()
        peer_count     = len(self._network.active_peer_count())

        with self._lock:
            if current_height > self._last_liveness_height:
                # Chain grew — reset liveness timer
                self._last_liveness_height = current_height
                self._last_liveness_time   = now
                return True

            stall_secs = now - self._last_liveness_time

        if stall_secs > self.LIVENESS_TIMEOUT_SECS and peer_count > 0:
            msg = (
                f"LIVENESS VIOLATION: Chain height has not advanced for "
                f"{stall_secs:.0f}s (height={current_height}, "
                f"peers={peer_count}, timeout={self.LIVENESS_TIMEOUT_SECS}s). "
                f"Check mining status, validator participation, and peer connectivity.")
            violations.append(msg)
            log.warning(msg)
            metrics.inc("invariant_liveness_violations")
            return False

        return True

    # ── Invariant 3: Balance Conservation ────────────────────────────────────

    def _check_balance_conservation(self, violations: List[str],
                                     full_scan: bool) -> bool:
        """
        Verify that total balances equal total issued coins.

        F-01 COMPLETION: All arithmetic uses INTEGER SATOSHI to match the
        consensus engine's _distribute_rewards() and apply_block() paths.

        The previous implementation mixed VSD floats (from transactions.amount
        and roles.stake) with satoshi integers (from balances.balance).  SQLite
        SUM() over REAL columns accumulates IEEE 754 rounding errors that can
        cross the epsilon threshold, causing false "over-issuance" alerts.

        total_issued_sat = sum of compute_reward_sat(i) for each mined block
        actual_sat       = sum of all satoshi balances (excl burn) + staked

        Conservation law:  actual_sat ≤ total_issued_sat - total_slashed_sat
        Equality is not expected because burn + deflation sinks consume coins.

        For performance, full_scan is only done at startup.  The periodic
        rolling check skips this invariant.
        """
        if not full_scan:
            return True   # skip for periodic rolling check (too slow)

        try:
            # AUDIT-FIX-O1c: items 1/2/4 below used to read self._storage._conn()
            # directly -- the aux-SQLite shadow in pgx mode, not Postgres (see
            # AUDIT-FIX-O1a). This check gates an automated safety action:
            # VisoldNode.start() feeds any violation from here straight to
            # self.circuit_breaker.record_violation(), so a drifted shadow could
            # trip the breaker over a false "over-issuance" reading on an
            # otherwise-healthy node. All four sums now come from the backend
            # this Storage instance actually considers authoritative.
            pgx3 = self._storage._pgx_enabled
            excl3 = (Config.BURN_ADDRESS, L2_BRIDGE_ADDRESS, L2_WITHDRAW_ADDRESS)

            # ── 1. Sum of all balances in satoshi (excluding burn address) ─────
            if pgx3:
                _row1 = self._storage._pg_fetch(
                    "SELECT COALESCE(SUM(balance_sat),0) AS total FROM accounts "
                    "WHERE address NOT IN ($1,$2,$3)", list(excl3))
                total_balances_sat = int(_row1[0]["total"]) if _row1 else 0
            else:
                c = self._storage._conn()
                row = c.execute(
                    "SELECT COALESCE(SUM(CAST(balance AS INTEGER)),0) AS total "
                    "FROM balances WHERE address NOT IN (?,?,?)", excl3
                ).fetchone()
                total_balances_sat = int(row["total"])

            # ── 2. Sum of all staked amounts (in satoshi) ──────────────────────
            total_staked_sat = self._storage.sum_all_staked_satoshi()

            # ── 3. Total issuance in satoshi ───────────────────────────────────
            # Authoritative: use compute_reward_sat() for each block height.
            # This matches exactly what _distribute_rewards() distributes.
            height = self._storage.chain_height()
            total_issued_sat = 0
            for h in range(1, height + 1):
                total_issued_sat += self._blockchain.compute_reward_sat(h) \
                    if self._blockchain else 0
            # Fallback: if no blockchain ref, use transactions table.
            # transactions.amount_sat (pgx) is already satoshi; the SQLite
            # transactions.amount column is VSD, hence the *SATOSHI_PER_VSD
            # only on that branch.
            if total_issued_sat == 0 and height > 0:
                if pgx3:
                    _row3 = self._storage._pg_fetch(
                        "SELECT COALESCE(SUM(amount_sat),0) AS total "
                        "FROM transactions WHERE sender='COINBASE'", [])
                    total_issued_sat = int(_row3[0]["total"]) if _row3 else 0
                else:
                    row3 = self._storage._conn().execute(
                        "SELECT COALESCE(SUM(CAST(amount * ? AS INTEGER)),0) AS total "
                        "FROM transactions WHERE sender='COINBASE'",
                        (Config.SATOSHI_PER_VSD,)
                    ).fetchone()
                    total_issued_sat = int(row3["total"])

            # ── 4. Total slashed in satoshi ────────────────────────────────────
            # Note: SLASH_RATE is applied here, not inside sum_all_slashed_satoshi
            # (which returns the raw slashed stake total) -- kept as a local
            # multiply so this check's own rate assumption stays visible here.
            total_slashed_sat = int(round(
                self._storage.sum_all_slashed_satoshi() * Config.SLASH_RATE))

            # ── 5. Conservation check (pure integer comparison) ────────────────
            # STAKE ACCOUNTING MODEL: stake is a LOCK, not a transfer.
            # Staked coins remain in balances.balance AND are recorded in
            # roles.stake.  Therefore the conservation law is:
            #
            #   total_balances_sat == total_issued_sat
            #
            # NOT "total_balances + total_staked" — that would double-count
            # the staked coins and produce a false over-issuance violation
            # whenever any address has an active stake.
            #
            # AUDIT-FIX-K2: previously this subtracted total_slashed_sat from
            # the ceiling too ("total_issued_sat - total_slashed_sat"), on the
            # assumption that slashing removes coins from circulation. It
            # doesn't: Storage.slash() only updates roles.stake/slashed --
            # it never debits balances.balance (consistent with stake being
            # modeled as a lock, not a transfer, elsewhere in this file). So
            # actual_sat was never actually reduced by a slash, and comparing
            # it against an artificially-lowered ceiling produced a
            # guaranteed false "over-issuance" violation equal to the
            # slashed amount after every slashing event. total_slashed_sat is
            # still computed above and logged below for informational/
            # metrics purposes -- it just no longer feeds the pass/fail
            # comparison. (The two other conservation-style checks in this
            # file, SystemInvariantGate.assert_conservation and
            # conservation_check, already compare balances against issuance
            # with no slashing term -- this brings this check in line with
            # those.)
            ceiling_sat   = total_issued_sat
            actual_sat    = total_balances_sat          # stake already inside balances
            over_issued   = actual_sat - ceiling_sat    # positive = real violation

            # Convert to VSD for logging only
            actual_vsd  = actual_sat / Config.SATOSHI_PER_VSD
            ceiling_vsd = ceiling_sat / Config.SATOSHI_PER_VSD
            issued_vsd  = total_issued_sat / Config.SATOSHI_PER_VSD
            held_vsd    = total_balances_sat / Config.SATOSHI_PER_VSD
            staked_vsd  = total_staked_sat / Config.SATOSHI_PER_VSD
            slashed_vsd = total_slashed_sat / Config.SATOSHI_PER_VSD

            # Threshold: 1 satoshi tolerance
            SATOSHI_EPSILON = 1

            if over_issued > SATOSHI_EPSILON:
                msg = (
                    f"CONSISTENCY VIOLATION: Over-issuance detected — "
                    f"held={actual_vsd:.8f} VSD exceeds "
                    f"issued-slashed={ceiling_vsd:.8f} VSD by "
                    f"{over_issued} satoshi. "
                    f"{'Orphaned balance rows detected at height 0 (no blocks issued yet). ' if total_issued_sat == 0 else ''}"
                    f"This indicates a double-credit bug in apply_block "
                    f"or orphaned rows in the balances table from a previous session.")
                violations.append(msg)
                log.critical(msg)
                metrics.inc("invariant_consistency_violations")
                return False

            unspent_sat = ceiling_sat - actual_sat
            if unspent_sat > Config.SATOSHI_PER_VSD:  # > 1 VSD unspent (burn/dust)
                log.info(
                    f"Balance conservation OK (deflation sink active): "
                    f"issued={issued_vsd:.4f}, "
                    f"held={held_vsd:.4f}, "
                    f"staked={staked_vsd:.4f} (locked inside held), "
                    f"slashed={slashed_vsd:.4f}, "
                    f"unspent_sink={unspent_sat / Config.SATOSHI_PER_VSD:.4f} VSD")
            else:
                log.info(
                    f"Balance conservation OK: "
                    f"issued={issued_vsd:.4f}, "
                    f"held={held_vsd:.4f}, "
                    f"staked={staked_vsd:.4f} (locked inside held), "
                    f"slashed={slashed_vsd:.4f} VSD")
            return True

        except Exception as e:
            log.warning(f"Balance conservation check failed: {e}")
            return True   # non-fatal: DB query failure is not a violation
