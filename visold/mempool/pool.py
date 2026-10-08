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
"""visold.mempool.pool

Original section: SECTION 7: MEMPOOL

Defines: Mempool
Origin: visold_vsd_.py L17919-17998, L18001-18866
"""

import threading
import time
import heapq as _heapq
from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional, TYPE_CHECKING, Tuple

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics
from visold.kernel.units import VSD_GLOBAL_MARKET, from_satoshi, to_satoshi
from visold.ledger.transaction import Transaction
from visold.rollup.batches import RollupSubmission
from visold.storage.storage import Storage

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.mempool.mev import CommitRevealMempool
    from visold.rollup.l2_state import Layer2State


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7: MEMPOOL
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# TPS-OPT-3 — IN-MEMORY PRIORITY QUEUE FOR MEMPOOL
# ─────────────────────────────────────────────────────────────────────────────
# The original Mempool.get_top() queries the full DB on every call:
#   mempool_all() → deserialize every row → group by sender → sort.
# That is O(n) in DB I/O + deserialization, which becomes the bottleneck at
# high tx submission rates.
#
# _MempoolHeap is a thread-safe, lazily-pruned min-heap (heapq) that stores
# transactions in canonical priority order: (-fee, timestamp, tx_id).
# Additions are O(log n), top-k retrieval is O(k log n), and removals are
# O(1) via lazy deletion (mark-and-skip).
#
# The DB is still the authoritative store — the heap is a read accelerator.
# The canonical nonce-gap filtering from get_top() is still applied.
# ─────────────────────────────────────────────────────────────────────────────

class _MempoolHeap:
    """Thread-safe priority queue for mempool transactions.

    Ordering: highest fee first → oldest timestamp → lexicographic tx_id.
    Uses lazy deletion: removed tx_ids are tracked in a set and skipped
    during iteration.  Periodic compaction reclaims space.
    """
    __slots__ = ("_heap", "_removed", "_lock", "_size",
                 "_COMPACT_THRESHOLD")

    def __init__(self):
        self._heap: list = []            # heapq of (-fee_sat, ts, tx_id, tx)
        self._removed: set = set()       # tx_ids lazily marked for deletion
        self._lock = threading.Lock()
        self._size: int = 0              # number of LIVE entries
        self._COMPACT_THRESHOLD = 2000   # compact when removed set exceeds this

    def push(self, tx: 'Transaction'):
        """Add a transaction.  Thread-safe, O(log n) in the common case."""
        fee_sat = to_satoshi(tx.fee) if tx.fee else 0
        entry = (-fee_sat, tx.timestamp, tx.tx_id, tx)
        with self._lock:
            if tx.tx_id in self._removed:
                # AUDIT-FIX (Batch E): tx_id was previously lazily removed —
                # remove() never deletes the physical array slot, only
                # flags the id, so a stale entry may still be sitting in
                # self._heap. Discarding the flag below without purging
                # that stale slot first would resurrect it as "live"
                # alongside the fresh entry we're about to push, so
                # get_all_live() would return the same tx_id twice (two
                # entries with the same nonce), which makes get_top()'s
                # per-sender contiguous-nonce walk stop one tx early and
                # silently exclude every later transaction from that
                # sender. This path is exercised whenever a transaction
                # that was mined-then-reorged-out gets re-added (see
                # Mempool.restore(), used by Blockchain._rollback_block).
                # Force a compaction first so the stale slot is physically
                # gone before the new entry goes in.
                self._compact_unlocked()
            _heapq.heappush(self._heap, entry)
            self._removed.discard(tx.tx_id)   # un-remove if re-added
            self._size += 1

    def remove(self, tx_id: str):
        """Lazily remove a transaction by tx_id.  Thread-safe, O(1)."""
        with self._lock:
            if tx_id not in self._removed:
                self._removed.add(tx_id)
                self._size = max(0, self._size - 1)
                if len(self._removed) > self._COMPACT_THRESHOLD:
                    self._compact_unlocked()

    def get_all_live(self) -> List['Transaction']:
        """Return all non-removed transactions in priority order.
        Used by get_top() for nonce-gap filtering.  Thread-safe.
        """
        with self._lock:
            result = []
            for entry in sorted(self._heap):
                _, _, tx_id, tx = entry
                if tx_id not in self._removed:
                    result.append(tx)
            return result

    def size(self) -> int:
        with self._lock:
            return self._size

    def clear(self):
        """Wipe all entries."""
        with self._lock:
            self._heap.clear()
            self._removed.clear()
            self._size = 0

    def _compact_unlocked(self):
        """Rebuild the heap without removed entries.  Called under lock."""
        self._heap = [e for e in self._heap if e[2] not in self._removed]
        _heapq.heapify(self._heap)
        self._removed.clear()


class Mempool:
    """
    Thread-safe mempool with full production-grade protections:

    • Hard cap of MEMPOOL_MAX transactions total.
    • Minimum fee rate: transactions below MIN_FEE_RATE are rejected.
    • Per-sender sliding-window rate limit.
    • Per-account NONCE enforcement — each sender's nonce must equal
      (chain_nonce + pending_nonces_count).  This prevents replay attacks
      and enforces transaction ordering.
    • Transaction EXPIRY — transactions past their expiry timestamp are
      rejected immediately.
    • Circular/self-trade detection — A→B then B→A within the pending
      pool are flagged; the second leg is rejected with a penalty note.
    • Dust protection.
    • EIP-1559-style dynamic base-fee pressure signal (informational).
    """

    MIN_FEE_RATE        = 0.001
    DUST_THRESHOLD      = 0.0001
    # v7.5.x: PER_SENDER_LIMIT raised from 20 → 60 to accommodate honest
    # high-frequency senders (payroll batches, market makers, exchange
    # withdrawal queues, automated payment services).  60 tx per 60-second
    # window = 1 tx/sec average, which is still strict enough that a single
    # sender cannot fill MEMPOOL_MAX (5000) faster than ~83 minutes of
    # sustained spam from one address — and the existing dust+fee+nonce
    # checks catch most attack patterns long before that.  Per-sender DoS
    # is still bounded; honest workflows no longer hit the wall.
    PER_SENDER_LIMIT    = 60
    RATE_WINDOW_SECS    = 60
    # Dynamic fee pressure: track rolling block fill ratios
    TARGET_FILL_RATIO   = 0.50   # 50% full → base fee stable

    def __init__(self, storage: Storage):
        self.storage    = storage
        self._lock      = threading.Lock()
        self._rate_tracker: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.PER_SENDER_LIMIT + 1))
        # Track pending nonces per sender: sender → set of nonces in pool
        self._pending_nonces: Dict[str, set] = defaultdict(set)
        # Track (sender, receiver) pairs for circular-trade detection
        self._pending_pairs: Dict[Tuple[str,str], int] = defaultdict(int)
        self._base_fee_multiplier: float = 1.0
        # v7.1.17: fast O(1) duplicate-tx_id guard (mempool cluttering defence)
        self._pending_tx_ids: set = set()
        # TPS-OPT-3: in-memory priority queue — avoids DB scan on get_top()
        self._heap = _MempoolHeap()
        # ── MEMPOOL-1 FIX (Layer2 ref for rollup pre-validation) ─────────────
        # Set by Blockchain.__init__ AFTER layer2 is constructed (Mempool is
        # created earlier in the same __init__).  When present, the Mempool's
        # add() method can pre-validate TYPE_ROLLUP submissions against the
        # current layer2 root and reject stale rollups at admission instead
        # of letting them propagate, get mined into a block, and trigger a
        # whole-block rejection inside apply_block.
        # SAFE — node-local check; never relaxes consensus.  A node without
        # this reference falls through to the apply-time check as before.
        self._layer2_ref: Optional['Layer2State'] = None
        # ── AUDIT-FIX (Batch E): MEV commit-reveal ref ────────────────────────
        # Set once at node startup via set_mev_ref(). When present and MEV
        # protection is enabled, add() requires a valid, sufficiently-aged
        # reveal before admitting a transaction (see add()'s MEV gate and
        # set_mev_ref()'s docstring for why this wiring was needed).
        self._mev_ref: Optional['CommitRevealMempool'] = None
        # ── v7.5.0-OPT Pre-Validation Pipeline ───────────────────────────────
        # Tracks tx_ids whose full cryptographic signature check has already
        # passed.  Populated by add() at gossip-arrival time; consulted by
        # Block.integrity_check() to skip re-verifying signatures we have
        # already checked.  This is a *cache* of verification work — it NEVER
        # relaxes consensus: if a tx_id is not in the set the signature is
        # checked the old way, and the set is cleared on every mempool mutation
        # that could invalidate it.  Bounded in size so a tx-flood cannot OOM
        # the node.
        self._verified: set = set()
        self._VERIFIED_MAX = max(Config.MEMPOOL_MAX * 2, 20000)
        # MAJOR-05 FIX: Rebuild in-memory nonce/pair state from persisted txs
        # so that restarts do not cause all pending transactions from senders
        # with nonce > chain_nonce to be rejected with "Nonce mismatch".
        self._rebuild_pending_state()
        # Identity claims are fee-bearing transactions. Older patched builds
        # could persist an auto-submitted claim even when the wallet had zero
        # balance; that transaction then survived restart and made mining
        # dry-run fail on REGISTER fee debit. Remove only that narrow class of
        # stale, unaffordable claims during mempool reconstruction.
        self._purge_unaffordable_identity_claims()
        # STALE-NONCE FIX: rows persisted before a restart can already be behind
        # the chain nonce (superseded by a block, or left by an interrupted
        # apply).  _rebuild_pending_state() re-loads them as if still pending.
        self.purge_stale_nonces()

    def _rebuild_pending_state(self) -> None:
        """Reconstruct _pending_nonces and _pending_pairs from the SQLite mempool.

        MAJOR-05: On startup the in-memory dicts are empty while the DB may
        contain persisted transactions.  Without rebuilding, every pending tx
        from a sender whose nonce > chain_nonce is rejected because
        expected_nonce = chain_nonce + 0 (empty _pending_nonces).

        Called once from __init__ — no lock needed (constructor, single thread).
        """
        try:
            for tx in self.storage.mempool_all():  # v7.1.17: was mempool_get_all() (non-existent method)
                self._pending_tx_ids.add(tx.tx_id)  # v7.1.17 clutter guard
                # TPS-OPT-3: populate the in-memory priority queue
                self._heap.push(tx)
                if tx.sender == "COINBASE":
                    continue
                self._pending_nonces[tx.sender].add(tx.nonce)
                if tx.receiver:
                    self._pending_pairs[(tx.sender, tx.receiver)] += 1
        except Exception as e:
            # Non-fatal: if the DB is empty or unavailable just start clean.
            log.warning(f"Mempool: _rebuild_pending_state failed: {e}")

    def _purge_unaffordable_identity_claims(self) -> None:
        """Remove persisted identity claims whose fee cannot be paid.

        This is deliberately limited to identity claims. Existing transfer,
        VVM, rollup, and role-register mempool behavior is untouched.
        """
        try:
            balance_cache: Dict[str, int] = {}
            for tx in list(self.storage.mempool_all()):
                if not Transaction.is_identity_claim(tx):
                    continue
                if tx.sender not in balance_cache:
                    balance_cache[tx.sender] = self.storage.get_balance_sat(
                        tx.sender)
                if balance_cache[tx.sender] < tx.compute_fee_sat():
                    log.warning(
                        "Mempool: dropping unaffordable identity claim %s "
                        "from %s (balance=%s sat, fee=%s sat)",
                        tx.tx_id[:12], tx.sender[:16],
                        balance_cache[tx.sender], tx.compute_fee_sat())
                    self.remove(tx.tx_id)
        except Exception as exc:
            log.debug("Mempool identity cleanup skipped: %s", exc)

    def set_layer2_ref(self, layer2: 'Layer2State') -> None:
        """Wire the layer2 reference for rollup pre-validation.

        Called by Blockchain.__init__ after both Mempool and Layer2State
        are constructed (Mempool is created earlier in the same __init__,
        so it cannot accept layer2 directly via the constructor).
        Idempotent — calling with the same ref twice is harmless.
        """
        self._layer2_ref = layer2

    def set_mev_ref(self, mev_mempool: 'CommitRevealMempool') -> None:
        """Wire the commit-reveal MEV-protection reference.

        AUDIT-FIX (Batch E): CommitRevealMempool.verify_reveal() existed
        but had no caller anywhere in the codebase, so enabling MEV
        protection (Config.MEV_PROTECTION_ENABLED / VISOLD_MEV_PROTECT=1)
        made getmevstatus report "enabled": true while gating nothing —
        a transaction was admitted the same whether or not a commitment
        had ever been submitted for it. Call this once at node startup
        with the module-level _mev_mempool singleton so add() can
        actually enforce the reveal check. A Mempool with no ref wired
        (e.g. a standalone Mempool(storage) built outside normal node
        startup) simply skips the check, same as before this fix.
        Idempotent — calling with the same ref twice is harmless.
        """
        self._mev_ref = mev_mempool

    def add(self, tx: Transaction) -> Tuple[bool, str]:
        with self._lock:
            # ── Expiry check ──────────────────────────────────────────────────
            if tx.is_expired():
                return False, f"Transaction expired (expiry={tx.expiry})"

            # ── Basic structural validation ───────────────────────────────────
            ok, msg = tx.is_valid()
            if not ok:
                return False, msg

            # Consensus role-registration minimums require state context and
            # therefore cannot be enforced by Transaction.is_valid() alone.
            # Reject an obvious initial sub-minimum registration here as well,
            # so the node does not gossip/store a transaction that an active
            # post-fix block validator will reject.  Existing same-role accounts
            # are additive top-ups and remain allowed at any positive amount.
            role_stake_activation = int(getattr(
                Config, "ROLE_STAKE_MIN_ACTIVATION_HEIGHT", 0))
            next_height = max(0, self.storage.chain_height() + 1)
            if (tx.tx_type == Transaction.TYPE_REGISTER
                    and not Transaction.is_identity_claim(tx)
                    and next_height >= role_stake_activation):
                role = str(tx.memo or "").strip().lower()
                if role in ("miner", "investor"):
                    existing_role = self.storage.get_role(tx.sender)
                    same_role_active = bool(
                        existing_role and existing_role.get("role") == role)
                    if not same_role_active:
                        minimum_sat = (
                            int(Config.MIN_MINER_STAKE)
                            if role == "miner"
                            else int(Config.MIN_INVESTOR_STAKE)
                        )
                        if to_satoshi(tx.amount) < minimum_sat:
                            return False, (
                                f"Minimum {role} stake: "
                                f"{from_satoshi(minimum_sat):.8f} VSD")

            # Identity claims are the only zero-value TYPE_REGISTER
            # transactions. Reject an unaffordable claim before it reaches
            # persistent mempool storage; otherwise mining dry-run would later
            # fail while debiting its fee.
            if Transaction.is_identity_claim(tx):
                if self.storage.get_balance_sat(tx.sender) < tx.compute_fee_sat():
                    return False, (
                        "Insufficient balance for identity claim fee: "
                        f"need {from_satoshi(tx.compute_fee_sat()):.8f} VSD")

            # ── AUDIT-FIX (Batch E): MEV commit-reveal enforcement ─────────────
            # CommitRevealMempool.verify_reveal() previously had no caller
            # anywhere in the codebase, so Config.MEV_PROTECTION_ENABLED
            # made getmevstatus report protection as active while it
            # gated nothing — a transaction was admitted the same whether
            # or not a commitment had ever been submitted for it. When no
            # ref is wired (set_mev_ref() never called) or MEV protection
            # is disabled, verify_reveal() itself short-circuits to
            # (True, ...), so this is a no-op for nodes that don't opt
            # in — existing behavior is unchanged for them.
            if tx.sender != "COINBASE" and self._mev_ref is not None:
                current_height = max(0, self.storage.chain_height())
                mev_ok, mev_msg = self._mev_ref.verify_reveal(tx, current_height)
                if not mev_ok:
                    return False, f"MEV protection: {mev_msg}"

            # ── Dust protection ───────────────────────────────────────────────
            # BUG-FIX: VVM TYPE_DEPLOY transactions have amount=0 (call value
            # may legitimately be zero when no ETH/VSD is sent alongside the
            # bytecode).  Applying the dust check to them always rejected them.
            # TYPE_CALL can similarly have call_value=0.  Both types have their
            # own economic enforcement (gas_price >= VVM_MIN_GAS_PRICE) inside
            # tx.is_valid(), so skip the amount-based dust check for VVM txs.
            is_vvm_tx = tx.tx_type in (Transaction.TYPE_DEPLOY, Transaction.TYPE_CALL)
            is_register_tx = tx.tx_type == Transaction.TYPE_REGISTER
            # v7.5.0-OPT: TYPE_ROLLUP is the L2 settlement tx — amount=0,
            # fee=0, economic backing is the L1 fee on the wrapping tx
            # and the proof verification cost in gas at apply time.
            is_rollup_tx   = tx.tx_type == Transaction.TYPE_ROLLUP
            # ── MEMPOOL-1 FIX: stale rollup pre-validation ────────────────────
            # Rejects TYPE_ROLLUP submissions whose previous_l2_root no longer
            # matches the current layer2 root.  Without this gate, a stale
            # rollup propagates through gossip, gets mined into a block by an
            # honest miner, then fails Blockchain._apply_rollup_tx — which
            # rejects the ENTIRE block (and every other user's tx in it) and
            # wastes the miner's PoW.  Anyone tracking the L2 root can submit
            # a freshly-stale rollup as a DoS vector.
            #
            # This check is node-local — it never relaxes consensus, only
            # tightens admission.  A node with no layer2 reference falls
            # through to the apply-time check unchanged.
            #
            # Race condition (admission OK → state changes → apply rejects):
            # narrow but real.  apply_block still tolerates the residual case
            # via MEMPOOL-1 part 2 (skip-and-remove instead of block-reject).
            if is_rollup_tx and self._layer2_ref is not None:
                try:
                    sub = RollupSubmission.from_json(tx.data)
                    cur_root = self._layer2_ref.root()
                    if sub.previous_l2_root != cur_root:
                        return False, (
                            f"Stale rollup: previous_l2_root "
                            f"{sub.previous_l2_root[:16]}... does not match "
                            f"current L2 root {cur_root[:16]}.... "
                            f"The L2 state changed since this batch was sealed; "
                            f"the sequencer should reseal a fresh batch.")
                except Exception as _pre_e:
                    # Don't reject on internal pre-check errors — let the
                    # apply-time path handle malformed payloads with its
                    # own error reporting.  is_valid() already verified
                    # JSON parses, so reaching here is unexpected.
                    log.debug(f"Mempool rollup pre-check internal error: {_pre_e}")
            # F-01 COMPLETION: compare in satoshi to avoid float edge cases.
            dust_sat = to_satoshi(self.DUST_THRESHOLD)
            # v7.2.0: REGISTER txs have amount == stake (may be 0 for unstake);
            # skip the dust threshold for them.
            if (not is_vvm_tx and not is_register_tx and not is_rollup_tx
                    and to_satoshi(tx.amount) < dust_sat):
                return False, f"Amount below dust threshold ({self.DUST_THRESHOLD} VSD)"

            # ── Minimum fee enforcement ───────────────────────────────────────
            # BUG-FIX: For VVM transactions the economic fee is gas_limit * gas_price,
            # not amount * MIN_FEE_RATE.  gas_price is already enforced by is_valid()
            # (gas_price >= VVM_MIN_GAS_PRICE), so skip the amount-based min-fee
            # check for VVM txs to avoid double-checking with the wrong formula.
            # v7.2.0: REGISTER txs also skip the amount-based fee check —
            # a REGISTER(none) tx carries amount=0, so the minimum would be
            # zero anyway, and charging a proportional fee on stake is already
            # handled by Transaction.compute_fee_sat() at apply time.
            # v7.5.0-OPT: TYPE_ROLLUP skips too — amount=0, fee=0 by design.
            if not is_vvm_tx and not is_register_tx and not is_rollup_tx:
                # F-01 COMPLETION: satoshi integer fee comparison.
                # min_fee_sat = amount_sat * FEE_RATE_BPS / 10000 * multiplier
                amount_sat = to_satoshi(tx.amount)
                fee_rate_bps = int(round(self.MIN_FEE_RATE * 10000))
                # Apply base_fee_multiplier as millionths to stay in int math
                mult_m = int(round(self._base_fee_multiplier * 1_000_000))
                min_fee_sat = amount_sat * fee_rate_bps * mult_m // (10000 * 1_000_000)
                tx_fee_sat = to_satoshi(tx.fee)

                # SEC-FIX M-06 (Absolute Mempool Fee Floor)
                # ────────────────────────────────────────
                # Lift the per-tx minimum to at least Config.MIN_TX_FEE_SAT.
                # The amount-proportional min_fee_sat above goes to zero for
                # tiny-amount transfers, leaving the mempool open to flood
                # attacks with thousands of near-zero-fee txs.  An absolute
                # satoshi floor closes that vector.  This is a NODE-LOCAL
                # acceptance policy — consensus is unaffected, so a block
                # mined by a permissive miner that contains a sub-floor tx
                # still validates.  But every honest node refuses such txs
                # at admission time, killing the cheap spam channel.
                abs_floor_sat = int(getattr(Config, "MIN_TX_FEE_SAT", 0))
                if abs_floor_sat > 0 and min_fee_sat < abs_floor_sat:
                    min_fee_sat = abs_floor_sat

                if tx_fee_sat < min_fee_sat and tx.sender != "COINBASE":
                    return False, (f"Fee too low: {tx.fee:.8f} VSD "
                                   f"(minimum {from_satoshi(min_fee_sat):.8f} VSD, "
                                   f"base_mult={self._base_fee_multiplier:.2f})")
                # ── v7.1.11 BUG-5 FIX (Static Fee Override) ──────────────
                # Consensus computes the actual debit/reward via
                # Transaction.compute_fee_sat(), which returns
                # amount_sat * TX_FEE_RATE_BPS // 10000 — the user-set
                # tx.fee field is currently IGNORED at consensus time.
                #
                # Pre-fix mempool admitted any tx with tx.fee >= min_fee
                # (down to amount * 0.001).  A user could set tx.fee to
                # anything between the minimum and infinity; if it didn't
                # match the consensus formula, the discrepancy was either
                # silently underpaid (mempool min < consensus formula) or
                # silently absorbed (user overpays, network only deducts
                # consensus rate, miner gets the lower amount).
                #
                # We CANNOT change compute_fee_sat() without forking every
                # existing chain (every historical state_root depends on
                # the current formula).  Instead we tighten admission so
                # tx.fee MUST equal what consensus will actually charge.
                # Real fee tipping requires a coordinated activation
                # upgrade; for now we eliminate the lying-fee attack
                # surface without touching consensus rules.
                #
                # Tolerance: exact equality on satoshi integers.  Wallet
                # code at line ~22347 already constructs txs with
                # fee = round(amount * TX_FEE_RATE, 8), which converts to
                # the same satoshi count, so legitimate wallets pass.
                consensus_fee_sat = tx.compute_fee_sat()
                if (tx_fee_sat != consensus_fee_sat
                        and tx.sender != "COINBASE"):
                    return False, (
                        f"Fee mismatch: tx.fee={tx.fee:.8f} VSD "
                        f"({tx_fee_sat} sat), consensus charges "
                        f"{from_satoshi(consensus_fee_sat):.8f} VSD "
                        f"({consensus_fee_sat} sat).  Set tx.fee exactly "
                        f"to amount * {Config.TX_FEE_RATE} until fee "
                        f"tipping is enabled in a coordinated upgrade.")

            # ── Already in mempool (in-memory O(1) check, v7.1.17) ────────────
            # Reject a tx whose tx_id already sits in the pending set before
            # hitting the DB.  This is the primary defence against mempool
            # cluttering: any re-submission of an identical transaction is
            # bounced here without burning DB I/O or incrementing any counter.
            if tx.tx_id in self._pending_tx_ids:
                return False, "Already in mempool"

            # ── Already confirmed ─────────────────────────────────────────────
            if self.storage.tx_exists(tx.tx_id):
                return False, "Already in chain"

            # ── Hard pool cap ─────────────────────────────────────────────────
            if self.storage.mempool_size() >= Config.MEMPOOL_MAX:
                return False, "Mempool full — try again later or increase fee"

            # ── Nonce enforcement (non-coinbase only) ─────────────────────────
            if tx.sender != "COINBASE" and tx.receiver != VSD_GLOBAL_MARKET:
                chain_nonce   = self.storage.get_nonce(tx.sender)
                pending_count = len(self._pending_nonces[tx.sender])
                expected_nonce = chain_nonce + pending_count
                # VSD-M06 FIX: reject transactions with a nonce gap > MAX_NONCE_GAP
                # to prevent mempool griefing via permanently-stuck high-nonce txs.
                MAX_NONCE_GAP = 16
                if tx.nonce > chain_nonce + MAX_NONCE_GAP:
                    return False, (
                        f"Nonce too far ahead: got {tx.nonce}, "
                        f"chain={chain_nonce}, max allowed={chain_nonce + MAX_NONCE_GAP} "
                        f"(MAX_NONCE_GAP={MAX_NONCE_GAP})")
                if tx.nonce != expected_nonce:
                    # Friendlier message: nonces must be contiguous.  Common
                    # honest cause: an earlier tx was dropped during gossip
                    # or expired before mining, leaving a gap.  Resubmitting
                    # the same nonces in order is the fix.
                    if tx.nonce < expected_nonce:
                        _hint = (
                            f"This nonce is already in use (chain has {chain_nonce}, "
                            f"{pending_count} more pending).  If you intended to "
                            f"replace a pending tx, the current implementation "
                            f"does not support fee-bump replacement — wait for "
                            f"the existing tx to confirm or expire.")
                    else:
                        _hint = (
                            f"There is a gap between your highest pending nonce "
                            f"and this one.  Resubmit any missing transactions "
                            f"(nonces {expected_nonce}..{tx.nonce - 1}) first, "
                            f"or wait for pending ones to confirm.")
                    return False, (
                        f"Nonce mismatch: got {tx.nonce}, expected {expected_nonce} "
                        f"(chain={chain_nonce}, pending={pending_count}). {_hint}")

            # ── Circular/self-trade detection ─────────────────────────────────
            # If the reverse direction is already pending in the mempool, reject
            # the second leg.  Two reciprocal transactions that both confirm in
            # the same window result in zero net balance change while still
            # debiting fees twice — by deferring the second leg until the first
            # one confirms or expires we keep the user from paying double-fees
            # for an effectively no-op round-trip.
            #
            # The previous error message read "Possible wash trading — rejected"
            # which inaccurately accused honest users (legitimate refunds, escrow
            # returns, marketplace cancel-and-resend flows).  The message below
            # explains that the rejection is temporary and points to the
            # remediation.
            if (tx.sender != "COINBASE"
                    and tx.receiver != VSD_GLOBAL_MARKET
                    and tx.sender != tx.receiver):
                reverse_pair = (tx.receiver, tx.sender)
                if self._pending_pairs.get(reverse_pair, 0) > 0:
                    return False, (
                        f"Reverse transaction "
                        f"{tx.receiver[:12]}...→{tx.sender[:12]}... is "
                        f"already pending in the mempool. "
                        f"Wait for it to confirm or expire (default 1 hour) "
                        f"before sending the reverse direction.")

            # ── Per-sender rate limit (non-coinbase only) ─────────────────────
            if tx.sender != "COINBASE":
                now    = time.time()
                window = self._rate_tracker[tx.sender]
                while window and (now - window[0]) > self.RATE_WINDOW_SECS:
                    window.popleft()
                if len(window) >= self.PER_SENDER_LIMIT:
                    return False, (
                        f"Rate limit exceeded: max {self.PER_SENDER_LIMIT} "
                        f"transactions per {self.RATE_WINDOW_SECS}s per sender")
                window.append(now)

            # ── Accept ────────────────────────────────────────────────────────
            self.storage.mempool_add(tx)
            self._pending_tx_ids.add(tx.tx_id)  # v7.1.17 clutter guard
            # TPS-OPT-3: mirror to in-memory priority queue
            self._heap.push(tx)
            # ── v7.5.0-OPT Pre-Validation Pipeline ────────────────────────
            # At this point tx.is_valid() (called above) has already run
            # verify_signature() successfully for every non-coinbase path,
            # AND all other structural / nonce / balance-adjacent checks
            # have passed.  Record the tx_id so Block.integrity_check() can
            # skip the expensive ECDSA recheck when this tx later appears
            # in a mined block.  Bounded to _VERIFIED_MAX entries — if we
            # hit the cap we drop the oldest half (FIFO-ish via pop).
            if tx.sender != "COINBASE":
                if len(self._verified) >= self._VERIFIED_MAX:
                    # Bound the set: keep recent half by rebuilding from
                    # the current heap (which is naturally bounded by
                    # mempool size and the heap caps itself).
                    live_ids = {t.tx_id for t in self._heap.get_all_live()}
                    self._verified &= live_ids
                self._verified.add(tx.tx_id)
            if tx.sender != "COINBASE":
                self._pending_nonces[tx.sender].add(tx.nonce)
                pair = (tx.sender, tx.receiver)
                self._pending_pairs[pair] = self._pending_pairs.get(pair, 0) + 1
            return True, "OK"

    def restore(self, tx: Transaction) -> Tuple[bool, str]:
        """
        AUDIT-FIX (Batch D/E): re-insert a transaction that already passed
        admission and was successfully mined once, now returning to the
        pool because Blockchain._rollback_block orphaned the block that
        contained it (ordinary reorg via reorg(), or a deep fork handled
        by _hard_reset_to()). Use this instead of add() for that purpose.

        This intentionally differs from add() in one specific way: add()'s
        nonce check requires tx.nonce to exactly extend the current
        contiguous pending run (chain_nonce + pending_count), which is
        correct for a brand-new submission but wrong here — a restored tx
        can legitimately need to fill a nonce "hole" below an already-
        pending, higher-nonce sibling transaction from the same sender
        (e.g. sender submitted nonce=5 and nonce=6 back-to-back; only the
        nonce=5 tx got mined and is the one now being rolled back, while
        nonce=6 is still sitting untouched in the pool). Applying add()'s
        formula here would reject the restore purely because of that
        unrelated sibling, silently losing a transaction that was, moments
        ago, confirmed on-chain — with no error surfaced anywhere.

        Everything else that reflects genuine current-state validity is
        still enforced: expiry, structural/signature validity, duplicate
        tx_id, already-on-chain, the hard pool cap, and nonce staleness
        (a nonce below the current chain nonce means the new canonical
        chain has already moved past this slot via some other tx, so this
        one must NOT be restored). Fee/dust/rate-limit/circular-trade
        checks are admission POLICY for brand-new submissions and are
        deliberately skipped here: this transaction already cleared them
        once and paid a fee that was valid at that time. Re-applying
        policy knobs that may have since moved — or a per-sender rate
        limit driven by a reorg the sender doesn't control — should not
        cause an already-honored transaction to be lost a second time.
        """
        with self._lock:
            if tx.is_expired():
                return False, f"Transaction expired (expiry={tx.expiry})"

            ok, msg = tx.is_valid()
            if not ok:
                return False, msg

            if tx.tx_id in self._pending_tx_ids:
                return False, "Already in mempool"

            if self.storage.tx_exists(tx.tx_id):
                return False, "Already in chain"

            if self.storage.mempool_size() >= Config.MEMPOOL_MAX:
                return False, "Mempool full — try again later or increase fee"

            if tx.sender != "COINBASE" and tx.receiver != VSD_GLOBAL_MARKET:
                chain_nonce = self.storage.get_nonce(tx.sender)
                if tx.nonce < chain_nonce:
                    return False, (
                        f"Nonce {tx.nonce} for {tx.sender[:12]} is stale "
                        f"(chain has advanced to {chain_nonce}) — the new "
                        f"canonical chain already accounts for this slot")
                if tx.nonce in self._pending_nonces[tx.sender]:
                    return False, (
                        f"Nonce {tx.nonce} for {tx.sender[:12]} is already "
                        f"claimed by a different pending transaction")

            self.storage.mempool_add(tx)
            self._pending_tx_ids.add(tx.tx_id)
            self._heap.push(tx)
            if tx.sender != "COINBASE":
                if len(self._verified) >= self._VERIFIED_MAX:
                    live_ids = {t.tx_id for t in self._heap.get_all_live()}
                    self._verified &= live_ids
                self._verified.add(tx.tx_id)
                self._pending_nonces[tx.sender].add(tx.nonce)
                pair = (tx.sender, tx.receiver)
                self._pending_pairs[pair] = self._pending_pairs.get(pair, 0) + 1
            return True, "OK"

    def remove(self, tx_id: str):
        """Remove a tx; also clean up nonce / pair tracking."""
        with self._lock:
            # IMPORTANT: must query the mempool table, not the confirmed
            # transactions table.  get_tx() only searches confirmed txs,
            # so it returns None for any pending tx that hasn't been mined yet,
            # leaving _pending_nonces and _pending_pairs permanently stale.
            tx = self.storage.mempool_get_by_id(tx_id)
            self.storage.mempool_remove(tx_id)
            self._pending_tx_ids.discard(tx_id)  # v7.1.17 clutter guard
            # TPS-OPT-3: lazy-remove from in-memory priority queue
            self._heap.remove(tx_id)
            # v7.5.0-OPT: drop verified-set entry (tx no longer resident).
            self._verified.discard(tx_id)
            if tx and tx.sender != "COINBASE":
                self._pending_nonces[tx.sender].discard(tx.nonce)
                pair = (tx.sender, tx.receiver)
                if pair in self._pending_pairs:
                    self._pending_pairs[pair] = max(0, self._pending_pairs[pair] - 1)
                    if self._pending_pairs[pair] == 0:
                        del self._pending_pairs[pair]

    def get_top(self, n: int) -> List[Transaction]:
        """
        Return the top-n transactions eligible for inclusion in the next block.

        Fix #7 — Mempool Global Consistency:
        All honest nodes must select transactions in the same canonical order
        so that block candidates built independently produce the same
        transaction set (modulo timing).  The canonical ordering rule is:

          1. Purge expired transactions.
          2. For each sender, collect pending transactions and advance only
             those whose nonce is the immediate next expected nonce (no gaps).
             This ensures the per-sender ordering is always contiguous and
             deterministic: two nodes with the same mempool always agree on
             which transactions are eligible.
          3. Merge the per-sender queues into one list.  Repeatedly take the
             best queue-head by fee (descending), then timestamp (ascending),
             then tx_id (lexicographic) — a fully deterministic total order.
             Only queue heads compete, so a sender's transactions are never
             reordered: nonce N always precedes nonce N+1 in the result, no
             matter how their fees compare.  (A plain global sort by fee would
             put a higher-fee nonce N+1 ahead of nonce N and produce a block
             that validate_block() rejects with a nonce mismatch.)

        Without nonce-gap enforcement, one node might include tx with nonce=3
        while another (which also has nonce=2 pending) must include nonce=2
        first — leading to inconsistent block construction.
        """
        # Also clean stale zero-balance identity claims left by an older
        # process before candidate construction. This call is outside the
        # mempool lock because the cleanup uses remove(), which acquires it.
        self._purge_unaffordable_identity_claims()
        with self._lock:
            self._purge_expired()

        # ── Canonical eligible set (Fix #7) ───────────────────────────────────
        # TPS-OPT-3: read from the in-memory priority queue instead of
        # scanning the entire DB table on every call.  The heap returns
        # transactions already sorted by (-fee, timestamp, tx_id).
        all_txs = self._heap.get_all_live()

        # Group by sender
        by_sender: Dict[str, List[Transaction]] = defaultdict(list)
        coinbase_txs: List[Transaction] = []
        for tx in all_txs:
            if tx.sender == "COINBASE":
                coinbase_txs.append(tx)
            else:
                by_sender[tx.sender].append(tx)

        # One queue per sender: the contiguous, gap-free run of nonces that
        # starts at that sender's chain nonce, in ascending nonce order.
        queues: List[List[Transaction]] = []

        for sender, txs in by_sender.items():
            # Sort per-sender by nonce
            txs.sort(key=lambda t: t.nonce)
            # Advance only the contiguous prefix starting at expected_nonce
            chain_nonce   = self.storage.get_nonce(sender)
            pending_nonces = sorted(self._pending_nonces.get(sender, set()))
            expected = chain_nonce
            run: List[Transaction] = []
            for tx in txs:
                if tx.nonce < expected:
                    # STALE-NONCE FIX: this nonce is already behind the chain (or
                    # repeats one just taken), so it can never be mined.  Skip it
                    # instead of letting it block the sender's later txs.
                    continue
                if tx.nonce == expected:
                    run.append(tx)
                    expected += 1
                else:
                    # Gap detected — stop here; remaining txs are not yet eligible
                    break
            if run:
                queues.append(run)

        # Coinbase entries have no nonce: each is its own one-element queue.
        for tx in coinbase_txs:
            queues.append([tx])

        # NONCE-ORDER FIX: k-way merge of the queues instead of one global
        # fee sort.  Priority is unchanged — fee DESC, timestamp ASC, tx_id ASC
        # (fully deterministic, tx_id is unique) — but only each queue's HEAD
        # competes, so per-sender nonce order is always preserved.  Taking a
        # prefix of the merged list (eligible[:n]) therefore can never leave a
        # nonce gap either.
        def _prio(t: Transaction, qi: int, pos: int):
            return (-t.fee, t.timestamp, t.tx_id, qi, pos)

        heap = [_prio(q[0], qi, 0) for qi, q in enumerate(queues)]
        _heapq.heapify(heap)
        eligible: List[Transaction] = []
        while heap:
            _nf, _ts, _tid, qi, pos = _heapq.heappop(heap)
            q = queues[qi]
            eligible.append(q[pos])
            pos += 1
            if pos < len(q):
                _heapq.heappush(heap, _prio(q[pos], qi, pos))
        return eligible[:n]

    def _purge_expired(self):
        """Remove all expired transactions (called under lock).

        TPS-OPT-3: scans the in-memory heap instead of the full DB table.
        Expired entries are removed from both the heap and the DB.
        """
        all_txs = self._heap.get_all_live()
        now = int(time.time())
        for tx in all_txs:
            if tx.expiry > 0 and now > tx.expiry:
                self.storage.mempool_remove(tx.tx_id)
                self._pending_tx_ids.discard(tx.tx_id)  # v7.1.17 clutter guard
                self._heap.remove(tx.tx_id)
                # v7.5.0-OPT: drop verified-set entry (expired tx purged).
                self._verified.discard(tx.tx_id)
                if tx.sender != "COINBASE":
                    self._pending_nonces[tx.sender].discard(tx.nonce)
                    # BUG-FIX: _pending_pairs was never updated on expiry, so
                    # stale entries accumulated indefinitely.  Any future reverse
                    # transaction (B→A after A→B expired) was wrongly flagged as
                    # a "circular trade" and rejected.
                    pair = (tx.sender, tx.receiver)
                    if pair in self._pending_pairs:
                        self._pending_pairs[pair] = max(0, self._pending_pairs[pair] - 1)
                        if self._pending_pairs[pair] == 0:
                            del self._pending_pairs[pair]

    def size(self) -> int:
        return self.storage.mempool_size()

    def all_txs(self) -> List[Transaction]:
        return self.storage.mempool_all()

    def pending_outflow_sat(self, sender: str) -> Tuple[int, int, int]:
        """
        Sum mempool obligations for ``sender`` without touching consensus.
        Returns (register_stake_sat, transfer_amount_sat, fee_sat) — all
        satoshi integers — so preflight checks and UI can show a truly
        spendable balance that accounts for already-submitted txs.

        This is a READ-ONLY helper.  It does not touch balances, roles, or
        any consensus path; it simply inspects mempool contents.
        """
        reg_sat = 0
        xfer_sat = 0
        fee_sat = 0
        if not sender:
            return 0, 0, 0
        try:
            for tx in self.storage.mempool_all():
                if getattr(tx, "sender", "") != sender:
                    continue
                try:
                    tx_fee_sat = tx.compute_fee_sat()
                except Exception:
                    tx_fee_sat = to_satoshi(getattr(tx, "fee", 0.0) or 0.0)
                fee_sat += int(tx_fee_sat)
                if tx.tx_type == Transaction.TYPE_REGISTER:
                    # REGISTER txs don't debit the stake at apply time, but they
                    # DO lock that amount — a second stake of the same coins
                    # would double-count availability until the first lands.
                    if (tx.memo or "").strip().lower() in ("miner", "investor"):
                        reg_sat += to_satoshi(getattr(tx, "amount", 0.0) or 0.0)
                elif tx.tx_type in (Transaction.TYPE_DEPLOY, Transaction.TYPE_CALL):
                    # VVM txs debit amount + max_gas upfront
                    xfer_sat += to_satoshi(getattr(tx, "amount", 0.0) or 0.0)
                else:
                    # Standard transfer: amount leaves the account at apply time
                    xfer_sat += to_satoshi(getattr(tx, "amount", 0.0) or 0.0)
        except Exception as _e:
            # Never fail a preflight because the mempool scan hiccuped
            log.debug(f"pending_outflow_sat scan failed: {_e}")
            return reg_sat, xfer_sat, fee_sat
        return reg_sat, xfer_sat, fee_sat

    def clear_confirmed(self, tx_ids: List[str]):
        for tid in tx_ids:
            self.remove(tid)

    def purge_stale_nonces(self, senders: Optional[Iterable[str]] = None) -> int:
        """Remove pending txs whose nonce is already behind the chain nonce.

        STALE-NONCE FIX.  clear_confirmed() removes only the exact tx_ids a
        block contained.  A DIFFERENT pending tx from the same sender with the
        SAME nonce (a re-submission, or two nodes that heard two versions) was
        left behind once the other version was mined.  Its nonce is now below
        the chain nonce, so validate_block() can never accept it, yet until its
        expiry (default 1 hour) it
          * stayed in _pending_nonces, so add() computed a wrong expected nonce
            and rejected the sender's next tx, and the CLI/RPC helpers that
            read _pending_nonces directly built gapped nonces;
          * blocked that sender's whole queue in get_top();
          * kept counting in pending_outflow_sat() and _pending_pairs.

        Every such tx is removed through remove(), which cleans the DB row,
        heap, _pending_tx_ids, _verified, _pending_nonces and _pending_pairs.

        ``senders`` limits the scan to those addresses: apply_block() passes the
        senders of the block it just applied (a chain nonce only moves for a
        sender that appears in a block).  ``None`` checks every pending sender
        (used once at startup).  Returns how many txs were removed.  Never
        raises: mempool housekeeping must not turn an already-committed block
        into an apply_block() failure.
        """
        try:
            only = None if senders is None else set(senders)
            if only is not None and not only:
                return 0
            stale_ids: List[str] = []
            # Collect under the lock, remove after releasing it: remove() takes
            # the same non-reentrant lock itself.
            with self._lock:
                chain_nonce: Dict[str, int] = {}
                for tx in self._heap.get_all_live():
                    if tx.sender == "COINBASE":
                        continue
                    if only is not None and tx.sender not in only:
                        continue
                    cn = chain_nonce.get(tx.sender)
                    if cn is None:
                        cn = self.storage.get_nonce(tx.sender)
                        chain_nonce[tx.sender] = cn
                    if tx.nonce < cn:
                        stale_ids.append(tx.tx_id)
        except Exception as exc:
            log.debug("Mempool stale-nonce scan skipped: %s", exc)
            return 0

        removed = 0
        for tid in stale_ids:
            try:
                self.remove(tid)
                removed += 1
            except Exception as exc:
                log.warning("Mempool: could not drop stale-nonce tx %s: %s",
                            tid[:12], exc)
        if removed:
            log.info("Mempool: dropped %d stale-nonce tx(s) already superseded "
                     "on-chain", removed)
        return removed

    # ── ROLLBACK SUPPORT: flush entire mempool ────────────────────────────
    def clear_all(self):
        """Flush every transaction from the mempool (DB + in-memory state).

        Used by the rollback procedure to discard transactions that may
        reference state (UTXOs, nonces, balances) that no longer exists
        after blocks are deleted.  This is a destructive, non-reversible
        operation — call only under the blockchain write-lock.
        """
        with self._lock:
            # ── Wipe persisted mempool rows ────────────────────────────
            if self.storage._pgx_enabled:
                try:
                    self.storage._pg_exec("DELETE FROM mempool")
                except Exception:
                    pass
                try:
                    self.storage._cache.mempool_remove(
                        list(self._pending_tx_ids))
                except Exception:
                    pass
            else:
                try:
                    c = self.storage._conn()
                    c.execute("DELETE FROM mempool")
                    c.commit()
                except Exception:
                    pass

            # ── Reset all in-memory tracking structures ────────────────
            self._pending_nonces.clear()
            self._pending_pairs.clear()
            self._pending_tx_ids.clear()
            self._rate_tracker.clear()
            self._base_fee_multiplier = 1.0
            # TPS-OPT-3: wipe the in-memory priority queue
            self._heap.clear()
            # v7.5.0-OPT: wipe verified-set so nothing stale survives rollback.
            self._verified.clear()
            log.info("Mempool: clear_all() — all pending transactions flushed")

    def update_base_fee(self, fill_ratio: float):
        """
        EIP-1559-style dynamic base fee adjustment.
        fill_ratio: ratio of last block's actual size to max size.
        """
        with self._lock:
            if fill_ratio > self.TARGET_FILL_RATIO:
                self._base_fee_multiplier = min(4.0, self._base_fee_multiplier * 1.125)
            elif fill_ratio < self.TARGET_FILL_RATIO:
                self._base_fee_multiplier = max(1.0, self._base_fee_multiplier / 1.125)
            metrics.set_gauge("base_fee_multiplier", self._base_fee_multiplier)

    # ── v7.5.0-OPT Pre-Validation Pipeline API ────────────────────────────
    def is_verified(self, tx_id: str) -> bool:
        """Return True iff ``tx_id`` has already passed the full crypto-
        validation pipeline in this mempool (ECDSA + structural + nonce).

        Used by Block.integrity_check() to skip the expensive ECDSA recheck
        when a block arrives carrying transactions we already vetted at
        gossip time.  Intentionally NOT wrapped in _lock: a set membership
        check on CPython is atomic for reads, and a false negative (returning
        False for a tx that WAS verified) is always safe — the caller will
        just do the verify_signature() the old way.
        """
        return tx_id in self._verified

    def mark_verified(self, tx_id: str) -> None:
        """External hook — mark a tx_id as fully verified.

        Used when a transaction is confirmed to have passed all checks
        outside of add() (e.g. after Full Audit Mode re-validation).  No-op
        if already present.  Bounded by the same _VERIFIED_MAX cap as add().
        """
        with self._lock:
            if len(self._verified) >= self._VERIFIED_MAX:
                live_ids = {t.tx_id for t in self._heap.get_all_live()}
                self._verified &= live_ids
            self._verified.add(tx_id)
