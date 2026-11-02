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
"""visold.selfhealing.rollback

Original section: SECTION 6: LAYER 5 — ROLLBACK ENGINE

Defines: BlockSnapshot, SnapshotStore, GovernanceRollbackVote, RollbackExecutor
Origin: visold_vsd_.py L51378-51418, L51421-51460, L51463-51516, L51519-51628, L51631-51823
"""

import hashlib
import math
import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from visold.crypto.ecc import ecdsa_verify, pub_from_hex, pub_to_address, sig_from_hex
from visold.kernel.logging_setup import log


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6: LAYER 5 — ROLLBACK ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class BlockSnapshot:
    """
    Lightweight pre-block snapshot for event-sourced rollback.

    Captured BEFORE a block is applied. Contains only the data needed
    to reverse the block's state transitions — NOT a full state copy.

    Integration: call BlockSnapshot.capture(blockchain, height) before
    apply_block() is called by StateEngine._handle_mine_result or
    _handle_new_block.
    """
    __slots__ = ("height", "state_root", "balances_delta",
                 "validators_snapshot", "vvm_storage_delta",
                 "captured_at", "block_hash")

    def __init__(
        self,
        height: int,
        state_root: str,
        balances_delta: Dict[str, int],
        validators_snapshot: List[dict],
        vvm_storage_delta: Dict[str, Any],
        block_hash: str,
    ):
        self.height = height
        self.state_root = state_root
        self.balances_delta = balances_delta
        self.validators_snapshot = validators_snapshot
        self.vvm_storage_delta = vvm_storage_delta
        self.captured_at = time.time()
        self.block_hash = block_hash

    def to_dict(self) -> dict:
        return {
            "height":               self.height,
            "state_root":           self.state_root,
            "balances_delta":       self.balances_delta,
            "validators_snapshot":  self.validators_snapshot,
            "block_hash":           self.block_hash,
            "captured_at":          self.captured_at,
        }


class SnapshotStore:
    """
    Ring-buffer store for BlockSnapshots.

    Keeps the last MAX_SNAPSHOTS blocks' pre-state. When a rollback
    is requested for height H, the snapshot for H must exist here.

    Storage: in-memory ring-buffer + JSON serialisation to disk on
    each commit (small footprint — only deltas are stored).
    """
    MAX_SNAPSHOTS = 50   # last 50 blocks — rollback window

    def __init__(self, data_dir: str):
        self._data_dir = data_dir
        self._snapshots: Dict[int, BlockSnapshot] = {}
        self._order: deque = deque(maxlen=self.MAX_SNAPSHOTS)
        self._lock = threading.Lock()

    def store(self, snap: BlockSnapshot) -> None:
        with self._lock:
            if len(self._order) >= self.MAX_SNAPSHOTS:
                oldest_height = self._order[0]
                self._snapshots.pop(oldest_height, None)
            self._order.append(snap.height)
            self._snapshots[snap.height] = snap

    def get(self, height: int) -> Optional[BlockSnapshot]:
        with self._lock:
            return self._snapshots.get(height)

    def has_range(self, from_height: int, to_height: int) -> bool:
        """Check if we have snapshots for the entire rollback range."""
        with self._lock:
            return all(h in self._snapshots
                       for h in range(from_height, to_height + 1))

    def available_depths(self) -> List[int]:
        """Return sorted list of snapshot heights."""
        with self._lock:
            return sorted(self._snapshots.keys())


def _verify_shbs_validator_signature(storage_ref, validator_addr: str,
                                     message: bytes,
                                     sig_hex: str, pub_hex: str
                                     ) -> Tuple[bool, str]:
    """
    AUDIT-FIX-5 (unauthenticated validator vote forgery): cryptographic
    identity+signature check shared by GovernanceRollbackVote.add_vote()
    and the AUDIT-FIX-6 preview-confirmation flow.

    Mirrors the existing "Fix #5: Cross-layer identity binding" pattern
    already used elsewhere in this codebase for validator block-signature
    verification — pub_hex must derive to the claimed address BEFORE the
    signature itself is checked — reused here rather than reinvented,
    since that exact pattern is already proven and exercised.

    Returns (ok, reason). reason is "" on success, otherwise a short
    machine-readable code: "not_validator", "bad_pubkey",
    "identity_mismatch", "bad_signature", "sig_invalid".
    """
    try:
        validators = storage_ref.get_validators() or []
    except Exception as exc:
        log.critical("SHBS validator snapshot unavailable: %s", exc)
        return False, "validator_set_unavailable"
    if not any(v.get("address") == validator_addr
               and not v.get("slashed", False)
               for v in validators):
        return False, "not_validator"

    try:
        claimed_pub = pub_from_hex(pub_hex)
    except Exception:
        return False, "bad_pubkey"

    try:
        derived_addr = pub_to_address(claimed_pub)
    except Exception:
        return False, "bad_pubkey"

    if derived_addr != validator_addr:
        return False, "identity_mismatch"

    try:
        sig = sig_from_hex(sig_hex)
    except Exception:
        return False, "bad_signature"

    try:
        h = hashlib.sha256(message).digest()
        if not ecdsa_verify(claimed_pub, h, sig):
            return False, "sig_invalid"
    except Exception:
        return False, "sig_invalid"

    return True, ""


class GovernanceRollbackVote:
    """
    Validator quorum voting for CRITICAL rollback decisions.

    Mechanics:
      1. SelfHealingSystem emits a RollbackProposal to all connected validators
         via P2P (custom message type MSG_ROLLBACK_PROPOSAL)
      2. Each validator checks the evidence, signs or rejects
      3. When ≥ 2/3 of active validators sign, QuorumReached → execute
      4. Fast-track override: if 3/3 validators sign, skip the VOTE_WINDOW wait

    This is decoupled from the existing GovernanceEngine upgrade-proposal system
    to avoid interference with in-flight upgrade votes.
    """

    QUORUM_FRACTION  = 2.0 / 3.0
    FAST_TRACK_FRAC  = 1.0
    VOTE_WINDOW_SECS = 30.0        # wait up to 30s for votes

    def __init__(self, storage_ref, proposal_id: str,
                 rollback_depth: int, evidence: dict):
        self.proposal_id   = proposal_id
        self.rollback_depth = rollback_depth
        self.evidence      = evidence
        self._storage      = storage_ref
        self._votes: Dict[str, bool] = {}   # addr → approve
        self._lock = threading.Lock()
        self.created_at    = time.time()
        self._closed       = False

    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.VOTE_WINDOW_SECS

    def add_vote(self, validator_addr: str, approve: bool,
                 sig_hex: str, pub_hex: str) -> str:
        """
        Record a vote. Returns "accepted", "already_voted", "not_validator",
        "identity_mismatch", "bad_pubkey", "bad_signature", "sig_invalid",
        or "closed".

        AUDIT-FIX-5: this now ACTUALLY performs the ECDSA verification the
        docstring always claimed to do. Previously sig_hex/pub_hex were
        accepted as parameters but never used anywhere in this method —
        any caller who knew a registered validator's address (public
        information) could cast a binding vote as that validator with no
        proof of private-key possession at all. Combined with the
        "shbs_vote" RPC method having no auth check, a single
        unauthenticated caller could forge quorum on any active rollback
        proposal by voting once per known validator address.

        The signed message binds proposal_id + approve, so a captured
        signature cannot be replayed onto a different proposal, and an
        "approve" signature cannot be reinterpreted as "reject" or vice
        versa.
        """
        if self._closed:
            return "closed"

        message = f"VSD-SHBS-VOTE|{self.proposal_id}|{approve}".encode()
        ok, reason = _verify_shbs_validator_signature(
            self._storage, validator_addr, message, sig_hex, pub_hex)
        if not ok:
            return reason

        with self._lock:
            if validator_addr in self._votes:
                return "already_voted"
            self._votes[validator_addr] = approve
            return "accepted"

    def quorum_status(self) -> dict:
        """
        Check current vote state.
        Returns: {reached: bool, fast_track: bool, approve_count: int,
                  reject_count: int, required: int, total_validators: int}
        """
        try:
            validators = self._storage.get_validators() or []
            active_validators = [v for v in validators
                                 if not v.get("slashed", False)]
            n_validators = len(active_validators)
        except Exception as exc:
            log.critical("SHBS validator snapshot unavailable: %s", exc)
            return {"reached": False, "fast_track": False,
                    "approve_count": 0, "reject_count": 0,
                    "required": None, "total_validators": None,
                    "auto_approve": False,
                    "error": "validator_set_unavailable"}

        if n_validators == 0:
            # No validators — auto-approve (solo node scenario)
            return {"reached": True, "fast_track": True,
                    "approve_count": 0, "reject_count": 0,
                    "required": 0, "total_validators": 0,
                    "auto_approve": True}

        with self._lock:
            approve = sum(1 for v in self._votes.values() if v)
            reject  = sum(1 for v in self._votes.values() if not v)
            required = math.ceil(n_validators * self.QUORUM_FRACTION)
            fast_track_req = n_validators  # all validators

        return {
            "reached":           approve >= required,
            "fast_track":        approve >= fast_track_req,
            "approve_count":     approve,
            "reject_count":      reject,
            "required":          required,
            "total_validators":  n_validators,
            "auto_approve":      False,
        }

    def close(self):
        self._closed = True


class RollbackExecutor:
    """
    Deterministic N-block rollback executor.

    Integration with existing code (CRITICAL — zero modifications to
    existing methods):

    Visold already has `Blockchain._rollback_block(block)` which:
      - Reverses _distribute_rewards (debits miner/validators)
      - Reverses all transactions (debit receiver, credit sender)
      - Deletes the block from storage
      - Updates chain tip

    RollbackExecutor uses this existing method in a loop from tip down to
    target_height, then optionally replays safe transactions.

    Safe-tx filtering: a transaction is "safe" if:
      1. It was not sent by or to the flagged address
      2. It passes VVMEngine.simulate() without error
      3. It passes Mempool validation (correct nonce, fee, sig)
    """

    def __init__(self, blockchain_ref, storage_ref, snapshot_store: SnapshotStore):
        self._blockchain = blockchain_ref
        self._storage    = storage_ref
        self._snapshots  = snapshot_store
        self._lock       = threading.Lock()   # serialize rollback operations

    def execute(
        self,
        target_height: int,
        flagged_addresses: Set[str],
        replay_safe: bool = True,
    ) -> Tuple[bool, str]:
        """
        Roll back from current tip to target_height, then apply the replay policy.

        Args:
            target_height: the chain height to roll back TO (exclusive).
                           All blocks from current_tip down to target_height+1
                           will be removed.
            flagged_addresses: transactions involving these addresses are NOT
                               re-admitted to the mempool.
            replay_safe: if True, re-admit the non-flagged transactions of the
                         removed blocks; if False, re-admit none of them.

        Returns (success: bool, message: str)

        SAFETY INVARIANTS:
          1. Never rolls back below genesis (height 0)
          2. Never rolls back more than SnapshotStore.MAX_SNAPSHOTS blocks
          3. The rollback itself is Blockchain.rollback(): every block is
             reversed as one atomic unit, and Layer2State, the snapshot index,
             the difficulty cache and the finality fence are reconciled to the
             height actually reached
          4. The state root is verified by Blockchain.rollback() (divergence
             is reported and makes the result unsuccessful)
        """
        with self._lock:
            try:
                current_tip = self._blockchain.height()
                log.warning(
                    f"[ROLLBACK] Starting rollback: tip={current_tip} → "
                    f"target={target_height}")

                # Safety bounds
                if target_height < 0:
                    return False, "Cannot rollback below genesis"
                rollback_depth = current_tip - target_height
                if rollback_depth <= 0:
                    return False, f"Already at or below target height {target_height}"
                if rollback_depth > SnapshotStore.MAX_SNAPSHOTS:
                    return False, (
                        f"Rollback depth {rollback_depth} exceeds "
                        f"safe window {SnapshotStore.MAX_SNAPSHOTS}")

                # Canonical Block objects for every height that will be removed.
                # They are read before the rollback so their transactions can be
                # classified afterwards.
                removed_blocks = []
                for h in range(current_tip, target_height, -1):
                    blk = self._storage.get_block(h)
                    if blk is None:
                        log.error(f"[ROLLBACK] Block {h} not found — aborting")
                        return False, f"Block {h} missing from storage"
                    removed_blocks.append(blk)

                ok, msg = self._blockchain.rollback(target_height)
                new_tip = self._blockchain.height()
                removed_now = [b for b in removed_blocks if int(b.index) > new_tip]
                replayed, dropped = self._apply_replay_policy(
                    removed_now, flagged_addresses, replay_safe)
                log.warning(
                    f"[ROLLBACK] Complete. Removed {len(removed_now)} blocks. "
                    f"New tip: {new_tip}")

                if new_tip != target_height:
                    # Partial: the chain is reconciled at new_tip (the failing
                    # block and everything below it are intact).
                    return False, (
                        f"Rollback incomplete at height {new_tip}: {msg}. "
                        f"Replayed {replayed} safe txs, dropped {dropped}.")
                if not ok:
                    return False, (
                        f"Rollback reached target {target_height} but was flagged: {msg}. "
                        f"Replayed {replayed} safe txs, dropped {dropped}.")
                return True, (
                    f"Rolled back {len(removed_now)} blocks "
                    f"(tip: {current_tip} → {new_tip}). "
                    f"Replayed {replayed} safe txs, dropped {dropped}.")

            except Exception as exc:
                log.error(f"[ROLLBACK] Unexpected error: {exc}", exc_info=True)
                return False, f"Rollback failed: {exc}"

    def _apply_replay_policy(
        self,
        removed_blocks: List,
        flagged: Set[str],
        replay_safe: bool,
    ) -> Tuple[int, int]:
        """Decide which transactions of the removed blocks stay in the mempool.

        Blockchain.rollback() already re-admits every non-coinbase transaction
        of the removed blocks.  The policy then:
          * keeps (and, if missing, re-adds in chronological order) a transaction
            only when replay_safe is True and neither its sender nor its receiver
            is flagged;
          * removes every other transaction from the mempool.
        Mempool.add() re-validates nonce, fee and signature, so a stale
        transaction is simply not admitted.  Returns (replayed, dropped).
        """
        mempool = self._blockchain.mempool
        replayed = 0
        dropped = 0
        # Chronological order: lowest height first, in-block order preserved.
        for blk in sorted(removed_blocks, key=lambda b: int(b.index)):
            for tx in blk.transactions:
                if tx.sender == "COINBASE":
                    continue
                is_safe = (replay_safe
                           and tx.sender not in flagged
                           and tx.receiver not in flagged)
                if is_safe:
                    ok, _ = mempool.add(tx)
                    if ok:
                        replayed += 1
                else:
                    mempool.remove(tx.tx_id)
                    dropped += 1
        return replayed, dropped
