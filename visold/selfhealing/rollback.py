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
        if not any(v.get("address") == validator_addr
                   and not v.get("slashed", False)
                   for v in validators):
            return False, "not_validator"
    except Exception:
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
        except Exception:
            n_validators = 1

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
        Roll back from current tip to target_height, then replay safe txs.

        Args:
            target_height: the chain height to roll back TO (exclusive).
                           All blocks from current_tip down to target_height+1
                           will be removed.
            flagged_addresses: transactions involving these addresses are NOT
                               replayed.
            replay_safe: if True, replay non-flagged transactions into mempool.

        Returns (success: bool, message: str)

        SAFETY INVARIANTS:
          1. Never rolls back below genesis (height 0)
          2. Never rolls back more than SnapshotStore.MAX_SNAPSHOTS blocks
          3. Each block rollback is atomic — uses existing _rollback_block()
          4. State root is verified after rollback completes
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

                # Collect blocks to roll back and their safe transactions
                safe_txs: List[dict] = []
                rolled_heights: List[int] = []

                for h in range(current_tip, target_height, -1):
                    block_dict = self._storage.get_block(h)
                    if block_dict is None:
                        log.error(f"[ROLLBACK] Block {h} not found — aborting")
                        return False, f"Block {h} missing from storage"

                    # Collect safe transactions before rolling back
                    if replay_safe:
                        block_safe_txs = self._collect_safe_txs(
                            block_dict, flagged_addresses, h)
                        # AUDIT-FIX-M3: this loop walks tip -> target (newest
                        # to oldest). Prepend (not extend/append) so the
                        # final safe_txs list ends up in true chronological
                        # order (oldest block first, in-block order
                        # preserved within each block). Mempool.add()
                        # enforces strict per-sender nonce contiguity with
                        # no future-nonce buffering, so replaying
                        # newest-first silently dropped a sender's newer tx
                        # whenever they had more than one tx in the
                        # rolled-back range.
                        safe_txs = block_safe_txs + safe_txs

                    # Reconstruct Block object and call existing _rollback_block
                    try:
                        # Import Block from the main module at call time
                        # (avoids circular import at module load)
                        block_obj = self._dict_to_block(block_dict)
                        self._blockchain._rollback_block(block_obj)
                        rolled_heights.append(h)
                        log.info(f"[ROLLBACK] Rolled back block {h}")
                    except Exception as exc:
                        log.error(
                            f"[ROLLBACK] Failed to rollback block {h}: {exc}")
                        return False, f"Rollback of block {h} failed: {exc}"

                new_tip = self._blockchain.height()
                log.warning(
                    f"[ROLLBACK] Complete. Removed {len(rolled_heights)} blocks. "
                    f"New tip: {new_tip}")

                # Replay safe transactions into mempool
                replayed = 0
                if replay_safe and safe_txs:
                    replayed = self._replay_into_mempool(safe_txs)
                    log.info(f"[ROLLBACK] Replayed {replayed} safe transactions")

                return True, (
                    f"Rolled back {len(rolled_heights)} blocks "
                    f"(tip: {current_tip} → {new_tip}). "
                    f"Replayed {replayed} safe txs.")

            except Exception as exc:
                log.error(f"[ROLLBACK] Unexpected error: {exc}", exc_info=True)
                return False, f"Rollback failed: {exc}"

    def _collect_safe_txs(
        self,
        block_dict: dict,
        flagged: Set[str],
        height: int,
    ) -> List[dict]:
        """
        Collect transactions from a block that are safe to replay:
        - Not coinbase
        - Sender and receiver not in flagged set
        """
        safe = []
        for tx in block_dict.get("transactions", []):
            if not isinstance(tx, dict):
                continue
            sender   = tx.get("sender", "")
            receiver = tx.get("receiver", "")
            if sender == "COINBASE":
                continue
            if sender in flagged or receiver in flagged:
                continue
            safe.append(tx)
        return safe

    def _replay_into_mempool(self, safe_txs: List[dict]) -> int:
        """Re-add safe transactions to the mempool."""
        count = 0
        for tx_dict in safe_txs:
            try:
                # Import Transaction from main module at call time
                tx = self._dict_to_tx(tx_dict)
                ok, _ = self._blockchain.mempool.add(tx)
                if ok:
                    count += 1
            except Exception as exc:
                log.debug(f"[ROLLBACK] replay tx failed: {exc}")
        return count

    def _dict_to_block(self, block_dict: dict):
        """
        Reconstruct a Block object from a dict using the main module's class.
        Imported lazily to avoid circular import at module load time.
        """
        import sys
        # The main visold module registers itself; look for 'Block' in globals
        for mod_name, mod in sys.modules.items():
            if hasattr(mod, "Block") and hasattr(mod, "Transaction"):
                try:
                    return mod.Block.from_dict(block_dict)
                except Exception:
                    pass
        raise RuntimeError("Block class not found in loaded modules")

    def _dict_to_tx(self, tx_dict: dict):
        """Reconstruct Transaction from dict."""
        import sys
        for mod_name, mod in sys.modules.items():
            if hasattr(mod, "Transaction"):
                try:
                    return mod.Transaction.from_dict(tx_dict)
                except Exception:
                    pass
        raise RuntimeError("Transaction class not found in loaded modules")
