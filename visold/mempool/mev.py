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
"""visold.mempool.mev

Original section: SECTION 7A1: MEV PROTECTION — COMMIT-REVEAL SCHEME

Defines: CommitRevealMempool
Origin: visold_vsd_.py L18874-18990, L18994
"""

import threading
from typing import Dict, TYPE_CHECKING, Tuple

from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.ledger.transaction import Transaction


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7A1: MEV PROTECTION — COMMIT-REVEAL SCHEME
# Protects users from front-running by separating transaction commitment
# (hash only) from revelation (full tx) across block boundaries.
# ─────────────────────────────────────────────────────────────────────────────
class CommitRevealMempool:
    """
    Optional MEV protection layer using a commit-reveal scheme.

    Mechanism
    ─────────
    Phase 1 — COMMIT (block N):
      The sender submits COMMIT(H) where H = SHA-256(tx_id ‖ sender ‖ nonce).
      Only the commitment hash is broadcast; the actual transaction details
      (amount, receiver, memo) are kept private.

    Phase 2 — REVEAL (block N+1):
      The sender broadcasts the full transaction.  Nodes verify that it
      matches an existing commitment before accepting it into the mempool.

    Protection guarantees:
      • Front-running bots cannot see the transaction details until after
        the commitment is already included in a block.
      • Sandwich attacks require knowing the full tx before the commitment
        block is mined — which is impossible by construction.

    F-12 — Security Scope Disclaimer (IMPORTANT):
    ─────────────────────────────────────────────
    This scheme protects against EXTERNAL MEV bots only.  It does NOT
    protect against malicious validators.  A validator node receives the
    full revealed transaction in block N+1 before constructing their block
    proposal, and can still insert a front-running transaction ahead of the
    revealed one in their proposed ordering.

    Full validator-level MEV resistance requires threshold encryption of
    commitments (e.g., a distributed decryption key held by the validator
    committee) so that no single validator can decrypt the transaction
    content until after block inclusion.  This is a known research-track
    item on the Visold roadmap (Q1 2027 ZK-proof integration phase).

    Users enabling MEV protection (VISOLD_MEV_PROTECT=1) should be informed
    of this limitation.  The mevcommit RPC response includes a
    "validator_mev_protected": false flag to surface this constraint.

    Limitations:
      • Adds 1-block latency to all protected transactions.
      • Only effective if Config.MEV_PROTECTION_ENABLED = True.
      • Does NOT protect against malicious validators (see above).

    Thread safety: protected by _lock.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # commit_hash → (sender, block_height_committed, tx_id_hint)
        self._pending_commits: Dict[str, Tuple[str, int, str]] = {}

    def submit_commit(self, commit_hash: str, sender: str,
                      current_height: int) -> Tuple[bool, str]:
        """
        Phase 1: Accept a transaction commitment.
        commit_hash = SHA-256(tx_id ‖ sender ‖ nonce).
        Returns (True, "OK") if accepted, (False, reason) otherwise.
        """
        if not Config.MEV_PROTECTION_ENABLED:
            return False, "MEV protection is not enabled"
        with self._lock:
            if commit_hash in self._pending_commits:
                return False, "Commitment already exists"
            self._pending_commits[commit_hash] = (sender, current_height, "")
        metrics.inc("mev_commits_submitted")
        log.debug(f"MEV commit accepted: {commit_hash[:16]}... from {sender[:16]}")
        return True, "OK"

    def verify_reveal(self, tx: 'Transaction',
                      current_height: int) -> Tuple[bool, str]:
        """
        Phase 2: Verify a revealed transaction matches a prior commitment.
        The commitment hash is reconstructed from the tx and checked.
        """
        if not Config.MEV_PROTECTION_ENABLED:
            return True, "MEV protection not enabled — reveal not required"
        commit_hash = self._compute_commit_hash(tx)
        with self._lock:
            entry = self._pending_commits.get(commit_hash)
            if entry is None:
                return False, (
                    f"No matching commitment for tx {tx.tx_id[:16]}. "
                    f"Submit COMMIT first (MEV protection is active).")
            sender, committed_at, _ = entry
            if sender != tx.sender:
                return False, "Commitment sender mismatch"
            delay = current_height - committed_at
            if delay < Config.COMMIT_REVEAL_DELAY_BLOCKS:
                return False, (
                    f"Reveal too early: committed at block {committed_at}, "
                    f"current={current_height}, "
                    f"required delay={Config.COMMIT_REVEAL_DELAY_BLOCKS} blocks")
            # Consume the commitment
            del self._pending_commits[commit_hash]
        metrics.inc("mev_reveals_verified")
        return True, "OK"

    def _compute_commit_hash(self, tx: 'Transaction') -> str:
        """Reconstruct the commitment hash from a transaction."""
        raw = f"{tx.tx_id}:{tx.sender}:{tx.nonce}"
        return sha256(raw.encode())

    def prune_stale(self, current_height: int, max_age_blocks: int = 20):
        """Remove commitments that were never revealed within max_age_blocks."""
        with self._lock:
            cutoff = current_height - max_age_blocks
            stale = [h for h, (_, committed_at, _) in self._pending_commits.items()
                     if committed_at < cutoff]
            for h in stale:
                del self._pending_commits[h]
            if stale:
                log.debug(f"MEV: pruned {len(stale)} stale commitments")

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending_commits)


# Global singleton — shared by VisoldNode and RPCServer
_mev_mempool = CommitRevealMempool()
