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
"""visold.storage.state_pruner

Original section: SECTION 6C: STATE TREE PRUNING (MERKLE / PATRICIA)

Defines: StatePruner
Origin: visold_vsd_.py L16498-16593
"""

from typing import TYPE_CHECKING

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.chain.blockchain import Blockchain
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6C: STATE TREE PRUNING (MERKLE / PATRICIA)
# Removes historical state snapshots that are no longer required to verify
# the current chain tip, bounding database growth on long-running nodes.
# ─────────────────────────────────────────────────────────────────────────────
class StatePruner:
    """
    Prunes historical state snapshots to bound database growth.

    What is pruned
    ──────────────
    The state_root stored in each block is a SHA-256 commitment over all
    (address, balance) and (contract, storage_root) pairs at that height.
    To reconstruct the state at any historical height, the node would need
    to replay all transactions from genesis — but most production nodes only
    care about the current state.

    This pruner tracks which state snapshots are no longer needed:
      • Any state snapshot more than KEEP_SNAPSHOTS blocks old is a candidate.
      • The pruner writes a 'state_pruned_until' marker so nodes can inform
        light clients that state before that height is unavailable.
      • Blocks and transactions themselves are NOT pruned — only the state
        index rows in `balances` that can be recomputed from the chain.

    In practice, for Visold's architecture where balances are live rows (not
    historical snapshots), this pruner records compaction metadata and marks
    old snapshot heights so the operator knows the node is not a full archive.

    Thread safety: single-threaded (called from StateEngine timer tick).
    """

    def __init__(self, storage: 'Storage', blockchain: 'Blockchain'):
        self._storage    = storage
        self._blockchain = blockchain
        self._last_prune_height: int = -1

    def maybe_prune(self, current_height: int):
        """Trigger pruning if it's time.  Returns number of records pruned."""
        if not Config.STATE_PRUNE_ENABLED:
            return 0
        if current_height < Config.STATE_PRUNE_KEEP_SNAPSHOTS:
            return 0
        if (current_height - self._last_prune_height) < Config.STATE_PRUNE_INTERVAL:
            return 0

        self._last_prune_height = current_height
        pruned = self._prune_state_snapshots(current_height)
        if pruned > 0:
            log.info(f"StatePruner: pruned {pruned} historical state entries "
                     f"(keep last {Config.STATE_PRUNE_KEEP_SNAPSHOTS} snapshots)")
        return pruned

    def _prune_state_snapshots(self, current_height: int) -> int:
        """
        Mark the 'state_pruned_until' watermark in node_meta.
        The actual state rows (balances table) are live current-state rows
        that must be kept.  What we compact is the node_meta snapshot markers.
        """
        cutoff = max(0, current_height - Config.STATE_PRUNE_KEEP_SNAPSHOTS)
        pruned = 0
        try:
            c = self._storage._conn()
            # Prune state snapshot markers stored in node_meta
            rows = c.execute(
                "SELECT key FROM node_meta WHERE key LIKE 'state_snapshot:%' LIMIT 500"
            ).fetchall()
            to_delete = []
            for r in rows:
                try:
                    h = int(r["key"].split(":")[1])
                    if h < cutoff:
                        to_delete.append(r["key"])
                except (IndexError, ValueError):
                    pass
            if to_delete:
                c.executemany("DELETE FROM node_meta WHERE key=?",
                              [(k,) for k in to_delete])
                c.commit()
                pruned = len(to_delete)
            # Record the pruning watermark
            self._storage.set_meta("state_pruned_until", str(cutoff))
            metrics.set_gauge("state_pruned_until_height", float(cutoff))
        except Exception as e:
            log.debug(f"StatePruner: prune error: {e}")
        return pruned

    def record_snapshot(self, height: int, state_root: str):
        """Record a state snapshot marker for a block height."""
        if Config.STATE_PRUNE_ENABLED:
            try:
                self._storage.set_meta(f"state_snapshot:{height}", state_root)
            except Exception:
                pass

    def get_pruned_watermark(self) -> int:
        """Return the height below which state snapshots are unavailable."""
        try:
            val = self._storage.get_meta("state_pruned_until")
            return int(val) if val else 0
        except Exception:
            return 0
