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
"""visold.network.reputation

Original section: SECTION 6B: PEER REPUTATION SCORE PERSISTENCE

Defines: PeerReputationManager
Origin: visold_vsd_.py L16357-16490
"""

import threading
import time
from typing import Dict, List, TYPE_CHECKING

from visold.kernel.config import Config
from visold.kernel.logging_setup import log

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6B: PEER REPUTATION SCORE PERSISTENCE
# Long-term "good behavior" tracking persisted in the database.
# Supplements the short-term ban_score with a continuous reputation signal.
# ─────────────────────────────────────────────────────────────────────────────
class PeerReputationManager:
    """
    Persistent peer reputation system that tracks good behavior over months.

    Motivation
    ──────────
    The existing ban_score only tracks misbehavior (bad messages).  This class
    adds a complementary "positive" signal:
      • fast_block_bonus:   peer propagated a valid block within FAST_BLOCK_SECS
      • valid_tx_bonus:     peer forwarded a valid, non-duplicate transaction
      • uptime_bonus:       peer maintained stable connection per tick

    Scores decay exponentially toward 0.5 (neutral) over time, so historical
    good behavior gradually fades.  This prevents a peer from exploiting past
    reputation to mask recent misbehavior.

    During network congestion, the P2PNetwork uses reputation scores to prefer
    high-quality peers when evicting low-priority peers from the peer set.

    Thread safety: all mutations are protected by a per-instance lock.
    """

    NEUTRAL   = 0.5
    MIN_SCORE = 0.0
    MAX_SCORE = 1.0

    def __init__(self, storage: 'Storage'):
        self._storage = storage
        self._lock    = threading.Lock()
        self._cache:  Dict[str, float] = {}  # peer_id → current score
        self._dirty:  set = set()            # peer_ids with unsaved changes
        self._last_persist = time.time()
        self._ensure_table()

    def _ensure_table(self):
        """Create the reputation_extended table if it doesn't exist."""
        try:
            c = self._storage._conn()
            c.execute("""
                CREATE TABLE IF NOT EXISTS reputation_extended (
                    peer_id      TEXT PRIMARY KEY,
                    score        REAL DEFAULT 0.5,
                    fast_blocks  INTEGER DEFAULT 0,
                    valid_txs    INTEGER DEFAULT 0,
                    uptime_ticks INTEGER DEFAULT 0,
                    last_updated INTEGER DEFAULT 0
                )
            """)
            c.commit()
        except Exception as e:
            log.debug(f"ReputationManager: table init error: {e}")

    def get_score(self, peer_id: str) -> float:
        with self._lock:
            if peer_id in self._cache:
                return self._cache[peer_id]
        try:
            row = self._storage._conn().execute(
                "SELECT score FROM reputation_extended WHERE peer_id=?",
                (peer_id,)).fetchone()
            score = float(row["score"]) if row else self.NEUTRAL
        except Exception:
            score = self.NEUTRAL
        with self._lock:
            self._cache[peer_id] = score
        return score

    def record_fast_block(self, peer_id: str):
        """Peer propagated a valid block quickly — award bonus."""
        self._adjust(peer_id, Config.REPUTATION_GOOD_BLOCK_BONUS, "fast_blocks")

    def record_valid_tx(self, peer_id: str):
        """Peer forwarded a valid, useful transaction — award small bonus."""
        self._adjust(peer_id, Config.REPUTATION_GOOD_TX_BONUS, "valid_txs")

    def record_uptime(self, peer_id: str):
        """Peer is still connected — award a small uptime tick."""
        self._adjust(peer_id, 0.001, "uptime_ticks")

    def _adjust(self, peer_id: str, delta: float, counter_col: str):
        with self._lock:
            current = self._cache.get(peer_id, self.NEUTRAL)
            # Exponential approach to MAX_SCORE: diminishing returns near ceiling
            remaining = self.MAX_SCORE - current
            new_score = min(self.MAX_SCORE,
                            current + delta * max(0.0, remaining))
            self._cache[peer_id] = new_score
            self._dirty.add(peer_id)
        self._maybe_persist()

    def decay_all(self):
        """
        Apply hourly decay toward NEUTRAL for all cached scores.
        Called periodically by the peer decay loop.
        """
        factor = Config.REPUTATION_DECAY_FACTOR
        with self._lock:
            for pid in list(self._cache.keys()):
                score = self._cache[pid]
                # Decay toward NEUTRAL, not toward 0
                self._cache[pid] = self.NEUTRAL + (score - self.NEUTRAL) * factor
                self._dirty.add(pid)
        self._maybe_persist(force=True)

    def _maybe_persist(self, force: bool = False):
        now = time.time()
        if not force and (now - self._last_persist) < Config.REPUTATION_PERSIST_INTERVAL:
            return
        self._last_persist = now
        with self._lock:
            dirty_copy = {pid: self._cache[pid] for pid in self._dirty}
            self._dirty.clear()
        if not dirty_copy:
            return
        try:
            c = self._storage._conn()
            for pid, score in dirty_copy.items():
                c.execute("""
                    INSERT OR REPLACE INTO reputation_extended
                    (peer_id, score, last_updated)
                    VALUES (?, ?, ?)
                    ON CONFLICT(peer_id) DO UPDATE SET
                        score=excluded.score,
                        last_updated=excluded.last_updated
                """, (pid, score, int(now)))
            c.commit()
        except Exception as e:
            log.debug(f"ReputationManager: persist error: {e}")

    def best_peers(self, candidates: List[str], k: int) -> List[str]:
        """Return top-k peer_ids by reputation score."""
        scored = [(self.get_score(pid), pid) for pid in candidates]
        scored.sort(reverse=True)
        return [pid for _, pid in scored[:k]]
