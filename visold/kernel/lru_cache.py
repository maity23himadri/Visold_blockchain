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
"""visold.kernel.lru_cache

Original section: SECTION 12: LRU CACHE

Defines: LRUCache
Origin: visold_vsd_.py L31143-31218
"""

import threading
import time
from collections import OrderedDict


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 12: LRU CACHE
# ─────────────────────────────────────────────────────────────────────────────
class LRUCache:
    """Bounded LRU cache with optional TTL expiry.

    Eviction policy (v7.0.1.0):
      Size cap  — when len > capacity the least-recently-used entry is dropped.
      Time cap  — when ttl > 0, get() treats entries older than ttl seconds as
                  cache misses and deletes them on access.  put() also sweeps a
                  small batch of expired entries so the cache self-cleans even
                  for keys that are written but never re-read.

    Both policies run independently.  A cache that is small enough to never hit
    the size cap will still discard stale entries after ttl seconds, preventing
    old gossip-dedup hashes from suppressing legitimate retransmissions.
    """

    def __init__(self, capacity: int, ttl: float = 0.0):
        self.capacity  = capacity
        self.ttl       = ttl          # seconds; 0 = disabled (size-only eviction)
        self._cache: OrderedDict = OrderedDict()   # key → (value, insert_time)
        self._lock     = threading.Lock()

    # ── Internal helpers (must be called with _lock held) ─────────────────────

    def _is_expired(self, ts: float) -> bool:
        return self.ttl > 0 and (time.time() - ts) > self.ttl

    def _sweep_expired(self, max_scan: int = 64):
        """Delete up to max_scan expired entries in insertion order.

        Called from put() to prevent the cache from filling with stale entries
        that are never accessed (and therefore never cleaned by get()).  Scanning
        a small fixed batch keeps the amortised cost O(1) per put() call.
        """
        if self.ttl <= 0:
            return
        to_delete = []
        for k, (_, ts) in self._cache.items():
            if len(to_delete) >= max_scan:
                break
            if self._is_expired(ts):
                to_delete.append(k)
        for k in to_delete:
            del self._cache[k]

    # ── Public API ────────────────────────────────────────────────────────────

    def get(self, key):
        with self._lock:
            if key not in self._cache:
                return None
            value, ts = self._cache[key]
            # BUG-FIX (v7.0.1.0): check TTL on every access.
            # LRU-only eviction kept stale hashes alive for 48 h+ on low-
            # traffic nodes, incorrectly suppressing legitimate retransmissions.
            if self._is_expired(ts):
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return value

    def put(self, key, value):
        with self._lock:
            now = time.time()
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (value, now)
            # Sweep a small batch of expired entries before applying the size cap
            # so that genuinely stale entries are freed rather than displacing
            # live entries that happen to be at the LRU end.
            self._sweep_expired()
            if len(self._cache) > self.capacity:
                self._cache.popitem(last=False)   # evict LRU entry

    def delete(self, key):
        with self._lock:
            self._cache.pop(key, None)
