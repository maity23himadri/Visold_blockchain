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
"""visold.consensus.mining_safety

Original section: SECTION 1H-EXT — MINING SAFETY GUARD

Defines: MiningSafetyGuard
Origin: visold_vsd_.py L9548-9765
"""

import threading
import time
from typing import TYPE_CHECKING, Tuple

from visold.kernel.config import Config
from visold.kernel.logging_setup import log

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.chain.blockchain import Blockchain


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1H-EXT — MINING SAFETY GUARD
#
# Defends the miner against four classes of bootstrap / live-mining failure
# that, if left unhandled, produce blocks the network rejects, infinite
# mining loops, or stuck sync:
#
#   1. STALE-TIP MINING.  After a long offline period, the local chain tip
#      is far behind the network.  Mining on the stale tip would create an
#      orphaned/rejected block.  pre_mine_sync_check() blocks mining until
#      the node is "caught up" (best peer height ≤ local + tolerance), or
#      the absolute wait cap is reached.
#
#   2. UNREACHABLE-GAP SYNC.  Sometimes a reconnecting node finds the chain
#      so far ahead that block-by-block sync is impractical.
#      should_trigger_fast_sync() flags this case so the caller can prefer
#      the snapshot fast-sync path instead of the standard pagination loop.
#
#   3. STALLED BLOCK DOWNLOAD.  A peer accepts a GET_BLOCK request and never
#      replies.  block_download_timed_out() answers "yes, rotate" once the
#      configured timeout has elapsed without progress.
#
#   4. INFINITE MINE.  Mining runs for many minutes without finding a block
#      (e.g. local clock skew put block.timestamp far in the future, or the
#      candidate's prev_hash is no longer the chain tip).  mining_should_abort()
#      answers "yes, abort and rebuild" when MINING_STALE_CANDIDATE_TIMEOUT
#      seconds elapse without success.
#
# All checks are LOCAL-ONLY.  No consensus rule, validation step, or message
# format is altered.  Disabling MINING_SAFETY_ENABLED makes every check a
# no-op so legacy behaviour is preserved bit-for-bit.
# ═════════════════════════════════════════════════════════════════════════════

class MiningSafetyGuard:
    """
    Local-only safety wrapper around the mining loop.  Owned by MiningEngine.

    External dependencies are kept loose: callers pass in a "best peer height"
    callable so the guard does not need to import P2PNetwork directly.  This
    avoids circular imports and makes unit tests trivial.
    """

    def __init__(self,
                 blockchain: 'Blockchain',
                 best_peer_height_fn,
                 trigger_fast_sync_fn=None,
                 trigger_chain_sync_fn=None):
        """
        Parameters
        ──────────
        blockchain            : the local Blockchain instance.
        best_peer_height_fn   : zero-arg callable returning the highest known
                                peer chain_height, or -1 if no peers.
        trigger_fast_sync_fn  : optional callable to kick off a fast-sync
                                attempt.  Must be idempotent and non-blocking
                                (e.g. spawn a background thread).
        trigger_chain_sync_fn : optional callable to kick off a normal
                                pagination sync.  Same idempotency rules.
        """
        self.blockchain            = blockchain
        self._best_peer_height_fn  = best_peer_height_fn
        self._trigger_fast_sync_fn = trigger_fast_sync_fn
        self._trigger_chain_sync_fn= trigger_chain_sync_fn

        # Watchdog timestamps (set on each event)
        self._mine_started_at: float          = 0.0
        self._block_download_started_at: float= 0.0

    # ─────────────────────────────────────────────────────────────────────
    # 1. STALE-TIP MINING — pre-mine sync gate
    # ─────────────────────────────────────────────────────────────────────
    def is_synced(self) -> Tuple[bool, int, int]:
        """Return (is_synced, local_height, best_peer_height).

        'is_synced' means: best_peer_height <= local_height + tolerance.
        If no peers are connected (best_peer_height == -1) we treat the
        node as synced — a solo node cannot, by definition, be 'behind'
        anyone.  This preserves bootstrap behaviour where the very first
        node mines its own genesis chain.
        """
        try:
            local_height = self.blockchain.height()
        except Exception:
            local_height = -1
        try:
            best_peer = int(self._best_peer_height_fn())
        except Exception:
            best_peer = -1
        if best_peer < 0:
            return True, local_height, best_peer
        tolerance = int(Config.MINING_SYNC_HEIGHT_TOLERANCE)
        return (best_peer <= local_height + tolerance,
                local_height, best_peer)

    def pre_mine_sync_check(self, stop_event: 'threading.Event'
                             ) -> Tuple[bool, str]:
        """Block (with timed wait) until the node is sufficiently synced
        to produce a block the network will accept.

        Returns (proceed, reason).  proceed=False means the caller should
        skip this mining iteration.  reason is a short human-readable
        explanation (used for logging only).

        The wait is bounded by MINING_SYNC_MAX_WAIT seconds so a node with
        a permanently-disconnected peer (false high-height advertisement)
        eventually proceeds anyway, with a warning.  An external stop_event
        always wins — shutdown is honoured immediately.

        Behaviour when MINING_SYNC_REQUIRED_BEFORE_MINE is False: returns
        (True, 'sync gate disabled') without delay.
        """
        if not Config.MINING_SAFETY_ENABLED:
            return True, "safety disabled"
        if not Config.MINING_SYNC_REQUIRED_BEFORE_MINE:
            return True, "sync gate disabled"

        deadline = time.time() + float(Config.MINING_SYNC_MAX_WAIT)
        synced, lh, bh = self.is_synced()
        if synced:
            return True, "already synced"

        # Try to hint at a sync up-front so the caller doesn't wait silently
        gap = max(0, bh - lh)
        if (gap >= int(Config.MINING_FAR_BEHIND_THRESHOLD)
                and self._trigger_fast_sync_fn is not None):
            try:
                self._trigger_fast_sync_fn()
            except Exception:
                pass
        elif self._trigger_chain_sync_fn is not None:
            try:
                self._trigger_chain_sync_fn()
            except Exception:
                pass

        log.info(
            f"[MiningSafety] Pausing mining — local={lh}, best_peer={bh}, "
            f"gap={gap} block(s).  Waiting up to "
            f"{Config.MINING_SYNC_MAX_WAIT}s for sync to converge."
        )

        probe = float(Config.MINING_SYNC_PROBE_INTERVAL)
        # Periodically re-kick sync so that a single dropped MSG_GET_CHAIN
        # response (which is silently dropped by the peer's pagination
        # logic if a previous request is still in flight) doesn't leave
        # us waiting forever for the wait cap to expire.
        last_kick = time.time()
        while time.time() < deadline:
            if stop_event.is_set():
                return False, "stop event"
            time.sleep(probe)
            synced, lh, bh = self.is_synced()
            if synced:
                log.info(f"[MiningSafety] Sync converged — local={lh}, "
                         f"best_peer={bh}.  Resuming mining.")
                return True, "synced"
            # Re-kick every ~30 seconds while waiting.  This handles the
            # "block download stalled" scenario in the user spec — a peer
            # accepted GET_CHAIN and never replied, so we ask again
            # (potentially against a different peer the second time).
            if time.time() - last_kick >= 30.0:
                gap = max(0, bh - lh)
                if (gap >= int(Config.MINING_FAR_BEHIND_THRESHOLD)
                        and self._trigger_fast_sync_fn is not None):
                    try:
                        self._trigger_fast_sync_fn()
                    except Exception:
                        pass
                elif self._trigger_chain_sync_fn is not None:
                    try:
                        self._trigger_chain_sync_fn()
                    except Exception:
                        pass
                last_kick = time.time()

        # Wait cap exceeded — proceed anyway with a warning.  Better to mine
        # an orphan than to hang silently forever; the orphan will be
        # discovered and the chain reorganised on the next gossip wave.
        log.warning(
            f"[MiningSafety] Sync wait cap "
            f"({Config.MINING_SYNC_MAX_WAIT}s) exceeded — proceeding with "
            f"local height {lh} vs best peer {bh}.  Mined block may be "
            f"orphaned if the peer height is genuine."
        )
        return True, "wait cap exceeded"

    # ─────────────────────────────────────────────────────────────────────
    # 2. UNREACHABLE-GAP SYNC
    # ─────────────────────────────────────────────────────────────────────
    def should_trigger_fast_sync(self) -> bool:
        """Return True iff the local height is far enough behind that
        snapshot fast-sync is preferable to block-by-block pagination."""
        if not Config.MINING_SAFETY_ENABLED:
            return False
        try:
            local_height = self.blockchain.height()
        except Exception:
            return False
        try:
            best_peer = int(self._best_peer_height_fn())
        except Exception:
            return False
        if best_peer < 0:
            return False
        return (best_peer - local_height) >= int(
            Config.MINING_FAR_BEHIND_THRESHOLD)

    # ─────────────────────────────────────────────────────────────────────
    # 3. STALLED BLOCK DOWNLOAD
    # ─────────────────────────────────────────────────────────────────────
    def block_download_started(self) -> None:
        """Mark the start of a GET_BLOCK / GET_CHAIN exchange."""
        self._block_download_started_at = time.time()

    def block_download_progress(self) -> None:
        """Reset the download timer on observed progress (e.g. a chunk
        arrived).  Calling this often is fine — it is just a timestamp set."""
        self._block_download_started_at = time.time()

    def block_download_timed_out(self) -> bool:
        """Return True iff the current download exchange has stalled."""
        if not Config.MINING_SAFETY_ENABLED:
            return False
        if self._block_download_started_at <= 0.0:
            return False
        return ((time.time() - self._block_download_started_at)
                > float(Config.MINING_BLOCK_DOWNLOAD_TIMEOUT))

    # ─────────────────────────────────────────────────────────────────────
    # 4. INFINITE MINE
    # ─────────────────────────────────────────────────────────────────────
    def mining_started(self) -> None:
        self._mine_started_at = time.time()

    def mining_finished(self) -> None:
        self._mine_started_at = 0.0

    def mining_should_abort(self) -> bool:
        """Return True iff the current mining attempt has run past the
        stale-candidate timeout (≈ 4× target block time)."""
        if not Config.MINING_SAFETY_ENABLED:
            return False
        if self._mine_started_at <= 0.0:
            return False
        return ((time.time() - self._mine_started_at)
                > float(Config.MINING_STALE_CANDIDATE_TIMEOUT))

    def mining_elapsed(self) -> float:
        if self._mine_started_at <= 0.0:
            return 0.0
        return time.time() - self._mine_started_at
