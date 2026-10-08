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
"""visold.mining.engine

Original section: SECTION 14: AUTO MINING ENGINE

Defines: MiningEngine
Origin: visold_vsd_.py L39548-40211
"""

import threading
import time
from typing import List, Optional, TYPE_CHECKING

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.consensus.difficulty import DifficultyEngine
from visold.consensus.hashrate_governor import HashrateGovernor
from visold.consensus.mining_safety import MiningSafetyGuard
from visold.crypto.vrf import vrf_prove
from visold.kernel.config import Config
from visold.kernel.events import Event, EventType
from visold.kernel.logging_setup import log
from visold.kernel.messages import MSG_HASHRATE_REPORT
from visold.kernel.metrics import metrics
from visold.ledger.block import Block
from visold.mining.parallel_miner import ParallelMiner
from visold.network.p2p import P2PNetwork
from visold.storage.storage import Storage

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.state.engine import StateEngine
    from visold.wallet.wallet import Wallet


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 14: AUTO MINING ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class MiningEngine:
    def __init__(self, blockchain: Blockchain, consensus: ConsensusEngine,
                 network: P2PNetwork, wallet: 'Wallet', storage: Storage,
                 state_engine: Optional['StateEngine'] = None):
        self.blockchain   = blockchain
        self.consensus    = consensus
        self.network      = network
        self.wallet       = wallet
        self.storage      = storage
        # StateEngine reference — injected after construction to avoid circular
        # dependency.  If None (e.g. in tests), falls back to direct apply_block.
        self._state_engine: Optional['StateEngine'] = state_engine
        self._running   = False
        self._paused    = False
        self._stop_evt  = threading.Event()
        self._thread    = None
        self.hashes_done  = 0
        self.start_time   = 0.0
        self.blocks_found = 0
        self.current_candidate: Optional[Block] = None
        # Parallel mining engine — owns CPU threads and GPU context
        self._parallel = ParallelMiner()
        # ── v7.5.0-OPT Parallel Block Construction ──────────────────────────
        # Background thread continuously (re)builds the next candidate block
        # from the pre-verified mempool so that when the PoW winner lands the
        # block is ready for immediate broadcast — no "now compute state_root,
        # now assemble txs" stall at the moment we need speed most.
        #
        # The prewarm candidate is consumed in _mine_one().  If the chain tip
        # has advanced since it was built (i.e. someone else mined first) or
        # if no candidate is ready, _mine_one() falls back to the synchronous
        # build path — correctness is never predicated on the prewarm existing.
        self._prewarm_lock    = threading.Lock()
        self._prewarm_block:  Optional[Block] = None
        self._prewarm_height: int = -1       # chain tip at build time
        self._prewarm_stop    = threading.Event()
        self._prewarm_thread: Optional[threading.Thread] = None
        # Signal used to wake the prewarm loop when something material
        # changes (new tip applied, tx accepted).  Falls back to a short
        # timed wait if not signalled.
        self._prewarm_wake    = threading.Event()

        # ── v7.6.0 Hashrate Optimization ────────────────────────────────────
        # Local-only governor that translates the current difficulty into a
        # per-miner hashrate cap.  It is ALWAYS instantiated so status() and
        # log lines can read its snapshot, but the actual throttle activates
        # only when Config.HASHRATE_OPTIMIZATION_ENABLED is True.  The
        # governor is consensus-neutral — see the class header for details.
        self._hashrate_governor = HashrateGovernor()

        # Periodic broadcast of OUR actual hashrate to peers, plus the
        # mining-watchdog clock used by MiningSafetyGuard.
        self._hr_report_stop   = threading.Event()
        self._hr_report_thread: Optional[threading.Thread] = None

        # AUDIT-FIX-20 (Batch F, Finding 3): serializes start()/stop() so
        # the two can never interleave — see the comments on those methods.
        self._lifecycle_lock = threading.Lock()

        # Safety guard — its three callables stay loose-coupled with the
        # network so a None-network test mode still works.
        def _best_peer_height() -> int:
            try:
                if self.network is None or not getattr(self.network, "peers", None):
                    return -1
                # Each PeerConnection records the peer-advertised chain_height
                # in its `chain_height` attribute (set during HELLO/ACCEPT).
                # We take the maximum of all currently-connected peers.
                heights = []
                for p in list(self.network.peers.values()):
                    h = getattr(p, "chain_height", -1)
                    try:
                        heights.append(int(h))
                    except (TypeError, ValueError):
                        continue
                return max(heights) if heights else -1
            except Exception:
                return -1

        def _kick_fast_sync() -> None:
            try:
                if self.network is None:
                    return
                # Fire a non-blocking attempt against the first peer that has
                # snapshot capability.  If none, the call is a silent no-op.
                for p in list(self.network.peers.values()):
                    caps = getattr(p, "capabilities", None) or []
                    if "snapshots" in caps or "snapshot" in caps:
                        threading.Thread(
                            target=lambda peer=p: self.network._fast_sync_from_peer(peer)
                                if hasattr(self.network, "_fast_sync_from_peer") else None,
                            daemon=True,
                            name="mine-safety-fastsync"
                        ).start()
                        return
            except Exception:
                pass

        def _kick_chain_sync() -> None:
            try:
                if self.network is None:
                    return
                # Re-issue MSG_GET_CHAIN against the highest-known peer.  This
                # is the same path _auto_sync_on_connect uses; we just
                # nudge it to run again now.
                best_peer = None
                best_h    = -1
                for p in list(self.network.peers.values()):
                    h = getattr(p, "chain_height", -1)
                    try:
                        h = int(h)
                    except (TypeError, ValueError):
                        h = -1
                    if h > best_h and getattr(p, "connected", False):
                        best_h    = h
                        best_peer = p
                if best_peer is None:
                    return
                cur_h = self.blockchain.height()
                from_idx = max(0, cur_h + 1) if cur_h > 0 else 0
                try:
                    self.network._sync_request(
                        best_peer, from_idx, from_idx + 199,
                        kind="safety-resync", force=False)
                except Exception:
                    pass
            except Exception:
                pass

        self._safety_guard = MiningSafetyGuard(
            blockchain            = self.blockchain,
            best_peer_height_fn   = _best_peer_height,
            trigger_fast_sync_fn  = _kick_fast_sync,
            trigger_chain_sync_fn = _kick_chain_sync,
        )

    def get_hashrate_governor(self) -> 'HashrateGovernor':
        """Public accessor — used by P2PNetwork's MSG_HASHRATE_REPORT handler."""
        return self._hashrate_governor

    def set_state_engine(self, engine: 'StateEngine'):
        """Inject StateEngine after both objects are created."""
        self._state_engine = engine

    def start(self):
        # AUDIT-FIX-20 (Batch F, Finding 3): start()/stop() used to mutate
        # self._running plus every per-subsystem Event/Thread field with no
        # lock between them.  A concurrent start()+stop() could interleave
        # so that stop()'s .set() on a stop-flag landed after start()'s
        # .clear() of that same flag but before the freshly-created
        # thread's first check of it — leaving that thread dead on arrival
        # while self._running still read True and start() had already
        # returned "Mining started" with no error surfaced (a silent
        # partial-failure state).  Serializing the two full method bodies
        # under one lock makes that interleaving impossible; as a side
        # effect the "Already mining" guard below is now also atomic
        # against a concurrent start().
        with self._lifecycle_lock:
            role = self.storage.get_role(self.wallet.address)
            if role and role["role"] == "investor":
                return False, "Investors cannot mine"
            if self._running:
                return False, "Already mining"
            self._running = True
            self._paused  = False
            self._stop_evt.clear()
            self._thread  = threading.Thread(target=self._mine_loop, daemon=True)
            self._thread.start()
            # ── v7.5.0-OPT Start the parallel candidate-builder thread ──────
            self._prewarm_stop.clear()
            self._prewarm_wake.clear()
            self._prewarm_thread = threading.Thread(
                target=self._prewarm_loop, daemon=True, name="mine-prewarm")
            self._prewarm_thread.start()
            # ── v7.6.0 Start the hashrate-report broadcast thread ──────────
            self._hr_report_stop.clear()
            self._hr_report_thread = threading.Thread(
                target=self._hashrate_report_loop, daemon=True,
                name="mine-hr-report")
            self._hr_report_thread.start()
            self.start_time = time.time()
            log.info("Auto mining started (with parallel candidate builder + "
                     "hashrate governor)")
            return True, "Mining started"

    def stop(self):
        # AUDIT-FIX-20 (Batch F, Finding 3): see start() above.
        with self._lifecycle_lock:
            self._running = False
            self._stop_evt.set()
            # ── v7.5.0-OPT Stop prewarm thread first ─────────────────────────
            self._prewarm_stop.set()
            self._prewarm_wake.set()   # unblock any wait()
            if self._prewarm_thread:
                self._prewarm_thread.join(timeout=3)
            # ── v7.6.0 Stop hashrate-report thread ──────────────────────────
            self._hr_report_stop.set()
            if self._hr_report_thread:
                self._hr_report_thread.join(timeout=3)
            if self._thread:
                self._thread.join(timeout=5)
            log.info("Mining stopped")
            return True, "Mining stopped"

    # ── v7.6.0 Hashrate-report broadcast loop ────────────────────────────
    def _hashrate_report_loop(self):
        """Periodically broadcast our actual (unthrottled) hashrate to peers
        so every node's HashrateGovernor has a fresh view of the network's
        actual-hashrate distribution.

        v7.6.1 — this loop NO LONGER overwrites the governor's measurement.
        The per-block EMA in _mine_one() is the canonical value; this loop
        only READS it for broadcasting.  The previous implementation
        recomputed (total_hashes / total_elapsed) on every cycle and
        clobbered the EMA, defeating the smoothing.

        The broadcast is metadata only — it never affects block validation
        or consensus.  If the network reference is None (test mode) the
        loop is a no-op.
        """
        interval = max(5.0, float(Config.HASHRATE_REPORT_INTERVAL))
        while not self._hr_report_stop.is_set() and self._running:
            try:
                # Read the EMA-smoothed rate (already maintained by _mine_one).
                hr = self._hashrate_governor.get_local_actual_hashrate()

                # Broadcast to peers if we have any AND we have a measurement.
                if (self.network is not None
                        and getattr(self.network, "peers", None)
                        and not self._paused
                        and hr > 0.0):
                    msg = {
                        "type":     MSG_HASHRATE_REPORT,
                        "node_id":  getattr(self.network, "node_id", ""),
                        "hashrate": float(hr),
                        "ts":       int(time.time()),
                    }
                    # Send to all currently-connected peers (point-to-point).
                    # We do NOT use the gossip flooder because hashrate
                    # reports are small, fresh, and self-evicting — there is
                    # no benefit to amplification, and gossip would let a
                    # single misbehaving peer rebroadcast a stale value.
                    for p in list(self.network.peers.values()):
                        try:
                            if getattr(p, "connected", False):
                                p.send(msg)
                        except Exception:
                            continue
            except Exception as _e:
                log.debug(f"[HR-Report] loop error: {_e}")
            # Wait, but wake immediately on stop.
            self._hr_report_stop.wait(timeout=interval)

    def pause(self):
        self._paused = True
        return True, "Mining paused"

    def resume(self):
        self._paused = False
        return True, "Mining resumed"

    def status(self) -> dict:
        elapsed = time.time() - self.start_time if self.start_time else 1
        session_mean_hr = self.hashes_done / elapsed if elapsed > 0 else 0
        self.network.hashrate = session_mean_hr
        binfo = self._parallel.backend_info()
        gov_snapshot = self._hashrate_governor.status_snapshot()
        # ── v7.6.2 The dashboard "Hashrate" field now reports the EMA so it
        # is consistent with the Hashrate Optimization panel below it.  The
        # session mean (hashes_done / total_elapsed) is preserved as a
        # separate field for operators who want to see total work done.
        ema_hr = gov_snapshot['local_actual_hps']
        return {
            "running":       self._running,
            "paused":        self._paused,
            "hashrate":      f"{ema_hr:.1f} H/s",
            "session_mean_hashrate": f"{session_mean_hr:.1f} H/s",
            "blocks_found":  self.blocks_found,
            "difficulty":    self.blockchain.get_difficulty(),
            "chain_height":  self.blockchain.height(),
            # ── Parallel mining info ───────────────────────────────────────────
            "backend":       binfo["backend"],
            "cpu_threads":   binfo["cpu_threads"],
            "gpu_enabled":   binfo["gpu_enabled"],
            "gpu_device":    binfo["gpu_device"],
            "gpu_batch":     binfo["gpu_batch"],
            "cuda_avail":    binfo["cuda_avail"],
            "opencl_avail":  binfo["opencl_avail"],
            # ── v7.6.0 Hashrate optimization governor ───────────────────────────
            "actual_hashrate":     f"{gov_snapshot['local_actual_hps']:.1f} H/s",
            "optimized_hashrate":  (f"{gov_snapshot['allowed_local_hps']:.1f} H/s"
                                    if gov_snapshot['allowed_local_hps'] != float('inf')
                                    else "unlimited"),
            "required_network_hashrate": f"{gov_snapshot['required_total_hps']:.1f} H/s",
            "live_peer_hr_reports":      gov_snapshot['live_peer_reports'],
        }

    def _mine_loop(self):
        while self._running:
            if self._paused:
                time.sleep(1)
                continue
            try:
                self._mine_one()
            except Exception as e:
                log.error(f"Mining error: {e}")
                time.sleep(2)

    # ── v7.5.0-OPT Parallel Block Construction ────────────────────────────
    def _prewarm_loop(self):
        """Background thread that keeps a ready-to-mine candidate block warm.

        Rebuild policy:
          • Rebuild whenever the chain tip advances (prev candidate is stale
            — prev_hash, height, state_root, VRF all depend on the tip).
          • Rebuild whenever _prewarm_wake is signalled (e.g. after a sizable
            batch of new mempool txs has arrived and somebody calls
            wake_prewarm()).
          • Otherwise refresh once every _PREWARM_IDLE_SECS so the mempool
            content actually in the candidate stays current.

        Correctness: this loop NEVER writes to the chain.  It only calls
        ConsensusEngine.build_candidate_block(), which is a pure builder
        (takes blockchain._lock only for its internal dry_run_state_root,
        which is itself non-mutating).  The candidate it produces is stored
        into _prewarm_block under _prewarm_lock.
        """
        _PREWARM_IDLE_SECS   = 5.0
        _PREWARM_ERR_BACKOFF = 2.0
        while not self._prewarm_stop.is_set():
            if self._paused:
                # Don't waste CPU prewarming while paused.
                self._prewarm_wake.wait(timeout=1.0)
                self._prewarm_wake.clear()
                continue
            try:
                # Snapshot the current tip first so we can compare against
                # what build_candidate_block actually produces.
                tip = self.blockchain.latest_block()
                tip_height = tip.index if tip is not None else -1

                # Build the VRF proof bound to the CURRENT tip hash.  If the
                # tip advances by the time we consume this candidate, the
                # prewarm is stale and _consume_prewarm() discards it.
                alpha = (tip.block_hash if tip is not None else "genesis").encode()
                vrf_proof, vrf_beta = vrf_prove(self.wallet.priv, alpha)
                candidate = self.consensus.build_candidate_block(
                    self.wallet.address, vrf_proof.hex(), vrf_beta.hex())

                # Store only if it still matches the observed tip height + 1.
                # (A race with apply_block could have advanced the tip while
                # we were building; that's fine — we just won't publish the
                # stale candidate.)
                with self._prewarm_lock:
                    self._prewarm_block  = candidate
                    self._prewarm_height = tip_height
            except Exception as _pe:
                log.debug(f"prewarm build failed: {_pe}")
                # Back off briefly before retry — avoid hot-looping on a
                # persistent error (e.g. DB temporarily locked).
                self._prewarm_stop.wait(timeout=_PREWARM_ERR_BACKOFF)
                continue

            # Wait either for a wake signal or the idle refresh interval.
            self._prewarm_wake.wait(timeout=_PREWARM_IDLE_SECS)
            self._prewarm_wake.clear()

    def wake_prewarm(self) -> None:
        """Public hook — signal that the prewarm should rebuild soon.

        Call this after events that materially change what the next block
        should contain: chain tip advanced (primary trigger), large mempool
        influx, etc.  No-op if the prewarm thread is not running (safe for
        tests, node shutdown, investor nodes that never mine).
        """
        try:
            self._prewarm_wake.set()
        except Exception:
            pass

    def _consume_prewarm(self) -> Optional[Block]:
        """Pop the currently-warm candidate IF it is still valid against the
        live chain tip; otherwise return None so _mine_one() falls back to
        a synchronous build.

        Validity rule: the prewarm's prev_hash must equal the CURRENT tip
        hash, and its height must be tip+1.  Any mismatch means someone
        mined (or synced) between build and consume — the candidate's
        state_root / VRF / tx selection is tied to an old tip and must be
        thrown away.
        """
        tip = self.blockchain.latest_block()
        tip_hash   = tip.block_hash if tip is not None else "0" * 64
        tip_height = tip.index if tip is not None else -1
        with self._prewarm_lock:
            blk = self._prewarm_block
            # Consume exactly once — clear the slot so a second call must
            # wait for the next prewarm cycle.
            self._prewarm_block = None
        if blk is None:
            return None
        if blk.prev_hash != tip_hash:
            return None
        if blk.index != tip_height + 1:
            return None
        # The prewarm is valid.  Refresh its timestamp to "now" bounded below
        # by the MTP+1 rule (build_candidate_block set it; we just advance it
        # if wall-clock has moved forward since then).  We do NOT touch any
        # other field — state_root, merkle_root, vrf, tx list are all fixed.
        try:
            now_ts = int(time.time())
            if now_ts > blk.timestamp:
                blk.timestamp = now_ts
                # nonce is reset to 0 so the PoW starts fresh on the new
                # header (timestamp change invalidates any partial work).
                blk.nonce = 0
        except Exception:
            pass
        return blk

    def _mine_one(self):
        # ── v7.6.0 Pre-mine sync gate ─────────────────────────────────────
        # Refuse to mine on a stale tip — that would just produce orphaned
        # blocks the network rejects.  Wait until we are caught up to the
        # best peer (within tolerance), or until the absolute wait cap
        # elapses.  If MINING_SAFETY_ENABLED is False this is a no-op.
        try:
            proceed, why = self._safety_guard.pre_mine_sync_check(self._stop_evt)
            if not proceed:
                # Stop event fired during the wait — exit cleanly.
                return
            # If pre_mine_sync_check actually slept (i.e. we were behind and
            # waited for sync), bail out of this iteration so the outer
            # _mine_loop can re-check `_running` / `_paused` flags promptly
            # and the prewarm thread produces a fresh candidate against the
            # (now-advanced) tip.  When proceed=True with why="wait cap
            # exceeded" we still mine — sync didn't converge, but the
            # operator has accepted the orphan-risk via the wait cap.
            if why == "synced":
                # We waited and converged — the prewarm cache is stale
                # (built against an old tip), so kick the prewarm builder.
                self.wake_prewarm()
                return
        except Exception as _se:
            log.debug(f"[MiningSafety] pre-check error: {_se}")
            # Non-fatal — fall through to mining.

        # ── v7.5.0-OPT: try the prewarmed candidate first ─────────────────
        block = self._consume_prewarm()
        if block is None:
            latest = self.blockchain.latest_block()
            alpha  = (latest.block_hash if latest else "genesis").encode()
            vrf_proof, vrf_beta = vrf_prove(self.wallet.priv, alpha)
            vrf_proof_hex = vrf_proof.hex()
            vrf_beta_hex  = vrf_beta.hex()
            block = self.consensus.build_candidate_block(
                self.wallet.address, vrf_proof_hex, vrf_beta_hex)
        self.current_candidate = block

        # ── v7.6.0 Compute hashrate cap from the governor ─────────────────
        # The cap is recomputed for every block because difficulty (and the
        # required network hashrate that follows from it) can change with
        # each block.  When optimization is disabled the governor returns
        # +inf and we pass max_hps=0 so the workers run unthrottled.
        try:
            allowed_hps, req_total, _gov_dbg = (
                self._hashrate_governor.advise(block.difficulty))
        except Exception as _ge:
            log.debug(f"[HashrateGovernor] advise error: {_ge}")
            allowed_hps = float("inf")
            req_total   = 0.0

        if allowed_hps == float("inf") or allowed_hps <= 0.0:
            mine_max_hps = 0.0   # unlimited
        else:
            mine_max_hps = float(allowed_hps)

        start = time.time()
        # ── v7.6.0 Begin watchdog clock ───────────────────────────────────
        try:
            self._safety_guard.mining_started()
        except Exception:
            pass

        # ── v7.6.0 Watchdog thread: aborts mining if it runs too long ────
        # When MINING_STALE_CANDIDATE_TIMEOUT seconds have elapsed without
        # finding a block, set the local stop event so the workers exit;
        # _mine_one then returns and the outer _mine_loop rebuilds against
        # the (possibly advanced) chain tip.  This protects against:
        #   • Stale candidate (someone else mined; our prev_hash is wrong)
        #   • Local clock skew that put block.timestamp in the future
        #   • Unexpected difficulty divergence
        watchdog_local_stop = threading.Event()
        watchdog_fired      = [False]

        def _mining_watchdog():
            poll = 1.0
            while not watchdog_local_stop.is_set():
                if self._stop_evt.is_set():
                    return
                if self._safety_guard.mining_should_abort():
                    watchdog_fired[0] = True
                    elapsed_w = self._safety_guard.mining_elapsed()
                    log.warning(
                        f"[MiningSafety] Mining attempt has run "
                        f"{elapsed_w:.0f}s (>{Config.MINING_STALE_CANDIDATE_TIMEOUT}s) "
                        f"without solving — aborting and rebuilding candidate "
                        f"against the latest tip.")
                    self._stop_evt.set()
                    # The mining loop will re-check _running and rebuild.
                    return
                if watchdog_local_stop.wait(timeout=poll):
                    return

        wd_thread = threading.Thread(
            target=_mining_watchdog, daemon=True, name="mine-watchdog")
        wd_thread.start()

        # ── Parallel mine (CPU threads or GPU) — now possibly throttled ──
        try:
            success = self._parallel.mine(
                block, stop_event=self._stop_evt, max_hps=mine_max_hps)
        finally:
            watchdog_local_stop.set()
            wd_thread.join(timeout=2.0)
            try:
                self._safety_guard.mining_finished()
            except Exception:
                pass

        elapsed = time.time() - start

        # If the watchdog fired we treat this as an aborted attempt.  Clear
        # the stop event so the outer loop can immediately try again on a
        # fresh candidate — but only if shutdown was NOT requested.
        if watchdog_fired[0] and self._running:
            self._stop_evt.clear()
            self.wake_prewarm()
            return

        # hashes_done ≈ winning nonce (threads cover interleaved ranges,
        # so the winner's nonce value ≈ total hashes attempted).
        if success:
            self.hashes_done += block.nonce + 1

        # ── v7.6.1 Refresh local actual hashrate using a sliding window ──
        # Previously we used (total_hashes / total_elapsed) which produces
        # a session-mean that includes early bootstrap blocks where the
        # throttle was inactive.  That mean stays elevated for many blocks
        # and confuses the operator (panel shows Actual >> Optimized even
        # though the recent rate equals Optimized).
        #
        # The sliding window measures only the most recent block, which
        # is closer to the live rate the throttle is actually enforcing.
        # Combined with a 5-block exponential smoothing, it converges to
        # the true throttled rate within a few blocks while still being
        # noise-tolerant.
        try:
            block_hashes  = float(block.nonce + 1) if success else 0.0
            block_elapsed = max(elapsed, 1e-3)
            block_hr      = block_hashes / block_elapsed if success else 0.0
            if block_hr > 0.0:
                # 5-block EMA: weight = 1/5 for new, 4/5 for old
                prev_hr = self._hashrate_governor.get_local_actual_hashrate()
                if prev_hr > 0.0:
                    smoothed = 0.2 * block_hr + 0.8 * prev_hr
                else:
                    smoothed = block_hr
                self._hashrate_governor.update_local_actual_hashrate(smoothed)
        except Exception:
            pass

        if not success:
            return

        # ── Final MTP safety check before submission ──────────────────────────
        # mine() preserves the MTP-safe timestamp set by build_candidate_block
        # (it only advances, never regresses).  This final check is a belt-and-
        # suspenders guard: if for any reason block.timestamp still equals the
        # MTP (e.g. edge case at exactly midnight second boundary), we advance
        # it by one second and re-mine so the new hash is also PoW-valid.
        current_height = block.index
        recent_ts: List[int] = []
        for _i in range(max(0, current_height - Config.DIFF_MTP_WINDOW),
                        current_height):
            _blk = self.blockchain.storage.get_block(_i)
            if _blk is not None:
                recent_ts.append(_blk.timestamp)
        if recent_ts:
            mtp = DifficultyEngine.compute_mtp(recent_ts)
            if block.timestamp <= mtp:
                block.timestamp = mtp + 1
                block.nonce     = 0
                # Re-mine without throttle for this small adjustment — the
                # MTP fix-up usually finds a new nonce in microseconds and
                # we don't want the throttle to delay an already-mined block.
                if not self._parallel.mine(block, stop_event=self._stop_evt,
                                            max_hps=0.0):
                    return   # aborted — do not submit

        # SECURITY: Seal the block after all mining and MTP adjustments are
        # complete.  This locks the consensus-critical fields (transactions,
        # merkle_root, block_hash, etc.) so they cannot be tampered with
        # between mining and submission to the StateEngine / network.
        if not block._sealed:
            block.seal()

        # ── v7.6.2 Per-block throttle diagnostic ─────────────────────────
        # Print the measured rate alongside the cap so a throttle leak is
        # immediately visible in the log.  measured = nonce / elapsed; cap
        # = mine_max_hps.  In a healthy throttle:
        #   measured ≈ cap × (1 ± 0.15)    (15% jitter is normal)
        # If measured >> cap consistently, the throttle is leaking.
        try:
            block_measured_hr = (float(block.nonce + 1) / max(elapsed, 1e-3))
        except Exception:
            block_measured_hr = 0.0
        cap_str = ('unlimited' if mine_max_hps == 0.0 else f'{mine_max_hps:.0f}')
        if mine_max_hps > 0.0 and block_measured_hr > 0.0:
            ratio = block_measured_hr / mine_max_hps
            ratio_str = f"  measured/cap={ratio:.2f}x"
        else:
            ratio_str = ""

        log.info(
            f"Block #{block.index} mined!  hash={block.block_hash[:16]}…  "
            f"nonce={block.nonce}  backend={self._parallel._backend.upper()}  "
            f"time={elapsed:.1f}s  "
            f"measured={block_measured_hr:.0f}H/s  cap={cap_str}H/s"
            f"{ratio_str}"
        )

        # ── Post MINE_RESULT to StateEngine (single-writer principle) ──────────
        if self._state_engine is not None:
            evt = Event(
                EventType.MINE_RESULT,
                {"block": block, "consensus": self.consensus},
            )
            ok, msg = self._state_engine.post_sync(evt, timeout=15.0)
            # BELT-AND-SUSPENDERS: if StateEngine accepted the block but
            # broadcast did not fire for any reason (race, swallowed exc),
            # force a second broadcast here. Receivers dedup via _seen_msgs.
            if ok and self.network is not None:
                try:
                    self.network.broadcast_block(block)
                except Exception as _bbe:
                    log.error(f"[BROADCAST-BACKUP] failed for #{block.index}: {_bbe}")
        else:
            ok, msg = self.blockchain.apply_block(block)
            if ok:
                self.network.broadcast_block(block)
                self.consensus.validate_and_finalize(block)

        if ok:
            self.blocks_found += 1
            hr = self.hashes_done / max(time.time() - self.start_time, 1)
            metrics.set_gauge("hashrate", hr)
            # ── v7.5.0-OPT Wake the prewarm thread ──────────────────────
            # The tip just advanced — the currently-warm candidate (if any)
            # is now stale.  Signal the prewarm loop to rebuild against the
            # new tip immediately so we're ready for the next block.
            self.wake_prewarm()
        else:
            log.warning(f"Block apply failed: {msg}")
