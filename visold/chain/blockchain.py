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
"""visold.chain.blockchain

Original section: END SECTION 7E — Pass 4 (sequencer + submission).  Next passes add the

Defines: Blockchain
Origin: visold_vsd_.py L25780-30470
"""

import hashlib
import json
import math
import os
import threading
import time
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING, Tuple

from visold.consensus.difficulty import DifficultyEngine
from visold.crypto.ecc import ecdsa_verify, pub_from_hex, pub_to_address, sig_from_hex
from visold.crypto.hashing import sha256
from visold.economics.monitor import EconomicMonitor
from visold.governance.engine import GovernanceEngine
from visold.governance.versioning import ProtocolVersionManager
from visold.kernel.clock import network_clock
from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics
from visold.kernel.units import bft_threshold_met, from_satoshi, gas_fee_to_sat, to_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.rollup.batches import RollupSubmission
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, L2_WITHDRAW_ADDRESS, Layer2State
from visold.rollup.ledger_sync import sync_local_ledger
from visold.state.batch_proxy import _StorageBatchProxy
from visold.storage.rolling_window_pruner import RollingWindowPruner
from visold.storage.snapshot import StateSnapshotEngine
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.event_index import ContractEventIndex
from visold.vm.naming import (
    normalize_contract_name, validate_contract_name, derive_contract_address)
from visold.vm.precompiles import VVMPrecompiles

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.consensus.rate_defection import RateDefectionAuditor
    from visold.network.p2p import P2PNetwork


# ═════════════════════════════════════════════════════════════════════════════
# END SECTION 7E — Pass 4 (sequencer + submission).  Next passes add the
# verifier precompile hookup, wallet L2 signing helpers, P2P gossip path,
# and the reorg handler.
# ═════════════════════════════════════════════════════════════════════════════


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8: BLOCKCHAIN (CHAIN MANAGEMENT + REORG + HYBRID DIFFICULTY)
# ─────────────────────────────────────────────────────────────────────────────
class Blockchain:
    def __init__(self, storage: Storage):
        self.storage        = storage
        self.mempool        = Mempool(storage)
        self._lock          = threading.RLock()
        # In-memory guard closes the small window between a successful
        # apply_block() return and the caller's durable block_apply marker.
        self._applied_block_hashes: set[str] = set()
        self._genesis_hash  = None
        # AUDIT-FIX (Batch D): incrementally-tracked replacement for the old
        # bounded finality-fence scan in reorg()/accept_chain(). See
        # _maybe_finalize_by_bft/_maybe_finalize_by_depth/add_validator_sig,
        # which update this whenever they set block.finalized = True, and
        # _init_highest_finalized_height() below, which seeds it correctly
        # for a node restarting against an existing chain.
        self._highest_finalized_height = -1
        self._proto_mgr     = ProtocolVersionManager(storage)
        self._eco_mon       = EconomicMonitor(storage)
        # GovernanceEngine wraps _proto_mgr and drives the upgrade lifecycle
        self._governance    = GovernanceEngine(storage, self._proto_mgr)
        # SC-FIX-8: Event index for O(1) log queries by contract/topic
        self._event_index   = ContractEventIndex(storage)
        # SC-IMPROVEMENT-2: VVMEngine cached for gas estimation
        self._vvm_engine    = VVMEngine(storage)
        # v7.4.0: Rolling window pruner and state snapshot engine
        self._rolling_pruner   = RollingWindowPruner(storage)
        self._snapshot_engine  = StateSnapshotEngine(storage)
        # Injected by VisoldNode after construction
        self._slash_evidence: Optional[Any] = None
        # ── v7.7.0 Rate defection auditor ────────────────────────────────────
        # Optional; injected by VisoldNode after construction.  When None,
        # _maybe_run_rate_audit is a no-op (light/non-mining nodes).
        self._rate_auditor: Optional['RateDefectionAuditor'] = None
        # v7.5.0-OPT Network-Aware Block Sizing — injected after P2PNetwork is
        # constructed via set_network().  Optional; when None, block sizing
        # falls back to the original mempool-depth-only policy.
        self._network: Optional['P2PNetwork'] = None
        # ── v7.5.0-OPT LAYER-2 ROLLUP STATE ─────────────────────────────
        # Owned here so that apply_block's TYPE_ROLLUP branch can consult
        # and mutate the L2 tree under the same lock that protects L1
        # state transitions.  The Sequencer (if running) shares this same
        # Layer2State instance via Node.start().  Safe to construct eagerly
        # — Layer2State persists via the same Storage object.
        self.layer2 = Layer2State(storage)
        # MEMPOOL-1 FIX: wire layer2 into mempool so it can pre-validate
        # TYPE_ROLLUP submissions against the current L2 root and reject
        # stale rollups at admission instead of at apply-block time.
        # Without this, a stale rollup would propagate through gossip,
        # get included in a block by a miner, then fail _apply_rollup_tx
        # — rejecting the ENTIRE block (and every other user's tx in it)
        # and wasting the miner's PoW.  This is a free DoS vector: anyone
        # who tracks the L2 root can submit a freshly-stale rollup.
        self.mempool.set_layer2_ref(self.layer2)
        # v7.0.1.2 — Bug 1 fix: retry genesis save if it did not persist
        # (e.g. transient SQLite lock, KV write error, disk full on first
        # boot).  Without this retry the node boots with chain_height() == -1
        # which surfaces as "Height: -1" in the dashboard and breaks every
        # downstream sync path that assumes height >= 0.
        if self.storage.chain_height() < 0:
            self._create_genesis()
            if self.storage.chain_height() < 0:
                log.warning("Genesis save did not persist on first attempt; "
                            "retrying...")
                self._create_genesis()
                if self.storage.chain_height() < 0:
                    log.error("Genesis could not be persisted after 2 "
                              "attempts — storage backend may be read-only "
                              "or corrupted.  Node will continue and attempt "
                              "to self-heal on first height() call.")
        else:
            self._maybe_migrate_difficulty_state()
            self._init_highest_finalized_height()

    def _init_highest_finalized_height(self) -> None:
        """AUDIT-FIX (Batch D): one-time startup scan seeding
        self._highest_finalized_height for a node restarting against an
        existing chain, where blocks may already be finalized from before
        this process started. Scans from the current tip downward and stops
        at the first (i.e. highest) block found with finalized=True — this
        is the same direction/stopping rule the old bounded fence scan used,
        just unbounded and run only once at startup rather than on every
        reorg attempt, so the O(n) cost here is a one-time startup cost, not
        a per-reorg one. Safe to call on a fresh/empty chain (loop body
        never executes when height() < 0).
        """
        try:
            h = self.height()
            for idx in range(h, -1, -1):
                blk = self.storage.get_block(idx)
                if blk and blk.finalized:
                    self._highest_finalized_height = idx
                    return
        except Exception as exc:
            log.warning(
                "_init_highest_finalized_height scan failed: %s — "
                "starting from -1 (safe default: fence will only "
                "protect blocks finalized from this point forward "
                "until the next full rescan)", exc)

    def set_network(self, network: 'P2PNetwork') -> None:
        """Inject the P2PNetwork reference after both objects are created.

        v7.5.0-OPT — solely used by get_dynamic_block_size() to consult the
        LatencyTracker.  Never referenced by consensus rules; a None value
        (network not yet set) degrades safely back to the mempool-only
        sizing policy.
        """
        self._network = network

    # ── v7.7.0 Rate Defection Audit Hook ─────────────────────────────────────
    def _maybe_run_rate_audit(self, block_height: int) -> None:
        """Trigger one audit cycle if all preconditions are met.

        This is called from the apply_block success path on every node.  It
        is idempotent and self-rate-limiting:
          • The auditor only runs at cadence boundaries (every N blocks).
          • The auditor needs a non-empty cap registry; without one it is
            a no-op (light/non-mining nodes).
          • Failures are logged at debug level only — auditing must never
            fail a block apply.

        On flag, the auditor returns evidence packets which we broadcast
        to the network via the P2PNetwork instance (if attached).  Each
        packet is independently verified by every receiving node.
        """
        auditor = getattr(self, "_rate_auditor", None)
        if auditor is None:
            return   # No auditor wired (light node or early init) — no-op

        # Build the cap registry from the network's hashrate governor view.
        # The governor lives on the mining engine; we reach it via the
        # network if available, otherwise skip.
        cap_registry: Dict[str, float] = {}
        try:
            net = self._network
            if net is None:
                return
            mining_engine = getattr(net, "_mining_engine_ref", None)
            if mining_engine is None:
                return   # Non-mining node has no governor view; skip audit.
            gov = mining_engine.get_hashrate_governor()
            if gov is None:
                return
            with gov._lock:
                # Snapshot the registry under lock — values are floats.
                for pid, (rate, _ts) in gov._peer_rates.items():
                    if rate > 0:
                        cap_registry[pid] = float(rate)
                # Include our own measured rate keyed by our node_id.
                if gov._local_actual_hashrate > 0:
                    self_id = getattr(net, "node_id", "self")
                    cap_registry[self_id] = float(gov._local_actual_hashrate)
        except Exception as exc:
            log.debug(f"[RateAudit] Failed to build registry: {exc}")
            return

        if not cap_registry:
            return   # Nothing to audit yet

        # Run the audit cycle.  Returns a list of evidence packets to
        # broadcast (possibly empty).
        try:
            evidence_list = auditor.run_audit_cycle(block_height, cap_registry)
        except Exception as exc:
            log.debug(f"[RateAudit] cycle exception: {exc}")
            return

        if not evidence_list:
            return

        # Broadcast each evidence packet via the network.
        net = self._network
        if net is None:
            return
        for ev in evidence_list:
            try:
                # Use the broadcast helper if available; otherwise iterate
                # peers manually.  We treat this as a normal-priority gossip
                # message — not consensus-critical (light nodes ignore it),
                # but should reach all mining nodes promptly.
                if hasattr(net, "broadcast_message"):
                    net.broadcast_message(ev)
                elif hasattr(net, "broadcast"):
                    net.broadcast(ev)
                else:
                    for p in list(getattr(net, "peers", {}).values()):
                        try:
                            if getattr(p, "connected", False):
                                p.send(ev)
                        except Exception:
                            continue
                log.info(
                    f"[RateAudit] Broadcast evidence: miner={ev['miner'][:12]}… "
                    f"window=[{ev['window_start']}..{ev['window_end']}] "
                    f"ratio={ev['ratio']:.2f}")
            except Exception as exc:
                log.debug(f"[RateAudit] Broadcast failed: {exc}")

    # ── Genesis ───────────────────────────────────────────────────────────────
    def _create_genesis(self):
        # =====================================================================
        # DETERMINISTIC GENESIS CONSTRUCTION
        # ---------------------------------------------------------------------
        # CRITICAL CONSENSUS RULE:
        # Every node on this chain — independent of machine, OS, locale, or
        # wall-clock time — MUST construct a byte-for-byte identical genesis
        # block. Any divergence produces a different block_hash, which causes
        # validate_block() to reject foreign genesis blocks as "wrong-chain"
        # and the two nodes will never sync.
        #
        # PREVIOUS BUG (fixed in this method):
        #   Transaction.coinbase() does not accept a timestamp argument, so it
        #   fell back to `int(time.time())` inside Transaction.__init__. The
        #   genesis tx was therefore stamped with each node's first-launch
        #   wall-clock second, producing a different tx_id, a different
        #   merkle_root, and a different genesis block_hash on every machine.
        #
        # FIX:
        #   Build the genesis transaction by calling Transaction(...) directly
        #   with EVERY field pinned to a Config constant — including the
        #   timestamp and expiry. No call paths inside Transaction.__init__
        #   may now read the system clock.
        # =====================================================================

        genesis_tx = Transaction(
            sender    = "COINBASE",                  # required so __init__ keeps expiry=0
            receiver  = Config.GENESIS_MINER,
            amount    = Config.GENESIS_TX_AMOUNT,
            fee       = 0.0,
            timestamp = Config.GENESIS_TIMESTAMP,    # ← was the missing piece
            memo      = Config.GENESIS_TX_MEMO,
            nonce     = Config.GENESIS_TX_NONCE,
            expiry    = Config.GENESIS_TX_EXPIRY,
        )
        # Patch sender to the symbolic genesis sender. We do this AFTER
        # construction (not via the constructor) for two reasons:
        #   1. The expiry-default branch in __init__ only triggers when
        #      sender == "COINBASE", so we need that during construction.
        #   2. Every node performs the exact same patch, so the resulting
        #      tx object is still byte-for-byte identical across the network.
        # We must recompute tx_id afterwards because _compute_id() hashes the
        # sender field.
        genesis_tx.sender = Config.GENESIS_TX_SENDER
        genesis_tx.tx_id  = genesis_tx._compute_id()

        # ── Build the genesis block from pinned constants ────────────────────
        genesis = Block(
            index         = 0,
            prev_hash     = "0" * 64,
            transactions  = [genesis_tx],
            miner_address = Config.GENESIS_MINER,
            difficulty    = Config.INITIAL_DIFFICULTY,
            timestamp     = Config.GENESIS_TIMESTAMP,
            nonce         = Config.GENESIS_NONCE,
        )

        # SECURITY: finalize and seal genesis before storing.
        # seal() computes the final merkle_root and locks all consensus-
        # critical fields so genesis cannot be modified after creation.
        genesis.finalized = True
        # AUDIT-FIX (Batch D): keep the incremental finality-fence tracker
        # in sync (see _highest_finalized_height in __init__).
        self._highest_finalized_height = max(self._highest_finalized_height, 0)
        genesis.seal()

        # ── Pinned-hash verification ─────────────────────────────────────────
        # If an operator has pinned the canonical genesis hash in
        # Config.GENESIS_HASH_PIN, refuse to start when the locally-computed
        # hash diverges. This catches accidental code changes (e.g. someone
        # tweaks GENESIS_TX_MEMO) BEFORE they are persisted to disk and
        # silently fork the network.
        pinned = (Config.GENESIS_HASH_PIN or "").strip().lower()
        if pinned and pinned != genesis.block_hash.lower():
            raise RuntimeError(
                "FATAL: Computed genesis hash does not match Config.GENESIS_HASH_PIN.\n"
                f"  computed = {genesis.block_hash}\n"
                f"  pinned   = {pinned}\n"
                "Refusing to start to avoid silently forking the network. "
                "Either revert the genesis-affecting change or update "
                "Config.GENESIS_HASH_PIN intentionally."
            )

        self._genesis_hash = genesis.block_hash
        self.storage.save_block(genesis)
        self.storage.set_meta("genesis_hash", genesis.block_hash)

        # Mark that this chain uses the hybrid rolling-window difficulty system.
        self.storage.set_meta("hybrid_diff_v1", "1")

        # Print the genesis hash so operators can immediately confirm that
        # every node has produced the same canonical genesis block.
        print(f"[GENESIS] Hash: {genesis.block_hash}  "
              f"ts={Config.GENESIS_TIMESTAMP}  nonce={Config.GENESIS_NONCE}  "
              f"diff={Config.INITIAL_DIFFICULTY}")

        log.info(f"Genesis block created: {genesis.block_hash[:16]}... "
                 f"ts={Config.GENESIS_TIMESTAMP} nonce={Config.GENESIS_NONCE} "
                 f"diff={Config.INITIAL_DIFFICULTY}")

    # ── Hybrid difficulty state migration ────────────────────────────────────
    def _maybe_migrate_difficulty_state(self):
        """
        Idempotent migration from the legacy ASERT-DAA system to the
        Hybrid Rolling-Window + Per-Block difficulty engine.

        The new difficulty engine is anchor-free: it derives all adjustment
        signals directly from the last MACRO_WINDOW+1 block timestamps stored
        in the chain.  No external state needs to be migrated.

        This function:
          1. Detects chains created by older software (asert_anchor present,
             hybrid_diff_v1 absent) and logs the one-time migration notice.
          2. Writes the hybrid_diff_v1 marker so the notice is not repeated.
          3. Flushes the DifficultyEngine cache to ensure the first post-
             migration get_difficulty() call reads fresh chain data.

        Safe to call on every startup — if the marker already exists the
        function returns immediately after a single cheap DB read.
        """
        if self.storage.get_meta("hybrid_diff_v1"):
            return  # already migrated or created with new code

        # One-time migration log
        old_anchor = self.storage.get_meta("asert_anchor")
        if old_anchor:
            log.info(
                "Difficulty system migrated: ASERT-DAA → "
                "Hybrid Rolling-Window + Per-Block adjustment. "
                "The legacy asert_anchor is no longer used."
            )
        else:
            log.info(
                "Hybrid difficulty engine activated (anchor-free). "
                "Difficulty is computed from chain history."
            )

        self.storage.set_meta("hybrid_diff_v1", "1")
        DifficultyEngine.invalidate_cache(from_height=0)  # flush any stale cache

    # ── State queries ─────────────────────────────────────────────────────────
    def height(self) -> int:
        """
        Return the index of the chain tip.

        v7.0.1.2 — Bug 1 fix (self-healing against height == -1):
          If the underlying storage reports -1 (genesis missing or KV/SQL
          inconsistency), attempt a one-shot genesis recreation under
          _lock so concurrent accept_chain() / apply_block() paths do not
          race.  The method NEVER returns a negative value — the minimum
          exposed height is 0 (genesis).  This prevents:
            • "Height: -1" in the CLI dashboard
            • from_idx = max(0, -1 + 1) = 0 being overshadowed by any
              peer-reported height=-1 that crept into a MSG_CHAIN /
              server_height field
            • downstream consumers that do `height() - 1` arithmetic
              producing -2 and silently corrupting logic
        """
        h = self.storage.chain_height()
        if h < 0:
            # Self-heal: genesis missing or DB inconsistency.
            try:
                with self._lock:
                    if self.storage.chain_height() < 0:
                        log.warning("height(): chain empty at runtime — "
                                    "re-creating genesis (self-heal)")
                        self._create_genesis()
            except Exception as _e:
                log.error(f"height(): genesis self-heal failed: {_e}")
            h = self.storage.chain_height()
        # Never expose a negative height to callers (UI, peers, sync math).
        return h if h >= 0 else 0

    def latest_block(self) -> Optional[Block]:
        h = self.height()
        return self.storage.get_block(h) if h >= 0 else None

    def get_block(self, idx: int) -> Optional[Block]:
        return self.storage.get_block(idx)

    # ── Hybrid difficulty ─────────────────────────────────────────────────────
    def get_difficulty(self) -> float:
        """
        Return the canonical required difficulty for the next block.

        Delegates entirely to DifficultyEngine.compute_next_difficulty(), which
        implements the Hybrid Rolling-Window Macro + Per-Block Micro algorithm.

        Returns a float — difficulty may be fractional (e.g. 0.001, 0.003).

        This is the single authoritative source of difficulty for:
          • Block candidate construction  (consensus.build_candidate_block)
          • Block validation              (validate_block)
          • Mining status display         (CLI / RPC)

        Incoming blocks MUST NOT be trusted for their self-reported difficulty
        field.  validate_block() always calls get_difficulty() independently
        and rejects the block if the values do not match exactly.
        """
        return DifficultyEngine.compute_next_difficulty(
            self.storage, self.height()
        )

    def compute_reward(self, height: int) -> float:
        """Return block reward in VSD (float) for use with credit().
        Config.INITIAL_REWARD and Config.MIN_REWARD are in satoshi; convert
        to VSD here so callers that pass the result to credit() / to_satoshi()
        do not double-multiply by SATOSHI_PER_VSD."""
        return from_satoshi(self.compute_reward_sat(height))

    def compute_reward_sat(self, height: int) -> int:
        """Return block reward in satoshi — no float intermediate (F-01 COMPLETION).

        AUDIT-FIX (Batch D): the decay factor is now computed as an EXACT
        rational (Config.REWARD_DECAY_NUM / Config.REWARD_DECAY_DEN) using
        pure Python big-integer arithmetic, not Config.REWARD_DECAY_RATE ** n
        (float ** int, routed to the platform's C library pow() -- not
        guaranteed byte-identical across libm implementations for the same
        input, the same risk class SEC-FIX M-05 eliminated for difficulty).
        int ** int in Python is exact integer exponentiation-by-squaring, so
        this is fully portable and byte-identical on every interpreter.
        Rounding is done on the exact rational result with an explicit,
        platform-independent round-half-up rule rather than float round().
        """
        n = height // Config.REWARD_DECAY_BLOCKS
        numerator = Config.INITIAL_REWARD * (Config.REWARD_DECAY_NUM ** n)
        denominator = Config.REWARD_DECAY_DEN ** n
        r_sat = (numerator + denominator // 2) // denominator
        r_sat = max(Config.MIN_REWARD, r_sat)
        return r_sat

    def get_dynamic_block_size(self) -> int:
        """Return the byte cap used when building the NEXT candidate block.

        Inputs (all non-consensus — this number is only used at candidate
        build time; it is NEVER validated against by peers):

          • Mempool depth — grow the cap when a backlog is forming, shrink
            it when the pool is nearly empty (pre-existing behaviour).

          • v7.5.0-OPT Network-aware shrink — consult the LatencyTracker
            and if the mean peer RTT exceeds soft thresholds, reduce the
            cap so the block is more likely to propagate fully within the
            fixed 60-second TARGET_BLOCK_TIME window.

            Thresholds (tuned for consumer links; purely advisory):
                rtt <= 0.25 s  →  no change        (healthy LAN / fibre)
                0.25 – 0.50 s  →  cap * 0.75       (typical home DSL)
                0.50 – 1.00 s  →  cap * 0.50       (slow / congested)
                rtt  > 1.00 s  →  cap * 0.25       (satellite / mobile)

            A floor of 64 KB is applied so that even on a pathological link
            the chain can still include at least the coinbase + a handful
            of high-fee transactions.

        ⚠  DOES NOT alter TARGET_BLOCK_TIME (60 s, fixed consensus value).
        ⚠  DOES NOT alter difficulty adjustment (DifficultyEngine).
        ⚠  DOES NOT change any per-tx satoshi math — this function only
           decides how many *bytes* of txs to pack.
        """
        mp = self.mempool.size()
        base = Config.MIN_BLOCK_SIZE
        if mp > 1000:
            base = min(Config.MAX_BLOCK_SIZE, int(base * (1 + Config.BLOCK_SIZE_UP)))
        elif mp < 100:
            base = max(Config.MIN_BLOCK_SIZE, int(base * (1 - Config.BLOCK_SIZE_DOWN)))

        # ── v7.5.0-OPT Network-aware shrink ──────────────────────────────
        # Only applies when a P2PNetwork has been wired in AND the tracker
        # has at least one fresh RTT sample.  Missing network / zero-sample
        # path degrades silently to the mempool-only value above.
        net = self._network
        if net is not None:
            try:
                tracker = getattr(net, "latency_tracker", None)
                if tracker is not None:
                    rtt = tracker.avg_rtt()
                    if rtt > 0.0:
                        if rtt > 1.00:
                            factor_ppm = 250_000     # 25%
                        elif rtt > 0.50:
                            factor_ppm = 500_000     # 50%
                        elif rtt > 0.25:
                            factor_ppm = 750_000     # 75%
                        else:
                            factor_ppm = 1_000_000   # 100% (no shrink)
                        if factor_ppm < 1_000_000:
                            # Integer math only — no float drift on block
                            # size, and no interaction with satoshi math.
                            shrunk = (base * factor_ppm) // 1_000_000
                            FLOOR = 65_536   # 64 KB minimum
                            base = max(FLOOR, shrunk)
                            try:
                                metrics.set_gauge("block_size_rtt_factor_ppm",
                                                  factor_ppm)
                                metrics.set_gauge("network_avg_rtt_ms",
                                                  int(rtt * 1000))
                            except Exception:
                                pass
            except Exception as _lat_e:
                # Any failure in the advisory path must not break block
                # construction.  Log and continue with the pre-shrink value.
                log.debug(f"latency-aware sizing skipped: {_lat_e}")
        return base

    # ── Block validation ──────────────────────────────────────────────────────
    def validate_block(self, block: Block) -> Tuple[bool, str]:
        with self._lock:
            # Consensus fields must never accept IEEE-754 non-finite values.
            # NaN makes ordinary comparisons false and can otherwise bypass
            # timestamp and difficulty validation.
            try:
                if not math.isfinite(float(block.difficulty)):
                    return False, "Invalid block difficulty: value must be finite"
                if not math.isfinite(float(block.timestamp)):
                    return False, "Invalid block timestamp: value must be finite"
            except (TypeError, ValueError, OverflowError):
                return False, "Invalid block consensus numeric field"
            # ═══════════════════════════════════════════════════════════════════
            # SECURITY FIX: Cryptographic integrity check runs for EVERY block
            # including genesis (index == 0).
            #
            # Root cause of the "Forged Block Accepted" vulnerability:
            #   The original code contained:
            #       if block.index == 0: return True, "OK"
            #   This unconditionally accepted ANY genesis block without verifying
            #   its transactions, merkle_root, or block_hash.  An attacker could
            #   deep-copy the genesis block, modify its transactions (e.g. add a
            #   coinbase that credits their wallet), and validation would pass.
            #
            # Fix: integrity_check() verifies the full cryptographic chain for
            # every block regardless of index:
            #   block_hash ← header_dict (includes merkle_root)
            #   merkle_root ← tx_ids
            #   tx_ids      ← tx field content (via _compute_id)
            #   signatures  ← tx signing_bytes (ECDSA verification)
            #
            # Any modification to any transaction — amount, receiver, adding or
            # removing a transaction — breaks at least one link in this chain
            # and is rejected before any other check runs.
            #
            # v7.5.0-OPT: pass self.mempool so Block.integrity_check() can skip
            # ECDSA recheck for txs already validated at gossip time.  See the
            # detailed rationale at the top of Block.integrity_check().
            # ═══════════════════════════════════════════════════════════════════
            # The integrity pass is the authoritative signature check for
            # this block.  Record exactly which transaction IDs were proven
            # valid so the later semantic-validation loop does not perform a
            # second ECDSA verification of the same signed bytes.
            verified_tx_ids = set()
            integrity_tx_ids = set()
            ok_int, int_msg = block.integrity_check(
                mempool=self.mempool,
                verified_txids=verified_tx_ids,
                integrity_txids=integrity_tx_ids)
            if not ok_int:
                return False, int_msg

            # ── Genesis block: verify against the stored canonical hash ────────
            # For index=0 we cannot check prev_hash, MTP, difficulty, or PoW
            # (there is no parent block).  What we CAN enforce is that the block
            # hash matches what was recorded when the node first created genesis.
            if block.index == 0:
                stored_genesis = self.storage.get_meta("genesis_hash")
                if stored_genesis:
                    if block.block_hash != stored_genesis:
                        return False, (
                            f"Genesis block hash mismatch: "
                            f"presented={block.block_hash[:16]}, "
                            f"canonical={stored_genesis[:16]}. "
                            f"Forged or wrong-chain genesis block rejected.")
                    # Hash matches the stored genesis — genesis is valid.
                    return True, "OK"
                # No genesis_hash stored yet (first boot) — accept but do NOT
                # bypass the integrity_check above which already ran.
                return True, "OK"

            # ── Previous block linkage ────────────────────────────────────────
            prev_hash = self.storage.get_block_hash(block.index - 1)
            if not prev_hash:
                return False, "Previous block not found"
            if block.prev_hash != prev_hash:
                return False, "prev_hash mismatch"

            # ── Timestamp validation (MTP — Median Time Past) ─────────────────
            # Collect the timestamps of the last MTP_WINDOW blocks ending at
            # prev (NOT including the block being validated) for MTP computation.
            #
            # Fix #8 — Time / Synchronization:
            # Use network_clock.network_time() instead of raw time.time() so
            # that MTP upper-bound validation is robust to local clock skew.
            # The NetworkClock maintains a median of recent peer-observed block
            # timestamps; under significant clock drift it emits a warning and
            # the local time is used as the safe fallback.
            now = network_clock.network_time()
            mtp_lookback  = Config.DIFF_MTP_WINDOW
            ts_start      = max(0, block.index - mtp_lookback)
            recent_ts: List[int] = self.storage.get_block_timestamps(
                ts_start, block.index - 1)

            ts_ok, ts_msg = DifficultyEngine.validate_timestamp(
                new_ts=block.timestamp,
                recent_timestamps=recent_ts,
                network_time=now,
            )
            if not ts_ok:
                return False, ts_msg

            # ── Proof of Work ─────────────────────────────────────────────────
            if not block.validate_pow():
                return False, "Invalid PoW"

            # ── Difficulty ────────────────────────────────────────────────────
            # Float-tolerant comparison: difficulties are now floats, so we
            # use a tiny epsilon instead of exact equality to guard against
            # any floating-point representation differences between nodes
            # (e.g. 0.001000000000000001 vs 0.001).  1e-9 is orders of
            # magnitude tighter than the smallest difficulty step (DIFF_MIN_ABS_STEP
            # = 0.0001) so it cannot mask a real mismatch.
            expected_diff = self.get_difficulty()
            if abs(float(block.difficulty) - float(expected_diff)) > 1e-9:
                return False, (f"Difficulty mismatch: got {block.difficulty}, "
                               f"expected {expected_diff}")

            # ── Block size ────────────────────────────────────────────────────
            # Consensus MUST use a chain-wide deterministic limit.  The dynamic
            # sizing policy is intentionally based on local mempool depth and
            # network RTT, so it is suitable only for candidate construction.
            # Consulting it here would let two honest nodes disagree about the
            # validity of the same already-sealed block.
            block_bytes = block.size()
            max_bytes   = int(Config.MAX_BLOCK_SIZE)
            if block_bytes > max_bytes:
                return False, (f"Block too large: {block_bytes} bytes "
                               f"(max {max_bytes})")

            # ── VVM aggregate block-gas limit ─────────────────────────────────
            # VVM_TX_GAS_CAP limits one transaction; VVM_BLOCK_GAS_LIMIT limits
            # the total declared VVM gas budget in one block.  The application
            # path accounts the same deterministic quantity (gas_limit) for each
            # DEPLOY/CALL, so consensus must reject a block before mutation when
            # the aggregate exceeds the configured bound.
            gas_activation = int(getattr(
                Config, "VVM_BLOCK_GAS_LIMIT_ACTIVATION_HEIGHT", 0))
            if block.index >= gas_activation:
                block_vvm_gas = 0
                for _gas_tx in block.transactions:
                    if _gas_tx.tx_type in (
                            Transaction.TYPE_DEPLOY, Transaction.TYPE_CALL):
                        block_vvm_gas += int(_gas_tx.gas_limit)
                        if block_vvm_gas > int(Config.VVM_BLOCK_GAS_LIMIT):
                            return False, (
                                f"Block VVM gas limit exceeded: {block_vvm_gas} "
                                f"(max {int(Config.VVM_BLOCK_GAS_LIMIT)})")

            # ── Exactly one coinbase, must be first ───────────────────────────
            coinbase_count = sum(1 for tx in block.transactions
                                 if tx.sender == "COINBASE")
            if coinbase_count != 1:
                return False, f"Block must have exactly 1 coinbase tx, got {coinbase_count}"
            if block.transactions[0].sender != "COINBASE":
                return False, "Coinbase must be the first transaction"

            # ── Coinbase amount must exactly match the canonical subsidy ───────
            # F-01 COMPLETION: all arithmetic in satoshi to eliminate float drift.
            #
            # The coinbase amount is the canonical record of NEW issuance: the
            # deterministic block subsidy. Transaction fees are pre-existing
            # sender funds and are added separately by _distribute_rewards();
            # they are deliberately not part of cumulative issuance. Therefore
            # neither an under-claim nor an over-claim is valid.
            expected_subsidy_sat = self.compute_reward_sat(block.index)
            cb_tx      = block.transactions[0]
            cb_amt_sat = to_satoshi(cb_tx.amount)
            if cb_amt_sat != expected_subsidy_sat:
                return False, (f"Coinbase amount {cb_tx.amount} does not match "
                               f"required subsidy {from_satoshi(expected_subsidy_sat)}")

            # ── Coinbase receiver must match block miner_address ───────────────
            # SECURITY FIX: Without this check an attacker can take a valid
            # mined block, swap the coinbase receiver in the serialised dict to
            # their own address, keep the original coinbase tx_id (which
            # from_dict loads verbatim without recomputing), and the Merkle
            # root / block_hash remain unchanged — PoW still validates — while
            # the mining reward is silently redirected to the attacker.
            if cb_tx.receiver != block.miner_address:
                return False, (
                    f"Coinbase receiver '{cb_tx.receiver}' does not match "
                    f"block miner_address '{block.miner_address}'")

            # ── Integrity results are authoritative for this immutable block ──
            # integrity_check() already verified every tx_id and the Merkle root.
            # Recomputing those same commitments here only added CPU cost during
            # catch-up. The block is immutable after sealing and this method holds
            # the blockchain lock for the full validation pass.

            # ── Transaction validation ────────────────────────────────────────
            seen_tx_ids = set()
            # Same-block VVM ordering: a CALL may legitimately target a
            # contract deployed earlier in this very block.  The old check
            # consulted only committed pre-block storage, so validate_block()
            # rejected a block that apply_block() itself could execute
            # deterministically (DEPLOY first, CALL second).  Track only
            # deployments that are actually eligible to create a contract
            # under the same name-gate rules used by _apply_vvm_tx(); this
            # prevents a CALL from being admitted merely because a colliding
            # deploy appears earlier in the block.  Runtime VM failure remains
            # a normal reverted VVM transaction, matching apply_block().
            pending_deploy_addrs: Set[str] = set()
            pending_deploy_names: Set[str] = set()
            # BUG-3 FIX: track satoshi already "spent" by earlier transactions
            # in this block for each sender.  Without this, two txs from the
            # same sender each spending 90% of balance both pass the individual
            # check (90% < 100%) but the second debit fails in apply_block,
            # causing a validated block to fail application — breaking atomicity.
            pending_debits: Dict[str, int] = {}
            # AUDIT-FIX-11 (double-debit via nonce reuse): apply_block's own
            # nonce bookkeeping is `set_nonce(sender, max(current, tx.nonce+1))`
            # — that formula never rejects tx.nonce < current (a stale/reused
            # nonce) or tx.nonce > current (a gap); it just silently no-ops
            # the advance for a stale nonce while the transaction is still
            # fully applied. Two different, independently and validly signed
            # transactions from the same sender that happen to reuse a nonce
            # (e.g., an ordinary wallet "replace/cancel" re-sign) previously
            # had NOTHING in validate_block or apply_block requiring them to
            # be mutually exclusive — both could be mined, double-debiting the
            # sender. Track the expected next nonce per sender across this
            # block the same way pending_debits already tracks spend, and
            # require exact sequential equality.
            pending_nonces: Dict[str, int] = {}
            # Validation does not mutate account balances. Cache each sender's
            # pre-block balance once, then apply pending same-block debits locally.
            preblock_balances: Dict[str, int] = {}
            non_coinbase_tx_ids = [
                tx.tx_id for tx in block.transactions if tx.sender != "COINBASE"
            ]
            existing_block_tx_ids = self.storage.existing_tx_ids(non_coinbase_tx_ids)
            sender_addresses = {
                tx.sender for tx in block.transactions if tx.sender != "COINBASE"
            }
            preblock_balances = self.storage.get_balances_sat(sender_addresses)

            # Consensus-level stake lock.  REGISTER mutations are intentionally
            # applied only after reward distribution, so the stake visible in
            # the pre-block state remains locked for every transaction in this
            # block.  Effective positive REGISTER deltas are also reserved:
            # the stake is not transferred away, but it becomes locked when the
            # deferred role mutation is applied at the end of the block.
            #
            # This shadow state mirrors the exact guards in apply_block:
            # identity claims have no role effect, opposite roles are ignored,
            # slashed validators cannot re-register, and "none" clears the
            # role.  Keeping this simulation here (rather than merely reading
            # the current stake) prevents a block from spending funds that a
            # later REGISTER in the same block will lock.
            locked_stake_reserve: Dict[str, int] = {}
            role_shadow: Dict[str, Optional[dict]] = {}
            for tx in block.transactions:
                if tx.tx_type != Transaction.TYPE_REGISTER or tx.sender == "COINBASE":
                    continue
                if Transaction.is_identity_claim(tx):
                    continue
                if tx.sender not in role_shadow:
                    role_shadow[tx.sender] = self.storage.get_role(tx.sender)

            for addr, role_existing in role_shadow.items():
                if role_existing and role_existing.get("role") in ("miner", "investor"):
                    locked_stake_reserve[addr] = to_satoshi(
                        float(role_existing.get("stake", 0.0)))
                else:
                    locked_stake_reserve[addr] = 0

            # Start with every currently active role, not only addresses that
            # submit REGISTER transactions in this block.
            for existing_role_name in ("miner", "investor"):
                for r in self.storage.get_all_by_role(existing_role_name):
                    addr = r.get("address")
                    if addr:
                        locked_stake_reserve[addr] = to_satoshi(
                            float(r.get("stake", 0.0)))

            # Re-simulate only the REGISTER mutations that can actually take
            # effect at the end of this block and add their positive stake
            # deltas to the lock reserve.
            #
            # A REGISTER that creates or changes into a role is an initial
            # registration and must carry the role's configured minimum stake.
            # Once that role is already active, later REGISTERs are additive
            # top-ups and may be any positive amount.  This check lives here,
            # with the canonical pre-block/in-block role state, because
            # Transaction.is_valid() intentionally has no storage context.
            role_stake_activation = int(getattr(
                Config, "ROLE_STAKE_MIN_ACTIVATION_HEIGHT", 0))
            # Preserve the existing same-block UNREGISTER → REGISTER semantics:
            # an address that already had an active role at block start may
            # clear it and establish a new same-role stake in this block.  The
            # legacy tests/protocol deliberately permit that re-registration
            # amount to be arbitrary positive stake, while a genuinely new
            # activation is subject to the configured minimum.
            same_block_reentry: set[str] = set()
            for tx in block.transactions:
                if tx.tx_type != Transaction.TYPE_REGISTER or tx.sender == "COINBASE":
                    continue
                if Transaction.is_identity_claim(tx):
                    continue
                role = (tx.memo or "").strip().lower()
                if role not in ("miner", "investor", "none"):
                    role = "none"
                current = role_shadow.get(tx.sender)
                if role == "none":
                    # The previous role's stake becomes spendable again at the
                    # end of this block. Keep the reserve in lockstep with the
                    # shadow role state. A slash marker, however, is permanent
                    # through an ordinary unregister and must survive this
                    # transition so a later REGISTER cannot self-unslash.
                    if current and current.get("role") in ("miner", "investor"):
                        same_block_reentry.add(tx.sender)
                    locked_stake_reserve[tx.sender] = 0
                    was_slashed = bool(current and current.get("slashed"))
                    role_shadow[tx.sender] = {
                        "role": "none", "stake": 0.0, "slashed": was_slashed
                    }
                    continue
                if current and current.get("role") == "miner" and role == "investor":
                    continue
                if current and current.get("role") == "investor" and role == "miner":
                    continue
                if current and current.get("slashed"):
                    continue
                same_role = bool(current and current.get("role") == role)
                if (block.index >= role_stake_activation
                        and not same_role
                        and tx.sender not in same_block_reentry):
                    minimum_sat = (
                        int(Config.MIN_MINER_STAKE)
                        if role == "miner"
                        else int(Config.MIN_INVESTOR_STAKE)
                    )
                    tx_stake_sat = to_satoshi(float(tx.amount))
                    if tx_stake_sat < minimum_sat:
                        return False, (
                            f"REGISTER({role}) stake below minimum: "
                            f"{from_satoshi(tx_stake_sat):.8f} VSD "
                            f"(minimum {from_satoshi(minimum_sat):.8f} VSD)")
                cur_stake = float(current.get("stake", 0.0)) if same_role else 0.0
                delta_sat = to_satoshi(float(tx.amount))
                locked_stake_reserve[tx.sender] = (
                    locked_stake_reserve.get(tx.sender, 0) + max(0, delta_sat))
                role_shadow[tx.sender] = {
                    "role": role,
                    "stake": cur_stake + float(tx.amount),
                    "slashed": False,
                }

            for tx in block.transactions:
                if tx.sender == "COINBASE":
                    continue
                # Duplicate within block
                if tx.tx_id in seen_tx_ids:
                    return False, f"Duplicate tx in block: {tx.tx_id[:8]}"
                seen_tx_ids.add(tx.tx_id)

                # tx_id integrity was established by the single authoritative
                # Block.integrity_check() pass above. Keep this fail-closed
                # membership assertion so future callers cannot accidentally
                # bypass the integrity result.
                if tx.tx_id not in integrity_tx_ids:
                    return False, f"tx_id integrity result missing for {tx.tx_id[:16]}"

                ok, msg = tx.is_valid(
                    reference_time=block.timestamp,
                    block_height=block.index,
                    signature_already_verified=(tx.tx_id in verified_tx_ids),
                )
                if not ok:
                    return False, f"Invalid tx {tx.tx_id[:8]}: {msg}"
                # AUDIT-FIX-14a: require a real (non-zero) expiry for ordinary
                # transactions. expiry=0 means "never expires" — a user tx
                # with expiry=0 stays valid forever, which combined with
                # pruning (see AUDIT-FIX-14b below) made replay possible
                # indefinitely, not just within a short window.
                if (block.index >= Config.EXPIRY_REQUIRED_ACTIVATION_HEIGHT
                        and tx.sender != "COINBASE" and tx.expiry == 0):
                    return False, (
                        f"tx {tx.tx_id[:8]}: expiry=0 not permitted for "
                        f"non-coinbase transactions")
                # AUDIT-FIX-14b: tx_exists() alone depends on the prunable
                # `transactions` table — once a transaction's row is pruned
                # (Storage.prune_old_data, or RollingWindowPruner at its
                # default 600-block window), tx_exists() returns False again
                # for a tx_id that was already applied, making it replayable.
                # replay_guard_exists() consults a separate, permanent,
                # never-pruned index populated alongside every block save —
                # see Storage.record_applied_tx_id / replay_guard_exists.
                if tx.tx_id in existing_block_tx_ids:
                    return False, f"Double-spend: {tx.tx_id[:8]}"

                # ── AUDIT-FIX-11: strict nonce sequencing ──────────────────────
                if block.index >= Config.NONCE_STRICT_ACTIVATION_HEIGHT:
                    expected_nonce = pending_nonces.get(tx.sender)
                    if expected_nonce is None:
                        expected_nonce = self.storage.get_nonce(tx.sender)
                    if tx.nonce != expected_nonce:
                        return False, (
                            f"Nonce mismatch for {tx.sender[:12]}: tx {tx.tx_id[:8]} "
                            f"has nonce {tx.nonce}, expected {expected_nonce} "
                            f"(stale/reused or gapped nonce)")
                    pending_nonces[tx.sender] = expected_nonce + 1

                # ── Balance check (sequential — BUG-3 FIX) ───────────────────
                # Deduct from the sender's balance minus what earlier txs in
                # this same block have already consumed (pending_debits).
                already_spent = pending_debits.get(tx.sender, 0)
                bal_sat = preblock_balances.get(tx.sender, 0)
                locked_sat = locked_stake_reserve.get(tx.sender, 0)
                available_sat = bal_sat - already_spent - locked_sat

                # ── VVM-specific balance check ─────────────────────────────────
                # F-01 COMPLETION: satoshi integer arithmetic eliminates float drift.
                if tx.tx_type in (Transaction.TYPE_DEPLOY, Transaction.TYPE_CALL):
                    # Sender must cover: call_value + max_gas_fee (all in satoshi)
                    max_gas_fee_sat = gas_fee_to_sat(tx.gas_limit, tx.gas_price)
                    required_sat    = to_satoshi(tx.amount) + max_gas_fee_sat
                    if available_sat < required_sat:
                        return False, (
                            f"Insufficient balance for VVM tx {tx.tx_id[:8]}: "
                            f"need {from_satoshi(required_sat):.8f} VSD "
                            f"(amount={tx.amount:.8f} "
                            f"+ max_gas={from_satoshi(max_gas_fee_sat):.8f}), "
                            f"have {from_satoshi(available_sat):.8f}")
                    pending_debits[tx.sender] = already_spent + required_sat
                    if tx.tx_type == Transaction.TYPE_DEPLOY:
                        # Derivation is consensus-deterministic and mirrors
                        # VVMEngine.deploy(): sender + transaction nonce + tx_id.
                        # We only expose the predicted address to later CALLs
                        # after the deploy passes the same name-collision gate
                        # conditions as the real execution path.
                        deploy_addr = derive_contract_address(
                            tx.sender, tx.nonce, tx.tx_id)
                        deploy_name = normalize_contract_name(
                            getattr(tx, "contract_name", "") or "")
                        naming_active = (
                            block.index >= Config.CONTRACT_NAMING_ACTIVATION_HEIGHT)
                        name_blocked = False
                        if naming_active and deploy_name:
                            name_blocked = (
                                self.storage.contract_name_exists(deploy_name)
                                or deploy_name in pending_deploy_names)
                        if not name_blocked:
                            pending_deploy_addrs.add(deploy_addr)
                            if naming_active and deploy_name:
                                pending_deploy_names.add(deploy_name)
                    elif tx.tx_type == Transaction.TYPE_CALL:
                        # Ordinary calls still require an already-committed
                        # contract.  The sole exception is a deterministic
                        # contract address produced by an eligible DEPLOY that
                        # appeared earlier in this same block.
                        if (not self.storage.get_contract(tx.receiver)
                                and tx.receiver not in pending_deploy_addrs):
                            return False, (
                                f"Contract not found for CALL tx {tx.tx_id[:8]}: "
                                f"{tx.receiver}")
                elif tx.tx_type == Transaction.TYPE_REGISTER:
                    # AUDIT-FIX: apply_block only ever debits the FEE for a
                    # REGISTER tx — tx.amount is the stake, a LOCK on the
                    # sender's existing balance that stays inside balances
                    # rather than being transferred out (see
                    # _rollback_block's own comment on this exact point).
                    # Previously this fell through to the generic "else"
                    # branch below and reserved amount + fee, over-counting
                    # the stake as spent for the rest of this block's
                    # validation and wrongly rejecting a later same-sender
                    # transaction that apply_block would actually have
                    # accepted, since the stake amount never actually left
                    # the sender's spendable balance.
                    required_sat = tx.compute_fee_sat()
                    if available_sat < required_sat:
                        return False, f"Insufficient balance for {tx.sender[:12]}"
                    pending_debits[tx.sender] = already_spent + required_sat
                else:
                    # Standard transfer balance check (satoshi)
                    required_sat = to_satoshi(tx.amount) + tx.compute_fee_sat()
                    if available_sat < required_sat:
                        return False, f"Insufficient balance for {tx.sender[:12]}"
                    pending_debits[tx.sender] = already_spent + required_sat

            # ── Genesis hash integrity ────────────────────────────────────────
            stored_genesis = self.storage.get_meta("genesis_hash")
            if stored_genesis:
                gen = self.storage.get_block(0)
                if gen and gen.block_hash != stored_genesis:
                    return False, "Genesis hash tampered"

            # ── Protocol version validation (Problem #13 + Governance) ──────────
            # GovernanceEngine.validate_block_version() enforces:
            #   - tolerant (both versions ok) before activation height
            #   - strict (old version rejected) at/after activation height
            #   - hard-fork guard (never accept version > current + 1)
            ok_ver, ver_msg = self._governance.validate_block_version(
                block.protocol_version, block.index)
            if not ok_ver:
                return False, ver_msg

            # ── State root validation (Problem #3) ────────────────────────────
            # v7.1.10-hotfix2: the OLD design compared prev_stored.state_root
            # against ``self.storage.compute_state_root()`` (the LIVE root).
            # That only worked if live state was *exactly* the state committed
            # at block N-1 — any dry-run-restore glitch, mempool pre-debit,
            # HT-volume update, or contract-state mutation outside apply_block
            # would cause the live root to drift from prev_stored.state_root,
            # producing spurious "Prev block state_root mismatch" rejections
            # even though the incoming block was perfectly valid.  Observed in
            # production: 11 blocks applied successfully, then block #12
            # rejected because background state-writes had drifted the live
            # root away from block #11's committed root.
            #
            # The correct consensus check is already performed INSIDE
            # ``apply_block`` (post-apply): we tentatively apply the block,
            # recompute the resulting state_root, compare it to the block's
            # committed state_root, and roll back the snapshot on mismatch.
            # Chain continuity is already enforced via prev_hash verification
            # in integrity_check().  The prev-root live check here is
            # redundant AND actively harmful, so it is disabled.
            #
            # (We keep the empty-root / pre-v7.1.9-block short-circuit below
            # for backward-compat, but remove the drift-prone comparison.)
            if block.state_root and block.index > 0:
                # No-op by design — see comment block above.
                # Chain continuity: prev_hash check in integrity_check().
                # State correctness: post-apply recompute in apply_block().
                pass

            return True, "OK"

    # ── Dry-run state root (v7.1.9 — Option A fix) ────────────────────────────
    def dry_run_state_root(self,
                           transactions: List['Transaction'],
                           miner_address: str,
                           height: int,
                           timestamp: Optional[int] = None,
                           difficulty: Optional[float] = None) -> str:
        """
        Compute the state_root that WOULD result from applying ``transactions``
        on top of the current chain state, WITHOUT actually persisting any
        mutation.

        This is the cornerstone of the v7.1.9 sync-bug fix.  Previously
        ``apply_block`` mutated ``block.state_root`` AFTER the PoW had
        already committed to a header that included the (empty) state_root —
        so every receiving node recomputed a different ``block_hash`` and
        rejected the block on integrity_check().  The candidate-builder now
        calls THIS method to obtain the correct state_root BEFORE the PoW
        loop runs, so the mined hash and the recomputed hash agree.

        v7.2.0-FIX-1+2: VVM DEPLOY / CALL transactions are now fully simulated
        instead of being silently skipped.  Skipping them caused every block
        containing a smart-contract transaction to be rejected with
        "state_root mismatch" on all receiving nodes because the miner committed
        a state_root computed without running the VVM, while every validating
        node ran the VVM in apply_block and computed a different post-state.

        VVM simulation uses VVMEngine.simulate() — a pure dry-run that clones
        storage reads but discards all storage writes.  Balance effects (gas fee,
        gas refund, call_value) are applied to the in-memory snapshot so the
        resulting state_root matches what apply_block will produce.  Contract
        storage writes are temporarily applied, storage_root updated, then
        restored — so the state_root also covers post-execution contract state.

        Implementation notes
        ────────────────────
        • Reuses the exact same code paths as ``apply_block`` (debit/credit,
          coinbase skip, _distribute_rewards, nonce advance) so determinism
          is guaranteed bit-for-bit across miners and validators.
        • The whole simulation runs inside a snapshot/restore envelope, so
          chain state is unchanged after this method returns.  It is safe to
          call from any thread without disturbing concurrent reads — but
          callers MUST hold ``self._lock`` (or call from within a holder)
          to avoid a concurrent ``apply_block`` interleaving with the dry
          run.  ``build_candidate_block`` acquires the lock before calling.

        Returns the hex state_root string (or sha256("empty_state") for an
        empty chain).  Raises only on truly catastrophic storage failure.
        """
        # Build the touched-account set the same way apply_block does.
        touched: Set[str] = set()
        for tx in transactions:
            if tx.sender:   touched.add(tx.sender)
            if tx.receiver: touched.add(tx.receiver)
        if miner_address:
            touched.add(miner_address)
        for v in self.storage.get_all_by_role("investor"):
            touched.add(v["address"])
        for m in self.storage.get_all_by_role("miner"):
            touched.add(m["address"])
        touched.add(Config.BURN_ADDRESS)
        # Always include L2 sentinel addresses so any bridge mutations made
        # during the dry-run are properly captured in the snapshot and fully
        # restored in the finally block — even if no L2 tx is in this batch.
        touched.add(L2_BRIDGE_ADDRESS)
        touched.add(L2_WITHDRAW_ADDRESS)

        snap = self.storage.snapshot_accounts(touched)

        # AUDIT-FIX (Batch D): _distribute_rewards() below permanently
        # increments the meta-table cumulative_issued_sat counter via
        # increment_cumulative_issued_sat() -- a mutation snapshot_accounts/
        # restore_accounts never covers, since that pair only tracks
        # (balance_sat, nonce, ht_volume_sat) per address. Without also
        # snapshotting this counter, every candidate block a miner evaluates
        # (not just the one actually mined) permanently inflates it, so
        # get_total_issued_satoshi() drifts away from sum_all_balances_satoshi()
        # even though every balance effect is correctly rolled back below --
        # and that drift is exactly what SystemInvariantGate.assert_conservation()
        # treats as corruption-level, tripping the hardened circuit breaker
        # into READ_ONLY/SAFE_SHUTDOWN after just two such events in 5 minutes.
        _cumulative_issued_snap = self.storage.get_cumulative_issued_sat()

        # Track contract storage slot backups for restore after dry-run.
        _slot_backup: dict = {}          # (addr, slot) -> original_value
        _tag_backup: dict = {}           # (addr, slot) -> original explicit tag / None
        _touched_contracts: set = set() # contracts whose storage_root was updated

        # VVM-DRYRUN-FIX: a successful DEPLOY can create a brand-new account
        # balance when tx.amount > 0. The deployment address is only known
        # after the VM executes, so it cannot be included in the initial
        # snapshot above. Capture its exact pre-state once known and restore it
        # in finally, keeping dry_run_state_root() truly side-effect-free.
        _dry_run_dynamic_accounts: dict = {}
        # VVM-2 FIX: contracts newly DEPLOYED during dry_run that we must
        # purge in the finally block — apply_block uses vvm.deploy() which
        # writes a row to contract_accounts plus a code blob to contract_code,
        # and dry_run must mirror that to compute the matching state_root.
        # destroy_contract() only sets destroyed=1 (which IS what
        # compute_state_root() filters on — destroyed contracts are excluded
        # from the root), so dry_run's perspective on the state hash matches
        # apply_block's even though the row physically remains.  We still
        # explicitly destroy_contract here so callers (which observe
        # contract_accounts via list/scan APIs) don't see ghost contracts.
        _dry_run_deployed: set = set()
        # Contracts SELFDESTRUCT-ed during dry_run.  These are real,
        # already-on-chain contracts whose runtime ran SELFDESTRUCT under
        # this dry-run.  Marking them destroyed=1 here matches what
        # apply_block's compute_state_root would observe.  But on the way
        # out of dry_run we MUST un-destroy them — apply_block hasn't
        # actually committed the SELFDESTRUCT yet, and leaving the flag
        # set would brick the contract for future real calls.
        _dry_run_selfdestructed: set = set()

        def _snapshot_dry_run_account(address: str) -> None:
            """Capture an account's exact pre-dry-run state once.

            SELFDESTRUCT can transfer value to a beneficiary that was not
            known when the initial touched-account set was assembled.  Nested
            execution can also reach a source address outside the top-level
            transaction's sender/receiver pair.  Those rows must be restored
            after simulation just like dynamically-created deploy accounts.
            """
            if (not address or address in snap
                    or address in _dry_run_dynamic_accounts):
                return
            _dry_run_dynamic_accounts[address] = \
                self.storage.snapshot_accounts([address])[address]

        # State-channel precompiles use direct persistent tables/balances, so
        # the dry-run needs an outer journal covering the complete simulation.
        # VVMEngine uses nested journals for nested CALL/CREATE frames; the
        # outer journal therefore captures the true pre-dry-run state while
        # inner failed frames can independently roll back their own mutations.
        _state_channel_journal = self.storage.begin_state_channel_journal()

        # Use the real parent hash for the candidate context.  Most VVM block
        # opcodes do not need it directly, but a candidate simulation must not
        # invent consensus-visible header fields when the actual block already
        # has a canonical predecessor.
        _candidate_prev_hash = "0" * 64
        if height > 0:
            try:
                _parent_block = self.storage.get_block(height - 1)
                if _parent_block is not None:
                    _candidate_prev_hash = _parent_block.block_hash
            except Exception:
                # A missing parent will be rejected by normal block validation;
                # do not make dry-run itself fail merely because this optional
                # context lookup is unavailable.
                pass

        try:
            fee_pool_sat = 0
            for tx in transactions:
                if tx.sender == "COINBASE":
                    continue

                # ── v7.2.0-FIX-1+2: VVM DEPLOY / CALL — fully simulated ──────
                if tx.tx_type in (Transaction.TYPE_DEPLOY, Transaction.TYPE_CALL):
                    max_gas_fee_sat = gas_fee_to_sat(tx.gas_limit, tx.gas_price)
                    amount_sat      = to_satoshi(tx.amount)
                    total_upfront   = amount_sat + max_gas_fee_sat

                    # Debit upfront (mirrors _apply_vvm_tx step 1).
                    # If the sender can't afford it, skip this tx — same as
                    # apply_block does (it debits upfront and returns (0, False)
                    # on failure without adding to fee_pool).
                    if not self.storage.debit_sat(tx.sender, total_upfront):
                        continue

                    # AUDIT-FIX-1 (state_root divergence): SC-NAME-1 gate,
                    # mirrored from _apply_vvm_tx via the shared
                    # _deploy_name_gate() helper. MUST run before the VM —
                    # otherwise a name-collision or invalid-name DEPLOY would
                    # get simulated here as a full VM execution (and possibly
                    # "succeed"), while _apply_vvm_tx (the real path run by
                    # apply_block on every node, including this miner's own)
                    # never invokes the VM for that tx at all. That mismatch
                    # is exactly what makes the resulting block's state_root
                    # diverge from what apply_block actually computes,
                    # guaranteeing universal rejection of the block.
                    _blocked, _norm, _reason = self._deploy_name_gate(
                        tx, height)
                    if _blocked:
                        if _reason.startswith("invalid:"):
                            # Mirrors _apply_vvm_tx: full refund, no fee.
                            self.storage.credit_sat(tx.sender, total_upfront)
                        else:  # "collision" — mirrors _apply_vvm_tx exactly:
                            # charge NAME_COLLISION_GAS_PENALTY, refund the
                            # rest, contribute 0 to fee_pool_sat (SC-V73-FIX-8
                            # order-independence — see _apply_vvm_tx).
                            _penalty_gas = min(
                                Config.VVM_DEPLOY_GAS_BASE, tx.gas_limit)
                            _penalty_fee_sat = gas_fee_to_sat(
                                _penalty_gas, tx.gas_price)
                            _collision_refund = total_upfront - _penalty_fee_sat
                            if _collision_refund > 0:
                                self.storage.credit_sat(
                                    tx.sender, _collision_refund)
                        cur_nonce = self.storage.get_nonce(tx.sender)
                        self.storage.set_nonce(
                            tx.sender, max(cur_nonce, tx.nonce + 1))
                        continue

                    # Run a pure VM dry-run via VVMEngine.simulate().
                    # simulate() clones storage reads but discards all writes —
                    # it returns a VVMResult with storage_writes populated but
                    # not committed.
                    vvm = VVMEngine(storage=self.storage)
                    # Consensus-critical: execute against the exact candidate
                    # block context, never the previous block.
                    ctx = Block(
                        index=height,
                        prev_hash=_candidate_prev_hash,
                        transactions=transactions,
                        miner_address=miner_address,
                        difficulty=(self.get_difficulty()
                                    if difficulty is None else float(difficulty)),
                        timestamp=(int(time.time())
                                   if timestamp is None else int(timestamp)),
                    )
                    # VVM-2 FIX (CRITICAL): the previous implementation called
                    #   vvm.simulate(sender=tx.sender, ..., call_value=tx.amount,
                    #                bytecode=...)
                    # which is wrong on three counts:
                    #   1. simulate() takes `caller=`, NOT `sender=` — the kwarg
                    #      raised TypeError on every call.
                    #   2. simulate() does not accept a `bytecode=` parameter.
                    #   3. call_value was passed as float VSD; simulate-internals
                    #      eventually do `value & UINT256_MAX` (TypeError again).
                    # The TypeError was caught by the surrounding except, so
                    # EVERY VVM tx in dry_run was treated as a full-gas revert
                    # — no contract storage writes, no contract_addr tracking,
                    # no storage_root updates.  apply_block then ran the REAL
                    # vvm.deploy/call and produced a different state_root,
                    # silently passing through the empty-state_root short-circuit
                    # and disabling consensus state_root verification for every
                    # VVM-containing block.
                    #
                    # The fix: dry_run mirrors _apply_vvm_tx exactly — same
                    # vvm.deploy / vvm.call invocations, same call_value as
                    # integer satoshi.  For DEPLOY, vvm.deploy persists the
                    # new contract row + code; the finally block destroys it
                    # so dry_run is non-mutating from the caller's perspective.
                    _deploy_addr_for_cleanup = None
                    try:
                        if tx.tx_type == Transaction.TYPE_DEPLOY:
                            result = vvm.deploy(
                                sender     = tx.sender,
                                bytecode   = bytes.fromhex(tx.data) if tx.data else b"",
                                call_value = amount_sat,
                                gas_limit  = tx.gas_limit,
                                block_ctx  = ctx,
                                tx         = tx,
                            )
                            # Track the new contract address for finally cleanup.
                            if result.success and result.contract_addr:
                                _deploy_addr_for_cleanup = result.contract_addr
                                _touched_contracts.add(result.contract_addr)
                        else:  # TYPE_CALL
                            result = vvm.call(
                                caller     = tx.sender,
                                contract   = tx.receiver,
                                calldata   = bytes.fromhex(tx.data) if tx.data else b"",
                                call_value = amount_sat,
                                gas_limit  = tx.gas_limit,
                                block_ctx  = ctx,
                                tx         = tx,
                            )
                    except Exception as _vme:
                        # vvm.deploy/call raised — treat as full-gas revert.
                        # _apply_vvm_tx wraps execution in the same try/except
                        # via _execute internals, so reaching here means a
                        # truly unexpected error.  Drive the same revert
                        # bookkeeping apply_block would.
                        log.debug(
                            f"dry_run VVM execution error for "
                            f"{tx.tx_id[:8]}: {_vme}")
                        gas_used           = tx.gas_limit
                        actual_gas_fee_sat = gas_fee_to_sat(gas_used, tx.gas_price)
                        refund_sat         = max_gas_fee_sat - actual_gas_fee_sat
                        if refund_sat > 0:
                            self.storage.credit_sat(tx.sender, refund_sat)
                        # call_value refund on revert
                        if amount_sat > 0:
                            self.storage.credit_sat(tx.sender, amount_sat)
                        fee_pool_sat += actual_gas_fee_sat
                        cur_nonce = self.storage.get_nonce(tx.sender)
                        self.storage.set_nonce(
                            tx.sender, max(cur_nonce, tx.nonce + 1))
                        continue
                    # Track the deploy contract for finally cleanup whether
                    # or not we entered the success branch below.
                    if _deploy_addr_for_cleanup:
                        _dry_run_deployed.add(_deploy_addr_for_cleanup)

                    gas_used           = min(result.gas_used, tx.gas_limit)
                    actual_gas_fee_sat = gas_fee_to_sat(gas_used, tx.gas_price)
                    refund_sat         = max_gas_fee_sat - actual_gas_fee_sat

                    # Refund unused gas (mirrors _apply_vvm_tx step 3).
                    if refund_sat > 0:
                        self.storage.credit_sat(tx.sender, refund_sat)

                    if result.success:
                        # VVM-2 FIX: For DEPLOY, mirror apply_block's
                        # post-execution persistence so compute_state_root()
                        # observes the new contract.  Without these calls,
                        # the contract row never lands in contract_accounts
                        # and storage_root for the new address remains
                        # sha256(b"empty_storage") — apply_block, doing
                        # the real save_contract, would compute a different
                        # state_root → block rejection.
                        if (tx.tx_type == Transaction.TYPE_DEPLOY
                                and result.contract_addr):
                            try:
                                code_hash = sha256(result.return_data)
                                self.storage.save_contract_code(
                                    code_hash, result.return_data)
                                _cname = normalize_contract_name(
                                    getattr(tx, "contract_name", "") or "")
                                self.storage.save_contract(
                                    address       = result.contract_addr,
                                    code_hash     = code_hash,
                                    creator       = tx.sender,
                                    created_at    = (ctx.timestamp
                                                     if ctx is not None else 0),
                                    contract_name = _cname,
                                )
                                _dry_run_deployed.add(result.contract_addr)
                            except Exception as _sc_err:
                                log.debug(
                                    f"dry_run DEPLOY persist for "
                                    f"{tx.tx_id[:8]} failed: {_sc_err}")

                        # Mirror apply_block's pending_deployments flush
                        # for CREATE/CREATE2 children spawned during this tx.
                        for _pd in (result.pending_deployments or []):
                            try:
                                self.storage.save_contract_code(
                                    _pd["code_hash"], _pd["code_bytes"])
                                self.storage.save_contract(
                                    address       = _pd["address"],
                                    code_hash     = _pd["code_hash"],
                                    creator       = _pd["creator"],
                                    created_at    = _pd["created_at"],
                                    contract_name = _pd.get("contract_name", ""),
                                )
                                _dry_run_deployed.add(_pd["address"])
                            except Exception as _pd_err:
                                log.debug(
                                    f"dry_run pending_deployment "
                                    f"{_pd.get('address', '?')[:12]} "
                                    f"persist failed: {_pd_err}")

                        # Apply the VM's complete balance overlay. The top-level
                        # tx amount was already debited above; these deltas now
                        # materialise the recipient plus every successful nested
                        # CALL/CREATE value transfer in the same order as apply_block.
                        for _addr, _delta in result.balance_deltas.items():
                            _delta = int(_delta)
                            if _delta == 0:
                                continue
                            if _addr not in snap and _addr not in _dry_run_dynamic_accounts:
                                _dry_run_dynamic_accounts[_addr] = \
                                    self.storage.snapshot_accounts([_addr])[_addr]
                            if _delta > 0:
                                self.storage.credit_sat(_addr, _delta)
                            else:
                                if not self.storage.debit_sat(_addr, -_delta):
                                    raise RuntimeError(
                                        f"dry-run VVM balance overlay debit failed for {_addr[:16]}")
                            touched.add(_addr)

                        # Mirror the real SELFDESTRUCT balance transfer exactly:
                        # debit the source contract and credit the beneficiary.
                        # The previous dry-run path only marked the contract as
                        # destroyed, so its computed root omitted the actual
                        # beneficiary credit and retained the source balance.
                        for _sd_transfer in result.self_destruct_transfers:
                            if len(_sd_transfer) != 3:
                                raise RuntimeError(
                                    "SELFDESTRUCT transfer record is missing its source")
                            _source_addr, _beneficiary_addr, _sd_amount = _sd_transfer
                            _sd_amount = int(_sd_amount)
                            if _sd_amount <= 0:
                                continue
                            _snapshot_dry_run_account(_source_addr)
                            _snapshot_dry_run_account(_beneficiary_addr)
                            if not self.storage.debit_sat(_source_addr, _sd_amount):
                                raise RuntimeError(
                                    f"dry-run SELFDESTRUCT source {_source_addr[:16]} "
                                    f"has insufficient balance for {_sd_amount} sat")
                            self.storage.credit_sat(_beneficiary_addr, _sd_amount)

                        # Apply storage writes temporarily so
                        # update_contract_storage_root sees the correct slots,
                        # then update the storage_root column — this makes
                        # compute_state_root() include post-execution contract
                        # state, matching what apply_block produces.
                        # All writes and root updates are reversed in the
                        # finally block below.
                        # VVM-3 mirror: skip __selfdestruct__ markers; they
                        # are not real slot writes (apply_block calls
                        # destroy_contract for them — we don't do that here
                        # because dry_run is non-mutating; the destroyed=1
                        # path matches what apply_block's compute_state_root
                        # would observe in the same flow).
                        for (addr, slot), value in result.storage_writes.items():
                            if addr == "__selfdestruct__":
                                # Mirror apply_block: the named contract is
                                # destroyed so excluded from state_root.
                                # Tracked separately from _dry_run_deployed
                                # because the contract is REAL (on-chain
                                # already) — finally must un-destroy it
                                # since apply_block has not actually
                                # committed the SELFDESTRUCT yet.
                                try:
                                    self.storage.destroy_contract(slot)
                                    _dry_run_selfdestructed.add(slot)
                                except Exception:
                                    pass
                                continue
                            if (addr, slot) not in _slot_backup:
                                _slot_backup[(addr, slot)] = \
                                    self.storage.sload(addr, slot)
                                _old_tag = self.storage.get_storage_tag(addr, slot)
                                _tag_backup[(addr, slot)] = (
                                    int(_old_tag) if int(_old_tag) != 0 else None)
                            self.storage.sstore(addr, slot, value)
                            self.storage.set_storage_tag(
                                addr, slot, int(result.storage_tags.get((addr, slot), 0)))
                        for addr in result.touched_contracts:
                            _touched_contracts.add(addr)
                            self.storage.update_contract_storage_root(addr)

                    else:
                        # Revert: refund call_value to sender.
                        if amount_sat > 0:
                            self.storage.credit_sat(tx.sender, amount_sat)

                    fee_pool_sat += actual_gas_fee_sat
                    cur_nonce = self.storage.get_nonce(tx.sender)
                    self.storage.set_nonce(
                        tx.sender, max(cur_nonce, tx.nonce + 1))
                    continue

                # ── REGISTER tx — fee + nonce only (same as apply_block) ──────
                if tx.tx_type == Transaction.TYPE_REGISTER:
                    # v7.2.0: REGISTER txs charge ONLY the fee (not tx.amount),
                    # advance the nonce, and defer role mutation to AFTER
                    # _distribute_rewards.  This block must mirror apply_block
                    # EXACTLY or the miner's pre-computed state_root will not
                    # match the post-apply computed state_root and the block
                    # will be rejected with "state_root mismatch".
                    fee_sat = tx.compute_fee_sat()
                    if fee_sat > 0:
                        if not self.storage.debit_sat(tx.sender, fee_sat):
                            raise RuntimeError(
                                f"dry-run REGISTER fee debit failed "
                                f"for {tx.sender[:12]}")
                        fee_pool_sat += fee_sat
                    cur_nonce = self.storage.get_nonce(tx.sender)
                    self.storage.set_nonce(tx.sender,
                                           max(cur_nonce, tx.nonce + 1))
                    continue

                # ── TYPE_ROLLUP — fee + nonce only (same as apply_block) ─────
                # MEMPOOL-1 / VVM-2 mirror: apply_block bumps the nonce and
                # charges the (currently 0) fee for TYPE_ROLLUP txs.  Pre-fix
                # dry_run had NO TYPE_ROLLUP handling so it fell into the
                # "standard transfer" branch — which charged a 0-amount,
                # 0-fee no-op and did NOT bump the nonce.  apply_block DID
                # bump the nonce → state_root mismatch on every block
                # containing a rollup tx.
                #
                # We deliberately do NOT call _apply_rollup_tx in dry_run.
                # Layer2State mutations from rollup application are not part
                # of storage.compute_state_root() (Layer2State has its own
                # tree), so skipping them here costs no state_root parity.
                # The actual rollup application happens at apply_block time;
                # if the rollup ends up failing there, MEMPOOL-1 part 2
                # below tolerates it (skip-and-remove).
                if tx.tx_type == Transaction.TYPE_ROLLUP:
                    fee_sat = tx.compute_fee_sat()  # 0 by validation
                    if fee_sat > 0:
                        if not self.storage.debit_sat(tx.sender, fee_sat):
                            raise RuntimeError(
                                f"dry-run ROLLUP fee debit failed "
                                f"for {tx.sender[:12]}")
                        fee_pool_sat += fee_sat
                    cur_nonce = self.storage.get_nonce(tx.sender)
                    self.storage.set_nonce(tx.sender,
                                           max(cur_nonce, tx.nonce + 1))
                    continue

                # ── Standard transfer ─────────────────────────────────────────
                fee_sat = tx.compute_fee_sat()
                amount_sat = to_satoshi(tx.amount)
                if not self.storage.debit_sat(tx.sender, fee_sat + amount_sat):
                    # Same balance check that apply_block does — if it would
                    # fail there, it fails here, and the candidate-builder
                    # should drop this tx from the candidate.
                    raise RuntimeError(f"dry-run debit failed for {tx.sender[:12]}")
                # AUDIT-FIX (Batch D): broadcasting to VSD_GLOBAL_MARKET used
                # to skip crediting the amount anywhere -- destroying it
                # outright, which get_burned_satoshi()'s own docstring says
                # this chain never does ("tracks burns by crediting
                # Config.BURN_ADDRESS rather than destroying funds outright").
                # sum_all_balances_satoshi() has no burn adjustment because it
                # doesn't need one as long as every debit is matched by a
                # credit somewhere -- route the amount to the burn address,
                # the same sink every other burn on this chain uses, instead
                # of letting it vanish and permanently desync
                # sum_all_balances_satoshi() from get_total_issued_satoshi().
                if tx.receiver != "VSD_GLOBAL_MARKET":
                    self.storage.credit_sat(tx.receiver, amount_sat)
                else:
                    self.storage.credit_sat(Config.BURN_ADDRESS, amount_sat)
                # ── L2 DEPOSIT HOOK (mirror of apply_block) ───────────────
                # Must replicate every storage mutation apply_block makes so
                # the pre-computed state_root matches the post-apply root.
                # L2 tree mutations are NOT part of storage.compute_state_root()
                # (they live in Layer2State's own Merkle tree), but the L1
                # escrow credit to L2_BRIDGE_ADDRESS IS in storage and must
                # be included — which the credit_sat above already covers.
                # No additional action needed for deposits beyond what the
                # standard credit_sat already did.
                # ── L2 WITHDRAWAL HOOK (mirror of apply_block) ────────────
                # When receiver == L2_WITHDRAW_ADDRESS, apply_block debits
                # L2_BRIDGE_ADDRESS and credits tx.sender on L1.  We must
                # mirror those exact storage mutations here so the dry-run
                # state_root matches the post-apply state_root.
                # L2 tree mutations (L2_withdraw) are NOT in storage and do
                # NOT affect compute_state_root() — only the L1 balance
                # changes matter here.
                if tx.receiver == L2_WITHDRAW_ADDRESS and amount_sat > 0:
                    layer2 = getattr(self, "layer2", None)
                    if layer2 is not None:
                        l2_bal = layer2.get_balance_sat(tx.sender)
                        bridge_bal = self.storage.get_balance_sat(
                            L2_BRIDGE_ADDRESS)
                        if l2_bal >= amount_sat and bridge_bal >= amount_sat:
                            # Mirror the escrow debit + sender credit that
                            # apply_block will execute.  Do NOT touch the L2
                            # tree here — dry_run must be side-effect-free on
                            # Layer2State (the finally block only restores
                            # storage accounts, not L2 tree mutations).
                            self.storage.debit_sat(L2_BRIDGE_ADDRESS, amount_sat)
                            self.storage.credit_sat(tx.sender, amount_sat)
                            # Add L2_BRIDGE_ADDRESS to touched so it's included
                            # in the snapshot restore at the end of the dry-run.
                            touched.add(L2_BRIDGE_ADDRESS)
                fee_pool_sat += fee_sat
                cur_nonce = self.storage.get_nonce(tx.sender)
                self.storage.set_nonce(tx.sender, max(cur_nonce, tx.nonce + 1))

            # Apply rewards exactly the same way apply_block will.
            tmp_block = Block(
                index=height, prev_hash=_candidate_prev_hash, transactions=transactions,
                miner_address=miner_address,
                difficulty=(self.get_difficulty()
                            if difficulty is None else float(difficulty)),
                timestamp=(int(time.time())
                           if timestamp is None else int(timestamp)),
            )
            self._distribute_rewards(tmp_block, fee_pool_sat)

            return self.storage.compute_state_root()
        finally:
            # ── Restore contract storage slot writes ──────────────────────────
            # Must run BEFORE restore_accounts so that update_contract_storage_root
            # (called below to revert storage_root columns) sees the original slots.
            try:
                for (addr, slot), orig_value in _slot_backup.items():
                    self.storage.sstore(addr, slot, orig_value)
                    _old_tag = _tag_backup.get((addr, slot))
                    self.storage.set_storage_tag(
                        addr, slot, int(_old_tag) if _old_tag is not None else 0)
                for addr in _touched_contracts:
                    try:
                        self.storage.update_contract_storage_root(addr)
                    except Exception as _csr_e:
                        log.debug(
                            "dry_run_state_root: storage_root restore "
                            "failed for %s: %s", addr, _csr_e)
            except Exception as _slot_e:
                log.error(
                    "CRITICAL: dry_run_state_root slot restore failed: %s — "
                    "contract storage_root may be stale; "
                    "node should be restarted.", _slot_e)

            # VVM-DRYRUN-FIX: restore any account rows whose addresses were
            # created dynamically by a simulated DEPLOY. This is separate from
            # contract_accounts cleanup because call-value balances live in the
            # ordinary accounts/balances table.
            try:
                if _dry_run_dynamic_accounts:
                    self.storage.restore_accounts(_dry_run_dynamic_accounts)
            except Exception as _dyn_acc_e:
                log.error(
                    "CRITICAL: dry_run_state_root dynamic account restore failed: %s — "
                    "live balance state may be contaminated; node should be restarted.",
                    _dyn_acc_e)

            # VVM-2 FIX: clean up contracts that vvm.deploy() created during
            # dry-run.  We must PHYSICALLY DELETE the row from
            # contract_accounts (not just flip destroyed=1), because the
            # SAME tx will be re-applied for real on this node when the
            # block lands, and apply_block uses INSERT OR IGNORE — a stale
            # destroyed=1 row would cause that INSERT to silently no-op,
            # leaving the new contract permanently destroyed and bricking
            # every future call to it.
            try:
                if self.storage._pgx_enabled:
                    for _dep_addr in _dry_run_deployed:
                        try:
                            self.storage._pg_exec(
                                "DELETE FROM contract_accounts WHERE address=$1",
                                _dep_addr)
                        except Exception:
                            pass
                        try:
                            with self.storage._aux_lock:
                                self.storage._conn().execute(
                                    "DELETE FROM contract_accounts WHERE address=?",
                                    (_dep_addr,))
                                self.storage._conn().commit()
                        except Exception:
                            pass
                else:
                    c = self.storage._conn()
                    for _dep_addr in _dry_run_deployed:
                        c.execute(
                            "DELETE FROM contract_accounts WHERE address=?",
                            (_dep_addr,))
                    c.commit()
            except Exception as _dep_outer:
                log.error(
                    "CRITICAL: dry_run_state_root deploy cleanup failed: %s",
                    _dep_outer)

            # VVM-2 FIX: un-destroy contracts that ran SELFDESTRUCT during
            # dry-run.  Those are real on-chain contracts whose destroyed
            # flag was set inside the dry-run to make compute_state_root
            # match what apply_block would compute — but since apply_block
            # has not committed the SELFDESTRUCT yet, we MUST clear the
            # flag again or future real calls will see the contract as
            # gone.  Done with a direct UPDATE because there is no public
            # un-destroy API (and we don't want to add one — un-destroy is
            # specifically a dry-run primitive, not a chain operation).
            if _dry_run_selfdestructed:
                try:
                    if self.storage._pgx_enabled:
                        for _sd in _dry_run_selfdestructed:
                            try:
                                self.storage._pg_exec(
                                    "UPDATE contract_accounts SET destroyed=FALSE "
                                    "WHERE address=$1", _sd)
                            except Exception:
                                pass
                            try:
                                with self.storage._aux_lock:
                                    self.storage._conn().execute(
                                        "UPDATE contract_accounts SET destroyed=0 "
                                        "WHERE address=?", (_sd,))
                                    self.storage._conn().commit()
                            except Exception:
                                pass
                    else:
                        c = self.storage._conn()
                        for _sd in _dry_run_selfdestructed:
                            c.execute(
                                "UPDATE contract_accounts SET destroyed=0 "
                                "WHERE address=?", (_sd,))
                        c.commit()
                except Exception as _und_e:
                    log.error(
                        "CRITICAL: dry_run_state_root selfdestruct un-destroy "
                        "failed: %s — contracts may be permanently disabled. "
                        "Node should be restarted.", _und_e)

            # Restore direct state-channel mutations BEFORE the broad initial
            # account snapshot. The journal covers channel-party accounts that
            # may have been discovered only during execution; restore_accounts(snap)
            # then restores every originally-touched account to its exact entry state.
            try:
                self.storage.end_state_channel_journal(_state_channel_journal)
                self.storage.restore_state_channel_journal(_state_channel_journal)
            except Exception as _sc_journal_e:
                log.error(
                    "CRITICAL: dry_run_state_root state-channel restore failed: %s — "
                    "live channel/account state may be contaminated; node should be restarted.",
                    _sc_journal_e)

            # ── ALWAYS restore account balances / nonces ──────────────────────
            try:
                self.storage.restore_accounts(snap)
            except Exception as _re:
                log.error(
                    "CRITICAL: dry_run_state_root restore failed: %s — "
                    "state may be corrupted; node should be restarted.", _re)

            # AUDIT-FIX (Batch D): restore the cumulative issuance counter
            # snapshotted above, undoing _distribute_rewards()'s
            # increment_cumulative_issued_sat() call so a dry run leaves this
            # meta value unchanged, matching the "chain state is unchanged
            # after this method returns" contract this function documents.
            try:
                self.storage.set_meta(
                    "cumulative_issued_sat", str(_cumulative_issued_snap))
            except Exception as _cre:
                log.error(
                    "CRITICAL: dry_run_state_root cumulative_issued_sat "
                    "restore failed: %s — node should be restarted.", _cre)

    # ── Blockchain rollback ───────────────────────────────────────────────
    def rollback(self, target_height: int) -> Tuple[bool, str]:
        """Roll the chain back to *target_height*, deleting every block above it.

        Procedure (executed under the global chain lock):
          1. Validate that target_height is within [0, current_height).
          2. Delete blocks from current_height down to target_height + 1.
          3. Recompute and store the authoritative state_root from the
             surviving ledger state (balances + contract accounts).
          4. Invalidate the DifficultyEngine cache from target_height
             onward so the next get_difficulty() reads fresh chain data.
          5. Return (True, summary_message) on success.

        The caller is responsible for:
          * Stopping mining BEFORE calling rollback (prevents new blocks
            from being appended mid-rollback).

        Rolled-back transactions are automatically restored to the mempool
        only after their confirmed-chain indexes are removed, so callers
        should not blindly clear the mempool after a successful rollback.

        Returns
        -------
        (bool, str) — (success_flag, human-readable status message)
        """
        with self._lock:
            current = self.height()

            # ── Guard: target must be strictly below current tip ───────
            if target_height < 0:
                return False, "Target height must be >= 0."
            if target_height >= current:
                return False, (
                    "Target height ({}) must be below "
                    "current tip ({}).".format(target_height, current))

            # Full transaction bodies below this watermark are not guaranteed
            # to exist after rolling pruning. Exact rollback therefore cannot be
            # performed safely; fail closed before touching any persistent state.
            try:
                _pruned_until = int(self._rolling_pruner.get_pruned_watermark())
            except Exception:
                _pruned_until = 0
            if _pruned_until and target_height < _pruned_until:
                return False, (
                    f"Rollback rejected: target height {target_height} is below "
                    f"the rolling-prune watermark {_pruned_until}. Full block "
                    "transaction data required for an exact rollback is no "
                    "longer guaranteed to be available.")

            # ── Verify the target block actually exists ────────────────
            target_block = self.storage.get_block(target_height)
            if target_block is None:
                return False, (
                    "Block at height {} not found in "
                    "storage — cannot rollback to a missing block.".format(
                        target_height))

            deleted = 0
            # ── Roll back blocks from tip down to target + 1 ──────────
            # BUG FIX: previously called storage.delete_block(h) directly,
            # which only removed the block record from DB/KV but NEVER
            # reversed the balance/reward/nonce mutations that apply_block
            # performed.  This caused height to decrease while balances
            # stayed at their post-block values — a state corruption that
            # caused state_root mismatches and made contract deploy/call
            # fail after rollback.
            #
            # Fix: call _rollback_block() for each block, which:
            #   1. Calls _rollback_rewards() to debit every reward credit.
            #   2. Reverses every transaction (credits sender, debits receiver).
            #   3. Restores VVM contract storage slots from the receipt delta.
            #   4. Re-adds transactions to the mempool for re-mining.
            #   5. Finally calls storage.delete_block() to remove the record.
            for h in range(current, target_height, -1):
                try:
                    blk = self.storage.get_block(h)
                    if blk is None:
                        log.warning("rollback: block %d not found, skipping", h)
                        deleted += 1
                        continue
                    self._rollback_block(blk)
                    deleted += 1
                except Exception as exc:
                    log.error("rollback: failed to rollback block %d: %s",
                              h, exc)
                    return False, (
                        "Error rolling back block {}: {}. "
                        "Rollback incomplete — {} blocks removed "
                        "before failure.".format(h, exc, deleted))

            # ── Recompute state_root from the surviving ledger ─────────
            # Now that balances have been correctly reversed, this root
            # will match target_block.state_root (no divergence warning).
            new_state_root = self.storage.compute_state_root()
            target_sr = getattr(target_block, "state_root", "")

            # ── Roll back the L2 tree to match the new L1 tip ─────────
            # _rollback_block() above already reversed each withdrawal tx's
            # L2_deposit() call (restoring individual L2 balances), but the
            # L2StateTree also keeps a confirmed-root history keyed by L1
            # height.  Rolling back that history ensures the next
            # RollupSubmission uses the correct previous_l2_root and that
            # reorg detection works correctly in Layer2State.
            try:
                layer2 = getattr(self, "layer2", None)
                if layer2 is not None:
                    ok_l2, msg_l2 = layer2.rollback_to_height(target_height)
                    if ok_l2:
                        log.info(
                            f"[ROLLBACK] L2 tree rolled back to height "
                            f"{target_height}: {msg_l2}")
                    else:
                        log.error(
                            f"[ROLLBACK] L2 rollback_to_height({target_height}) "
                            f"failed: {msg_l2}")
            except Exception as _l2_rb_e:
                log.error(f"[ROLLBACK] L2 tree rollback raised: {_l2_rb_e}")

            # ── Flush difficulty cache so next query reads fresh data ──
            try:
                DifficultyEngine.invalidate_cache(from_height=target_height)
            except Exception:
                pass   # non-fatal; cache will self-heal on next miss

            # ── Record the rollback event in node metadata ─────────────
            try:
                self.storage.set_meta(
                    "last_rollback",
                    json.dumps({
                        "from_height":  current,
                        "to_height":    target_height,
                        "deleted":      deleted,
                        "new_state_root": new_state_root,
                        "timestamp":    int(time.time()),
                    }))
            except Exception:
                pass  # metadata write failure is non-fatal

            new_height = self.height()  # re-read from storage

            summary = (
                "Rollback OK: {} -> {} "
                "({} blocks deleted). "
                "State root: {}...".format(
                    current, new_height, deleted,
                    new_state_root[:16]))
            if target_sr and target_sr != new_state_root:
                summary += (
                    "  WARNING: state_root divergence: target block "
                    "recorded {}... but live ledger "
                    "computes {}... — manual "
                    "inspection recommended.".format(
                        target_sr[:16], new_state_root[:16]))
                log.warning("ROLLBACK: %s", summary)
                # AUDIT-FIX-N2: a detected state-root divergence must not
                # share the same `return True` path as a clean rollback --
                # this was the one condition the check above exists to
                # catch, but the boolean success flag never reflected it
                # (only the message text did), so callers gating on the
                # flag (CLI._rollback_chain's "[OK]"/resume-mining prompt)
                # had no way to tell a genuinely clean rollback from one
                # that just proved the ledger no longer matches the target
                # block's recorded state.
                return False, summary
            log.warning("ROLLBACK: %s", summary)
            return True, summary

    # ── Apply block ───────────────────────────────────────────────────────────
    def _undo_vvm_block_effects(
            self, vvm_undo_log: List[dict],
            restore_state_channel_accounts: bool = True) -> None:
        """
        AUDIT-FIX-3 (state corruption / non-atomic contract storage):
        reverse every VVM transaction's contract-storage side effects
        recorded in ``vvm_undo_log``, restoring pre-block state.

        Call this from every apply_block() failure path — it is the
        missing counterpart to restore_accounts()/restore_roles()/
        _l2.restore_full(), which already undo balances/roles/L2 state on
        those same paths. Without it, a block that is ultimately rejected
        could still leave permanent contract-storage mutations on disk:
        Storage.sstore / save_contract / save_contract_code /
        update_contract_storage_root are all called directly by
        _apply_vvm_tx and commit immediately — they are not covered by
        the balance/role snapshot-restore mechanism, and
        Storage.restore_contract_slots() (which could undo them) was
        never actually wired into apply_block's failure paths before this
        fix. A transaction earlier in the block that individually
        succeeded, followed by a later transaction that forces the whole
        block out, would otherwise corrupt this node's future
        compute_state_root() relative to any peer that never attempted
        the same doomed block ordering.

        The reversal logic mirrors dry_run_state_root()'s own `finally`
        block, which performs the identical kind of "fully un-apply a set
        of VVM executions" work on every single candidate block a miner
        ever builds:
          • restore every touched slot to its pre-tx value;
          • PHYSICALLY DELETE newly-deployed contract rows rather than
            soft-deleting (destroyed=1) them — a soft delete would make a
            legitimate future re-deploy to the same address silently
            no-op against save_contract()'s INSERT OR IGNORE;
          • un-mark self-destructed contracts as live again, since the
            SELFDESTRUCT never actually lands on the canonical chain once
            this block is rejected;
          • recompute storage_root for every contract left with restored
            (not deleted) slots.

        vvm_undo_log is walked in REVERSE application order so that, if
        two transactions in the same block touched the same slot, the
        slot ends up at its true pre-block value rather than an
        intermediate one.
        """
        if not vvm_undo_log:
            return

        touched_contracts: Set[str] = set()
        deployed_addrs: List[str] = []
        selfdestructed_addrs: List[str] = []

        try:
            for undo in reversed(vvm_undo_log):
                _sc_undo = undo.get("state_channel_journal")
                if _sc_undo:
                    self.storage.restore_state_channel_journal(
                        _sc_undo,
                        restore_accounts=restore_state_channel_accounts)
                for (addr, slot), prev_val in undo.get("storage_delta", {}).items():
                    self.storage.sstore(addr, slot, prev_val)
                    prev_tag = undo.get("storage_tag_delta", {}).get((addr, slot))
                    self.storage.set_storage_tag(
                        addr, slot, int(prev_tag) if prev_tag is not None else 0)
                touched_contracts.update(undo.get("touched_contracts", ()))
                deployed_addrs.extend(undo.get("deployed", []))
                selfdestructed_addrs.extend(undo.get("selfdestructed", []))
        except Exception as _slot_e:
            log.error(
                "CRITICAL: apply_block VVM-undo slot restore failed: %s — "
                "contract storage may be left partially mutated by a "
                "rejected block. Node should be restarted.", _slot_e)

        # Physically delete newly-deployed contracts (see docstring for why
        # a soft destroyed=1 is not safe here). Mirrors the exact
        # dual-backend (Postgres + SQLite) pattern dry_run_state_root uses.
        try:
            if self.storage._pgx_enabled:
                for _dep_addr in deployed_addrs:
                    try:
                        self.storage._pg_exec(
                            "DELETE FROM contract_accounts WHERE address=$1",
                            _dep_addr)
                    except Exception:
                        pass
                    try:
                        with self.storage._aux_lock:
                            self.storage._conn().execute(
                                "DELETE FROM contract_accounts WHERE address=?",
                                (_dep_addr,))
                            self.storage._conn().commit()
                    except Exception:
                        pass
            else:
                c = self.storage._conn()
                for _dep_addr in deployed_addrs:
                    c.execute(
                        "DELETE FROM contract_accounts WHERE address=?",
                        (_dep_addr,))
                if deployed_addrs:
                    c.commit()
        except Exception as _dep_e:
            log.error(
                "CRITICAL: apply_block VVM-undo deploy cleanup failed: %s",
                _dep_e)
        # Deleted contracts don't need a storage_root recompute.
        touched_contracts.difference_update(deployed_addrs)

        # Un-mark self-destructed contracts as live again.
        if selfdestructed_addrs:
            try:
                if self.storage._pgx_enabled:
                    for _sd in selfdestructed_addrs:
                        try:
                            self.storage._pg_exec(
                                "UPDATE contract_accounts SET destroyed=FALSE "
                                "WHERE address=$1", _sd)
                        except Exception:
                            pass
                        try:
                            with self.storage._aux_lock:
                                self.storage._conn().execute(
                                    "UPDATE contract_accounts SET destroyed=0 "
                                    "WHERE address=?", (_sd,))
                                self.storage._conn().commit()
                        except Exception:
                            pass
                else:
                    c = self.storage._conn()
                    for _sd in selfdestructed_addrs:
                        c.execute(
                            "UPDATE contract_accounts SET destroyed=0 "
                            "WHERE address=?", (_sd,))
                    c.commit()
            except Exception as _und_e:
                log.error(
                    "CRITICAL: apply_block VVM-undo selfdestruct un-mark "
                    "failed: %s — contracts may be left permanently "
                    "destroyed. Node should be restarted.", _und_e)

        # Recompute storage_root for every contract left with restored
        # (as opposed to deleted) slots.
        for addr in touched_contracts:
            try:
                self.storage.update_contract_storage_root(addr)
            except Exception as _root_e:
                log.debug(
                    "apply_block VVM-undo: storage_root recompute failed "
                    "for %s: %s", addr, _root_e)

    def apply_block(self, block: Block) -> Tuple[bool, str]:
        """Apply one block atomically at the persistent-storage boundary.

        SQLite uses one database transaction.  PGX uses a PostgreSQL
        transaction covering all consensus state plus a durable canonical-tip
        marker, while RocksDB is written first and treated as canonical only
        after that PostgreSQL transaction commits.  Startup reconciliation
        removes RocksDB blocks above the committed PGX tip after a crash.
        """
        atomic_storage = self.storage
        if getattr(atomic_storage, "_pgx_enabled", False):
            with atomic_storage.pgx_atomic_block() as pgx_tx:
                result = self._apply_block_unwrapped(block)
                if result[0] and pgx_tx is not None:
                    pgx_tx["commit"] = True
            return result

        atomic_started = False
        atomic_storage.begin_sqlite_atomic_block()
        atomic_started = True
        try:
            result = self._apply_block_unwrapped(block)
        except BaseException:
            if atomic_started:
                atomic_storage.rollback_sqlite_atomic_block()
            raise
        if atomic_started:
            if result[0]:
                atomic_storage.commit_sqlite_atomic_block()
            else:
                atomic_storage.rollback_sqlite_atomic_block()
        return result

    def _apply_block_unwrapped(self, block: Block) -> Tuple[bool, str]:
        with self._lock:
            # DUPLICATE-BLOCK IDEMPOTENCY FIX:
            # A peer may relay the same block more than once.  Once a block
            # has already been successfully applied, re-running its state
            # mutations can change the local state root and make an otherwise
            # valid block fail on the second delivery.  Only short-circuit
            # The in-memory set closes the race before the caller records
            # block_apply:<height>.  The durable marker covers node restart.
            # A different hash is never short-circuited and still goes through
            # normal fork validation.
            existing_hash = self.storage.get_block_hash(block.index)
            applied_marker = self.storage.get_meta(f"block_apply:{block.index}")
            if (block.block_hash in self._applied_block_hashes
                    or (existing_hash == block.block_hash
                        and applied_marker == "ok")):
                return True, "Block already applied (idempotent duplicate)"

            ok, msg = self.validate_block(block)
            if not ok:
                return False, msg

            # ═══════════════════════════════════════════════════════════════════
            # GENESIS IDEMPOTENCY (v7.1.5)
            # -------------------------------------------------------------------
            # Genesis is now broadcast over the same MSG_BLOCK gossip path as
            # every other block (see Node.start() and P2PNetwork.broadcast_genesis).
            # When a peer receives our Genesis broadcast — or we receive theirs —
            # the block reaches apply_block() with index == 0.  validate_block()
            # has already confirmed the hash matches our canonical genesis (or
            # that no genesis is stored yet and the deterministic fields check
            # out via integrity_check()).
            #
            # If we ALREADY have a stored genesis whose hash matches the
            # incoming block, short-circuit here WITHOUT re-running state
            # mutation, _distribute_rewards, or save_block.  Running those a
            # second time would:
            #   • Double-save block 0 and rewrite tip metadata.
            #   • Re-invoke _distribute_rewards (genesis reward semantics are
            #     undefined — there is no prior chain state).
            #   • Trigger the touched-account snapshot/restore machinery
            #     needlessly on every gossip hop of genesis.
            #
            # Returning ok=True preserves the existing gossip semantics:
            # _handle_new_block() will still relay the message to other peers
            # (exclude=source_peer), and _seen_msgs LRU dedupes repeats so the
            # message dies naturally after one fan-out hop per node.
            # ═══════════════════════════════════════════════════════════════════
            if block.index == 0:
                existing_hash = self.storage.get_block_hash(0)
                if existing_hash == block.block_hash:
                    return True, "Genesis already present (idempotent)"
                # If existing is None we are a fresh node whose Blockchain.__init__
                # has not yet created genesis.  In that rare path (which
                # normally cannot occur because __init__ creates genesis
                # synchronously before the network is up), fall through to the
                # regular save path below so the peer-provided genesis is
                # persisted.  Determinism of GENESIS_* constants guarantees
                # byte-for-byte equality with what we would have built locally.

            block_start = time.time()

            # ═══════════════════════════════════════════════════════════════════
            # ATOMIC BLOCK APPLICATION (CRIT fix):
            #   apply_block previously mutated balances/nonces row-by-row with
            #   no transactional envelope.  If any tx after the first one
            #   triggered an error (insufficient balance due to a race,
            #   _distribute_rewards failure, save_block failure, ...) we
            #   returned False but the earlier mutations were permanent —
            #   corrupting state and breaking the conservation invariant.
            #
            # Fix: snapshot every address this block will touch BEFORE any
            # mutation.  On any exception or logical failure inside the
            # tx-application loop OR during _distribute_rewards, restore the
            # snapshot.  Same-block same-result on all nodes is preserved
            # because the snapshot captures the pre-state deterministically.
            # ═══════════════════════════════════════════════════════════════════
            touched = set()
            register_txs = []  # v7.2.0: collect REGISTER txs; applied after rewards
            for tx in block.transactions:
                if tx.sender:   touched.add(tx.sender)
                if tx.receiver: touched.add(tx.receiver)
                # A top-level DEPLOY can credit a deterministic contract address
                # that is not present in tx.receiver. Include that address in
                # the pre-block account snapshot so apply_block's atomic
                # failure path can restore the call-value balance as well as
                # the sender balance.
                if tx.tx_type == Transaction.TYPE_DEPLOY and tx.sender:
                    try:
                        touched.add(derive_contract_address(
                            tx.sender, tx.nonce, tx.tx_id))
                    except Exception:
                        # An invalid deploy will be rejected by transaction/VM
                        # validation; failure to derive a defensive snapshot
                        # must never make a block valid by itself.
                        pass
                if (tx.tx_type == Transaction.TYPE_REGISTER
                        and not Transaction.is_identity_claim(tx)):
                    register_txs.append(tx)
            # Reward recipients: miner + all registered validators + miners.
            if block.miner_address:
                touched.add(block.miner_address)
            for v in self.storage.get_all_by_role("investor"):
                touched.add(v["address"])
            for m in self.storage.get_all_by_role("miner"):
                touched.add(m["address"])
            touched.add(Config.BURN_ADDRESS)

            snap = self.storage.snapshot_accounts(touched)
            _cumulative_issued_snap_apply = self.storage.get_cumulative_issued_sat()

            def _restore_cumulative_issued_apply() -> None:
                """Restore the non-address issuance counter on block rejection."""
                try:
                    self.storage.set_meta(
                        "cumulative_issued_sat",
                        str(_cumulative_issued_snap_apply),
                    )
                except Exception as _e:
                    log.error(
                        "CRITICAL: failed to restore cumulative issuance "
                        "after rejected block #%s: %s", block.index, _e)
            # v7.2.0: also snapshot roles for REGISTER-tx addresses so a
            # mid-block failure rolls role mutations back along with balances.
            role_snap = self.storage.snapshot_roles(
                [tx.sender for tx in register_txs])
            # Persist the exact pre-block role state so a later chain rollback
            # (including after node restart) can restore the state that this
            # block actually replaced.  Reconstructing it from the post-block
            # state is unsafe for UNREGISTER, ignored REGISTERs, and slashed
            # validators.
            if role_snap:
                self.storage.record_block_role_snapshot(
                    block.index, block.block_hash, role_snap)

            # ── L2-4 FIX: snapshot Layer2State for full block atomicity ──
            # Layer2 can be mutated DURING apply_block by:
            #   • L2 bridge deposit hook (tree credit + persist)
            #   • L2 bridge withdraw hook (tree debit + persist + L1 escrow move)
            #   • TYPE_ROLLUP application (tree advance + commit_batch which
            #     appends to _history and bumps _last_batch_id)
            # Pre-fix, none of those mutations were rolled back if a LATER
            # tx in the same block failed.  apply_block would call
            # restore_accounts(snap) on the L1 side and return False — the
            # block was rejected — but the local L2 state retained the
            # mutation, drifting from the canonical chain and from peers.
            # Take the snapshot now so every failure path can restore it.
            _l2 = getattr(self, "layer2", None)
            l2_snap = _l2.snapshot_full() if _l2 is not None else None

            # ═══════════════════════════════════════════════════════════════════
            # TPS-OPT-2: BATCH PROXY
            # Swap self.storage with a batching proxy for the duration of block
            # application.  All credit_sat / debit_sat / set_nonce /
            # update_ht_volume calls are buffered in memory and flushed in ONE
            # atomic I/O operation (single PG transaction + single RocksDB
            # WriteBatch).  This cuts ~800 round-trips per 200-tx block to 1.
            # The proxy delegates all other methods (VVM, contract storage,
            # etc.) to the real Storage via __getattr__.
            # ═══════════════════════════════════════════════════════════════════
            _real_storage = self.storage
            self.storage = _StorageBatchProxy(_real_storage)  # type: ignore[assignment]

            try:
                # F-01 COMPLETION: fee_pool is integer satoshi — no float accumulation.
                fee_pool_sat = 0
                block_gas_used = 0
                # AUDIT-FIX-3: block-scoped log of every VVM tx's contract-
                # storage undo record, in application order. Replayed in
                # reverse by _undo_vvm_block_effects() on any failure path
                # below, so contract storage gets the same all-or-nothing
                # guarantee balances/roles/L2 state already have.
                _vvm_undo_log: List[dict] = []
                for tx in block.transactions:
                    if tx.sender == "COINBASE":
                        # The coinbase transaction is the canonical issuance record
                        # whose amount feeds the conservation invariant
                        # (SafetyInvariantChecker sums coinbase amounts as total_issued).
                        # DO NOT credit the receiver here — _distribute_rewards() is
                        # the sole authoritative issuer and will credit all parties
                        # according to the tokenomics split.  Crediting here AND in
                        # _distribute_rewards was the double-credit bug that caused
                        # held+staked > total_issued (13.75 VSD discrepancy per 5 blocks).
                        continue

                    # ── VVM transaction routing ────────────────────────────────────
                    if tx.tx_type in (Transaction.TYPE_DEPLOY, Transaction.TYPE_CALL):
                        gas_fee_sat, vvm_ok, vvm_undo = self._apply_vvm_tx(tx, block)
                        if vvm_undo:
                            _vvm_undo_log.append(vvm_undo)
                        fee_pool_sat += gas_fee_sat
                        block_gas_used += tx.gas_limit  # actual tracked in receipt
                        self.storage.update_ht_volume(tx.sender, tx.amount)
                        current_nonce = self.storage.get_nonce(tx.sender)
                        self.storage.set_nonce(tx.sender, max(current_nonce, tx.nonce + 1))
                        continue

                    # ── v7.2.0 REGISTER transaction (on-chain role change) ─────────
                    # Collect fee and advance nonce now, but DEFER the actual
                    # role mutation until after _distribute_rewards so that
                    # the new registration only becomes effective at block
                    # N+1.  The role change is applied in the post-rewards
                    # loop below using ``register_txs``.
                    if tx.tx_type == Transaction.TYPE_REGISTER:
                        fee_sat = tx.compute_fee_sat()
                        if fee_sat > 0:
                            if not self.storage.debit_sat(tx.sender, fee_sat):
                                self.storage = _real_storage
                                self.storage.restore_accounts(snap)
                                self.storage.restore_roles(role_snap)
                                if _l2 is not None: _l2.restore_full(l2_snap)
                                # AUDIT-FIX-3: undo any VVM contract-storage
                                # effects from transactions that succeeded
                                # earlier in this block before this failure.
                                self._undo_vvm_block_effects(
                                    _vvm_undo_log, restore_state_channel_accounts=False)
                                _restore_cumulative_issued_apply()
                                return False, (
                                    f"REGISTER fee debit failed for "
                                    f"{tx.sender[:12]}")
                            fee_pool_sat += fee_sat
                        current_nonce = self.storage.get_nonce(tx.sender)
                        self.storage.set_nonce(tx.sender, max(current_nonce, tx.nonce + 1))
                        continue

                    # ── v7.5.0-OPT L2 ROLLUP SUBMISSION ────────────────────
                    # TYPE_ROLLUP carries a RollupSubmission JSON in tx.data.
                    # If verification fails the ENTIRE BLOCK is rejected —
                    # the caller below snapshots/restores so partial state
                    # mutations from earlier txs in the same block are
                    # rolled back.  Balance impact: 0 (the settlement tx
                    # moves no L1 balances itself; deposits/withdrawals are
                    # separate L1 transfers to L2_BRIDGE_ADDRESS).
                    if tx.tx_type == Transaction.TYPE_ROLLUP:
                        ok_r, msg_r = self._apply_rollup_tx(tx, block)
                        if not ok_r:
                            # MEMPOOL-1 part 2: do NOT reject the whole block
                            # for a failing rollup tx.  Pre-fix, ANY rollup
                            # failure caused the entire block (including all
                            # other users' txs in it) to be rejected — a free
                            # block-DoS for anyone who can submit a stale
                            # rollup.  Now we skip the failing rollup, remove
                            # it from the local mempool so it doesn't get
                            # re-mined, and continue applying the remaining
                            # txs in the block.
                            #
                            # Consensus safety: every node sees the same
                            # block, runs the same _apply_rollup_tx against
                            # the same layer2 state at this point, and
                            # reaches the same skip decision deterministically.
                            # The block's state_root is computed by the miner
                            # via dry_run, which has matching skip semantics
                            # (dry_run does NOT call _apply_rollup_tx — it
                            # only bumps the nonce + charges the (0) fee, so
                            # the state_root reflects "rollup nonce-bumped
                            # but not applied", same as we'll produce here).
                            log.info(
                                f"[ROLLUP-SKIP] tx {tx.tx_id[:12]}... "
                                f"rejected by _apply_rollup_tx ({msg_r}); "
                                f"skipping and removing from mempool — block "
                                f"otherwise valid.")
                            try:
                                self.mempool.remove(tx.tx_id)
                            except Exception as _mp_err:
                                log.debug(
                                    f"[ROLLUP-SKIP] mempool.remove failed: "
                                    f"{_mp_err}")
                            metrics.inc("rollup_txs_skipped")
                            # Bump nonce + (zero) fee path so the dry_run /
                            # apply_block state-root parity (see TYPE_ROLLUP
                            # branch in dry_run_state_root) holds: dry_run
                            # always nonce-bumps without applying the rollup.
                            fee_sat = tx.compute_fee_sat()
                            if fee_sat > 0:
                                if not self.storage.debit_sat(tx.sender, fee_sat):
                                    self.storage = _real_storage
                                    self.storage.restore_accounts(snap)
                                    self.storage.restore_roles(role_snap)
                                    if _l2 is not None: _l2.restore_full(l2_snap)
                                    # AUDIT-FIX-3: undo any VVM contract-storage
                                    # effects from transactions that succeeded
                                    # earlier in this block before this failure.
                                    self._undo_vvm_block_effects(
                                        _vvm_undo_log, restore_state_channel_accounts=False)
                                    _restore_cumulative_issued_apply()
                                    return False, (
                                        f"Rollup-skip fee debit failed for "
                                        f"{tx.sender[:12]}")
                                fee_pool_sat += fee_sat
                            current_nonce = self.storage.get_nonce(tx.sender)
                            self.storage.set_nonce(tx.sender,
                                                   max(current_nonce, tx.nonce + 1))
                            continue
                        # Sender still pays the fee (cost of L1 settlement)
                        # and nonce still advances so the sequencer's next
                        # submission has a fresh nonce.  amount is always 0
                        # for TYPE_ROLLUP, so fee_sat is 0 too — but we
                        # compute it via the canonical path so any future
                        # fee policy change picks us up automatically.
                        fee_sat = tx.compute_fee_sat()
                        if fee_sat > 0:
                            if not self.storage.debit_sat(tx.sender, fee_sat):
                                self.storage = _real_storage
                                self.storage.restore_accounts(snap)
                                self.storage.restore_roles(role_snap)
                                if _l2 is not None: _l2.restore_full(l2_snap)
                                # AUDIT-FIX-3: undo any VVM contract-storage
                                # effects from transactions that succeeded
                                # earlier in this block before this failure.
                                self._undo_vvm_block_effects(
                                    _vvm_undo_log, restore_state_channel_accounts=False)
                                _restore_cumulative_issued_apply()
                                return False, (
                                    f"Rollup fee debit failed for "
                                    f"{tx.sender[:12]}")
                            fee_pool_sat += fee_sat
                        current_nonce = self.storage.get_nonce(tx.sender)
                        self.storage.set_nonce(tx.sender,
                                               max(current_nonce, tx.nonce + 1))
                        continue

                    # ── Standard transfer (satoshi integer arithmetic) ─────────────
                    fee_sat = tx.compute_fee_sat()
                    amount_sat = to_satoshi(tx.amount)
                    total_debit_sat = amount_sat + fee_sat
                    if not self.storage.debit_sat(tx.sender, total_debit_sat):
                        # CRIT fix: roll back everything this block touched
                        self.storage = _real_storage
                        self.storage.restore_accounts(snap)
                        self.storage.restore_roles(role_snap)
                        if _l2 is not None: _l2.restore_full(l2_snap)
                        # AUDIT-FIX-3: undo any VVM contract-storage
                        # effects from transactions that succeeded
                        # earlier in this block before this failure.
                        self._undo_vvm_block_effects(
                            _vvm_undo_log, restore_state_channel_accounts=False)
                        _restore_cumulative_issued_apply()
                        return False, f"Balance error for {tx.sender[:12]}"
                    # AUDIT-FIX (Batch D): broadcasting to VSD_GLOBAL_MARKET
                    # used to skip crediting the amount anywhere -- destroying
                    # it outright, which get_burned_satoshi()'s own docstring
                    # says this chain never does ("tracks burns by crediting
                    # Config.BURN_ADDRESS rather than destroying funds
                    # outright"). Route it to the burn address instead, the
                    # same sink every other burn on this chain uses, so
                    # sum_all_balances_satoshi() stays in sync with
                    # get_total_issued_satoshi() instead of permanently
                    # losing amount_sat from every broadcast.
                    if tx.receiver != "VSD_GLOBAL_MARKET":
                        self.storage.credit_sat(tx.receiver, amount_sat)
                    else:
                        self.storage.credit_sat(Config.BURN_ADDRESS, amount_sat)
                    # ── v7.5.0-OPT L2 BRIDGE DEPOSIT HOOK ────────────────
                    # If this transfer targets the L2_BRIDGE_ADDRESS, the
                    # L1 side has just been credited (escrow).  Mirror the
                    # credit on the L2 tree for tx.sender so the user has
                    # spendable L2 balance.  Pure integer math.  Failure
                    # to mirror is non-fatal (L1 is the truth; the supply
                    # invariant check will eventually surface drift) but
                    # is logged loudly.
                    if tx.receiver == L2_BRIDGE_ADDRESS and amount_sat > 0:
                        # L2-1 FIX: if L2_deposit fails or raises, roll back
                        # the L1 escrow credit so the user does not lose
                        # funds.  Pre-fix code only logged the error and
                        # left the L1 credit in place — the bridge balance
                        # would diverge from total L2 supply (invariant
                        # violation) AND the user's deposit amount would be
                        # stranded in L2_BRIDGE_ADDRESS with no matching L2
                        # balance.  In practice L2_deposit's pre-conditions
                        # (int amount, positive, address non-empty) are all
                        # already met by the caller, so this branch should
                        # never fire — but if it ever does, atomic rejection
                        # is the only safe answer.
                        layer2 = getattr(self, "layer2", None)
                        if layer2 is not None:
                            _l2_failed = False
                            _l2_err    = ""
                            try:
                                ok_d, msg_d = layer2.L2_deposit(
                                    tx.sender, amount_sat,
                                    l1_height=block.index,
                                    l1_block_hash=block.block_hash)
                                if not ok_d:
                                    _l2_failed = True
                                    _l2_err    = msg_d
                            except Exception as _dep_e:
                                _l2_failed = True
                                _l2_err    = f"exception: {_dep_e}"
                            if _l2_failed:
                                log.error(
                                    f"[L2-BRIDGE] L2_deposit({tx.sender[:12]}, "
                                    f"{amount_sat}) failed: {_l2_err} — "
                                    f"rolling back L1 to maintain bridge "
                                    f"invariant.")
                                self.storage = _real_storage
                                self.storage.restore_accounts(snap)
                                self.storage.restore_roles(role_snap)
                                if _l2 is not None: _l2.restore_full(l2_snap)
                                # AUDIT-FIX-3: undo any VVM contract-storage
                                # effects from transactions that succeeded
                                # earlier in this block before this failure.
                                self._undo_vvm_block_effects(
                                    _vvm_undo_log, restore_state_channel_accounts=False)
                                _restore_cumulative_issued_apply()
                                return False, (
                                    f"L2 deposit rejected: {_l2_err}")
                    # ── L2 → L1 WITHDRAWAL HOOK ───────────────────────────
                    # If this transfer targets L2_WITHDRAW_ADDRESS the user
                    # is requesting a forced-exit from L2.  The L1 transfer
                    # already debited tx.sender and credited L2_WITHDRAW_ADDRESS
                    # (which acts as a burn sink for the routing amount).
                    # We now:
                    #   1. Debit tx.sender's L2 tree balance.
                    #   2. Debit L2_BRIDGE_ADDRESS escrow by amount_sat
                    #      and credit tx.sender's L1 wallet — net effect:
                    #      sender gets their money back on L1, and the
                    #      L2_WITHDRAW_ADDRESS acts as a routing/burn address
                    #      for the L1 routing amount (which came from sender).
                    # Because this runs inside apply_block the L2 root
                    # mutation is part of the same atomic block application
                    # and will be captured in the next RollupSubmission's
                    # previous_l2_root — no state-root mismatch is possible.
                    # Failure is FATAL for this tx (block is rejected) to
                    # prevent partial state where L1 credits without L2 debit.
                    elif tx.receiver == L2_WITHDRAW_ADDRESS and amount_sat > 0:
                        try:
                            layer2 = getattr(self, "layer2", None)
                            if layer2 is None:
                                # L2 not active — refund sender, reject block.
                                self.storage = _real_storage
                                self.storage.restore_accounts(snap)
                                self.storage.restore_roles(role_snap)
                                if _l2 is not None: _l2.restore_full(l2_snap)
                                # AUDIT-FIX-3: undo any VVM contract-storage
                                # effects from transactions that succeeded
                                # earlier in this block before this failure.
                                self._undo_vvm_block_effects(
                                    _vvm_undo_log, restore_state_channel_accounts=False)
                                _restore_cumulative_issued_apply()
                                return False, "L2 withdrawal rejected: L2 subsystem not initialised"
                            # Step 1: debit L2 tree.
                            ok_w, msg_w = layer2.L2_withdraw(tx.sender, amount_sat,
                                                           l1_height=block.index,
                                                           l1_block_hash=block.block_hash)
                            if not ok_w:
                                self.storage = _real_storage
                                self.storage.restore_accounts(snap)
                                self.storage.restore_roles(role_snap)
                                if _l2 is not None: _l2.restore_full(l2_snap)
                                # AUDIT-FIX-3: undo any VVM contract-storage
                                # effects from transactions that succeeded
                                # earlier in this block before this failure.
                                self._undo_vvm_block_effects(
                                    _vvm_undo_log, restore_state_channel_accounts=False)
                                _restore_cumulative_issued_apply()
                                return False, (f"L2 withdrawal rejected for "
                                               f"{tx.sender[:12]}: {msg_w}")
                            # Step 2: debit bridge escrow, credit sender on L1.
                            if not self.storage.debit_sat(L2_BRIDGE_ADDRESS, amount_sat):
                                # Roll back L2 debit.
                                layer2.L2_deposit(tx.sender, amount_sat)
                                self.storage = _real_storage
                                self.storage.restore_accounts(snap)
                                self.storage.restore_roles(role_snap)
                                if _l2 is not None: _l2.restore_full(l2_snap)
                                # AUDIT-FIX-3: undo any VVM contract-storage
                                # effects from transactions that succeeded
                                # earlier in this block before this failure.
                                self._undo_vvm_block_effects(
                                    _vvm_undo_log, restore_state_channel_accounts=False)
                                _restore_cumulative_issued_apply()
                                return False, (f"L2 withdrawal rejected: bridge "
                                               f"escrow debit failed for "
                                               f"{tx.sender[:12]}")
                            self.storage.credit_sat(tx.sender, amount_sat)
                            log.info(f"[L2-BRIDGE] L2→L1 withdrawal confirmed: "
                                     f"{tx.sender[:12]} {amount_sat:,} sat")
                            try:
                                metrics.inc("l2_withdrawals_l1")
                                metrics.set_gauge("l2_total_supply_sat",
                                                  layer2.total_supply_sat())
                            except Exception:
                                pass
                        except Exception as _wdraw_e:
                            log.error(f"[L2-BRIDGE] withdrawal hook raised: {_wdraw_e}")
                            self.storage = _real_storage
                            self.storage.restore_accounts(snap)
                            self.storage.restore_roles(role_snap)
                            if _l2 is not None: _l2.restore_full(l2_snap)
                            # AUDIT-FIX-3: undo any VVM contract-storage
                            # effects from transactions that succeeded
                            # earlier in this block before this failure.
                            self._undo_vvm_block_effects(
                                _vvm_undo_log, restore_state_channel_accounts=False)
                            _restore_cumulative_issued_apply()
                            return False, f"L2 withdrawal hook exception: {_wdraw_e}"
                    fee_pool_sat += fee_sat
                    self.storage.update_ht_volume(tx.sender, tx.amount)
                    # Advance per-account nonce on confirmation
                    if tx.sender != "COINBASE":
                        current_nonce = self.storage.get_nonce(tx.sender)
                        self.storage.set_nonce(tx.sender, max(current_nonce, tx.nonce + 1))

                self._distribute_rewards(block, fee_pool_sat)

                # ── v7.2.0 APPLY REGISTER TX ROLE CHANGES AFTER REWARDS ─────
                # Rewards at block N use the role set as-of END of block N-1.
                # REGISTER txs inside block N therefore take effect at N+1 —
                # which is exactly the semantics we need for consensus
                # determinism.  Every node applies the same REGISTER txs in
                # the same block; after this loop, every node's role table
                # is identical going into block N+1's reward calculation.
                for tx in register_txs:
                    # Identity claims use the TYPE_REGISTER envelope but must
                    # never mutate the miner/investor role table.
                    if Transaction.is_identity_claim(tx):
                        continue
                    role = (tx.memo or "").strip().lower()
                    if role not in ("miner", "investor", "none"):
                        # Invalid role → treat as unstake (safest default).
                        role = "none"
                    if role == "none":
                        # Storage.set_role() preserves an existing slash marker
                        # when clearing the active role, so REGISTER("none")
                        # cannot be used as a self-unslash operation.
                        self.storage.set_role(tx.sender, "none", 0.0)
                    else:
                        # Validate miner/investor mutual exclusion.
                        role_existing = self.storage.get_role(tx.sender)
                        if role_existing and role_existing.get("role") == "miner" and role == "investor":
                            # Silently ignored — miners can't become investors.
                            continue
                        if role_existing and role_existing.get("role") == "investor" and role == "miner":
                            continue
                        # AUDIT-FIX-12 (slashing trivially reversible):
                        # a currently-slashed address cannot re-register via
                        # this ordinary path at all. The storage writer also
                        # preserves slashed=TRUE when REGISTER("none") clears
                        # the active role, so the unregister transition cannot
                        # be chained into a self-unslash + re-registration.
                        if role_existing and role_existing.get("slashed"):
                            log.warning(
                                f"REGISTER tx {tx.tx_id[:8]} from slashed "
                                f"address {tx.sender[:12]} ignored — "
                                f"re-registration does not clear slashed "
                                f"status")
                            continue
                        # Additive stake semantics: if already registered with
                        # the same role, accumulate; otherwise create.
                        cur_stake = float(role_existing.get("stake", 0.0)) if (
                            role_existing and role_existing.get("role") == role) else 0.0
                        new_stake = cur_stake + float(tx.amount)
                        self.storage.set_role(tx.sender, role, new_stake)

                # ─────────────────────────────────────────────────────────
                # v7.1.9 OPTION-A FIX: state_root is CONSENSUS-CRITICAL.
                #
                # Before the fix, this block did:
                #     state_root = self.storage.compute_state_root()
                #     block.state_root = state_root
                # That mutated the block AFTER PoW had already sealed the
                # header.  Receivers recomputed block_hash with the new
                # state_root and got a DIFFERENT hash from the one in the
                # message → integrity_check rejected every block → sync
                # universally broken.
                #
                # New behaviour: VERIFY the block's declared state_root
                # matches what we computed locally.  This is the actual
                # consensus check state_root is meant to provide.
                #
                # Genesis (index == 0) is exempt: its state_root is "" by
                # construction (no prior state to commit to) and its
                # GENESIS_IDEMPOTENCY short-circuit above already returned
                # before we ever reach this code path.
                #
                # Backward-compat: blocks with state_root == "" (legacy
                # candidates from pre-v7.1.9 nodes during the upgrade
                # window) are accepted with a warning so a mixed-version
                # network can complete the rollout.  Once all peers run
                # v7.1.9+, every new block will have state_root set and
                # any mismatch is treated as a hard reject.
                # ─────────────────────────────────────────────────────────
                computed_state_root = self.storage.compute_state_root()
                if block.state_root == "":
                    log.warning(
                        f"Block #{block.index} has empty state_root "
                        f"(pre-v7.1.9 miner?).  Accepting for upgrade "
                        f"compatibility but this path will be removed.")
                elif block.state_root != computed_state_root:
                    # CONSENSUS FAILURE: roll back and reject.
                    # AUDIT-FIX (Batch D): restore_all_touched() must run
                    # while self.storage still refers to the proxy, BEFORE
                    # the reassignment below -- it restores every address the
                    # proxy touched, including ones outside the pre-computed
                    # snap set (a freshly deployed contract's address, a
                    # SELFDESTRUCT beneficiary) that snapshot_accounts()
                    # could never have known about in advance. This matters
                    # specifically here because compute_state_root() just
                    # above already flushed the proxy's buffered writes to
                    # real storage, so without this call such a credit would
                    # permanently survive this "rejected" block.
                    self.storage.restore_all_touched()
                    self.storage = _real_storage
                    self.storage.restore_accounts(snap)
                    self.storage.restore_roles(role_snap)
                    if _l2 is not None: _l2.restore_full(l2_snap)
                    # AUDIT-FIX-3: undo any VVM contract-storage
                    # effects from transactions that succeeded
                    # earlier in this block before this failure.
                    self._undo_vvm_block_effects(
                        _vvm_undo_log, restore_state_channel_accounts=False)
                    _restore_cumulative_issued_apply()
                    return False, (
                        f"state_root mismatch at #{block.index}: "
                        f"declared={block.state_root[:16]}... "
                        f"computed={computed_state_root[:16]}... "
                        f"(Option-A consensus check)")
                # Note: we no longer assign block.state_root.  It was
                # populated by build_candidate_block and sealed by
                # mine()/seal().  The _SEALED_FIELDS guard would in fact
                # raise AttributeError if we tried to write to it now.

                # ── Protocol version signal (Problem #13) ─────────────────────────
                self._proto_mgr.record_block_version(block.protocol_version, block.index)

                # ── Finality: unfinalized until BFT threshold met ─────────────────
                # (or POW_FINALITY_DEPTH confirmations if no investors)
                block.finalized = False
                self.storage.save_block(block)

            except Exception as _exc:
                _restore_cumulative_issued_apply()
                # ANY exception in the tx-application or reward path leaves
                # state partially mutated. Roll back to the pre-block snapshot
                # so the node can cleanly reject the block without corruption.
                # TPS-OPT-2: restore real storage first (proxy may be dirty)
                # AUDIT-FIX (Batch D): same rationale as the state_root-
                # mismatch branch above -- this handler also covers
                # exceptions raised AFTER compute_state_root()'s flush (e.g.
                # during record_block_version/save_block), where a
                # proxy-buffered credit to an address outside the
                # pre-computed snap set would otherwise have already reached
                # real storage with nothing left to reverse it. Guarded:
                # if an inner handler already reassigned self.storage to
                # _real_storage before raising further, there is no proxy
                # left to restore from and nothing more to do here.
                try:
                    self.storage.restore_all_touched()
                except Exception:
                    pass
                self.storage = _real_storage
                try:
                    self.storage.restore_accounts(snap)
                    self.storage.restore_roles(role_snap)
                    if _l2 is not None: _l2.restore_full(l2_snap)
                    # AUDIT-FIX-3: undo any VVM contract-storage effects
                    # from transactions that succeeded earlier in this
                    # block before the exception was raised.
                    self._undo_vvm_block_effects(
                        _vvm_undo_log, restore_state_channel_accounts=False)
                except Exception as _rb_exc:
                    log.error("CRITICAL: restore failed during "
                              "apply_block rollback: %s", _rb_exc)
                log.error("apply_block exception at height %d: %s",
                          block.index, _exc)
                _restore_cumulative_issued_apply()
                return False, f"Exception in apply_block: {_exc}"

            # TPS-OPT-2: restore real storage reference now that the proxy's
            # batch has been flushed (inside compute_state_root → flush()).
            self.storage = _real_storage

            # Check if block already achieves BFT finality via existing sigs
            self._maybe_finalize_by_bft(block)
            # Check PoW depth finality (fallback for no-investor networks)
            self._maybe_finalize_by_depth(block.index)

            confirmed_ids = [tx.tx_id for tx in block.transactions]
            self.mempool.clear_confirmed(confirmed_ids)
            # STALE-NONCE FIX: clear_confirmed() only removes the block's own
            # tx_ids.  A competing pending tx (same sender, same nonce, different
            # tx_id) is now unmineable and would otherwise poison this sender's
            # nonce accounting until it expires.  Never raises.
            self.mempool.purge_stale_nonces(
                {tx.sender for tx in block.transactions
                 if tx.sender != "COINBASE"})

            # ── Base fee update (Problem #7 — dynamic fee market) ─────────────
            max_bytes  = self.get_dynamic_block_size()
            block_size = len(json.dumps(block.to_dict()).encode())
            fill_ratio = block_size / max_bytes if max_bytes > 0 else 0.0
            self.mempool.update_base_fee(fill_ratio)

            # ── Metrics (Problem #11) ─────────────────────────────────────────
            elapsed = time.time() - block_start
            metrics.inc("blocks_applied")
            metrics.set_gauge("chain_height",  block.index)
            metrics.set_gauge("difficulty",    block.difficulty)
            metrics.set_gauge("mempool_size",  self.mempool.size())
            metrics.record_block_time(elapsed)

            # ── Fix #8: Feed block timestamp into network clock ───────────────
            # Maintain the network time estimate by recording every applied
            # block's timestamp.  This feeds the NetworkClock median and
            # enables drift detection vs the local system clock.
            network_clock.record_block_timestamp(block.timestamp)

            # ── Economic monitoring (Problem #15) ─────────────────────────────
            if block.miner_address:
                self._eco_mon.record_reward(block.miner_address,
                                            self.compute_reward(block.index))
            self._eco_mon.record_block_fees(from_satoshi(fee_pool_sat))

            # ── Local Transaction Indexer (vsd_personal_ledger) ───────────────
            # Archive owner-related transactions before the block may be pruned
            # by the rolling-window pruner below.  sync_local_ledger dispatches
            # all file I/O to a daemon thread — zero latency on this path.
            # Set OWNER_ADDRESS to your VSD address to enable archiving.
            # Leave as "" to disable (the function returns instantly on "").
            _OWNER_ADDRESS: str = os.environ.get("VSD_LEDGER_OWNER", "")
            sync_local_ledger(block, _OWNER_ADDRESS)

            # ── v7.4.0: Rolling window pruning (background, non-blocking) ─────
            self._rolling_pruner.prune_async(block.index)

            # ── v7.4.0: State snapshot at every SNAPSHOT_INTERVAL blocks ──────
            # Fires in a daemon thread; never delays block application.
            _snap_root = getattr(block, "state_root", "") or ""
            self._snapshot_engine.maybe_snapshot(
                block.index, _snap_root, state_lock=self._lock
            )

            # ── v7.7.0: Rate defection audit ──────────────────────────────────
            # Run an audit cycle (no-op unless we're at a cadence boundary
            # AND we have a registry).  The auditor handles all timing,
            # registry-staleness, and observe-only behaviour internally.
            # We pass a function-call to fetch the registry rather than
            # the registry itself, because the registry must be live at
            # audit time and may change between block apply and audit.
            try:
                self._maybe_run_rate_audit(block.index)
            except Exception as exc:
                log.debug(f"[RateAudit] cycle skipped: {exc}")

            self._applied_block_hashes.add(block.block_hash)
            return True, "OK"

    def _apply_rollup_tx(self, tx: 'Transaction',
                         block: 'Block') -> Tuple[bool, str]:
        """Apply a TYPE_ROLLUP transaction.

        Steps
        ─────
        1. Parse the RollupSubmission from tx.data.
        2. Structural check (sizes, non-empty roots, etc.).
        3. Stateful root check: submission.previous_l2_root must equal
           the CURRENT layer2 root — otherwise this batch was built
           against a stale view and must be rejected so the sequencer
           rebuilds.
        4. Decompress the DA blob and RE-EXECUTE every L2 tx against a
           snapshot of Layer2State.  The resulting root must equal the
           submission's new_l2_root.  This is the safety net that makes
           even a broken IProofBackend unable to corrupt state — a real
           ZK verifier makes this redundant, but belt-and-suspenders
           is cheap and the simulated backend REQUIRES it.
        5. Invoke the L2_VERIFIER precompile for the proof check.  If
           the precompile returns False, revert the layer2 mutation and
           fail.
        6. Commit the batch in Layer2State (records the new confirmed
           root with an L1-height-bound snapshot for reorg rollback).

        Called under self._lock (apply_block holds it), so the check-then-
        mutate sequence against layer2 is race-free as long as Layer2State
        mutations outside apply_block also respect either _lock or the
        layer2 internal lock.

        All balance / nonce arithmetic inside Layer2State is pure
        integer satoshi.
        """
        # ── 1. Parse ─────────────────────────────────────────────────────
        try:
            submission = RollupSubmission.from_json(tx.data or "")
        except Exception as e:
            return False, f"malformed RollupSubmission: {e}"

        # ── 2. Structural ────────────────────────────────────────────────
        ok, msg = submission.structural_ok()
        if not ok:
            return False, msg

        # ── 3. Stateful root match ───────────────────────────────────────
        layer2 = getattr(self, "layer2", None)
        if layer2 is None:
            return False, "Layer2State not initialised on this node"
        current_root = layer2.root()
        if submission.previous_l2_root != current_root:
            return False, (
                f"stale rollup: submission.prev={submission.previous_l2_root[:16]}, "
                f"chain L2 root={current_root[:16]}")

        # ── 4. Re-execute under a pre-mutation snapshot ─────────────────
        # Take a full snapshot so any re-execution failure leaves Layer2State
        # exactly as it was.  Snapshot cost is O(account_count) — acceptable
        # because rollup settlements are infrequent (every few L1 blocks)
        # and the account set is bounded.
        try:
            l2_txs = RollupSubmission.decompress_batch(submission.compressed_data)
        except Exception as e:
            return False, f"bad compressed_data: {e}"
        if len(l2_txs) > Config.L2_MAX_BATCH_SIZE:
            return False, (f"batch too large: {len(l2_txs)} > "
                           f"{Config.L2_MAX_BATCH_SIZE}")

        # ── BUG-FIX (v7.7.1): hold layer2._lock for the ENTIRE re-execution
        # span, not just per-tx.  Without this, the Sequencer's seal_batch
        # path (which also takes layer2._lock per-tx) can interleave its own
        # apply_l2_tx calls between ours, mutating the tree mid-replay.  Our
        # pre-snap would then be stale relative to those interleaved muta-
        # tions and a rollback would clobber the Sequencer's work too.
        # apply_l2_tx uses an RLock so the inner re-acquisitions are free.
        with layer2._lock:
            pre_snap = layer2._tree.snapshot()
            try:
                for i, l2tx in enumerate(l2_txs):
                    ok_apply, apply_msg = layer2.apply_l2_tx(l2tx)
                    if not ok_apply:
                        # Roll back partial mutations and reject.
                        layer2._tree.restore(pre_snap)
                        return False, (f"re-execution failed at tx {i}: "
                                       f"{apply_msg}")
                computed_root = layer2.root()
                if computed_root != submission.new_l2_root:
                    layer2._tree.restore(pre_snap)
                    return False, (
                        f"new_root mismatch: re-exec={computed_root[:16]}, "
                        f"submission={submission.new_l2_root[:16]}")
            except Exception as e:
                # Any unexpected error — roll back and fail.  Never leave L2
                # in a mid-apply state.
                try:
                    layer2._tree.restore(pre_snap)
                except Exception:
                    log.error("CRITICAL: layer2 snapshot restore failed after "
                              "re-exec exception; L2 state may be inconsistent")
                return False, f"re-execution raised: {e}"

            # ── 5. Proof verification via L2_VERIFIER precompile ───────────
            # Held under layer2._lock so the post-mutation tree state cannot
            # be observed externally if we end up rolling back.
            batch_h = RollupSubmission.batch_hash(submission.compressed_data)
            calldata = json.dumps({
                "previous_l2_root": submission.previous_l2_root,
                "new_l2_root":      submission.new_l2_root,
                "batch_hash":       batch_h,
                "zk_proof":         submission.zk_proof.hex(),
                "backend":          submission.backend,
            }, separators=(",", ":"), sort_keys=True).encode("utf-8")
            # Budget: 2 million gas for proof verification — generous even
            # for STARK-sized proofs.
            verify_budget = 2_000_000
            ok_v, ret_v, gas_v = VVMPrecompiles.execute(
                VVMPrecompiles.L2_VERIFIER, calldata, verify_budget)
            if not ok_v:
                # Roll back L2.  Return data contains the 4-byte tag for
                # diagnostics.
                try:
                    layer2._tree.restore(pre_snap)
                except Exception:
                    log.error("CRITICAL: layer2 restore failed after verifier "
                              "rejection; L2 state may be inconsistent")
                tag = ret_v[1:5].decode("ascii", errors="replace") if len(ret_v) >= 5 else "NONE"
                return False, f"L2 proof verification failed ({tag})"

            # ── 6. Commit the batch (records snapshot for reorg rollback) ──
            # Still under layer2._lock so the snapshot recorded in commit
            # cannot race with concurrent Sequencer mutations.
            l1_height     = block.index
            l1_block_hash = block.block_hash
            ok_c, msg_c = layer2.commit_batch(
                batch_id          = submission.batch_id,
                new_root_expected = submission.new_l2_root,
                l1_height         = l1_height,
                l1_block_hash     = l1_block_hash,
            )
            if not ok_c:
                # Commit failed (e.g., non-monotonic batch_id) — restore and
                # reject.  A correct sequencer never submits a non-monotonic
                # batch; if we see one here it's either a bug or an attack.
                try:
                    layer2._tree.restore(pre_snap)
                except Exception:
                    log.error("CRITICAL: layer2 restore failed after commit "
                              "rejection; L2 state may be inconsistent")
                return False, f"commit_batch rejected: {msg_c}"

        log.info(
            f"[L2-ROLLUP] batch_id={submission.batch_id} applied at L1 "
            f"height {l1_height}: {len(l2_txs)} txs, "
            f"prev={submission.previous_l2_root[:12]}, "
            f"new={submission.new_l2_root[:12]}, "
            f"backend={submission.backend}")
        return True, "OK"

    def _deploy_name_gate(self, tx: 'Transaction', block_index: int
                          ) -> Tuple[bool, str, str]:
        """
        AUDIT-FIX-1 (state_root divergence): shared SC-NAME-1 gate for
        TYPE_DEPLOY contract-name validity/uniqueness.

        This MUST be called — with identical inputs, against identical chain
        state — by every code path whose outcome feeds a committed
        state_root: ``_apply_vvm_tx`` (the real, consensus-committing
        execution) and ``dry_run_state_root`` (the miner's pre-commit
        simulation that fills in the candidate block header).

        Before this fix the two implementations were separate. A block
        containing two DEPLOY txs sharing a contract_name would compute the
        correct root in ``_apply_vvm_tx`` (VM never runs for the second,
        colliding tx) but a wrong one in ``dry_run_state_root`` (which had
        no equivalent check and simulated both deploys as succeeding). The
        miner's declared header state_root and the root apply_block actually
        produces would then disagree, and the block would be rejected
        everywhere — including by the miner's own node — on every state_root
        mismatch check. Routing both call sites through one function makes
        that divergence structurally impossible: there is only one place
        that decides "blocked or not," and both paths ask it the same way.

        Returns (blocked, norm_name, reason):
          blocked   -- True if the VM must NOT be invoked for this tx; the
                       caller must apply the matching refund/penalty itself
                       and skip execution entirely.
          norm_name -- normalized contract name ("" if the gate doesn't
                       apply to this tx).
          reason    -- "" if not blocked, "invalid:<detail>" if the name is
                       structurally invalid, or "collision" if the
                       normalized name is already registered on-chain.
        """
        if not (tx.tx_type == Transaction.TYPE_DEPLOY
                and block_index >= Config.CONTRACT_NAMING_ACTIVATION_HEIGHT):
            return False, "", ""
        raw_name = getattr(tx, "contract_name", "")
        if not raw_name:                # "" = unnamed; skip uniqueness check
            return False, "", ""
        norm = normalize_contract_name(raw_name)
        ok_n, reason_n = validate_contract_name(norm)
        if not ok_n:
            return True, norm, f"invalid:{reason_n}"
        if self.storage.contract_name_exists(norm):
            return True, norm, "collision"
        return False, norm, ""

    def _apply_vvm_tx(self, tx: 'Transaction',
                      block: 'Block') -> Tuple[int, bool, dict]:
        """
        Execute a VVM DEPLOY or CALL transaction.

        Returns (gas_fee_collected_in_satoshi, success_bool, vvm_undo).
        F-01 COMPLETION: all gas/value arithmetic uses satoshi integers.
        Deducts max_gas upfront, executes VM, refunds unused gas.
        If execution reverts: state changes are rolled back, gas up to gas_used
        is still consumed (reverts still pay for computation), no value transfer.
        If execution succeeds: state changes committed, value transferred.

        AUDIT-FIX-3 (state corruption / non-atomic contract storage):
        ``vvm_undo`` is a dict describing exactly how to reverse this call's
        CONTRACT-STORAGE side effects (sstore writes, new deployments,
        self-destructs) — it is {} when there is nothing to undo (debit
        failure, name-gate block, or a reverted VM run all leave contract
        storage untouched). apply_block collects these per-tx across the
        whole block and replays them, in reverse, on every failure path —
        symmetric with how it already replays restore_accounts/restore_roles
        for balances/roles. Without this, a VVM tx that succeeds early in a
        block whose LATER tx forces the whole block to be rejected would
        leave its sstore/save_contract effects permanently committed to
        disk (they write directly via Storage.sstore/save_contract, which
        are not covered by the balance/role snapshot-restore mechanism),
        silently corrupting this node's state relative to peers who never
        attempted the same doomed block.
        """
        # ── 1. Debit max gas upfront (satoshi) ────────────────────────────────
        max_gas_fee_sat = gas_fee_to_sat(tx.gas_limit, tx.gas_price)
        amount_sat      = to_satoshi(tx.amount)
        # Also debit call_value if sending VSD to contract
        total_upfront_sat = amount_sat + max_gas_fee_sat
        if not self.storage.debit_sat(tx.sender, total_upfront_sat):
            # v7.1.11 BUG-2 FIX (Free-Gas Minting):
            #   Pre-fix returned (max_gas_fee_sat, False) when the upfront
            #   debit failed.  apply_block then ADDED that fee to the
            #   block's reward pool — minting satoshi out of thin air
            #   because the sender was never charged.  An attacker could
            #   submit a 1-million-gas tx with zero balance and force the
            #   network to mint gas_limit * gas_price as miner reward on
            #   every failed attempt.
            #
            #   Now: return (0, False) so apply_block adds nothing to
            #   the fee pool.  The receipt is still saved with success=False
            #   and revert_reason="Balance debit failed" so _rollback_block
            #   (Bug 3 fix) can correctly identify the never-debited case
            #   and skip the spurious refund.
            log.error(f"VVM tx {tx.tx_id[:8]}: balance debit failed (safety net)")
            self.storage.save_vvm_receipt(
                tx_id=tx.tx_id, block_idx=block.index,
                contract_addr="", gas_used=0,           # was tx.gas_limit
                gas_limit=tx.gas_limit, success=False,
                return_data=b"", revert_reason="Balance debit failed",
                logs=[], storage_delta={"__fee_pool_sat__": 0})
            return 0, False, {}                         # was (max_gas_fee_sat, False)

        # ── 2. SC-NAME-1: Contract name uniqueness check ──────────────────────
        # Perform this check AFTER the upfront debit (so the sender pays gas
        # for the duplicate-name attempt) but BEFORE VM execution (the VM is
        # never invoked for a name-collision tx, saving gas proportional to
        # init-code complexity).
        #
        # AUDIT-FIX-1: delegates to _deploy_name_gate(), the single shared
        # implementation also used by dry_run_state_root(). See that method's
        # docstring for why sharing this logic (rather than each path
        # re-implementing it) is required for consensus correctness.
        blocked, norm, reason = self._deploy_name_gate(tx, block.index)
        if blocked:
            if reason.startswith("invalid:"):
                # Refund upfront debit — name is structurally invalid.
                # This is a defence-in-depth path; mempool should have
                # caught malformed names via Transaction.is_valid().
                self.storage.credit_sat(tx.sender, total_upfront_sat)
                self.storage.save_vvm_receipt(
                    tx_id=tx.tx_id, block_idx=block.index,
                    contract_addr="", gas_used=0,
                    gas_limit=tx.gas_limit, success=False,
                    return_data=b"",
                    revert_reason=f"Invalid contract name: {reason[len('invalid:'):]}",
                    logs=[], storage_delta={"__fee_pool_sat__": 0})
                return 0, False, {}

            else:  # reason == "collision"
                # SC-V73-FIX-8: name-collision fee ordering race fix.
                # OLD: returned collision_fee_sat to apply_block which added
                # it to the miner reward pool.  But two nodes processing the
                # same block with different tx ordering could disagree on WHICH
                # deploy is "first" — one node charges the collision penalty
                # to deploy B (seeing A first), the other to deploy A (seeing B
                # first).  Different fee pools → different state_roots.
                # FIX: return 0 fee to the pool so both outcomes are identical
                # regardless of processing order.  The sender STILL pays the
                # penalty (already debited upfront); we just don't mint it to
                # the miner, making the net effect order-independent.
                # The receipt records gas_used=NAME_COLLISION_GAS_PENALTY for
                # audit/display so operators can see the penalty was charged.
                NAME_COLLISION_GAS_PENALTY = min(
                    Config.VVM_DEPLOY_GAS_BASE, tx.gas_limit)
                collision_fee_sat = gas_fee_to_sat(
                    NAME_COLLISION_GAS_PENALTY, tx.gas_price)
                collision_refund_sat = total_upfront_sat - collision_fee_sat
                if collision_refund_sat > 0:
                    self.storage.credit_sat(tx.sender, collision_refund_sat)
                self.storage.save_vvm_receipt(
                    tx_id=tx.tx_id, block_idx=block.index,
                    contract_addr="", gas_used=NAME_COLLISION_GAS_PENALTY,
                    gas_limit=tx.gas_limit, success=False,
                    return_data=b"",
                    revert_reason="Contract name already exists",
                    logs=[], storage_delta={"__fee_pool_sat__": 0})
                log.warning(
                    f"VVM deploy {tx.tx_id[:8]}: name collision '{norm}' "
                    f"by {tx.sender[:12]}")
                metrics.inc("vvm_deploy_name_collision")
                # SC-V73-FIX-8: return 0, not collision_fee_sat, so fee pool
                # is identical across all nodes regardless of tx ordering.
                return 0, False, {}

        # ── 3. Run VVM ────────────────────────────────────────────────────────
        # VVM-1 FIX: pass call_value as integer satoshi, not Python float VSD.
        # Pre-fix code passed `tx.amount` directly — a Python float — into
        # vvm.deploy/call.  The first place this float reached was the
        # CALLVALUE opcode at _execute() which does
        #     self.stack.append(value & UINT256_MAX)
        # → TypeError: unsupported operand type(s) for &: 'float' and 'int'
        # caught by the outer `except Exception` in _execute(), which then
        # set frame.reverted=True with output b"VVM internal error: ...".
        # Result: ANY contract that touched CALLVALUE with a non-zero value
        # silently reverted with a confusing internal-error message and the
        # user paid full gas for nothing.  Other balance opcodes (BALANCE,
        # SELFBALANCE, VSDBALANCE) already use get_balance_sat() so they
        # were fine; only CALLVALUE was broken.  SELFDESTRUCT had a local
        # workaround at line ~16338 that detected the float and converted
        # — that code path is now redundant but harmless to keep (it still
        # handles legacy callers correctly).
        # We use the same `amount_sat` already computed for the upfront
        # debit so the value the contract sees and the value the sender
        # pays are guaranteed to be the same satoshi integer.
        vvm = VVMEngine(storage=self.storage)

        if tx.tx_type == Transaction.TYPE_DEPLOY:
            result = vvm.deploy(
                sender      = tx.sender,
                bytecode    = bytes.fromhex(tx.data),
                call_value  = amount_sat,
                gas_limit   = tx.gas_limit,
                block_ctx   = block,
                tx          = tx,
            )
        else:  # TYPE_CALL
            result = vvm.call(
                caller      = tx.sender,
                contract    = tx.receiver,
                calldata    = bytes.fromhex(tx.data) if tx.data else b"",
                call_value  = amount_sat,
                gas_limit   = tx.gas_limit,
                block_ctx   = block,
                tx          = tx,
            )

        # VVMEngine restores its journal before returning a failed execution.
        # On success it returns the exact pre-channel/account state needed for
        # both block-failure rollback and later canonical reorg rollback.
        _state_channel_undo = result.state_channel_journal

        try:
            gas_used = result.gas_used
            gas_used = min(gas_used, tx.gas_limit)   # never exceed limit

            # ── 4. Compute actual gas fee & refund unused gas (satoshi) ───────────
            actual_gas_fee_sat = gas_fee_to_sat(gas_used, tx.gas_price)
            refund_sat = max_gas_fee_sat - actual_gas_fee_sat
            if refund_sat > 0:
                self.storage.credit_sat(tx.sender, refund_sat)

            # ── 5. Apply or roll back state changes ───────────────────────────────
            # Track every contract created or self-destructed by this transaction
            # so both in-block failure rollback and later consensus rollback can
            # reverse the exact VVM account-set mutation.
            _deployed_addrs: list[str] = []
            _selfdestruct_targets: list[str] = []
            if result.success:
                # If deploy: persist contract account + code FIRST so that
                # update_contract_storage_root (called below) can find the row.
                # BUG FIX: previously save_contract was called AFTER
                # update_contract_storage_root.  Because save_contract uses
                # INSERT OR IGNORE, the contract row didn't exist yet when
                # update_contract_storage_root ran an UPDATE — the UPDATE
                # silently matched zero rows, leaving storage_root as
                # sha256(b"empty_storage") even when the init code wrote storage.
                # compute_state_root() then read the stale empty root, producing
                # a state_root mismatch that caused every subsequent block
                # (and contract call) to be rejected with "state_root mismatch".
                # AUDIT-FIX-3: track every contract address newly created by this
                # tx (top-level deploy + nested CREATE/CREATE2), so apply_block
                # can physically delete them if this block ends up rejected by a
                # LATER tx. Deleting (not soft-deleting) matters: if the same
                # deploy is retried in a corrected future block, save_contract's
                # INSERT OR IGNORE must not be blocked by a stale leftover row.

                if tx.tx_type == Transaction.TYPE_DEPLOY and result.contract_addr:
                    code_hash = sha256(result.return_data)
                    self.storage.save_contract_code(code_hash, result.return_data)
                    # SC-NAME-1: pass the normalised name (already validated above).
                    _cname = normalize_contract_name(getattr(tx, "contract_name", ""))
                    self.storage.save_contract(
                        address       = result.contract_addr,
                        code_hash     = code_hash,
                        creator       = tx.sender,
                        created_at    = block.timestamp,
                        contract_name = _cname,
                    )
                    _deployed_addrs.append(result.contract_addr)
                    if _cname:
                        log.info(
                            f"Contract deployed: {result.contract_addr} "
                            f"name='{_cname}' by {tx.sender[:12]} gas={gas_used}")
                    else:
                        log.info(
                            f"Contract deployed: {result.contract_addr} "
                            f"(unnamed) by {tx.sender[:12]} gas={gas_used}")

                # SC-V73-FIX-2: Flush deferred CREATE/CREATE2 deployments.
                # These were accumulated in result.pending_deployments during VM
                # execution instead of being written directly to the DB (which would
                # have committed them even if the parent tx later reverted — "ghost
                # contract" bug).  Now that the top-level execution has succeeded,
                # persist them all atomically here.
                for _pd in result.pending_deployments:
                    try:
                        self.storage.save_contract_code(_pd["code_hash"], _pd["code_bytes"])
                        self.storage.save_contract(
                            address       = _pd["address"],
                            code_hash     = _pd["code_hash"],
                            creator       = _pd["creator"],
                            created_at    = _pd["created_at"],
                            contract_name = _pd.get("contract_name", ""),
                        )
                        _deployed_addrs.append(_pd["address"])
                        log.debug(
                            f"Flushed pending CREATE deployment: {_pd['address'][:16]} "
                            f"by {_pd['creator'][:12]}")
                    except Exception as _pd_err:
                        # Log but do not abort: a duplicate INSERT OR IGNORE is safe.
                        log.warning(f"pending_deployment flush error {_pd['address'][:16]}: {_pd_err}")

                # Commit storage writes
                # VVM-3 FIX: SELFDESTRUCT pushed a marker entry into
                # storage_writes with the form (("__selfdestruct__", addr), 1).
                # Pre-fix code looped over storage_writes calling sstore on
                # every entry — including this marker — which would write a
                # row with contract_addr="__selfdestruct__" and slot_key=<addr>
                # to the contract_storage table.  That is junk data and
                # does NOT destroy the contract; the contract continued to
                # exist after SELFDESTRUCT, only its balance was transferred.
                # We now extract the marker entries first, perform the real
                # destroy_contract calls, and only sstore real (addr, slot)
                # writes.
                for (addr, slot), value in result.storage_writes.items():
                    if addr == "__selfdestruct__":
                        # 'slot' here is actually the contract address being
                        # destroyed; the value is the marker (1).
                        _selfdestruct_targets.append(slot)
                        continue
                    self.storage.sstore(addr, slot, value)
                    _tag = int(result.storage_tags.get((addr, slot), 0))
                    self.storage.set_storage_tag(addr, slot, _tag)
                # Update storage_root for all touched contracts
                # (now safe even for newly-deployed contracts because the row
                # was already inserted above)
                for addr in result.touched_contracts:
                    self.storage.update_contract_storage_root(addr)
                # Actually destroy the SELFDESTRUCT-marked contracts.  Order:
                # AFTER the storage_root updates so we don't try to update a
                # destroyed contract's root.  The SELFDESTRUCT beneficiary
                # transfer is applied below via self_destruct_transfers, so
                # the balance has already moved before we delete the row.
                for _sd_addr in _selfdestruct_targets:
                    try:
                        self.storage.destroy_contract(_sd_addr)
                        log.info(f"[VVM] SELFDESTRUCT: contract {_sd_addr[:16]} destroyed")
                    except Exception as _sd_err:
                        log.error(f"[VVM] SELFDESTRUCT destroy_contract({_sd_addr[:16]}) "
                                  f"failed: {_sd_err}")

                # AUDIT-FIX-3: assemble this tx's contract-storage undo record.
                # apply_block appends this to a block-scoped list and replays it
                # (in reverse) on any failure path, restoring contract storage
                # to exactly its pre-this-tx state — the same guarantee
                # restore_accounts()/restore_roles() already give balances/roles.
                vvm_undo = {
                    "storage_delta": {
                        (addr, slot): result.storage_orig.get((addr, slot), 0)
                        for (addr, slot) in result.storage_writes.keys()
                        if addr != "__selfdestruct__"
                    },
                    "storage_tag_delta": {
                        (addr, slot): result.storage_tag_orig.get((addr, slot))
                        for (addr, slot) in result.storage_writes.keys()
                        if addr != "__selfdestruct__"
                    },
                    "touched_contracts": set(result.touched_contracts),
                    "deployed":       list(_deployed_addrs),
                    "selfdestructed": list(_selfdestruct_targets),
                    "state_channel_journal": _state_channel_undo or {},
                }

                # Materialise the VM's complete successful balance overlay.  The
                # transaction sender was already debited ``amount_sat`` together
                # with the maximum gas fee above; the overlay now credits the
                # top-level recipient and applies every nested CALL/CREATE value
                # movement exactly once.
                for _addr, _delta in result.balance_deltas.items():
                    _delta = int(_delta)
                    if _delta > 0:
                        self.storage.credit_sat(_addr, _delta)
                    elif _delta < 0:
                        if not self.storage.debit_sat(_addr, -_delta):
                            raise RuntimeError(
                                f"VVM balance overlay debit failed for {_addr[:16]} "
                                f"of {-_delta} sat")

                # SC-V73-FIX-3 / AUDIT-FIX-SELFDESTRUCT-1: materialize each
                # SELFDESTRUCT transfer as a real balance move.  The old path only
                # credited the beneficiary, leaving the destroyed contract's
                # balance untouched and therefore creating new supply.  Debit the
                # exact source first so a failed transfer cannot mint value; the
                # surrounding apply_block rollback restores the whole proxy state
                # if the subsequent credit fails.
                for _sd_transfer in result.self_destruct_transfers:
                    if len(_sd_transfer) != 3:
                        raise RuntimeError(
                            "SELFDESTRUCT transfer record is missing its source")
                    _source_addr, _beneficiary_addr, amount_sat_sd = _sd_transfer
                    amount_sat_sd = int(amount_sat_sd)
                    if amount_sat_sd <= 0:
                        continue
                    if not self.storage.debit_sat(_source_addr, amount_sat_sd):
                        raise RuntimeError(
                            f"SELFDESTRUCT source {_source_addr[:16]} has insufficient "
                            f"balance for transfer of {amount_sat_sd} sat")
                    self.storage.credit_sat(_beneficiary_addr, amount_sat_sd)
                metrics.inc("vvm_txs_success")
            else:
                # Revert: call_value already debited from sender but not credited
                # → refund the call_value back to sender (satoshi)
                if amount_sat > 0:
                    self.storage.credit_sat(tx.sender, amount_sat)
                log.debug(f"VVM tx {tx.tx_id[:8]} reverted: {result.revert_reason}")
                metrics.inc("vvm_txs_reverted")
                # AUDIT-FIX-3: a reverted VM run never reached the sstore/deploy/
                # selfdestruct block above — no contract storage was touched, so
                # there is nothing for apply_block to undo.
                vvm_undo = {}

            # ── 6. Persist receipt + update event index ───────────────────────────
            # Build storage_delta (original slot values → for reorg rollback).
            # VVM-3 FIX: skip __selfdestruct__ marker entries — these are not
            # real storage writes (they instructed _apply_vvm_tx to destroy
            # the contract, which is recorded in receipt.contract_addr +
            # tx.tx_type==DEPLOY for the rollback path's destroy_contract call).
            # Recording them in storage_delta would only confuse the rollback
            # path which would try to sstore them back as a phantom slot.
            storage_delta: dict = {}
            for (addr, slot) in result.storage_writes.keys():
                if addr == "__selfdestruct__":
                    continue
                prev_val = result.storage_orig.get((addr, slot), 0)
                storage_delta[f"{addr}:{slot}"] = hex(prev_val)

            # AUDIT-FIX (Batch D): SELFDESTRUCT beneficiary transfers were never
            # persisted anywhere — result.self_destruct_transfers only ever
            # existed as an in-memory VM result, so _rollback_block's VVM
            # reversal (which reconstructs everything to undo purely from this
            # receipt) had no way to know which addresses received a
            # SELFDESTRUCT credit or how much, making that credit permanently
            # unreversible on reorg for every ordinary reorg of a successfully-
            # applied block, not just the narrow apply_block-internal-failure
            # window the touched-set fix above addresses. Reserved key follows
            # the same dunder convention as "__selfdestruct__" above, so it
            # cannot collide with a real "{addr}:{slot}" storage key. Only
            # persisted on success — a reverted call never actually credited
            # anything (see the revert branch above), so there is nothing to
            # reverse for those.
            if result.success and result.self_destruct_transfers:
                storage_delta["__self_destruct_transfers__"] = [
                    [source_addr, beneficiary_addr, int(amount_sat_sd)]
                    for (source_addr, beneficiary_addr, amount_sat_sd)
                    in result.self_destruct_transfers
                ]

            # VVM-ROLLBACK-FIX: persist account-level creations/destructions as
            # part of the receipt.  The old receipt only captured slot deltas, so
            # consensus rollback could not fully undo nested CREATE/CREATE2 or
            # SELFDESTRUCT effects.  These reserved keys are metadata, not real
            # storage slots.
            if result.success and _deployed_addrs:
                storage_delta["__deployed_contracts__"] = list(dict.fromkeys(
                    str(a) for a in _deployed_addrs if a))
            if result.success and _selfdestruct_targets:
                storage_delta["__selfdestructed_contracts__"] = list(dict.fromkeys(
                    str(a) for a in _selfdestruct_targets if a))
            if result.success and _state_channel_undo:
                # JSON-safe form of the exact direct channel/account pre-state.
                storage_delta["__state_channels_before__"] = {
                    "channels": dict(_state_channel_undo.get("channels", {})),
                    "accounts": {
                        str(addr): list(snapshot)
                        for addr, snapshot in _state_channel_undo.get(
                            "accounts", {}).items()
                    },
                }

            # VVM-VALUE-ROLLBACK-FIX: persist the exact destination of the
            # successful top-level call-value transfer. Rollback must reverse this
            # real balance credit before refunding the sender. A DEPLOY's recipient
            # is only known after VM execution, so receipt metadata avoids guessing.
            # The rollback path also has a type-based fallback for older receipts.
            # Persist the exact amount that this VVM tx contributed to the
            # block reward pool.  This is deliberately distinct from gas_used:
            # pre-execution failures such as name collisions can display a
            # non-zero penalty while returning zero to the reward pool.
            storage_delta["__fee_pool_sat__"] = int(actual_gas_fee_sat)
            # New receipts carry the complete VM balance overlay.  Rollback uses
            # this marker instead of the legacy single-recipient value metadata.
            if result.success and result.balance_deltas:
                storage_delta["__vvm_balance_deltas__"] = {
                    str(_addr): int(_delta)
                    for _addr, _delta in result.balance_deltas.items()
                    if int(_delta) != 0
                }

            if result.success and amount_sat > 0:
                if tx.tx_type == Transaction.TYPE_DEPLOY and result.contract_addr:
                    _value_recipient = str(result.contract_addr)
                elif tx.tx_type == Transaction.TYPE_CALL:
                    _value_recipient = str(tx.receiver)
                else:
                    _value_recipient = str(tx.sender)
                storage_delta["__value_transfer__"] = {
                    "address": _value_recipient,
                    "amount_sat": int(amount_sat),
                }

            resolved_contract = result.contract_addr or tx.receiver
            self.storage.save_vvm_receipt(
                tx_id          = tx.tx_id,
                block_idx      = block.index,
                contract_addr  = resolved_contract,
                gas_used       = gas_used,
                gas_limit      = tx.gas_limit,
                success        = result.success,
                return_data    = result.return_data if result.success else b"",
                revert_reason  = result.revert_reason,
                logs           = result.logs,
                storage_delta  = storage_delta,
            )

            # SC-FIX-8: Index event logs for O(1) future queries
            if result.success and result.logs and resolved_contract:
                try:
                    self._event_index.index_logs(
                        tx_id         = tx.tx_id,
                        block_idx     = block.index,
                        contract_addr = resolved_contract,
                        logs          = result.logs,
                    )
                except Exception as _ei_err:
                    log.debug(f"Event index update failed for {tx.tx_id[:8]}: {_ei_err}")

            metrics.inc("vvm_gas_used", gas_used)
        except BaseException:
            if _state_channel_undo:
                try:
                    self.storage.restore_state_channel_journal(_state_channel_undo)
                except Exception as _sc_restore_e:
                    log.error(
                        "CRITICAL: VVM state-channel rollback after apply error failed: %s — "
                        "state may be corrupted; node should be restarted.",
                        _sc_restore_e)
            raise

        return actual_gas_fee_sat, result.success, vvm_undo

    # ── SC-IMPROVEMENT-2: Gas estimation ─────────────────────────────────────
    def estimate_vvm_gas(self, *, caller: str, contract: str,
                         calldata: bytes, call_value: int) -> dict:
        """
        Estimate the minimum gas required for a VVM call to succeed.

        Returns a dict:
          {
            "estimated_gas": int,       # minimum viable gas (with 10% buffer)
            "gas_cap": int,             # VVM_TX_GAS_CAP (absolute ceiling)
            "success": bool,            # False if call would always revert
            "note": str                 # human-readable explanation
          }

        No state is modified. Uses VVMEngine.simulate() internally.
        Exposed via RPC as "estimategas" action.
        """
        height  = self.storage.chain_height()
        ctx     = self.storage.get_block(height)
        vvm     = self._vvm_engine

        # Quick reachability check
        contract_rec = self.storage.get_contract(contract)
        if not contract_rec:
            return {
                "estimated_gas": 0,
                "gas_cap": Config.VVM_TX_GAS_CAP,
                "success": False,
                "note": f"Contract {contract[:20]}... not found on chain",
            }

        try:
            estimated = vvm.estimate_gas(
                caller      = caller,
                contract    = contract,
                calldata    = calldata,
                call_value  = call_value,
                block_ctx   = ctx,
            )
        except Exception as e:
            return {
                "estimated_gas": Config.VVM_TX_GAS_CAP,
                "gas_cap": Config.VVM_TX_GAS_CAP,
                "success": False,
                "note": f"Estimation error: {e}",
            }

        if estimated >= Config.VVM_TX_GAS_CAP:
            return {
                "estimated_gas": Config.VVM_TX_GAS_CAP,
                "gas_cap": Config.VVM_TX_GAS_CAP,
                "success": False,
                "note": "Call always reverts at max gas — check contract logic",
            }

        return {
            "estimated_gas": estimated,
            "gas_cap": Config.VVM_TX_GAS_CAP,
            "success": True,
            "note": f"Estimated gas with 10% buffer (base: {int(estimated / 1.1)})",
        }

    # ── v11.0.0: Native State Channel Storage API ─────────────────────────────
    # AUDIT-FIX (Batch D): these six methods used to live here, calling
    # self._conn() -- which does not exist anywhere on Blockchain -- so every
    # call failed with AttributeError before ever touching a channel row.
    # They are now correctly implemented on Storage (which genuinely has
    # _conn()/_pg_exec() and the state_channels table in both backends);
    # VVMEngine's precompile handler already calls self._storage.X(...),
    # so no change was needed there, only fixing where X actually lives.
    # See Storage.create_channel / get_channel / close_channel /
    # raise_dispute / force_close_channel / get_open_channel_between.

    # ── SC-FIX-8: Event query API ─────────────────────────────────────────────
    def get_contract_events(self, contract: str,
                            from_block: int = 0,
                            to_block: int = 2**31) -> list:

        """
        Return all event logs emitted by `contract` in the given block range.
        O(1) index lookup — no chain scan required.
        """
        return self._event_index.get_events_by_contract(
            contract, from_block, to_block)

    def get_events_by_topic(self, topic0: str,
                            from_block: int = 0,
                            to_block: int = 2**31) -> list:
        """
        Return all event logs matching topic0 across all contracts.
        O(1) index lookup — no chain scan required.
        """
        return self._event_index.get_events_by_topic(
            topic0, from_block, to_block)

    def _maybe_finalize_by_bft(self, block: Block):
        """
        Check if block already has ≥ 2/3 weighted stake votes and mark finalized.

        Consensus Fix #5: If validators exist but the threshold is not yet met,
        the block is saved as un-finalized (pending).  It can be upgraded to
        BFT-finalized later via add_validator_sig() when additional votes arrive
        from the network.  The block is NEVER dropped here — only promoted.

        BUG-2 FIX: stake comparison now uses the integer bft_threshold_met()
        helper (cross-multiplication, no float division) so that two nodes
        accumulating votes in different orders always agree on finality.

        AUDIT-FIX (Batch D): this used to check only "if not validators: return"
        (i.e. ran with validator_count >= 1), so a single registered validator
        holding a majority of registered stake could BFT-finalize a block --
        which reorg()'s Fix #2 fence and accept_chain()'s Case 3 guard both
        treat as permanently, unconditionally irreversible -- during exactly
        the bootstrap window Config.MIN_VALIDATORS_FOR_BFT and
        BOOTSTRAP_POW_FINALITY_DEPTH exist to protect (see SEC-FIX H-04).
        _maybe_finalize_by_depth already gated its depth choice on this same
        threshold; add_validator_sig()'s own inline copy of this check is
        fixed the same way.
        """
        validators = self.storage.get_all_by_role("investor")
        if len(validators) < Config.MIN_VALIDATORS_FOR_BFT:
            return
        # BUG-2 FIX: convert stake to satoshi integers — no float division
        total_stake_sat = sum(to_satoshi(v["stake"]) for v in validators)
        if total_stake_sat <= 0:
            return
        voted_stake_sat = 0
        seen_voters = set()
        for vs in block.validator_sigs:
            voter_addr = vs.get("addr")
            if voter_addr in seen_voters:
                continue
            seen_voters.add(voter_addr)
            for v in validators:
                if v["address"] == voter_addr:
                    voted_stake_sat += to_satoshi(v["stake"])
        if bft_threshold_met(voted_stake_sat, total_stake_sat):
            block.finalized = True
            # AUDIT-FIX (Batch D): keep the incremental finality-fence
            # tracker in sync — see _highest_finalized_height in __init__.
            self._highest_finalized_height = max(
                self._highest_finalized_height, block.index)
            self.storage.save_block(block)
            pct = voted_stake_sat * 100 // total_stake_sat
            log.info(f"Block #{block.index} BFT-finalized ({pct}% stake)")
            metrics.inc("blocks_finalized_bft")

    def _maybe_finalize_by_depth(self, applied_height: int):
        """
        Finalize blocks that are POW_FINALITY_DEPTH confirmations deep.

        Fix #9 — Finality Liveness Guarantee:
        The original code only used PoW-depth finality when there were NO
        investors.  This leaves the chain in a liveness-stall if validators
        are registered but a majority is offline (their total stake < 2/3).
        The chain would keep growing (PoW continues) but no blocks would ever
        be finalized, which blocks RPC callers waiting on finality.

        The fix adds an explicit degraded-participation fallback:
          • If validators exist but BFT finality has not progressed for more
            than FINALITY_LIVENESS_TIMEOUT blocks, automatically fall back to
            PoW-depth finality for those blocks.
          • A metric counter and a WARNING log are emitted so operators know
            that BFT finality is degraded and should restore validators.
          • Once BFT recovers (validators come back online), BFT finality
            resumes and PoW-depth fallback stops being triggered.

        This preserves liveness under partial validator failure without
        weakening the safety guarantee: BFT-finalized blocks cannot be reorged
        (Fix #2), and PoW-depth finalized blocks can be upgraded to BFT-final
        when validators return.
        """
        validators = self.storage.get_all_by_role("investor")

        # SEC-FIX H-04 (Bootstrap Finality Depth)
        # ───────────────────────────────────────
        # During bootstrap (validator count below MIN_VALIDATORS_FOR_BFT) the
        # chain has no BFT finality at all and runs in pure PoW mode.  Six
        # confirmations against a near-MIN_DIFFICULTY target is too shallow
        # to defend against a 51% rewrite by a determined attacker, so use
        # the deeper BOOTSTRAP_POW_FINALITY_DEPTH until enough validators
        # register.  Once the validator set reaches MIN_VALIDATORS_FOR_BFT
        # the chain switches to BFT finality and the steady-state depth (6)
        # applies.
        validator_count = len(validators) if validators else 0
        bft_active      = validator_count >= int(getattr(
            Config, "MIN_VALIDATORS_FOR_BFT", 3))
        finality_depth  = int(Config.POW_FINALITY_DEPTH) if bft_active \
            else int(getattr(Config,
                             "BOOTSTRAP_POW_FINALITY_DEPTH",
                             Config.POW_FINALITY_DEPTH))

        target = applied_height - finality_depth
        if target < 0:
            return

        if not validators:
            # Bootstrap mode: no validators at all — pure PoW finality
            blk = self.storage.get_block(target)
            if blk and not blk.finalized:
                blk.finalized = True
                # AUDIT-FIX (Batch D): keep the incremental finality-fence
                # tracker in sync — see _highest_finalized_height in __init__.
                self._highest_finalized_height = max(
                    self._highest_finalized_height, blk.index)
                self.storage.save_block(blk)
                metrics.inc("blocks_finalized_pow")
            return

        # ── Degraded BFT participation fallback (Fix #9) ─────────────────────
        # Validators exist but may be offline.  Check if finality has stalled.
        FINALITY_LIVENESS_TIMEOUT = max(
            Config.GOVERNANCE_FINALITY_TIMEOUT,
            Config.POW_FINALITY_DEPTH * 2,
        )
        # Find the highest finalized block
        highest_fin = -1
        for idx in range(applied_height, max(-1, applied_height - FINALITY_LIVENESS_TIMEOUT - 1), -1):
            blk = self.storage.get_block(idx)
            if blk and blk.finalized:
                highest_fin = blk.index
                break

        stalled_blocks = applied_height - highest_fin
        if stalled_blocks > FINALITY_LIVENESS_TIMEOUT:
            # BFT finality has stalled: fall back to PoW-depth finality
            blk = self.storage.get_block(target)
            if blk and not blk.finalized:
                blk.finalized = True
                # AUDIT-FIX (Batch D): keep the incremental finality-fence
                # tracker in sync — see _highest_finalized_height in __init__.
                self._highest_finalized_height = max(
                    self._highest_finalized_height, blk.index)
                self.storage.save_block(blk)
                metrics.inc("blocks_finalized_pow_fallback")
                log.warning(
                    f"FINALITY LIVENESS FALLBACK: BFT finality stalled for "
                    f"{stalled_blocks} blocks (timeout={FINALITY_LIVENESS_TIMEOUT}). "
                    f"Falling back to PoW-depth finality for block #{target}. "
                    f"Check validator participation — BFT requires ≥"
                    f"{Config.BFT_THRESHOLD*100:.0f}% of stake online.")
                metrics.set_gauge("finality_stall_blocks", float(stalled_blocks))
        else:
            metrics.set_gauge("finality_stall_blocks", float(max(0, stalled_blocks)))

    # ── Chain reorg (rollback + replay) ──────────────────────────────────────
    def _vvm_fee_pool_credit_sat(self, tx: Transaction, receipt: Optional[dict]) -> int:
        """Return the exact VVM fee contribution that was added to the
        block reward pool when ``tx`` was applied.

        Forward execution returns the actual fee-pool contribution explicitly
        from ``_apply_vvm_tx``.  Rollback runs later, so it must reconstruct
        that exact amount from the persisted receipt rather than assuming
        ``gas_used * gas_price`` always entered the pool.  In particular, a
        name-collision DEPLOY records the collision penalty as ``gas_used``
        for audit/display but intentionally returns *zero* to the reward pool.

        New receipts persist ``__fee_pool_sat__`` so future consensus changes
        cannot create another mismatch between forward and rollback.  Older
        receipts fall back to the historical semantics, with known pre-execution
        zero-pool failures handled explicitly for backward compatibility.
        """
        if receipt is None:
            return gas_fee_to_sat(tx.gas_limit, tx.gas_price)

        sd = receipt.get("storage_delta") or {}
        marker = sd.get("__fee_pool_sat__")
        if marker is not None:
            try:
                return max(0, int(marker))
            except (TypeError, ValueError):
                log.warning(
                    "Invalid __fee_pool_sat__ for VVM tx %s; using legacy fallback",
                    tx.tx_id[:8],
                )

        # Backward compatibility for receipts produced before the exact
        # fee-pool contribution marker was introduced.  These failure paths
        # charged no fee to the reward pool even when the receipt displays a
        # non-zero gas_used value (name collision).
        reason = str(receipt.get("revert_reason") or "")
        if (reason == "Balance debit failed"
                or reason == "Contract name already exists"
                or reason.startswith("Invalid contract name:")):
            return 0

        gas_used = receipt.get("gas_used", tx.gas_limit)
        try:
            gas_used = min(int(gas_used), int(tx.gas_limit))
        except (TypeError, ValueError):
            gas_used = int(tx.gas_limit)
        return gas_fee_to_sat(gas_used, tx.gas_price)

    def _rollback_rewards(self, block: Block):
        """
        Exact mirror of _distribute_rewards — debits every credit that
        _distribute_rewards applied so that a reorg leaves balances clean.

        v7.1.12 (Option B): rewritten for V2 reward rules.

        ALSO FIXES a latent bug carried from v7.1.11: the old rollback
        still tried to debit ``block.validator_sigs[0]["addr"]`` for the
        primary 20%, but the v7.1.11 apply path was fixed to always
        credit ``block.miner_address``.  That asymmetry meant any reorg
        of a block with validator sigs would have corrupted balances
        (debiting the wrong account).  In v7.1.12 V2 there is no
        primary-validator credit at all (the all-validators pool is the
        only validator reward), so this category of bug is structurally
        eliminated.

        Must be called BEFORE reversing the transaction list so that
        role/stake tables still reflect the state at the time the block
        was applied.
        """
        # 1. Rebuild fee_pool_sat the same way _distribute_rewards saw it
        fee_pool_sat = 0
        for tx in block.transactions:
            if tx.sender == "COINBASE":
                continue
            if tx.tx_type in (Transaction.TYPE_DEPLOY, Transaction.TYPE_CALL):
                receipt = self.storage.get_vvm_receipt(tx.tx_id)
                fee_pool_sat += self._vvm_fee_pool_credit_sat(tx, receipt)
            else:
                fee_pool_sat += tx.compute_fee_sat()

        total_sat = self.compute_reward_sat(block.index) + fee_pool_sat

        # ── v7.2.0: ROLE-BASED ROLLBACK (mirror of _distribute_rewards) ────
        # Must iterate roles in the SAME order and compute the SAME shares
        # as _distribute_rewards did when this block was applied, then debit
        # each credit.  With v7.2.0's on-chain REGISTER model the role set
        # during rollback is identical to the role set during apply (roles
        # are always consistent with block height).
        validators = self.storage.get_all_by_role("investor")
        miners     = self.storage.get_all_by_role("miner")

        # Bootstrap / empty-role fast path: mirror of _distribute_rewards.
        if not validators and not miners:
            if block.miner_address:
                self.storage.debit_sat(block.miner_address, total_sat)
            else:
                self.storage.debit_sat(Config.BURN_ADDRESS, total_sat)
            return

        # 2. V2 share constants — must match _distribute_rewards exactly
        s_creator_m = int(round(Config.REWARD_CREATOR        * 1_000_000))  # 200_000
        s_miners_m  = int(round(Config.REWARD_ALL_MINERS     * 1_000_000))  # 450_000
        s_val_all_m = int(round(Config.REWARD_ALL_VALIDATORS * 1_000_000))  # 350_000

        # NO-VALIDATORS REDIRECT: their 35% rolled into miners pool
        if not validators:
            s_miners_m  += s_val_all_m
            s_val_all_m  = 0

        creator_sat    = total_sat * s_creator_m // 1_000_000
        miner_pool_sat = total_sat * s_miners_m  // 1_000_000
        v_pool_sat     = total_sat * s_val_all_m // 1_000_000 if validators else 0
        total_credited = creator_sat + miner_pool_sat + v_pool_sat
        burn_sat       = total_sat - total_credited

        # 3. Reverse proposer credit (20%)
        if creator_sat > 0 and block.miner_address:
            self.storage.debit_sat(block.miner_address, creator_sat)

        # 4. Reverse rounding-dust burn
        if burn_sat > 0:
            self.storage.debit_sat(Config.BURN_ADDRESS, burn_sat)

        # 5. Reverse all-miners credits (45%, or 80% when no validators)
        if miner_pool_sat > 0:
            if miners:
                weights = [self._miner_reward_weight(m, block.index - 1)
                           for m in miners]
                active = [(m, w) for m, w in zip(miners, weights) if w > 0]
                remainder_sat = miner_pool_sat
                if active:
                    total_weight = sum(w for _, w in active)
                    for m, weight in active:
                        share_sat = miner_pool_sat * weight // total_weight
                        if share_sat > 0:
                            self.storage.debit_sat(m["address"], share_sat)
                        remainder_sat -= share_sat
                # Remainder was credited to block proposer in _distribute_rewards
                if remainder_sat > 0 and block.miner_address:
                    self.storage.debit_sat(block.miner_address, remainder_sat)
            else:
                # No registered miners → entire pool was credited to proposer.
                self.storage.debit_sat(block.miner_address, miner_pool_sat)

        # 6. Reverse all-validators credits (35%) — only if validators registered
        if v_pool_sat > 0 and validators:
            stakes = [max(int(round(float(v.get("stake", 0)) * 1_000_000)), 0)
                      for v in validators]
            total_stake = sum(stakes)
            if total_stake > 0:
                remainder_sat = v_pool_sat
                for i, v in enumerate(validators):
                    share_sat = v_pool_sat * stakes[i] // total_stake
                    if share_sat > 0:
                        self.storage.debit_sat(v["address"], share_sat)
                    remainder_sat -= share_sat
                # Remainder was credited to block proposer in _distribute_rewards
                if remainder_sat > 0:
                    self.storage.debit_sat(block.miner_address, remainder_sat)
            else:
                # total_stake == 0 → entire pool was redirected to proposer
                self.storage.debit_sat(block.miner_address, v_pool_sat)

    def _rollback_block(self, block: Block):
        """
        Reverse a block's state changes.
        Re-adds non-coinbase transactions back to the mempool so they can be
        re-mined in the new canonical chain.
        VVM transactions are rolled back using the storage_delta from their receipt.
        """
        # Mempool.restore() deliberately refuses a tx that is still present in
        # the confirmed transaction indexes. Queue orphaned transactions and
        # restore them only after storage.delete_block() has removed the block,
        # tx indexes, and rollback replay-guard entries.
        _mempool_restore: list[Transaction] = []

        def _queue_mempool_restore(tx_obj: Transaction) -> None:
            if tx_obj.is_expired():
                log.debug(
                    "[ROLLBACK] Skipping mempool re-add for expired tx %s",
                    tx_obj.tx_id[:8])
                return
            _mempool_restore.append(tx_obj)

        def _parse_selfdestruct_transfers(tx_obj, receipt_obj):
            """Return canonical (source, beneficiary, amount_sat) triples.

            Current receipts persist the source explicitly.  Older receipts
            used [beneficiary, amount] only, so derive the source from the
            top-level CALL/DEPLOY recipient or, as a last deterministic
            fallback, from the recorded self-destruct target list.  If a
            legacy record cannot be mapped safely, rollback fails closed
            rather than guessing a balance source.
            """
            storage_delta_obj = (receipt_obj or {}).get("storage_delta") or {}
            raw_transfers = storage_delta_obj.get(
                "__self_destruct_transfers__", [])
            if not raw_transfers:
                return []

            targets = [str(a) for a in storage_delta_obj.get(
                "__selfdestructed_contracts__", []) if a]
            parsed = []
            for idx, item in enumerate(raw_transfers):
                if not isinstance(item, (list, tuple)):
                    raise RuntimeError(
                        f"[ROLLBACK] malformed SELFDESTRUCT transfer record "
                        f"for tx {tx_obj.tx_id[:8]}")
                if len(item) == 3:
                    source, beneficiary, amount_sat = item
                elif len(item) == 2:
                    beneficiary, amount_sat = item
                    if tx_obj.tx_type == Transaction.TYPE_CALL:
                        source = tx_obj.receiver or ""
                    elif tx_obj.tx_type == Transaction.TYPE_DEPLOY:
                        source = (receipt_obj or {}).get("contract_addr") or ""
                    elif idx < len(targets):
                        source = targets[idx]
                    elif len(targets) == 1:
                        source = targets[0]
                    else:
                        raise RuntimeError(
                            f"[ROLLBACK] cannot determine SELFDESTRUCT source "
                            f"for tx {tx_obj.tx_id[:8]}")
                else:
                    raise RuntimeError(
                        f"[ROLLBACK] malformed SELFDESTRUCT transfer tuple "
                        f"for tx {tx_obj.tx_id[:8]}")

                try:
                    source = str(source or "")
                    beneficiary = str(beneficiary or "")
                    amount_sat = int(amount_sat)
                except (TypeError, ValueError):
                    raise RuntimeError(
                        f"[ROLLBACK] malformed SELFDESTRUCT transfer values "
                        f"for tx {tx_obj.tx_id[:8]}")
                if not source or not beneficiary or amount_sat < 0:
                    raise RuntimeError(
                        f"[ROLLBACK] invalid SELFDESTRUCT transfer values "
                        f"for tx {tx_obj.tx_id[:8]}")
                parsed.append((source, beneficiary, amount_sat))
            return parsed

        # ── ROLLBACK PREFLIGHT: VVM balance-reversal safety ──────────────────
        # Rollback reverses a successful VVM transaction in this order:
        #
        #   1. reverse SELFDESTRUCT beneficiary credits
        #   2. reverse the top-level CALL/DEPLOY value transfer
        #   3. refund the sender's amount + actual gas fee
        #
        # A single balance check against the final state is therefore wrong for
        # a self-destructing value recipient: the recipient may be empty at the
        # end of the block because its balance was immediately forwarded to the
        # beneficiary.  The old preflight rejected exactly that valid rollback.
        #
        # Use a read-only balance overlay and simulate the same VVM reversal
        # order in reverse transaction order.  This catches the dangerous case
        # where a beneficiary really has spent the transferred value, while
        # allowing funds that are restored by a later rollback step to satisfy
        # an earlier reversal in the same block.  No persistent state is changed
        # by this preflight.
        _pf_balances: Dict[str, int] = {}

        def _pf_get_balance(address: str) -> int:
            if address not in _pf_balances:
                _pf_balances[address] = self.storage.get_balance_sat(address)
            return _pf_balances[address]

        def _pf_debit(address: str, amount_sat: int) -> bool:
            if amount_sat <= 0:
                return True
            current = _pf_get_balance(address)
            if current < amount_sat:
                return False
            _pf_balances[address] = current - amount_sat
            return True

        def _pf_credit(address: str, amount_sat: int) -> None:
            if amount_sat <= 0:
                return
            _pf_balances[address] = _pf_get_balance(address) + amount_sat

        for _pf_tx in reversed(block.transactions):
            if _pf_tx.sender == "COINBASE":
                continue
            if _pf_tx.tx_type not in (Transaction.TYPE_DEPLOY, Transaction.TYPE_CALL):
                continue

            _pf_receipt = self.storage.get_vvm_receipt(_pf_tx.tx_id)
            if not _pf_receipt:
                continue

            _pf_success = bool(_pf_receipt.get("success", False))
            _pf_sd = _pf_receipt.get("storage_delta") or {}

            # Reverse SELFDESTRUCT transfers first, exactly as the main rollback
            # path does.  This is what replenishes a self-destructing contract's
            # balance before its original CALL/DEPLOY value is reversed.
            if _pf_success:
                for (_pf_source, _pf_beneficiary, _pf_sd_amount) in \
                        _parse_selfdestruct_transfers(_pf_tx, _pf_receipt):
                    _pf_sd_amount = int(_pf_sd_amount)
                    if _pf_sd_amount <= 0:
                        continue
                    if not _pf_debit(_pf_beneficiary, _pf_sd_amount):
                        raise RuntimeError(
                            f"[ROLLBACK] unsafe SELFDESTRUCT rollback for tx "
                            f"{_pf_tx.tx_id[:8]}: beneficiary "
                            f"{_pf_beneficiary[:12]} has "
                            f"{_pf_get_balance(_pf_beneficiary)} sat, but "
                            f"reversing requires {_pf_sd_amount} sat. "
                            f"Rollback descendants first so the transferred "
                            f"value is restored before rolling back this block.")
                    _pf_credit(_pf_source, _pf_sd_amount)

            # Successful VVM transactions reverse their exact top-level value
            # destination before refunding the sender.  Reverted transactions
            # do not reverse a value transfer because _apply_vvm_tx already
            # refunded that value during forward execution.
            _pf_meta = _pf_sd.get("__value_transfer__")
            _pf_recipient = ""
            _pf_amount_sat = 0
            if _pf_success:
                if isinstance(_pf_meta, dict):
                    try:
                        _pf_recipient = str(_pf_meta.get("address") or "")
                        _pf_amount_sat = int(_pf_meta.get("amount_sat", 0))
                    except (TypeError, ValueError):
                        _pf_recipient = ""
                        _pf_amount_sat = 0
                if not _pf_recipient:
                    if _pf_tx.tx_type == Transaction.TYPE_DEPLOY:
                        _pf_recipient = str(_pf_receipt.get("contract_addr") or "")
                    elif _pf_tx.tx_type == Transaction.TYPE_CALL:
                        _pf_recipient = str(_pf_tx.receiver or "")
                if _pf_amount_sat <= 0:
                    _pf_amount_sat = to_satoshi(_pf_tx.amount)
                if _pf_amount_sat > 0:
                    if not _pf_recipient:
                        raise RuntimeError(
                            f"[ROLLBACK] cannot determine VVM value-transfer "
                            f"recipient for tx {_pf_tx.tx_id[:8]} during preflight")
                    if not _pf_debit(_pf_recipient, _pf_amount_sat):
                        raise RuntimeError(
                            f"[ROLLBACK] unsafe VVM rollback for tx {_pf_tx.tx_id[:8]}: "
                            f"recipient {_pf_recipient[:12]} has "
                            f"{_pf_get_balance(_pf_recipient)} sat, but reversing "
                            f"requires {_pf_amount_sat} sat. Rollback descendants "
                            f"first so the transferred value is restored before "
                            f"rolling back this block.")

            # Mirror the sender refund so an earlier transaction in the same
            # block can correctly use funds restored by this later transaction.
            gas_used = int(_pf_receipt.get("gas_used", 0) or 0)
            actual_gas_fee_sat = gas_fee_to_sat(gas_used, _pf_tx.gas_price)
            if _pf_success:
                _pf_refund_sat = to_satoshi(_pf_tx.amount) + actual_gas_fee_sat
            else:
                _pf_refund_sat = actual_gas_fee_sat
            if (_pf_receipt.get("revert_reason") == "Balance debit failed"):
                _pf_refund_sat = 0
            _pf_credit(_pf_tx.sender, _pf_refund_sat)

        # ── Exact REGISTER rollback ─────────────────────────────────────────
        # REGISTER role changes are deferred until after reward distribution
        # during forward application.  Rollback therefore restores the exact
        # pre-block role snapshot BEFORE reversing rewards, because rewards for
        # this block were calculated from that pre-block validator/miner set.
        register_txs = [
            tx for tx in block.transactions
            if tx.tx_type == Transaction.TYPE_REGISTER
            and not Transaction.is_identity_claim(tx)
        ]
        if register_txs:
            role_snap = self.storage.get_block_role_snapshot(
                block.index, block.block_hash)
            if role_snap is None:
                # Never guess at a prior role state.  A best-effort inverse can
                # silently corrupt stake, slashing, or reward attribution.
                raise RuntimeError(
                    f"[ROLLBACK] exact REGISTER role snapshot missing for "
                    f"block #{block.index} {block.block_hash[:16]}...; "
                    f"refusing unsafe rollback")
            self.storage.restore_roles(role_snap)

        # Reverse reward distribution (mirror of apply_block order:
        # _distribute_rewards is called AFTER the tx loop, so we undo it
        # BEFORE the tx loop during rollback) -- now AFTER the REGISTER
        # pre-pass above, so get_all_by_role() here sees the same
        # pre-block-N role/stake set _distribute_rewards originally used.
        self._rollback_rewards(block)

        # Reverse transactions in reverse order
        for tx in reversed(block.transactions):
            if tx.sender == "COINBASE":
                # Coinbase TX is the issuance record only — no direct credit
                # was applied in apply_block, so nothing to reverse here.
                continue

            # AUDIT-FIX (Batch D): restore the sender's nonce. apply_block
            # unconditionally advances tx.sender's nonce for every non-
            # coinbase tx via set_nonce(sender, max(current, tx.nonce+1))
            # — this holds regardless of tx.receiver, including the
            # VSD_GLOBAL_MARKET broadcast case — but this method never had
            # a matching decrement, so storage.account_nonces silently
            # drifted out of sync with the chain it is supposed to
            # summarize every time a block was rolled back. Two concrete
            # consequences of leaving it stale: (1) the mempool restore
            # call below for this very tx would see a too-high chain_nonce
            # and be rejected every time, permanently and silently losing
            # the transaction; (2) any node that experienced this rollback
            # would keep believing this sender's nonce is higher than it
            # truly is, so that node alone would reject a subsequent,
            # perfectly valid block containing a correctly-nonced tx from
            # this sender that every other honest node accepts — a
            # node-local fork.
            #
            # We iterate in reverse block order (see the loop above), and
            # reorg()/_hard_reset_to() likewise roll back blocks tip-
            # downward, so for a sender with multiple affected txs this
            # naturally lowers the stored nonce monotonically to the
            # lowest nonce that sender used among everything being rolled
            # back. The "only if lower" guard mirrors apply_block's own
            # max()-based never-lower invariant in the forward direction —
            # rolling back can only rewind the nonce, never raise it.
            _cur_nonce = self.storage.get_nonce(tx.sender)
            if tx.nonce < _cur_nonce:
                self.storage.set_nonce(tx.sender, tx.nonce)

            # ── VVM rollback ───────────────────────────────────────────────────
            if tx.tx_type in (Transaction.TYPE_DEPLOY, Transaction.TYPE_CALL):
                receipt = self.storage.get_vvm_receipt(tx.tx_id)
                # ── v7.1.11 BUG-3 FIX (Catastrophic Double-Credit Exploit) ──
                # Pre-fix code unconditionally refunded
                #     refund_sat = to_satoshi(tx.amount) + actual_gas_fee_sat
                # even when the original tx had NEVER debited the sender (it
                # failed at the upfront balance check in _apply_vvm_tx).  An
                # attacker could submit a massive VVM transfer with zero
                # balance, get receipt.success=False, then force a 1-block
                # reorg — and the rollback would credit them the entire
                # never-spent amount.  Pure money-printer.
                #
                # We now identify the never-debited case by the receipt's
                # revert_reason (set in the v7.1.11 _apply_vvm_tx fix) and
                # skip both the refund AND the mempool re-add (the tx is
                # invalid by construction; re-mining it would just fail
                # again forever).
                _never_debited = (
                    receipt is not None
                    and not receipt.get("success", False)
                    and receipt.get("revert_reason") == "Balance debit failed"
                )
                if _never_debited:
                    log.info(
                        f"[ROLLBACK] Skipping refund for never-debited "
                        f"VVM tx {tx.tx_id[:8]} from {tx.sender[:12]} "
                        f"(was rejected at upfront-debit step)")
                    continue

                if receipt and receipt["success"]:
                    # VVM rollback has two distinct account classes:
                    #   • contracts CREATED by this orphaned tx: physically
                    #     remove account + storage so deterministic replay can
                    #     call save_contract() again;
                    #   • pre-existing contracts SELFDESTRUCTed by this tx:
                    #     restore their destroyed flag to live.
                    #
                    # This distinction is consensus-critical.  A soft-delete of
                    # a newly-created contract leaves the address occupied, and
                    # save_contract() intentionally ignores conflicting rows.
                    _sd = receipt.get("storage_delta") or {}
                    _deployed = set(
                        str(a) for a in _sd.get("__deployed_contracts__", [])
                        if a)
                    _selfdestructed = set(
                        str(a) for a in _sd.get("__selfdestructed_contracts__", [])
                        if a)

                    # Restore direct state-channel table/account effects to the
                    # exact pre-VVM state.  The journal snapshot is intentionally
                    # taken after the VVM tx's upfront amount/gas debit and before
                    # channel deposit/settlement mutations, so the ordinary
                    # top-level rollback logic below can then reverse the tx-level
                    # amount and fee exactly once.
                    _state_channels_before = _sd.get("__state_channels_before__")
                    if isinstance(_state_channels_before, dict):
                        _restored_accounts = {}
                        for _addr, _snap in (
                                _state_channels_before.get("accounts", {}) or {}).items():
                            if isinstance(_snap, (list, tuple)) and len(_snap) == 4:
                                _restored_accounts[str(_addr)] = tuple(_snap)
                        self.storage.restore_state_channel_journal({
                            "channels": dict(_state_channels_before.get(
                                "channels", {}) or {}),
                            "accounts": _restored_accounts,
                        })

                    # Backward compatibility for receipts produced before the
                    # reserved __deployed_contracts__ key existed.  A top-level
                    # DEPLOY still has its deterministic contract_addr.
                    if (tx.tx_type == Transaction.TYPE_DEPLOY
                            and receipt.get("contract_addr")):
                        _self_addr = str(receipt["contract_addr"])
                        _deployed.add(_self_addr)

                    # Restore real storage slots first, but NEVER recreate slots
                    # for a contract that was itself deployed by this orphaned
                    # block.  That entire contract is removed below.
                    slot_groups: Dict[str, dict] = {}
                    for slot_key, prev_hex in _sd.items():
                        if slot_key.startswith("__"):
                            continue
                        if ":" not in slot_key:
                            log.warning(
                                "[ROLLBACK] Ignoring malformed VVM storage_delta "
                                "key %r for tx %s", slot_key, tx.tx_id[:8])
                            continue
                        addr, slot = slot_key.split(":", 1)
                        if addr in _deployed:
                            continue
                        if addr not in slot_groups:
                            slot_groups[addr] = self.storage.get_all_contract_slots(addr)
                        prev_val = int(prev_hex, 16) if prev_hex != "0x0" else 0
                        self.storage.sstore(addr, slot, prev_val)
                        tag_meta = _sd.get("__storage_tag_delta__", {})
                        prev_tag = tag_meta.get(slot_key) if isinstance(tag_meta, dict) else None
                        self.storage.set_storage_tag(
                            addr, slot, int(prev_tag) if prev_tag is not None else 0)
                    for addr in slot_groups:
                        self.storage.update_contract_storage_root(addr)

                    # Reverse SELFDESTRUCT beneficiary credits.  These debits
                    # are made before account restoration so a contract that is
                    # both a beneficiary and a self-destruct target in one tx
                    # follows the same balance semantics as the forward path.
                    for _sd_source, _addr, _amt in \
                            _parse_selfdestruct_transfers(tx, receipt):
                        _amt = int(_amt)
                        if _amt <= 0:
                            continue
                        if not self.storage.debit_sat(_addr, _amt):
                            raise RuntimeError(
                                f"[ROLLBACK] cannot reverse SELFDESTRUCT "
                                f"credit of {_amt} sat to {_addr[:12]} for "
                                f"tx {tx.tx_id[:8]}")
                        self.storage.credit_sat(_sd_source, _amt)

                    # New receipts persist the complete VM balance overlay.
                    # Reverse it after SELFDESTRUCT credits have been reversed,
                    # restoring exactly the pre-transaction account balances.
                    _vvm_balance_meta = _sd.get("__vvm_balance_deltas__")
                    if isinstance(_vvm_balance_meta, dict):
                        for _addr, _delta_raw in _vvm_balance_meta.items():
                            _delta = int(_delta_raw)
                            if _delta > 0:
                                if not self.storage.debit_sat(str(_addr), _delta):
                                    raise RuntimeError(
                                        f"[ROLLBACK] cannot reverse VVM balance credit of "
                                        f"{_delta} sat from {str(_addr)[:12]} for tx {tx.tx_id[:8]}")
                            elif _delta < 0:
                                self.storage.credit_sat(str(_addr), -_delta)
                    else:
                        # VVM-VALUE-ROLLBACK-FIX: reverse the successful top-level
                        # DEPLOY/CALL value transfer before refunding the sender.
                        # Without this debit, rollback refunds the sender while the
                        # contract keeps the original value, creating tx.amount new
                        # satoshis of supply. New receipts persist the exact target;
                        # older receipts use deterministic fallbacks.
                        _value_meta = _sd.get("__value_transfer__")
                        _value_recipient = ""
                        _value_amount_sat = 0
                        if isinstance(_value_meta, dict):
                            try:
                                _value_recipient = str(_value_meta.get("address") or "")
                                _value_amount_sat = int(_value_meta.get("amount_sat", 0))
                            except (TypeError, ValueError):
                                _value_recipient = ""
                                _value_amount_sat = 0
                        if not _value_recipient:
                            if tx.tx_type == Transaction.TYPE_DEPLOY:
                                _value_recipient = str(receipt.get("contract_addr") or "")
                            elif tx.tx_type == Transaction.TYPE_CALL:
                                _value_recipient = str(tx.receiver or "")
                        if _value_amount_sat <= 0:
                            # Backward compatibility for receipts created before
                            # __value_transfer__ was persisted. Successful VVM
                            # transactions debit tx.amount upfront and credit the
                            # exact same amount on success.
                            _value_amount_sat = to_satoshi(tx.amount)

                        if _value_amount_sat > 0:
                            if not _value_recipient:
                                raise RuntimeError(
                                    f"[ROLLBACK] cannot determine VVM value-transfer "
                                    f"recipient for tx {tx.tx_id[:8]}")
                            if not self.storage.debit_sat(
                                    _value_recipient, _value_amount_sat):
                                raise RuntimeError(
                                    f"[ROLLBACK] cannot reverse VVM value transfer of "
                                    f"{_value_amount_sat} sat from {_value_recipient[:12]} "
                                    f"for tx {tx.tx_id[:8]}")

                    # Physically remove every contract created by this orphaned
                    # transaction, including nested CREATE/CREATE2 children.
                    # Capture their code hashes before deletion; code is shared
                    # by hash, so only delete a blob after ALL accounts have
                    # been removed and no other live account references it.
                    _code_hashes_to_check: set[str] = set()
                    for _dep_addr in _deployed:
                        _removed_hash = self.storage.remove_contract(_dep_addr)
                        if _removed_hash:
                            _code_hashes_to_check.add(str(_removed_hash))
                    for _code_hash in _code_hashes_to_check:
                        try:
                            if self.storage.count_contracts_by_code_hash(
                                    _code_hash) == 0:
                                self.storage.delete_contract_code(_code_hash)
                        except Exception as _cc_err:
                            log.error(
                                "[ROLLBACK] code cleanup failed for %s: %s",
                                _code_hash[:16], _cc_err)

                    # A pre-existing contract affected by SELFDESTRUCT must
                    # become live again.  If an address was newly deployed in
                    # the same tx, deletion above takes precedence.
                    _restore_live = _selfdestructed - _deployed
                    for _sd_addr in _restore_live:
                        try:
                            if self.storage._pgx_enabled:
                                self.storage._pg_exec(
                                    "UPDATE contract_accounts SET destroyed=FALSE "
                                    "WHERE address=$1", _sd_addr)
                                try:
                                    with self.storage._aux_lock:
                                        self.storage._conn().execute(
                                            "UPDATE contract_accounts SET destroyed=0 "
                                            "WHERE address=?", (_sd_addr,))
                                        self.storage._conn().commit()
                                except Exception:
                                    pass
                            else:
                                self.storage._conn().execute(
                                    "UPDATE contract_accounts SET destroyed=0 "
                                    "WHERE address=?", (_sd_addr,))
                                self.storage._conn().commit()
                        except Exception as _und_e:
                            log.error(
                                "CRITICAL: rollback could not restore "
                                "SELFDESTRUCT target %s: %s",
                                _sd_addr[:16], _und_e)

                    # Remove deleted addresses from the root-recompute set; live
                    # SELFDESTRUCT targets remain in touched contracts and need
                    # their restored storage_root recomputed.
                    for _dep_addr in _deployed:
                        slot_groups.pop(_dep_addr, None)

                    for addr in set(slot_groups) | _restore_live:
                        try:
                            if self.storage.get_contract(addr):
                                self.storage.update_contract_storage_root(addr)
                        except Exception as _root_e:
                            log.warning(
                                "[ROLLBACK] VVM storage_root recompute failed "
                                "for %s: %s", addr[:16], _root_e)

                # Reverse the sender-side net effect of this VVM tx.
                #
                # SUCCESS: the upfront debit was `amount + max_gas`; unused gas
                # was already refunded, and `amount` was transferred to the
                # contract.  Rollback therefore reverses the contract value
                # transfer above AND refunds `amount + actual_gas_fee` here.
                #
                # REVERT/FAIL AFTER THE UPFRONT DEBIT: _apply_vvm_tx already
                # refunded the call value to the sender.  Only the gas/penalty
                # actually consumed remains charged.  Adding tx.amount again
                # here would double-refund a reverted value-bearing call and
                # create exactly tx.amount new VSD on every such rollback.
                #
                # PRE-EXECUTION FAILURES (invalid name, collision, etc.) are
                # naturally covered by the same rule: their receipt.gas_used
                # records the amount of any penalty actually retained, while
                # the already-refunded value contributes nothing here.
                gas_used = receipt["gas_used"] if receipt else tx.gas_limit
                actual_gas_fee_sat = gas_fee_to_sat(gas_used, tx.gas_price)
                if receipt and receipt.get("success", False):
                    refund_sat = to_satoshi(tx.amount) + actual_gas_fee_sat
                else:
                    refund_sat = actual_gas_fee_sat
                if refund_sat > 0:
                    self.storage.credit_sat(tx.sender, refund_sat)
                # FIX-3: Only re-add to mempool when the tx is still live
                # (not expired) and the nonce is still valid after rollback.
                # Mempool.add() already re-checks expiry and nonce, but an
                # expired or nonce-stale tx would just pollute the mempool
                # temporarily before _purge_expired or nonce enforcement
                # cleans it up — costing unnecessary DB writes.
                _queue_mempool_restore(tx)
                continue

            # ── REGISTER tx rollback ───────────────────────────────────────────
            # apply_block debited ONLY the fee for a REGISTER tx (tx.amount is
            # the stake, which is a LOCK on the sender's existing balance — it is
            # never transferred out).  The role-table revert was done in the
            # pre-pass above.  Here we only refund the fee and re-add to mempool.
            # We must NOT fall through to the standard path which would
            # incorrectly try debit_sat(receiver, amount_sat) on a balance that
            # was never credited there, corrupting balances in the opposite
            # direction.
            if tx.tx_type == Transaction.TYPE_REGISTER:
                fee_sat = tx.compute_fee_sat()
                if fee_sat > 0:
                    self.storage.credit_sat(tx.sender, fee_sat)
                _queue_mempool_restore(tx)
                continue

            # ── TYPE_ROLLUP rollback ───────────────────────────────────────────
            # A TYPE_ROLLUP tx has amount=0, fee=0 (enforced by validation), so
            # there are no L1 balance mutations to reverse.  The only real
            # side-effect is layer2.commit_batch() which added a snapshot entry
            # to Layer2State._history and advanced _last_batch_id.  That L2
            # state is rolled back by the outer rollback() / reorg() callers
            # which invoke layer2.rollback_to_height() AFTER _rollback_block
            # returns — so nothing extra is needed here.  We re-add to mempool
            # so the sequencer can re-submit after the chain heals.
            if tx.tx_type == Transaction.TYPE_ROLLUP:
                _queue_mempool_restore(tx)
                continue

            # ── Standard transfer rollback (satoshi) ────────────────────────────
            fee_sat = tx.compute_fee_sat()
            amount_sat = to_satoshi(tx.amount)
            total_debit_sat = amount_sat + fee_sat
            # ── L2 → L1 WITHDRAWAL ROLLBACK ───────────────────────────────────
            # apply_block's withdrawal hook performed THREE extra mutations
            # beyond the standard debit/credit:
            #   a) credited L2_WITHDRAW_ADDRESS (standard path — reversed below)
            #   b) debited L2_BRIDGE_ADDRESS escrow
            #   c) credited tx.sender from escrow
            # We must reverse (b) and (c) here, and restore the L2 tree balance.
            # The standard rollback below reverses (a) via debit_sat(receiver).
            if tx.receiver == L2_WITHDRAW_ADDRESS and amount_sat > 0:
                layer2 = getattr(self, "layer2", None)
                # Reverse (c): debit the amount that was credited to sender
                # by the hook (standard rollback credit_sat below will
                # restore the original tx debit — we only undo the hook extra).
                if not self.storage.debit_sat(tx.sender, amount_sat):
                    log.warning(
                        f"[ROLLBACK] L2-withdrawal hook reversal: "
                        f"cannot debit sender {tx.sender[:12]} for hook credit")
                # Reverse (b): credit bridge escrow back.
                self.storage.credit_sat(L2_BRIDGE_ADDRESS, amount_sat)
                # Restore L2 tree: re-credit the sender's L2 balance that
                # was debited by the hook.
                if layer2 is not None:
                    try:
                        ok_rb, msg_rb = layer2.L2_deposit(tx.sender, amount_sat)
                        if not ok_rb:
                            log.error(
                                f"[ROLLBACK] L2_deposit rollback failed for "
                                f"{tx.sender[:12]}: {msg_rb}")
                        else:
                            log.info(
                                f"[ROLLBACK] L2 balance restored: "
                                f"{tx.sender[:12]} +{amount_sat:,} sat")
                    except Exception as _l2rb_e:
                        log.error(
                            f"[ROLLBACK] L2_deposit rollback raised: {_l2rb_e}")
            # ── L1 → L2 DEPOSIT ROLLBACK ──────────────────────────────────────
            # apply_block's deposit hook (receiver == L2_BRIDGE_ADDRESS) called
            # layer2.L2_deposit(sender, amount_sat), crediting the sender's L2
            # tree balance.  The standard path below correctly reverses the L1
            # side (debit_sat(L2_BRIDGE_ADDRESS) and credit_sat(sender+fee)),
            # but WITHOUT this block the sender's L2 balance remains inflated
            # after rollback — an invisible extra-credit on the L2 tree that
            # breaks the L2 supply invariant (L2 total supply > L1 escrow).
            elif tx.receiver == L2_BRIDGE_ADDRESS and amount_sat > 0:
                layer2 = getattr(self, "layer2", None)
                if layer2 is not None:
                    try:
                        ok_rb, msg_rb = layer2.L2_withdraw(tx.sender, amount_sat,
                                                           l1_height=block.index,
                                                           l1_block_hash=block.block_hash)
                        if not ok_rb:
                            log.error(
                                f"[ROLLBACK] L2_withdraw (deposit undo) failed for "
                                f"{tx.sender[:12]}: {msg_rb}")
                        else:
                            log.info(
                                f"[ROLLBACK] L2 deposit reversed: "
                                f"{tx.sender[:12]} -{amount_sat:,} sat")
                    except Exception as _l2dep_rb_e:
                        log.error(
                            f"[ROLLBACK] L2_withdraw (deposit undo) raised: "
                            f"{_l2dep_rb_e}")
            # Reverse standard transfer: debit receiver, credit sender+fee.
            # Mempool restoration is deferred until after delete_block().
            # AUDIT-FIX (Batch D): the forward path now credits
            # Config.BURN_ADDRESS for a VSD_GLOBAL_MARKET broadcast instead
            # of skipping the credit entirely -- mirror that here by
            # debiting the burn address instead of skipping the debit, so
            # reorg-rollback of a broadcast-containing block still nets to
            # zero exactly like it did before (when there was nothing to
            # reverse because nothing had been credited).
            debit_target = (Config.BURN_ADDRESS
                            if tx.receiver == "VSD_GLOBAL_MARKET" else tx.receiver)
            if not self.storage.debit_sat(debit_target, amount_sat):
                log.warning(f"Reorg rollback: cannot debit receiver {debit_target[:12]}")
            self.storage.credit_sat(tx.sender, total_debit_sat)
            # Mempool restoration is deferred until the confirmed block is
            # removed from storage (see _mempool_restore above).
            _queue_mempool_restore(tx)
        # EVENT-1 FIX: clean up the contract event index for this block.
        # Pre-fix, delete_block_events() was defined but never called, so
        # after a reorg the index retained entries for blocks that no
        # longer exist on the canonical chain.  Subsequent
        # get_events_by_contract / get_events_by_topic queries returned
        # stale events from rolled-back blocks, which is a silent
        # correctness bug for any contract event watcher.
        try:
            ev_index = getattr(self, "_event_index", None)
            if ev_index is not None:
                ev_index.delete_block_events(block.index)
        except Exception as _ev_err:
            log.warning(f"[ROLLBACK] event index cleanup failed for "
                        f"block {block.index}: {_ev_err}")
        # Remove the block and all canonical indexes derived from it. A block
        # deliberately orphaned by rollback/reorg must also release its tx ids
        # from the replay guard; those txs are no longer canonical.
        _rolled_back_tx_ids = [tx.tx_id for tx in block.transactions]
        if not self.storage.delete_block(
                block.index, rollback_tx_ids=_rolled_back_tx_ids):
            raise RuntimeError(
                f"Failed to delete rolled-back block {block.index} from storage")

        # Clear duplicate-application memory immediately after the canonical
        # delete succeeds. No later bookkeeping failure may resurrect the old
        # in-memory "already applied" state for a block that no longer exists.
        self._applied_block_hashes.discard(block.block_hash)

        # The reward distributor increments cumulative NEW issuance once per
        # block. Reverse it only after block deletion has succeeded, so a failed
        # storage delete cannot leave the supply counter ahead of the chain.
        self.storage.decrement_cumulative_issued_sat(
            self.compute_reward_sat(block.index))

        # Confirmed indexes are now gone, so mempool.restore() can legitimately
        # accept the original tx ids back into the pool.
        for _tx in _mempool_restore:
            _ok, _msg = self.mempool.restore(_tx)
            if not _ok:
                log.warning(
                    "[ROLLBACK] Could not restore tx %s to mempool: %s",
                    _tx.tx_id[:8], _msg)

    def reorg(self, new_chain: List[Block], *,
              allow_deep_no_investor: bool = False,
              enforce_deep_tiebreak: bool = False) -> Tuple[bool, str]:
        """
        Perform a chain reorganisation.
        new_chain: ordered list of blocks starting from the fork point.
        Accepted when the replacement chain satisfies Visold's fork-choice
        rule and every replacement block can be applied successfully.

        Fix #2 — Finality vs Chain Growth Boundary:
        A finalized block is normally irreversible by protocol definition.
        The ordinary reorg path therefore rejects any replacement whose fork
        point is at or below the highest finalized height.  The deep PoW-only
        synchronization path may explicitly opt into the documented
        no-investor exception; even there, the full replacement is tentative
        and any validation/application failure restores the prior canonical
        suffix before returning.

        This fence preserves BFT finality while still allowing independent
        PoW-only chains to converge when no investor/BFT validator set exists.
        """
        with self._lock:
            if not new_chain:
                return False, "Empty chain"

            fork_height = new_chain[0].index
            tip         = self.height()

            # ── Fix #2: Finality fence ────────────────────────────────────────
            # AUDIT-FIX (Batch D): this used to be a scan bounded to
            # min(tip, fork_height + 50) "for performance", which meant a
            # finalized block sitting more than 50 heights below the fork
            # point was invisible here -- and in ordinary operation
            # (POW_FINALITY_DEPTH=6 / BOOTSTRAP_POW_FINALITY_DEPTH=20 finalize
            # blocks continuously as the chain grows), that's exactly the
            # range most likely to actually contain one whenever
            # tip - fork_height > 50, since nothing else requires a reorg
            # attempted through this function to be shallow. Replaced with an
            # O(1) check against the incrementally-maintained
            # self._highest_finalized_height (updated wherever a block is
            # actually finalized — see _maybe_finalize_by_bft,
            # _maybe_finalize_by_depth, add_validator_sig, _create_genesis —
            # and seeded correctly at startup by
            # _init_highest_finalized_height for a node restarting against
            # an existing chain). This removes both the performance
            # motivation for bounding the scan and the correctness gap that
            # bound introduced, rather than just widening the bound and
            # re-introducing the same class of gap at a different depth.
            highest_finalized = self._highest_finalized_height

            if highest_finalized >= 0 and fork_height <= highest_finalized:
                if not allow_deep_no_investor:
                    return False, (
                        f"Reorg rejected: fork_height={fork_height} would roll back "
                        f"finalized block at height={highest_finalized}. "
                        f"BFT-finalized blocks are irreversible.")

                # The only caller allowed to cross the finality fence is the
                # deep-fork PoW path in accept_chain(), and only when the
                # network has no investors/BFT validators. Keep that rule
                # enforced here as well so a future caller cannot accidentally
                # turn an ordinary reorg into a finality bypass.
                if self.storage.get_all_by_role("investor"):
                    return False, (
                        "Reorg rejected: finalized history is protected while "
                        "investors/BFT validators are present.")
                log.warning(
                    "Deep PoW fork crossing finalized height %d with no "
                    "investors; using the explicit no-BFT exception with "
                    "full old-chain recovery on validation failure.",
                    highest_finalized)

            # A competing branch may be the same height. It is eligible
            # when it carries more cumulative work, or when equal work is
            # resolved by the deterministic tip-hash tiebreak below.
            new_tip = new_chain[-1].index
            if new_tip < tip:
                return False, f"New chain tip {new_tip} below current tip {tip}"

            # ── BUG-FIX (v7.1.2) — Remove two-pass dry-run validation ─────
            # The old code pre-validated ALL new_chain blocks BEFORE rolling
            # back the old chain:
            #
            #     for b in new_chain:
            #         validate_block(b)      # ← block 2 fails here because
            #                                #   block 1's parent (block 0 = genesis)
            #                                #   is in DB but block 1 itself has
            #                                #   NOT been applied yet.
            #
            # validate_block(N) needs the parent block (N-1) to already be in
            # storage to resolve prev_hash, compute expected difficulty, and
            # verify MTP.  During a reorg, the old chain above fork_height is
            # about to be rolled back — so NONE of the new_chain blocks past
            # the first can be pre-validated.  The loop failed at new_chain[1]
            # with "Previous block not found" and the entire reorg was
            # rejected — making Case 2 accept_chain() silently fail.
            #
            # Fix: skip the dry-run.  Each new_chain block is still validated
            # inside apply_block() below (apply_block → validate_block under
            # _lock), but at that point its parent has just been applied, so
            # all local-state lookups succeed.  On any failure we still have
            # the saved-old-chain restore logic.

            # ── Save old chain for rollback-of-rollback on failure (CRIT-03) ──
            # If apply_block() fails mid-way after we've already rolled back
            # the old chain, we must re-apply the saved blocks to restore a
            # consistent state.  Without this the node is left in a half-reorged
            # limbo with neither the old nor the new chain intact.
            _saved_old_blocks = []
            for idx in range(tip, fork_height - 1, -1):
                blk = self.storage.get_block(idx)
                if blk:
                    _saved_old_blocks.append(blk)
            # _saved_old_blocks is in descending order; reverse for re-apply.
            _saved_old_blocks.reverse()   # now ascending: fork_height … tip

            # ── AUDIT-FIX-4: heaviest-chain rule, not longest-chain ────────────
            # The check above (new_tip <= tip) only compares block COUNT.
            # That is the correct fork-choice rule ONLY under constant
            # difficulty. DifficultyEngine retargets roughly every block
            # (LWMA-style, bounded by MACRO_CLAMP per window — not a slow,
            # long-epoch retarget), so a chain that is longer by block count
            # can carry LESS cumulative proof-of-work than the chain it
            # would replace, letting an attacker who can grind low-
            # difficulty blocks force a reorg without ever out-hashing the
            # honest network.
            #
            # accept_chain()'s deep-reorg path (Case 3, past the finality
            # fence) already uses _cumulative_difficulty() as its fork-
            # choice tiebreak for exactly this reason. This applies the
            # identical rule here, for the shallow/common case that every
            # call to reorg() actually handles (deep reorgs never reach
            # this function — they're rejected by the finality fence
            # above). That shallow range is both the one a realistic
            # attacker can reach and the one ordinary network-latency
            # forks resolve in, so it is exactly where a correct fork-
            # choice rule matters most.
            #
            # _saved_old_blocks (just computed above) is precisely the
            # current chain's segment from fork_height..tip, so it is
            # reused directly rather than re-querying storage.
            new_work = self._cumulative_difficulty(new_chain)
            old_work = self._cumulative_difficulty(_saved_old_blocks)
            if new_work < old_work:
                return False, (
                    f"New chain tip {new_tip} has less cumulative work from "
                    f"height {fork_height} ({new_work:.2f} < {old_work:.2f}); "
                    f"rejecting to enforce the heaviest-chain rule")
            if new_work == old_work and (
                    (new_tip == tip)
                    or enforce_deep_tiebreak):
                _old_tip_hash = _saved_old_blocks[-1].block_hash if _saved_old_blocks else ""
                _new_tip_hash = new_chain[-1].block_hash
                if _new_tip_hash >= _old_tip_hash:
                    return False, (
                        f"Equal-work branch loses deterministic tip-hash "
                        f"tiebreak: {_new_tip_hash[:16]} >= "
                        f"{_old_tip_hash[:16]}")

            # Rollback current chain from tip down to fork_height
            for blk in reversed(_saved_old_blocks):
                self._rollback_block(blk)

            # ── v7.5.0-OPT LAYER-2 REORG HOOK ────────────────────────────────
            # Any RollupSubmission confirmed at an L1 height >= fork_height
            # is now on a discarded branch.  Roll the L2 tree back to the
            # most recent snapshot taken at l1_height < fork_height.  If
            # the new chain contains its own rollup submissions, they will
            # be re-applied as apply_block() processes each new block
            # below — and Layer2State.commit_batch() will re-add them to
            # the snapshot history with the new L1 heights.
            #
            # Safety: rollback_to_height() is idempotent — calling it with
            # a height that has no matching snapshot resets the tree to
            # empty (which is correct for a deep reorg below any ever-
            # confirmed batch).
            try:
                layer2 = getattr(self, "layer2", None)
                if layer2 is not None:
                    safe_l1 = fork_height - 1
                    ok_rb, msg_rb = layer2.rollback_to_height(safe_l1)
                    if not ok_rb:
                        log.error(
                            f"[L2-REORG] rollback_to_height({safe_l1}) "
                            f"returned non-OK: {msg_rb}")
                    else:
                        log.info(
                            f"[L2-REORG] L2 state rolled back to L1 height "
                            f"<= {safe_l1} ({msg_rb})")
            except Exception as _l2_rb_e:
                log.error(f"[L2-REORG] rollback hook raised: {_l2_rb_e}")

            # Capture the exact L2 state at the fork point.  If applying the
            # replacement chain fails, _rollback_block() cannot undo a committed
            # TYPE_ROLLUP tree transition by itself; this checkpoint lets the
            # recovery path restore precisely the state from which the old
            # canonical suffix must be replayed.
            _l2_reorg_base_snap = None
            try:
                if layer2 is not None:
                    _l2_reorg_base_snap = layer2.snapshot_full()
            except Exception as _l2_snap_e:
                log.error(f"[L2-REORG] failed to snapshot fork-point L2 state: {_l2_snap_e}")
                return False, f"Unable to snapshot L2 state before reorg: {_l2_snap_e}"

            # Apply new chain — on any failure, restore the old chain.
            _applied: list = []
            for b in new_chain:
                ok, msg = self.apply_block(b)
                if not ok:
                    log.error(
                        f"Reorg apply failed at block {b.index}: {msg} — "
                        f"restoring {len(_applied)} already-applied blocks "
                        f"and {len(_saved_old_blocks)} old-chain blocks")
                    # Roll back whatever we managed to apply from new_chain
                    for _rb in reversed(_applied):
                        try:
                            self._rollback_block(_rb)
                        except Exception as _rbe:
                            log.error(f"Restore rollback failed at "
                                      f"block {_rb.index}: {_rbe}")
                    # Restore the exact L2 state at the fork point before
                    # replaying the old canonical suffix.  Without this, a
                    # discarded TYPE_ROLLUP can survive because _rollback_block
                    # intentionally does not guess its L2 inverse.
                    if layer2 is not None and _l2_reorg_base_snap is not None:
                        try:
                            layer2.restore_full(_l2_reorg_base_snap)
                        except Exception as _l2_restore_e:
                            log.error(
                                f"[L2-REORG] failed to restore fork-point L2 state: "
                                f"{_l2_restore_e}")
                            return False, (
                                f"Reorg apply block {b.index}: {msg}; "
                                f"L2 recovery failed: {_l2_restore_e}")

                    # Re-apply the original chain
                    for _ob in _saved_old_blocks:
                        try:
                            self.apply_block(_ob)
                        except Exception as _obe:
                            log.error(f"Restore apply failed at "
                                      f"block {_ob.index}: {_obe}")
                    return False, f"Reorg apply block {b.index}: {msg}"
                _applied.append(b)

            # Invalidate difficulty cache for all heights at or after the fork.
            # The new chain may have different timestamps and therefore different
            # computed difficulties from the fork point onwards.
            DifficultyEngine.invalidate_cache(from_height=fork_height)

            log.info(f"Chain reorg: rolled back to {fork_height}, new tip={new_tip}")
            return True, "OK"

    def _miner_activity_credit(self, miner_address: str, tip_before: int) -> int:
        """Return deterministic recent canonical-PoW activity credit.

        The credit is derived only from already-applied canonical blocks, so
        every node computes the same value during block application and
        rollback.  A block at the newest position contributes WINDOW points;
        each older block contributes one fewer point until it expires.  This
        supplies a bounded grace period for temporary outages while excluding
        permanently idle registered miners from the miner pool.
        """
        if not miner_address or tip_before < 0:
            return 0
        window = max(1, int(Config.MINER_ACTIVITY_WINDOW))
        first = max(0, tip_before - window + 1)
        credit = 0
        for height in range(first, tip_before + 1):
            previous = self.storage.get_block(height)
            if previous is None or previous.miner_address != miner_address:
                continue
            age = tip_before - height
            credit += window - age
        return credit

    def _miner_reward_weight(self, miner: dict, tip_before: int) -> int:
        """Return fixed-point score × canonical activity weight."""
        try:
            score_micro = max(
                int(round(float(miner.get("score", 1.0)) * 1_000_000)), 1)
        except (TypeError, ValueError, OverflowError):
            score_micro = 1
        activity = self._miner_activity_credit(
            str(miner.get("address", "")), tip_before)
        return score_micro * activity

    def _distribute_rewards(self, block: Block, fee_pool_sat: int):
        """
        V2 reward distribution (v7.1.12 — Option B clean break).

        Distribution rules:
          • 20% → block proposer (miner who solved PoW).
          • 45% → all active miners ∝ hashrate score.
          • 35% → all active validators ∝ stake.
          • If NO validators are registered: their 35% rolls into the
            all-miners pool → miners share 80% total.

        No explicit burn.  Integer-division dust (typically 0-2 sat per
        block) goes to BURN_ADDRESS so the conservation invariant
            sum(all credits) == total_sat
        holds exactly in integer arithmetic.

        Determinism guarantees (consensus-critical):
          • All arithmetic is integer satoshi — no float multiplication.
          • Share fractions are expressed as millionths (parts per
            1,000,000) computed once at config-load time.
          • Iteration order over miners/validators is whatever
            storage.get_all_by_role() returns; that function MUST yield
            the same order on every node (it does — ORDER BY address
            ASC at the SQL/RocksDB layer).
          • Reward is a pure function of (block, registered roles).  It
            does NOT depend on block.validator_sigs (which are gathered
            asynchronously after broadcast and would create a live-vs-
            sync consensus split — see v7.1.11 Bug 1 changelog).

        WARNING — DO NOT EDIT THESE PERCENTAGES on a chain that has
        already produced blocks.  Changing reward consensus invalidates
        every historical state_root.  If a future change is needed,
        implement an activation-height upgrade so old blocks still
        validate under the original rules.
        """
        # ── v7.2.0: ROLE-BASED REWARDS, CONSENSUS-DETERMINISTIC ─────────────
        # As of v7.2.0, roles are populated exclusively by TYPE_REGISTER
        # transactions applied inside apply_block.  REGISTER txs at block N
        # take effect at block N+1 (they are processed AFTER _distribute_
        # rewards in apply_block).  Every node therefore has the identical
        # role set when this function runs for any given block, so the
        # iteration over get_all_by_role is consensus-safe.
        #
        # This restores the intended tokenomics split:
        #   20% → block proposer
        #   45% → all registered miners ∝ score
        #   35% → all registered investors ∝ stake
        #   (if no investors are registered, their 35% rolls into miners)
        #
        # If BOTH miner and investor tables are empty (bootstrap / legacy
        # chains), the full reward goes to the proposer — same as the
        # v7.1.10-hotfix4 safety behavior.
        # ────────────────────────────────────────────────────────────────
        # 1. Total reward (base + fees) in satoshi
        base_reward_sat = self.compute_reward_sat(block.index)
        # AUDIT-FIX-16: track cumulative NEW issuance. Deliberately only
        # base_reward_sat (the coinbase subsidy), not total_sat below —
        # fee_pool_sat is a transfer of already-existing balance from
        # senders to reward recipients, not new supply, and including it
        # here would make the conservation check trivially wrong by double-
        # counting fees as issuance.
        self.storage.increment_cumulative_issued_sat(base_reward_sat)
        total_sat = base_reward_sat + fee_pool_sat

        # 2. Gather the role set AS-OF the START of this block.  REGISTER
        #    txs inside this block will mutate roles AFTER this function
        #    returns, so this lookup correctly reflects state through N-1.
        all_validators = self.storage.get_all_by_role("investor")
        all_miners     = self.storage.get_all_by_role("miner")

        # 3. Bootstrap / empty-role fast path: no registrations yet anywhere
        #    on the chain → proposer gets everything.  Same outcome on
        #    every node because the role tables are empty on every node.
        if not all_validators and not all_miners:
            if block.miner_address:
                self.storage.credit_sat(block.miner_address, total_sat)
            else:
                self.storage.credit_sat(Config.BURN_ADDRESS, total_sat)
            return

        # 4. V2 share constants in millionths (sum to 1_000_000 exactly)
        s_creator_m = int(round(Config.REWARD_CREATOR        * 1_000_000))  # 200_000
        s_miners_m  = int(round(Config.REWARD_ALL_MINERS     * 1_000_000))  # 450_000
        s_val_all_m = int(round(Config.REWARD_ALL_VALIDATORS * 1_000_000))  # 350_000

        # 5. No-validators redirect: their 35% rolls into the miners pool
        if not all_validators:
            s_miners_m  += s_val_all_m
            s_val_all_m  = 0

        # Running total of every satoshi actually credited.
        # Burn = total_sat - total_credited_sat (only rounding dust).
        total_credited_sat = 0

        # 5. Block proposer reward (20%)
        creator_sat = total_sat * s_creator_m // 1_000_000
        self.storage.credit_sat(block.miner_address, creator_sat)
        total_credited_sat += creator_sat

        # 6. All-miners pool (45%, or 80% when no validators)
        miner_pool_sat      = total_sat * s_miners_m // 1_000_000
        credited_miners_sat = 0
        if all_miners:
            weights = [self._miner_reward_weight(m, block.index - 1)
                       for m in all_miners]
            active = [(m, w) for m, w in zip(all_miners, weights) if w > 0]
            if active:
                total_weight = sum(w for _, w in active)
                for miner, weight in active:
                    share_sat = miner_pool_sat * weight // total_weight
                    self.storage.credit_sat(miner["address"], share_sat)
                    credited_miners_sat += share_sat
                # Integer-division remainder → block proposer (deterministic)
                miner_remainder = miner_pool_sat - credited_miners_sat
                if miner_remainder > 0:
                    self.storage.credit_sat(block.miner_address, miner_remainder)
            else:
                # Registered miners exist but none has recent canonical PoW;
                # preserve conservation by assigning the pool to the proposer.
                self.storage.credit_sat(block.miner_address, miner_pool_sat)
        else:
            # No miners registered (bootstrap edge — proposer receives pool).
            self.storage.credit_sat(block.miner_address, miner_pool_sat)
        total_credited_sat += miner_pool_sat

        # 7. All-validators pool (35%) — only when validators registered
        if all_validators:
            v_pool_sat       = total_sat * s_val_all_m // 1_000_000
            val_all_credited = 0
            stakes      = [max(int(round(float(v.get("stake", 0)) * 1_000_000)), 0)
                           for v in all_validators]
            total_stake = sum(stakes)
            if total_stake > 0:
                for i, val in enumerate(all_validators):
                    v_share_sat = v_pool_sat * stakes[i] // total_stake
                    self.storage.credit_sat(val["address"], v_share_sat)
                    val_all_credited += v_share_sat
                # Integer-division remainder → block proposer
                val_remainder = v_pool_sat - val_all_credited
                if val_remainder > 0:
                    self.storage.credit_sat(block.miner_address, val_remainder)
                total_credited_sat += v_pool_sat
            else:
                # Validators registered but ALL stakes round to dust
                # (extreme edge case).  Redirect to proposer so no
                # satoshi is leaked — same v7.1.11 Bug-4 logic.
                self.storage.credit_sat(block.miner_address, v_pool_sat)
                total_credited_sat += v_pool_sat

        # 8. Burn integer-division dust to BURN_ADDRESS so
        #    sum(all credits) == total_sat exactly.  Typically 0-2 sat.
        burn_sat = total_sat - total_credited_sat
        if burn_sat > 0:
            self.storage.credit_sat(Config.BURN_ADDRESS, burn_sat)


    # ── Chain from peer (fork handling / reorg) ───────────────────────────────
    def _cumulative_difficulty(self, blocks: List[Block]):
        """Return canonical cumulative PoW work for ``blocks``.

        Visold's difficulty unit maps to per-block work proportional to
        ``2 ** (4 * D)``.  Fork choice must compare accumulated proof-of-work,
        not the arithmetic sum of difficulty labels.  Decimal arithmetic keeps
        the comparison finite and stable even near the protocol's MAX_DIFFICULTY
        where a binary float would overflow.
        """
        from decimal import Decimal, localcontext

        max_d = Decimal(str(float(Config.MAX_DIFFICULTY)))
        min_d = Decimal('0')
        total = Decimal(0)
        with localcontext() as ctx:
            ctx.prec = 80
            for block in blocks:
                try:
                    d = Decimal(str(float(block.difficulty)))
                except (TypeError, ValueError, OverflowError):
                    # Invalid consensus blocks should already have been rejected
                    # before fork choice.  Do not let malformed data poison the
                    # comparison or silently receive arbitrary work.
                    continue
                if not d.is_finite():
                    continue
                d = min(max(d, min_d), max_d)
                total += Decimal(2) ** (d * Decimal(4))
        return total

    def _find_common_ancestor(self, incoming: List[Block]) -> int:
        """
        Walk incoming blocks from oldest to newest and return the index of the
        last block that is IDENTICAL (same block_hash) to what we have stored.
        Returns -1 if no common block is found (full divergence from genesis).
        """
        common = -1
        for b in incoming:
            stored = self.storage.get_block(b.index)
            if stored and stored.block_hash == b.block_hash:
                common = b.index
            else:
                break   # divergence point found — stop scanning
        return common

    def _hard_reset_to(self, keep_height: int):
        """
        Roll back and DELETE all blocks above keep_height.
        Used when a peer's chain wins a fork-choice that crosses the finality
        fence — possible only on no-investor networks where PoW is the sole
        finality mechanism and the correct chain must be adopted regardless.
        All rolled-back blocks' transactions are returned to the mempool.

        BUG-FIX (v6.9.9.5) — balance/height inconsistency:
        When keep_height == -1 (full reset to before genesis), _rollback_block()
        alone is insufficient.  If the local chain was previously deleted while
        the SQLite balances table survived (partial data wipe), orphaned balance
        rows persist after the rollback loop — producing balance > 0 at height 0.
        Fix: after the loop, when keep_height < 0, wipe the entire balances table
        so the invariant  (chain_height == 0 ⟹ all balances == 0)  always holds
        before the peer's blocks are re-applied by accept_chain().
        """
        tip = self.height()
        for idx in range(tip, keep_height, -1):
            blk = self.storage.get_block(idx)
            if blk:
                self._rollback_block(blk)   # returns txs to mempool + deletes block

        # BUG-FIX: genesis-level reset — wipe any orphaned balance rows.
        # _rollback_block only undoes credits/debits for blocks it finds in DB.
        # If those blocks were already deleted (chain wipe without rollback),
        # orphaned rows survive and break the balance == f(chain) invariant.
        if keep_height < 0:
            try:
                self.storage.wipe_all_balances()
                log.warning(
                    "[BUG-FIX] Hard-reset to genesis: wiped all rows from "
                    "balances table to enforce balance=f(chain) invariant. "
                    "Balances will be reconstructed as peer blocks are applied.")
            except Exception as _wipe_err:
                log.error(
                    f"[BUG-FIX] Hard-reset: failed to wipe balances table: "
                    f"{_wipe_err}  — state may be inconsistent.")

        # Un-finalize the kept tip so reorg() can proceed from there.
        # Guard: get_block(-1) is meaningless; only fetch when a real block exists.
        if keep_height >= 0:
            kept = self.storage.get_block(keep_height)
            if kept and kept.finalized:
                kept.finalized = False
                self.storage.save_block(kept)

        DifficultyEngine.invalidate_cache(from_height=max(0, keep_height + 1))
        log.warning(
            f"Hard-reset: rolled back to height {keep_height} "
            f"to adopt peer's higher-work chain")

    def accept_chain(self, blocks: List[Block]) -> Tuple[bool, str]:
        """
        Accept a sequence of blocks from a peer.

        Three cases handled in order:

        1. Pure extension (blocks start above our tip) — sequential append.
        2. Standard reorg (fork above finality fence, peer longer) — reorg().
        3. Genesis-level/deep divergence (independently-mined chains, no
           investors) — compare cumulative difficulty and route the winner
           through the transactional reorg path, which restores the previous
           canonical suffix if any replacement block fails validation/application.

        Fix: the original code only handled case 1 and a narrow version of
        case 2 (fork_start <= current_tip AND incoming_tip > current_tip).
        It completely missed case 3 — the exact scenario that occurs when two
        nodes each start mining independently before connecting as peers.
        Every block on the shorter chain was already finalized (POW_FINALITY_
        DEPTH=6), so reorg() rejected the sync unconditionally.  The result:
        both nodes kept mining on separate forks forever even while peered.
        """
        with self._lock:
            if not blocks:
                return False, "Empty"

            incoming_tip  = blocks[-1].index
            current_tip   = self.height()

            # ── Case 1: Pure extension (no overlap) ───────────────────────────
            # Incoming chain starts exactly one above our tip — just append.
            # Also handles fresh-node bootstrap: height() == -1 and peer sends
            # blocks starting at index 0 (genesis).  Without the second clause
            # a fresh node always fell through to Case 3, which then called
            # validate_block(block_1) before block_0 was stored and failed with
            # "Previous block not found", leaving the chain permanently empty.
            #
            # BUG-FIX (v7.1.2) — "0 new blocks received" ghost-peer sync fail:
            #   Scenario: local node at height=0 (genesis only), peer at
            #   height=66.  _auto_sync_on_connect sends from_idx=0 (so the
            #   fork-choice can detect divergence at block 1).  The peer
            #   replies with blocks 0..65.  Old Case 1 checks failed because
            #   blocks[0].index == 0 != current_tip(=0) + 1, and current_tip
            #   was 0, not -1.  The batch fell through to Case 2 → reorg(),
            #   whose two-pass validation required block 1's parent (already
            #   present — genesis) OK but block 2's parent (block 1) NOT yet
            #   stored → "Previous block not found" → the entire 65-block
            #   payload was rejected.  Symptom: manual sync reports
            #   "0 new blocks received" even though the peer has 66 blocks.
            #
            #   Fix: also accept the case where the batch starts at or below
            #   our current tip AND the overlapping blocks match by hash
            #   (peer has the same history up to our tip, plus more).  Skip
            #   the overlap and sequentially append the new blocks.  This
            #   covers the fresh-sync case where the outbound `from_idx`
            #   deliberately starts at 0 for fork-detection purposes.
            _overlap_ok = False
            _skip_n     = 0
            if (0 <= blocks[0].index <= current_tip
                    and blocks[-1].index > current_tip):
                # Verify every overlapping block matches our stored hash.
                _overlap_ok = True
                for b in blocks:
                    if b.index > current_tip:
                        break
                    stored = self.storage.get_block(b.index)
                    if stored is None or stored.block_hash != b.block_hash:
                        _overlap_ok = False
                        break
                    _skip_n += 1

            if (blocks[0].index == current_tip + 1
                    or (current_tip == -1 and blocks[0].index == 0)
                    or _overlap_ok):
                # When we skipped overlapping blocks, drop them from the list.
                _to_apply = blocks[_skip_n:] if _overlap_ok else blocks
                if not _to_apply:
                    return True, "Already have all these blocks"
                # BUG-FIX (v7.0.0.1): Must interleave validate+apply per block.
                #
                # The old two-pass approach (validate ALL then apply ALL) is
                # broken for any batch of 2+ blocks:
                #
                #   Pass 1: validate_block(block[0]) — OK (genesis case or tip+1)
                #           validate_block(block[1]) — calls storage.get_block(0)
                #                                      → None (block 0 not in DB yet)
                #                                      → "Previous block not found"
                #                                      → entire batch rejected
                #
                # validate_block() reads the LOCAL chain state (storage.get_block,
                # get_difficulty, compute_state_root).  Block N's parent must
                # already be in the DB before block N can be validated.  The only
                # safe order is: validate(N) → apply(N) → validate(N+1) → ...
                #
                # Note: apply_block() calls validate_block() internally as well,
                # so the external pre-validate is a performance optimisation only.
                # We keep it because it avoids partial state writes on bad batches
                # from trusted peers, but the key change is per-block interleaving.
                for block in _to_apply:
                    ok, msg = self.validate_block(block)
                    if not ok:
                        return False, f"Block {block.index}: {msg}"
                    ok, msg = self.apply_block(block)
                    if not ok:
                        return False, f"Apply block {block.index}: {msg}"
                return True, "OK"

            # ── Validate the supplied sequence before any fork-choice work ────
            # A paginated response is only a prefix of a peer chain.  It is
            # never valid input for deep-fork cumulative-work comparison.
            # Require strict index continuity so a caller cannot accidentally
            # compare two disconnected pages as one chain.
            for _i in range(1, len(blocks)):
                if blocks[_i].index != blocks[_i - 1].index + 1:
                    return False, (
                        f"Non-contiguous chain payload at index {blocks[_i].index}; "
                        f"expected {blocks[_i - 1].index + 1}")

            # ── Find common ancestor ───────────────────────────────────────────
            common_height = self._find_common_ancestor(blocks)

            # An initialized Visold node must always share the pinned genesis
            # with every admissible peer chain.  A negative common ancestor is
            # therefore NOT a legitimate deep-fork starting point: it means the
            # supplied payload does not contain our canonical genesis (or the
            # supplied genesis hash is different).  The old implementation
            # treated that condition as permission to hard-reset to height -1
            # and only then validate the peer genesis, which let an invalid
            # high-difficulty payload destructively wipe local state.
            #
            # Check only the authenticated stored genesis hash here rather than
            # calling validate_block(genesis): legacy chains may intentionally
            # carry historical genesis transaction IDs that are handled by the
            # normal genesis compatibility rules.  The block hash itself is the
            # canonical chain anchor and is already what _find_common_ancestor()
            # compares.
            if common_height < 0 and current_tip >= 0:
                # The payload may start at any height, but it must be anchored
                # to a block we already have.  In particular, never interpret
                # "no common block in payload" as permission to reset to -1.
                first = blocks[0]
                if first.index == 0:
                    local_anchor = self.storage.get_block(0)
                    if local_anchor is None:
                        return False, (
                            "Deep fork rejected: local canonical genesis is "
                            "missing")
                    if first.block_hash != local_anchor.block_hash:
                        return False, (
                            "Deep fork rejected: peer genesis does not match "
                            "the local canonical genesis")
                    common_height = 0
                elif first.index > 0:
                    local_anchor = self.storage.get_block(first.index - 1)
                    if (local_anchor is None
                            or first.prev_hash != local_anchor.block_hash):
                        return False, (
                            "Deep fork rejected: peer payload is not anchored "
                            "to the local canonical chain")
                    common_height = first.index - 1
                else:
                    return False, (
                        f"Deep fork rejected: invalid first block index "
                        f"{first.index}")

            # ── Case 2: Standard reorg (fork above finality fence) ────────────
            if common_height >= 0:
                fork_start = common_height + 1
                # Only the blocks AFTER the common ancestor are new
                new_blocks = [b for b in blocks if b.index >= fork_start]
                if not new_blocks:
                    return True, "Already have all these blocks"
                if new_blocks[-1].index < current_tip:
                    return False, (
                        f"Incoming tip {new_blocks[-1].index} below our tip "
                        f"{current_tip}")

                # Check finality fence
                # AUDIT-FIX (Batch D): this used to be a second copy of the
                # exact same bounded scan (min(current_tip, fork_start + 50))
                # as reorg()'s own fence, so it provided no independent
                # protection — both shared the identical blind spot for a
                # finalized block sitting more than 50 heights below the
                # fork point. Replaced with the same O(1) check against
                # self._highest_finalized_height reorg() now uses (see the
                # comment there for the full rationale).
                highest_finalized = self._highest_finalized_height
                if highest_finalized >= 0 and fork_start <= highest_finalized:
                    # Fork crosses finality fence — fall through to case 3
                    pass
                else:
                    return self.reorg(new_blocks)

            # ── Case 3: Genesis-level / deep fork — fork-choice by cumulative work
            # This handles two nodes that each mined their own chain independently
            # before connecting.  The genesis block is identical (hardcoded), but
            # block 1 onwards differs because each node uses its own miner address.
            # The finality fence blocks a normal reorg, so we use cumulative PoW
            # difficulty as the tie-breaker and hard-reset the loser.
            #
            # Safety: this path is only taken when there are NO investors
            # (no BFT finality).  On a network with investors, BFT-finalized
            # blocks are truly irreversible and this reset is skipped.
            validators = self.storage.get_all_by_role("investor")
            if validators:
                return False, (
                    "Deep fork rejected: BFT-finalized blocks are irreversible. "
                    "Cannot adopt peer chain that diverges below the finality fence.")

            # A deep-fork decision requires the complete peer suffix through
            # the peer tip.  Using only a 200-block response page as "peer
            # cumulative work" can reject a genuinely longer chain.
            if incoming_tip < current_tip:
                return False, (
                    f"Deep-fork comparison requires peer tip >= ours; "
                    f"peer={incoming_tip}, ours={current_tip}")

            # Compare work only AFTER the common ancestor; work before that
            # point is shared by definition and cancels out.  Preserve the
            # existing deep-fork fork-choice rule exactly (including its
            # equal-work tip-hash tiebreak), but do NOT mutate canonical state
            # based on that ranking alone.  reorg() performs the tentative
            # replacement and restores the complete old canonical suffix if
            # any peer block fails validation/application.
            peer_suffix = [b for b in blocks if b.index > common_height]
            if not peer_suffix or peer_suffix[-1].index != incoming_tip:
                return False, "Incomplete peer fork suffix"

            our_suffix = []
            for idx in range(common_height + 1, current_tip + 1):
                blk = self.storage.get_block(idx)
                if blk is None:
                    return False, f"Missing local block {idx} while computing fork work"
                our_suffix.append(blk)

            our_work = self._cumulative_difficulty(our_suffix)
            peer_work = self._cumulative_difficulty(peer_suffix)
            if peer_work < our_work:
                return False, (
                    f"Peer chain rejected: peer cumulative work "
                    f"{peer_work:.4f} < ours {our_work:.4f}")
            if peer_work == our_work:
                _our_blk = self.storage.get_block(current_tip)
                _our_tip_hash = _our_blk.block_hash if _our_blk else ""
                _peer_tip_hash = peer_suffix[-1].block_hash
                if _peer_tip_hash >= _our_tip_hash:
                    return False, (
                        f"Peer chain rejected: equal cumulative work "
                        f"{peer_work:.4f} and our tip hash wins tiebreak")

            return self.reorg(
                peer_suffix,
                allow_deep_no_investor=True,
                enforce_deep_tiebreak=True,
            )

    # ── BFT finality + slashing ───────────────────────────────────────────────
    def add_validator_sig(self, block_hash: str, validator_address: str,
                          sig_hex: str, pub_hex: str) -> bool:
        """
        Record a validator vote.
        • Double-sign detection → slash.
        • On BFT threshold → mark block finalized.
        • Logs economic collusion patterns.

        Fix #5 — Cross-Layer Identity Binding:
        Before accepting a validator signature, we verify that the pub_hex
        supplied with the sig derives to the same wallet address as the
        validator_address claimed.  This binds the transport-layer identity
        (pub_hex from the P2P session) to the validator role identity
        (validator_address from the role registry), preventing a peer from
        submitting BFT votes on behalf of a different validator by spoofing
        the address field.

        Additionally, the signature itself is verified against the pub_hex so
        that a forged or replayed sig from a different key is rejected even if
        the address matches (key reuse attack prevention).
        """
        # Locate the canonical block directly by hash. A fixed five-block
        # lookback could discard a valid validator vote when peer gossip was
        # delayed behind several locally received blocks, preventing quorum
        # finality even though the block remained pending and canonical.
        target_block = self.storage.get_block_by_hash(block_hash)
        if target_block is None:
            return False
        for idx in (target_block.index,):
            block = target_block
            if block and block.block_hash == block_hash:
                if block.finalized: return True

                # ── Fix #5: Cross-layer identity binding ─────────────────────
                # Verify that pub_hex → address matches the claimed validator
                # address.  This prevents a peer from injecting votes for a
                # validator it does not control by sending a valid sig with a
                # mismatched pub_hex/address pair.
                try:
                    claimed_pub  = pub_from_hex(pub_hex)
                    derived_addr = pub_to_address(claimed_pub)
                    if derived_addr != validator_address:
                        log.warning(
                            f"Validator sig identity mismatch: "
                            f"pub_hex derives to {derived_addr[:16]}... "
                            f"but claimed validator is {validator_address[:16]}... "
                            f"— rejected (Fix #5)")
                        return False
                except Exception as e:
                    log.warning(f"Validator sig pub_hex parse failed: {e}")
                    return False

                # ── Verify the signature itself ───────────────────────────────
                try:
                    sig  = sig_from_hex(sig_hex)
                    h_bytes = hashlib.sha256(block_hash.encode()).digest()
                    if not ecdsa_verify(claimed_pub, h_bytes, sig):
                        log.warning(
                            f"Validator sig cryptographic verification failed "
                            f"for {validator_address[:16]}...")
                        return False
                except Exception as e:
                    log.warning(f"Validator sig verification error: {e}")
                    return False

                # ── Double-sign detection ─────────────────────────────────────
                prior_votes = self.storage.get_validator_votes_at_height(idx)
                for pv in prior_votes:
                    if (pv["validator_addr"] == validator_address and
                            pv["block_hash"] != block_hash):
                        log.warning(f"SLASH: double-sign by {validator_address[:16]} "
                                    f"at height {idx}")
                        self.storage.slash(validator_address)
                        # ── NEW: Auto-broadcast slashing evidence ─────────────
                        # Build and broadcast a verifiable evidence packet so ALL
                        # honest nodes independently slash the double-signer.
                        if (Config.AUTO_SLASH_EVIDENCE and
                                hasattr(self, "_slash_evidence") and
                                self._slash_evidence):
                            try:
                                evidence = self._slash_evidence.build_evidence(
                                    validator_address = validator_address,
                                    pub_hex           = pub_hex,
                                    block_hash_a      = pv["block_hash"],
                                    sig_a             = pv["sig_hex"],
                                    block_hash_b      = block_hash,
                                    sig_b             = sig_hex,
                                    height            = idx,
                                    own_address       = self.storage.get_meta(
                                        "own_address") or "unknown",
                                    block_header_a    = (
                                        self.storage.get_block_by_hash(
                                            pv["block_hash"]).header_dict()
                                        if self.storage.get_block_by_hash(
                                            pv["block_hash"]) is not None else None),
                                    block_header_b    = target_block.header_dict(),
                                )
                                # Mark as already processed locally
                                self._slash_evidence.apply_evidence(evidence)
                                # Let the network handle the gossip
                                log.info(
                                    f"Auto-slashing evidence built for "
                                    f"{validator_address[:16]} at height {idx}")
                                metrics.inc("slash_evidence_auto_built")
                            except Exception as e:
                                log.debug(f"Slash evidence build error: {e}")
                        return False

                # A block can arrive through multiple peers. Once this
                # validator has already voted for this exact block, accept the
                # duplicate transport event without appending a second,
                # independently-randomized ECDSA signature or counting the
                # stake twice. A different block hash at this height remains a
                # double-sign and is handled above.
                same_block_vote = next(
                    (pv for pv in prior_votes
                     if pv["validator_addr"] == validator_address
                     and pv["block_hash"] == block_hash),
                    None,
                )
                if same_block_vote is not None:
                    if not any(vs.get("addr") == validator_address
                               for vs in block.validator_sigs):
                        block.validator_sigs.append({
                            "addr": validator_address,
                            "sig": same_block_vote["sig_hex"],
                            "pub": same_block_vote["pub_hex"],
                        })
                        self.storage.save_block(block)
                    return True

                # Record vote
                self.storage.record_validator_vote(
                    block_hash, validator_address, sig_hex, pub_hex,
                    block_idx=idx)

                entry = {"addr": validator_address, "sig": sig_hex, "pub": pub_hex}
                if entry not in block.validator_sigs:
                    block.validator_sigs.append(entry)

                # BUG-2 FIX: integer BFT threshold — no float division
                # AUDIT-FIX (Batch D): this inline copy of the threshold check
                # had no MIN_VALIDATORS_FOR_BFT gate at all (not even the
                # zero-validators guard _maybe_finalize_by_bft had), so as
                # few as one registered validator could BFT-finalize a block
                # via this path too. Same fix, same rationale as
                # _maybe_finalize_by_bft above.
                validators = self.storage.get_all_by_role("investor")
                if len(validators) >= Config.MIN_VALIDATORS_FOR_BFT:
                    total_stake_sat = sum(to_satoshi(v["stake"]) for v in validators)
                    voted_stake_sat = 0
                    seen_voters = set()
                    for vs in block.validator_sigs:
                        voter_addr = vs.get("addr")
                        if voter_addr in seen_voters:
                            continue
                        seen_voters.add(voter_addr)
                        for v in validators:
                            if v["address"] == voter_addr:
                                voted_stake_sat += to_satoshi(v["stake"])

                    if bft_threshold_met(voted_stake_sat, total_stake_sat):
                        block.finalized = True
                        # AUDIT-FIX (Batch D): keep the incremental
                        # finality-fence tracker in sync — see
                        # _highest_finalized_height in __init__.
                        self._highest_finalized_height = max(
                            self._highest_finalized_height, block.index)
                        pct = (voted_stake_sat * 100 // total_stake_sat
                               if total_stake_sat > 0 else 0)
                        log.info(f"Block #{block.index} finalized via BFT ({pct}% stake)")
                        metrics.inc("blocks_finalized_bft")

                self.storage.save_block(block)

                # Economic collusion monitoring
                all_sig_addrs = [vs["addr"] for vs in block.validator_sigs]
                self._eco_mon.record_validator_sigs(all_sig_addrs)

                return True
        return False
