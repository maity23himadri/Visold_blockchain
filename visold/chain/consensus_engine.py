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
"""visold.chain.consensus_engine

Original section: SECTION 10: CONSENSUS (PoW + PoS + BFT + VRF)

Defines: ConsensusEngine
Origin: visold_vsd_.py L30668-30996
"""

import json
import time
from typing import Any, List, Optional, TYPE_CHECKING, Tuple

from visold.chain.blockchain import Blockchain
from visold.consensus.difficulty import DifficultyEngine
from visold.crypto.ecc import sig_to_hex
from visold.crypto.vrf import vrf_prove
from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.wallet.wallet import Wallet


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10: CONSENSUS (PoW + PoS + BFT + VRF)
# ─────────────────────────────────────────────────────────────────────────────
class ConsensusEngine:
    def __init__(self, blockchain: Blockchain, wallet: 'Wallet'):
        self.blockchain = blockchain
        self.wallet     = wallet
        # AUDIT-FIX-8 (freeze/rate-limit scope): optional, set externally
        # (Node.start(), after SHBS hardening succeeds) to
        # shbs.freeze_reg. When present, build_candidate_block() excludes
        # frozen senders' transactions from blocks THIS node proposes.
        # This is intentionally a LOCAL mining-policy filter only — it must
        # never be consulted by validate_block/apply_block, since freeze
        # state is per-node, non-consensus state; making it consensus-
        # relevant would let nodes with different freeze sets disagree on
        # block validity and fork.
        self._freeze_registry = None
        # Late-bound by VisoldNode after P2PNetwork construction. Keeping this
        # optional preserves standalone consensus/test construction.
        self._network = None

    def set_network(self, network: Any) -> None:
        """Attach the node's P2P network for validator-vote gossip."""
        self._network = network

    def select_block_proposer(self, candidates: List[dict]) -> Optional[dict]:
        """VRF-based leader selection — lowest VRF output wins.

        SEC-FIX M-04 (Deterministic Proposer Selection)
        ───────────────────────────────────────────────
        The pre-fix code fell back to ``random.getrandbits(256)`` for
        candidates that did not supply a private key.  ``random`` is not
        seeded from the chain, so two honest nodes evaluating the same
        candidate set would compute different selections — a silent
        consensus split.  Even though this code path is not currently on
        the live block-production flow, leaving the fallback in place is a
        footgun for any future maintainer who promotes it.

        The fix: candidates without a private key are NOT eligible to
        propose.  No random value is invented.  If the candidate set is
        empty after this filter, the function returns None and the caller
        falls back to its non-VRF path.
        """
        if not candidates:
            return None
        latest = self.blockchain.latest_block()
        alpha  = (latest.block_hash if latest else "genesis").encode()
        best    = None
        best_vr = None
        for c in candidates:
            priv_hex = c.get("priv_hex")
            if not priv_hex:
                # Not eligible — no key, no deterministic VRF.  SKIP.
                continue
            try:
                priv = int(priv_hex, 16)
                _, beta = vrf_prove(priv, alpha)
                val = int.from_bytes(beta, 'big')
                if best_vr is None or val < best_vr:
                    best_vr = val
                    best = c
            except Exception:
                # VRF failed for this candidate — skip rather than guess.
                continue
        return best

    def build_candidate_block(self, miner_address: str, vrf_proof: str = "",
                               vrf_output: str = "") -> Block:
        # AUDIT-FIX-18 (Batch F, Finding 1): tip detection, difficulty, and
        # the MTP timestamp window are read together as one atomic snapshot
        # under blockchain._lock.  Previously this ran lock-free while
        # Blockchain.reorg()/.rollback() (which DO hold this same lock)
        # mutated storage and called DifficultyEngine.invalidate_cache()
        # concurrently.  If DifficultyEngine._compute_uncached() started
        # before such a reorg and finished after it, its result was written
        # into DifficultyEngine's process-global _cache AFTER the
        # invalidation had already run for that height — permanently
        # poisoning that cache slot with a stale value.  Because
        # Blockchain.validate_block() trusts that same cache (via
        # get_difficulty()) when checking an incoming block's difficulty
        # for an exact match, the poisoned entry could make this node
        # wrongly reject valid blocks from the honest network until a
        # later reorg happened to invalidate that height again.  Holding
        # the same lock reorg()/rollback() already use for invalidate_cache()
        # closes the race — a difficulty computation can no longer straddle
        # an invalidation.  This also fixes a smaller, related gap: height/
        # prev_hash (from latest_block()) and diff/mtp used to potentially
        # be computed against two different tips if a block landed in the
        # gap between the old unlocked reads; they are now one snapshot.
        with self.blockchain._lock:
            latest    = self.blockchain.latest_block()
            prev_hash = latest.block_hash if latest else "0"*64
            height    = (latest.index + 1) if latest else 0
            diff      = self.blockchain.get_difficulty()

            recent_ts: List[int] = []
            for _i in range(max(0, height - Config.DIFF_MTP_WINDOW), height):
                _blk = self.blockchain.storage.get_block(_i)
                if _blk is not None:
                    recent_ts.append(_blk.timestamp)
            mtp = DifficultyEngine.compute_mtp(recent_ts) if recent_ts else 0

        # ── Consensus Fix #1: MTP-safe timestamp ─────────────────────────────
        # At low difficulty, blocks mine in microseconds — many blocks can share
        # the exact same integer second.  validate_block() enforces a strict
        # greater-than check against the MTP (Median Time Past).  If the new
        # block's timestamp equals the MTP, the block is rejected, causing an
        # infinite retry loop at the same height.
        #
        # Solution: always set the candidate timestamp to:
        #   safe_ts = max(current_time, MTP + 1)
        # This guarantees the timestamp is strictly greater than the MTP before
        # the block ever enters the mining loop, so validation cannot fail on
        # the timestamp rule regardless of mining speed.
        safe_ts = max(int(time.time()), mtp + 1)

        max_bytes = self.blockchain.get_dynamic_block_size()
        txs       = []
        used       = 0
        # AUDIT-FIX-8: exclude frozen senders' transactions from blocks
        # THIS node proposes. mempool.get_top()'s ordering stays fully
        # canonical/deterministic (Fix #7 above) — this filter only
        # decides which of those already-eligible transactions THIS
        # miner chooses to keep, exactly like the max_bytes cutoff below
        # already does. Read-only (is_frozen), never mutates rate-limit
        # state — that stays scoped to gossip admission (StateEngineHook)
        # so merely building a candidate block can't itself count as a
        # rate-limited "attempt".
        _freeze_reg = getattr(self, "_freeze_registry", None)
        for tx in self.blockchain.mempool.get_top(500):
            if _freeze_reg is not None:
                try:
                    if tx.sender != "COINBASE" and _freeze_reg.is_frozen(tx.sender):
                        continue
                except Exception:
                    pass
            tx_size = len(json.dumps(tx.to_dict()).encode())
            if used + tx_size > max_bytes:
                break
            txs.append(tx)
            used += tx_size

        reward = self.blockchain.compute_reward(height)
        cb     = Transaction.coinbase(miner_address, reward, height)
        txs.insert(0, cb)

        # ─────────────────────────────────────────────────────────────────────
        # v7.1.9 OPTION-A FIX: compute state_root BEFORE the PoW loop.
        #
        # Before this fix, state_root was left "" in the candidate, the PoW
        # solved a header containing state_root="", then apply_block mutated
        # the field to a non-empty value AFTER the block was sealed.
        # header_dict() included state_root in the hash preimage, so every
        # receiving peer recomputed a different block_hash, integrity_check
        # rejected the block, and sync was completely broken across the
        # entire network.  See changelog v7.1.9.
        #
        # We must run this dry-run while holding the blockchain lock so a
        # concurrent apply_block doesn't shift state under us.  The dry-run
        # itself is non-mutating (snapshot/restore).
        #
        # v7.2.0-FIX-4: If dry_run_state_root() fails due to a specific tx
        # (e.g. sender can't afford it), remove that tx and retry rather than
        # falling back to state_root="" for the entire block.  A block mined
        # with state_root="" is guaranteed to be rejected by all peers — the
        # retry produces a valid candidate instead.  The fallback to "" is
        # kept only for truly catastrophic / unrecoverable failures.
        # ─────────────────────────────────────────────────────────────────────
        pre_state_root = ""
        _candidate_txs = txs

        def _compute_candidate_root(candidate_txs):
            """Compute the exact candidate root, with a narrow legacy-signature fallback.

            Real Blockchain.dry_run_state_root() receives the candidate
            timestamp/difficulty so block-context opcodes execute identically
            to apply_block().  Some standalone test doubles and older embedders
            still expose the historical 3-argument API; only that specific
            signature mismatch is allowed to fall back.  Any TypeError raised
            *inside* the real dry-run is propagated instead of being masked.
            """
            kwargs = {
                "transactions": candidate_txs,
                "miner_address": miner_address,
                "height": height,
                "timestamp": safe_ts,
                "difficulty": diff,
            }
            try:
                return self.blockchain.dry_run_state_root(**kwargs)
            except TypeError as exc:
                msg = str(exc)
                if ("unexpected keyword argument 'timestamp'" not in msg
                        and "unexpected keyword argument \"timestamp\"" not in msg):
                    raise
                legacy_kwargs = {k: kwargs[k] for k in
                                 ("transactions", "miner_address", "height")}
                return self.blockchain.dry_run_state_root(**legacy_kwargs)

        _MAX_RETRIES   = 3
        for _attempt in range(_MAX_RETRIES):
            try:
                with self.blockchain._lock:
                    pre_state_root = _compute_candidate_root(_candidate_txs)
                break  # dry-run succeeded — use this candidate tx list
            except RuntimeError as _rte:
                # dry_run raises RuntimeError when a specific tx can't be
                # processed (e.g. "dry-run debit failed for <addr>").
                # Try to identify and remove the offending tx, then retry.
                err_msg = str(_rte)
                log.warning(
                    f"build_candidate_block: dry_run attempt {_attempt + 1} "
                    f"failed ({err_msg}) — removing offending tx and retrying")
                removed = False
                for _tx in _candidate_txs[1:]:   # skip coinbase at index 0
                    if _tx.sender in err_msg:
                        _candidate_txs = [t for t in _candidate_txs
                                          if t is not _tx]
                        log.info(
                            f"Removed tx {_tx.tx_id[:8]} from candidate "
                            f"(sender {_tx.sender[:12]} insufficient balance)")
                        removed = True
                        break
                if not removed:
                    # Can't isolate the failing tx — fall back to empty root.
                    log.warning(
                        f"build_candidate_block: could not isolate failing tx "
                        f"after attempt {_attempt + 1}; using empty state_root "
                        f"(block will be rejected by peers — safety net)")
                    pre_state_root = ""
                    break
            except Exception as _dre:
                # Unexpected error (storage failure, etc.) — fall back to "".
                log.warning(
                    f"build_candidate_block: dry_run_state_root failed "
                    f"({_dre}); falling back to empty state_root")
                pre_state_root = ""
                break

        # The tx-byte budget above intentionally governs local packing policy,
        # but the consensus limit applies to the COMPLETE serialized block.
        # CoinBase + header fields add bytes that are not included in ``used``.
        # Trim from the tail and recompute the deterministic state root until
        # the exact candidate representation is inside the hard consensus cap.
        # Removing only tail transactions preserves the canonical mempool order.
        hard_cap = int(Config.MAX_BLOCK_SIZE)
        while True:
            candidate = Block(
                index        = height,
                prev_hash    = prev_hash,
                transactions = _candidate_txs,
                miner_address= miner_address,
                difficulty   = diff,
                vrf_proof    = vrf_proof,
                vrf_output   = vrf_output,
                timestamp    = safe_ts,
                state_root   = pre_state_root,
            )
            if candidate.size() <= hard_cap:
                return candidate
            if len(_candidate_txs) <= 1:
                # Coinbase alone must fit under the configured consensus cap.
                # If configuration violates that invariant, fail loudly rather
                # than return a candidate that every validator must reject.
                raise RuntimeError(
                    f"Consensus MAX_BLOCK_SIZE={hard_cap} is too small for "
                    f"the mandatory coinbase/header block ({candidate.size()} bytes)"
                )

            _candidate_txs = _candidate_txs[:-1]
            with self.blockchain._lock:
                pre_state_root = _compute_candidate_root(_candidate_txs)

    def validate_and_finalize(self, block: Block) -> Tuple[bool, str]:
        """
        Post-mining consensus step: validate the block and, if this node is a
        registered validator, cast a weighted BFT vote.

        Consensus Fix #3 — Conditional Hybrid Consensus Mode:
        ───────────────────────────────────────────────────────
        The operating mode is determined by the total stake of all registered
        investors at the moment the block is applied:

          total_stake == 0  →  PoW-only mode
            No investors are registered yet (bootstrap phase).  The block is
            accepted purely on PoW merit and will be finalized by depth via
            _maybe_finalize_by_depth().  No BFT voting occurs.

          total_stake  > 0  →  Full hybrid mode (PoW + PoS + BFT)
            Validators exist.  If this node is an investor it casts a signed
            BFT vote via add_validator_sig().  If this node is NOT a validator
            the block remains pending (un-finalized) until 2/3 weighted stake
            votes accumulate from the network.  Pending blocks are NOT dropped.

        Consensus Fix #4 — PoS activation only when stake exists:
        ───────────────────────────────────────────────────────────
        The validator/BFT layer is gated on total_stake > 0.  This keeps the
        chain fully functional as a pure-PoW network during bootstrap and only
        switches to hybrid consensus once real stake enters the system.

        Consensus Fix #5 — BFT pending ≠ rejection:
        ─────────────────────────────────────────────
        A block whose BFT vote count is below the 2/3 threshold is marked
        pending (finalized=False) but is NOT rejected.  It will be promoted to
        BFT-finalized once enough validator votes arrive over the network.
        """
        ok, msg = self.blockchain.validate_block(block)
        if not ok:
            return False, msg

        # ── Detect consensus mode based on live validator set ─────────────────
        validators      = self.blockchain.storage.get_all_by_role("investor")
        total_stake     = sum(v["stake"] for v in validators) if validators else 0
        validator_count = len(validators)

        # F-09 FIX: Require MIN_VALIDATORS_FOR_BFT validators before BFT mode
        # is considered active.  Below this threshold the network uses PoW-only
        # finality — a pure-PoW bootstrap window is inherently more vulnerable
        # to 51% attacks, so we apply a deeper confirmation depth as compensation.
        bft_active = (validator_count >= Config.MIN_VALIDATORS_FOR_BFT
                      and total_stake > 0)

        if not bft_active:
            # ── Bootstrap / PoW-only mode ─────────────────────────────────────
            # Block finality is handled by depth confirmation in
            # Blockchain._maybe_finalize_by_depth().  No BFT vote is cast.
            # During bootstrap (< MIN_VALIDATORS_FOR_BFT validators) we warn
            # operators so they understand the reduced security model.
            if validator_count > 0:
                log.debug(
                    f"Block #{block.index}: BFT mode inactive — "
                    f"{validator_count}/{Config.MIN_VALIDATORS_FOR_BFT} "
                    f"validators registered (need {Config.MIN_VALIDATORS_FOR_BFT}). "
                    f"PoW-only finality at depth {Config.POW_FINALITY_DEPTH}.")
            else:
                log.debug(f"Block #{block.index}: PoW-only mode "
                          f"(no validators, finalized by depth)")
        else:
            # ── Full hybrid mode (PoW + PoS + BFT) ───────────────────────────
            role = self.blockchain.storage.get_role(self.wallet.address)
            if role and role["role"] == "investor":
                # This node is a registered validator — cast a BFT vote.
                try:
                    sig     = self.wallet.sign(block.block_hash.encode())
                    sig_hex = sig_to_hex(sig)
                    already_voted = any(
                        vote.get("validator_addr") == self.wallet.address
                        and vote.get("block_hash") == block.block_hash
                        for vote in self.blockchain.storage
                        .get_validator_votes_at_height(block.index)
                    )
                    accepted = self.blockchain.add_validator_sig(
                        block.block_hash,
                        self.wallet.address,
                        sig_hex,
                        self.wallet.pub_hex,
                    )
                    # Gossip only a newly recorded vote. Duplicate block
                    # delivery remains idempotent and does not create a vote
                    # broadcast loop.
                    if accepted and not already_voted and self._network is not None:
                        self._network.broadcast_validator_sig(
                            block.block_hash, sig_hex)
                    log.info(
                        f"Block #{block.index}: BFT vote cast "
                        f"(validators={validator_count}, "
                        f"total_stake={total_stake} sat)"
                    )
                except Exception as e:
                    log.warning(f"Block #{block.index}: BFT vote failed: {e}")
            else:
                log.debug(
                    f"Block #{block.index}: pending BFT finality "
                    f"({validator_count} validators, "
                    f"total_stake={total_stake} sat)"
                )


        return True, "OK"
