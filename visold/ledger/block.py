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
"""visold.ledger.block

Original section: SECTION 5: BLOCK

Defines: Block
Origin: visold_vsd_.py L11912-12425
"""

import json
import threading
import time
import concurrent.futures as _futures
from typing import List, Optional, TYPE_CHECKING, Tuple, Set

from visold.consensus.difficulty import DifficultyEngine
from visold.crypto.hashing import hash_obj, sha256
from visold.crypto.parallel_verify import (
    _PAR_SIG_THRESHOLD, _get_sig_pool, _par_verify_sig, _par_verify_sig_batch,
)
from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics
from visold.ledger.transaction import Transaction

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.mempool.pool import Mempool


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5: BLOCK
# ─────────────────────────────────────────────────────────────────────────────
class Block:
    VERSION = 1

    # ── SECURITY: Immutable-after-seal fields ────────────────────────────────
    # These fields are locked once seal() is called (after mining or loading).
    # Any attempt to modify them after sealing raises AttributeError so that
    # a deep-copy + transaction-mutation attack is caught at the object level.
    # ──────────────────────────────────────────────────────────────────────
    # v7.1.9 SEAL UPGRADE — ``state_root`` is now part of the immutable
    # header (Option A: EVM-style commitment).  Previously state_root was
    # left mutable so apply_block could fill it in post-PoW, but
    # header_dict() ALWAYS included state_root in the hash preimage.  That
    # meant the broadcast block's block_hash diverged from the recomputed
    # hash on every receiving peer, and integrity_check() rejected every
    # block — completely breaking sync.  See the v7.1.9 changelog.
    #
    # Now the candidate-builder dry-runs the txs to compute state_root
    # BEFORE the PoW loop runs, so the hash that gets mined and the hash
    # that any peer recomputes are byte-identical.
    # ──────────────────────────────────────────────────────────────────────
    _SEALED_FIELDS = frozenset({
        "index", "prev_hash", "transactions", "miner_address", "difficulty",
        "merkle_root", "block_hash", "version", "protocol_version",
        "vrf_proof", "vrf_output",
        "state_root",                                # v7.1.9 — see above
    })

    def __init__(self, index: int, prev_hash: str, transactions: List[Transaction],
                 miner_address: str, difficulty: float, timestamp: int = 0,
                 nonce: int = 0, block_hash: str = "", validator_sigs: Optional[List[dict]] = None,
                 vrf_proof: str = "", vrf_output: str = "", finalized: bool = False,
                 state_root: str = "", protocol_version: int = 0,
                 merkle_root: Optional[str] = None):
        # _sealed must be set via object.__setattr__ BEFORE any field assignment
        object.__setattr__(self, "_sealed", False)
        self.version          = self.VERSION
        self.protocol_version = protocol_version or Config.PROTOCOL_VERSION
        self.index            = index
        self.prev_hash        = prev_hash
        self.timestamp        = timestamp or int(time.time())
        # Store transactions as a tuple so mutation is structurally impossible
        self.transactions     = tuple(transactions)
        self.miner_address    = miner_address
        self.difficulty       = difficulty
        self.nonce            = nonce
        self.vrf_proof        = vrf_proof
        self.vrf_output       = vrf_output
        self.merkle_root      = self._merkle() if merkle_root is None else merkle_root
        # v7.1.9: state_root is set by the candidate-builder via dry-run
        # BEFORE the PoW loop, so the mined block_hash already commits to
        # it.  apply_block now VERIFIES (not mutates) state_root.
        self.state_root       = state_root
        self.block_hash       = block_hash or self.compute_hash()
        self.validator_sigs   = validator_sigs or []
        self.finalized        = finalized

    def __setattr__(self, name: str, value):
        """Prevent mutation of consensus-critical fields once the block is sealed."""
        if getattr(self, "_sealed", False) and name in self._SEALED_FIELDS:
            raise AttributeError(
                f"Block is sealed: cannot modify '{name}' after sealing. "
                f"This prevents post-mining transaction tampering."
            )
        object.__setattr__(self, name, value)

    def seal(self, recompute_merkle: bool = True) -> 'Block':
        """
        Lock the block's consensus-critical fields after mining.

        Once sealed:
          • transactions, merkle_root, block_hash, index, prev_hash,
            difficulty, miner_address, version, protocol_version,
            vrf_proof, vrf_output, AND state_root (v7.1.9) are read-only —
            any write attempt raises AttributeError.
          • finalized, validator_sigs, nonce, timestamp remain mutable.
            (nonce/timestamp may be re-tried during MTP fallback in
            mine(); validator_sigs and finalized are filled in during BFT
            voting which happens after the block is on-chain.)

        v7.1.9: state_root joined the sealed set because it is part of
        header_dict() — the PoW-committed preimage of block_hash.  The
        candidate-builder dry-runs txs to populate state_root BEFORE the
        PoW loop, so the mined hash is consistent with what receivers
        recompute.

        Call this once immediately after mine() returns True.
        Block.from_dict() also calls seal() so loaded blocks are immutable.
        """
        # Ensure merkle_root and block_hash are consistent before sealing.
        # Deserializers may pass the authenticated stored Merkle root and defer
        # recomputation to the authoritative integrity_check() path.
        if recompute_merkle:
            object.__setattr__(self, "merkle_root", self._merkle())
        object.__setattr__(self, "_sealed", True)
        return self

    def integrity_check(self, mempool: Optional['Mempool'] = None,
                        verified_txids: Optional[Set[str]] = None,
                        integrity_txids: Optional[Set[str]] = None) -> Tuple[bool, str]:
        """
        Cryptographic self-consistency check.  Verifies the full chain:
          block_hash  ←  header_dict (includes merkle_root)
          merkle_root ←  tx_ids
          tx_ids      ←  tx field content (via _compute_id)
          signatures  ←  tx signing_bytes (for non-coinbase tx)

        Returns (True, "OK") or (False, reason).
        Call this at the start of every validate_block() invocation.

        v7.5.0-OPT — Pre-Validation Pipeline
        ────────────────────────────────────
        If ``mempool`` is provided, transactions whose tx_id is present in
        ``mempool._verified`` have ALREADY had their ECDSA signature
        validated at gossip-arrival time — we skip the (expensive) ECDSA
        recheck for those and only verify the remainder.  This is a pure
        CPU-saving optimization: tx_id ties a transaction's signed payload
        to its id (merkle_root step above already bound it), so skipping
        the recheck is safe as long as:
          (a) the tx_id we see in the block equals the tx_id in _verified,
              which the merkle/id step has already proven, AND
          (b) the _verified entry is only set after verify_signature()==True
              inside Mempool.add(), which is enforced there.
        Falling back to full verification when ``mempool`` is None preserves
        the exact prior behaviour (used by tests and audit paths).

        ``verified_txids``, when supplied by the block validator, is populated
        with every non-coinbase tx_id whose signature was already established
        by this integrity pass. This lets the later semantic-validation pass
        avoid verifying the exact same signature a second time without making
        signature verification optional for ordinary callers.

        v7.1.10 LEGACY-BLOCK COMPATIBILITY
        ───────────────────────────────────
        Blocks mined under v7.1.7/v7.1.8 (BEFORE the state_root sealing
        fix in v7.1.9) suffer from the well-known mutation bug:
        ``state_root`` was populated AFTER the PoW had already committed
        to a header containing ``state_root=""``.  These blocks live
        forever on existing chains; a v7.1.9+ receiver would reject all
        of them at the modern hash check, making cross-version sync
        impossible.

        Fix: try the modern hash first.  If it doesn't match, retry the
        hash with ``state_root=""`` in the header (legacy-mode rule).
        If THAT matches, the block is a genuine pre-v7.1.9 block whose
        on-disk state_root was populated post-PoW; accept it with a
        DEBUG-level note.  If neither matches, the block is genuinely
        tampered/forged and is rejected.

        Once your network has fully re-mined under v7.1.9+ you can
        delete the legacy branch and tighten back to a single check.
        """
        # 1. Recompute merkle root from current transaction set
        computed_merkle = self._merkle()
        if self.merkle_root != computed_merkle:
            return False, (
                f"Block integrity failure: merkle_root mismatch — "
                f"stored={self.merkle_root[:16]}, "
                f"computed={computed_merkle[:16]}. "
                f"Transactions may have been tampered with after block creation."
            )

        # 2. Recompute block_hash from header (which includes merkle_root).
        #    Try modern rule first (header includes the populated state_root).
        computed_hash = self.compute_hash()
        if self.block_hash != computed_hash:
            # 2b. v7.1.10 legacy-block fallback: try with state_root="".
            #     Pre-v7.1.9 miners committed to that empty-string value
            #     in the PoW preimage, then mutated state_root post-seal.
            saved = self.state_root
            try:
                object.__setattr__(self, "state_root", "")
                legacy_hash = self.compute_hash()
            finally:
                object.__setattr__(self, "state_root", saved)
            if self.block_hash == legacy_hash:
                # Genuine legacy block.  Trace-level only — this is normal
                # during the upgrade window; would be log-spam on every
                # MSG_CHAIN page if escalated higher.
                log.debug(
                    f"[LEGACY-BLOCK] #{self.index} {self.block_hash[:12]}… "
                    f"accepted via pre-v7.1.9 hash rule (state_root='')")
                # Fall through to tx checks — the rest of integrity is
                # unaffected by which header rule produced the hash.
            else:
                return False, (
                    f"Block integrity failure: block_hash mismatch — "
                    f"stored={self.block_hash[:16]}, "
                    f"computed={computed_hash[:16]}, "
                    f"legacy_computed={legacy_hash[:16]}. "
                    f"Header fields tampered (neither modern nor legacy "
                    f"PoW-preimage rule matches)."
                )

        # 3. Verify each transaction's tx_id matches its content. New blocks
        #    use the canonical length-delimited encoding. For migration only,
        #    an explicitly enabled historical pre-V3 block may retain its exact
        #    pre-canonical tx_id. New blocks never fall back automatically.
        #
        #    Performance note: ``_compute_id()`` and ``signing_bytes()`` used to
        #    rebuild the exact same canonical byte sequence independently. The
        #    integrity pass is already the authoritative commitment check, so
        #    build the canonical preimage once, hash it for tx_id validation,
        #    and retain it for the signature-verification stage below. This does
        #    not trust any additional input and does not alter consensus bytes.
        signing_payloads = {}
        legacy_payloads = {}
        activation = int(getattr(
            Config, "TXID_CANONICAL_V3_ACTIVATION_HEIGHT", 0))
        legacy_allowed = bool(getattr(
            Config, "TXID_CANONICAL_V2_LEGACY_ENABLED", False))
        for tx in self.transactions:
            canonical_payload = tx.signing_bytes(self.index)
            expected_id = sha256(canonical_payload)
            selected_payload = canonical_payload
            legacy_payload = None
            if tx.tx_id != expected_id:
                # Historical V1 compatibility is explicit and height-gated.
                legacy_id = tx._compute_legacy_id(self.index) if (
                    legacy_allowed and activation > 0 and self.index < activation) else ""
                if not legacy_id or tx.tx_id != legacy_id:
                    return False, (
                        f"Block integrity failure: tx_id tampered in tx "
                        f"stored={tx.tx_id[:16]}, computed={expected_id[:16]}. "
                        f"Transaction content was modified after tx_id was set."
                    )
                # Keep canonical payload as the primary signature attempt and
                # preserve the historical legacy payload as the exact fallback
                # used by the pre-canonical verification rule.
                if legacy_allowed and activation > 0 and self.index < activation:
                    legacy_payload = tx._legacy_signing_bytes()
            signing_payloads[id(tx)] = selected_payload
            if legacy_payload is not None:
                legacy_payloads[id(tx)] = legacy_payload
            if integrity_txids is not None:
                integrity_txids.add(tx.tx_id)

        # 4. Verify non-coinbase transaction signatures
        #    TPS-OPT-1: fan out to ProcessPoolExecutor when the block carries
        #    enough non-coinbase txs to justify the dispatch overhead.  Each
        #    worker receives only primitives (pub_hex, sig_hex, signing_bytes)
        #    and returns a bool — zero shared state, zero lock contention.
        #
        #    v7.5.0-OPT: if a mempool was provided, filter out transactions
        #    whose tx_id is already in its _verified set (full ECDSA run at
        #    gossip time).  We still iterate ALL non-coinbase txs to enforce
        #    tx-id integrity (step 3 above) — we only skip the RE-verify
        #    work here.  A missing mempool (None) falls back to full
        #    verification, preserving historical behaviour and tests.
        non_cb = [(i, tx) for i, tx in enumerate(self.transactions)
                  if tx.sender != "COINBASE"]

        if mempool is not None:
            try:
                _to_verify = [(i, tx) for (i, tx) in non_cb
                              if not mempool.is_verified(tx.tx_id)]
                _skipped = len(non_cb) - len(_to_verify)
                if verified_txids is not None and _skipped > 0:
                    verified_txids.update(tx.tx_id for _, tx in non_cb if mempool.is_verified(tx.tx_id))
                if _skipped > 0:
                    # Record the win for observability.  Does not affect
                    # consensus — same outcome regardless.
                    try:
                        metrics.inc("sig_verify_skipped", _skipped)
                    except Exception:
                        pass
                non_cb = _to_verify
            except Exception:
                # Any failure in the pre-validation skip path falls back to
                # full verification — safety over speed.
                pass

        if len(non_cb) >= _PAR_SIG_THRESHOLD:
            pool = _get_sig_pool()
            activation = int(getattr(Config, "TXID_CANONICAL_V3_ACTIVATION_HEIGHT", 0))
            legacy_allowed = bool(getattr(Config, "TXID_CANONICAL_V2_LEGACY_ENABLED", False))
            allow_legacy = legacy_allowed and activation > 0 and self.index < activation
            # Batch jobs are intentionally coarse-grained: one process-pool
            # submission per worker-sized chunk rather than one IPC round-trip
            # for every transaction.  This preserves exactly the same
            # per-transaction verifier while substantially reducing pickling /
            # scheduling overhead on high-throughput blocks.
            worker_count = max(1, int(getattr(pool, "_max_workers", 1)))
            batch_count = min(worker_count, len(non_cb))
            batches = [[] for _ in range(batch_count)]
            for pos, item in enumerate(non_cb):
                tx = item[1]
                payload = (
                    tx.pub_hex,
                    tx.sig_hex,
                    signing_payloads[id(tx)],
                    tx.sender,
                    legacy_payloads.get(id(tx)) if allow_legacy else None,
                )
                batches[pos % batch_count].append((pos, tx, payload))

            futs = {}
            for batch in batches:
                payloads = [entry[2] for entry in batch]
                futs[pool.submit(_par_verify_sig_batch, payloads)] = batch

            for fut in _futures.as_completed(futs):
                invalid_offset = fut.result()
                batch = futs[fut]
                if invalid_offset >= 0:
                    tx = batch[invalid_offset][1]
                    return False, (
                        f"Block integrity failure: invalid signature on tx "
                        f"{tx.tx_id[:16]} from {tx.sender[:16]}."
                    )
                if verified_txids is not None:
                    verified_txids.update(entry[1].tx_id for entry in batch)
        else:
            # Small block — sequential is faster (no IPC overhead). Reuse the
            # canonical signing preimage already constructed for tx-id integrity
            # instead of rebuilding it inside Transaction.verify_signature().
            # The standalone worker performs the same sender-binding, signature
            # range, digest and optional legacy checks; only the call topology
            # changes.
            for _, tx in non_cb:
                payload = (
                    tx.pub_hex,
                    tx.sig_hex,
                    signing_payloads[id(tx)],
                    tx.sender,
                    legacy_payloads.get(id(tx)),
                )
                if not _par_verify_sig(*payload):
                    return False, (
                        f"Block integrity failure: invalid signature on tx "
                        f"{tx.tx_id[:16]} from {tx.sender[:16]}."
                    )
                if verified_txids is not None:
                    verified_txids.add(tx.tx_id)

        return True, "OK"

    def _merkle(self) -> str:
        """
        Compute the Merkle root of self.transactions.

        SEC-FIX H-01 (CVE-2012-2459 — Duplicate-Leaf Malleability)
        ──────────────────────────────────────────────────────────
        The pre-fix construction duplicated the last hash on odd levels and
        paired it with itself.  Two distinct transaction lists could produce
        the same Merkle root by appending a copy of the trailing tx — the
        classic Bitcoin-pre-2012 vulnerability.

        The fixed (V2) construction handles odd-level loners with a
        domain-separated promotion: the loner is hashed with a fixed marker
        ("|odd|") and carried forward unchanged.  This breaks the collision
        equivalence because the loner-promotion hash and a normal pairwise
        hash now live in disjoint domains.

        Activation: blocks at or above MERKLE_V2_ACTIVATION_HEIGHT use the
        V2 rule.  Earlier blocks keep the V1 rule so historical
        merkle_roots and block_hashes remain valid.  On a fresh chain set
        MERKLE_V2_ACTIVATION_HEIGHT = 0 (default).
        """
        hashes = [t.tx_id for t in self.transactions]
        if not hashes:
            return sha256(b"empty")

        # Pick the rule based on this block's height
        try:
            v2_active = self.index >= int(Config.MERKLE_V2_ACTIVATION_HEIGHT)
        except Exception:
            # Fail closed to V2 if Config is somehow unreachable — V2 is
            # always at least as safe as V1.
            v2_active = True

        if v2_active:
            # V2 — domain-separated odd-leaf promotion (CVE-2012-2459-safe).
            # Strategy: at each level, the FIRST n-1 even pairs are hashed
            # normally; if there is an odd loner, it is DOMAIN-SEPARATED
            # (hashed with a tag that no normal pairing can produce) and
            # carried up to the next level alone.  Because the odd-loner
            # hash lives in a disjoint domain from the pairwise hash, the
            # CVE-2012-2459 collision (where appending a copy of the last
            # tx produces the same root) is impossible: the duplicated leaf
            # would feed a normal pairwise hash, not the odd-tag hash, so
            # the resulting root differs.
            ODD_TAG = "|odd|"
            while len(hashes) > 1:
                pairs = len(hashes) // 2
                next_level = [
                    sha256((hashes[2*i] + hashes[2*i+1]).encode())
                    for i in range(pairs)
                ]
                if len(hashes) % 2 == 1:
                    loner = hashes[-1]
                    next_level.append(sha256((ODD_TAG + loner).encode()))
                hashes = next_level
            return hashes[0]

        # V1 (legacy) — kept ONLY for historical block re-validation
        while len(hashes) > 1:
            if len(hashes) % 2:
                hashes.append(hashes[-1])
            hashes = [
                sha256((hashes[i] + hashes[i+1]).encode())
                for i in range(0, len(hashes), 2)
            ]
        return hashes[0]

    def header_dict(self) -> dict:
        return {
            "version":          self.version,
            "protocol_version": self.protocol_version,
            "index":            self.index,
            "prev_hash":        self.prev_hash,
            "timestamp":        self.timestamp,
            "miner":            self.miner_address,
            "difficulty":       self.difficulty,
            "nonce":            self.nonce,
            "merkle_root":      self.merkle_root,
            "state_root":       self.state_root,
            "vrf_proof":        self.vrf_proof,
            "vrf_output":       self.vrf_output,
        }

    def compute_hash(self) -> str:
        return hash_obj(self.header_dict())

    def mine(self, stop_event: Optional[threading.Event] = None) -> bool:
        """
        PoW: find a nonce such that int(hash, 16) ≤ difficulty_to_target(difficulty).

        Numeric target system
        ─────────────────────
        Difficulty is a float (e.g. 0.001, 0.25, 1.5, 7.0).  The target is
        computed once via DifficultyEngine.difficulty_to_target() and then
        compared numerically:
            hash_int = int(block_hash, 16)
            valid    = hash_int <= target

        MTP-safe timestamp preservation
        ─────────────────────────────────
        build_candidate_block() already sets self.timestamp to a value that is
        guaranteed to be strictly greater than the MTP of recent blocks.  The
        mining loop must NOT blindly overwrite this with int(time.time()) at
        solve time because doing so could regress below the MTP and cause the
        block to fail validate_block()'s timestamp check.

        Timestamp is only advanced — never regressed — during the mining loop.
        The refresh at TIMESTAMP_REFRESH_INTERVAL increments the timestamp when
        time has moved forward but never moves it backward.

        Minimum nonce iterations
        ─────────────────────────
        Even at very low difficulty (e.g. 0.001 bootstrap) the loop always runs
        at least MIN_NONCE_ITERS iterations before accepting a solution.  This
        ensures the nonce in block headers and logs is never trivially 0, and
        that the mining loop genuinely exercises multiple hash computations per
        block.  The difficulty formula and PoW validity check are unchanged.
        """
        TIMESTAMP_REFRESH_INTERVAL = 50_000
        # Minimum nonce iterations required before accepting a valid hash.
        MIN_NONCE_ITERS = 16

        try:
            target = DifficultyEngine.difficulty_to_target(self.difficulty)
        except (TypeError, ValueError, OverflowError):
            # Malformed consensus input (including NaN/Infinity) cannot be
            # mined; fail closed instead of propagating an exception.
            return False
        if target <= 0:
            return False

        # Remember the MTP-safe timestamp set by build_candidate_block.
        # We only ever advance it forward — never backward.
        self.nonce = 0
        nonces_since_refresh = 0

        while True:
            if stop_event and stop_event.is_set():
                return False

            # Advance timestamp when enough nonces have elapsed, but ONLY
            # forward — preserve the MTP-safe floor set at block construction.
            if nonces_since_refresh >= TIMESTAMP_REFRESH_INTERVAL:
                new_ts = int(time.time())
                if new_ts > self.timestamp:   # only advance, never regress
                    self.timestamp = new_ts
                nonces_since_refresh = 0

            self.block_hash = self.compute_hash()
            hash_int = int(self.block_hash, 16)

            # Accept solution only after MIN_NONCE_ITERS honest iterations.
            # At very low difficulty every hash qualifies; this guard ensures
            # the miner genuinely iterates rather than always stopping at 0.
            if hash_int <= target and self.nonce >= MIN_NONCE_ITERS:
                # SECURITY: Seal the block so its consensus-critical fields
                # (transactions, merkle_root, block_hash, etc.) cannot be
                # mutated after a valid PoW solution is found.
                self.seal()
                return True   # timestamp already MTP-safe; do NOT overwrite

            self.nonce += 1
            nonces_since_refresh += 1

    def validate_pow(self) -> bool:
        """
        Verify Proof-of-Work using the canonical 256-bit integer target.

        The block hash (as a 256-bit integer) must be ≤ difficulty_to_target(D)
        where D = self.difficulty (float).  The numeric target path is the
        only authoritative check — the legacy string-prefix method does not
        support fractional difficulty values and is no longer used.
        """
        recomputed = self.compute_hash()
        if recomputed != self.block_hash:
            return False
        return DifficultyEngine.validate_pow_target(self.block_hash, self.difficulty)

    def total_tx_fees(self) -> float:
        return round(sum(t.compute_fee() for t in self.transactions if t.sender != "COINBASE"), 8)

    def total_tx_fees_sat(self) -> int:
        """Total fees in satoshi — pure integer sum (F-01 COMPLETION)."""
        return sum(t.compute_fee_sat() for t in self.transactions if t.sender != "COINBASE")

    def to_dict(self) -> dict:
        return {
            "version":          self.version,
            "protocol_version": self.protocol_version,
            "index":            self.index,
            "prev_hash":        self.prev_hash,
            "timestamp":        self.timestamp,
            "miner_address":    self.miner_address,
            "difficulty":       self.difficulty,
            "nonce":            self.nonce,
            "vrf_proof":        self.vrf_proof,
            "vrf_output":       self.vrf_output,
            "merkle_root":      self.merkle_root,
            "state_root":       self.state_root,
            "block_hash":       self.block_hash,
            "finalized":        self.finalized,
            "validator_sigs":   self.validator_sigs,
            "transactions":     [t.to_dict() for t in self.transactions],
        }

    # ── Block size inspection ────────────────────────────────────────────────
    def size(self) -> int:
        """
        Return the serialized size of this block in bytes.

        The size is measured as the length of the canonical JSON encoding of
        to_dict() — the same representation used on the wire and by the
        dynamic-block-size accounting in Blockchain.get_dynamic_block_size().
        This makes the returned number directly comparable against
        Config.MAX_BLOCK_SIZE and the fill-ratio computation in
        accept_chain().
        """
        return len(json.dumps(self.to_dict()).encode("utf-8"))

    def size_human(self) -> str:
        """
        Return the block size as a human-readable string
        (e.g. "812 B", "14.3 KB", "1.07 MB").  Convenience wrapper around
        size() for CLI / log output.
        """
        n = self.size()
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n / 1024:.2f} KB"
        return f"{n / (1024 * 1024):.2f} MB"

    @classmethod
    def from_dict(cls, d: dict) -> 'Block':
        txs = [Transaction.from_dict(t) for t in d.get("transactions", [])]
        blk = cls(
            index            = d["index"],
            prev_hash        = d["prev_hash"],
            transactions     = txs,
            miner_address    = d["miner_address"],
            difficulty       = d["difficulty"],
            timestamp        = d["timestamp"],
            nonce            = d["nonce"],
            block_hash       = d["block_hash"],
            validator_sigs   = d.get("validator_sigs", []),
            vrf_proof        = d.get("vrf_proof", ""),
            vrf_output       = d.get("vrf_output", ""),
            finalized        = d.get("finalized", False),
            state_root       = d.get("state_root", ""),
            protocol_version = d.get("protocol_version", Config.PROTOCOL_VERSION),
            merkle_root      = d.get("merkle_root") if "merkle_root" in d else None,
        )
        # Remember the historical Merkle commitment for a compact pruned
        # record. It must be restored *after* seal(), because seal() recomputes
        # merkle_root from the intentionally omitted transaction list.
        pruned_merkle = d.get("merkle_root") if d.get("pruned") else None
        # SECURITY: Seal blocks loaded from storage or network so their
        # consensus-critical fields are immutable after deserialisation.
        blk.seal(recompute_merkle=False)
        if pruned_merkle:
            # This is loader restoration of the authenticated stored header,
            # not a caller-visible mutation path; normal attribute writes
            # remain blocked by the sealed object.
            object.__setattr__(blk, "merkle_root", pruned_merkle)
        return blk
