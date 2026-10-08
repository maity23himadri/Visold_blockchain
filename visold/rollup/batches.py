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
"""visold.rollup.batches

Original section: END SECTION 7E — Pass 3 (proof backend + registry).  Next passes add the

Defines: RollupBatch, RollupSubmission
Origin: visold_vsd_.py L24854-24887, L24891-25014
"""

import json
import time
import zlib
from typing import List, Tuple

from visold.crypto.hashing import sha256
from visold.rollup.l2_state import L2Transaction
from visold.kernel.compression_utils import bounded_zlib_decompress


# ═════════════════════════════════════════════════════════════════════════════
# END SECTION 7E — Pass 3 (proof backend + registry).  Next passes add the
# Sequencer + RollupSubmission, verifier precompile, wallet/P2P integration.
# ═════════════════════════════════════════════════════════════════════════════


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 7E-4: ROLLUP BATCH + SUBMISSION + SEQUENCER
#
# Data flow
# ─────────
#     wallet → L2Transaction → P2P gossip (MSG_L2TX) →
#     Sequencer pending-pool → seal RollupBatch →
#     generate_batch_proof() via IProofBackend →
#     RollupSubmission payload →
#     L1 Transaction (tx_type=TYPE_ROLLUP, data=json(RollupSubmission)) →
#     block inclusion → verifier precompile at apply time →
#     Layer2State.commit_batch() on success
#
# Compression
# ───────────
# The batch's transaction list is canonicalised to a compact tuple form
# and zlib-compressed before being embedded in the L1 tx.  Typical ratio
# on our test workload is ~8:1 — 200 L2 transfers at ~300 B each (60 KB
# expanded) compress to ~7 KB.  The compressed blob is what lives on L1
# for Data Availability; the proof attests that the blob's decompressed
# contents validly transition prev_root → new_root.
# ═════════════════════════════════════════════════════════════════════════════
class RollupBatch:
    """An in-memory bundle of L2 transactions the sequencer is assembling.

    Lifecycle:
      1. Sequencer.add_l2_tx() appends to a mutable RollupBatch
      2. When size or age thresholds hit, Sequencer.seal() freezes it
      3. seal() produces:
           - the new L2 root (after applying every tx in-order)
           - the compressed DA blob
           - the batch_hash (sha256 of the compressed blob)
           - the proof bytes (via IProofBackend)
         and emits a RollupSubmission wrapping all of that
    """

    def __init__(self, batch_id: int, prev_root: str):
        self.batch_id:   int = int(batch_id)
        self.prev_root:  str = prev_root
        self.new_root:   str = ""          # filled at seal()
        self.txs:        List[L2Transaction] = []
        self.created_ts: float = time.time()
        self.sealed:     bool  = False
        # Applied tx_ids — used for accounting / explorer; never consensus.
        self.applied_ids: List[str] = []

    def size(self) -> int:
        return len(self.txs)

    def age_secs(self) -> float:
        return time.time() - self.created_ts

    def add_tx(self, tx: L2Transaction) -> None:
        if self.sealed:
            raise RuntimeError("cannot add to sealed RollupBatch")
        self.txs.append(tx)


# ─────────────────────────────────────────────────────────────────────────────
class RollupSubmission:
    """The on-chain payload that rides inside an L1 Transaction's `data`
    field for TYPE_ROLLUP transactions.

    Required fields (per spec):
      • batch_id          — monotonic unique identifier
      • previous_l2_root  — the L2 root this batch extends
      • new_l2_root       — the L2 root after applying the batch
      • zk_proof          — the proof bytes (opaque, backend-specific)
      • compressed_data   — zlib-compressed canonical batch blob (Data
                            Availability — anyone can decompress and
                            re-execute to audit)
      • backend           — IProofBackend.name() that produced zk_proof
      • backend_security  — IProofBackend.security() at creation time

    The `backend` and `backend_security` fields are non-consensus metadata
    preserved so auditors and explorers can see at a glance whether a
    given historical batch was produced under a real ZK backend or the
    simulated stand-in.  verify-at-apply-time always uses the CURRENTLY
    configured backend to avoid downgrade attacks.
    """

    # Maximum size in bytes of the compressed DA blob.  Blocks are capped
    # at ~4 MB; we leave plenty of room for other transactions by capping
    # any single rollup submission at 1 MB compressed.
    MAX_COMPRESSED_BYTES = 1_000_000

    def __init__(self, batch_id: int, previous_l2_root: str,
                 new_l2_root: str, zk_proof: bytes,
                 compressed_data: bytes, backend: str,
                 backend_security: str):
        self.batch_id         = int(batch_id)
        self.previous_l2_root = previous_l2_root
        self.new_l2_root      = new_l2_root
        self.zk_proof         = bytes(zk_proof) if zk_proof else b""
        self.compressed_data  = bytes(compressed_data) if compressed_data else b""
        self.backend          = backend or ""
        self.backend_security = backend_security or ""

    # ── Serialization ────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        # Binary fields are hex-encoded for JSON embedding into L1 tx.data.
        return {
            "kind":              "rollup_submission_v1",
            "batch_id":          self.batch_id,
            "previous_l2_root":  self.previous_l2_root,
            "new_l2_root":       self.new_l2_root,
            "zk_proof":          self.zk_proof.hex(),
            "compressed_data":   self.compressed_data.hex(),
            "backend":           self.backend,
            "backend_security":  self.backend_security,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'RollupSubmission':
        if d.get("kind") != "rollup_submission_v1":
            raise ValueError(f"not a rollup_submission_v1: kind={d.get('kind')}")
        return cls(
            batch_id         = int(d["batch_id"]),
            previous_l2_root = d["previous_l2_root"],
            new_l2_root      = d["new_l2_root"],
            zk_proof         = bytes.fromhex(d.get("zk_proof", "")),
            compressed_data  = bytes.fromhex(d.get("compressed_data", "")),
            backend          = d.get("backend", ""),
            backend_security = d.get("backend_security", ""),
        )

    def to_json(self) -> str:
        # Compact JSON — no whitespace — for deterministic byte length.
        return json.dumps(self.to_dict(), separators=(",", ":"),
                          sort_keys=True)

    @classmethod
    def from_json(cls, s: str) -> 'RollupSubmission':
        return cls.from_dict(json.loads(s))

    # ── Structural validation ────────────────────────────────────────────
    def structural_ok(self) -> Tuple[bool, str]:
        """Surface-level checks that do NOT require proof verification or
        decompression.  Cheap filters that can run before the precompile."""
        if self.batch_id < 0:
            return False, "batch_id must be non-negative"
        if not self.previous_l2_root or len(self.previous_l2_root) != 64:
            return False, "previous_l2_root must be 64 hex chars"
        if not self.new_l2_root or len(self.new_l2_root) != 64:
            return False, "new_l2_root must be 64 hex chars"
        if self.previous_l2_root == self.new_l2_root and len(self.compressed_data) > 0:
            # Zero-tx batch would have prev == new; with data present this
            # is inconsistent.
            return False, "root transition is a no-op but batch is non-empty"
        if len(self.compressed_data) > self.MAX_COMPRESSED_BYTES:
            return False, (f"compressed_data too large "
                           f"({len(self.compressed_data)} > "
                           f"{self.MAX_COMPRESSED_BYTES} bytes)")
        return True, "OK"

    # ── Data Availability helpers ────────────────────────────────────────
    @staticmethod
    def compress_batch(txs: List[L2Transaction]) -> bytes:
        """Canonicalise + zlib-compress a tx list.  Deterministic:
        callers on different machines MUST produce identical bytes."""
        rows = [tx.to_dict() for tx in txs]
        raw  = json.dumps(rows, separators=(",", ":"),
                          sort_keys=True).encode()
        return zlib.compress(raw, level=9)

    @staticmethod
    def decompress_batch(blob: bytes) -> List[L2Transaction]:
        """Inverse of compress_batch.  Caps decompressed size to 32 MB as
        a zip-bomb defence."""
        _MAX = 32 * 1024 * 1024
        try:
            raw = bounded_zlib_decompress(blob, _MAX)
        except (zlib.error, ValueError) as e:
            raise ValueError(f"bad compressed_data: {e}")
        rows = json.loads(raw.decode())
        return [L2Transaction.from_dict(r) for r in rows]

    @staticmethod
    def batch_hash(compressed_data: bytes) -> str:
        """The canonical hash the proof commits to.  Deterministic."""
        return sha256(compressed_data)
