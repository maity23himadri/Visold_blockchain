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
"""visold.network.spv

Original section: SECTION 1G: LIGHT CLIENT / SPV  (Problem #16)

Defines: SPVClient
Origin: visold_vsd_.py L8293-8488
"""

from typing import List, Optional, TYPE_CHECKING

from visold.crypto.hashing import sha256
from visold.kernel.config import Config

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.ledger.block import Block
    from visold.ledger.transaction import Transaction


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1G: LIGHT CLIENT / SPV  (Problem #16)
# ─────────────────────────────────────────────────────────────────────────────
class SPVClient:
    """
    Simplified Payment Verification (SPV) utilities.

    A light client only needs block headers and Merkle inclusion proofs
    to verify that a transaction is in a block, without downloading the
    full transaction set.

    Proof format:
    ═════════════
    A list of step dicts describing the co-path from the transaction leaf
    up to the Merkle root.  Two step kinds exist:

      • Pairing step  : {'hash': <sibling>, 'side': 'L' | 'R'}
            'R' → current is on the LEFT,  combine as sha256(current + sibling)
            'L' → current is on the RIGHT, combine as sha256(sibling + current)
      • Odd-loner step: {'hash': '',         'side': 'ODD'}
            current was the unpaired loner at that level — promote it via the
            domain-separated tag, sha256("|odd|" + current).  This step has no
            sibling because the V2 construction does not pair the loner.

    Verification:
    ═════════════
    Re-compute the root by walking the proof in order; compare the result
    with the block's stored merkle_root.

    SEC-FIX H-01 / SPV-1 (Merkle V2 compatibility)
    ──────────────────────────────────────────────
    Block._merkle() was upgraded to a CVE-2012-2459-safe V2 construction
    that domain-separates odd loners with the tag "|odd|".  V2 is the
    default on every fresh chain (Config.MERKLE_V2_ACTIVATION_HEIGHT = 0).
    The pre-fix proof helpers in this class still implemented the V1
    duplicate-last rule, so on any block whose tree had at least one odd
    level (i.e. tx_count is not a power of two) every generated proof
    failed verification against the block's stored root — making SPV
    unusable for the overwhelming majority of real blocks.

    The fixed helpers:
      • get_merkle_proof()    accepts the block height and emits the
        correct step kind for each level under the rule active at that
        height.
      • verify_merkle_proof() handles the new 'ODD' step type in addition
        to the legacy 'L'/'R' pairing steps.

    The proof format extension is backward compatible: legacy proofs that
    contain only 'L'/'R' steps (and were produced for power-of-two trees,
    or for blocks below MERKLE_V2_ACTIVATION_HEIGHT on chains that opted
    in) continue to verify identically.
    """

    @staticmethod
    def _v2_active_for_height(block_height: int) -> bool:
        """
        Mirror of the activation rule used in Block._merkle().  When the
        caller does not know the height (block_height < 0) we fail closed
        to V2 — V2 is at least as safe as V1 and is the default on fresh
        chains (activation height 0).
        """
        try:
            activation = int(Config.MERKLE_V2_ACTIVATION_HEIGHT)
        except Exception:
            return True
        if block_height < 0:
            return True
        return block_height >= activation

    @staticmethod
    def get_merkle_proof(transactions: List['Transaction'],
                         tx_id: str,
                         block_height: int = -1) -> Optional[List[dict]]:
        """
        Compute the Merkle inclusion proof for tx_id within the given tx list.

        block_height
            The index of the block whose merkle_root the proof will be
            verified against.  Used to select the V1 / V2 construction so
            that the proof matches Block._merkle() byte-for-byte.  Pass -1
            (or omit) when the height is unknown — the V2 rule is selected,
            which is correct on any fresh chain (activation height 0) and
            on any block at or above MERKLE_V2_ACTIVATION_HEIGHT.

        Returns a list of proof steps (see class docstring), or None if
        tx_id is not present in `transactions`.
        """
        hashes = [t.tx_id for t in transactions]
        if not hashes:
            return None
        try:
            idx = next(i for i, h in enumerate(hashes) if h == tx_id)
        except StopIteration:
            return None

        proof: List[dict] = []

        if SPVClient._v2_active_for_height(block_height):
            # V2 — domain-separated odd-loner promotion.  Mirror of the V2
            # branch of Block._merkle exactly.
            ODD_TAG = "|odd|"
            while len(hashes) > 1:
                pairs = len(hashes) // 2
                paired_count = pairs * 2  # number of leaves consumed by pairings

                if idx < paired_count:
                    # Target is in the paired region — emit a normal L/R step.
                    sibling_idx = idx ^ 1
                    side        = 'R' if idx % 2 == 0 else 'L'
                    proof.append({'hash': hashes[sibling_idx], 'side': side})
                else:
                    # Target IS the odd loner at this level — emit an ODD
                    # step with no sibling.  The verifier will hash
                    # ("|odd|" + current) to reproduce the V2 promotion.
                    proof.append({'hash': '', 'side': 'ODD'})

                # Build next level under the V2 rule.
                next_level = [
                    sha256((hashes[2*i] + hashes[2*i+1]).encode())
                    for i in range(pairs)
                ]
                if len(hashes) % 2 == 1:
                    next_level.append(
                        sha256((ODD_TAG + hashes[-1]).encode()))

                # Where does our target land in the next level?
                if idx < paired_count:
                    idx //= 2
                else:
                    # The loner is appended at the end of next_level.
                    idx = len(next_level) - 1
                hashes = next_level
            return proof

        # V1 (legacy) — duplicate-last-hash, kept ONLY for re-proving
        # historical blocks on chains that have opted in to legacy mode.
        # This path matches the V1 branch of Block._merkle exactly.
        while len(hashes) > 1:
            if len(hashes) % 2:
                hashes.append(hashes[-1])
            sibling_idx = idx ^ 1
            side        = 'R' if idx % 2 == 0 else 'L'
            proof.append({'hash': hashes[sibling_idx], 'side': side})
            hashes = [sha256((hashes[i] + hashes[i+1]).encode())
                      for i in range(0, len(hashes), 2)]
            idx //= 2
        return proof

    @staticmethod
    def verify_merkle_proof(tx_id: str, proof: List[dict], merkle_root: str) -> bool:
        """
        Verify a Merkle inclusion proof.

        Accepts both legacy proofs ('L'/'R' steps only) and V2 proofs that
        may also contain 'ODD' steps for domain-separated loner promotion.

        Returns True iff the reconstructed root matches `merkle_root`.
        Never raises — malformed or unknown step kinds yield False.
        """
        if proof is None or merkle_root is None:
            return False
        ODD_TAG = "|odd|"
        current = tx_id
        try:
            for step in proof:
                side = step.get('side', 'R')
                if side == 'ODD':
                    current = sha256((ODD_TAG + current).encode())
                elif side == 'R':
                    current = sha256((current + step['hash']).encode())
                elif side == 'L':
                    current = sha256((step['hash'] + current).encode())
                else:
                    # Unknown step kind — refuse rather than silently
                    # accepting under one of the legacy branches.
                    return False
        except (KeyError, TypeError, AttributeError):
            return False
        return current == merkle_root

    @staticmethod
    def get_block_header(block: 'Block') -> dict:
        """Return only the block header fields (for light-client sync)."""
        return {
            "version":         block.version,
            "protocol_version": block.protocol_version,
            "index":           block.index,
            "prev_hash":       block.prev_hash,
            "timestamp":       block.timestamp,
            "miner_address":   block.miner_address,
            "difficulty":      block.difficulty,
            "nonce":           block.nonce,
            "merkle_root":     block.merkle_root,
            "state_root":      block.state_root,
            "block_hash":      block.block_hash,
            "finalized":       block.finalized,
            "vrf_proof":       block.vrf_proof,
            "vrf_output":      block.vrf_output,
        }
