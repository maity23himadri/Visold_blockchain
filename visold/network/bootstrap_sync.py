"""Authenticated pruning-safe bootstrap helpers.

A bootstrap snapshot is NOT trusted merely because a peer advertises it.  The
receiver first verifies the PoW header chain from its locally-known genesis to
snapshot_height+1, then verifies the coinbase Merkle inclusion that commits to
the exact SHA-256 digest of the complete snapshot at snapshot_height.
"""
from __future__ import annotations

import math
import time
from typing import Dict, Iterable, List, Optional, Tuple

from visold.consensus.difficulty import DifficultyEngine
from visold.crypto.hashing import hash_obj
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.spv import SPVClient


_HEADER_KEYS = (
    "version", "protocol_version", "index", "prev_hash", "timestamp",
    "miner_address", "difficulty", "nonce", "merkle_root", "state_root",
    "block_hash", "vrf_proof", "vrf_output",
)


def _canonical_header_dict(d: dict) -> dict:
    """Return the exact dictionary hashed by Block.header_dict()."""
    return {
        "version": int(d.get("version", Block.VERSION)),
        "protocol_version": int(d.get("protocol_version", Config.PROTOCOL_VERSION)),
        "index": int(d["index"]),
        "prev_hash": str(d.get("prev_hash", "")),
        "timestamp": int(d.get("timestamp", 0)),
        "miner": str(d.get("miner_address", "")),
        "difficulty": float(d.get("difficulty", 0.0)),
        "nonce": int(d.get("nonce", 0)),
        "merkle_root": str(d.get("merkle_root", "")),
        "state_root": str(d.get("state_root", "")),
        "vrf_proof": str(d.get("vrf_proof", "")),
        "vrf_output": str(d.get("vrf_output", "")),
    }


class _HeaderDifficultyView:
    """Minimal Storage-compatible view used by the deterministic DAA."""
    def __init__(self, rows: List[Tuple[int, float]]):
        self.rows = rows

    def get_block_consensus_window(self, start_idx: int, end_idx: int):
        start = max(0, int(start_idx))
        end = min(int(end_idx), len(self.rows) - 1)
        if end < start:
            return []
        return list(self.rows[start:end + 1])


def _normalise_transport_block(d: dict) -> dict:
    """Strip untrusted post-consensus finality metadata before local storage."""
    out = dict(d)
    out["finalized"] = False
    out["validator_sigs"] = []
    # Header-only bootstrap records must remain explicitly marked as pruned.
    if not out.get("transactions"):
        out["pruned"] = True
    return out


def _extract_commitment(block_dict: dict, snapshot_height: int) -> Tuple[Optional[str], str]:
    """Authenticate and return the bootstrap digest committed by this block."""
    try:
        idx = int(block_dict.get("index", -1))
        if idx != int(snapshot_height) + 1:
            return None, "commitment block height mismatch"

        txs = block_dict.get("transactions") or []
        if txs:
            # Full block: authoritative integrity_check validates tx ids,
            # signatures, Merkle root and block hash before we inspect memo.
            blk = Block.from_dict(block_dict)
            ok, why = blk.integrity_check()
            if not ok:
                return None, f"commitment block integrity failed: {why}"
            if not blk.transactions or blk.transactions[0].sender != "COINBASE":
                return None, "commitment block has no leading coinbase"
            parsed = Transaction.parse_bootstrap_commitment(blk.transactions[0].memo)
            if not parsed:
                return None, "bootstrap commitment missing from coinbase"
            h, digest = parsed
            if int(h) != int(snapshot_height):
                return None, "bootstrap commitment snapshot height mismatch"
            return digest, "OK"

        retained = block_dict.get("bootstrap_commitment")
        if not isinstance(retained, dict):
            return None, "pruned commitment block has no retained Merkle proof"
        coinbase_d = retained.get("coinbase")
        proof = retained.get("merkle_proof")
        if not isinstance(coinbase_d, dict) or not isinstance(proof, list):
            return None, "malformed retained bootstrap commitment"
        coinbase = Transaction.from_dict(coinbase_d)
        # Bind every coinbase field to its advertised tx_id before verifying
        # inclusion.  A peer cannot alter memo and keep the old tx id.
        if coinbase.tx_id != coinbase._compute_id(block_height=idx):
            return None, "retained coinbase tx_id mismatch"
        if coinbase.sender != "COINBASE":
            return None, "retained commitment transaction is not coinbase"
        if not SPVClient.verify_merkle_proof(
                coinbase.tx_id, proof, str(block_dict.get("merkle_root", ""))):
            return None, "retained bootstrap commitment Merkle proof failed"
        parsed = Transaction.parse_bootstrap_commitment(coinbase.memo)
        if not parsed:
            return None, "retained coinbase has no bootstrap commitment"
        h, digest = parsed
        if int(h) != int(snapshot_height):
            return None, "retained bootstrap commitment height mismatch"
        if str(retained.get("digest", digest)) != digest:
            return None, "retained commitment digest metadata mismatch"
        if int(retained.get("snapshot_height", h)) != int(h):
            return None, "retained commitment height metadata mismatch"
        return digest, "OK"
    except Exception as exc:
        return None, f"bootstrap commitment verification failed: {exc}"


def verify_bootstrap_header_chain(
    blocks: Iterable[dict],
    genesis_hash: str,
    snapshot_height: int,
) -> Tuple[bool, str, List[dict], Optional[str]]:
    """Verify headers 0..snapshot_height+1 and authenticate snapshot digest.

    The function intentionally does not trust ``finalized``, validator
    signatures, manifest hashes, or peer-reported cumulative work.  The local
    genesis hash is the trust anchor.  Every subsequent header must satisfy
    linkage, exact header hash, PoW, deterministic DAA and MTP lower bound.
    """
    target = int(snapshot_height) + 1
    if target <= 1 or not genesis_hash:
        return False, "invalid bootstrap target/genesis", [], None

    by_height: Dict[int, dict] = {}
    for item in blocks:
        if not isinstance(item, dict):
            return False, "non-object block in bootstrap header stream", [], None
        try:
            h = int(item.get("index", -1))
        except Exception:
            return False, "invalid bootstrap block index", [], None
        if h < 0 or h > target:
            continue
        if h in by_height and str(by_height[h].get("block_hash")) != str(item.get("block_hash")):
            return False, f"conflicting bootstrap headers at height {h}", [], None
        by_height[h] = item

    missing = [h for h in range(0, target + 1) if h not in by_height]
    if missing:
        return False, f"bootstrap header stream has gaps (first missing={missing[0]})", [], None

    if str(by_height[0].get("block_hash", "")) != str(genesis_hash):
        return False, "bootstrap genesis does not match local canonical genesis", [], None

    rows: List[Tuple[int, float]] = []
    normalised: List[dict] = []
    prev_hash = str(genesis_hash)
    timestamps: List[int] = []
    now = int(time.time())

    for h in range(0, target + 1):
        d = by_height[h]
        try:
            # Validate required fields and numeric finiteness before hashing.
            for k in _HEADER_KEYS:
                if k not in d:
                    return False, f"bootstrap header {h} missing {k}", [], None
            diff = float(d["difficulty"])
            ts = int(d["timestamp"])
            if not math.isfinite(diff) or diff < 0:
                return False, f"bootstrap header {h} has invalid difficulty", [], None
            if h > 0 and str(d.get("prev_hash", "")) != prev_hash:
                return False, f"bootstrap prev_hash mismatch at height {h}", [], None
            computed = hash_obj(_canonical_header_dict(d))
            stored = str(d.get("block_hash", ""))
            if computed != stored:
                return False, f"bootstrap block_hash mismatch at height {h}", [], None

            if h > 0:
                if not DifficultyEngine.validate_pow_target(stored, diff):
                    return False, f"invalid bootstrap PoW at height {h}", [], None
                expected = DifficultyEngine._compute_uncached(_HeaderDifficultyView(rows), h - 1)
                if abs(diff - float(expected)) > 1e-9:
                    return False, (
                        f"bootstrap difficulty mismatch at height {h}: "
                        f"got {diff}, expected {expected}"), [], None
                recent = timestamps[-int(Config.DIFF_MTP_WINDOW):]
                ok_ts, why_ts = DifficultyEngine.validate_timestamp(ts, recent, now)
                if not ok_ts:
                    return False, f"bootstrap timestamp invalid at height {h}: {why_ts}", [], None

            rows.append((ts, diff))
            timestamps.append(ts)
            prev_hash = stored
            normalised.append(_normalise_transport_block(d))
        except Exception as exc:
            return False, f"bootstrap header validation error at {h}: {exc}", [], None

    digest, why = _extract_commitment(by_height[target], int(snapshot_height))
    if digest is None:
        return False, why, [], None
    return True, "OK", normalised, digest
