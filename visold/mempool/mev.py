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

"""visold.mempool.mev

MEV protection for transfers: on-chain commit-reveal with a merkle proof.

A protected transfer is two ordinary transfers from one wallet.

1. Commitment, mined first: a zero-value self-transfer whose data is
   "mev-commit:<H>". H is a salted SHA-256 of the transfer's contents
   (Transaction.mev_commitment), so observers see only H.

2. Reveal: the transfer itself, whose data is "mev-reveal:<salt>:<c>:<steps>".
   c is the height of the block that contains the commitment, and <steps> is
   the merkle path from the commitment to that block's merkle root. Consensus
   accepts the reveal when block c's header is on the canonical chain, c lies
   COMMIT_REVEAL_DELAY_BLOCKS to MEV_COMMIT_MAX_AGE_BLOCKS blocks before the
   block that includes the reveal, and the commitment (rebuilt from the
   reveal's own fields and salt) is in block c.

Validation reads only block headers, never block bodies. Headers are kept at
every height, including by pruned nodes and by nodes that bootstrap from an
authenticated snapshot, so every node gives the same answer.

What this protects: the transfer's contents stay hidden until its commitment is
on-chain. What it does not protect: once the reveal is broadcast it is visible
in the mempool, so a bot that can act on it before it is mined can do so. The
order of execution is not fixed, and validators see every transfer.

The node sends one protected transfer at a time (see StateEngine). The state of
the transfer in flight is kept in node metadata, so it survives restarts.
"""

import json
import secrets
import time
from typing import List, Optional, Tuple

from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.units import from_satoshi
from visold.ledger.transaction import (
    Transaction,
    encode_mev_steps,
    parse_mev_commit_data,
    parse_mev_reveal_data,
)

# Give up on a commitment that has not been mined within this many blocks.
MAX_WAIT_BLOCKS = 60
FLIGHT_META_KEY = "mev_protected_transfer"
# Rejections that can clear by themselves; the reveal is kept and retried.
_TRANSIENT_MARKERS = (
    "Mempool full", "Rate limit", "Reverse transaction",
    "is not on-chain", "is too recent", "is unavailable",
)


def is_protected_reveal(tx: Transaction) -> bool:
    """True for a transfer that carries an MEV reveal."""
    return (tx.tx_type == Transaction.TYPE_TRANSFER
            and str(tx.data).startswith(Config.MEV_REVEAL_PREFIX))


def is_transient_rejection(msg: str) -> bool:
    return any(marker in (msg or "") for marker in _TRANSIENT_MARKERS)


def new_salt() -> str:
    return secrets.token_hex(32)


def commit_fee_vsd() -> float:
    return from_satoshi(int(getattr(Config, "MIN_TX_FEE_SAT", 1000)))


def core_transfer(sender: str, receiver: str, amount: float, fee: float,
                  memo: str, nonce: int, timestamp: int) -> Transaction:
    """The transfer's contents as an unsigned transaction.

    The commitment and the reveal are both built from this object, so they agree
    on every field the commitment covers.
    """
    return Transaction(sender=sender, receiver=receiver, amount=amount, fee=fee,
                       memo=memo, nonce=int(nonce), timestamp=int(timestamp))


def commitment_tx_fields(sender: str, reveal_nonce: int, timestamp: int,
                         commitment: str) -> Transaction:
    """The commitment transaction that goes with a reveal of this nonce and time.

    The sender signs it and validators rebuild it from the reveal's fields, using
    this same function, so the two cannot disagree on its transaction id.
    """
    return Transaction(
        sender=sender, receiver=sender, amount=0.0, fee=commit_fee_vsd(),
        timestamp=int(timestamp), memo="", nonce=int(reveal_nonce) - 1,
        data=Config.MEV_COMMIT_PREFIX + commitment)


def build_commitment_tx(wallet, reveal_nonce: int, timestamp: int,
                        commitment: str) -> Transaction:
    tx = commitment_tx_fields(wallet.address, reveal_nonce, timestamp, commitment)
    tx.sign(wallet)
    return tx


def build_reveal_tx(wallet, core: Transaction, salt: str, commit_height: int,
                    steps: List[Tuple[str, str]]) -> Transaction:
    data = (Config.MEV_REVEAL_PREFIX + salt + ":" + str(int(commit_height)) + ":"
            + encode_mev_steps(steps))
    tx = Transaction(sender=core.sender, receiver=core.receiver, amount=core.amount,
                     fee=core.fee, memo=core.memo, nonce=core.nonce,
                     timestamp=core.timestamp, data=data)
    tx.sign(wallet)
    return tx


def flight_core(flight: dict) -> Transaction:
    """Rebuild the transfer's contents from the stored protected-transfer record."""
    core = flight["core"]
    return core_transfer(flight["sender"], core["receiver"],
                         from_satoshi(int(core["amount_sat"])),
                         from_satoshi(int(core["fee_sat"])),
                         core["memo"], int(core["nonce"]), int(core["timestamp"]))


# ── merkle paths (must mirror Block._merkle exactly) ─────────────────────────

def _uses_v2_merkle(block_index: int) -> bool:
    """Same rule as Block._merkle: V2 from MERKLE_V2_ACTIVATION_HEIGHT onwards."""
    try:
        return int(block_index) >= int(Config.MERKLE_V2_ACTIVATION_HEIGHT)
    except Exception:
        return True


def merkle_steps(tx_ids: List[str], index: int, v2: bool) -> List[Tuple[str, str]]:
    """Merkle path from leaf ``index`` to the root, built as Block._merkle builds it.

    Each step is ("L", sibling) when the sibling is on the left, ("R", sibling)
    when it is on the right, or ("O", "") for a loner promoted with the odd tag.
    """
    level = list(tx_ids)
    k = int(index)
    if not 0 <= k < len(level):
        raise ValueError("leaf index out of range")
    steps: List[Tuple[str, str]] = []
    while len(level) > 1:
        m = len(level)
        if v2:
            pairs = m // 2
            if k < 2 * pairs:
                if k % 2 == 0:
                    steps.append(("R", level[k + 1]))
                else:
                    steps.append(("L", level[k - 1]))
                k //= 2
            else:
                steps.append(("O", ""))
                k = pairs
            nxt = [sha256((level[2 * i] + level[2 * i + 1]).encode())
                   for i in range(pairs)]
            if m % 2 == 1:
                nxt.append(sha256(("|odd|" + level[-1]).encode()))
            level = nxt
        else:
            if m % 2 == 1:
                level = level + [level[-1]]
            if k % 2 == 0:
                steps.append(("R", level[k + 1]))
            else:
                steps.append(("L", level[k - 1]))
            k //= 2
            level = [sha256((level[2 * i] + level[2 * i + 1]).encode())
                     for i in range(len(level) // 2)]
    return steps


def verify_merkle_steps(leaf: str, steps: List[Tuple[str, str]], root: str,
                        v2: bool) -> bool:
    cur = leaf
    for kind, sibling in steps:
        if kind == "R":
            cur = sha256((cur + sibling).encode())
        elif kind == "L":
            cur = sha256((sibling + cur).encode())
        elif kind == "O" and v2:
            cur = sha256(("|odd|" + cur).encode())
        else:
            return False
    return cur == root


def reveal_steps_for_commit(storage, commit_txid: str,
                            commit_height: int) -> List[Tuple[str, str]]:
    """Merkle path of a commitment inside its block, read from the stored block."""
    block = storage.get_block(int(commit_height))
    if block is None:
        raise LookupError("commitment block body is not available")
    ids = [tx.tx_id for tx in block.transactions]
    if commit_txid not in ids:
        raise LookupError("commitment is not in its block")
    v2 = _uses_v2_merkle(block.index)
    steps = merkle_steps(ids, ids.index(commit_txid), v2)
    if not verify_merkle_steps(commit_txid, steps, block.merkle_root, v2):
        raise LookupError("block merkle root does not match its transactions")
    return steps


def build_reveal_for_flight(storage, wallet, flight: dict,
                            commit_height: int) -> Transaction:
    """Build the signed reveal of a protected transfer in flight.

    Raises ValueError for a fault that cannot clear by itself, and LookupError when
    the commitment's block body is not available yet.
    """
    core = flight_core(flight)
    salt = flight["salt"]
    commitment = core.mev_commitment(salt)
    expected = commitment_tx_fields(core.sender, int(core.nonce), int(core.timestamp),
                                    commitment)
    if expected.tx_id != flight["commit_txid"]:
        raise ValueError("stored commitment does not match the transfer it was made for")
    block = storage.get_block(int(commit_height))
    if block is None:
        raise LookupError("commitment block body is not available")
    found = [tx for tx in block.transactions if tx.tx_id == flight["commit_txid"]]
    if len(found) != 1:
        raise ValueError("commitment is not in its block")
    if parse_mev_commit_data(found[0].data) != commitment:
        raise ValueError("commitment on-chain does not match the transfer")
    steps = reveal_steps_for_commit(storage, flight["commit_txid"], commit_height)
    return build_reveal_tx(wallet, core, salt, commit_height, steps)


# ── consensus rule ──────────────────────────────────────────────────────────

def check_reveal(storage, reveal: Transaction, at_height: int) -> Tuple[bool, str]:
    """Check a reveal for the block at ``at_height``.

    Needs only block headers: the reveal carries the commitment's height and its
    merkle path, and the commitment is rebuilt from the reveal's own fields.
    """
    parsed = parse_mev_reveal_data(reveal.data)
    if parsed is None:
        return False, "reveal data is malformed"
    salt, commit_height, steps = parsed
    if int(reveal.nonce) < 1:
        return False, "reveal nonce must follow its commitment"
    delay = int(Config.COMMIT_REVEAL_DELAY_BLOCKS)
    max_age = int(Config.MEV_COMMIT_MAX_AGE_BLOCKS)
    at_height = int(at_height)
    if commit_height > at_height - delay:
        return False, f"commitment is too recent: it must be at least {delay} blocks old"
    if commit_height < at_height - max_age:
        return False, (f"commitment is too old: a reveal may come at most "
                       f"{max_age} blocks after it")
    header = storage.get_block_header(commit_height)
    if not header or not header.get("merkle_root"):
        return False, "commitment is not on-chain"
    commit = commitment_tx_fields(reveal.sender, int(reveal.nonce),
                                  int(reveal.timestamp), reveal.mev_commitment(salt))
    if not verify_merkle_steps(commit.tx_id, steps, header["merkle_root"],
                               _uses_v2_merkle(commit_height)):
        return False, "commitment is not part of its block"
    return True, "OK"


# ── node-side state of the transfer in flight ───────────────────────────────

def find_tx_height(storage, tx_id: str, lowest: int, tip: int) -> Optional[int]:
    """Height of ``tx_id`` among the blocks lowest..tip (newest first), or None."""
    for h in range(int(tip), max(0, int(lowest)) - 1, -1):
        block = storage.get_block(h)
        if block is None:
            continue
        for tx in block.transactions:
            if tx.tx_id == tx_id:
                return h
    return None


def load_flight(storage) -> Optional[dict]:
    """The protected transfer in flight on this node, or None."""
    raw = storage.get_meta(FLIGHT_META_KEY)
    if not raw:
        return None
    try:
        flight = json.loads(raw)
    except ValueError:
        return None
    return flight if isinstance(flight, dict) else None


def save_flight(storage, flight: Optional[dict]) -> None:
    storage.set_meta(FLIGHT_META_KEY, "" if flight is None else
                     json.dumps(flight, sort_keys=True, separators=(",", ":")))


PROTECTION_DEFAULT_KEY = "mev_protect_default"


def protection_default(storage) -> bool:
    """Whether this node's wallet sends protected transfers unless told otherwise.

    The terminal menu stores the node's choice. Until a choice is stored, the
    VISOLD_MEV_PROTECT setting gives the starting value (off unless set to 1).
    """
    raw = storage.get_meta(PROTECTION_DEFAULT_KEY)
    if raw in ("0", "1"):
        return raw == "1"
    return bool(Config.MEV_PROTECTION_ENABLED)


def set_protection_default(storage, on: bool) -> None:
    storage.set_meta(PROTECTION_DEFAULT_KEY, "1" if on else "0")


def protection_status(storage) -> dict:
    """Status for the getmevstatus RPC and the terminal UI."""
    flight = load_flight(storage)
    return {
        "enabled": protection_default(storage),
        "delay_blocks": int(Config.COMMIT_REVEAL_DELAY_BLOCKS),
        "max_age_blocks": int(Config.MEV_COMMIT_MAX_AGE_BLOCKS),
        "in_flight": None if flight is None else {
            "phase": flight.get("phase"),
            "commit_txid": flight.get("commit_txid"),
            "reveal_txid": flight.get("reveal_txid") or None,
            "commit_height": flight.get("commit_height"),
            "started_height": flight.get("started_height"),
        },
        "validator_mev_protected": False,
        "front_running_protection": (
            "partial: contents stay hidden until the commitment is on-chain; "
            "after the reveal is broadcast it is visible in the mempool, and "
            "validators see every transfer"),
    }
