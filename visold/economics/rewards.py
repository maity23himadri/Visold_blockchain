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
"""visold.economics.rewards

Original section: SECTION 21B: REWARD HARDENING  (production-ready coinbase + fee rules)

Defines: RewardConfig, RewardError, Coinbase, build_coinbase, compute_tx_fee, sum_block_fees, validate_block_rewards, assert_inputs_mature
Origin: visold_vsd_.py L49242-49274, L49277-49279, L49283-49332, L49335-49371, L49375-49412, L49415-49423, L49427-49520, L49524-49550, L49554-49580
"""

import hashlib
import json
import time


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 21B: REWARD HARDENING  (production-ready coinbase + fee rules)
# ─────────────────────────────────────────────────────────────────────────────
# Closes the five reward-logic weaknesses identified in the v7.1.5 audit:
#
#   1. PoW reward creation        — canonical, deterministic coinbase
#   2. PoS reward creation        — same strict format as PoW coinbase
#   3. Transaction-fee abuse      — per-tx and per-block fee caps
#   4. Reward validation          — exactly ONE coinbase at index 0,
#                                   monetary-conservation check
#   5. Coinbase maturity          — reward outputs unspendable for N blocks
#
# This section is ADDITIVE ONLY.  It defines new names in the module
# namespace; it does not modify or monkey-patch any existing class.  To
# activate the hardening, call these functions from the mining / validation
# paths.  Suggested integration points:
#
#     # in the PoW / PoS mining routines, BEFORE appending mempool txs:
#     coinbase_dict = build_coinbase(
#         miner_address = self.miner_address,
#         height        = new_height,
#         subsidy       = subsidy_for(new_height),
#         fees          = total_fees,
#         consensus     = "pow",          # or "pos"
#         extra_nonce   = os.urandom(8),  # PoW only; b"" for PoS
#     ).to_dict()
#     block.transactions.insert(0, coinbase_dict)
#
#     # in the block-validation routine, AFTER structural checks:
#     validate_block_rewards(block,
#                            expected_subsidy=subsidy_for(block.height),
#                            chain_tip_height=self.height(),
#                            utxo_lookup=self.storage.get_utxo)
#
#     # in the per-tx input check, BEFORE debiting inputs:
#     assert_inputs_mature(tx,
#                          utxo_lookup=self.storage.get_utxo,
#                          chain_tip_height=self.height())
#
# Two prerequisites on the storage layer: UTXO records must expose ``height``
# and ``is_coinbase`` fields.  If the current Storage.get_utxo does not
# return these, the maturity check degrades to a no-op for those records.
# ─────────────────────────────────────────────────────────────────────────────

class RewardConfig:
    """Consensus-critical constants.  Identical on every node; change only
    at a scheduled hard-fork height."""

    # Must match the reward tx_type used in Section 4 (TRANSACTION).  If the
    # main Transaction class defines TYPE_REWARD with a different string,
    # override this constant before first block validation.
    TX_TYPE_REWARD: str = "reward"

    # Sentinel sender for coinbase transactions.  Any reward tx with a
    # different sender is rejected.
    COINBASE_SENDER: str = "COINBASE"

    # Blocks a coinbase output must be buried under before it can be spent.
    # Bitcoin uses 100.  For a hybrid PoW+PoS chain with a finality gadget,
    # a value in the 64–128 range is appropriate.  Keep it above the deepest
    # realistic reorg depth your BFT gadget can produce.
    COINBASE_MATURITY: int = 100

    # Per-transaction fee cap.  A transaction whose (inputs − outputs)
    # exceeds this is rejected as almost certainly a user mistake or an
    # attack trying to route stolen funds through the fee channel.
    # Expressed in base units (satoshi).  1 VSD = 100_000_000 base units.
    MAX_FEE_PER_TX: int = 10 * 100_000_000           # 10 VSD

    # Per-block total fee cap.  Defence in depth: even if the per-tx cap is
    # lifted in future, a single block can never siphon more than this into
    # the coinbase.
    MAX_FEES_PER_BLOCK: int = 1_000 * 100_000_000    # 1 000 VSD

    # Hard ceiling on the total coinbase output.  Sanity bound against
    # arithmetic overflow and catastrophic-bug inflation.
    MAX_COINBASE_OUTPUT: int = 100_000 * 100_000_000  # 100 000 VSD


class RewardError(Exception):
    """Raised for any reward / coinbase rule violation.  All messages are
    safe to surface to peers; they do not leak node-local state."""


# ── 1 + 2.  Canonical coinbase construction (PoW and PoS share one format)
class Coinbase:
    """In-memory representation of a coinbase / reward transaction.

    The on-wire form is produced by to_dict(); feed that into the main
    Transaction.from_dict — field names match the main Transaction class
    so no adapter is needed.
    """
    __slots__ = ("height", "miner_address", "subsidy", "fees",
                 "consensus", "extra_nonce_hex", "timestamp")

    def __init__(self, height, miner_address, subsidy, fees,
                 consensus, extra_nonce_hex, timestamp):
        self.height          = int(height)
        self.miner_address   = str(miner_address)
        self.subsidy         = int(subsidy)
        self.fees            = int(fees)
        self.consensus       = str(consensus)
        self.extra_nonce_hex = str(extra_nonce_hex)
        self.timestamp       = int(timestamp)

    @property
    def amount(self) -> int:
        return self.subsidy + self.fees

    def to_dict(self) -> dict:
        # Signature is intentionally empty.  A coinbase has no sender key;
        # its authenticity is implied by the block that contains it.  Any
        # node receiving a coinbase with a non-empty signature MUST reject
        # the block.
        return {
            "tx_type":   RewardConfig.TX_TYPE_REWARD,
            "sender":    RewardConfig.COINBASE_SENDER,
            "receiver":  self.miner_address,
            "amount":    int(self.amount),
            "fee":       0,
            "nonce":     int(self.height),
            "timestamp": int(self.timestamp),
            "signature": "",
            "data": json.dumps({
                "subsidy":     int(self.subsidy),
                "fees":        int(self.fees),
                "consensus":   self.consensus,
                "extra_nonce": self.extra_nonce_hex,
            }, sort_keys=True, separators=(",", ":")),
        }

    def txid(self) -> str:
        body = json.dumps(self.to_dict(), sort_keys=True,
                          separators=(",", ":")).encode()
        return hashlib.sha256(body).hexdigest()


def build_coinbase(miner_address, height, subsidy, fees,
                   consensus, extra_nonce=b"", timestamp=None):
    """Build the single reward transaction for a block.  All inputs are
    validated; callers never need to sanity-check the result."""
    if not isinstance(miner_address, str) or not miner_address:
        raise RewardError("coinbase: miner_address must be non-empty str")
    if not miner_address.startswith(("VSD", "vsd")):
        raise RewardError("coinbase: miner_address is not a Visold address")
    if not isinstance(height, int) or height < 0:
        raise RewardError("coinbase: height must be a non-negative int")
    if not isinstance(subsidy, int) or subsidy < 0:
        raise RewardError("coinbase: subsidy must be a non-negative int")
    if not isinstance(fees, int) or fees < 0:
        raise RewardError("coinbase: fees must be a non-negative int")
    if fees > RewardConfig.MAX_FEES_PER_BLOCK:
        raise RewardError(
            "coinbase: fees {} exceed MAX_FEES_PER_BLOCK {}".format(
                fees, RewardConfig.MAX_FEES_PER_BLOCK))
    if consensus not in ("pow", "pos"):
        raise RewardError(
            "coinbase: consensus must be pow|pos, got {!r}".format(consensus))

    total = subsidy + fees
    if total > RewardConfig.MAX_COINBASE_OUTPUT:
        raise RewardError(
            "coinbase: total output {} exceeds MAX_COINBASE_OUTPUT {}".format(
                total, RewardConfig.MAX_COINBASE_OUTPUT))

    return Coinbase(
        height          = height,
        miner_address   = miner_address,
        subsidy         = int(subsidy),
        fees            = int(fees),
        consensus       = consensus,
        extra_nonce_hex = extra_nonce.hex() if extra_nonce else "",
        timestamp       = int(timestamp if timestamp is not None else time.time()),
    )


# ── 3.  Fee accounting with per-tx and per-block caps ───────────────────────
def compute_tx_fee(tx, utxo_lookup):
    """Return the fee of a normal (non-coinbase) transaction.

    ``utxo_lookup(txid, vout_index)`` must return the output being spent as
    a dict with at least ``amount``, or None if it is missing / already
    spent.  This function does arithmetic and cap enforcement only; the
    caller is responsible for double-spend detection.
    """
    if _is_coinbase_like(tx):
        raise RewardError("compute_tx_fee called on a coinbase transaction")

    inputs_total  = 0
    outputs_total = 0

    for tin in _tx_inputs(tx):
        utxo = utxo_lookup(tin["prev_txid"], int(tin["prev_vout"]))
        if utxo is None:
            raise RewardError(
                "tx {}: spends missing utxo {}:{}".format(
                    _tx_id(tx), tin["prev_txid"], tin["prev_vout"]))
        inputs_total += int(utxo["amount"])

    for tout in _tx_outputs(tx):
        amt = int(tout["amount"])
        if amt < 0:
            raise RewardError("tx {}: negative output amount".format(_tx_id(tx)))
        outputs_total += amt

    fee = inputs_total - outputs_total
    if fee < 0:
        raise RewardError(
            "tx {}: outputs ({}) exceed inputs ({}) — negative fee".format(
                _tx_id(tx), outputs_total, inputs_total))
    if fee > RewardConfig.MAX_FEE_PER_TX:
        raise RewardError(
            "tx {}: fee {} exceeds MAX_FEE_PER_TX {} — likely user error "
            "or attack".format(_tx_id(tx), fee, RewardConfig.MAX_FEE_PER_TX))
    return fee


def sum_block_fees(non_coinbase_txs, utxo_lookup):
    total = 0
    for tx in non_coinbase_txs:
        total += compute_tx_fee(tx, utxo_lookup)
        if total > RewardConfig.MAX_FEES_PER_BLOCK:
            raise RewardError(
                "block fees running total {} exceeds MAX_FEES_PER_BLOCK {}".format(
                    total, RewardConfig.MAX_FEES_PER_BLOCK))
    return total


# ── 4.  Block-level reward validation ───────────────────────────────────────
def validate_block_rewards(block, expected_subsidy, chain_tip_height,
                           utxo_lookup=None):
    """Enforce every reward-related rule on a candidate block.  Raises
    RewardError on violation; returns None on success.

    Rules enforced:
      R1  The block has at least one transaction.
      R2  tx[0] is a coinbase (tx_type == reward, sender == COINBASE,
          signature == "").
      R3  No other transaction in the block is a coinbase.
      R4  Claimed subsidy equals the schedule-derived subsidy for this
          height — miners cannot self-inflate.
      R5  Claimed fees equal the sum of actual fees of other txs (when
          utxo_lookup is provided).
      R6  coinbase.amount == subsidy + fees (monetary conservation).
      R7  coinbase.receiver is a well-formed VSD address.
      R8  coinbase.nonce == block height (replay-domain binding).
    """
    txs = list(getattr(block, "transactions", []) or [])

    # R1
    if not txs:
        raise RewardError("block has no transactions (missing coinbase)")

    # R2
    cb = txs[0]
    if not _is_coinbase_like(cb):
        raise RewardError("block tx[0] is not a coinbase")
    if _tx_signature(cb):
        raise RewardError("coinbase must have empty signature")
    if _tx_sender(cb) != RewardConfig.COINBASE_SENDER:
        raise RewardError(
            "coinbase sender must be {!r}, got {!r}".format(
                RewardConfig.COINBASE_SENDER, _tx_sender(cb)))

    # R3 — strict: exactly one coinbase, and it must be at index 0
    for i, tx in enumerate(txs[1:], start=1):
        if _is_coinbase_like(tx):
            raise RewardError(
                "multiple coinbase transactions found "
                "(indexes 0 and {}) — rejected".format(i))

    # Decode coinbase payload
    payload = _decode_coinbase_data(cb)
    subsidy_claim = int(payload.get("subsidy", -1))
    fees_claim    = int(payload.get("fees", -1))

    # R4
    if subsidy_claim != int(expected_subsidy):
        raise RewardError(
            "coinbase subsidy claim {} != expected {} for height {}".format(
                subsidy_claim, expected_subsidy,
                getattr(block, "height", getattr(block, "index", "?"))))

    # R5 (only when utxo_lookup is available)
    if utxo_lookup is not None:
        actual_fees = sum_block_fees(txs[1:], utxo_lookup)
        if fees_claim != actual_fees:
            raise RewardError(
                "coinbase fees claim {} != actual sum of tx fees {}".format(
                    fees_claim, actual_fees))
    else:
        if fees_claim < 0 or fees_claim > RewardConfig.MAX_FEES_PER_BLOCK:
            raise RewardError(
                "coinbase fees claim {} outside permitted range".format(
                    fees_claim))

    # R6
    total_out = int(_tx_amount(cb))
    if total_out != subsidy_claim + fees_claim:
        raise RewardError(
            "coinbase amount {} != subsidy+fees ({}+{})".format(
                total_out, subsidy_claim, fees_claim))
    if total_out > RewardConfig.MAX_COINBASE_OUTPUT:
        raise RewardError(
            "coinbase amount {} exceeds MAX_COINBASE_OUTPUT {}".format(
                total_out, RewardConfig.MAX_COINBASE_OUTPUT))

    # R7
    receiver = _tx_receiver(cb)
    if (not isinstance(receiver, str)
            or not receiver
            or not receiver.startswith(("VSD", "vsd"))):
        raise RewardError(
            "coinbase receiver is not a Visold address: {!r}".format(receiver))

    # R8
    claimed_height = int(_tx_nonce(cb))
    block_height   = int(getattr(block, "height",
                                 getattr(block, "index", -1)))
    if claimed_height != block_height:
        raise RewardError(
            "coinbase nonce {} != block height {}".format(
                claimed_height, block_height))


# ── 5.  Coinbase maturity ───────────────────────────────────────────────────
def assert_inputs_mature(tx, utxo_lookup, chain_tip_height):
    """Raise RewardError if any input of tx spends an immature coinbase
    output.  Regular (non-coinbase) inputs are always accepted.

    The UTXO record returned by utxo_lookup must include:
      - "height":      block height where the utxo was created
      - "is_coinbase": bool, True for coinbase-derived outputs
    """
    if _is_coinbase_like(tx):
        return  # coinbase has no inputs

    for tin in _tx_inputs(tx):
        utxo = utxo_lookup(tin["prev_txid"], int(tin["prev_vout"]))
        if utxo is None:
            # Double-spend / missing utxo is handled elsewhere; do not mask
            # it as a maturity error.
            continue
        if not utxo.get("is_coinbase"):
            continue
        created = int(utxo["height"])
        confirmations = chain_tip_height - created + 1
        if confirmations < RewardConfig.COINBASE_MATURITY:
            raise RewardError(
                "tx {}: spends immature coinbase {}:{} "
                "(confirmations={}, required={})".format(
                    _tx_id(tx), tin["prev_txid"], tin["prev_vout"],
                    confirmations, RewardConfig.COINBASE_MATURITY))


# ── Helpers: tolerate both attribute-style (Transaction) and dict-style txs
def _g(tx, name, default=None):
    if isinstance(tx, dict):
        return tx.get(name, default)
    return getattr(tx, name, default)


def _is_coinbase_like(tx):
    return (_g(tx, "tx_type") == RewardConfig.TX_TYPE_REWARD
            or _g(tx, "sender") == RewardConfig.COINBASE_SENDER)


def _tx_inputs(tx):    return list(_g(tx, "inputs", []) or [])


def _tx_outputs(tx):   return list(_g(tx, "outputs", []) or [])


def _tx_id(tx):        return str(_g(tx, "tx_id", _g(tx, "id", "")))


def _tx_sender(tx):    return str(_g(tx, "sender", ""))


def _tx_receiver(tx):  return str(_g(tx, "receiver", ""))


def _tx_amount(tx):    return int(_g(tx, "amount", 0) or 0)


def _tx_nonce(tx):     return int(_g(tx, "nonce", 0) or 0)


def _tx_signature(tx): return str(_g(tx, "signature", "") or "")


def _decode_coinbase_data(cb):
    raw = _g(cb, "data", "") or ""
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception as e:
        raise RewardError(
            "coinbase data field is not valid JSON: {}".format(e))
