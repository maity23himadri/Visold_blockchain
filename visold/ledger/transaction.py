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
"""visold.ledger.transaction

Original section: SECTION 4: TRANSACTION

Defines: Transaction
Origin: visold_vsd_.py L11423-11907
"""

import hashlib
import json
import math
import re
import struct
import time
from typing import Optional, TYPE_CHECKING, Tuple

from visold.crypto.ecc import (
    ecdsa_verify,
    pub_from_hex,
    pub_to_address,
    sig_from_hex,
    sig_to_hex,
)
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.units import VSD_GLOBAL_MARKET, gas_fee_to_sat, to_satoshi
from visold.ledger.addressing import is_valid_protocol_address
from visold.rollup.batches import RollupSubmission
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, L2_WITHDRAW_ADDRESS
from visold.vm.naming import normalize_contract_name, validate_contract_name

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.wallet.wallet import Wallet


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4: TRANSACTION
# ─────────────────────────────────────────────────────────────────────────────
_MEV_HEX64 = re.compile(r"[0-9a-f]{64}")
_MEV_DECIMAL = re.compile(r"0|[1-9][0-9]{0,18}")
MEV_MAX_STEPS = 40


def parse_mev_commit_data(data) -> Optional[str]:
    """Return the commitment hash carried by ``data``, or None if it is not one."""
    prefix = Config.MEV_COMMIT_PREFIX
    if not isinstance(data, str) or not data.startswith(prefix):
        return None
    digest = data[len(prefix):]
    return digest if _MEV_HEX64.fullmatch(digest) else None


def encode_mev_steps(steps) -> str:
    """Encode a merkle path: L<sibling>, R<sibling>, or O for an odd loner."""
    return "".join("O" if kind == "O" else kind + sibling for kind, sibling in steps)


def _decode_mev_steps(text: str):
    steps = []
    i = 0
    while i < len(text):
        kind = text[i]
        if kind == "O":
            steps.append(("O", ""))
            i += 1
        elif kind in ("L", "R"):
            sibling = text[i + 1:i + 65]
            if not _MEV_HEX64.fullmatch(sibling):
                return None
            steps.append((kind, sibling))
            i += 65
        else:
            return None
        if len(steps) > MEV_MAX_STEPS:
            return None
    return steps


def parse_mev_reveal_data(data):
    """Return (salt, commitment height, merkle steps) carried by a reveal, or None."""
    prefix = Config.MEV_REVEAL_PREFIX
    if not isinstance(data, str) or not data.startswith(prefix):
        return None
    parts = data[len(prefix):].split(":", 2)
    if len(parts) != 3:
        return None
    salt, height_text, steps_text = parts
    if not _MEV_HEX64.fullmatch(salt) or not _MEV_DECIMAL.fullmatch(height_text):
        return None
    steps = _decode_mev_steps(steps_text)
    if steps is None:
        return None
    return salt, int(height_text), steps


class Transaction:
    VERSION = 1

    # Transaction types
    TYPE_TRANSFER = "transfer"   # Standard VSD coin transfer (legacy behaviour)
    TYPE_DEPLOY   = "deploy"     # Deploy a new VVM smart contract
    TYPE_CALL     = "call"       # Call an existing VVM smart contract
    # ── v7.2.0 ON-CHAIN ROLE REGISTRATION ─────────────────────────────────
    # Role changes (miner / investor registration + unstaking) used to be
    # local-only DB writes that bypassed the block pipeline entirely.  That
    # made the role table non-deterministic across nodes — see the v7.1.10
    # hotfix series.  In v7.2.0 these become real transactions that are
    # gossipped, included in a block, and only take effect at block N+1
    # after being mined into block N.
    #
    # Semantics of the REGISTER tx:
    #   sender   = address being registered (must match tx signer)
    #   receiver = "" (unused)
    #   amount   = stake in VSD (float, user-friendly; converted to sat)
    #   memo     = role: one of "miner", "investor", or "none" to unstake
    # The stake is NOT debited — it's a lock recorded in the role table.
    # The spendable-balance guard in send_transaction enforces that staked
    # funds cannot be spent while the role is active.
    TYPE_REGISTER = "register"   # on-chain role registration / unstake

    # Identity/domain claims deliberately reuse the already consensus-tested
    # TYPE_REGISTER transaction envelope. This avoids a new wire type, block
    # parser branch, or sync message. Identity claims are fee+nonce-only
    # transactions and never enter the role table.
    IDENTITY_MEMO_PREFIX = "identity:"

    @classmethod
    def identity_name_from_memo(cls, memo: str) -> Optional[str]:
        """Return the canonical name carried by an identity claim memo."""
        if not isinstance(memo, str):
            return None
        raw = memo.strip()
        prefix = cls.IDENTITY_MEMO_PREFIX
        if not raw.casefold().startswith(prefix):
            return None
        name = raw[len(prefix):].strip().casefold()
        if not (re.fullmatch(r"[a-z0-9_.\-]{3,32}", name)
                or re.fullmatch(r"[a-z0-9_]{3,32}#[0-9a-f]{10}", name)):
            return None
        if "#" not in name:
            if name[0] in ".-" or name[-1] in ".-":
                return None
            if ".." in name or "--" in name:
                return None
        return name

    @classmethod
    def is_identity_claim(cls, tx: 'Transaction') -> bool:
        return (getattr(tx, "tx_type", "") == cls.TYPE_REGISTER
                and cls.identity_name_from_memo(getattr(tx, "memo", ""))
                is not None)

    # ── v7.5.0-OPT L2 ROLLUP SETTLEMENT ───────────────────────────────────
    # Carries a RollupSubmission payload in the `data` field (JSON-encoded).
    # Processed by the verifier precompile and Layer2State at apply time.
    # See SECTION 7E for the full rollup architecture.
    TYPE_ROLLUP   = "rollup"

    def __init__(self, sender: str, receiver: str, amount: float,
                 fee: float = 0.0, timestamp: int = 0,
                 pub_hex: str = "", sig_hex: str = "",
                 tx_id: str = "", memo: str = "",
                 nonce: int = 0, expiry: int = 0,
                 # ── VVM extension fields ─────────────────────────────────────
                 tx_type: str = "",        # "transfer" | "deploy" | "call"
                 data: str = "",           # hex-encoded bytecode (deploy) or calldata (call)
                 gas_limit: int = 0,       # gas budget for VVM execution
                 gas_price: float = 0.0,   # VSD per gas unit
                 # SC-NAME-1: optional human-readable contract name (deploy only)
                 contract_name: str = "",
                 ):
        self.version   = self.VERSION
        self.sender    = sender
        self.receiver  = receiver
        self.amount    = round(amount, 8)
        self.fee       = round(fee, 8)
        self.timestamp = timestamp or int(time.time())
        self.pub_hex   = pub_hex
        self.sig_hex   = sig_hex
        self.memo      = memo[:128]
        # Nonce: monotonically increasing per sender (replay protection + ordering)
        self.nonce     = nonce
        # Expiry: Unix timestamp after which tx is invalid (0 = no expiry, use default)
        if expiry == 0 and sender != "COINBASE":
            self.expiry = self.timestamp + Config.TX_DEFAULT_EXPIRY_SECS
        else:
            self.expiry = expiry
        # VVM fields — default to "transfer" type for backwards compatibility
        self.tx_type   = tx_type or self.TYPE_TRANSFER
        self.data      = data          # hex string, may be ""
        self.gas_limit = max(0, int(gas_limit))
        self.gas_price = max(0.0, float(gas_price))
        # SC-NAME-1: normalise at the boundary so every downstream path sees
        # the canonical form.  Empty string = unnamed / non-deploy tx.
        self.contract_name = normalize_contract_name(contract_name)
        if tx_id:
            self.tx_id = tx_id
        else:
            # Keep object construction permissive enough for validation tests
            # and network error handling: malformed non-finite numeric inputs
            # must be rejected by is_valid(), not crash object construction.
            try:
                self.tx_id = self._compute_id()
            except (TypeError, ValueError, OverflowError):
                self.tx_id = ""

    @staticmethod
    def _encode_v2_fields(fields: Tuple[Tuple[str, str], ...]) -> bytes:
        """Return an unambiguous, domain-separated transaction preimage.

        Every field carries its name and an explicit byte length.  Numeric
        consensus values are already canonicalized by the caller (satoshi
        amounts, satoshi-per-gas, and integer sequence/timestamp values), so
        there is no possibility for field-boundary ambiguity such as
        ``memo=""/nonce=123`` colliding with ``memo="1"/nonce=23``.
        """
        out = bytearray(b"VSD-TX-V2\x00")
        for name, value in fields:
            name_b = name.encode("utf-8")
            value_b = value.encode("utf-8")
            item = (struct.pack(">I", len(name_b)) + name_b +
                    struct.pack(">I", len(value_b)) + value_b)
            out.extend(struct.pack(">I", len(item)))
            out.extend(item)
        return bytes(out)

    def _canonical_fields(self) -> Tuple[Tuple[str, str], ...]:
        """Return the V2 transaction fields in protocol-defined form."""
        def _sat_text(value) -> str:
            try:
                return str(to_satoshi(value))
            except (TypeError, ValueError, OverflowError):
                # Non-finite values are invalid transactions, but keeping a
                # deterministic textual preimage lets callers construct/sign
                # a malformed object so validation can report the actual error.
                return f"invalid:{str(value).lower()}"

        def _int_text(value) -> str:
            try:
                return str(int(value))
            except (TypeError, ValueError, OverflowError):
                return f"invalid:{str(value).lower()}"

        gas_price_sat = _sat_text(self.gas_price)
        return (
            ("chain_id", str(Config.CHAIN_ID)),
            ("version", _int_text(self.version)),
            ("sender", str(self.sender)),
            ("receiver", str(self.receiver)),
            ("amount_sat", _sat_text(self.amount)),
            ("fee_sat", _sat_text(self.fee)),
            ("timestamp", _int_text(self.timestamp)),
            ("memo", str(self.memo)),
            ("nonce", _int_text(self.nonce)),
            ("expiry", _int_text(self.expiry)),
            ("tx_type", str(self.tx_type)),
            ("data_hash", sha256(self.data.encode()) if self.data else ""),
            ("gas_limit", _int_text(self.gas_limit)),
            ("gas_price_sat", gas_price_sat),
            ("contract_name", str(self.contract_name)),
        )

    def _compute_legacy_id(self, block_height: int = -1) -> str:
        """Compute the exact pre-canonical tx_id for historical blocks."""
        v3_activation = int(getattr(
            Config, "TXID_CANONICAL_V3_ACTIVATION_HEIGHT", 0))
        legacy_allowed = bool(getattr(Config, "TXID_CANONICAL_V2_LEGACY_ENABLED", False))
        if not (legacy_allowed and v3_activation > 0 and block_height >= 0
                and block_height < v3_activation):
            return ""

        # Reproduce the archive's previous rule exactly.  Before the old TXID
        # V2 activation it hashed data[:64]; at/after that activation it hashed
        # the full data field.  In both cases the surrounding fields were
        # concatenated without boundaries.
        old_activation = int(getattr(Config, "TXID_V2_ACTIVATION_HEIGHT", 0))
        old_v1_allowed = bool(getattr(Config, "TXID_V1_LEGACY_ENABLED", False))
        if (old_v1_allowed and old_activation > 0 and
                block_height < old_activation):
            data_component = self.data[:64]
        else:
            data_component = sha256(self.data.encode()) if self.data else ""
        core = (f"{self.sender}{self.receiver}{self.amount}{self.fee}"
                f"{self.timestamp}{self.memo}{self.nonce}{self.expiry}"
                f"{self.tx_type}{data_component}{self.gas_limit}{self.gas_price}"
                f"{self.contract_name}")
        return sha256(core.encode())

    def _compute_id(self, block_height: int = -1) -> str:
        """Compute the canonical length-delimited transaction id.

        ``block_height`` is retained for API compatibility.  Canonical txids
        are always produced for newly-created transactions; historical pre-v3
        txids are recognized explicitly by block-integrity code rather than by
        silently generating an unsafe id for ordinary transactions.
        """
        del block_height
        return sha256(self._encode_v2_fields(self._canonical_fields()))

    def _legacy_signing_bytes(self) -> bytes:
        """Return the pre-canonical signing payload for historical replay only."""
        data_hash = sha256(self.data.encode()) if self.data else ""
        d = (f"{Config.CHAIN_ID}{self.version}{self.sender}{self.receiver}{self.amount}"
             f"{self.fee}{self.timestamp}{self.memo}{self.nonce}{self.expiry}"
             f"{self.tx_type}{self.gas_limit}{self.gas_price}{data_hash}"
             f"{self.contract_name}")
        return d.encode()

    def signing_bytes(self, block_height: int = -1) -> bytes:
        """Return the canonical V2 transaction signing payload.

        A legacy payload is only considered by ``verify_signature`` when an
        already-mined historical block explicitly falls below the configured
        canonical V3 activation height.  New transactions are never signed
        with the ambiguous legacy format.
        """
        del block_height
        return self._encode_v2_fields(self._canonical_fields())

    def sign(self, wallet: 'Wallet'):
        sig = wallet.sign(self.signing_bytes())
        self.sig_hex = sig_to_hex(sig)
        self.pub_hex = wallet.pub_hex
        self.tx_id   = self._compute_id()

    def verify_signature(self, block_height: int = -1) -> bool:
        if self.sender == "COINBASE":
            return True
        try:
            pub = pub_from_hex(self.pub_hex)
            # SENDER-BINDING FIX: an ECDSA signature only proves that the signer
            # holds the private key behind pub_hex.  It does not prove that this
            # key OWNS `sender`.
            if pub_to_address(pub) != self.sender:
                return False
            sig = sig_from_hex(self.sig_hex)

            # New protocol: canonical, length-delimited V2 payload only.
            h = hashlib.sha256(self.signing_bytes()).digest()
            if ecdsa_verify(pub, h, sig):
                return True

            # Historical compatibility: a legacy signature may be accepted only
            # when the containing block is explicitly before the configured
            # canonical V3 activation height. Fresh chains never enter this path.
            activation = int(getattr(
                Config, "TXID_CANONICAL_V3_ACTIVATION_HEIGHT", 0))
            legacy_allowed = bool(getattr(
                Config, "TXID_CANONICAL_V2_LEGACY_ENABLED", False))
            if (legacy_allowed and activation > 0 and block_height >= 0
                    and block_height < activation):
                legacy_h = hashlib.sha256(self._legacy_signing_bytes()).digest()
                return ecdsa_verify(pub, legacy_h, sig)
            return False
        except Exception:
            return False

    def is_expired(self, reference_time: Optional[float] = None) -> bool:
        """Return whether the transaction expired at the supplied validation time.

        New/mempool validation defaults to the local wall clock.  Block
        validation supplies the containing block timestamp so historical
        replay remains deterministic: a transaction valid when mined must not
        become invalid merely because a node syncs the block later.
        """
        if self.sender == "COINBASE" or self.expiry == 0:
            return False
        now = int(time.time()) if reference_time is None else int(reference_time)
        return now > self.expiry

    def is_valid(self, reference_time: Optional[float] = None,
                 block_height: int = -1,
                 signature_already_verified: bool = False) -> Tuple[bool, str]:
        """Validate transaction consensus fields.

        ``signature_already_verified`` is a narrowly-scoped block-validation
        optimization.  It may only be set by ``Blockchain.validate_block``
        after ``Block.integrity_check`` has cryptographically verified this
        exact transaction (or established the same fact from the mempool's
        verified set after tx_id integrity was checked).  Normal callers keep
        the default ``False`` so signature verification remains mandatory.
        """
        # JSON/Python permit non-finite IEEE-754 values such as NaN and inf.
        # They must never enter consensus arithmetic because comparisons with
        # NaN are false and can therefore bypass ordinary range checks.
        for _field, _value in (("amount", self.amount),
                               ("fee", self.fee),
                               ("gas_price", self.gas_price)):
            try:
                if not math.isfinite(float(_value)):
                    return False, f"{_field} must be finite"
            except (TypeError, ValueError, OverflowError):
                return False, f"{_field} must be a finite number"

        # BUG-8: finite is not sufficient.  Conversion to satoshi must also
        # fit the signed 64-bit storage/consensus domain; otherwise a finite
        # Python float such as 1e301 raises in to_satoshi() later.
        _MAX_CONSENSUS_SAT = 2**63 - 1
        for _field, _value in (("amount", self.amount), ("fee", self.fee),
                               ("gas_price", self.gas_price)):
            try:
                _scaled = float(_value) * Config.SATOSHI_PER_VSD
                if not math.isfinite(_scaled) or abs(_scaled) > _MAX_CONSENSUS_SAT:
                    return False, f"{_field} exceeds consensus numeric range"
            except (TypeError, ValueError, OverflowError):
                return False, f"{_field} exceeds consensus numeric range"

        # Transaction type is consensus data.  Unknown values must fail closed;
        # otherwise an unsupported future type would silently fall through into
        # the legacy transfer validator and execute with the wrong semantics.
        if not isinstance(self.tx_type, str):
            return False, "Transaction type must be a string"
        _known_types = {
            self.TYPE_TRANSFER, self.TYPE_DEPLOY, self.TYPE_CALL,
            self.TYPE_REGISTER, self.TYPE_ROLLUP,
        }
        if self.tx_type not in _known_types:
            return False, f"Unknown transaction type: {self.tx_type!r}"

        # ── VVM transaction types — special validation ─────────────────────────
        if self.tx_type == self.TYPE_DEPLOY:
            if self.sender == "COINBASE":
                return False, "COINBASE cannot deploy contracts"
            if not self.data:
                return False, "Deploy transaction requires bytecode in 'data' field"
            try:
                raw = bytes.fromhex(self.data)
            except ValueError:
                return False, "Deploy 'data' field is not valid hex"
            if len(raw) > Config.VVM_MAX_BYTECODE_SIZE:
                return False, (f"Bytecode too large: {len(raw)} bytes "
                               f"(max {Config.VVM_MAX_BYTECODE_SIZE})")
            if self.gas_limit <= 0:
                return False, "Deploy transaction requires gas_limit > 0"
            if self.gas_price < Config.VVM_MIN_GAS_PRICE:
                return False, (f"gas_price {self.gas_price} below minimum "
                               f"{Config.VVM_MIN_GAS_PRICE}")
            if self.gas_limit > Config.VVM_TX_GAS_CAP:
                return False, (f"gas_limit {self.gas_limit} exceeds cap "
                               f"{Config.VVM_TX_GAS_CAP}")
            try:
                if gas_fee_to_sat(self.gas_limit, self.gas_price) > _MAX_CONSENSUS_SAT:
                    return False, "Deploy gas fee exceeds consensus numeric range"
            except (TypeError, ValueError, OverflowError):
                return False, "Deploy gas fee exceeds consensus numeric range"
            # AUDIT-FIX-10 (unauthorized minting): TYPE_DEPLOY was missing the
            # negative-amount check TYPE_CALL already has below. Without it,
            # a DEPLOY tx with amount < 0 passed validation, and downstream
            # Storage.debit_sat(sender, amount_sat + gas_fee_sat) with a
            # negative total effectively CREDITED the sender instead of
            # debiting them -- unlimited, unauthenticated minting from any
            # address, including a brand-new zero-balance one. See also the
            # AUDIT-FIX-10 guards added directly to debit_sat/credit_sat
            # themselves (defense in depth, not solely reliant on this
            # front-line check).
            if self.amount < 0:
                return False, "Deploy call value cannot be negative"
            # BUG-FIX: TYPE_DEPLOY was missing the expiry check that TYPE_CALL
            # already had.  Without this, expired deploy transactions could
            # remain valid in the mempool indefinitely.
            if self.is_expired(reference_time):
                return False, f"Transaction expired at {self.expiry}"
            if not self.pub_hex or not self.sig_hex:
                return False, "Missing signature or pubkey"
            if not signature_already_verified and not self.verify_signature(block_height=block_height):
                return False, "Invalid signature"
            # SC-NAME-1: validate contract_name when a name is supplied.
            # Empty name = "unnamed" and is always valid for backward compat.
            # Consensus (_apply_vvm_tx) re-validates with block height guard.
            if self.contract_name:
                ok_name, reason_name = validate_contract_name(self.contract_name)
                if not ok_name:
                    return False, f"Invalid contract_name: {reason_name}"
            return True, "OK"

        if self.tx_type == self.TYPE_CALL:
            if self.sender == "COINBASE":
                return False, "COINBASE cannot call contracts"
            if not self.receiver or not self.receiver.startswith("VSDc"):
                return False, "Call transaction receiver must be a contract address (VSDc...)"
            # data may be empty (fallback receive function)
            if self.data:
                try:
                    bytes.fromhex(self.data)
                except ValueError:
                    return False, "Call 'data' field is not valid hex"
            if self.gas_limit <= 0:
                return False, "Call transaction requires gas_limit > 0"
            if self.gas_price < Config.VVM_MIN_GAS_PRICE:
                return False, (f"gas_price {self.gas_price} below minimum "
                               f"{Config.VVM_MIN_GAS_PRICE}")
            if self.gas_limit > Config.VVM_TX_GAS_CAP:
                return False, (f"gas_limit {self.gas_limit} exceeds cap "
                               f"{Config.VVM_TX_GAS_CAP}")
            try:
                if gas_fee_to_sat(self.gas_limit, self.gas_price) > _MAX_CONSENSUS_SAT:
                    return False, "Call gas fee exceeds consensus numeric range"
            except (TypeError, ValueError, OverflowError):
                return False, "Call gas fee exceeds consensus numeric range"
            if self.amount < 0:
                return False, "Call value cannot be negative"
            if self.is_expired(reference_time):
                return False, f"Transaction expired at {self.expiry}"
            if not self.pub_hex or not self.sig_hex:
                return False, "Missing signature or pubkey"
            if not signature_already_verified and not self.verify_signature(block_height=block_height):
                return False, "Invalid signature"
            return True, "OK"

        # ── v7.5.0-OPT TYPE_ROLLUP validation ─────────────────────────────
        # The on-chain L2 settlement tx.  amount=0 and fee=0 are REQUIRED;
        # the real economic cost is paid via block inclusion + the
        # verifier precompile's gas charge at apply time.  The heavy
        # validation (proof check, prev_root match, batch re-execution)
        # happens in Blockchain._apply_rollup_tx — here we just gate on
        # shape and signature so a malformed submission never sits in
        # the mempool.
        if self.tx_type == self.TYPE_ROLLUP:
            if self.sender == "COINBASE":
                return False, "COINBASE cannot submit rollups"
            if self.receiver != L2_BRIDGE_ADDRESS:
                return False, (f"TYPE_ROLLUP receiver must be "
                               f"L2_BRIDGE_ADDRESS, got {self.receiver[:16]}")
            if to_satoshi(self.amount) != 0:
                return False, "TYPE_ROLLUP amount must be 0"
            if to_satoshi(self.fee) != 0:
                return False, "TYPE_ROLLUP fee must be 0"
            if not self.data:
                return False, "TYPE_ROLLUP missing data payload"
            if len(self.data) > 2 * RollupSubmission.MAX_COMPRESSED_BYTES + 4096:
                # Sanity-check the JSON envelope size — a legitimate
                # submission fits inside 2*MAX_COMPRESSED_BYTES (hex
                # encoding doubles binary size) plus a modest JSON overhead.
                return False, "TYPE_ROLLUP data too large"
            if self.is_expired(reference_time):
                return False, f"Transaction expired at {self.expiry}"
            if not self.pub_hex or not self.sig_hex:
                return False, "Missing signature or pubkey"
            if not signature_already_verified and not self.verify_signature(block_height=block_height):
                return False, "Invalid signature"
            # Cheap JSON structural parse — deeper checks at apply time.
            try:
                sub = RollupSubmission.from_json(self.data)
            except Exception as e:
                return False, f"TYPE_ROLLUP payload parse failed: {e}"
            ok_s, msg_s = sub.structural_ok()
            if not ok_s:
                return False, f"TYPE_ROLLUP structural: {msg_s}"
            return True, "OK"

        # ── Canonical identity-claim validation ─────────────────────────────
        # Identity claims are signed, zero-value TYPE_REGISTER transactions.
        # They pay the absolute minimum fee and are committed to canonical
        # block order by Storage.save_block().
        if self.tx_type == self.TYPE_REGISTER and self.is_identity_claim(self):
            if self.sender == "COINBASE":
                return False, "COINBASE cannot claim an identity"
            if self.receiver:
                return False, "Identity claim receiver must be empty"
            if to_satoshi(self.amount) != 0:
                return False, "Identity claim amount must be zero"
            if to_satoshi(self.fee) != int(getattr(Config, "MIN_TX_FEE_SAT", 1000)):
                return False, "Identity claim fee must equal MIN_TX_FEE_SAT"
            if self.is_expired(reference_time):
                return False, f"Transaction expired at {self.expiry}"
            if not self.pub_hex or not self.sig_hex:
                return False, "Missing signature or pubkey"
            if not signature_already_verified and not self.verify_signature(block_height=block_height):
                return False, "Invalid signature"
            return True, "OK"

        # ── Role unstake validation ────────────────────────────────────────────
        # RoleManager.unstake() uses the existing TYPE_REGISTER envelope with
        # memo="none" and amount=0. This is a signed role transition, not a
        # value transfer, and must bypass the standard positive-amount rule
        # while still paying the absolute minimum transaction fee.
        if (self.tx_type == self.TYPE_REGISTER and
                str(self.memo or "").strip().lower() == "none"):
            if self.sender == "COINBASE":
                return False, "COINBASE cannot unstake a role"
            if self.receiver:
                return False, "Role unstake receiver must be empty"
            if to_satoshi(self.amount) != 0:
                return False, "Role unstake amount must be zero"
            if to_satoshi(self.fee) != int(getattr(Config, "MIN_TX_FEE_SAT", 1000)):
                return False, "Role unstake fee must equal MIN_TX_FEE_SAT"
            if self.is_expired(reference_time):
                return False, f"Transaction expired at {self.expiry}"
            if not self.pub_hex or not self.sig_hex:
                return False, "Missing signature or pubkey"
            if not signature_already_verified and not self.verify_signature(block_height=block_height):
                return False, "Invalid signature"
            return True, "OK"

        # BUG-3/4: every remaining REGISTER transaction must be an explicit
        # role registration. Malformed identity claims and unknown role memos
        # must fail closed instead of reaching apply-time fallback-to-unstake.
        if self.tx_type == self.TYPE_REGISTER:
            _memo = str(self.memo or "").strip().lower()
            if _memo.startswith(self.IDENTITY_MEMO_PREFIX):
                return False, "Malformed identity claim memo"
            if _memo not in ("miner", "investor"):
                return False, ("REGISTER memo must be miner, investor, none, "
                               "or a valid identity claim")
            if self.receiver:
                return False, "Role registration receiver must be empty"

        # ── Standard transfer validation (unchanged) ───────────────────────────
        # ── MEV protection: formats of the commitment and the reveal ──────────
        # Chain rules (commitment on-chain, age, merkle path) are checked by
        # visold/mempool/mev.py in block validation and mempool admission.
        if self.tx_type == self.TYPE_TRANSFER and str(self.data).startswith(Config.MEV_COMMIT_PREFIX):
            if self.sender == "COINBASE":
                return False, "COINBASE cannot submit an MEV commitment"
            if self.receiver != self.sender:
                return False, "MEV commitment must be a self-transfer"
            if to_satoshi(self.amount) != 0:
                return False, "MEV commitment amount must be zero"
            if self.memo:
                return False, "MEV commitment memo must be empty"
            if to_satoshi(self.fee) != int(getattr(Config, "MIN_TX_FEE_SAT", 1000)):
                return False, "MEV commitment fee must equal MIN_TX_FEE_SAT"
            if parse_mev_commit_data(self.data) is None:
                return False, "MEV commitment data is malformed"
            if self.is_expired(reference_time):
                return False, f"Transaction expired at {self.expiry}"
            if not self.pub_hex or not self.sig_hex:
                return False, "Missing signature or pubkey"
            if not signature_already_verified and not self.verify_signature(block_height=block_height):
                return False, "Invalid signature"
            return True, "OK"
        if self.tx_type == self.TYPE_TRANSFER and str(self.data).startswith(Config.MEV_REVEAL_PREFIX):
            if parse_mev_reveal_data(self.data) is None:
                return False, "MEV reveal data is malformed"
        if self.amount <= 0:
            return False, "Amount must be positive"
        # BUG-FIX: a negative fee was never rejected here.  A crafted tx with
        # fee=-1.0 would pass is_valid() and could distort reward accounting
        # (fee_pool goes negative, conservation invariant violated).
        if self.fee < 0:
            return False, "Fee cannot be negative"
        if self.sender == self.receiver and self.sender != "COINBASE":
            return False, "Cannot send to self"
        # Expiry check; historical block validation passes the block time.
        if self.is_expired(reference_time):
            return False, f"Transaction expired at {self.expiry}"
        # Receiver shape is consensus data.  Reject malformed destinations
        # before signature acceptance so funds cannot be committed to an
        # address string that no wallet/contract can ever control.
        if (self.tx_type == self.TYPE_TRANSFER
                and self.sender != "COINBASE"
                and not is_valid_protocol_address(
                    self.receiver,
                    specials=(VSD_GLOBAL_MARKET, Config.BURN_ADDRESS,
                              L2_BRIDGE_ADDRESS, L2_WITHDRAW_ADDRESS),
                    allow_contract=True)):
            return False, "Invalid transfer receiver address"

        # VSD_GLOBAL_MARKET is a valid broadcast receiver
        if self.receiver == VSD_GLOBAL_MARKET and self.sender != "COINBASE":
            if not self.pub_hex or not self.sig_hex:
                return False, "Missing signature or pubkey"
            if not signature_already_verified and not self.verify_signature(block_height=block_height):
                return False, "Invalid signature"
            return True, "OK"
        if self.sender != "COINBASE":
            if not self.pub_hex or not self.sig_hex:
                return False, "Missing signature or pubkey"
            if not signature_already_verified and not self.verify_signature(block_height=block_height):
                return False, "Invalid signature"
        return True, "OK"

    def mev_commitment(self, salt_hex: str) -> str:
        """Salted commitment to this transfer, used by MEV commit-reveal.

        Covers every field except ``data`` (which carries the commitment) and the
        signature, so it can be computed before the transfer is signed.
        """
        core = json.dumps([self.sender, self.receiver, to_satoshi(self.amount),
                           to_satoshi(self.fee), self.memo, int(self.nonce),
                           int(self.timestamp), self.tx_type],
                          separators=(",", ":"), ensure_ascii=True)
        return sha256(b"visold-mev-commit-v1|" + core.encode("utf-8")
                      + b"|" + salt_hex.encode("utf-8"))

    def compute_fee(self) -> float:
        return round(self.amount * Config.TX_FEE_RATE, 8)

    def compute_fee_sat(self) -> int:
        """Fee in satoshi — deterministic integer arithmetic (F-01 COMPLETION).

        Convert amount to satoshi first, then apply fee rate as integer math:
          fee_sat = amount_sat * TX_FEE_RATE_BPS // 10000
        where TX_FEE_RATE is 0.01 = 100 basis points.
        This avoids float multiplication of (amount * rate) which can diverge.
        """
        if self.tx_type == self.TYPE_TRANSFER and str(self.data).startswith(Config.MEV_COMMIT_PREFIX):
            # MEV commitments pay a fixed fee: their amount is zero.
            return int(getattr(Config, "MIN_TX_FEE_SAT", 1000))
        if self.tx_type == self.TYPE_REGISTER and self.is_identity_claim(self):
            return int(getattr(Config, "MIN_TX_FEE_SAT", 1000))
        if (self.tx_type == self.TYPE_REGISTER and
                str(self.memo or "").strip().lower() == "none"):
            return int(getattr(Config, "MIN_TX_FEE_SAT", 1000))
        amount_sat = to_satoshi(self.amount)
        # TX_FEE_RATE = 0.01 → 100 basis points out of 10000
        fee_rate_bps = int(round(Config.TX_FEE_RATE * 10000))
        return amount_sat * fee_rate_bps // 10000

    def to_dict(self) -> dict:
        return {
            "version":   self.version,
            "tx_id":     self.tx_id,
            "sender":    self.sender,
            "receiver":  self.receiver,
            "amount":    self.amount,
            "fee":       self.fee,
            "timestamp": self.timestamp,
            "pub_hex":   self.pub_hex,
            "sig_hex":   self.sig_hex,
            "memo":      self.memo,
            "nonce":     self.nonce,
            "expiry":    self.expiry,
            # VVM fields — always serialized for protocol consistency
            "tx_type":   self.tx_type,
            "data":      self.data,
            "gas_limit": self.gas_limit,
            "gas_price": self.gas_price,
            # SC-NAME-1: contract name (empty string for non-deploy / unnamed)
            "contract_name": self.contract_name,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'Transaction':
        return cls(
            sender    = d["sender"],
            receiver  = d["receiver"],
            amount    = d["amount"],
            fee       = d.get("fee", 0.0),
            timestamp = d.get("timestamp", 0),
            pub_hex   = d.get("pub_hex", ""),
            sig_hex   = d.get("sig_hex", ""),
            tx_id     = d.get("tx_id", ""),
            memo      = d.get("memo", ""),
            nonce     = d.get("nonce", 0),
            expiry    = d.get("expiry", 0),
            # VVM fields — default to legacy "transfer" when absent (backwards compat)
            tx_type   = d.get("tx_type", cls.TYPE_TRANSFER),
            data      = d.get("data", ""),
            gas_limit = d.get("gas_limit", 0),
            gas_price = d.get("gas_price", 0.0),
            # SC-NAME-1: default "" keeps old serialised txs valid
            contract_name = d.get("contract_name", ""),
        )

    @classmethod
    def coinbase(cls, receiver: str, amount: float, block_height: int,
                 bootstrap_snapshot: Optional[Tuple[int, str]] = None) -> 'Transaction':
        """Create the canonical coinbase transaction.

        ``bootstrap_snapshot`` is the consensus-authenticated pruning-bootstrap
        commitment introduced in v7.6.1.  When present it is ``(height,
        sha256_hex)`` for the complete deterministic state snapshot at that
        height.  The commitment lives inside the coinbase memo, therefore the
        existing transaction-id -> Merkle-root -> block-hash chain authenticates
        it without changing the block header format or GPU mining preimage.
        """
        memo = f"coinbase:{block_height}"
        if bootstrap_snapshot is not None:
            snap_h, digest = bootstrap_snapshot
            snap_h = int(snap_h)
            digest = str(digest).lower()
            if snap_h < 0 or len(digest) != 64:
                raise ValueError("invalid bootstrap snapshot commitment")
            try:
                int(digest, 16)
            except ValueError as exc:
                raise ValueError("bootstrap snapshot digest must be hex") from exc
            memo += f"|{Config.BOOTSTRAP_COMMITMENT_TAG}:{snap_h}:{digest}"
        return cls(
            sender   = "COINBASE",
            receiver = receiver,
            amount   = amount,
            memo     = memo,
            nonce    = 0,
            expiry   = 0,
        )

    @classmethod
    def parse_bootstrap_commitment(cls, memo: str) -> Optional[Tuple[int, str]]:
        """Return ``(snapshot_height, digest)`` from a coinbase memo.

        Malformed or non-canonical encodings return ``None``.  Consensus code
        separately decides whether a commitment is mandatory at a given block
        height.
        """
        if not isinstance(memo, str):
            return None
        marker = f"|{Config.BOOTSTRAP_COMMITMENT_TAG}:"
        if marker not in memo:
            return None
        prefix, suffix = memo.split(marker, 1)
        if not prefix.startswith("coinbase:"):
            return None
        parts = suffix.split(":")
        if len(parts) != 2:
            return None
        try:
            height = int(parts[0])
        except (TypeError, ValueError):
            return None
        digest = parts[1].lower()
        if height < 0 or len(digest) != 64:
            return None
        try:
            int(digest, 16)
        except ValueError:
            return None
        return height, digest
