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
"""visold.vm.frame


Defines: VVMResult
Origin: visold_vsd_.py L19690-19720, L19723-20056, L20060-20092
"""

import hashlib
from typing import Dict, List, Optional, TYPE_CHECKING, Tuple

from visold.crypto.base58 import b58decode, b58encode
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.vm.opcodes import (
    _SSTORE_CLEAR_GAS,
    _SSTORE_REFUND,
    _SSTORE_RESET_GAS,
    _SSTORE_SET_GAS,
    _mem_expansion_cost,
)

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# ── Execution result ──────────────────────────────────────────────────────────
class VVMResult:
    """Immutable result object returned from VVMEngine.deploy() / .call()."""
    __slots__ = ("success", "gas_used", "return_data", "revert_reason",
                 "contract_addr", "logs", "storage_writes", "storage_orig",
                 "touched_contracts", "self_destruct_transfers",
                 "pending_deployments", "storage_tags", "storage_tag_orig",
                 "balance_deltas", "create_nonce_deltas",
                 "state_channel_journal")

    def __init__(self, *, success: bool, gas_used: int,
                 return_data: bytes = b"",
                 revert_reason: str = "",
                 contract_addr: str = "",
                 logs: Optional[list] = None,
                 storage_writes: Optional[dict] = None,
                 storage_orig: Optional[dict] = None,
                 touched_contracts: Optional[set] = None,
                 self_destruct_transfers: Optional[list] = None,
                 pending_deployments: Optional[list] = None,
                 storage_tags: Optional[dict] = None,
                 storage_tag_orig: Optional[dict] = None,
                 balance_deltas: Optional[dict] = None,
                 create_nonce_deltas: Optional[dict] = None,
                 state_channel_journal: Optional[dict] = None):
        self.success                 = success
        self.gas_used                = gas_used
        self.return_data             = return_data
        self.revert_reason           = revert_reason
        self.contract_addr           = contract_addr
        self.logs                    = logs or []
        self.storage_writes          = storage_writes or {}
        self.storage_orig            = storage_orig or {}
        self.touched_contracts       = touched_contracts or set()
        self.self_destruct_transfers = self_destruct_transfers or []
        # SC-V73-FIX-2: deferred contract deployments (CREATE/CREATE2).
        # Flushed to storage by _apply_vvm_tx only on top-level success.
        # Discarded on any revert path — prevents ghost contracts.
        self.pending_deployments     = pending_deployments or []
        self.storage_tags            = storage_tags or {}
        self.storage_tag_orig        = storage_tag_orig or {}
        self.balance_deltas          = balance_deltas or {}
        self.create_nonce_deltas     = create_nonce_deltas or {}
        # Direct state-channel/account mutations are journaled separately from
        # the VM frame's buffered contract-storage writes.  On top-level success
        # this is persisted as rollback metadata; on execution failure the VM
        # engine restores it before returning.
        self.state_channel_journal  = state_channel_journal


# ── VVM Execution Frame ───────────────────────────────────────────────────────
class _VMFrame:
    """
    A single activation frame on the VVM call stack.

    Holds all mutable per-call state: stack, memory, pc, gas counter, and
    a write-set for storage changes (not committed until execution succeeds).
    Each internal CALL/CREATE spawns a child _VMFrame; child writes are merged
    into the parent only on success.
    """
    UINT256_MAX = (1 << 256) - 1
    INT256_MAX  = (1 << 255) - 1
    INT256_MIN  = -(1 << 255)

    def __init__(self, *, code: bytes, calldata: bytes,
                 caller: str, address: str, origin: str,
                 call_value: int, gas_limit: int,
                 storage_ref: 'Storage',
                 is_static: bool = False,
                 depth: int = 0,
                 gas_price: int = 0,
                 block_ctx=None,
                 return_buffer: bytes = b"",
                 reentrance_guard: Optional['_ReentrancyGuard'] = None):
        self.code           = code
        self.calldata       = calldata
        self.caller         = caller
        self.address        = address   # address of THIS contract being executed
        self.origin         = origin    # original EOA sender of the top-level tx
        self.call_value     = call_value
        self.gas_remaining  = gas_limit
        self.gas_limit      = gas_limit
        self.storage        = storage_ref
        self.is_static      = is_static
        self.depth          = depth
        self.gas_price_wei  = gas_price
        self.block_ctx      = block_ctx
        self.return_buffer  = return_buffer  # return data from last sub-call
        # SC-FIX-1: reentrancy guard — shared across all frames in one execution
        self.reentrance_guard = reentrance_guard

        self.stack: List[int]   = []
        self.memory: bytearray  = bytearray()
        self._mem_words: int    = 0   # cached word count for O(1) gas calc
        self.pc: int            = 0
        self.stopped: bool      = False
        self.reverted: bool     = False
        self.output: bytes      = b""

        # Per-frame write buffer: (contract_addr, slot_key_hex) → new_value
        # Committed to storage only if frame succeeds.
        self.storage_writes: Dict[Tuple[str,str], int] = {}
        # Original slot values captured on first SLOAD/SSTORE (for gas tiers + rollback)
        self.storage_orig:   Dict[Tuple[str,str], int] = {}
        # Gas refund accumulator
        self.gas_refund: int = 0
        # Emitted log entries
        self.logs: list = []
        # Contracts touched (for storage_root update)
        self.touched_contracts: set = set()
        # SELFDESTRUCT transfers.  Each entry is
        #   (source_contract, beneficiary, amount_sat)
        # so the block processor can reverse the exact balance movement during
        # a consensus rollback.  Keeping the source here is important: the
        # beneficiary alone is insufficient to restore a destroyed contract's
        # pre-block balance.
        self.self_destruct_transfers: list = []
        # SC-V73-FIX-2: deferred CREATE/CREATE2 deployments.
        # Each entry: {"address": str, "code_hash": str, "code_bytes": bytes,
        #              "creator": str, "created_at": int, "contract_name": str}
        # Merged into parent on success; discarded on revert.
        self.pending_deployments: list = []

        # ── VVM Register File ─────────────────────────────────────────────
        # 8 general-purpose 256-bit registers (R0–R7), all zeroed at frame
        # creation.  Registers are frame-local: child frames start with a
        # fresh zeroed register file and never share registers with the
        # parent.  The parent's registers are untouched by any child call.
        self.registers: List[int] = [0] * 8

        # ── VVM Typed Value System ────────────────────────────────────────
        # _stack_tags is a parallel list to self.stack — always the same
        # length.  Each entry is an integer type tag (0–4):
        #   0 = VTYPE_UINT    (default for all arithmetic results)
        #   1 = VTYPE_ADDRESS (produced by ADDRESS, CALLER, ORIGIN, …)
        #   2 = VTYPE_BOOL    (produced by LT, GT, EQ, ISZERO, …)
        #   3 = VTYPE_SATOSHI (produced by BALANCE, SELFBALANCE, …)
        #   4 = VTYPE_HASH    (produced by SHA3, EXTCODEHASH, BLOCKHASH)
        # Invariant: len(_stack_tags) == len(stack) at all times.
        # The push/pop helpers maintain this invariant automatically.
        self._stack_tags: List[int] = []

        # Type-tagged storage: (contract_addr, slot_hex) → tag (int 0–4)
        # Persisted alongside storage_writes; consulted by TYPEDLOAD.
        # Staged type-tag writes for persistent storage.  The execution
        # overlay keeps explicit zero entries too, so an SSTORE that clears a
        # prior tag shadows that tag within the current execution.  Backends
        # omit tag-0 rows because zero is the canonical implicit default.
        self._storage_tags: Dict[Tuple[str, str], int] = {}
        # Original persisted tags captured on first write, for transaction and
        # block rollback.  ``None`` means the tag row did not exist.
        self._storage_tag_orig: Dict[Tuple[str, str], Optional[int]] = {}

        # Balance deltas are an execution-local overlay used by nested
        # CALL/CREATE value transfers.  They are never written directly by
        # the VM; the top-level transaction applies the final deltas only
        # after the whole VM execution succeeds.
        self.balance_deltas: Dict[str, int] = {}
        # Execution-local CREATE sequence counters.  CREATE addresses must be
        # unique when the same opcode site executes repeatedly in one parent
        # transaction.  The counter is discarded on transaction revert.
        self.create_nonce_deltas: Dict[str, int] = {}

    # ── Stack helpers ─────────────────────────────────────────────────────────
    def push(self, value: int, tag: int = 0):
        """Push value onto stack with optional type tag (default VTYPE_UINT=0)."""
        if len(self.stack) >= Config.VVM_MAX_STACK_DEPTH:
            raise RuntimeError("Stack overflow")
        self.stack.append(value & self.UINT256_MAX)
        self._stack_tags.append(tag & 0x07)

    def pop(self) -> int:
        """Pop value from stack (discards type tag)."""
        if not self.stack:
            raise RuntimeError("Stack underflow")
        self._stack_tags.pop()
        return self.stack.pop()

    def pop_typed(self) -> tuple:
        """Pop value and its type tag as (value, tag)."""
        if not self.stack:
            raise RuntimeError("Stack underflow")
        tag = self._stack_tags.pop()
        val = self.stack.pop()
        return val, tag

    def peek(self, n: int = 0) -> int:
        """Peek at element n from the top (0 = top)."""
        if len(self.stack) <= n:
            raise RuntimeError("Stack underflow (peek)")
        return self.stack[-(n + 1)]

    def peek_tag(self, n: int = 0) -> int:
        """Peek at the type tag of element n from the top (0 = top)."""
        if len(self._stack_tags) <= n:
            return 0  # default VTYPE_UINT for safety
        return self._stack_tags[-(n + 1)]

    def set_top_tag(self, tag: int):
        """Overwrite the type tag of the current stack top in-place."""
        if not self._stack_tags:
            raise RuntimeError("Stack empty — cannot set tag")
        self._stack_tags[-1] = tag & 0x07

    # ── Memory helpers ────────────────────────────────────────────────────────
    # Safety constants.
    # _UINT256_MAX_MEM : every stack value is masked to this domain before
    #   any arithmetic that could produce a negative Python int.
    # _SAFE_OFFSET_CAP : highest value ever passed to Python slice/bytearray
    #   indices or bytearray.extend().  Must be <= _ALLOC_HARD_CAP so that
    #   clamping to this value never itself triggers the hard-cap error.
    #
    #   CRITICAL BUG FIXED (SC-FIX-MEM-1):
    #   The previous value was (1 << 32) = 4_294_967_296.  This was exactly
    #   the value reported in "Memory hard cap exceeded: 4294967296 bytes".
    #   When any offset was >= _SAFE_OFFSET_CAP, min(offset, _SAFE_OFFSET_CAP)
    #   clamped it *to* 4 GB instead of rejecting it.  _mem_expand then
    #   received 4_294_967_296 as the offset, computed
    #     new_words = (4_294_967_296 + 32 + 31) // 32 = 134_217_730
    #     new_bytes = 134_217_730 * 32               = 4_294_967_360
    #   which exceeded _ALLOC_HARD_CAP and raised the crash.
    #   Fix: cap at _ALLOC_HARD_CAP (64 MB) so the clamp and the hard cap
    #   are consistent — any offset above 64 MB is OOG, not clamped into an
    #   allocation that itself breaches the cap.
    #
    # _ALLOC_HARD_CAP : absolute bytearray ceiling (64 MB).  Belt-and-suspenders
    #   guard; the gas model makes allocations beyond ~1 MB economically
    #   impossible in normal execution.
    _UINT256_MAX_MEM: int   = (1 << 256) - 1
    _ALLOC_HARD_CAP:  int   = 64 * 1024 * 1024  # 64 MB absolute ceiling
    _SAFE_OFFSET_CAP: int   = _ALLOC_HARD_CAP    # FIXED: was 1<<32 (4 GB) — see above

    def _mem_expand(self, offset: int, size: int) -> int:
        """Expand memory to cover [offset, offset+size) and return gas cost.

        SC-FIX-MEM-1 (2^32 inflation fix):
          The previous implementation masked inputs to uint256 but had no
          pre-allocation guard.  If offset was >= _ALLOC_HARD_CAP the function
          would compute new_words for a multi-gigabyte region, then hit the
          hard-cap assertion.  The bug manifested when _SAFE_OFFSET_CAP was
          (1<<32) = 4_294_967_296: any offset clamped to that sentinel value
          was fed here as 4 GB, producing new_bytes > _ALLOC_HARD_CAP and the
          "Memory hard cap exceeded: 4294967296 bytes" crash.

          Fixes:
            1. Mask inputs to uint256 (unchanged).
            2. Early-exit on size==0 (unchanged).
            3. NEW: pre-allocation guard rejects offset or size > _ALLOC_HARD_CAP
               BEFORE new_words is computed.  Raises RuntimeError that the
               executor converts to OOG — correct EVM behaviour.
            4. uint256 overflow detection preserved.
            5. Quadratic gas formula + hard-cap assertion preserved as
               belt-and-suspenders (dead code after step 3, but kept for safety).

        Debug: set Frame._MEM_DEBUG = True to log every expansion.
        """
        # Step 1: mask to uint256 domain.
        offset = offset & self._UINT256_MAX_MEM
        size   = size   & self._UINT256_MAX_MEM

        if size == 0:
            return 0

        # Step 2 (SC-FIX-MEM-1): pre-allocation range guard.
        # Reject before touching any Python allocation.  An offset or size
        # above _ALLOC_HARD_CAP is OOG by gas economics; enforce it here so
        # the error message is deterministic and no giant bytearray.extend()
        # is attempted.
        if offset > self._ALLOC_HARD_CAP or size > self._ALLOC_HARD_CAP:
            import logging as _log
            _log.getLogger("VVM").debug(
                "MEM_EXPAND OOG: offset=%d size=%d cap=%d",
                offset, size, self._ALLOC_HARD_CAP)
            raise RuntimeError(
                f"Memory OOG: offset={offset} size={size} exceeds "
                f"allocation cap {self._ALLOC_HARD_CAP}")

        # Step 3: uint256 wrap-around detection.
        end = offset + size   # Python arbitrary precision — never overflows
        if end > self._UINT256_MAX_MEM:
            raise RuntimeError(
                f"Memory address overflow: offset={offset} size={size} "
                f"sum exceeds uint256 domain")

        # Step 4: word count and gas.
        new_words  = (end + 31) // 32
        old_words  = self._mem_words

        if new_words <= old_words:
            return 0

        cost = _mem_expansion_cost(old_words, new_words)

        # Step 5: hard-cap assertion (belt-and-suspenders; step 2 fires first).
        new_bytes = new_words * 32
        if new_bytes > self._ALLOC_HARD_CAP:
            raise RuntimeError(
                f"Memory hard cap exceeded: {new_bytes} bytes "
                f"(offset={offset}, size={size})")

        # Step 6: safe allocation.
        if getattr(self, '_MEM_DEBUG', False):
            import logging as _log
            _log.getLogger("VVM").debug(
                "MEM_EXPAND: offset=%d size=%d old=%d new_words=%d "
                "new_bytes=%d gas=%d",
                offset, size, old_words, new_words, new_bytes, cost)
        self.memory.extend(b'\x00' * (new_bytes - len(self.memory)))
        self._mem_words = new_words
        return cost

    # Set True before execution to log every _mem_expand invocation.
    _MEM_DEBUG: bool = False

    def mload(self, offset: int) -> int:
        cost = self._mem_expand(offset, 32)
        self._use_gas(cost)
        safe_off = min(offset & self._UINT256_MAX_MEM, self._SAFE_OFFSET_CAP)
        return int.from_bytes(self.memory[safe_off:safe_off + 32], 'big')

    def mstore(self, offset: int, value: int):
        cost = self._mem_expand(offset, 32)
        self._use_gas(cost)
        safe_off = min(offset & self._UINT256_MAX_MEM, self._SAFE_OFFSET_CAP)
        self.memory[safe_off:safe_off + 32] = (value & self.UINT256_MAX).to_bytes(32, 'big')

    def mstore8(self, offset: int, value: int):
        cost = self._mem_expand(offset, 1)
        self._use_gas(cost)
        safe_off = min(offset & self._UINT256_MAX_MEM, self._SAFE_OFFSET_CAP)
        self.memory[safe_off] = value & 0xFF

    def mslice(self, offset: int, size: int) -> bytes:
        if (size & self._UINT256_MAX_MEM) == 0:
            return b""
        cost = self._mem_expand(offset, size)
        self._use_gas(cost)
        safe_off  = min(offset & self._UINT256_MAX_MEM, self._SAFE_OFFSET_CAP)
        safe_size = min(size   & self._UINT256_MAX_MEM, self._SAFE_OFFSET_CAP)
        return bytes(self.memory[safe_off:safe_off + safe_size])

    # ── Gas helpers ───────────────────────────────────────────────────────────
    def _use_gas(self, amount: int):
        if amount < 0:
            return
        if self.gas_remaining < amount:
            raise RuntimeError(f"Out of gas (need {amount}, have {self.gas_remaining})")
        self.gas_remaining -= amount

    # ── Storage helpers ───────────────────────────────────────────────────────
    def _sload(self, slot: int) -> int:
        slot_hex = hex(slot & self.UINT256_MAX)
        key = (self.address, slot_hex)
        if key in self.storage_writes:
            return self.storage_writes[key]
        val = self.storage.sload(self.address, slot_hex)
        if key not in self.storage_orig:
            self.storage_orig[key] = val
        return val

    def _sstore(self, slot: int, new_val: int, tag: int = 0):
        if self.is_static:
            raise RuntimeError("SSTORE in static context forbidden")
        slot_hex = hex(slot & self.UINT256_MAX)
        key = (self.address, slot_hex)
        if key not in self.storage_orig:
            orig = self.storage.sload(self.address, slot_hex)
            self.storage_orig[key] = orig
        else:
            orig = self.storage_orig[key]
        new_val = new_val & self.UINT256_MAX
        tag &= 0x07

        if key not in self._storage_tag_orig:
            try:
                original_tag = self.storage.get_storage_tag(self.address, slot_hex)
            except AttributeError:
                original_tag = 0
            self._storage_tag_orig[key] = (
                int(original_tag) if int(original_tag) != 0 else None
            )

        # Dynamic gas (EIP-2929 simplified)
        if orig == 0 and new_val != 0:
            gas_cost = _SSTORE_SET_GAS
        elif orig != 0 and new_val == 0:
            gas_cost = _SSTORE_CLEAR_GAS
            self.gas_refund += _SSTORE_REFUND
        else:
            gas_cost = _SSTORE_RESET_GAS
        self._use_gas(gas_cost)
        self.storage_writes[key] = new_val
        # Keep an explicit zero entry in the execution overlay.  A persisted
        # non-zero tag must be shadowed by a later TYPESET-to-default (or an
        # ordinary SSTORE), otherwise TYPEDLOAD in the same execution would
        # incorrectly fall back to the old persisted tag.
        self._storage_tags[key] = tag
        self.touched_contracts.add(self.address)

    def _get_storage_tag(self, key: Tuple[str, str]) -> int:
        """Return staged type metadata first, then persisted metadata."""
        if key in self._storage_tags:
            return self._storage_tags[key]
        try:
            return int(self.storage.get_storage_tag(key[0], key[1])) & 0x07
        except AttributeError:
            return 0

    # Address encoding used by the VM stack.
    #
    # EOA/user VSD addresses retain the protocol's ABI-compatible uint160
    # representation: the 20 raw bytes encoded by the Base58 payload.
    # Canonical VSDc contract addresses contain an 18-byte hexadecimal suffix,
    # so they use a tagged 256-bit representation to remain lossless without
    # overloading the 160-bit EOA domain.  Precompiles and legacy/test strings
    # use a tagged length-prefixed ASCII fallback.
    _ADDR_TAG_SHIFT = 248
    _ADDR_TAG_MASK  = 0xFF << _ADDR_TAG_SHIFT
    _ADDR_TAG_EOA   = 0x01
    _ADDR_TAG_CONTRACT = 0x02
    _ADDR_TAG_TEXT  = 0x03
    _ADDR_LOW_MASK  = (1 << _ADDR_TAG_SHIFT) - 1

    def _addr_to_int(self, address: str) -> int:
        """Encode a VSD address into a deterministic, lossless VM word."""
        if not isinstance(address, str) or not address:
            return 0

        # Canonical user/wallet address: VSD + base58(20 raw bytes).  Keep the
        # exact 160-bit ABI representation for interoperability with calldata.
        if address.startswith("VSD") and not address.startswith("VSDc"):
            try:
                raw20 = b58decode(address[3:])
                if len(raw20) == 20:
                    return int.from_bytes(raw20, "big")
            except Exception:
                pass

        # Canonical deterministic contract address: VSDc + 36 hex chars.
        if address.startswith("VSDc") and len(address) == 40:
            try:
                suffix = bytes.fromhex(address[4:])
                if len(suffix) == 18:
                    raw = bytes([self._ADDR_TAG_CONTRACT]) + suffix
                    raw = raw.ljust(32, b"\x00")
                    return int.from_bytes(raw, "big")
            except ValueError:
                pass

        # Precompiles and legacy/test addresses are encoded directly.  The
        # address alphabet used by Visold is short enough to fit in 30 bytes.
        raw_text = address.encode("utf-8")
        if len(raw_text) > 30:
            raise ValueError("VSD address text exceeds VM encoding capacity")
        raw = bytes([self._ADDR_TAG_TEXT, len(raw_text)]) + raw_text
        return int.from_bytes(raw.ljust(32, b"\x00"), "big")

    def _int_to_addr(self, val: int) -> str:
        """Decode a VM address word without hashing or information loss."""
        val &= self.UINT256_MAX
        raw = val.to_bytes(32, "big")
        tag = raw[0]

        if tag == self._ADDR_TAG_EOA:
            # Reserved tagged EOA representation (currently unused for new
            # addresses, but accepted so persisted/intermediate values remain
            # forward-compatible).
            raw20 = raw[-20:]
            return "VSD" + b58encode(raw20)

        if tag == self._ADDR_TAG_CONTRACT:
            suffix = raw[1:19]
            return "VSDc" + suffix.hex()

        if tag == self._ADDR_TAG_TEXT:
            length = raw[1]
            if length > 30:
                raise ValueError("invalid tagged VSD address length")
            try:
                return raw[2:2 + length].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("invalid tagged VSD address text") from exc

        # ABI uint160 compatibility for untagged address words. Values in
        # the 160-bit range decode directly to the canonical wallet payload.
        # Contract addresses use the explicit 0x02 tag above, so decoding here
        # never depends on mutable storage state (and also works for freshly
        # constructed frames and for CREATE2 before persistence).
        if val <= ((1 << 160) - 1):
            return "VSD" + b58encode(val.to_bytes(20, "big"))

        raise ValueError("invalid VSD address word")

    def _as_signed(self, val: int) -> int:
        """Interpret 256-bit unsigned as signed."""
        if val > self.INT256_MAX:
            return val - (1 << 256)
        return val

    def _from_signed(self, val: int) -> int:
        """Convert signed to unsigned 256-bit."""
        return val & self.UINT256_MAX


# ── SC-FIX-1: Global Reentrancy Guard ────────────────────────────────────────
class _ReentrancyGuard:
    """
    Per-top-level-execution reentrancy tracker.

    Tracks which contract addresses are currently on the call stack within a
    single VVM execution. If a contract tries to call back into itself (or into
    any ancestor in the current call chain) we raise RuntimeError which is
    caught by _execute() and reverts the child frame.

    This prevents the classic reentrancy attack pattern:
        ContractA.withdraw() → ExternalCall → AttackerContract.fallback()
                             → ContractA.withdraw() [BLOCKED]

    Usage: instantiate one _ReentrancyGuard per top-level VVMEngine.deploy/call
    invocation and pass it down through _internal_call frames.

    Thread-safety: each top-level call gets its own guard instance, so no
    locking is required — guards are never shared across threads.
    """
    __slots__ = ("_active",)

    def __init__(self):
        self._active: set = set()

    def enter(self, address: str):
        if address in self._active:
            raise RuntimeError(
                f"Reentrancy detected: contract {address[:16]}... "
                f"is already on the call stack")
        self._active.add(address)

    def exit(self, address: str):
        self._active.discard(address)
