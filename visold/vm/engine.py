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
"""visold.vm.engine


Defines: VVMEngine
Origin: visold_vsd_.py L20099-20101, L20106-20153, L20156-20170, L20174-21757
"""

import hashlib
from decimal import Decimal, ROUND_HALF_EVEN, InvalidOperation
from typing import Optional, TYPE_CHECKING, Tuple

from visold.crypto.ecc import ECPoint, pub_to_address
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.units import to_satoshi
from visold.vm.frame import VVMResult, _ReentrancyGuard, _VMFrame
from visold.vm.opcodes import Op, _GAS, _GAS_REFUND_DENOMINATOR
from visold.vm.precompiles import VVMPrecompiles

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# SC-V73-FIX-4: deterministic gas_price conversion.
# int(tx.gas_price * 1e8) is float arithmetic and gives different integers
# on x86 vs ARM for certain decimal values.  Use round() (half-even) once,
# matching gas_fee_to_sat() which is already used everywhere else.
def _gas_price_to_sat(gas_price_vsd: float) -> int:
    """Convert a VSD-per-gas float to integer satoshi-per-gas deterministically."""
    return int(round(gas_price_vsd * Config.SATOSHI_PER_VSD))


def _difficulty_to_vm_uint(difficulty) -> int:
    """Encode protocol difficulty for VVM's uint256-only operand stack.

    Block difficulty is intentionally a fractional protocol value, while the
    VM stack stores only integers.  Use a canonical decimal-string conversion
    and fixed-point scale instead of passing a Python float into ``push()``;
    this preserves fractional difficulty and avoids platform-dependent binary
    float bit operations.
    """
    try:
        value = Decimal(str(difficulty)) * Decimal(Config.VVM_DIFFICULTY_SCALE)
        encoded = int(value.to_integral_value(rounding=ROUND_HALF_EVEN))
    except (InvalidOperation, ValueError, TypeError, OverflowError):
        raise RuntimeError("invalid block difficulty for VVM")
    if encoded < 0:
        raise RuntimeError("negative block difficulty for VVM")
    if encoded > _VMFrame.UINT256_MAX:
        raise RuntimeError("block difficulty exceeds VVM uint256 range")
    return encoded


# ── State Channel helpers (module-level, used by VVMEngine._run) ──────────────

def _chan_recover_address(msg_hash_b: bytes,
                          v: int, r: int, s: int) -> str:
    """
    Recover the VSD address of the signer from a secp256k1 ECDSA signature.
    Returns the VSD address string on success, or "" on any failure.

    Mirrors the ECRecover precompile (VVMPrecompiles._ecrecover) exactly so
    that off-chain signing tools that use the precompile path and contracts
    that use CHAN_CLOSE / CHAN_DISPUTE always agree on the recovered address.

    Parameters
    ----------
    msg_hash_b : bytes  — 32-byte SHA-256 digest that was signed
    v          : int    — recovery id, must be 27 or 28 (Ethereum convention)
    r          : int    — ECDSA signature r component (uint256)
    s          : int    — ECDSA signature s component (uint256)
    """
    try:
        N = ECPoint.N
        P = ECPoint.P
        # v must be 27 or 28
        if v not in (27, 28):
            return ""
        # r, s must be in [1, N)
        if not (1 <= r < N and 1 <= s < N):
            return ""
        recovery_id = v - 27
        # Compute curve point R from r
        x = r + recovery_id * N
        if x >= P:
            return ""
        y_sq = (pow(x, 3, P) + 7) % P
        y    = pow(y_sq, (P + 1) // 4, P)
        if (y % 2) != (recovery_id % 2):
            y = P - y
        R_pt     = ECPoint(x, y)
        # pub = r^{-1} * (s*R - hash*G)
        r_inv    = pow(r, N - 2, N)
        hash_int = int.from_bytes(msg_hash_b, "big")
        u1       = (-hash_int * r_inv) % N
        u2       = (s         * r_inv) % N
        G_pt     = ECPoint(ECPoint.Gx, ECPoint.Gy)
        rec_pub  = (u1 * G_pt) + (u2 * R_pt)
        if rec_pub.is_inf():
            return ""
        return pub_to_address(rec_pub)
    except Exception:
        return ""


def _chan_state_msg(channel_id: str, seq_no: int,
                    bal_opener: int, bal_counter: int) -> bytes:
    """
    Build the canonical 32-byte state-update digest that both parties sign
    when creating an off-chain state update for a VVM state channel.

    Format: SHA-256( "{channel_id}:{seq_no}:{bal_opener}:{bal_counter}" )

    All fields are colon-separated ASCII so the message is unambiguous and
    reproducible in any language without a special encoder.
    The channel_id is the 64-hex-char representation of the channel uint256.
    """
    blob = (f"{channel_id}:{seq_no}:"
            f"{bal_opener}:{bal_counter}").encode("ascii")
    return hashlib.sha256(blob).digest()


# ── Main VVM Engine ───────────────────────────────────────────────────────────
class VVMEngine:
    """
    Visold Virtual Machine — deterministic stack-based execution engine.

    Security guarantees:
    • Full sandboxing: no OS/network/file access from bytecode.
    • Strict gas enforcement: every opcode charges gas before executing.
    • Stack depth enforced at Config.VVM_MAX_CALL_DEPTH frames.
    • Memory hard-capped at Config.VVM_MAX_MEMORY_BYTES per frame.
    • Static context propagated: SSTORE/LOG/CREATE forbidden inside STATICCALL.
    • Re-entrancy safe: each call frame has its own isolated write buffer;
      writes are only committed to storage on clean return (no partial states).
    • All integer arithmetic is 256-bit modular (overflow impossible).
    • All code is read-only; no self-modifying code path exists.
    """

    def __init__(self, storage: 'Storage'):
        self._storage = storage

    # ── Public entry points ───────────────────────────────────────────────────

    def deploy(self, *, sender: str, bytecode: bytes,
               call_value: int, gas_limit: int,
               block_ctx, tx,
               parent_storage_writes: Optional[dict] = None,
               parent_storage_tags: Optional[dict] = None,
               parent_storage_tag_orig: Optional[dict] = None,
               parent_balance_deltas: Optional[dict] = None,
               parent_create_nonce_deltas: Optional[dict] = None,
               deployed_address: Optional[str] = None) -> 'VVMResult':
        """
        Execute a contract deployment.
        bytecode = init code.  The init code runs and its RETURN data becomes
        the deployed runtime bytecode.
        Returns VVMResult with contract_addr set on success.

        parent_storage_writes: when called from CREATE/CREATE2 inside an
          existing execution, the parent frame's pending writes are pre-loaded.
        parent_storage_tags / parent_storage_tag_orig: same for typed-storage
          metadata so child init-code observes and correctly rolls back parent
          tag writes.
        parent_balance_deltas: execution-local value-transfer overlay inherited
          from the parent frame.  No balance is written to persistent storage
          until the top-level transaction commits.
        deployed_address: deterministic address override used by CREATE2.
        """
        if gas_limit > Config.VVM_TX_GAS_CAP:
            return VVMResult(success=False, gas_used=gas_limit,
                             revert_reason="gas_limit exceeds cap")

        # Derive deterministic contract address unless CREATE2 supplied the
        # already-computed deterministic destination.
        if deployed_address:
            contract_addr = str(deployed_address)
        else:
            nonce      = self._storage.get_nonce(sender)
            addr_input = f"{sender}:{nonce}:{tx.tx_id}"
            contract_addr = "VSDc" + sha256(addr_input.encode())[:36]

        # Charge deployment base gas.
        # NOTE: base_gas must NOT include per-byte code storage here — that cost
        # is charged *after* the init code runs, once we know the actual runtime
        # bytecode length (returned by the init code via RETURN).  Including it
        # here double-charges code-storage gas for large bytecodes, exhausting
        # frame.gas_remaining before the final store check and causing silent
        # deploy failures for bytecodes in the 500-700 byte range.
        base_gas = Config.VVM_DEPLOY_GAS_BASE
        if base_gas > gas_limit:
            return VVMResult(success=False, gas_used=gas_limit,
                             revert_reason="insufficient gas for deploy base cost")

        # SC-FIX-1: Fresh reentrancy guard per top-level execution
        guard = _ReentrancyGuard()
        guard.enter(contract_addr)

        # SC-V73-FIX-4: use deterministic int conversion (not float * 1e8)
        frame = _VMFrame(
            code          = bytecode,
            calldata      = b"",
            caller        = sender,
            address       = contract_addr,
            origin        = sender,
            call_value    = call_value,
            gas_limit     = gas_limit - base_gas,
            storage_ref   = self._storage,
            is_static     = False,
            depth         = 0,
            gas_price     = _gas_price_to_sat(tx.gas_price),
            block_ctx     = block_ctx,
            reentrance_guard = guard,
        )
        frame._use_gas(0)  # base gas already deducted from limit above

        # SC-V73-FIX-6: pre-populate parent writes so child SLOAD sees them
        if parent_storage_writes:
            frame.storage_writes = dict(parent_storage_writes)
            frame.storage_orig   = {}  # child should not inherit orig tracking
        if parent_storage_tags:
            frame._storage_tags = dict(parent_storage_tags)
        if parent_storage_tag_orig:
            frame._storage_tag_orig = dict(parent_storage_tag_orig)
        if parent_balance_deltas:
            frame.balance_deltas = dict(parent_balance_deltas)
        if parent_create_nonce_deltas:
            frame.create_nonce_deltas = dict(parent_create_nonce_deltas)
        if call_value > 0 and not parent_balance_deltas:
            frame.balance_deltas[contract_addr] = (
                frame.balance_deltas.get(contract_addr, 0) + int(call_value)
            )

        # State-channel precompiles perform direct storage mutations rather
        # than frame-buffered contract writes.  Journal them for this exact
        # execution frame so a VM revert (including nested CREATE/CALL) cannot
        # leak channel/account side effects into the parent state.
        state_channel_journal = self._storage.begin_state_channel_journal()
        try:
            self._execute(frame)
        except Exception:
            guard.exit(contract_addr)
            self._storage.end_state_channel_journal(state_channel_journal)
            self._storage.restore_state_channel_journal(state_channel_journal)
            raise
        guard.exit(contract_addr)

        gas_used_raw = base_gas + (frame.gas_limit - frame.gas_remaining)

        # SC-FIX-2: Cap gas refund at gas_used // GAS_REFUND_DENOMINATOR (EIP-3529)
        capped_refund = min(frame.gas_refund, gas_used_raw // _GAS_REFUND_DENOMINATOR)
        gas_used = max(0, min(gas_used_raw - capped_refund, gas_limit))

        if frame.reverted:
            self._storage.end_state_channel_journal(state_channel_journal)
            self._storage.restore_state_channel_journal(state_channel_journal)
            return VVMResult(
                success=False,
                gas_used=min(gas_used_raw, gas_limit),
                revert_reason=frame.output.decode("utf-8", errors="replace")
                              if frame.output else "Reverted",
            )

        runtime_code = frame.output
        if len(runtime_code) > Config.VVM_MAX_BYTECODE_SIZE:
            # BUG-FIX (v7.7.1): use actual gas_used_raw, not gas_limit.
            # The init code already executed and we tracked exact gas.
            # Charging gas_limit here over-bills the user for an honest
            # init-code that returned a too-large runtime.  We still cap
            # at gas_limit to defend against negative-balance arithmetic.
            self._storage.end_state_channel_journal(state_channel_journal)
            self._storage.restore_state_channel_journal(state_channel_journal)
            return VVMResult(success=False, gas_used=min(gas_used_raw, gas_limit),
                             revert_reason="runtime bytecode exceeds max size")

        # Charge for storing runtime code (per-byte, post-execution)
        code_store_gas = len(runtime_code) * Config.VVM_GAS_PER_BYTE_CODE
        if frame.gas_remaining < code_store_gas:
            # BUG-FIX (v7.7.1): use actual gas spent so far.  We have NOT
            # debited code_store_gas because we cannot afford it; bill
            # only what was actually consumed up to this point.
            self._storage.end_state_channel_journal(state_channel_journal)
            self._storage.restore_state_channel_journal(state_channel_journal)
            return VVMResult(success=False, gas_used=min(gas_used_raw, gas_limit),
                             revert_reason="out of gas storing runtime code")
        frame.gas_remaining -= code_store_gas

        # Recompute gas_used now that gas_remaining is finalised (includes
        # code_store_gas).  Using the stale pre-store value would under-report
        # gas consumption and miscount refunds for large contracts.
        gas_used_raw = base_gas + (frame.gas_limit - frame.gas_remaining)
        capped_refund = min(frame.gas_refund, gas_used_raw // _GAS_REFUND_DENOMINATOR)
        gas_used = max(0, min(gas_used_raw - capped_refund, gas_limit))

        self._storage.end_state_channel_journal(state_channel_journal)
        return VVMResult(
            success              = True,
            gas_used             = gas_used,
            return_data          = runtime_code,
            contract_addr        = contract_addr,
            logs                 = frame.logs,
            storage_writes       = frame.storage_writes,
            storage_orig         = frame.storage_orig,
            touched_contracts    = frame.touched_contracts,
            self_destruct_transfers = frame.self_destruct_transfers,
            pending_deployments  = frame.pending_deployments,
            storage_tags         = frame._storage_tags,
            storage_tag_orig     = frame._storage_tag_orig,
            balance_deltas       = frame.balance_deltas,
            create_nonce_deltas  = frame.create_nonce_deltas,
            state_channel_journal= state_channel_journal,
        )

    def call(self, *, caller: str, contract: str,
             calldata: bytes, call_value: int,
             gas_limit: int, block_ctx, tx) -> 'VVMResult':
        """
        Execute a message call against an existing contract.
        Returns VVMResult.
        """
        if gas_limit > Config.VVM_TX_GAS_CAP:
            return VVMResult(success=False, gas_used=gas_limit,
                             revert_reason="gas_limit exceeds cap")

        contract_rec = self._storage.get_contract(contract)
        if not contract_rec:
            return VVMResult(success=False, gas_used=21000,
                             revert_reason=f"Contract {contract} not found")

        runtime_code = self._storage.get_contract_code(contract_rec["code_hash"])
        if runtime_code is None:
            return VVMResult(success=False, gas_used=21000,
                             revert_reason="Contract code missing from storage")

        # SC-FIX-1: Fresh reentrancy guard per top-level execution
        guard = _ReentrancyGuard()
        guard.enter(contract)

        # SC-V73-FIX-4: use deterministic int conversion (not float * 1e8)
        frame = _VMFrame(
            code          = runtime_code,
            calldata      = calldata,
            caller        = caller,
            address       = contract,
            origin        = caller,
            call_value    = call_value,
            gas_limit     = gas_limit,
            storage_ref   = self._storage,
            is_static     = False,
            depth         = 0,
            gas_price     = _gas_price_to_sat(tx.gas_price),
            block_ctx     = block_ctx,
            reentrance_guard = guard,
        )

        if call_value > 0:
            frame.balance_deltas[contract] = int(call_value)

        state_channel_journal = self._storage.begin_state_channel_journal()
        try:
            self._execute(frame)
        except Exception:
            guard.exit(contract)
            self._storage.end_state_channel_journal(state_channel_journal)
            self._storage.restore_state_channel_journal(state_channel_journal)
            raise
        guard.exit(contract)

        gas_used_raw = frame.gas_limit - frame.gas_remaining

        # SC-FIX-2: Cap gas refund at gas_used // GAS_REFUND_DENOMINATOR (EIP-3529)
        capped_refund = min(frame.gas_refund, gas_used_raw // _GAS_REFUND_DENOMINATOR)
        gas_used = max(0, min(gas_used_raw - capped_refund, gas_limit))

        if frame.reverted:
            self._storage.end_state_channel_journal(state_channel_journal)
            self._storage.restore_state_channel_journal(state_channel_journal)
            return VVMResult(
                success=False,
                gas_used=min(gas_used_raw, gas_limit),
                revert_reason=frame.output.decode("utf-8", errors="replace")
                              if frame.output else "Reverted",
            )

        self._storage.end_state_channel_journal(state_channel_journal)
        return VVMResult(
            success              = True,
            gas_used             = gas_used,
            return_data          = frame.output,
            logs                 = frame.logs,
            storage_writes       = frame.storage_writes,
            storage_orig         = frame.storage_orig,
            touched_contracts    = frame.touched_contracts,
            self_destruct_transfers = frame.self_destruct_transfers,
            pending_deployments  = frame.pending_deployments,
            storage_tags         = frame._storage_tags,
            storage_tag_orig     = frame._storage_tag_orig,
            balance_deltas       = frame.balance_deltas,
            state_channel_journal= state_channel_journal,
        )

    def simulate(self, *, caller: str, contract: str,
                 calldata: bytes, call_value: int,
                 gas_limit: int, block_ctx) -> 'VVMResult':
        """
        SC-IMPROVEMENT-1: Pure dry-run simulation.

        Executes the contract call but discards ALL storage writes.
        No state changes are committed. Safe to call from RPC/read-only paths.

        Uses a _ReadOnlyStorage proxy that satisfies sload() but silently
        drops all sstore() calls. The VVMResult reflects what WOULD happen
        including gas_used, return_data, logs, and revert_reason.
        """
        contract_rec = self._storage.get_contract(contract)
        if not contract_rec:
            return VVMResult(success=False, gas_used=21000,
                             revert_reason=f"Contract {contract} not found")
        runtime_code = self._storage.get_contract_code(contract_rec["code_hash"])
        if runtime_code is None:
            return VVMResult(success=False, gas_used=21000,
                             revert_reason="Contract code missing from storage")

        class _SimTx:
            gas_price = 0.0

        # Shallow proxy: intercept sstore so writes are silently dropped
        class _SimStorage:
            def __init__(self, real):
                self._real = real
            def sload(self, addr, slot):
                return self._real.sload(addr, slot)
            def sstore(self, addr, slot, val):
                pass  # discard
            def get_storage_tag(self, addr, slot):
                return self._real.get_storage_tag(addr, slot)
            def get_contract(self, addr):
                return self._real.get_contract(addr)
            def get_contract_code(self, h):
                return self._real.get_contract_code(h)
            def get_balance(self, addr):
                return self._real.get_balance(addr)
            def get_balance_sat(self, addr):
                return self._real.get_balance_sat(addr)
            def get_role(self, addr):
                return self._real.get_role(addr)
            def get_all_by_role(self, role):
                return self._real.get_all_by_role(role)
            def get_block(self, idx):
                return self._real.get_block(idx)

        sim_storage = _SimStorage(self._storage)
        guard = _ReentrancyGuard()
        guard.enter(contract)
        # SC-V73-FIX-4: deterministic gas_price (simulate uses 0 — no tx context)
        frame = _VMFrame(
            code             = runtime_code,
            calldata         = calldata,
            caller           = caller,
            address          = contract,
            origin           = caller,
            call_value       = call_value,
            gas_limit        = min(gas_limit, Config.VVM_TX_GAS_CAP),
            storage_ref      = sim_storage,  # type: ignore[arg-type]
            is_static        = True,   # prevent any state mutation path
            depth            = 0,
            gas_price        = 0,      # dry-run: no tx, no gas price
            block_ctx        = block_ctx,
            reentrance_guard = guard,
        )
        if call_value > 0:
            frame.balance_deltas[contract] = int(call_value)
        self._execute(frame)
        guard.exit(contract)
        gas_used_raw = frame.gas_limit - frame.gas_remaining
        capped_refund = min(frame.gas_refund, gas_used_raw // _GAS_REFUND_DENOMINATOR)
        gas_used = max(0, gas_used_raw - capped_refund)
        if frame.reverted:
            return VVMResult(
                success=False,
                gas_used=gas_used_raw,
                revert_reason=frame.output.decode("utf-8", errors="replace")
                              if frame.output else "Reverted",
            )
        return VVMResult(
            success=True,
            gas_used=gas_used,
            return_data=frame.output,
            logs=frame.logs,
            storage_writes={},  # dry-run: nothing committed
            storage_orig={},
            touched_contracts=set(),
            self_destruct_transfers=[],
            storage_tags={},
            storage_tag_orig={},
            balance_deltas={},
        )

    def estimate_gas(self, *, caller: str, contract: str,
                     calldata: bytes, call_value: int,
                     block_ctx) -> int:
        """
        SC-IMPROVEMENT-2: Binary-search gas estimator.

        Returns the minimum gas limit that makes the call succeed.
        Uses simulate() internally so no state is modified.
        Returns VVM_TX_GAS_CAP if the call fails at max gas (intrinsically reverts).
        """
        lo = 21000
        hi = Config.VVM_TX_GAS_CAP

        # Quick check at max — if it reverts even with max gas, bail early
        probe = self.simulate(caller=caller, contract=contract, calldata=calldata,
                              call_value=call_value, gas_limit=hi, block_ctx=block_ctx)
        if not probe.success:
            return hi  # caller should interpret this as "call will always revert"

        # Binary search for minimum viable gas
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            r = self.simulate(caller=caller, contract=contract, calldata=calldata,
                              call_value=call_value, gas_limit=mid, block_ctx=block_ctx)
            if r.success:
                hi = mid
            else:
                lo = mid

        # Add 10% buffer for safety (storage warm/cold variance)
        return min(int(hi * 1.1), Config.VVM_TX_GAS_CAP)

    # ── Internal CALL (contract-to-contract) ─────────────────────────────────
    def _internal_call(self, *, caller_frame: '_VMFrame',
                       callee_addr: str, calldata: bytes,
                       call_value: int, gas: int,
                       is_static: bool = False,
                       is_delegate: bool = False) -> Tuple[bool, bytes]:
        """
        Spawn a child frame for contract-to-contract call.
        Returns (success, return_data).
        Writes are merged into caller_frame on success only.
        """
        if caller_frame.depth >= Config.VVM_MAX_CALL_DEPTH:
            return False, b""
        if is_static and call_value != 0:
            return False, b""

        # ── SC-FIX-1: Reentrancy guard check ─────────────────────────────────
        guard = caller_frame.reentrance_guard
        if guard is not None:
            try:
                guard.enter(callee_addr)
            except RuntimeError as re_err:
                log.debug(f"VVM reentrancy blocked: {re_err}")
                return False, str(re_err).encode()[:256]

        # Build a tentative balance overlay.  A nested transfer becomes part
        # of the parent only if the child call succeeds; this gives CALL the
        # same revert semantics as its storage writes.
        pending_balance_deltas = dict(caller_frame.balance_deltas)
        if not is_delegate and call_value > 0:
            source = caller_frame.address
            effective = (self._storage.get_balance_sat(source) +
                         int(pending_balance_deltas.get(source, 0)))
            if effective < call_value:
                if guard is not None:
                    guard.exit(callee_addr)
                return False, b""
            pending_balance_deltas[source] = (
                pending_balance_deltas.get(source, 0) - int(call_value)
            )
            pending_balance_deltas[callee_addr] = (
                pending_balance_deltas.get(callee_addr, 0) + int(call_value)
            )

        # ── Precompile dispatch ────────────────────────────────────────────────
        if VVMPrecompiles.is_precompile(callee_addr):
            child_gas = min(gas, caller_frame.gas_remaining)
            caller_frame._use_gas(child_gas // 64)
            ok, ret, gas_used = VVMPrecompiles.execute(
                callee_addr, calldata, child_gas)
            caller_frame.gas_remaining = max(
                0, caller_frame.gas_remaining - gas_used)
            caller_frame.return_buffer = ret
            if ok:
                caller_frame.balance_deltas = pending_balance_deltas
            if guard is not None:
                guard.exit(callee_addr)
            return ok, ret

        contract_rec = self._storage.get_contract(callee_addr)
        if not contract_rec:
            # Calling an EOA or non-existent address is a successful no-code
            # call.  Attached value still transfers to that address.
            caller_frame.balance_deltas = pending_balance_deltas
            if guard is not None:
                guard.exit(callee_addr)
            return True, b""

        runtime_code = self._storage.get_contract_code(contract_rec["code_hash"])
        if runtime_code is None:
            if guard is not None:
                guard.exit(callee_addr)
            return False, b""

        # If DELEGATECALL: executing callee code in caller's storage context
        exec_address  = caller_frame.address if is_delegate else callee_addr
        # SC-V73-FIX-7: DELEGATECALL must preserve msg.sender as the entity that
        # called the contract containing DELEGATECALL (caller_frame.caller), not
        # the intermediate contract (caller_frame.address).  This matches
        # Ethereum spec: msg.sender inside a delegated library == original caller.
        exec_caller   = caller_frame.caller if is_delegate else caller_frame.address

        child = _VMFrame(
            code          = runtime_code,
            calldata      = calldata,
            caller        = exec_caller,
            address       = exec_address,
            origin        = caller_frame.origin,
            # SC-V73-FIX-7: DELEGATECALL also preserves msg.value (call_value)
            call_value    = caller_frame.call_value if is_delegate else call_value,
            gas_limit     = gas,
            storage_ref   = self._storage,
            is_static     = is_static or caller_frame.is_static,
            depth         = caller_frame.depth + 1,
            gas_price     = caller_frame.gas_price_wei,
            block_ctx     = caller_frame.block_ctx,
            return_buffer = caller_frame.return_buffer,
            reentrance_guard = guard,
        )
        # Pre-populate child with parent's write buffer so it sees parent writes.
        child.storage_writes = dict(caller_frame.storage_writes)
        child.storage_orig   = dict(caller_frame.storage_orig)
        child._storage_tags  = dict(caller_frame._storage_tags)
        child._storage_tag_orig = dict(caller_frame._storage_tag_orig)
        child.balance_deltas = pending_balance_deltas

        # State-channel opcodes perform direct persistent mutations rather than
        # using the frame-local storage/balance overlays above.  A nested CALL
        # therefore needs its own journal boundary so child REVERT restores only
        # the child's direct side effects.  The journal implementation records
        # each first pre-mutation snapshot in every active journal, so a child
        # journal can safely restore its own changes while the enclosing parent
        # journal still retains the original transaction-level pre-state for a
        # later parent/top-level revert.
        state_channel_journal = self._storage.begin_state_channel_journal()
        journal_active = True
        try:
            self._execute(child)

            gas_consumed = child.gas_limit - child.gas_remaining
            caller_frame._use_gas(gas_consumed)

            if child.reverted:
                # Discard child writes AND direct state-channel/account side
                # effects.  The enclosing parent journal remains active.
                caller_frame.return_buffer = child.output
                self._storage.end_state_channel_journal(state_channel_journal)
                journal_active = False
                self._storage.restore_state_channel_journal(
                    state_channel_journal)
                return False, child.output

            # Child succeeded: its direct state-channel mutations become part
            # of the enclosing transaction.  Do not restore them; simply close
            # the child journal.  The parent journal has already captured the
            # same first pre-state and can roll everything back if the parent
            # later reverts.
            self._storage.end_state_channel_journal(state_channel_journal)
            journal_active = False
        except Exception:
            # _execute() normally catches VM exceptions itself, but keep this
            # boundary exception-safe so a storage/backend failure cannot leave
            # an active journal or leaked direct side effects.
            if journal_active:
                self._storage.end_state_channel_journal(state_channel_journal)
                journal_active = False
            self._storage.restore_state_channel_journal(
                state_channel_journal)
            raise
        finally:
            if guard is not None:
                guard.exit(callee_addr)

        # Merge child writes back into parent
        caller_frame.storage_writes.update(child.storage_writes)
        caller_frame.storage_orig.update(
            {k: v for k, v in child.storage_orig.items()
             if k not in caller_frame.storage_orig})
        caller_frame._storage_tags.update(child._storage_tags)
        caller_frame._storage_tag_orig.update(
            {k: v for k, v in child._storage_tag_orig.items()
             if k not in caller_frame._storage_tag_orig})
        caller_frame.balance_deltas = child.balance_deltas
        caller_frame.touched_contracts.update(child.touched_contracts)
        caller_frame.logs.extend(child.logs)
        caller_frame.gas_refund  += child.gas_refund
        caller_frame.self_destruct_transfers.extend(child.self_destruct_transfers)
        # SC-V73-FIX-2: propagate deferred deployments from child to parent
        caller_frame.pending_deployments.extend(child.pending_deployments)
        caller_frame.return_buffer = child.output
        return True, child.output

    # ── Core execution loop ───────────────────────────────────────────────────
    def _execute(self, f: '_VMFrame'):
        """
        Main interpreter loop.  Dispatches one opcode per iteration.
        Raises nothing — all errors set f.reverted=True and f.output=error bytes.
        """
        try:
            self._run(f)
        except RuntimeError as e:
            f.reverted = True
            f.output   = str(e).encode()[:256]
        except Exception as e:
            f.reverted = True
            f.output   = f"VVM internal error: {e}".encode()[:256]

    def _run(self, f: '_VMFrame'):  # noqa: C901 (complexity accepted for perf)
        W = _VMFrame.UINT256_MAX
        code = f.code

        while f.pc < len(code) and not f.stopped and not f.reverted:
            op = code[f.pc]
            f.pc += 1

            # ── Gas charge ─────────────────────────────────────────────────
            base_cost = _GAS.get(op)
            if base_cost is None:
                raise RuntimeError(f"Invalid opcode 0x{op:02X}")
            if op != Op.SSTORE:   # SSTORE gas computed inside _sstore
                f._use_gas(base_cost)

            # ── Dispatch ───────────────────────────────────────────────────
            if op == Op.STOP:
                f.stopped = True

            elif op == Op.ADD:
                f.push((f.pop() + f.pop()) & W)
            elif op == Op.MUL:
                f.push((f.pop() * f.pop()) & W)
            elif op == Op.SUB:
                a, b = f.pop(), f.pop()
                f.push((a - b) & W)
            elif op == Op.DIV:
                a, b = f.pop(), f.pop()
                f.push(a // b if b else 0)
            elif op == Op.SDIV:
                a, b = f._as_signed(f.pop()), f._as_signed(f.pop())
                if b == 0:
                    f.push(0)
                else:
                    result = abs(a) // abs(b)
                    if (a < 0) != (b < 0):
                        result = -result
                    f.push(f._from_signed(result))
            elif op == Op.MOD:
                a, b = f.pop(), f.pop()
                f.push(a % b if b else 0)
            elif op == Op.SMOD:
                a, b = f._as_signed(f.pop()), f._as_signed(f.pop())
                if b == 0:
                    f.push(0)
                else:
                    result = abs(a) % abs(b)
                    if a < 0:
                        result = -result
                    f.push(f._from_signed(result))
            elif op == Op.ADDMOD:
                a, b, n = f.pop(), f.pop(), f.pop()
                f.push((a + b) % n if n else 0)
            elif op == Op.MULMOD:
                a, b, n = f.pop(), f.pop(), f.pop()
                f.push((a * b) % n if n else 0)
            elif op == Op.EXP:
                a, b = f.pop(), f.pop()
                # Extra gas: 50 per byte of exponent
                exp_bytes = max(1, (b.bit_length() + 7) // 8) if b else 0
                f._use_gas(50 * exp_bytes)
                f.push(pow(a, b, 1 << 256))
            elif op == Op.SIGNEXTEND:
                b, x = f.pop(), f.pop()
                if b < 31:
                    sign_bit = 1 << (b * 8 + 7)
                    mask = sign_bit - 1
                    if x & sign_bit:
                        f.push(x | (~mask & W))
                    else:
                        f.push(x & mask)
                else:
                    f.push(x)

            elif op == Op.LT:
                f.push(1 if f.pop() < f.pop() else 0, Op.VTYPE_BOOL)
            elif op == Op.GT:
                f.push(1 if f.pop() > f.pop() else 0, Op.VTYPE_BOOL)
            elif op == Op.SLT:
                a, b = f._as_signed(f.pop()), f._as_signed(f.pop())
                f.push(1 if a < b else 0, Op.VTYPE_BOOL)
            elif op == Op.SGT:
                a, b = f._as_signed(f.pop()), f._as_signed(f.pop())
                f.push(1 if a > b else 0, Op.VTYPE_BOOL)
            elif op == Op.EQ:
                f.push(1 if f.pop() == f.pop() else 0, Op.VTYPE_BOOL)
            elif op == Op.ISZERO:
                f.push(1 if f.pop() == 0 else 0, Op.VTYPE_BOOL)
            elif op == Op.AND:
                f.push(f.pop() & f.pop())
            elif op == Op.OR:
                f.push(f.pop() | f.pop())
            elif op == Op.XOR:
                f.push(f.pop() ^ f.pop())
            elif op == Op.NOT:
                f.push(~f.pop() & W)
            elif op == Op.BYTE:
                i, x = f.pop(), f.pop()
                f.push((x >> (248 - i * 8)) & 0xFF if i < 32 else 0)
            elif op == Op.SHL:
                shift, val = f.pop(), f.pop()
                f.push((val << shift) & W if shift < 256 else 0)
            elif op == Op.SHR:
                shift, val = f.pop(), f.pop()
                f.push(val >> shift if shift < 256 else 0)
            elif op == Op.SAR:
                shift, val = f.pop(), f.pop()
                signed = f._as_signed(val)
                if shift >= 256:
                    f.push(W if signed < 0 else 0)
                else:
                    f.push(f._from_signed(signed >> shift))

            elif op == Op.SHA3:
                offset, size = f.pop(), f.pop()
                data = f.mslice(offset, size)
                f._use_gas(6 * ((size + 31) // 32))  # 6 gas per word
                h = int.from_bytes(hashlib.sha256(data).digest(), 'big')
                f.push(h, Op.VTYPE_HASH)          # SHA3 → HASH type

            elif op == Op.ADDRESS:
                f.push(f._addr_to_int(f.address), Op.VTYPE_ADDRESS)
            elif op == Op.BALANCE:
                addr_int = f.pop()
                addr_str = f._int_to_addr(addr_int)
                # SC-FIX-6: use integer satoshi path (never float balance math).
                # Include the execution-local value-transfer overlay so a
                # nested CALL/CREATE is immediately visible to BALANCE.
                bal_sat = (self._storage.get_balance_sat(addr_str)
                           + int(f.balance_deltas.get(addr_str, 0)))
                if bal_sat < 0:
                    raise RuntimeError(f"negative execution balance for {addr_str}")
                f.push(bal_sat, Op.VTYPE_SATOSHI)
            elif op == Op.ORIGIN:
                f.push(f._addr_to_int(f.origin), Op.VTYPE_ADDRESS)
            elif op == Op.CALLER:
                f.push(f._addr_to_int(f.caller), Op.VTYPE_ADDRESS)
            elif op == Op.CALLVALUE:
                f.push(f.call_value, Op.VTYPE_SATOSHI)
            elif op == Op.CALLDATALOAD:
                i = f.pop()
                # Safe CALLDATALOAD: any uint256 offset is valid per EVM spec.
                # Values >= len(calldata) return zero (right-padded with 0x00).
                #
                # SC-FIX-MEM-1 note: _SAFE_OFFSET_CAP is now _ALLOC_HARD_CAP
                # (64 MB), not (1<<32) as the old comment stated.  The clamp
                # below (safe_i) ensures Python never receives a raw uint256
                # as a bytearray/bytes slice index even if calldata is huge.
                i = i & f._UINT256_MAX_MEM
                cd_len = len(f.calldata)
                if i >= cd_len:
                    f.push(0)
                else:
                    # safe_i: i already < cd_len (a real Python int <= ~1 GB in
                    # practice), so min() is a no-op in normal execution.  It
                    # guards against pathological calldata buffers.
                    safe_i = min(i, f._SAFE_OFFSET_CAP)
                    end    = min(safe_i + 32, cd_len)
                    chunk  = f.calldata[safe_i:end]
                    if len(chunk) < 32:
                        chunk = chunk + b'\x00' * (32 - len(chunk))
                    f.push(int.from_bytes(chunk, 'big'))
            elif op == Op.CALLDATASIZE:
                f.push(len(f.calldata))
            elif op == Op.CALLDATACOPY:
                dst, src, size = f.pop(), f.pop(), f.pop()
                # Safe CALLDATACOPY:
                # • mask all three to uint256 before any arithmetic
                # • _mem_expand handles dst/safe_size + gas charge
                # • safe_size clamped to _SAFE_OFFSET_CAP (= _ALLOC_HARD_CAP,
                #   64 MB) — note: _SAFE_OFFSET_CAP was formerly (1<<32);
                #   SC-FIX-MEM-1 lowered it to match the allocation cap
                # • src clamped to cd_len so OOB reads produce zero-padding
                #   without giant slice indices
                dst  = dst  & f._UINT256_MAX_MEM
                src  = src  & f._UINT256_MAX_MEM
                size = size & f._UINT256_MAX_MEM
                if size == 0:
                    pass  # EVM: no-op, no gas beyond opcode base
                else:
                    safe_size = min(size, f._SAFE_OFFSET_CAP)
                    mem_cost  = f._mem_expand(dst, safe_size)
                    f._use_gas(mem_cost + 3 * ((safe_size + 31) // 32))
                    cd_len    = len(f.calldata)
                    safe_src  = min(src, cd_len)  # clamp to valid calldata range
                    end       = min(safe_src + safe_size, cd_len)
                    chunk     = f.calldata[safe_src:end]
                    if len(chunk) < safe_size:
                        chunk = chunk + b'\x00' * (safe_size - len(chunk))
                    safe_dst  = min(dst, f._SAFE_OFFSET_CAP)
                    f.memory[safe_dst:safe_dst + safe_size] = chunk
            elif op == Op.CODESIZE:
                f.push(len(f.code))
            elif op == Op.CODECOPY:
                dst, src, size = f.pop(), f.pop(), f.pop()
                dst  = dst  & f._UINT256_MAX_MEM
                src  = src  & f._UINT256_MAX_MEM
                size = size & f._UINT256_MAX_MEM
                if size == 0:
                    pass
                else:
                    safe_size = min(size, f._SAFE_OFFSET_CAP)
                    mem_cost  = f._mem_expand(dst, safe_size)
                    f._use_gas(mem_cost + 3 * ((safe_size + 31) // 32))
                    code_len  = len(f.code)
                    safe_src  = min(src, code_len)
                    end       = min(safe_src + safe_size, code_len)
                    chunk     = f.code[safe_src:end]
                    if len(chunk) < safe_size:
                        chunk = chunk + b'\x00' * (safe_size - len(chunk))
                    safe_dst  = min(dst, f._SAFE_OFFSET_CAP)
                    f.memory[safe_dst:safe_dst + safe_size] = chunk
            elif op == Op.GASPRICE:
                f.push(f.gas_price_wei)
            elif op == Op.EXTCODESIZE:
                addr_int = f.pop()
                addr_str = f._int_to_addr(addr_int)
                c = self._storage.get_contract(addr_str)
                if c:
                    code = self._storage.get_contract_code(c["code_hash"]) or b""
                    f.push(len(code) if code else 0)
                else:
                    f.push(0)
            elif op == Op.EXTCODECOPY:
                addr_int, dst, src, size = f.pop(), f.pop(), f.pop(), f.pop()
                addr_str = f._int_to_addr(addr_int)
                c = self._storage.get_contract(addr_str)
                ext_code = b""
                if c:
                    ext_code = self._storage.get_contract_code(c["code_hash"]) or b""
                dst  = dst  & f._UINT256_MAX_MEM
                src  = src  & f._UINT256_MAX_MEM
                size = size & f._UINT256_MAX_MEM
                if size == 0:
                    pass
                else:
                    safe_size = min(size, f._SAFE_OFFSET_CAP)
                    mem_cost  = f._mem_expand(dst, safe_size)
                    f._use_gas(mem_cost + 3 * ((safe_size + 31) // 32))
                    ext_len   = len(ext_code)
                    safe_src  = min(src, ext_len)
                    end       = min(safe_src + safe_size, ext_len)
                    chunk     = ext_code[safe_src:end]
                    if len(chunk) < safe_size:
                        chunk = chunk + b'\x00' * (safe_size - len(chunk))
                    safe_dst  = min(dst, f._SAFE_OFFSET_CAP)
                    f.memory[safe_dst:safe_dst + safe_size] = chunk
            elif op == Op.RETURNDATASIZE:
                f.push(len(f.return_buffer))
            elif op == Op.RETURNDATACOPY:
                dst, src, size = f.pop(), f.pop(), f.pop()
                # RETURNDATACOPY is the one copy opcode that MUST revert on
                # out-of-bounds (EVM spec: src+size > len(return_buffer) →
                # revert).  We still mask inputs to uint256 first to prevent
                # any Python ssize_t crash before the bounds check.
                dst  = dst  & f._UINT256_MAX_MEM
                src  = src  & f._UINT256_MAX_MEM
                size = size & f._UINT256_MAX_MEM
                rb_len = len(f.return_buffer)
                # Use Python arbitrary-precision addition for the bounds check
                # so uint256 values that would wrap ssize_t are caught cleanly.
                if src + size > rb_len:
                    raise RuntimeError("RETURNDATACOPY out of bounds")
                safe_size = min(size, f._SAFE_OFFSET_CAP)
                mem_cost  = f._mem_expand(dst, safe_size)
                f._use_gas(mem_cost + 3 * ((safe_size + 31) // 32))
                safe_src  = min(src, f._SAFE_OFFSET_CAP)
                data      = f.return_buffer[safe_src:safe_src + safe_size]
                safe_dst  = min(dst, f._SAFE_OFFSET_CAP)
                f.memory[safe_dst:safe_dst + safe_size] = data

            # SC-FIX-4: EXTCODEHASH (EIP-1052) — needed by proxy/upgrade patterns
            elif op == Op.EXTCODEHASH:
                addr_int = f.pop()
                addr_str = f._int_to_addr(addr_int)
                c = self._storage.get_contract(addr_str)
                if c and c.get("code_hash"):
                    f.push(int(c["code_hash"][:64], 16), Op.VTYPE_HASH)
                else:
                    f.push(0)  # EOA or non-existent — UINT (0 has no hash meaning)

                        
            # SC-FIX-3: BLOCKHASH was listed in gas table but had no dispatch —
            # any contract using block entropy hit "Unknown opcode 0x40" and reverted.
            elif op == Op.BLOCKHASH:
                n = f.pop()
                ctx = f.block_ctx
                current_height = ctx.index if ctx else 0
                # EVM spec: valid for the 256 most recent blocks (excluding current)
                if n == 0 or n >= current_height or current_height - n > 256:
                    f.push(0)
                else:
                    blk = self._storage.get_block(n)
                    if blk and blk.block_hash:
                        try:
                            f.push(int(blk.block_hash[:64], 16), Op.VTYPE_HASH)
                        except Exception:
                            f.push(0)
                    else:
                        f.push(0)

            elif op == Op.COINBASE:
                ctx = f.block_ctx
                f.push(f._addr_to_int(ctx.miner_address if ctx else ""), Op.VTYPE_ADDRESS)
            elif op == Op.TIMESTAMP:
                # SC-V73-FIX-5: Never fall back to time.time() — wall-clock time
                # is non-deterministic across nodes and would cause divergent
                # execution in any time-gated contract.  Return 0 when block_ctx
                # is absent (e.g. simulate() dry-runs) so the result is the same
                # on every node regardless of when they run the simulation.
                ctx = f.block_ctx
                f.push(ctx.timestamp if ctx else 0)
            elif op == Op.NUMBER:
                ctx = f.block_ctx
                # SC-V73-FIX-5: return 0, not None-triggered AttributeError
                f.push(ctx.index if ctx else 0)
            elif op == Op.DIFFICULTY:
                ctx = f.block_ctx
                # VVM stack values are uint256 integers.  Protocol difficulty
                # is fractional, so expose a deterministic fixed-point value
                # rather than passing a Python float into Frame.push().
                # With no block context use the same deterministic sentinel as
                # the other block-context opcodes.
                f.push(_difficulty_to_vm_uint(ctx.difficulty) if ctx else 0)
            elif op == Op.GASLIMIT:
                f.push(Config.VVM_BLOCK_GAS_LIMIT)
            elif op == Op.CHAINID:
                cid = int(sha256(Config.CHAIN_ID.encode())[:8], 16)
                f.push(cid)
            elif op == Op.SELFBALANCE:
                # Use the same integer satoshi path as BALANCE and include the
                # execution-local value-transfer overlay.
                bal_sat = (self._storage.get_balance_sat(f.address)
                           + int(f.balance_deltas.get(f.address, 0)))
                if bal_sat < 0:
                    raise RuntimeError(f"negative execution balance for {f.address}")
                f.push(bal_sat, Op.VTYPE_SATOSHI)

            elif op == Op.POP:
                f.pop()

            elif op == Op.MLOAD:
                offset = f.pop()
                f.push(f.mload(offset))
            elif op == Op.MSTORE:
                offset, val = f.pop(), f.pop()
                f.mstore(offset, val)
            elif op == Op.MSTORE8:
                offset, val = f.pop(), f.pop()
                f.mstore8(offset, val)

            elif op == Op.SLOAD:
                f.push(f._sload(f.pop()))
            elif op == Op.SSTORE:
                slot = f.pop()
                val, tag = f.pop_typed()
                f._sstore(slot, val, tag)

            elif op == Op.JUMP:
                dest = f.pop()
                # dest is uint256; clamp to _SAFE_OFFSET_CAP before any
                # bytes/list index operation to prevent ssize_t overflow.
                safe_dest = dest if dest <= f._SAFE_OFFSET_CAP else len(code)
                if safe_dest >= len(code) or code[safe_dest] != Op.JUMPDEST:
                    raise RuntimeError(f"Invalid JUMP destination {dest}")
                f.pc = safe_dest
            elif op == Op.JUMPI:
                dest, cond = f.pop(), f.pop()
                if cond:
                    # dest is uint256; clamp to _SAFE_OFFSET_CAP before
                    # bytes indexing to prevent ssize_t overflow.
                    safe_dest = dest if dest <= f._SAFE_OFFSET_CAP else len(code)
                    if safe_dest >= len(code) or code[safe_dest] != Op.JUMPDEST:
                        raise RuntimeError(f"Invalid JUMPI destination {dest}")
                    f.pc = safe_dest
            elif op == Op.PC:
                f.push(f.pc - 1)
            elif op == Op.MSIZE:
                f.push(len(f.memory))
            elif op == Op.GAS:
                f.push(f.gas_remaining)
            elif op == Op.JUMPDEST:
                pass  # marks valid jump target; no side effect

            elif Op.PUSH1 <= op <= Op.PUSH32:
                n_bytes = op - Op.PUSH1 + 1
                raw = code[f.pc:f.pc + n_bytes]
                f.pc += n_bytes
                f.push(int.from_bytes(raw.ljust(n_bytes, b'\x00'), 'big'))

            elif Op.DUP1 <= op <= Op.DUP16:
                idx = op - Op.DUP1  # DUP1 duplicates top (idx=0)
                f.push(f.peek(idx), f.peek_tag(idx))   # preserve type tag
            elif Op.SWAP1 <= op <= Op.SWAP16:
                idx = op - Op.SWAP1 + 1
                if len(f.stack) <= idx:
                    raise RuntimeError("SWAP: stack too shallow")
                # Swap both value and type tag atomically
                f.stack[-1], f.stack[-(idx+1)] = f.stack[-(idx+1)], f.stack[-1]
                f._stack_tags[-1], f._stack_tags[-(idx+1)] = (
                    f._stack_tags[-(idx+1)], f._stack_tags[-1])

            elif Op.LOG0 <= op <= Op.LOG4:
                if f.is_static:
                    raise RuntimeError("LOG in static context forbidden")
                n_topics = op - Op.LOG0
                offset, size = f.pop(), f.pop()
                topics = [f.pop() for _ in range(n_topics)]
                data = f.mslice(offset, size)
                f._use_gas(375 * n_topics + 8 * size)
                f.logs.append({
                    "address": f.address,
                    "topics":  [hex(t) for t in topics],
                    "data":    data.hex(),
                })

            # ── VSD-native opcodes ─────────────────────────────────────────
            elif op == Op.STAKINGBAL:
                addr_int = f.pop()
                addr_str = f._int_to_addr(addr_int)
                role = self._storage.get_role(addr_str)
                stake = role["stake"] if role else 0.0
                # BUG-4 FIX: use to_satoshi() instead of float * 1e8.
                # float * 1e8 can produce off-by-one rounding (e.g.
                # 1.1 * 1e8 → 110000000.00000001 → 110000000 vs stored 110000001).
                f.push(to_satoshi(stake), Op.VTYPE_SATOSHI)
            elif op == Op.VALIDCOUNT:
                validators = self._storage.get_all_by_role("investor")
                f.push(len(validators))           # VTYPE_UINT — plain count
            elif op == Op.VSDBALANCE:
                addr_int = f.pop()
                addr_str = f._int_to_addr(addr_int)
                # Integer satoshi path, including the same execution-local
                # value-transfer overlay used by BALANCE.
                bal_sat = (self._storage.get_balance_sat(addr_str)
                           + int(f.balance_deltas.get(addr_str, 0)))
                if bal_sat < 0:
                    raise RuntimeError(f"negative execution balance for {addr_str}")
                f.push(bal_sat, Op.VTYPE_SATOSHI)

            # SC-FIX-10: New VSD-native opcodes
            elif op == Op.BLOCKFINALIZED:
                # SC-V73-FIX-1: Only query finality for blocks STRICTLY BEFORE
                # the current block being applied.  BFT finality propagates
                # asynchronously — querying the current block or future blocks
                # returns different values on different nodes depending on
                # whether they have received the BFT certificate yet, splitting
                # consensus.  Past blocks are already permanently canonical so
                # their finality status is identical on every honest node.
                target_height = f.pop()
                current_height = f.block_ctx.index if f.block_ctx else 0
                if target_height < current_height:
                    blk = self._storage.get_block(target_height)
                    f.push(1 if (blk and getattr(blk, "finalized", False)) else 0,
                           Op.VTYPE_BOOL)
                else:
                    # Current or future block: deterministically return 0.
                    # Contracts must not make finality-gated decisions based on
                    # the block currently being processed.
                    f.push(0, Op.VTYPE_BOOL)

            elif op == Op.TXSENDER:
                # Push the origin EOA (top-level tx sender) as uint160
                # Explicit alternative to ORIGIN for audit clarity in VSD contracts
                f.push(f._addr_to_int(f.origin), Op.VTYPE_ADDRESS)

            # ── System opcodes ─────────────────────────────────────────────
            # SC-V73-FIX-2 + SC-V73-FIX-6: CREATE opcode
            # Old code called save_contract/save_contract_code directly here,
            # committing the child to the DB even if the parent later reverts.
            # Fix: accumulate in frame.pending_deployments instead.  The block
            # processor flushes pending_deployments only on top-level success.
            # Fix-6: pass parent storage_writes to child so init-code SLOAD sees
            # parent's in-flight writes correctly.
            elif op == Op.CREATE:
                if f.is_static:
                    raise RuntimeError("CREATE in static context forbidden")
                value, offset, size = f.pop(), f.pop(), f.pop()
                init_code = f.mslice(offset, size)
                child_gas = f.gas_remaining - f.gas_remaining // 64
                f._use_gas(f.gas_remaining // 64)
                f._use_gas(32 * ((len(init_code) + 31) // 32))

                # CREATE is deterministic in Visold, but repeated execution of
                # the same CREATE site must still produce distinct addresses.
                # Use an execution-local sequence in addition to the existing
                # creator/bytecode/program-counter material.  This is discarded
                # on parent revert and therefore cannot leak state.
                create_seq = int(f.create_nonce_deltas.get(f.address, 0))
                f.create_nonce_deltas[f.address] = create_seq + 1

                class _StubTx:
                    tx_id     = sha256(
                        f"{init_code.hex()}:{f.address}:{f.pc}:{create_seq}".encode())
                    gas_price = 0.0

                create_addr = "VSDc" + sha256(
                    f"{f.address}:{self._storage.get_nonce(f.address)}:"
                    f"{_StubTx.tx_id}:{create_seq}".encode()
                )[:36]
                pending_balance_deltas = dict(f.balance_deltas)
                if value > 0:
                    effective = (self._storage.get_balance_sat(f.address) +
                                 int(pending_balance_deltas.get(f.address, 0)))
                    if effective < value:
                        f.push(0)
                        gas_used_child = 0
                    else:
                        pending_balance_deltas[f.address] = (
                            pending_balance_deltas.get(f.address, 0) - int(value))
                        pending_balance_deltas[create_addr] = (
                            pending_balance_deltas.get(create_addr, 0) + int(value))
                        gas_used_child = None
                else:
                    gas_used_child = None

                if gas_used_child is None:
                    sub_engine = VVMEngine(self._storage)
                    sub_result = sub_engine.deploy(
                        sender              = f.address,
                        bytecode            = init_code,
                        call_value          = value,
                        gas_limit           = child_gas,
                        block_ctx           = f.block_ctx,
                        tx                  = _StubTx(),
                        parent_storage_writes = dict(f.storage_writes),
                        parent_storage_tags   = dict(f._storage_tags),
                        parent_storage_tag_orig = dict(f._storage_tag_orig),
                        parent_balance_deltas = pending_balance_deltas,
                        parent_create_nonce_deltas = dict(f.create_nonce_deltas),
                        deployed_address     = create_addr,
                    )
                    if sub_result.success and sub_result.contract_addr:
                        f.storage_writes.update(sub_result.storage_writes)
                        f.storage_orig.update(
                            {k: v for k, v in sub_result.storage_orig.items()
                             if k not in f.storage_orig})
                        f._storage_tags.update(sub_result.storage_tags)
                        f._storage_tag_orig.update(
                            {k: v for k, v in sub_result.storage_tag_orig.items()
                             if k not in f._storage_tag_orig})
                        f.balance_deltas = dict(sub_result.balance_deltas)
                        f.create_nonce_deltas = dict(sub_result.create_nonce_deltas)
                        f.touched_contracts.update(sub_result.touched_contracts)
                        f.logs.extend(sub_result.logs)
                        f.self_destruct_transfers.extend(sub_result.self_destruct_transfers)
                        code_hash = sha256(sub_result.return_data)
                        f.pending_deployments.append({
                            "address":       sub_result.contract_addr,
                            "code_hash":     code_hash,
                            "code_bytes":    sub_result.return_data,
                            "creator":       f.address,
                            "created_at":    f.block_ctx.timestamp if f.block_ctx else 0,
                            "contract_name": "",
                        })
                        f.pending_deployments.extend(sub_result.pending_deployments)
                        f.push(f._addr_to_int(sub_result.contract_addr))
                    else:
                        f.push(0)
                    gas_used_child = sub_result.gas_used

                if f.gas_remaining < gas_used_child:
                    f.gas_remaining = 0
                else:
                    f.gas_remaining -= gas_used_child

            # SC-FIX-5: CREATE2 — deterministic contract deployment via salt
            # SC-V73-FIX-2 + SC-V73-FIX-6: same deferred-deployment fix as CREATE.
            elif op == Op.CREATE2:
                if f.is_static:
                    raise RuntimeError("CREATE2 in static context forbidden")
                value, offset, size, salt = f.pop(), f.pop(), f.pop(), f.pop()
                init_code = f.mslice(offset, size)
                child_gas = f.gas_remaining - f.gas_remaining // 64
                f._use_gas(f.gas_remaining // 64)
                f._use_gas(6 * ((len(init_code) + 31) // 32))

                salt_bytes  = salt.to_bytes(32, 'big')
                code_hash   = hashlib.sha256(init_code).hexdigest()
                addr_input  = b"VSDc2" + f.address.encode() + salt_bytes + code_hash.encode()
                contract2_addr = "VSDc" + hashlib.sha256(addr_input).hexdigest()[:36]

                class _StubTx2:
                    tx_id     = hashlib.sha256(addr_input).hexdigest()
                    gas_price = 0.0

                pending_balance_deltas2 = dict(f.balance_deltas)
                if value > 0:
                    effective2 = (self._storage.get_balance_sat(f.address) +
                                  int(pending_balance_deltas2.get(f.address, 0)))
                    if effective2 < value:
                        f.push(0)
                        gas2_child = 0
                    else:
                        pending_balance_deltas2[f.address] = (
                            pending_balance_deltas2.get(f.address, 0) - int(value))
                        pending_balance_deltas2[contract2_addr] = (
                            pending_balance_deltas2.get(contract2_addr, 0) + int(value))
                        gas2_child = None
                else:
                    gas2_child = None

                if gas2_child is None:
                    sub_engine2 = VVMEngine(self._storage)
                    sub_result2 = sub_engine2.deploy(
                        sender              = f.address,
                        bytecode            = init_code,
                        call_value          = value,
                        gas_limit           = child_gas,
                        block_ctx           = f.block_ctx,
                        tx                  = _StubTx2(),
                        parent_storage_writes = dict(f.storage_writes),
                        parent_storage_tags   = dict(f._storage_tags),
                        parent_storage_tag_orig = dict(f._storage_tag_orig),
                        parent_balance_deltas = pending_balance_deltas2,
                        deployed_address      = contract2_addr,
                    )
                    if sub_result2.success and sub_result2.contract_addr:
                        f.storage_writes.update(sub_result2.storage_writes)
                        f.storage_orig.update(
                            {k: v for k, v in sub_result2.storage_orig.items()
                             if k not in f.storage_orig})
                        f._storage_tags.update(sub_result2.storage_tags)
                        f._storage_tag_orig.update(
                            {k: v for k, v in sub_result2.storage_tag_orig.items()
                             if k not in f._storage_tag_orig})
                        f.balance_deltas = dict(sub_result2.balance_deltas)
                        f.touched_contracts.update(sub_result2.touched_contracts)
                        f.logs.extend(sub_result2.logs)
                        f.self_destruct_transfers.extend(sub_result2.self_destruct_transfers)
                        code_hash_hex = sha256(sub_result2.return_data)
                        f.pending_deployments.append({
                            "address":       contract2_addr,
                            "code_hash":     code_hash_hex,
                            "code_bytes":    sub_result2.return_data,
                            "creator":       f.address,
                            "created_at":    f.block_ctx.timestamp if f.block_ctx else 0,
                            "contract_name": "",
                        })
                        f.pending_deployments.extend(sub_result2.pending_deployments)
                        f.push(f._addr_to_int(contract2_addr))
                    else:
                        f.push(0)
                    gas2_child = sub_result2.gas_used

                if f.gas_remaining < gas2_child:
                    f.gas_remaining = 0
                else:
                    f.gas_remaining -= gas2_child

            elif op == Op.CALL or op == Op.CALLCODE:
                gas_param = f.pop()
                addr_int  = f.pop()
                value_    = f.pop()
                in_off    = f.pop()
                in_size   = f.pop()
                out_off   = f.pop()
                out_size  = f.pop()
                calldata_ = f.mslice(in_off, in_size)
                child_gas = min(gas_param, f.gas_remaining - f.gas_remaining // 64)
                f._use_gas(f.gas_remaining // 64)
                callee = f._int_to_addr(addr_int)
                is_delegate = (op == Op.CALLCODE)
                ok, ret = self._internal_call(
                    caller_frame = f,
                    callee_addr  = callee,
                    calldata     = calldata_,
                    call_value   = value_,
                    gas          = child_gas,
                    is_static    = f.is_static,
                    is_delegate  = is_delegate,
                )
                # Write return data to output memory
                if ret and out_size > 0:
                    copy_size = min(len(ret), out_size)
                    mem_cost = f._mem_expand(out_off, out_size)
                    f._use_gas(mem_cost)
                    # SC-FIX-MEM-2: clamp out_off before using as slice index.
                    # out_off was popped from the stack as uint256; without this
                    # clamp a large but valid-looking offset passes _mem_expand
                    # (which rejects only values > _ALLOC_HARD_CAP) yet then
                    # causes an OverflowError or ssize_t crash in the bytearray
                    # slice.  _mem_expand already enforces the cap, so any
                    # out_off that survives it is <= _SAFE_OFFSET_CAP.
                    safe_out_off = min(out_off & f._UINT256_MAX_MEM, f._SAFE_OFFSET_CAP)
                    f.memory[safe_out_off:safe_out_off + copy_size] = ret[:copy_size]
                f.push(1 if ok else 0)

            elif op == Op.DELEGATECALL:
                gas_param = f.pop()
                addr_int  = f.pop()
                in_off    = f.pop()
                in_size   = f.pop()
                out_off   = f.pop()
                out_size  = f.pop()
                calldata_ = f.mslice(in_off, in_size)
                child_gas = min(gas_param, f.gas_remaining - f.gas_remaining // 64)
                f._use_gas(f.gas_remaining // 64)
                callee = f._int_to_addr(addr_int)
                ok, ret = self._internal_call(
                    caller_frame = f,
                    callee_addr  = callee,
                    calldata     = calldata_,
                    call_value   = f.call_value,
                    gas          = child_gas,
                    is_static    = f.is_static,
                    is_delegate  = True,
                )
                if ret and out_size > 0:
                    copy_size = min(len(ret), out_size)
                    mem_cost = f._mem_expand(out_off, out_size)
                    f._use_gas(mem_cost)
                    # SC-FIX-MEM-2: clamp out_off (same fix as CALL above).
                    safe_out_off = min(out_off & f._UINT256_MAX_MEM, f._SAFE_OFFSET_CAP)
                    f.memory[safe_out_off:safe_out_off + copy_size] = ret[:copy_size]
                f.push(1 if ok else 0)

            elif op == Op.STATICCALL:
                gas_param = f.pop()
                addr_int  = f.pop()
                in_off    = f.pop()
                in_size   = f.pop()
                out_off   = f.pop()
                out_size  = f.pop()
                calldata_ = f.mslice(in_off, in_size)
                child_gas = min(gas_param, f.gas_remaining - f.gas_remaining // 64)
                f._use_gas(f.gas_remaining // 64)
                callee = f._int_to_addr(addr_int)
                ok, ret = self._internal_call(
                    caller_frame = f,
                    callee_addr  = callee,
                    calldata     = calldata_,
                    call_value   = 0,
                    gas          = child_gas,
                    is_static    = True,
                )
                if ret and out_size > 0:
                    copy_size = min(len(ret), out_size)
                    mem_cost = f._mem_expand(out_off, out_size)
                    f._use_gas(mem_cost)
                    # SC-FIX-MEM-2: clamp out_off (same fix as CALL/DELEGATECALL).
                    safe_out_off = min(out_off & f._UINT256_MAX_MEM, f._SAFE_OFFSET_CAP)
                    f.memory[safe_out_off:safe_out_off + copy_size] = ret[:copy_size]
                f.push(1 if ok else 0)

            elif op == Op.RETURN:
                offset, size = f.pop(), f.pop()
                f.output  = f.mslice(offset, size)
                f.stopped = True

            elif op == Op.REVERT:
                offset, size = f.pop(), f.pop()
                f.output   = f.mslice(offset, size)
                f.reverted = True

            elif op == Op.SELFDESTRUCT:
                if f.is_static:
                    raise RuntimeError("SELFDESTRUCT in static context forbidden")
                beneficiary_int = f.pop()
                beneficiary     = f._int_to_addr(beneficiary_int)
                # SC-V73-FIX-3: own_balance must include any call_value that was
                # sent to this contract in the current execution but has not yet
                # been credited to the on-chain balance (it's still in-flight as
                # f.call_value).  The live DB balance reflects only committed state.
                # Not including call_value here would make the transfer amount wrong
                # whenever a contract self-destructs in the same call that received
                # value (e.g. a one-shot payment-then-destroy pattern).
                db_balance_sat   = self._storage.get_balance_sat(f.address)
                pending_delta_sat = int(f.balance_deltas.get(f.address, 0))
                own_balance_sat  = db_balance_sat + pending_delta_sat
                if own_balance_sat < 0:
                    raise RuntimeError("SELFDESTRUCT source balance became negative")
                # A contract can be reached more than once during one
                # top-level execution (for example via two sequential CALLs).
                # SELFDESTRUCT is a one-time state transition per source
                # contract in this execution.  The marker is already part of
                # the frame write-set, so use it as the canonical duplicate
                # guard rather than maintaining a second mutable set.
                marker_key = ("__selfdestruct__", f.address)
                if marker_key not in f.storage_writes:
                    if own_balance_sat > 0:
                        # Record the SOURCE as well as the beneficiary.  The
                        # source balance must be debited when the transfer is
                        # materialized; without that debit SELFDESTRUCT mints
                        # the transferred balance.
                        f.self_destruct_transfers.append(
                            (f.address, beneficiary, own_balance_sat))
                f.touched_contracts.add(f.address)
                # Mark contract for destruction (applied by block processor)
                f.storage_writes[marker_key] = 1
                f.stopped = True

            # ── VVM Register File opcodes ──────────────────────────────────
            #
            # All register ops are frame-local.  They operate exclusively on
            # f.registers[0..7] and the stack.  No memory expansion occurs,
            # no storage reads/writes, no static-context violations.
            #
            # RSTORE Rn  (0xC0–0xC7): pop stack top → Rn
            elif Op.RSTORE_R0 <= op <= Op.RSTORE_R7:
                rn = op - Op.RSTORE_R0   # 0..7
                if not f.stack:
                    raise RuntimeError("RSTORE: stack underflow")
                f.registers[rn] = f.pop() & _VMFrame.UINT256_MAX

            # RLOAD Rn  (0xC8–0xCF): push Rn → stack
            elif Op.RLOAD_R0 <= op <= Op.RLOAD_R7:
                rn = op - Op.RLOAD_R0    # 0..7
                f.push(f.registers[rn])  # already uint256-masked on store

            # RMOV Rn ← Rm  (0xD0–0xD7): register-to-register copy.
            # The source register index (0–7) is encoded in the byte
            # immediately following the opcode (1-byte immediate operand).
            # This mirrors PUSH<N>'s immediate-byte convention in the VVM
            # but operates entirely within the register file.
            elif Op.RMOV_R0 <= op <= Op.RMOV_R7:
                rn = op - Op.RMOV_R0     # destination register 0..7
                # Read and advance past the 1-byte source-register operand
                if f.pc >= len(code):
                    raise RuntimeError("RMOV: missing source register operand")
                rm = code[f.pc] & 0x07   # source register 0..7
                f.pc += 1
                f.registers[rn] = f.registers[rm]

            # RADD Rn  (0xD8–0xDF): pop a (top), pop b → Rn = (a+b) mod 2^256.
            # Equivalent to ADD + RSTORE but cheaper than two separate ops.
            elif Op.RADD_R0 <= op <= Op.RADD_R7:
                rn = op - Op.RADD_R0     # 0..7
                if len(f.stack) < 2:
                    raise RuntimeError("RADD: stack underflow (need 2 values)")
                a = f.pop()
                b = f.pop()
                f.registers[rn] = (a + b) & _VMFrame.UINT256_MAX

            # RSWAP Rn  (0xE0–0xE7): atomic exchange stack top ↔ register Rn.
            # Equivalent to RSTORE Rn; RLOAD Rn (old value) but in one opcode
            # without an intermediate stack slot.
            elif Op.RSWAP_R0 <= op <= Op.RSWAP_R7:
                rn = op - Op.RSWAP_R0    # 0..7
                if not f.stack:
                    raise RuntimeError("RSWAP: stack underflow")
                old_reg = f.registers[rn]
                f.registers[rn] = f.stack[-1] & _VMFrame.UINT256_MAX
                f.stack[-1] = old_reg    # old_reg is already masked

            # RCLEAR  (0xE8): zero all 8 registers atomically.
            # Useful as a security hygiene op before returning from a sensitive
            # computation to ensure no register state leaks to the caller.
            elif op == Op.RCLEAR:
                f.registers = [0] * 8

            # RPUSH_ALL  (0xE9): push R0..R7 onto stack.
            # R0 is pushed first so R7 ends up on top.
            # Stack must have room for 8 additional values.
            elif op == Op.RPUSH_ALL:
                if len(f.stack) + 8 > Config.VVM_MAX_STACK_DEPTH:
                    raise RuntimeError("RPUSH_ALL: stack overflow (need 8 free slots)")
                for reg_val in f.registers:          # R0 first → R7 last (R7 on top)
                    f.push(reg_val)                  # registers are tagless → VTYPE_UINT

            # RPOP_ALL  (0xEA): pop 8 values from stack into R7..R0.
            # Stack top → R7, next → R6, …, bottom of group → R0.
            # This pairs naturally with RPUSH_ALL: a RPUSH_ALL followed
            # (after some computation) by RPOP_ALL restores all registers.
            elif op == Op.RPOP_ALL:
                if len(f.stack) < 8:
                    raise RuntimeError("RPOP_ALL: stack underflow (need 8 values)")
                # Pop in reverse order so that the top-of-stack goes into R7
                for rn in range(7, -1, -1):
                    f.registers[rn] = f.stack.pop() & _VMFrame.UINT256_MAX
                    f._stack_tags.pop()   # drain parallel tag list

            # ── VVM Typed Value System opcodes ────────────────────────────
            #
            # TYPEOF  (0xEB): push type tag of current stack top (non-destructive)
            elif op == Op.TYPEOF:
                if not f.stack:
                    raise RuntimeError("TYPEOF: stack underflow")
                tag = f.peek_tag(0)
                f.push(tag)              # tag pushed as VTYPE_UINT (it's a number)

            # TYPEASSERT (0xEC): pop expected_tag; inspect NEW top; revert on mismatch
            elif op == Op.TYPEASSERT:
                if len(f.stack) < 2:
                    raise RuntimeError("TYPEASSERT: need at least 2 stack values")
                expected = f.pop() & 0x07    # consume the expected-tag argument
                actual   = f.peek_tag(0)     # inspect current top without popping it
                if actual != expected:
                    raise RuntimeError(
                        f"type mismatch: expected tag {expected} "
                        f"but stack top has tag {actual}")

            # TYPESET (0xED): pop tag literal; re-tag stack top with it
            elif op == Op.TYPESET:
                if len(f.stack) < 2:
                    raise RuntimeError("TYPESET: need at least 2 stack values")
                new_tag = f.pop() & 0x07     # consume the tag argument
                f.set_top_tag(new_tag)       # re-tag stack top in-place

            # TYPECHECK (0xEE): pop expected_tag; push 1 if matches, 0 if not
            # Non-reverting predicate — lets contracts branch on type.
            elif op == Op.TYPECHECK:
                if len(f.stack) < 2:
                    raise RuntimeError("TYPECHECK: need at least 2 stack values")
                expected = f.pop() & 0x07
                actual   = f.peek_tag(0)
                f.push(1 if actual == expected else 0, Op.VTYPE_BOOL)

            # TYPEDLOAD (0xEF): SLOAD + restore stored type tag
            # Reads value and its persisted tag from _storage_tags.
            # If no tag was stored (old data), defaults to VTYPE_UINT.
            elif op == Op.TYPEDLOAD:
                slot = f.pop()
                val  = f._sload(slot)
                slot_hex = hex(slot & _VMFrame.UINT256_MAX)
                key  = (f.address, slot_hex)
                # Consult frame-local tag writes first, then persisted storage tags.
                stored_tag = f._get_storage_tag(key)
                f.push(val, stored_tag)

            # ── VVM Native Time-Lock opcodes ──────────────────────────────
            #
            # All three guards read the current block height from block_ctx.
            # If block_ctx is absent (simulate() dry-runs) height is 0, which
            # means AFTER 0 passes, BEFORE 0 reverts, WINDOW 0 N passes only
            # if N > 0.  This is deterministic and safe for offline simulation.
            #
            # AFTER height (0xF6): revert if current_block < height
            elif op == Op.AFTER:
                height = f.pop() & _VMFrame.UINT256_MAX
                current = f.block_ctx.index if f.block_ctx else 0
                if current < height:
                    raise RuntimeError(
                        f"AFTER guard failed: current block {current} "
                        f"< required {height}")

            # BEFORE height (0xF7): revert if current_block >= height
            elif op == Op.BEFORE:
                height = f.pop() & _VMFrame.UINT256_MAX
                current = f.block_ctx.index if f.block_ctx else 0
                if current >= height:
                    raise RuntimeError(
                        f"BEFORE guard failed: current block {current} "
                        f">= deadline {height}")

            # WINDOW start end (0xF8): revert if current_block outside [start, end)
            # Stack layout: end is on top, start is below it.
            elif op == Op.WINDOW:
                end   = f.pop() & _VMFrame.UINT256_MAX  # top
                start = f.pop() & _VMFrame.UINT256_MAX  # below top
                current = f.block_ctx.index if f.block_ctx else 0
                if start >= end:
                    raise RuntimeError(
                        f"WINDOW guard invalid: start {start} >= end {end}")
                if current < start or current >= end:
                    raise RuntimeError(
                        f"WINDOW guard failed: current block {current} "
                        f"outside [{start}, {end})")

            # BLOCKAGE (0xF9): push current block height as VTYPE_UINT
            # Named alias for NUMBER, optimised for use with time-lock guards.
            elif op == Op.BLOCKAGE:
                current = f.block_ctx.index if f.block_ctx else 0
                f.push(current)   # VTYPE_UINT — plain block height integer

            # ── VVM Native State Channel opcodes ──────────────────────────
            # Signature recovery and state-message helpers are module-level
            # functions: _chan_recover_address() and _chan_state_msg()
            # defined just above VVMEngine._run().

            # ── CHAN_OPEN (0xFB) ───────────────────────────────────────────
            elif op == Op.CHAN_OPEN:
                # Static-call guard — channel open mutates state
                if f.is_static:
                    raise RuntimeError(
                        "CHAN_OPEN: not allowed in static context")
                # Pop stack: counterparty_addr, deposit_sat, timeout_blocks
                if len(f.stack) < 3:
                    raise RuntimeError("CHAN_OPEN: stack underflow (need 3)")
                counterparty_int  = f.pop()
                deposit_sat       = f.pop()
                timeout_raw       = f.pop()
                # Validate block context
                if not f.block_ctx:
                    f.push(0); f._use_gas(0)  # gas already charged above
                else:
                    current_height = f.block_ctx.index
                    caller_str     = f._int_to_addr(
                                         f._addr_to_int(f.caller))
                    counter_str    = f._int_to_addr(counterparty_int)
                    # Edge case: self-channel
                    if caller_str == counter_str:
                        f.push(0)
                    # Edge case: zero deposit
                    elif deposit_sat == 0:
                        f.push(0)
                    # Edge case: insufficient balance
                    elif self._storage.get_balance_sat(caller_str) < deposit_sat:
                        f.push(0)
                    else:
                        # Clamp timeout to sane range [10, 50_000]
                        timeout_blocks = max(10, min(50_000, timeout_raw))
                        # Check duplicate open channel between this pair
                        existing = self._storage.get_open_channel_between(
                            caller_str, counter_str, f.address)
                        if existing is not None:
                            f.push(0)
                        else:
                            # Derive channel_id deterministically
                            raw_id = (f"{caller_str}:{counter_str}:"
                                      f"{current_height}:{f.address}")
                            channel_id = sha256(raw_id.encode())
                            # Debit caller's balance.  This is a direct
                            # persistent balance mutation, so capture it in
                            # the execution journal before changing it.
                            self._storage._record_state_channel_balance_before(caller_str)
                            ok = self._storage.debit_sat(caller_str, deposit_sat)
                            if not ok:
                                f.push(0)
                            else:
                                created = self._storage.create_channel(
                                    channel_id, f.address,
                                    caller_str, counter_str,
                                    deposit_sat, timeout_blocks,
                                    current_height)
                                if created:
                                    # Return channel_id as uint256
                                    chan_int = int(channel_id, 16) & _VMFrame.UINT256_MAX
                                    f.push(chan_int)
                                else:
                                    # DB insert failed — refund and push 0.
                                    # The balance journal already captured the
                                    # pre-debit value, so a later VM revert is
                                    # still exactly reversible.
                                    self._storage.credit_sat(caller_str, deposit_sat)
                                    f.push(0)
                    # Extra gas for force-close path (base already charged)
                    f._use_gas(0)

            # ── CHAN_CLOSE (0xFC) ──────────────────────────────────────────
            elif op == Op.CHAN_CLOSE:
                if f.is_static:
                    raise RuntimeError(
                        "CHAN_CLOSE: not allowed in static context")
                if len(f.stack) < 5:
                    raise RuntimeError("CHAN_CLOSE: stack underflow (need 5)")
                channel_id_int   = f.pop()
                final_bal_caller = f.pop()
                final_bal_counter= f.pop()
                sig_r            = f.pop()
                sig_s            = f.pop()

                # Convert channel_id int → hex string (64 hex chars)
                channel_id = format(channel_id_int & _VMFrame.UINT256_MAX, '064x')
                ch = self._storage.get_channel(channel_id)

                def _chan_close_fail():
                    f.push(0, Op.VTYPE_BOOL)

                if ch is None:
                    _chan_close_fail()
                elif ch["status"] != "OPEN":
                    _chan_close_fail()
                else:
                    caller_str = f._int_to_addr(f._addr_to_int(f.caller))
                    # Caller must be opener or counterparty
                    if caller_str not in (ch["opener"], ch["counterparty"]):
                        _chan_close_fail()
                    # Conservation: final balances must equal total deposit
                    elif final_bal_caller < 0 or final_bal_counter < 0:
                        _chan_close_fail()
                    elif (final_bal_caller + final_bal_counter
                          != ch["total_deposit_sat"]):
                        _chan_close_fail()
                    else:
                        # Determine counterparty (the other party from caller)
                        if caller_str == ch["opener"]:
                            signer_addr = ch["counterparty"]
                            bal_opener  = final_bal_caller
                            bal_counter = final_bal_counter
                        else:
                            signer_addr = ch["opener"]
                            bal_opener  = final_bal_counter
                            bal_counter = final_bal_caller
                        # Build and verify cooperative-close message
                        # Signed blob: sha256("CLOSE:" || channel_id ||
                        #              ":" || bal_opener || ":" || bal_counter)
                        close_blob = (
                            f"CLOSE:{channel_id}:{bal_opener}:{bal_counter}"
                        ).encode()
                        msg_hash_b = hashlib.sha256(close_blob).digest()
                        # Try v=27 and v=28 (standard Ethereum convention)
                        recovered = ""
                        for v_try in (27, 28):
                            r = sig_r & _VMFrame.UINT256_MAX
                            s = sig_s & _VMFrame.UINT256_MAX
                            addr_try = _chan_recover_address(
                                msg_hash_b, v_try, r, s)
                            if addr_try == signer_addr:
                                recovered = addr_try
                                break
                        if recovered != signer_addr:
                            _chan_close_fail()
                        else:
                            cur_h = f.block_ctx.index if f.block_ctx else 0
                            closed = self._storage.close_channel(
                                channel_id, cur_h)
                            if not closed:
                                _chan_close_fail()
                            else:
                                # Settle balances.  Capture both recipients
                                # before the direct credits so a containing
                                # VM frame can revert atomically.
                                self._storage._record_state_channel_balance_before(ch["opener"])
                                self._storage._record_state_channel_balance_before(ch["counterparty"])
                                self._storage.credit_sat(ch["opener"],   bal_opener)
                                self._storage.credit_sat(ch["counterparty"], bal_counter)
                                f._use_gas(0)   # extra gas already in base
                                f.push(1, Op.VTYPE_BOOL)

            # ── CHAN_DISPUTE (0xFE) ────────────────────────────────────────
            elif op == Op.CHAN_DISPUTE:
                if f.is_static:
                    raise RuntimeError(
                        "CHAN_DISPUTE: not allowed in static context")
                if len(f.stack) < 6:
                    raise RuntimeError("CHAN_DISPUTE: stack underflow (need 6)")
                channel_id_int = f.pop()
                seq_no         = f.pop()
                bal_caller     = f.pop()
                bal_counter    = f.pop()
                sig_r          = f.pop()
                sig_s          = f.pop()

                channel_id = format(
                    channel_id_int & _VMFrame.UINT256_MAX, '064x')
                ch = self._storage.get_channel(channel_id)
                cur_h = f.block_ctx.index if f.block_ctx else 0

                def _chan_dispute_fail():
                    f.push(0, Op.VTYPE_BOOL)

                if ch is None:
                    _chan_dispute_fail()
                elif ch["status"] not in ("OPEN", "DISPUTED"):
                    _chan_dispute_fail()
                else:
                    caller_str = f._int_to_addr(f._addr_to_int(f.caller))
                    if caller_str not in (ch["opener"], ch["counterparty"]):
                        _chan_dispute_fail()

                    # ── Force-close path (channel already DISPUTED) ───────
                    elif ch["status"] == "DISPUTED":
                        timeout_expired = (
                            cur_h >= ch["dispute_height"] + ch["timeout_blocks"])
                        if not timeout_expired:
                            _chan_dispute_fail()
                        else:
                            # Extra gas for force-close (settle balances)
                            f._use_gas(2000)
                            ok = self._storage.force_close_channel(
                                channel_id, cur_h)
                            if not ok:
                                _chan_dispute_fail()
                            else:
                                self._storage._record_state_channel_balance_before(ch["opener"])
                                self._storage._record_state_channel_balance_before(ch["counterparty"])
                                self._storage.credit_sat(
                                    ch["opener"],
                                    ch["dispute_bal_opener"])
                                self._storage.credit_sat(
                                    ch["counterparty"],
                                    ch["dispute_bal_counter"])
                                f.push(1, Op.VTYPE_BOOL)  # 1 = force-closed

                    # ── Raise dispute path (channel OPEN) ─────────────────
                    else:
                        # seq_no must be strictly greater than existing dispute
                        if seq_no <= ch["dispute_seq"] and ch["dispute_seq"] > 0:
                            _chan_dispute_fail()
                        # Balance conservation
                        elif bal_caller < 0 or bal_counter < 0:
                            _chan_dispute_fail()
                        elif bal_caller + bal_counter != ch["total_deposit_sat"]:
                            _chan_dispute_fail()
                        else:
                            # Determine which party's sig we're verifying
                            if caller_str == ch["opener"]:
                                signer_addr = ch["counterparty"]
                                bal_opener  = bal_caller
                                bal_ctr     = bal_counter
                            else:
                                signer_addr = ch["opener"]
                                bal_opener  = bal_counter
                                bal_ctr     = bal_caller
                            # Build state-update message
                            msg_hash_b = _chan_state_msg(
                                channel_id, seq_no, bal_opener, bal_ctr)
                            # Verify counterparty signature (try v=27,28)
                            recovered = ""
                            for v_try in (27, 28):
                                r = sig_r & _VMFrame.UINT256_MAX
                                s = sig_s & _VMFrame.UINT256_MAX
                                addr_try = _chan_recover_address(
                                    msg_hash_b, v_try, r, s)
                                if addr_try == signer_addr:
                                    recovered = addr_try
                                    break
                            if recovered != signer_addr:
                                _chan_dispute_fail()
                            else:
                                raised = self._storage.raise_dispute(
                                    channel_id, seq_no,
                                    bal_opener, bal_ctr, cur_h)
                                if not raised:
                                    _chan_dispute_fail()
                                else:
                                    f.push(2, Op.VTYPE_BOOL)  # 2 = dispute raised

            else:
                raise RuntimeError(f"Unknown opcode 0x{op:02X}")
