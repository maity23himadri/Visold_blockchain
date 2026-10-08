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
"""visold.vm.opcodes

Original section: SECTION 7B: VVM — VISOLD VIRTUAL MACHINE

Defines: Op
Origin: visold_vsd_.py L19206-19607, L19611-19670, L19673-19676, L19681, L19684-19687
"""




# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7B: VVM — VISOLD VIRTUAL MACHINE
# Production-grade stack-based deterministic smart contract engine.
# Architecture mirrors EVM: stack(256-bit words), memory(byte-addressable),
# persistent storage(key→value), gas metering, sandboxed execution.
# ─────────────────────────────────────────────────────────────────────────────

# ── Opcode definitions ────────────────────────────────────────────────────────
class Op:
    """VVM opcode constants (one byte each, 0x00–0xFF)."""
    # Arithmetic
    STOP        = 0x00
    ADD         = 0x01
    MUL         = 0x02
    SUB         = 0x03
    DIV         = 0x04
    SDIV        = 0x05
    MOD         = 0x06
    SMOD        = 0x07
    ADDMOD      = 0x08
    MULMOD      = 0x09
    EXP         = 0x0A
    SIGNEXTEND  = 0x0B
    # Comparison
    LT          = 0x10
    GT          = 0x11
    SLT         = 0x12
    SGT         = 0x13
    EQ          = 0x14
    ISZERO      = 0x15
    # Bitwise
    AND         = 0x16
    OR          = 0x17
    XOR         = 0x18
    NOT         = 0x19
    BYTE        = 0x1A
    SHL         = 0x1B
    SHR         = 0x1C
    SAR         = 0x1D
    # Crypto
    SHA3        = 0x20
    # Environment
    ADDRESS     = 0x30
    BALANCE     = 0x31
    ORIGIN      = 0x32
    CALLER      = 0x33
    CALLVALUE   = 0x34
    CALLDATALOAD= 0x35
    CALLDATASIZE= 0x36
    CALLDATACOPY= 0x37
    CODESIZE    = 0x38
    CODECOPY    = 0x39
    GASPRICE    = 0x3A
    EXTCODESIZE = 0x3B
    EXTCODECOPY = 0x3C
    RETURNDATASIZE=0x3D
    RETURNDATACOPY=0x3E
    EXTCODEHASH = 0x3F   # SC-FIX-4: EIP-1052 — hash of external contract code
    # Block info
    BLOCKHASH   = 0x40
    COINBASE    = 0x41
    TIMESTAMP   = 0x42
    NUMBER      = 0x43
    DIFFICULTY  = 0x44
    GASLIMIT    = 0x45
    CHAINID     = 0x46
    SELFBALANCE = 0x47
    # Stack
    POP         = 0x50
    # Memory
    MLOAD       = 0x51
    MSTORE      = 0x52
    MSTORE8     = 0x53
    # Storage
    SLOAD       = 0x54
    SSTORE      = 0x55
    # Control flow
    JUMP        = 0x56
    JUMPI       = 0x57
    PC          = 0x58
    MSIZE       = 0x59
    GAS         = 0x5A
    JUMPDEST    = 0x5B
    # Push operations (PUSH1..PUSH32) — all individual constants required so
    # that _build_mnemonic_table (which iterates dir(Op)) registers every
    # mnemonic.  PUSH1 and PUSH32 are also kept as the range sentinels used
    # by the existing range checks (Op.PUSH1 <= opcode <= Op.PUSH32).
    PUSH1       = 0x60
    PUSH2       = 0x61
    PUSH3       = 0x62
    PUSH4       = 0x63
    PUSH5       = 0x64
    PUSH6       = 0x65
    PUSH7       = 0x66
    PUSH8       = 0x67
    PUSH9       = 0x68
    PUSH10      = 0x69
    PUSH11      = 0x6A
    PUSH12      = 0x6B
    PUSH13      = 0x6C
    PUSH14      = 0x6D
    PUSH15      = 0x6E
    PUSH16      = 0x6F
    PUSH17      = 0x70
    PUSH18      = 0x71
    PUSH19      = 0x72
    PUSH20      = 0x73
    PUSH21      = 0x74
    PUSH22      = 0x75
    PUSH23      = 0x76
    PUSH24      = 0x77
    PUSH25      = 0x78
    PUSH26      = 0x79
    PUSH27      = 0x7A
    PUSH28      = 0x7B
    PUSH29      = 0x7C
    PUSH30      = 0x7D
    PUSH31      = 0x7E
    PUSH32      = 0x7F
    # Dup operations (DUP1..DUP16) — all individual constants for mnemonic table
    DUP1        = 0x80
    DUP2        = 0x81
    DUP3        = 0x82
    DUP4        = 0x83
    DUP5        = 0x84
    DUP6        = 0x85
    DUP7        = 0x86
    DUP8        = 0x87
    DUP9        = 0x88
    DUP10       = 0x89
    DUP11       = 0x8A
    DUP12       = 0x8B
    DUP13       = 0x8C
    DUP14       = 0x8D
    DUP15       = 0x8E
    DUP16       = 0x8F
    # Swap operations (SWAP1..SWAP16) — all individual constants for mnemonic table
    SWAP1       = 0x90
    SWAP2       = 0x91
    SWAP3       = 0x92
    SWAP4       = 0x93
    SWAP5       = 0x94
    SWAP6       = 0x95
    SWAP7       = 0x96
    SWAP8       = 0x97
    SWAP9       = 0x98
    SWAP10      = 0x99
    SWAP11      = 0x9A
    SWAP12      = 0x9B
    SWAP13      = 0x9C
    SWAP14      = 0x9D
    SWAP15      = 0x9E
    SWAP16      = 0x9F
    # Log operations
    LOG0        = 0xA0
    LOG1        = 0xA1
    LOG2        = 0xA2
    LOG3        = 0xA3
    LOG4        = 0xA4
    # VSD-native opcodes (blockchain-aware)
    STAKINGBAL  = 0xB0   # push staking balance of address on stack
    VALIDCOUNT  = 0xB1   # push current active validator count (read-only)
    VSDBALANCE  = 0xB2   # push VSD balance of address (same as BALANCE but explicit)
    BLOCKFINALIZED = 0xB3  # SC-FIX-10: push 1 if block at height is BFT-finalized
    TXSENDER    = 0xB4   # SC-FIX-10: push origin EOA as uint160
    # ── VVM Register File (R0–R7) ─────────────────────────────────────────
    # 8 general-purpose 256-bit registers, frame-local.
    # Registers are isolated per call frame — child calls start with all
    # registers zeroed; parent registers are never visible to callees and
    # are never modified by a callee's RSTORE/RMOV/RSWAP operations.
    #
    # RSTORE Rn  (0xC0–0xC7): pop stack top → register Rn
    # RLOAD  Rn  (0xC8–0xCF): push register Rn → stack top
    # RMOV   Rn,Rm (0xD0–0xD7): copy register Rm → register Rn
    #   operand byte (0–7) selects source register Rm
    # RADD   Rn  (0xD8–0xDF): pop two stack values, add, result → Rn
    # RSWAP  Rn  (0xE0–0xE7): exchange register Rn with stack top (atomic)
    # RCLEAR     (0xE8):       zero all 8 registers in one instruction
    # RPUSH_ALL  (0xE9):       push R0..R7 onto stack in order (R0 first)
    # RPOP_ALL   (0xEA):       pop 8 values from stack into R7..R0 in order
    #
    # Gas costs are deliberately cheaper than memory ops:
    #   RSTORE / RLOAD / RSWAP : 1 gas  (no memory expansion)
    #   RMOV                   : 1 gas
    #   RADD                   : 2 gas  (arithmetic + store)
    #   RCLEAR                 : 3 gas  (8 zeroes at once)
    #   RPUSH_ALL / RPOP_ALL   : 8 gas  (8 stack ops bundled)
    #
    # Encoding range chosen to avoid all current and near-future EVM opcode
    # assignments (0xB5–0xBF are also free but kept as VSD-native expansion
    # space; 0xC0–0xEA are the register file).
    RSTORE_R0   = 0xC0
    RSTORE_R1   = 0xC1
    RSTORE_R2   = 0xC2
    RSTORE_R3   = 0xC3
    RSTORE_R4   = 0xC4
    RSTORE_R5   = 0xC5
    RSTORE_R6   = 0xC6
    RSTORE_R7   = 0xC7
    RLOAD_R0    = 0xC8
    RLOAD_R1    = 0xC9
    RLOAD_R2    = 0xCA
    RLOAD_R3    = 0xCB
    RLOAD_R4    = 0xCC
    RLOAD_R5    = 0xCD
    RLOAD_R6    = 0xCE
    RLOAD_R7    = 0xCF
    # RMOV Rn ← Rm: destination encoded in opcode byte (D0+n),
    # source register index (0–7) in the immediately following operand byte.
    RMOV_R0     = 0xD0
    RMOV_R1     = 0xD1
    RMOV_R2     = 0xD2
    RMOV_R3     = 0xD3
    RMOV_R4     = 0xD4
    RMOV_R5     = 0xD5
    RMOV_R6     = 0xD6
    RMOV_R7     = 0xD7
    # RADD Rn: pop a,b from stack; Rn = (a + b) & UINT256_MAX
    RADD_R0     = 0xD8
    RADD_R1     = 0xD9
    RADD_R2     = 0xDA
    RADD_R3     = 0xDB
    RADD_R4     = 0xDC
    RADD_R5     = 0xDD
    RADD_R6     = 0xDE
    RADD_R7     = 0xDF
    # RSWAP Rn: exchange stack top ↔ register Rn (atomic, no intermediate)
    RSWAP_R0    = 0xE0
    RSWAP_R1    = 0xE1
    RSWAP_R2    = 0xE2
    RSWAP_R3    = 0xE3
    RSWAP_R4    = 0xE4
    RSWAP_R5    = 0xE5
    RSWAP_R6    = 0xE6
    RSWAP_R7    = 0xE7
    RCLEAR      = 0xE8   # zero all 8 registers atomically
    RPUSH_ALL   = 0xE9   # push R0..R7 onto stack (R0 pushed first → R7 on top)
    RPOP_ALL    = 0xEA   # pop 8 values: stack top → R7, next → R6, …, → R0
    # ── VVM Typed Value System (0xEB–0xEF) ───────────────────────────────────
    # Every VVM stack slot carries a hidden 3-bit type tag alongside its
    # 256-bit value.  Type tags are managed by the VM — contracts read and
    # assert them but never forge them.
    #
    # Type tag constants (also exposed as Op attributes for assembler use):
    #   VTYPE_UINT    = 0  — generic 256-bit unsigned integer (default)
    #   VTYPE_ADDRESS = 1  — VSD address encoded as uint160
    #   VTYPE_BOOL    = 2  — boolean: only 0 or 1 are valid
    #   VTYPE_SATOSHI = 3  — VSD amount in atov (atomic) units
    #   VTYPE_HASH    = 4  — SHA-256 output (32-byte digest as uint256)
    #
    # TYPEOF    (0xEB): push the type tag (0–4) of the current stack top
    #                   as a VTYPE_UINT value.  Does NOT pop the value.
    # TYPEASSERT(0xEC): pop one value (the expected type tag 0–4), then
    #                   inspect the NEW stack top's tag; REVERT with reason
    #                   "type mismatch" if they differ.  Consumes the tag
    #                   argument but leaves the inspected value on stack.
    # TYPESET   (0xED): pop a type-tag literal (0–4) and re-tag the current
    #                   stack top with that type.  Used by the VM internally
    #                   when native opcodes produce typed results; also
    #                   available to contracts for explicit casting.
    # TYPECHECK (0xEE): like TYPEASSERT but does NOT revert — pushes 1 if
    #                   tag matches, 0 if not (non-destructive predicate).
    # TYPEDLOAD (0xEF): SLOAD variant that also restores the stored type tag
    #                   (type tags are persisted alongside values in storage).
    TYPEOF      = 0xEB
    TYPEASSERT  = 0xEC
    TYPESET     = 0xED
    TYPECHECK   = 0xEE
    TYPEDLOAD   = 0xEF
    # Type tag numeric constants — exposed on Op so VASM source can write
    # "PUSH1 Op.VTYPE_ADDRESS" symbolically.
    VTYPE_UINT    = 0
    VTYPE_ADDRESS = 1
    VTYPE_BOOL    = 2
    VTYPE_SATOSHI = 3
    VTYPE_HASH    = 4
    # System
    CREATE      = 0xF0
    CALL        = 0xF1
    CALLCODE    = 0xF2
    RETURN      = 0xF3
    DELEGATECALL= 0xF4
    CREATE2     = 0xF5   # SC-FIX-5: deterministic contract deployment
    # ── VVM Native Time-Lock opcodes (0xF6–0xF9) ─────────────────────────
    # Time-lock guards expressed as single opcodes — cheaper and more
    # auditable than manual JUMPI+NUMBER patterns.  All three revert with
    # a descriptive reason string if the block-height condition is NOT met,
    # so execution simply does not proceed past the guard.
    #
    # AFTER  height (0xF6): revert if current block < height
    #   "This code may only run at or after block <height>"
    #   Pop: height (uint256, treated as block index)
    #   Push: nothing  — guard only; no stack residue
    #   Gas: 8  (cheaper than equivalent JUMPI pattern: ~18 gas)
    #
    # BEFORE height (0xF7): revert if current block >= height
    #   "This code may only run before block <height>"
    #   Pop: height
    #   Push: nothing
    #   Gas: 8
    #
    # WINDOW start end (0xF8): revert if current block outside [start, end)
    #   "This code may only run in block range [start, end)"
    #   Pop: end (top), start (next) — end popped first, start second
    #   Push: nothing
    #   Gas: 12  (two comparisons)
    #
    # BLOCKAGE (0xF9): push the current block height as VTYPE_UINT.
    #   Alias for NUMBER but named for use alongside time-lock guards.
    #   Contracts can store BLOCKAGE result in a register and compare
    #   with AFTER/BEFORE without touching memory.
    #   Gas: 2  (same as NUMBER)
    AFTER       = 0xF6
    BEFORE      = 0xF7
    WINDOW      = 0xF8
    BLOCKAGE    = 0xF9
    STATICCALL  = 0xFA
    # ── VVM Native State Channel opcodes (0xFB, 0xFC, 0xFE) ──────────────────
    # State channels allow two parties to exchange signed off-chain state
    # updates and only touch the blockchain on open, cooperative-close, or
    # dispute.  Making these VM-native means:
    #   • The node enforces channel rules — no exploitable contract logic needed.
    #   • Gas cost is a flat fee, not a recursive Solidity execution.
    #   • Channel state is stored in a dedicated SQLite table with indexed
    #     lookups, not in expensive contract storage slots.
    #
    # ── CHAN_OPEN (0xFB) ──────────────────────────────────────────────────────
    # Opens a new payment channel between the contract's caller and a
    # counterparty address, locking a deposit from the caller.
    #
    # Stack (top → bottom when CHAN_OPEN executes):
    #   [0] counterparty_addr  — uint160 address of the other party
    #   [1] deposit_sat        — satoshi amount caller locks into channel
    #   [2] timeout_blocks     — dispute window in blocks (min 10, max 50 000)
    #
    # Pops: 3 values
    # Pushes: channel_id (uint256) — unique ID derived from
    #         sha256(caller || counterparty || block_height || contract_addr)
    #         or 0 on failure (insufficient balance, duplicate channel, bad args)
    # Gas: 5000  (comparable to SSTORE × 5 — creates DB row + debits balance)
    #
    # Edge cases handled in dispatch:
    #   • caller == counterparty         → push 0 (no self-channels)
    #   • deposit_sat == 0               → push 0 (zero deposits rejected)
    #   • deposit_sat > caller balance   → push 0 (insufficient funds)
    #   • timeout_blocks < 10            → clamped to 10
    #   • timeout_blocks > 50 000        → clamped to 50 000
    #   • channel already open between same pair + contract → push 0
    #   • block_ctx absent (simulate)    → push 0 (cannot open without height)
    #   • STATICCALL context             → reverts (state-mutating)
    #
    # ── CHAN_CLOSE (0xFC) ─────────────────────────────────────────────────────
    # Cooperatively closes an open channel.  Both parties' final balances are
    # settled on-chain.  Requires a valid cooperative-close signature from
    # the counterparty.
    #
    # Stack (top → bottom):
    #   [0] channel_id        — uint256 channel identifier
    #   [1] final_bal_caller  — satoshi owed to the opener (caller)
    #   [2] final_bal_counter — satoshi owed to the counterparty
    #   [3] sig_r             — uint256 r component of counterparty's signature
    #   [4] sig_s             — uint256 s component of counterparty's signature
    #
    # Pops: 5 values
    # Pushes: 1 if closed successfully, 0 on failure
    # Gas: 8000  (DB update + two balance credits + signature verification)
    #
    # Edge cases:
    #   • channel not found              → push 0
    #   • channel not OPEN               → push 0 (already closed/disputed)
    #   • caller is not opener or counterparty → push 0
    #   • final_bal_caller + final_bal_counter != channel.total_deposit_sat
    #                                    → push 0 (conservation violation)
    #   • either final balance < 0       → push 0
    #   • counterparty signature invalid → push 0
    #   • STATICCALL context             → reverts
    #
    # ── CHAN_DISPUTE (0xFE) ───────────────────────────────────────────────────
    # Raises a dispute on an open channel by submitting a signed state update.
    # The submitter claims the counterparty is unresponsive or dishonest.
    # After timeout_blocks blocks the channel can be force-closed with the
    # disputed state by calling CHAN_DISPUTE again on the same channel_id.
    #
    # First call (raise dispute):
    # Stack (top → bottom):
    #   [0] channel_id        — uint256 channel identifier
    #   [1] seq_no            — sequence number of the state being submitted
    #   [2] bal_caller        — satoshi claimed by caller in this state
    #   [3] bal_counter       — satoshi claimed by counterparty in this state
    #   [4] sig_r             — uint256 r of counterparty's signature on state
    #   [5] sig_s             — uint256 s of counterparty's signature on state
    #
    # Pops: 6 values
    # Pushes: 2 = dispute raised, 1 = force-close executed (timeout expired),
    #         0 = failure
    # Gas: 10000 (first call); 12000 (force-close call — also credits balances)
    #
    # Edge cases:
    #   • channel not found / not OPEN   → push 0
    #   • caller not a channel party     → push 0
    #   • seq_no <= existing dispute seq → push 0 (replay of old state)
    #   • bal_caller + bal_counter != total_deposit → push 0
    #   • signature invalid              → push 0
    #   • Force-close: timeout not yet expired → push 0
    #   • STATICCALL context             → reverts
    CHAN_OPEN    = 0xFB
    CHAN_CLOSE   = 0xFC
    CHAN_DISPUTE = 0xFE
    REVERT      = 0xFD
    SELFDESTRUCT= 0xFF


# ── Gas costs (per opcode / operation) ───────────────────────────────────────
_GAS = {
    Op.STOP:          0,
    Op.ADD:           3,    Op.MUL:        5,    Op.SUB:       3,
    Op.DIV:           5,    Op.SDIV:       5,    Op.MOD:       5,
    Op.SMOD:          5,    Op.ADDMOD:     8,    Op.MULMOD:    8,
    Op.EXP:           10,   Op.SIGNEXTEND: 5,
    Op.LT:            3,    Op.GT:         3,    Op.SLT:       3,
    Op.SGT:           3,    Op.EQ:         3,    Op.ISZERO:    3,
    Op.AND:           3,    Op.OR:         3,    Op.XOR:       3,
    Op.NOT:           3,    Op.BYTE:       3,    Op.SHL:       3,
    Op.SHR:           3,    Op.SAR:        3,
    Op.SHA3:          30,
    Op.ADDRESS:       2,    Op.BALANCE:    100,  Op.ORIGIN:    2,
    Op.CALLER:        2,    Op.CALLVALUE:  2,    Op.CALLDATALOAD: 3,
    Op.CALLDATASIZE:  2,    Op.CALLDATACOPY: 3,  Op.CODESIZE:  2,
    Op.CODECOPY:      3,    Op.GASPRICE:   2,    Op.EXTCODESIZE: 100,
    Op.EXTCODECOPY:   100,  Op.RETURNDATASIZE: 2, Op.RETURNDATACOPY: 3,
    Op.EXTCODEHASH:   100,  # SC-FIX-4: EIP-1052
    Op.BLOCKHASH:     20,   Op.COINBASE:   2,    Op.TIMESTAMP: 2,
    Op.NUMBER:        2,    Op.DIFFICULTY: 2,    Op.GASLIMIT:  2,
    Op.CHAINID:       2,    Op.SELFBALANCE: 5,
    Op.POP:           2,
    Op.MLOAD:         3,    Op.MSTORE:     3,    Op.MSTORE8:   3,
    Op.SLOAD:         100,  Op.SSTORE:     0,   # SSTORE gas computed dynamically
    Op.JUMP:          8,    Op.JUMPI:      10,   Op.PC:        2,
    Op.MSIZE:         2,    Op.GAS:        2,    Op.JUMPDEST:  1,
    Op.LOG0:          375,  Op.LOG1:       375,  Op.LOG2:      375,
    Op.LOG3:          375,  Op.LOG4:       375,
    Op.STAKINGBAL:    100,  Op.VALIDCOUNT: 20,   Op.VSDBALANCE: 100,
    Op.BLOCKFINALIZED: 50,  Op.TXSENDER:   2,    # SC-FIX-10
    # Register file gas costs (cheaper than memory — no expansion overhead)
    Op.RCLEAR:    3,   Op.RPUSH_ALL: 8,   Op.RPOP_ALL: 8,
    # Typed Value System gas costs
    Op.TYPEOF:    2,   Op.TYPEASSERT: 3,  Op.TYPESET:  2,
    Op.TYPECHECK: 3,   Op.TYPEDLOAD:  103,
    # Native Time-Lock gas costs
    Op.AFTER:     8,   Op.BEFORE:     8,  Op.WINDOW:   12,
    Op.BLOCKAGE:  2,
    # Native State Channel gas costs
    Op.CHAN_OPEN:    5000,   # create channel row + debit deposit
    Op.CHAN_CLOSE:   8000,   # verify sig + settle two balances
    Op.CHAN_DISPUTE: 10000,  # verify sig + update dispute state (force-close = 12000 charged in dispatch)  # 100 (SLOAD) + 3 (type restore)
    Op.CREATE:        32000, Op.CALL:      0,    Op.CALLCODE:  0,
    Op.STATICCALL:    0,     Op.RETURN:    0,
    Op.DELEGATECALL:  0,    Op.CREATE2:    32000, # SC-FIX-5
    Op.REVERT:        0,    Op.SELFDESTRUCT: 5000,
}


# PUSH1..PUSH32 all cost 3; DUP1..DUP16 cost 3; SWAP1..SWAP16 cost 3
for _oc in range(Op.PUSH1, Op.PUSH32 + 1):  _GAS[_oc] = 3


for _oc in range(Op.DUP1,  Op.DUP16  + 1):  _GAS[_oc] = 3


for _oc in range(Op.SWAP1, Op.SWAP16  + 1):  _GAS[_oc] = 3


# Register file: RSTORE_R0..R7 = 1 gas, RLOAD_R0..R7 = 1 gas
for _oc in range(Op.RSTORE_R0, Op.RSTORE_R7 + 1): _GAS[_oc] = 1


for _oc in range(Op.RLOAD_R0,  Op.RLOAD_R7  + 1): _GAS[_oc] = 1


# RMOV_R0..R7 = 1 gas (register-to-register copy)
for _oc in range(Op.RMOV_R0,  Op.RMOV_R7   + 1): _GAS[_oc] = 1


# RADD_R0..R7 = 2 gas (pop two stack values, add, store in register)
for _oc in range(Op.RADD_R0,  Op.RADD_R7   + 1): _GAS[_oc] = 2


# RSWAP_R0..R7 = 1 gas (atomic exchange stack top ↔ register)
for _oc in range(Op.RSWAP_R0, Op.RSWAP_R7  + 1): _GAS[_oc] = 1


# SSTORE gas tiers (EIP-2929/EIP-3529 simplified)
_SSTORE_SET_GAS    = 20000   # slot goes 0 → nonzero


_SSTORE_RESET_GAS  = 5000    # slot nonzero → different nonzero


_SSTORE_CLEAR_GAS  = 5000    # slot nonzero → 0 (with refund)


_SSTORE_REFUND     = 15000   # gas refunded when clearing a slot


# SC-FIX-2: Gas refund cap (EIP-3529) — refund cannot exceed gas_used // 5.
# Without this cap, a contract clearing many storage slots accumulates unbounded
# refund, making its net gas cost negative and enabling near-free computation.
_GAS_REFUND_DENOMINATOR = 5


# Memory expansion cost: 3 gas per word (32 bytes) + quadratic
def _mem_expansion_cost(old_words: int, new_words: int) -> int:
    def _cost(w):
        return 3 * w + (w * w) // 512
    return max(0, _cost(new_words) - _cost(old_words))
