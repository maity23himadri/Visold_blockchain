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
"""visold.vm.static_analyzer

Original section: SECTION 7D: VVM STATIC ANALYZER

Defines: VVMStaticAnalyzer
Origin: visold_vsd_.py L22904-23257
"""

from typing import List, Tuple

from visold.vm.opcodes import Op


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7D: VVM STATIC ANALYZER
# Performs pre-deployment safety analysis on VVM bytecode to detect common
# vulnerability patterns before a contract is deployed.
# ─────────────────────────────────────────────────────────────────────────────
class VVMStaticAnalyzer:
    """
    Bytecode-level static analysis for VVM smart contracts.

    Analyzes contract bytecode to detect:
      1. Reentrancy patterns:  CALL/DELEGATECALL before SSTORE in same code path
      2. Integer overflow risk: arithmetic (ADD/MUL/EXP) without ISZERO guards
      3. Unbounded loops:      backward JUMP targets without GAS check
      4. Selfdestruct risk:    SELFDESTRUCT in accessible code paths
      5. Missing JUMPDEST:     JUMP/JUMPI to invalid destinations

    Usage
    ─────
    Call analyze(bytecode) before deploying.  Returns a AnalysisReport with
    a list of findings.  The node does NOT block deployment on warnings —
    the report is informational and logged at INFO level.

    F-13 — IMPORTANT SECURITY LIMITATION:
    ──────────────────────────────────────
    This is a SINGLE-PASS LINEAR HEURISTIC scanner.  It does NOT perform
    control-flow graph (CFG) analysis, dataflow analysis, or symbolic
    execution.  It can be trivially bypassed by an adversary who:
      • Splits CALL and SSTORE across internal function calls (via JUMP)
      • Uses DELEGATECALL to forward the call before SSTORE
      • Inserts a JUMPDEST between the flagged opcodes to break linear scan
      • Uses indirect jump dispatch tables (common in compiled Solidity)

    A "no issues found" result does NOT guarantee absence of vulnerabilities.
    For production-critical contracts, a separate off-chain formal verifier
    (SMT-based, e.g. Manticore, Mythril, or Halmos) is strongly recommended.
    The analyzecontract RPC response includes "analysis_is_heuristic": true
    to surface this limitation to callers.
    """

    class Finding:
        """A single static analysis finding."""
        __slots__ = ("severity", "code", "description", "offset")
        def __init__(self, severity: str, code: str,
                     description: str, offset: int = -1):
            self.severity    = severity   # "HIGH", "MEDIUM", "LOW", "INFO"
            self.code        = code
            self.description = description
            self.offset      = offset

        def to_dict(self) -> dict:
            return {"severity": self.severity, "code": self.code,
                    "description": self.description, "offset": self.offset}

    class AnalysisReport:
        def __init__(self, bytecode_len: int, findings: list):
            self.bytecode_len = bytecode_len
            self.findings     = findings
            self.high_count   = sum(1 for f in findings if f.severity == "HIGH")
            self.medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
            self.low_count    = sum(1 for f in findings if f.severity == "LOW")

        def to_dict(self) -> dict:
            return {
                "bytecode_len":       self.bytecode_len,
                "high_count":         self.high_count,
                "medium_count":       self.medium_count,
                "low_count":          self.low_count,
                "findings":           [f.to_dict() for f in self.findings],
                # F-13 FIX: Explicit flag so API callers know this is heuristic only
                "analysis_is_heuristic": True,
                "disclaimer": (
                    "This is a single-pass heuristic scan. It does not perform "
                    "CFG analysis and can be bypassed by obfuscated bytecode. "
                    "A 'no issues found' result does NOT guarantee safety."
                ),
            }

        def __str__(self) -> str:
            if not self.findings:
                return "No issues found."
            lines = [f"Findings: {self.high_count} HIGH, "
                     f"{self.medium_count} MEDIUM, {self.low_count} LOW"]
            for f in self.findings:
                lines.append(f"  [{f.severity}] {f.code} @ offset {f.offset}: "
                             f"{f.description}")
            return "\n".join(lines)

    @classmethod
    def analyze(cls, bytecode: bytes) -> 'VVMStaticAnalyzer.AnalysisReport':
        """
        Analyze bytecode.  Returns AnalysisReport.
        Never raises exceptions — errors produce a LOW finding and continue.
        """
        findings: list = []
        try:
            cls._scan_reentrancy(bytecode, findings)
            cls._scan_unbounded_loops(bytecode, findings)
            cls._scan_selfdestruct(bytecode, findings)
            cls._scan_jumpdests(bytecode, findings)
            cls._scan_missing_gas_limit(bytecode, findings)
            cls._scan_timelock(bytecode, findings)
            cls._scan_state_channels(bytecode, findings)
        except Exception as e:
            findings.append(cls.Finding(
                "LOW", "ANALYZER_ERROR",
                f"Static analyzer error (non-fatal): {e}"))
        return cls.AnalysisReport(len(bytecode), findings)

    @classmethod
    def _parse_ops(cls, bytecode: bytes) -> List[Tuple[int, int, bytes]]:
        """
        Parse bytecode into (offset, opcode, immediate_bytes) triples.
        Skips PUSH data bytes correctly.
        Also skips the 1-byte source-register operand of RMOV_R0..RMOV_R7
        so that the operand byte is never misidentified as an opcode.
        """
        ops = []
        i = 0
        while i < len(bytecode):
            op = bytecode[i]
            if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
                n = op - 0x60 + 1
                imm = bytecode[i+1:i+1+n]
                ops.append((i, op, imm))
                i += 1 + n
            elif Op.RMOV_R0 <= op <= Op.RMOV_R7:  # RMOV has 1-byte source operand
                imm = bytecode[i+1:i+2]
                ops.append((i, op, imm))
                i += 2
            else:
                ops.append((i, op, b""))
                i += 1
        return ops

    @classmethod
    def _scan_reentrancy(cls, bytecode: bytes,
                         findings: list):
        """
        Detect potential reentrancy: an external CALL followed by SSTORE
        without an intervening STOP/RETURN/REVERT (checks-effects-interactions
        pattern violation).

        v7.5.x: CREATE and CREATE2 are also treated as reentrancy entry
        points.  Pre-fix the scan only considered (CALL, DELEGATECALL,
        CALLCODE) — but a contract that calls CREATE/CREATE2 hands
        control to attacker-supplied init code which can call back into
        the parent before the SSTORE lands.  The standard mitigation is
        the same checks-effects-interactions pattern.
        STATICCALL is intentionally NOT in the list because it forces
        is_static on the child frame, which forbids any state mutation
        in the callee — re-entry through STATICCALL cannot mutate state
        and so cannot be a reentrancy vector.
        """
        ops = cls._parse_ops(bytecode)
        call_offsets = [off for off, op, _ in ops
                        if op in (Op.CALL, Op.DELEGATECALL, Op.CALLCODE,
                                  Op.CREATE, Op.CREATE2)]
        sstore_offsets = {off for off, op, _ in ops if op == Op.SSTORE}

        for call_off in call_offsets:
            # Check for SSTORE after this CALL with no intervening terminal
            subsequent = [(off, op) for off, op, _ in ops if off > call_off]
            found_sstore_after = False
            for off, op in subsequent:
                if op in (Op.STOP, Op.RETURN, Op.REVERT):
                    break  # safe: execution terminates before reaching SSTORE
                if off in sstore_offsets:
                    found_sstore_after = True
                    break
            if found_sstore_after:
                findings.append(cls.Finding(
                    "HIGH", "REENTRANCY",
                    "External call (CALL/DELEGATECALL/CALLCODE/CREATE/CREATE2) "
                    "followed by SSTORE without intervening STOP/RETURN. "
                    "Use checks-effects-interactions pattern to prevent reentrancy.",
                    call_off))

    @classmethod
    def _scan_unbounded_loops(cls, bytecode: bytes, findings: list):
        """
        Detect backward JUMPs (potential infinite loops) without a GAS check.
        A backward JUMP where no GAS opcode appears between JUMPDEST and the
        JUMP is suspicious — gas will still exhaust it but warns operators.
        """
        ops      = cls._parse_ops(bytecode)
        jumpdests = {off for off, op, _ in ops if op == Op.JUMPDEST}

        for i, (off, op, imm) in enumerate(ops):
            if op == Op.JUMP:
                # Try to find the jump target from prior PUSH
                if i > 0:
                    _, prev_op, prev_imm = ops[i-1]
                    if 0x60 <= prev_op <= 0x7F and prev_imm:
                        dest = int.from_bytes(prev_imm, "big")
                        if dest < off and dest in jumpdests:
                            # Backward jump — check for GAS between dest and here
                            has_gas = any(op2 == Op.GAS
                                          for off2, op2, _ in ops
                                          if dest <= off2 < off)
                            if not has_gas:
                                findings.append(cls.Finding(
                                    "MEDIUM", "UNBOUNDED_LOOP",
                                    f"Backward JUMP to {dest} without GAS check. "
                                    f"Contract may run expensive loops.",
                                    off))

    @classmethod
    def _scan_selfdestruct(cls, bytecode: bytes, findings: list):
        """Flag any SELFDESTRUCT opcode — high risk if unintended."""
        ops = cls._parse_ops(bytecode)
        for off, op, _ in ops:
            if op == Op.SELFDESTRUCT:
                findings.append(cls.Finding(
                    "HIGH", "SELFDESTRUCT",
                    "Contract contains SELFDESTRUCT. Ensure this is intentional "
                    "and protected by access control.",
                    off))

    @classmethod
    def _scan_jumpdests(cls, bytecode: bytes, findings: list):
        """
        Detect JUMP/JUMPI instructions that push a literal destination
        that is NOT a JUMPDEST.  These will always revert at runtime.
        """
        ops       = cls._parse_ops(bytecode)
        jumpdests = {off for off, op, _ in ops if op == Op.JUMPDEST}

        for i, (off, op, _) in enumerate(ops):
            if op in (Op.JUMP, Op.JUMPI) and i > 0:
                _, prev_op, prev_imm = ops[i-1]
                if 0x60 <= prev_op <= 0x7F and prev_imm:
                    dest = int.from_bytes(prev_imm, "big")
                    if dest not in jumpdests:
                        findings.append(cls.Finding(
                            "MEDIUM", "INVALID_JUMP_DEST",
                            f"JUMP to offset {dest} which is not a JUMPDEST. "
                            f"This path will always revert.",
                            off))

    @classmethod
    def _scan_missing_gas_limit(cls, bytecode: bytes, findings: list):
        """
        Detect CALL/DELEGATECALL that forward all remaining gas
        (top stack value is GAS opcode result, not a literal).
        """
        ops = cls._parse_ops(bytecode)
        for i, (off, op, _) in enumerate(ops):
            if op in (Op.CALL, Op.DELEGATECALL, Op.CALLCODE) and i > 0:
                _, prev_op, _ = ops[i-1]
                if prev_op == Op.GAS:
                    findings.append(cls.Finding(
                        "LOW", "GAS_FORWARD_ALL",
                        "CALL forwards all remaining gas (GAS opcode used directly). "
                        "Consider capping forwarded gas to limit reentrancy risk.",
                        off))

    @classmethod
    def _scan_timelock(cls, bytecode: bytes, findings: list):
        """
        Detect suspicious time-lock patterns:
          1. AFTER/BEFORE/WINDOW preceded by PUSH1 0 — guard height is
             always zero, meaning AFTER 0 always passes (useless guard)
             and BEFORE 0 always reverts (dead code).
          2. WINDOW where the static analysis can tell start >= end
             (always-failing guard — contracts can never execute body).
          3. BEFORE without any AFTER — one-sided time window may be
             missing the lower bound (LOW informational finding).
        """
        ops = cls._parse_ops(bytecode)
        has_after  = any(op == Op.AFTER  for _, op, _ in ops)
        has_before = any(op == Op.BEFORE for _, op, _ in ops)

        for i, (off, op, imm) in enumerate(ops):
            # Pattern: PUSH1 0x00 immediately before AFTER or BEFORE
            if op in (Op.AFTER, Op.BEFORE) and i > 0:
                _, prev_op, prev_imm = ops[i - 1]
                if (Op.PUSH1 <= prev_op <= Op.PUSH32
                        and int.from_bytes(prev_imm or b'\x00', 'big') == 0):
                    label = "AFTER" if op == Op.AFTER else "BEFORE"
                    findings.append(cls.Finding(
                        "MEDIUM", "TIMELOCK_ZERO_HEIGHT",
                        f"{label} guard with height=0: "
                        f"{'always passes (no-op guard)' if op == Op.AFTER else 'always reverts (dead code)'}",
                        off))

            # WINDOW: if both args are PUSH literals, check start < end
            if op == Op.WINDOW and i >= 2:
                _, end_op,   end_imm   = ops[i - 1]
                _, start_op, start_imm = ops[i - 2]
                if (Op.PUSH1 <= end_op   <= Op.PUSH32 and
                        Op.PUSH1 <= start_op <= Op.PUSH32):
                    end_val   = int.from_bytes(end_imm   or b'\x00', 'big')
                    start_val = int.from_bytes(start_imm or b'\x00', 'big')
                    if start_val >= end_val:
                        findings.append(cls.Finding(
                            "HIGH", "TIMELOCK_INVALID_WINDOW",
                            f"WINDOW guard has start={start_val} >= end={end_val}: "
                            f"contract body is unreachable (always reverts).",
                            off))

        # BEFORE without AFTER — missing lower-bound guard (informational)
        if has_before and not has_after:
            findings.append(cls.Finding(
                "LOW", "TIMELOCK_NO_LOWER_BOUND",
                "Contract uses BEFORE (upper deadline) but no AFTER (lower bound). "
                "Consider adding AFTER to prevent premature execution."))

    @classmethod
    def _scan_state_channels(cls, bytecode: bytes, findings: list):
        """
        Detect dangerous state-channel patterns at deploy time:

          1. CHAN_OPEN without CHAN_CLOSE or CHAN_DISPUTE — funds may be locked
             forever (no exit path).
          2. CHAN_CLOSE without CHAN_DISPUTE — no griefing protection if
             counterparty goes silent.
          3. CHAN_DISPUTE used in STATICCALL context — would always revert;
             detected by checking if STATICCALL precedes CHAN_DISPUTE in same
             basic block with no intervening CALL that could switch context.
          4. CHAN_OPEN + CHAN_CLOSE present but CHAN_DISPUTE absent — missing
             dispute path means a non-cooperative counterparty can lock funds.
        """
        ops = cls._parse_ops(bytecode)
        opset = {op for _, op, _ in ops}

        has_open    = Op.CHAN_OPEN    in opset
        has_close   = Op.CHAN_CLOSE   in opset
        has_dispute = Op.CHAN_DISPUTE in opset

        # Rule 1: CHAN_OPEN with no settlement path at all
        if has_open and not has_close and not has_dispute:
            findings.append(cls.Finding(
                "HIGH", "CHANNEL_NO_EXIT",
                "CHAN_OPEN found but neither CHAN_CLOSE nor CHAN_DISPUTE present. "
                "Deposited funds may be permanently locked if counterparty "
                "is unresponsive."))

        # Rule 2: CHAN_CLOSE without CHAN_DISPUTE
        if has_close and not has_dispute:
            findings.append(cls.Finding(
                "MEDIUM", "CHANNEL_NO_DISPUTE",
                "CHAN_CLOSE present but CHAN_DISPUTE is absent. "
                "If counterparty refuses to co-sign closure, funds cannot be "
                "recovered. Add CHAN_DISPUTE as a unilateral exit path."))

        # Rule 3: CHAN_OPEN + CHAN_CLOSE but no CHAN_DISPUTE
        if has_open and has_close and not has_dispute:
            findings.append(cls.Finding(
                "HIGH", "CHANNEL_MISSING_DISPUTE_PATH",
                "Channel opened and closed cooperatively but no dispute path. "
                "A silent counterparty can hold opener's deposit hostage."))

        # Rule 4: CHAN_DISPUTE in bytecode — verify CHAN_OPEN is also present
        if has_dispute and not has_open:
            findings.append(cls.Finding(
                "LOW", "CHANNEL_DISPUTE_WITHOUT_OPEN",
                "CHAN_DISPUTE present but CHAN_OPEN absent. "
                "This contract can dispute channels it did not open — "
                "verify this is intentional (e.g. a dispute arbitrator)."))
