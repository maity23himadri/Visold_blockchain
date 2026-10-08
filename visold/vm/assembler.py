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
"""visold.vm.assembler

Original section: SECTION 7B2: VASM ASSEMBLER

Defines: AssemblyResult, VVMAssembler
Origin: visold_vsd_.py L22142-22156, L22159-22593
"""

import re as _re
import struct as _struct
from dataclasses import dataclass as _dataclass, field as _field
from typing import Dict as _Dict, List as _List

from visold.kernel.config import Config
from visold.vm.opcodes import Op


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7B2: VASM ASSEMBLER
# Translates human-readable VASM (VVM Assembly) source into raw VVM bytecode.
#
# VASM is a simple line-oriented assembly language for the Visold Virtual
# Machine.  One mnemonic per line; operands follow the mnemonic separated by
# whitespace.  Labels, comments, and data literals are supported.
#
# SYNTAX REFERENCE
# ────────────────
#   ; comment                        — rest of line ignored
#   .label_name:                     — define a jump destination label
#   PUSH1  0x2A                      — push one byte (decimal or 0x hex)
#   PUSH4  3735928559                — push four bytes
#   PUSH32 0xDEAD...BEEF             — push 32 bytes (pad-left with zeros)
#   JUMP   .loop                     — PUSH4 of label offset + JUMP opcode
#   JUMPI  .exit                     — PUSH4 of label offset + JUMPI opcode
#   ADD / MUL / SSTORE / …          — any other Op mnemonic, no operand
#   STAKINGBAL / VALIDCOUNT / …     — VSD-native opcodes
#
# USAGE
# ─────
#   src = """
#       ; simple counter contract — store(0, callvalue)
#       CALLVALUE
#       PUSH1 0x00
#       SSTORE
#       STOP
#   """
#   asm    = VVMAssembler()
#   result = asm.assemble(src)          # AssemblyResult
#   if result.ok:
#       hex_bytecode = result.hex       # pass this as tx["data"] for TYPE_DEPLOY
#   else:
#       print(result.errors)
#
# DISASSEMBLY
# ───────────
#   listing = VVMAssembler.disassemble(bytes.fromhex(hex_bytecode))
#   print(listing)
# ─────────────────────────────────────────────────────────────────────────────



@_dataclass
class AssemblyResult:
    """Returned by VVMAssembler.assemble()."""
    ok:       bool
    bytecode: bytes         = b""
    hex:      str           = ""
    errors:   _List[str]    = _field(default_factory=list)
    warnings: _List[str]    = _field(default_factory=list)
    # source map: bytecode offset → (line_number, mnemonic)
    source_map: _Dict[int, tuple] = _field(default_factory=dict)

    def __repr__(self):
        if self.ok:
            return f"<AssemblyResult ok bytes={len(self.bytecode)}>"
        return f"<AssemblyResult FAILED errors={self.errors}>"


class VVMAssembler:
    """
    VASM → VVM bytecode assembler for the Visold Virtual Machine.

    Two-pass assembler:
      Pass 1 — tokenise source, resolve sizes, build a preliminary layout so
               label offsets can be calculated.
      Pass 2 — emit final bytecode with all forward-reference labels resolved.

    Thread-safety: each assemble() call is stateless; the instance holds no
    mutable state between calls.
    """

    # ── Opcode name → (opcode_byte, operand_bytes) ──────────────────────────
    # operand_bytes == 0  → no immediate operand (standard opcodes)
    # operand_bytes == N  → PUSH<N>, assembler reads N bytes from the source
    # JUMP / JUMPI are special: if followed by a label they auto-emit a PUSH4
    _MNEMONIC_TABLE: _Dict[str, tuple] = {}

    @classmethod
    def _build_mnemonic_table(cls) -> None:
        if cls._MNEMONIC_TABLE:
            return  # already built

        # Pull every name from Op that maps to an int opcode
        for name in dir(Op):
            if name.startswith("_"):
                continue
            val = getattr(Op, name)
            if not isinstance(val, int):
                continue
            opcode = val & 0xFF
            # PUSH1..PUSH32 carry an implicit operand length
            if Op.PUSH1 <= opcode <= Op.PUSH32:
                n_bytes = opcode - Op.PUSH1 + 1
                cls._MNEMONIC_TABLE[name] = (opcode, n_bytes)
            # DUP1..DUP16, SWAP1..SWAP16 have no immediate operand
            else:
                cls._MNEMONIC_TABLE[name] = (opcode, 0)

    # ── Token types ──────────────────────────────────────────────────────────
    _TK_MNEMONIC  = "MNEMONIC"
    _TK_LABEL_DEF = "LABEL_DEF"    # .name:
    _TK_LABEL_REF = "LABEL_REF"    # .name  (operand of JUMP/JUMPI)
    _TK_LITERAL   = "LITERAL"      # 0x... or decimal integer
    _TK_COMMENT   = "COMMENT"

    # ── Regex helpers ────────────────────────────────────────────────────────
    _RE_LABEL_DEF  = _re.compile(r"^\s*\.([A-Za-z_][A-Za-z0-9_]*):\s*$")
    _RE_LABEL_REF  = _re.compile(r"^\.([ A-Za-z_][A-Za-z0-9_]*)$")
    _RE_HEX_LIT    = _re.compile(r"^0[xX][0-9A-Fa-f]+$")
    _RE_DEC_LIT    = _re.compile(r"^-?\d+$")
    _RE_COMMENT    = _re.compile(r";.*$")

    # ── JUMP/JUMPI auto-label handling ───────────────────────────────────────
    # These opcodes get a PUSH4 of the target address inserted automatically
    # when followed by a label reference.  The total cost is 5 bytes (PUSH4 +
    # 4-byte offset + the JUMP/JUMPI byte itself).
    _JUMP_OPS = {"JUMP", "JUMPI"}

    # RMOV_R0..RMOV_R7 each require a 1-byte immediate operand (source reg 0–7).
    # The assembler reads the next token as a register name "R0".."R7" and
    # encodes it as a single byte following the opcode.
    _RMOV_OPS = {f"RMOV_R{n}" for n in range(8)}

    def assemble(self, source: str) -> AssemblyResult:
        """
        Assemble *source* VASM text into VVM bytecode.

        Returns an AssemblyResult; always succeeds structurally (errors are
        collected rather than raising).

        IR node kinds used internally:
          "opcode"     — plain opcode with pre-encoded immediate bytes
          "label_def"  — label definition, emits zero bytes
          "label_push" — JUMP/JUMPI preceded by an auto-emitted PUSH4;
                         size = 6 (PUSH4[1] + offset[4] + jump_op[1])
          "push_label" — PUSH<N> whose operand is a label reference;
                         size = 1 + N where N is the PUSH width (fixed at
                         parse time so label offsets can be computed before
                         the label's value is known)
        """
        self._build_mnemonic_table()
        errors:   _List[str] = []
        warnings: _List[str] = []

        # ── Pass 1: tokenise & build intermediate representation ─────────────
        ir: list = []

        lines = source.splitlines()
        for lineno, raw_line in enumerate(lines, start=1):
            # Strip inline comments
            line = self._RE_COMMENT.sub("", raw_line).strip()
            if not line:
                continue

            # Label definition?  (.name: on its own line)
            m = self._RE_LABEL_DEF.match(line)
            if m:
                ir.append({"kind": "label_def", "name": m.group(1), "line": lineno})
                continue

            # Split into tokens
            tokens = line.split()
            mnem = tokens[0].upper()
            rest = tokens[1:]

            if mnem not in self._MNEMONIC_TABLE:
                errors.append(f"Line {lineno}: unknown mnemonic '{tokens[0]}'")
                continue

            opcode, operand_bytes = self._MNEMONIC_TABLE[mnem]

            # ── PUSH<N> — may have a literal OR a label reference ────────────
            if operand_bytes > 0:
                if not rest:
                    errors.append(
                        f"Line {lineno}: {mnem} requires a {operand_bytes}-byte operand")
                    continue

                raw_val = rest[0]

                # ── PUSH<N> .label  (label reference as PUSH operand) ────────
                # The size of the emitted instruction is fixed (1 + operand_bytes)
                # because the programmer chose the specific PUSH width; the
                # label's numeric value is substituted in Pass 2.
                if raw_val.startswith("."):
                    label_name = raw_val[1:]  # strip leading '.'
                    ir.append({"kind": "push_label",
                               "op": opcode,
                               "operand_bytes": operand_bytes,
                               "label": label_name,
                               "line": lineno,
                               "mnem": mnem})
                    continue

                # ── PUSH<N> with a numeric literal ───────────────────────────
                val_int, err = self._parse_literal(raw_val, lineno)
                if err:
                    errors.append(err)
                    continue

                # Auto-upgrade: if the value is too large for the requested
                # PUSH width, find the smallest PUSHn (1..32) that fits and
                # silently use it instead of raising an error.  This handles
                # the common "PUSH1 256" mistake without breaking the contract.
                if val_int < 0:
                    # Two's-complement: compute signed value in the requested
                    # width (same as _int_to_bytes) then check it fits.
                    val_masked = val_int & ((1 << (operand_bytes * 8)) - 1)
                    fits_in_requested = True   # masking always fits
                    actual_bytes = operand_bytes
                    val_int = val_masked
                else:
                    fits_in_requested = val_int < (1 << (operand_bytes * 8))
                    if not fits_in_requested:
                        # Find smallest n in 1..32 such that val_int fits
                        actual_bytes = None
                        for n in range(1, 33):
                            if val_int < (1 << (n * 8)):
                                actual_bytes = n
                                break
                        if actual_bytes is None:
                            errors.append(
                                f"Line {lineno}: value {val_int} exceeds "
                                f"maximum 32-byte PUSH operand range")
                            continue
                        upgraded_mnem = f"PUSH{actual_bytes}"
                        warnings.append(
                            f"Line {lineno}: {mnem} operand {val_int} does "
                            f"not fit in {operand_bytes} byte(s); "
                            f"upgraded to {upgraded_mnem}")
                        opcode = Op.PUSH1 + (actual_bytes - 1)
                        operand_bytes = actual_bytes
                    else:
                        actual_bytes = operand_bytes

                try:
                    operand = self._int_to_bytes(val_int, actual_bytes)
                except OverflowError:
                    errors.append(
                        f"Line {lineno}: value {val_int} does not fit in "
                        f"{actual_bytes} byte(s) for {mnem}")
                    continue
                ir.append({"kind": "opcode", "op": opcode,
                           "operand": operand, "line": lineno, "mnem": mnem})

            # ── JUMP / JUMPI with a label reference ─────────────────────────
            # Emits PUSH4 <offset> JUMP/JUMPI automatically (existing behaviour).
            elif mnem in self._JUMP_OPS and rest and rest[0].startswith("."):
                label_name = rest[0][1:]  # strip leading '.'
                ir.append({"kind": "label_push", "label": label_name,
                           "line": lineno, "mnem": mnem, "op": opcode})

            # ── RMOV Rn Rm — register-to-register copy with 1-byte immediate ─
            # Syntax: RMOV_R0 R3   (copy R3 → R0)
            # The source register token must be "R0".."R7".
            elif mnem in self._RMOV_OPS:
                if not rest:
                    errors.append(
                        f"Line {lineno}: {mnem} requires a source register "
                        f"operand (R0..R7)")
                    continue
                src_tok = rest[0].upper()
                if src_tok not in (f"R{n}" for n in range(8)):
                    errors.append(
                        f"Line {lineno}: {mnem} source operand must be "
                        f"R0..R7, got '{rest[0]}'")
                    continue
                src_idx = int(src_tok[1])   # "R3" → 3
                ir.append({"kind": "opcode", "op": opcode,
                           "operand": bytes([src_idx]),
                           "line": lineno, "mnem": mnem})

            # ── Plain opcode (no operand) ────────────────────────────────────
            # Extra tokens after a no-operand mnemonic are silently ignored;
            # they are almost always inline annotations left after comment
            # stripping (e.g. the comment marker itself was removed but a
            # stray word remained).  Emitting a warning here is noise.
            else:
                ir.append({"kind": "opcode", "op": opcode,
                           "operand": b"", "line": lineno, "mnem": mnem})

        if errors:
            return AssemblyResult(ok=False, errors=errors, warnings=warnings)

        # ── Pass 1b: compute byte offsets for every IR node ──────────────────
        # Sizes:
        #   opcode     : 1 + len(operand)
        #   label_def  : 0
        #   label_push : 6  (PUSH4[1] + 4-byte target + JUMP/JUMPI[1])
        #   push_label : 1 + operand_bytes  (PUSH<N>[1] + N-byte target)
        offsets = []
        pos = 0
        for node in ir:
            offsets.append(pos)
            if node["kind"] == "opcode":
                pos += 1 + len(node["operand"])
            elif node["kind"] == "label_push":
                pos += 6
            elif node["kind"] == "push_label":
                pos += 1 + node["operand_bytes"]
            # label_def: 0 bytes

        total_bytes = pos

        # ── Pass 1c: build label → byte-offset map ────────────────────────────
        label_offsets: _Dict[str, int] = {}
        for i, node in enumerate(ir):
            if node["kind"] == "label_def":
                name = node["name"]
                if name in label_offsets:
                    errors.append(
                        f"Line {node['line']}: duplicate label '.{name}'")
                    continue
                # A label resolves to the offset of the next code-emitting node
                # (skip over consecutive label_def nodes, which emit nothing).
                target_offset = total_bytes  # default: end of bytecode
                for j in range(i + 1, len(ir)):
                    if ir[j]["kind"] != "label_def":
                        target_offset = offsets[j]
                        break
                label_offsets[name] = target_offset

        if errors:
            return AssemblyResult(ok=False, errors=errors, warnings=warnings)

        # ── Pass 2: emit final bytecode ──────────────────────────────────────
        buf = bytearray()
        source_map: _Dict[int, tuple] = {}

        for node in ir:
            kind = node["kind"]
            if kind == "label_def":
                continue  # no bytes emitted

            byte_offset = len(buf)

            if kind == "label_push":
                # JUMP/JUMPI with auto-PUSH4 prefix (existing behaviour)
                label = node["label"]
                if label not in label_offsets:
                    errors.append(
                        f"Line {node['line']}: undefined label '.{label}'")
                    continue
                target = label_offsets[label]
                if target > 0xFFFF_FFFF:
                    errors.append(
                        f"Line {node['line']}: label offset {target} "
                        f"exceeds 4-byte range")
                    continue
                push4_op = Op.PUSH1 + 3   # PUSH4 = 0x63
                buf.append(push4_op)
                buf.extend(_struct.pack(">I", target))
                buf.append(node["op"])
                source_map[byte_offset] = (node["line"],
                                           f"PUSH4+{node['mnem']} .{label}")
                source_map[byte_offset + 5] = (node["line"], node["mnem"])

            elif kind == "push_label":
                # PUSH<N> with a label operand — resolve the label now
                label = node["label"]
                if label not in label_offsets:
                    errors.append(
                        f"Line {node['line']}: undefined label '.{label}'")
                    continue
                target = label_offsets[label]
                n = node["operand_bytes"]
                max_val = (1 << (n * 8)) - 1
                if target > max_val:
                    errors.append(
                        f"Line {node['line']}: label '.{label}' offset "
                        f"{target} (0x{target:X}) does not fit in "
                        f"{n} byte(s) for {node['mnem']} "
                        f"(max 0x{max_val:X}); use a wider PUSH")
                    continue
                buf.append(node["op"])
                buf.extend(target.to_bytes(n, "big"))
                source_map[byte_offset] = (node["line"],
                                           f"{node['mnem']} .{label}")

            else:  # plain opcode
                source_map[byte_offset] = (node["line"], node["mnem"])
                buf.append(node["op"])
                buf.extend(node["operand"])

        if errors:
            return AssemblyResult(ok=False, errors=errors, warnings=warnings)

        bytecode = bytes(buf)
        return AssemblyResult(
            ok=True,
            bytecode=bytecode,
            hex=bytecode.hex(),
            errors=[],
            warnings=warnings,
            source_map=source_map,
        )

    # ── Disassembler ─────────────────────────────────────────────────────────
    @staticmethod
    def disassemble(bytecode: bytes) -> str:
        """
        Produce a human-readable VASM listing from raw VVM bytecode.

        Each line shows:   <hex_offset>  <mnemonic>  [<hex operand>]

        RMOV_Rn instructions show the source register as "R<n>" rather than
        a raw hex byte, matching VASM assembly source syntax.
        Unknown bytes are shown as  DATA 0xNN.
        """
        VVMAssembler._build_mnemonic_table()

        # Build reverse lookup: opcode byte → (mnemonic, operand_bytes)
        rev: _Dict[int, tuple] = {}
        for name, (op, n) in VVMAssembler._MNEMONIC_TABLE.items():
            # Prefer the shortest name for duplicates (shouldn't exist, but be safe)
            if op not in rev or len(name) < len(rev[op][0]):
                rev[op] = (name, n)

        lines_out = []
        pc = 0
        data = bytecode
        n = len(data)

        while pc < n:
            op_byte = data[pc]
            if op_byte in rev:
                mnem, imm_len = rev[op_byte]
                # RMOV_Rn: 1-byte immediate is a register index — show as R<n>
                if Op.RMOV_R0 <= op_byte <= Op.RMOV_R7:
                    if pc + 1 < n:
                        src_idx = data[pc + 1] & 0x07
                        lines_out.append(
                            f"0x{pc:04X}  {mnem}  R{src_idx}")
                        pc += 2
                    else:
                        lines_out.append(
                            f"0x{pc:04X}  {mnem}  <truncated: missing src reg>")
                        pc = n
                elif imm_len == 0:
                    lines_out.append(f"0x{pc:04X}  {mnem}")
                    pc += 1
                else:
                    imm_end = pc + 1 + imm_len
                    imm_bytes = data[pc + 1: imm_end]
                    if len(imm_bytes) < imm_len:
                        lines_out.append(
                            f"0x{pc:04X}  {mnem}  <truncated: only "
                            f"{len(imm_bytes)}/{imm_len} bytes>")
                        pc = n
                    else:
                        hex_imm = "0x" + imm_bytes.hex()
                        lines_out.append(f"0x{pc:04X}  {mnem}  {hex_imm}")
                        pc = imm_end
            else:
                lines_out.append(f"0x{pc:04X}  DATA  0x{op_byte:02X}")
                pc += 1

        return "\n".join(lines_out)

    # ── Helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _parse_literal(raw: str, lineno: int):
        """Return (int_value, error_string_or_None)."""
        if VVMAssembler._RE_HEX_LIT.match(raw):
            return int(raw, 16), None
        if VVMAssembler._RE_DEC_LIT.match(raw):
            return int(raw, 10), None
        return None, f"Line {lineno}: invalid literal '{raw}' (expected 0x… hex or decimal)"

    @staticmethod
    def _int_to_bytes(value: int, n_bytes: int) -> bytes:
        """Pack *value* into exactly *n_bytes* big-endian bytes."""
        if value < 0:
            # Signed: two's complement
            value = value & ((1 << (n_bytes * 8)) - 1)
        result = value.to_bytes(n_bytes, "big")   # raises OverflowError if too big
        return result

    # ── Convenience: assemble + validate bytecode size ───────────────────────
    def assemble_for_deploy(self, source: str) -> AssemblyResult:
        """
        Like assemble() but also checks that the result does not exceed
        Config.VVM_MAX_BYTECODE_SIZE (24 KB).  Suitable for feeding directly
        into a TYPE_DEPLOY transaction's 'data' field.
        """
        result = self.assemble(source)
        if result.ok and len(result.bytecode) > Config.VVM_MAX_BYTECODE_SIZE:
            result.ok = False
            result.errors.append(
                f"Bytecode size {len(result.bytecode)} bytes exceeds "
                f"VVM_MAX_BYTECODE_SIZE ({Config.VVM_MAX_BYTECODE_SIZE} bytes).  "
                f"Split the contract into smaller pieces.")
        return result
