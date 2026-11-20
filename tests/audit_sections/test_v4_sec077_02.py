"""V4 regression tests for Section 77 (Session 06): VM Assembler, Bytecode Generation, and Static Analysis."""

import unittest

from visold.vm.assembler import VVMAssembler
from visold.vm.opcodes import Op
from visold.vm.static_analyzer import VVMStaticAnalyzer


class TestAuditSection77(unittest.TestCase):
    def test_negative_literal_out_of_range_upgrades_push_width(self):
        """PUSH1 with out-of-range negative literals auto-widens or rejects cleanly without silent truncation."""
        asm = VVMAssembler()

        res_256 = asm.assemble("PUSH1 -256\nSTOP")
        self.assertTrue(res_256.ok)
        # Widened to PUSH2 (0x61) with 0xFF00 (-256 in 2-byte two's complement)
        self.assertEqual(res_256.bytecode, bytes([Op.PUSH2, 0xFF, 0x00, Op.STOP]))

        res_129 = asm.assemble("PUSH1 -129\nSTOP")
        self.assertTrue(res_129.ok)
        self.assertEqual(res_129.bytecode, bytes([Op.PUSH2, 0xFF, 0x7F, Op.STOP]))

    def test_vtype_constants_rejected_as_executable_opcodes(self):
        """Op.VTYPE_* type-tag constants are rejected as unknown mnemonics."""
        asm = VVMAssembler()
        res = asm.assemble(
            "VTYPE_UINT\n"
            "VTYPE_ADDRESS\n"
            "VTYPE_BOOL\n"
            "VTYPE_SATOSHI\n"
            "VTYPE_HASH\n"
        )
        self.assertFalse(res.ok)
        self.assertEqual(len(res.errors), 5)

    def test_state_channel_scan_single_finding_for_missing_dispute(self):
        """CHAN_OPEN + CHAN_CLOSE without CHAN_DISPUTE emits a single finding (no double counting)."""
        bytecode = bytes([Op.CHAN_OPEN, Op.CHAN_CLOSE, Op.STOP])
        report = VVMStaticAnalyzer.analyze(bytecode)
        codes = [f.code for f in report.findings]

        self.assertEqual(codes, ["CHANNEL_MISSING_DISPUTE_PATH"])
        self.assertEqual(report.medium_count, 0)
        self.assertEqual(report.high_count, 1)
