"""V4 regression tests for Section 77: Assembler and Static Analyzer."""

import time

from visold.vm.opcodes import Op
from visold.vm.assembler import VVMAssembler
from visold.vm.static_analyzer import VVMStaticAnalyzer


def test_static_analyzer_scan_reentrancy_linear_time():
    """_scan_reentrancy() runs in linear time without O(N^2) CPU DoS."""
    n_calls = 8192
    bytecode = bytes([Op.CALL]) * n_calls

    t0 = time.perf_counter()
    report = VVMStaticAnalyzer.analyze(bytecode)
    elapsed = time.perf_counter() - t0

    assert report.bytecode_len == n_calls
    assert report.findings == []
    assert elapsed < 0.5, f"Expected linear-time < 0.5s, got {elapsed:.3f}s"


def test_op_vtype_constants_rejected_as_opcodes_and_accepted_as_push_operands():
    """Op.VTYPE_* constants are not executable mnemonics and work with PUSH1 Op.VTYPE_*."""
    asm = VVMAssembler()

    res_vtype = asm.assemble("VTYPE_UINT\nVTYPE_ADDRESS\nVTYPE_BOOL\nVTYPE_SATOSHI\nVTYPE_HASH")
    assert res_vtype.ok is False
    assert len(res_vtype.errors) == 5

    res_sym = asm.assemble("PUSH1 Op.VTYPE_ADDRESS")
    assert res_sym.ok is True
    assert res_sym.bytecode == bytes([Op.PUSH1, Op.VTYPE_ADDRESS])


def test_static_analyzer_state_channels_checks_staticcall_and_no_duplicate():
    """_scan_state_channels() flags STATICCALL before CHAN_DISPUTE and avoids duplicate missing-dispute findings."""
    bc_static_dispute = bytes([Op.CHAN_OPEN, Op.STATICCALL, Op.CHAN_DISPUTE])
    report_static = VVMStaticAnalyzer.analyze(bc_static_dispute)
    assert [f.code for f in report_static.findings] == ["CHANNEL_DISPUTE_IN_STATICCALL"]

    bc_no_dispute = bytes([Op.CHAN_OPEN, Op.CHAN_CLOSE])
    report_single = VVMStaticAnalyzer.analyze(bc_no_dispute)
    codes = [f.code for f in report_single.findings]
    assert codes == ["CHANNEL_MISSING_DISPUTE_PATH"]
