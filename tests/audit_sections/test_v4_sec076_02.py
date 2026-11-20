"""V4 regression tests for Section 76 (Session 06): Precompiled Contracts and Gas."""

import unittest

from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op
from visold.vm.precompiles import VVMPrecompiles


class _DummyStorage:
    def get_balance_sat(self, addr):
        return 0

    def get_contract(self, addr):
        return None

    def get_contract_code(self, code_hash):
        return None


def _make_call_precompile_bytecode(precompile_addr: str, gas_param: int, out_size: int = 32) -> bytes:
    frame = _VMFrame.__new__(_VMFrame)
    addr_int = frame._addr_to_int(precompile_addr)

    code = bytearray()

    def push_int(val: int, size: int = 32):
        op = Op.PUSH1 + (size - 1)
        code.append(op)
        code.extend(val.to_bytes(size, "big"))

    push_int(out_size, 1)
    push_int(0, 1)
    push_int(0, 1)
    push_int(0, 1)
    push_int(addr_int, 32)
    push_int(gas_param, 4)
    code.append(Op.STATICCALL)
    code.append(Op.STOP)
    return bytes(code)


class TestAuditSection76(unittest.TestCase):
    def test_precompile_dispatch_no_double_64th_charge(self):
        """VVMEngine._internal_call does not double-charge 1/64th gas for precompiles."""
        engine = VVMEngine(_DummyStorage())

        code = _make_call_precompile_bytecode(VVMPrecompiles.ECRECOVER, gas_param=3000, out_size=0)
        frame = _VMFrame(
            code=code,
            calldata=b"",
            caller="VSDcaller",
            address="VSDcontract",
            origin="VSDcaller",
            call_value=0,
            gas_limit=3065,
            storage_ref=_DummyStorage(),
        )
        engine._execute(frame)

        self.assertFalse(frame.reverted)
        self.assertEqual(frame.stack[-1], 1)
        self.assertEqual(frame.gas_remaining, 47)

        code_id = _make_call_precompile_bytecode(VVMPrecompiles.IDENTITY, gas_param=64_000, out_size=0)
        frame_id = _VMFrame(
            code=code_id,
            calldata=b"",
            caller="VSDcaller",
            address="VSDcontract",
            origin="VSDcaller",
            call_value=0,
            gas_limit=64_018,
            storage_ref=_DummyStorage(),
        )
        engine._execute(frame_id)
        self.assertFalse(frame_id.reverted)
        self.assertEqual(frame_id.stack[-1], 1)
        self.assertEqual(frame_id.gas_remaining, 63_985)

    def test_modexp_enforces_gas_limit_on_short_calldata_and_zero_mod(self):
        ok_short, _, gas_short = VVMPrecompiles.execute(
            VVMPrecompiles.MODEXP, b"\x01\x02", gas_limit=0
        )
        self.assertFalse(ok_short)
        self.assertLessEqual(gas_short, 0)

        header = (
            (0).to_bytes(32, "big")
            + (0).to_bytes(32, "big")
            + (1024).to_bytes(32, "big")
        )
        ok_zero, _, gas_zero = VVMPrecompiles.execute(
            VVMPrecompiles.MODEXP, header, gas_limit=1
        )
        self.assertFalse(ok_zero)
        self.assertLessEqual(gas_zero, 1)

    def test_unknown_precompile_respects_gas_limit(self):
        unknown_addr = "VSDcPRECOMPILE000000000000099"
        self.assertTrue(VVMPrecompiles.is_precompile(unknown_addr))

        ok, ret, gas_used = VVMPrecompiles.execute(unknown_addr, b"", gas_limit=100)
        self.assertFalse(ok)
        self.assertEqual(ret, b"unknown precompile")
        self.assertLessEqual(gas_used, 100)

        engine = VVMEngine(_DummyStorage())
        code = _make_call_precompile_bytecode(unknown_addr, gas_param=100, out_size=0)
        frame = _VMFrame(
            code=code,
            calldata=b"",
            caller="VSDcaller",
            address="VSDcontract",
            origin="VSDcaller",
            call_value=0,
            gas_limit=10_000,
            storage_ref=_DummyStorage(),
        )
        engine._execute(frame)
        self.assertFalse(frame.reverted)
        self.assertEqual(frame.stack[-1], 0)
        self.assertGreater(frame.gas_remaining, 9_000)
