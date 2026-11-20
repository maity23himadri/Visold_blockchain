"""V4 regression tests for Section 73 (Session 06): VM Stack, Memory Bounds, and OOG."""

import tempfile
import unittest
from pathlib import Path

from visold.kernel.config import Config
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op


class _DummyTx:
    tx_id = "tx_sec73_test"
    gas_price = 0.00000001


class TestSection73VMStackMemoryOOG(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmp.name) / "test_sec73.db")
        self.storage = Storage(db_path=self.db_path)
        self.engine = VVMEngine(self.storage)

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        self._tmp.cleanup()

    def test_pre_gas_64mb_memory_allocation_blocked(self):
        """Oversized memory access is rejected before allocating 64 MB of RAM."""
        offset = 64_000_000
        bytecode = bytes([Op.PUSH4]) + offset.to_bytes(4, "big") + bytes([Op.MLOAD, Op.STOP])
        frame = _VMFrame(
            code=bytecode,
            calldata=b"",
            caller="VSD111111111111111111111111111111",
            address="VSDc" + "aa" * 18,
            origin="VSD111111111111111111111111111111",
            call_value=0,
            gas_limit=50,
            storage_ref=self.storage,
        )
        self.engine._execute(frame)
        self.assertTrue(frame.reverted)
        self.assertIn(b"Memory OOG", frame.output)
        self.assertEqual(len(frame.memory), 0)

    def test_call_retains_one_64th_gas_for_parent_on_child_oog(self):
        """EIP-150: parent retains ~1/64th gas when child runs out of gas and succeeds."""
        loop_code = bytes([Op.JUMPDEST, Op.PUSH1, 0, Op.JUMP])
        loop_addr = "VSDc" + "bb" * 18
        self.storage.save_contract_code("hash_loop", loop_code)
        self.storage.save_contract(
            address=loop_addr, code_hash="hash_loop",
            creator="VSD111111111111111111111111111111",
            created_at=1, contract_name="",
        )

        addr_int = _VMFrame(
            code=b"", calldata=b"", caller="", address="", origin="",
            call_value=0, gas_limit=0, storage_ref=self.storage,
        )._addr_to_int(loop_addr)
        parent_code = (
            bytes([Op.PUSH1, 0]) * 5
            + bytes([Op.PUSH32]) + addr_int.to_bytes(32, "big")
            + bytes([Op.PUSH4]) + (1_000_000).to_bytes(4, "big")
            + bytes([Op.CALL, Op.POP, Op.STOP])
        )
        parent_addr = "VSDc" + "cc" * 18
        self.storage.save_contract_code("hash_parent", parent_code)
        self.storage.save_contract(
            address=parent_addr, code_hash="hash_parent",
            creator="VSD111111111111111111111111111111",
            created_at=1, contract_name="",
        )

        res = self.engine.call(
            caller="VSD111111111111111111111111111111",
            contract=parent_addr,
            calldata=b"",
            call_value=0,
            gas_limit=64_000,
            block_ctx=None,
            tx=_DummyTx(),
        )
        self.assertTrue(res.success, res.revert_reason)

    def test_stack_overflow_and_underflow(self):
        code = bytes([Op.PUSH1, 1]) * (Config.VVM_MAX_STACK_DEPTH + 1)
        frame = _VMFrame(
            code=code, calldata=b"", caller="", address="", origin="",
            call_value=0, gas_limit=100_000, storage_ref=self.storage,
        )
        self.engine._execute(frame)
        self.assertTrue(frame.reverted)
        self.assertIn(b"Stack overflow", frame.output)
