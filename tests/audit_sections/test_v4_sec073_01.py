"""V4 regression tests for Section 73: VM Stack, Memory Bounds, and Out-of-Gas Handling."""

import os
import tempfile
import types

from visold.kernel.config import Config
from visold.resilience.hardened_core import (
    _HC_MAX_RECURSION_DEPTH,
    _make_hardened_vvm_internal_call,
)
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op


class _DummyTx:
    def __init__(self, tx_id: str = "tx_sec73_test", gas_price: float = 0.0):
        self.tx_id = tx_id
        self.gas_price = gas_price


class _DummyBlockCtx:
    def __init__(self, index: int = 1, timestamp: int = 1_700_000_000):
        self.index = index
        self.timestamp = timestamp
        self.miner_address = "VSD1111111111111111111111111111111111"
        self.difficulty = 1.0


def _make_storage(tmpdir: str) -> Storage:
    db_path = os.path.join(tmpdir, "test_sec73.db")
    return Storage(db_path=db_path)


def test_create_respects_max_call_depth():
    """Op.CREATE enforces Config.VVM_MAX_CALL_DEPTH and rejects creation at max depth."""
    with tempfile.TemporaryDirectory() as tmp:
        storage = _make_storage(tmp)
        vvm = VVMEngine(storage)
        tx = _DummyTx("tx_sec73_depth")
        blk = _DummyBlockCtx()

        # Self-replicating init code that runs CREATE on itself
        init_code = bytes([
            Op.CODESIZE,
            Op.PUSH1, 0x00,
            Op.PUSH1, 0x00,
            Op.CODECOPY,
            Op.CODESIZE,
            Op.PUSH1, 0x00,
            Op.PUSH1, 0x00,
            Op.CREATE,
            Op.STOP,
        ])
        res = vvm.deploy(
            sender="VSDsender000000000000000000000000000",
            bytecode=init_code,
            call_value=0,
            gas_limit=100_000_000,
            block_ctx=blk,
            tx=tx,
        )
        assert res.success
        assert len(res.pending_deployments) <= Config.VVM_MAX_CALL_DEPTH

        # Frame already at Config.VVM_MAX_CALL_DEPTH must NOT be able to CREATE
        child_init = bytes([Op.STOP])
        parent_code = bytes([
            Op.PUSH1, len(child_init),
            Op.PUSH1, 0x00,
            Op.PUSH1, 0x00,
            Op.CREATE,
            Op.STOP,
        ])
        max_depth_frame = _VMFrame(
            code=parent_code,
            calldata=b"",
            caller="VSDsender",
            address="VSDc" + "aa" * 18,
            origin="VSDsender",
            call_value=0,
            gas_limit=1_000_000,
            storage_ref=storage,
            depth=Config.VVM_MAX_CALL_DEPTH,
        )
        vvm._execute(max_depth_frame)
        assert not max_depth_frame.reverted
        assert len(max_depth_frame.pending_deployments) == 0
        assert max_depth_frame.stack[-1] == 0


def test_mem_expand_checks_cap_before_allocation():
    """_VMFrame.mload() rejects oversized offset before allocating memory."""
    with tempfile.TemporaryDirectory() as tmp:
        storage = _make_storage(tmp)
        frame = _VMFrame(
            code=b"",
            calldata=b"",
            caller="VSDcaller",
            address="VSDc" + "00" * 18,
            origin="VSDcaller",
            call_value=0,
            gas_limit=100,
            storage_ref=storage,
        )

        offset_64mb = (64 * 1024 * 1024) - 32
        raised = False
        try:
            frame.mload(offset_64mb)
        except RuntimeError as e:
            assert "Memory OOG" in str(e) or "Out of gas" in str(e), f"Unexpected error: {e}"
            raised = True

        assert raised, "Expected RuntimeError on oversized memory access"
        assert len(frame.memory) == 0
        assert frame._mem_words == 0


def test_vvm_max_memory_bytes_enforced():
    """Config.VVM_MAX_MEMORY_BYTES (1 MB) is enforced as the per-frame hard memory cap."""
    with tempfile.TemporaryDirectory() as tmp:
        storage = _make_storage(tmp)
        vvm = VVMEngine(storage)
        tx = _DummyTx("tx_sec73_memcap")
        blk = _DummyBlockCtx()

        runtime_code = bytes([
            Op.PUSH1, 0x01,
            Op.PUSH4, 0x00, 0x40, 0x00, 0x00,  # 4 MB offset
            Op.MSTORE,
            Op.MSIZE,
            Op.PUSH1, 0x00,
            Op.MSTORE,
            Op.PUSH1, 0x20,
            Op.PUSH1, 0x00,
            Op.RETURN,
        ])
        storage.save_contract("VSDc" + "2b" * 18, "codehash_2b", "VSDsender", 1)
        storage.save_contract_code("codehash_2b", runtime_code)

        res = vvm.call(
            caller="VSDsender000000000000000000000000000",
            contract="VSDc" + "2b" * 18,
            calldata=b"",
            call_value=0,
            gas_limit=100_000_000,
            block_ctx=blk,
            tx=tx,
        )
        assert not res.success
        assert "Memory OOG" in res.revert_reason or "exceeds allocation cap" in res.revert_reason


def test_oog_consumes_all_remaining_gas():
    """On Out-of-Gas, VVMEngine consumes the entire gas_limit rather than refunding unspent gas."""
    with tempfile.TemporaryDirectory() as tmp:
        storage = _make_storage(tmp)
        vvm = VVMEngine(storage)
        tx = _DummyTx("tx_sec73_oog")
        blk = _DummyBlockCtx()

        runtime_code = bytes([
            Op.PUSH1, 0x01,
            Op.PUSH1, 0x00,
            Op.SSTORE,
            Op.STOP,
        ])
        storage.save_contract("VSDc" + "11" * 18, "codehash_3", "VSDsender", 1)
        storage.save_contract_code("codehash_3", runtime_code)

        gas_limit = 10_000
        res = vvm.call(
            caller="VSDsender000000000000000000000000000",
            contract="VSDc" + "11" * 18,
            calldata=b"",
            call_value=0,
            gas_limit=gas_limit,
            block_ctx=blk,
            tx=tx,
        )
        assert not res.success
        assert "Out of gas" in res.revert_reason
        assert res.gas_used == gas_limit


def test_resource_cap_allows_depth_64_and_handles_max_depth_gracefully():
    """Hardened _internal_call allows depth 64+ and fails CALL gracefully at _HC_MAX_RECURSION_DEPTH."""
    with tempfile.TemporaryDirectory() as tmp:
        storage = _make_storage(tmp)
        vvm = VVMEngine(storage)
        orig_icall = vvm.__class__._internal_call
        vvm._internal_call = types.MethodType(
            _make_hardened_vvm_internal_call(orig_icall), vvm
        )
        tx = _DummyTx("tx_sec73_rcap")
        blk = _DummyBlockCtx()

        assert _HC_MAX_RECURSION_DEPTH == Config.VVM_MAX_CALL_DEPTH

        addrs = ["VSDc" + f"{i:036x}" for i in range(_HC_MAX_RECURSION_DEPTH + 2)]
        helper = _VMFrame(
            code=b"", calldata=b"", caller="", address="", origin="",
            call_value=0, gas_limit=0, storage_ref=storage
        )
        for i in range(_HC_MAX_RECURSION_DEPTH + 1):
            addr_bytes = helper._addr_to_int(addrs[i + 1]).to_bytes(32, "big")
            prefix = bytes([
                Op.PUSH1, 0x20, Op.PUSH1, 0x00, Op.PUSH1, 0x00, Op.PUSH1, 0x00, Op.PUSH1, 0x00,
                Op.PUSH32,
            ]) + addr_bytes + bytes([
                Op.PUSH3, 0x01, 0x86, 0xA0,
                Op.CALL,
                Op.ISZERO,
                Op.ISZERO,
            ])
            body_fail = bytes([Op.PUSH1, 0xAA, Op.PUSH1, 0x00, Op.MSTORE])
            ok_dest = len(prefix) + 3 + len(body_fail)
            code = prefix + bytes([Op.PUSH1, ok_dest, Op.JUMPI]) + body_fail + bytes([
                Op.JUMPDEST,
                Op.PUSH1, 0x20,
                Op.PUSH1, 0x00,
                Op.RETURN,
            ])
            ch = f"ch_{i}"
            storage.save_contract(addrs[i], ch, "VSDsender", 1)
            storage.save_contract_code(ch, code)

        leaf_code = bytes([
            Op.PUSH1, 0x55, Op.PUSH1, 0x00, Op.MSTORE,
            Op.PUSH1, 0x20, Op.PUSH1, 0x00, Op.RETURN,
        ])
        storage.save_contract(addrs[-1], "ch_leaf", "VSDsender", 1)
        storage.save_contract_code("ch_leaf", leaf_code)

        # Calling from C0 reaches depth cap gracefully (returns 0xAA rather than reverting top frame)
        res = vvm.call(
            caller="VSDsender000000000000000000000000000",
            contract=addrs[0],
            calldata=b"",
            call_value=0,
            gas_limit=50_000_000,
            block_ctx=blk,
            tx=tx,
        )
        assert res.success
        assert int.from_bytes(res.return_data, "big") == 0xAA
