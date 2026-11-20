"""V4 regression tests for Section 74: Execution Frames, Call Depth, Context Isolation."""

from __future__ import annotations

import os
import tempfile
import time
from types import SimpleNamespace
import pytest

from visold.crypto.hashing import sha256
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op


def _make_storage(td: str) -> Storage:
    return Storage(os.path.join(td, "audit74.db"))


def _install_contract(st: Storage, addr: str, runtime: bytes, creator: str = "VSDtestcreator000000000000000000000"):
    code_hash = sha256(runtime)
    st.save_contract_code(code_hash, runtime)
    st.save_contract(addr, code_hash, creator, int(time.time()))


def _push32(val: int) -> bytes:
    return bytes([Op.PUSH32]) + (val & _VMFrame.UINT256_MAX).to_bytes(32, "big")


def _push1(val: int) -> bytes:
    return bytes([Op.PUSH1, val & 0xFF])


def _addr_int(addr: str) -> int:
    dummy = _VMFrame.__new__(_VMFrame)
    return _VMFrame._addr_to_int(dummy, addr)


def _dummy_tx(tx_id: str = "tx_audit_74"):
    return SimpleNamespace(tx_id=tx_id, gas_price=0.0)


def _dummy_block(index: int = 1):
    return SimpleNamespace(index=index, timestamp=1700000000, miner_address="VSDminer", difficulty=1.0)


def test_create_preserves_reentrancy_guard():
    """Op.CREATE preserves the active _ReentrancyGuard so init code cannot re-enter Contract A."""
    with tempfile.TemporaryDirectory() as td:
        st = _make_storage(td)
        addr_a = "VSDc" + "aa" * 18
        a_int = _addr_int(addr_a)

        init_code = (
            _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push1(0)
            + _push32(a_int) + _push32(50000)
            + bytes([Op.CALL])
            + _push1(0) + bytes([Op.MSTORE])
            + _push1(32) + _push1(0) + bytes([Op.RETURN])
        )

        reentrant_branch = _push1(0x42) + _push1(0) + bytes([Op.SSTORE, Op.STOP])

        padded_init = init_code.ljust(((len(init_code) + 31) // 32) * 32, b"\x00")
        store_init = b""
        for i in range(0, len(padded_init), 32):
            chunk = int.from_bytes(padded_init[i:i + 32], "big")
            store_init += _push32(chunk) + _push1(i) + bytes([Op.MSTORE])

        deploy_branch = (
            bytes([Op.JUMPDEST])
            + store_init
            + _push1(len(init_code)) + _push1(0) + _push1(0)
            + bytes([Op.CREATE])
            + _push1(0) + bytes([Op.MSTORE])
            + _push1(32) + _push1(0) + bytes([Op.RETURN])
        )

        deploy_pc = 4 + len(reentrant_branch)
        header = bytes([Op.CALLDATASIZE]) + _push1(deploy_pc) + bytes([Op.JUMPI])
        code_a = header + reentrant_branch + deploy_branch

        _install_contract(st, addr_a, code_a)
        engine = VVMEngine(st)
        res = engine.call(
            caller="VSDcaller0000000000000000000000000000",
            contract=addr_a,
            calldata=b"\x01",
            call_value=0,
            gas_limit=500000,
            block_ctx=_dummy_block(),
            tx=_dummy_tx(),
        )
        assert res.success, f"Call failed: {res.revert_reason}"
        assert res.storage_writes.get((addr_a, "0x0")) is None
        assert len(res.pending_deployments) == 1
        assert int.from_bytes(res.pending_deployments[0]["code_bytes"], "big") == 0


def test_internal_call_shares_pending_deployments_with_child():
    """Child frame sees parent's pending CREATE deployment via EXTCODESIZE."""
    with tempfile.TemporaryDirectory() as td:
        st = _make_storage(td)
        addr_a = "VSDc" + "a1" * 18
        addr_b = "VSDc" + "b1" * 18

        init_c = (
            _push32(0x60010000 << 224) + _push1(0) + bytes([Op.MSTORE])
            + _push1(4) + _push1(0) + bytes([Op.RETURN])
        )
        padded_init = init_c.ljust(((len(init_c) + 31) // 32) * 32, b"\x00")
        store_init = b""
        for i in range(0, len(padded_init), 32):
            chunk = int.from_bytes(padded_init[i:i + 32], "big")
            store_init += _push32(chunk) + _push1(i) + bytes([Op.MSTORE])

        code_b = (
            _push1(0) + bytes([Op.CALLDATALOAD, Op.EXTCODESIZE])
            + _push1(0) + bytes([Op.MSTORE])
            + _push1(32) + _push1(0) + bytes([Op.RETURN])
        )
        _install_contract(st, addr_b, code_b)

        code_a = (
            store_init
            + _push1(len(init_c)) + _push1(0) + _push1(0) + bytes([Op.CREATE])
            + _push1(0) + bytes([Op.MSTORE])
            + _push1(32) + _push1(64) + _push1(32) + _push1(0) + _push1(0)
            + _push32(_addr_int(addr_b)) + _push32(50000) + bytes([Op.CALL])
            + bytes([Op.POP])
            + _push1(32) + _push1(64) + bytes([Op.RETURN])
        )
        _install_contract(st, addr_a, code_a)

        engine = VVMEngine(st)
        res = engine.call(
            caller="VSDcaller0000000000000000000000000000",
            contract=addr_a,
            calldata=b"",
            call_value=0,
            gas_limit=500000,
            block_ctx=_dummy_block(),
            tx=_dummy_tx(),
        )
        assert res.success, f"Call failed: {res.revert_reason}"
        assert len(res.pending_deployments) == 1
        assert len(res.pending_deployments[0]["code_bytes"]) == 4
        extcodesize_seen_by_b = int.from_bytes(res.return_data, "big")
        assert extcodesize_seen_by_b == 4


def test_delegatecall_create_produces_distinct_addresses():
    """Two DELEGATECALLs executing CREATE in the same tx produce distinct addresses."""
    with tempfile.TemporaryDirectory() as td:
        st = _make_storage(td)
        addr_a = "VSDc" + "a2" * 18
        addr_lib = "VSDc" + "12" * 18

        init_c = (
            _push32(0x60010000 << 224) + _push1(0) + bytes([Op.MSTORE])
            + _push1(4) + _push1(0) + bytes([Op.RETURN])
        )
        padded_init = init_c.ljust(((len(init_c) + 31) // 32) * 32, b"\x00")
        store_init = b""
        for i in range(0, len(padded_init), 32):
            chunk = int.from_bytes(padded_init[i:i + 32], "big")
            store_init += _push32(chunk) + _push1(i) + bytes([Op.MSTORE])

        code_lib = (
            store_init
            + _push1(len(init_c)) + _push1(0) + _push1(0) + bytes([Op.CREATE])
            + _push1(0) + bytes([Op.MSTORE])
            + _push1(32) + _push1(0) + bytes([Op.RETURN])
        )
        _install_contract(st, addr_lib, code_lib)

        code_a = (
            _push1(32) + _push1(0) + _push1(0) + _push1(0) + _push32(_addr_int(addr_lib)) + _push32(100000)
            + bytes([Op.DELEGATECALL, Op.POP])
            + _push1(32) + _push1(32) + _push1(0) + _push1(0) + _push32(_addr_int(addr_lib)) + _push32(100000)
            + bytes([Op.DELEGATECALL, Op.POP])
            + _push1(64) + _push1(0) + bytes([Op.RETURN])
        )
        _install_contract(st, addr_a, code_a)

        engine = VVMEngine(st)
        res = engine.call(
            caller="VSDcaller0000000000000000000000000000",
            contract=addr_a,
            calldata=b"",
            call_value=0,
            gas_limit=500000,
            block_ctx=_dummy_block(),
            tx=_dummy_tx(),
        )
        assert res.success, f"Call failed: {res.revert_reason}"
        addr1 = int.from_bytes(res.return_data[:32], "big")
        addr2 = int.from_bytes(res.return_data[32:64], "big")
        assert addr1 != 0
        assert addr2 != 0
        assert addr1 != addr2
        assert len(res.pending_deployments) == 2
        assert res.pending_deployments[0]["address"] != res.pending_deployments[1]["address"]


def test_simulate_with_call_value_supports_delegatecall():
    """VVMEngine.simulate(..., call_value=100) allows DELEGATECALL without spurious static failure."""
    with tempfile.TemporaryDirectory() as td:
        st = _make_storage(td)
        proxy = "VSDc" + "c1" * 18
        impl = "VSDc" + "c2" * 18

        code_impl = (
            _push32(0x1234) + _push1(0) + bytes([Op.MSTORE])
            + _push1(32) + _push1(0) + bytes([Op.RETURN])
        )
        _install_contract(st, impl, code_impl)

        code_proxy = (
            _push1(32) + _push1(0) + _push1(0) + _push1(0) + _push32(_addr_int(impl)) + _push32(50000)
            + bytes([Op.DELEGATECALL])
            + _push1(32) + bytes([Op.MSTORE])
            + _push1(64) + _push1(0) + bytes([Op.RETURN])
        )
        _install_contract(st, proxy, code_proxy)

        engine = VVMEngine(st)
        res_zero = engine.simulate(
            caller="VSDcaller0000000000000000000000000000",
            contract=proxy,
            calldata=b"",
            call_value=0,
            gas_limit=500000,
            block_ctx=_dummy_block(),
        )
        assert res_zero.success
        assert int.from_bytes(res_zero.return_data[32:64], "big") == 1
        assert int.from_bytes(res_zero.return_data[:32], "big") == 0x1234

        res_val = engine.simulate(
            caller="VSDcaller0000000000000000000000000000",
            contract=proxy,
            calldata=b"",
            call_value=100,
            gas_limit=500000,
            block_ctx=_dummy_block(),
        )
        assert res_val.success
        assert int.from_bytes(res_val.return_data[32:64], "big") == 1
        assert int.from_bytes(res_val.return_data[:32], "big") == 0x1234


def test_return_buffer_isolated_across_child_and_cleared_on_eoa():
    """Child frame starts with empty RETURNDATASIZE and EOA call clears parent return_buffer."""
    with tempfile.TemporaryDirectory() as td:
        st = _make_storage(td)
        addr_a = "VSDc" + "d1" * 18
        addr_b = "VSDc" + "d2" * 18
        addr_c = "VSDc" + "d3" * 18
        addr_eoa = "VSDc" + "d4" * 18

        code_b = (
            _push32(int.from_bytes(b"SECRET".ljust(32, b"\x00"), "big"))
            + _push1(0) + bytes([Op.MSTORE])
            + _push1(6) + _push1(0) + bytes([Op.RETURN])
        )
        _install_contract(st, addr_b, code_b)

        code_c = (
            bytes([Op.RETURNDATASIZE]) + _push1(0) + bytes([Op.MSTORE])
            + _push1(32) + _push1(0) + bytes([Op.RETURN])
        )
        _install_contract(st, addr_c, code_c)

        code_a = (
            _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push32(_addr_int(addr_b)) + _push32(50000)
            + bytes([Op.CALL, Op.POP])
            + _push1(32) + _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push32(_addr_int(addr_c)) + _push32(50000)
            + bytes([Op.CALL, Op.POP])
            + _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push32(_addr_int(addr_b)) + _push32(50000)
            + bytes([Op.CALL, Op.POP])
            + _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push32(_addr_int(addr_eoa)) + _push32(50000)
            + bytes([Op.CALL, Op.POP])
            + bytes([Op.RETURNDATASIZE]) + _push1(32) + bytes([Op.MSTORE])
            + _push1(64) + _push1(0) + bytes([Op.RETURN])
        )
        _install_contract(st, addr_a, code_a)

        engine = VVMEngine(st)
        res = engine.call(
            caller="VSDcaller0000000000000000000000000000",
            contract=addr_a,
            calldata=b"",
            call_value=0,
            gas_limit=500000,
            block_ctx=_dummy_block(),
            tx=_dummy_tx(),
        )
        assert res.success, f"Call failed: {res.revert_reason}"
        c_rds = int.from_bytes(res.return_data[:32], "big")
        a_rds_after_eoa = int.from_bytes(res.return_data[32:64], "big")
        assert c_rds == 0
        assert a_rds_after_eoa == 0


def test_selfdestruct_zeroes_balance_preventing_double_spend():
    """SELFDESTRUCT zeroes target's effective balance immediately, preventing double-spend."""
    with tempfile.TemporaryDirectory() as td:
        st = _make_storage(td)
        addr_a = "VSDc" + "e1" * 18
        addr_b = "VSDc" + "e2" * 18
        addr_c = "VSDc" + "e3" * 18
        st.credit_sat(addr_b, 1000)

        sd_branch = _push32(_addr_int(addr_a)) + bytes([Op.SELFDESTRUCT])
        send_branch = (
            bytes([Op.JUMPDEST])
            + _push1(0) + _push1(0) + _push1(0) + _push1(0)
            + _push32(1000) + _push32(_addr_int(addr_c)) + _push32(50000)
            + bytes([Op.CALL, Op.POP, Op.STOP])
        )
        dest_pc = 4 + len(sd_branch)
        code_b = bytes([Op.CALLDATASIZE]) + _push1(dest_pc) + bytes([Op.JUMPI]) + sd_branch + send_branch
        _install_contract(st, addr_b, code_b)

        code_a = (
            _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push32(_addr_int(addr_b)) + _push32(50000)
            + bytes([Op.CALL, Op.POP])
            + _push32(_addr_int(addr_b)) + bytes([Op.BALANCE]) + _push1(0) + bytes([Op.MSTORE])
            + _push1(1) + _push1(32) + bytes([Op.MSTORE])
            + _push1(0) + _push1(0) + _push1(32) + _push1(32) + _push1(0) + _push32(_addr_int(addr_b)) + _push32(100000)
            + bytes([Op.CALL, Op.POP])
            + _push1(32) + _push1(0) + bytes([Op.RETURN])
        )
        _install_contract(st, addr_a, code_a)

        engine = VVMEngine(st)
        res = engine.call(
            caller="VSDcaller0000000000000000000000000000",
            contract=addr_a,
            calldata=b"",
            call_value=0,
            gas_limit=500000,
            block_ctx=_dummy_block(),
            tx=_dummy_tx(),
        )
        assert res.success, f"Call failed: {res.revert_reason}"
        bal_b_after_sd = int.from_bytes(res.return_data, "big")
        assert bal_b_after_sd == 0
        assert res.balance_deltas.get(addr_c, 0) == 0
        assert res.self_destruct_transfers == [(addr_b, addr_a, 1000)]
