"""V4 regression tests for Section 72: Gas Metering and Estimation."""

from __future__ import annotations

import os
import tempfile

from visold.chain.blockchain import Blockchain
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op
from visold.vm.precompiles import VVMPrecompiles
from visold.wallet.wallet import Wallet


def _push1(v: int) -> bytes:
    return bytes((Op.PUSH1, v & 0xFF))


def _push32(v: int) -> bytes:
    return bytes((Op.PUSH32,)) + (v & ((1 << 256) - 1)).to_bytes(32, "big")


def _install(st: Storage, address: str, code: bytes, creator: str) -> None:
    h = sha256(code)
    st.save_contract_code(h, code)
    st.save_contract(address, h, creator, 1)


class _Tx:
    gas_price = 0.0

    def __init__(self, tx_id: str):
        self.tx_id = tx_id


def test_estimate_gas_succeeds_for_state_mutating_contract():
    """VVMEngine.simulate() and estimate_gas() succeed for state-mutating contracts."""
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "vm.db"))
        bc = Blockchain(storage=st)
        vvm = bc._vvm_engine
        caller = Wallet.generate().address

        # Contract 1: SSTORE(slot=0, val=42) + STOP
        sstore_addr = "VSDc" + "aa" * 18
        sstore_code = _push1(42) + _push1(0) + bytes((Op.SSTORE, Op.STOP))
        _install(st, sstore_addr, sstore_code, caller)

        res_call = vvm.call(
            caller=caller,
            contract=sstore_addr,
            calldata=b"",
            call_value=0,
            gas_limit=100_000,
            block_ctx=None,
            tx=_Tx("a" * 64),
        )
        assert res_call.success is True
        assert res_call.gas_used == 20_006

        res_sim = vvm.simulate(
            caller=caller,
            contract=sstore_addr,
            calldata=b"",
            call_value=0,
            gas_limit=100_000,
            block_ctx=None,
        )
        assert res_sim.success is True
        assert res_sim.gas_used == 20_006

        est = vvm.estimate_gas(
            caller=caller,
            contract=sstore_addr,
            calldata=b"",
            call_value=0,
            block_ctx=None,
        )
        assert 20_006 <= est < Config.VVM_TX_GAS_CAP

        bc_est = bc.estimate_vvm_gas(
            caller=caller,
            contract=sstore_addr,
            calldata=b"",
            call_value=0,
        )
        assert bc_est["success"] is True
        assert 20_006 <= bc_est["estimated_gas"] < Config.VVM_TX_GAS_CAP

        # Contract 2: LOG0(offset=0, size=0) + STOP
        log_addr = "VSDc" + "bb" * 18
        log_code = _push1(0) + _push1(0) + bytes((Op.LOG0, Op.STOP))
        _install(st, log_addr, log_code, caller)

        res_log_call = vvm.call(
            caller=caller,
            contract=log_addr,
            calldata=b"",
            call_value=0,
            gas_limit=100_000,
            block_ctx=None,
            tx=_Tx("b" * 64),
        )
        assert res_log_call.success is True
        assert res_log_call.gas_used == 381

        est_log = vvm.estimate_gas(
            caller=caller,
            contract=log_addr,
            calldata=b"",
            call_value=0,
            block_ctx=None,
        )
        assert 381 <= est_log < Config.VVM_TX_GAS_CAP


def test_precompile_no_double_1_64_deduction():
    """Precompile calls do not double-deduct 1/64th gas and return unused 1/64th to caller."""
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "vm.db"))
        vvm = VVMEngine(st)
        caller = Wallet.generate().address
        contract_addr = "VSDc" + "cc" * 18

        ecrecover_int = _VMFrame.__new__(_VMFrame)._addr_to_int(VVMPrecompiles.ECRECOVER)

        push2_3000 = bytes((Op.PUSH2,)) + (3000).to_bytes(2, "big")
        code = (
            _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push1(0)
            + _push32(ecrecover_int) + push2_3000
            + bytes((Op.CALL, Op.STOP))
        )
        _install(st, contract_addr, code, caller)

        # 21 gas for 7 pushes + 3047 = 3068 gas_limit -> 47 gas (1/64th) retained by caller,
        # 3000 gas consumed by ECRECOVER -> total gas_used = 3021.
        res = vvm.call(
            caller=caller,
            contract=contract_addr,
            calldata=b"",
            call_value=0,
            gas_limit=3068,
            block_ctx=None,
            tx=_Tx("c" * 64),
        )
        assert res.success is True
        assert res.gas_used == 3021

        frame = _VMFrame(
            code=code,
            calldata=b"",
            caller=caller,
            address=contract_addr,
            origin=caller,
            call_value=0,
            gas_limit=3068,
            storage_ref=st,
            execution_id="d" * 64,
        )
        vvm._execute(frame)
        assert not frame.reverted
        assert frame.stack == [1]
        assert frame.gas_remaining == 47
