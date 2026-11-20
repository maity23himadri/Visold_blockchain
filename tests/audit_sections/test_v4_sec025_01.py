"""V4 regression tests for Section 25 (Session 01): Fees, Gas Calculation, and Numerical Boundaries."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.units import gas_fee_to_sat, to_satoshi
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op
from visold.vm.precompiles import VVMPrecompiles
from visold.wallet.wallet import Wallet


class _BlockCtx:
    index = 1
    timestamp = 1_700_000_000
    difficulty = 4.0
    miner_address = "VSD1miner00000000000000000000000000"


def _make_storage(tmp_path):
    db_path = str(tmp_path / "test_sec25.db")
    return Storage(db_path=db_path)


def test_estimate_gas_and_simulate_succeed_on_state_mutating_contract(tmp_path):
    """VVMEngine.simulate() and estimate_gas() work on state-mutating (SSTORE) contracts."""
    storage = _make_storage(tmp_path)
    engine = VVMEngine(storage)
    wallet = Wallet.generate()

    runtime = bytes([Op.PUSH1, 0x42, Op.PUSH1, 0x00, Op.SSTORE, Op.STOP])
    init_code = bytes([
        Op.PUSH1, len(runtime),
        Op.PUSH1, 12,
        Op.PUSH1, 0,
        Op.CODECOPY,
        Op.PUSH1, len(runtime),
        Op.PUSH1, 0,
        Op.RETURN,
    ]) + runtime

    deploy_tx = Transaction(
        sender=wallet.address,
        receiver="",
        amount=0.0,
        tx_type=Transaction.TYPE_DEPLOY,
        data=init_code.hex(),
        gas_limit=200_000,
        gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    deploy_tx.sign(wallet)

    dep_res = engine.deploy(
        sender=wallet.address,
        bytecode=init_code,
        call_value=0,
        gas_limit=200_000,
        block_ctx=_BlockCtx(),
        tx=deploy_tx,
    )
    assert dep_res.success, dep_res.revert_reason
    contract_addr = dep_res.contract_addr
    storage.save_contract_code(sha256(runtime), runtime)
    storage.save_contract(contract_addr, sha256(runtime), wallet.address, 1)

    call_tx = Transaction(
        sender=wallet.address,
        receiver=contract_addr,
        amount=0.0,
        tx_type=Transaction.TYPE_CALL,
        data="",
        gas_limit=100_000,
        gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    call_tx.sign(wallet)

    real_res = engine.call(
        caller=wallet.address,
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=100_000,
        block_ctx=_BlockCtx(),
        tx=call_tx,
    )
    assert real_res.success, real_res.revert_reason
    assert real_res.gas_used < 30_000

    sim_res = engine.simulate(
        caller=wallet.address,
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=100_000,
        block_ctx=_BlockCtx(),
    )
    assert sim_res.success is True, sim_res.revert_reason

    est = engine.estimate_gas(
        caller=wallet.address,
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        block_ctx=_BlockCtx(),
    )
    assert est < Config.VVM_TX_GAS_CAP
    assert est >= real_res.gas_used


def test_internal_call_precompile_respects_gas_budget_and_oog(tmp_path):
    """Unknown precompile does not overcharge past gas_param, and SHA256 OOG reverts cleanly."""
    storage = _make_storage(tmp_path)
    engine = VVMEngine(storage)
    wallet = Wallet.generate()

    unknown_precompile = "VSDcPRECOMPILE999999999999999"
    tmp_frame = _VMFrame.__new__(_VMFrame)
    addr_int = tmp_frame._addr_to_int(unknown_precompile)
    addr_bytes = addr_int.to_bytes(32, "big")

    code = bytes([
        Op.PUSH1, 0,
        Op.PUSH1, 0,
        Op.PUSH1, 0,
        Op.PUSH1, 0,
        Op.PUSH1, 0,
        Op.PUSH32, *addr_bytes,
        Op.PUSH1, 100,  # gas_param = 100
        Op.CALL,
        Op.POP,
        Op.STOP,
    ])
    ch = sha256(code)
    contract_addr = "VSDc" + "11" * 18
    storage.save_contract_code(ch, code)
    storage.save_contract(contract_addr, ch, wallet.address, 1)

    tx = Transaction(
        sender=wallet.address,
        receiver=contract_addr,
        amount=0.0,
        tx_type=Transaction.TYPE_CALL,
        data="",
        gas_limit=100_000,
        gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    tx.sign(wallet)

    res = engine.call(
        caller=wallet.address,
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=100_000,
        block_ctx=_BlockCtx(),
        tx=tx,
    )
    assert res.success is True
    assert res.gas_used < 21_000

    # Part (b): SHA256 precompile OOG with tight gas_limit must not succeed
    sha_addr_int = tmp_frame._addr_to_int(VVMPrecompiles.SHA256)
    sha_addr_bytes = sha_addr_int.to_bytes(32, "big")
    code_sha = bytes([
        Op.PUSH1, 0,
        Op.PUSH1, 0,
        Op.PUSH1, 128,
        Op.PUSH1, 0,
        Op.PUSH1, 0,
        Op.PUSH32, *sha_addr_bytes,
        Op.PUSH2, 0x03, 0xE8,  # gas_param = 1000
        Op.CALL,
        Op.STOP,
    ])
    ch2 = sha256(code_sha)
    contract_addr2 = "VSDc" + "22" * 18
    storage.save_contract_code(ch2, code_sha)
    storage.save_contract(contract_addr2, ch2, wallet.address, 1)

    res2 = engine.call(
        caller=wallet.address,
        contract=contract_addr2,
        calldata=b"",
        call_value=0,
        gas_limit=130,
        block_ctx=_BlockCtx(),
        tx=tx,
    )
    assert res2.success is True
    # Direct _internal_call with gas=105 (< 108 needed for 128-byte SHA256) returns False (OOG)
    frame = _VMFrame(
        code=b"",
        calldata=b"",
        caller=wallet.address,
        address=contract_addr2,
        origin=wallet.address,
        call_value=0,
        gas_limit=105,
        storage_ref=storage,
    )
    ok_oog, _ret_oog = engine._internal_call(
        caller_frame=frame,
        callee_addr=VVMPrecompiles.SHA256,
        calldata=b"\x00" * 128,
        call_value=0,
        gas=105,
    )
    assert ok_oog is False


def test_compute_fee_and_compute_fee_sat_consistent(tmp_path):
    """Transaction.compute_fee() and compute_fee_sat() agree, and mempool indexes non-zero fee."""
    w = Wallet.generate()
    w2 = Wallet.generate()

    tx_dust = Transaction(
        sender=w.address,
        receiver=w2.address,
        amount=0.00000150,
        fee=0.00000001,
    )
    assert to_satoshi(tx_dust.compute_fee()) == tx_dust.compute_fee_sat()

    tx_id = Transaction(
        sender=w.address,
        receiver="",
        amount=0.0,
        fee=0.00001000,
        tx_type=Transaction.TYPE_REGISTER,
        memo="identity:alice_test",
    )
    assert tx_id.compute_fee_sat() == Config.MIN_TX_FEE_SAT
    assert to_satoshi(tx_id.compute_fee()) == Config.MIN_TX_FEE_SAT

    storage = _make_storage(tmp_path)
    storage.mempool_add(tx_id)
    row = storage._conn().execute(
        "SELECT fee FROM mempool WHERE tx_id=?", (tx_id.tx_id,)
    ).fetchone()
    assert row["fee"] > 0.0


def test_transaction_is_valid_rejects_combined_amount_and_gas_fee_overflow():
    """Transaction.is_valid() rejects transactions where amount_sat + gas_fee_sat > 2^63-1."""
    w = Wallet.generate()
    contract_addr = "VSDc" + "aa" * 18

    tx = Transaction(
        sender=w.address,
        receiver=contract_addr,
        amount=90_000_000_000.0,
        tx_type=Transaction.TYPE_CALL,
        data="",
        gas_limit=1_000_000,
        gas_price=90_000.0,
    )
    tx.sign(w)

    total_sat = to_satoshi(tx.amount) + gas_fee_to_sat(tx.gas_limit, tx.gas_price)
    assert total_sat > (2**63 - 1)
    ok, _msg = tx.is_valid()
    assert ok is False
