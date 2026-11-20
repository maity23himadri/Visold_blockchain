"""V4 regression tests for Section 79: Contract Storage, State Isolation, and Contract Lifecycle."""

from __future__ import annotations

import os
import tempfile
import time
import pytest

from visold.chain.blockchain import Blockchain
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.wallet.wallet import Wallet


def _make_chain(td: str):
    db = os.path.join(td, "sec79_audit.db")
    st = Storage(db)
    bc = Blockchain(st)
    return st, bc


def _caddr(label: str) -> str:
    return "VSDc" + sha256(label.encode())[:36]


def _dummy_frame(st: Storage) -> _VMFrame:
    return _VMFrame(code=b"", calldata=b"", caller="", address="", origin="", call_value=0, gas_limit=0, storage_ref=st)


def _apply_single_tx(bc: Blockchain, st: Storage, tx: Transaction, miner: str) -> Block:
    height = bc.height() + 1
    coinbase = Transaction.coinbase(
        miner,
        bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
        height,
    )
    state_root = bc.dry_run_state_root([coinbase, tx], miner, height)
    block = Block(
        index=height,
        prev_hash=bc.latest_block().block_hash,
        transactions=[coinbase, tx],
        miner_address=miner,
        difficulty=bc.get_difficulty(),
        state_root=state_root,
    )
    assert block.mine(), "block failed to mine"
    ok, msg = bc.apply_block(block)
    assert ok, f"apply_block failed: {msg}"
    return block


def _sign_call(sender_w: Wallet, contract: str, nonce: int, data_hex: str = "",
               amount: float = 0.0, gas_limit: int = 200_000,
               gas_price: float = 1e-7) -> Transaction:
    tx = Transaction(
        sender=sender_w.address,
        receiver=contract,
        amount=amount,
        fee=0.0,
        nonce=nonce,
        tx_type=Transaction.TYPE_CALL,
        data=data_hex,
        gas_limit=gas_limit,
        gas_price=gas_price,
    )
    tx.sign(sender_w)
    return tx


def test_rollback_preserves_storage_tag_on_overwritten_slot():
    """Rollback should restore both slot value and pre-existing non-zero type_tag."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        st.credit_sat(sender_w.address, 5_000_000_000)
        st.credit_sat(miner_w.address, 5_000_000_000)

        contract = _caddr("sec79_tag_bug")
        runtime = bytes.fromhex(
            "60003560001a600114601257"
            "602260005500"
            "5b60116004ed60005500"
        )
        code_hash = sha256(runtime)
        st.save_contract_code(code_hash, runtime)
        st.save_contract(contract, code_hash, sender_w.address, int(time.time()))

        tx1 = _sign_call(sender_w, contract, st.get_nonce(sender_w.address), data_hex="01")
        _apply_single_tx(bc, st, tx1, miner_w.address)
        assert st.sload(contract, "0x0") == 0x11
        assert st.get_storage_tag(contract, "0x0") == 4
        root_b1 = st.compute_state_root()

        tx2 = _sign_call(sender_w, contract, st.get_nonce(sender_w.address), data_hex="02")
        _apply_single_tx(bc, st, tx2, miner_w.address)
        assert st.sload(contract, "0x0") == 0x22
        assert st.get_storage_tag(contract, "0x0") == 0

        bc.rollback(1)

        assert st.sload(contract, "0x0") == 0x11
        assert st.get_storage_tag(contract, "0x0") == 4
        assert st.compute_state_root() == root_b1


def test_create2_redeploy_after_selfdestruct_consistent_state_root():
    """CREATE2 after SELFDESTRUCT does not cause dry_run_state_root vs apply_block divergence."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        df = _dummy_frame(st)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        st.credit_sat(sender_w.address, 5_000_000_000)
        st.credit_sat(miner_w.address, 5_000_000_000)

        factory = _caddr("sec79_factory")
        init_code = bytes.fromhex("603360005360ff60015360026000f3")
        assert len(init_code) == 15

        factory_code = (
            bytes([0x6E]) + init_code +
            bytes.fromhex("600052" "6001600f60116000f5" "60005500")
        )
        code_hash = sha256(factory_code)
        st.save_contract_code(code_hash, factory_code)
        st.save_contract(factory, code_hash, sender_w.address, int(time.time()))

        tx1 = _sign_call(sender_w, factory, st.get_nonce(sender_w.address), gas_limit=500_000)
        _apply_single_tx(bc, st, tx1, miner_w.address)

        child_int = st.sload(factory, "0x0")
        assert child_int != 0, "Initial CREATE2 failed"
        child_addr = df._int_to_addr(child_int)
        assert st.get_contract(child_addr) is not None

        tx2 = _sign_call(sender_w, child_addr, st.get_nonce(sender_w.address), gas_limit=200_000)
        _apply_single_tx(bc, st, tx2, miner_w.address)
        assert st.get_contract(child_addr) is None

        tx3 = _sign_call(sender_w, factory, st.get_nonce(sender_w.address), gas_limit=500_000)
        height = bc.height() + 1
        coinbase = Transaction.coinbase(
            miner_w.address,
            bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
            height,
        )
        declared_root = bc.dry_run_state_root([coinbase, tx3], miner_w.address, height)
        b3 = Block(
            index=height,
            prev_hash=bc.latest_block().block_hash,
            transactions=[coinbase, tx3],
            miner_address=miner_w.address,
            difficulty=bc.get_difficulty(),
            state_root=declared_root,
        )
        assert b3.mine()
        ok, msg = bc.apply_block(b3)
        assert ok, msg


def test_create2_redeploy_after_selfdestruct_rejected_on_direct_apply():
    """CREATE2 to a previously destroyed address is rejected consistently in VM and storage."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        df = _dummy_frame(st)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        st.credit_sat(sender_w.address, 5_000_000_000)
        st.credit_sat(miner_w.address, 5_000_000_000)

        factory = _caddr("sec79_factory_b")
        init_code = bytes.fromhex("603360005360ff60015360026000f3")
        factory_code = (
            bytes([0x6E]) + init_code +
            bytes.fromhex("600052" "6001600f60116000f5" "60005500")
        )
        code_hash = sha256(factory_code)
        st.save_contract_code(code_hash, factory_code)
        st.save_contract(factory, code_hash, sender_w.address, int(time.time()))

        tx1 = _sign_call(sender_w, factory, st.get_nonce(sender_w.address), gas_limit=500_000)
        _apply_single_tx(bc, st, tx1, miner_w.address)
        child_int = st.sload(factory, "0x0")
        child_addr = df._int_to_addr(child_int)

        tx2 = _sign_call(sender_w, child_addr, st.get_nonce(sender_w.address), gas_limit=200_000)
        _apply_single_tx(bc, st, tx2, miner_w.address)
        assert st.get_contract(child_addr) is None

        tx3 = _sign_call(sender_w, factory, st.get_nonce(sender_w.address), gas_limit=500_000)
        dummy_block = Block(
            index=bc.height() + 1,
            prev_hash=bc.latest_block().block_hash,
            transactions=[tx3],
            miner_address=miner_w.address,
            difficulty=bc.get_difficulty(),
        )
        _, ok, _ = bc._apply_vvm_tx(tx3, dummy_block)
        assert ok
        assert st.sload(factory, "0x0") == 0
        assert st.get_contract(child_addr) is None


def test_selfdestruct_zeroes_balance_prevents_double_spend_in_block():
    """SELFDESTRUCT zeroes target balance immediately so second CALL cannot double-spend."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        df = _dummy_frame(st)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sink_w = Wallet.generate()
        st.credit_sat(sender_w.address, 5_000_000_000)
        st.credit_sat(miner_w.address, 5_000_000_000)

        contract_b = _caddr("sec79_target_b")
        contract_a = _caddr("sec79_caller_a")
        st.credit_sat(contract_b, 1_000_000)

        sink_int = df._addr_to_int(sink_w.address)
        sink_bytes = sink_int.to_bytes(32, "big")

        code_b = (
            bytes.fromhex("60003560001a600114600e57") +
            bytes.fromhex("33ff") +
            bytes.fromhex("5b6000600060006000620f4240") +
            bytes([0x7F]) + sink_bytes +
            bytes.fromhex("61c350f100")
        )
        hb = sha256(code_b)
        st.save_contract_code(hb, code_b)
        st.save_contract(contract_b, hb, sender_w.address, int(time.time()))

        b_int = df._addr_to_int(contract_b)
        b_bytes = b_int.to_bytes(32, "big")
        code_a = (
            bytes.fromhex("6000600053") +
            bytes.fromhex("60006000600160006000") +
            bytes([0x7F]) + b_bytes +
            bytes.fromhex("620186a0f150") +
            bytes.fromhex("6001600053") +
            bytes.fromhex("60006000600160006000") +
            bytes([0x7F]) + b_bytes +
            bytes.fromhex("620186a0f15000")
        )
        ha = sha256(code_a)
        st.save_contract_code(ha, code_a)
        st.save_contract(contract_a, ha, sender_w.address, int(time.time()))

        vvm = VVMEngine(storage=st)
        tx = _sign_call(sender_w, contract_a, 0, gas_limit=500_000)
        res = vvm.call(
            caller=sender_w.address,
            contract=contract_a,
            calldata=b"",
            call_value=0,
            gas_limit=500_000,
            block_ctx=bc.latest_block(),
            tx=tx,
        )
        assert res.success, f"VM call failed: {res.revert_reason}"
        assert res.self_destruct_transfers == [(contract_b, contract_a, 1_000_000)]
        assert res.balance_deltas.get(contract_b, 0) == 0
        assert res.balance_deltas.get(sink_w.address, 0) == 0
