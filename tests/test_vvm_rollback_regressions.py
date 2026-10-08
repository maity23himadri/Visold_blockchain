"""Regression tests for VVM value rollback accounting.

These tests exercise the real Blockchain.apply_block()/rollback() path with
SQLite storage.  They specifically guard against refunding tx.amount twice
for a reverted value-bearing VVM call while preserving the existing successful
DEPLOY/CALL rollback behavior.
"""

from __future__ import annotations

import os
import tempfile
import time

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet
from visold.crypto.hashing import sha256
from visold.vm.naming import derive_contract_address


def _make_chain(td: str):
    db = os.path.join(td, "rollback_regression.db")
    st = Storage(db)
    bc = Blockchain(st)
    return st, bc


def _apply_single_tx(bc: Blockchain, st: Storage, tx: Transaction, miner: str):
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
    assert block.mine(), "regression block failed to mine"
    ok, msg = bc.apply_block(block)
    assert ok, msg
    return block


def _balances(st: Storage, *addresses: str):
    return tuple(st.get_balance_sat(a) for a in addresses)


def test_reverted_call_value_rollback_is_supply_neutral():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sender, miner = sender_w.address, miner_w.address
        contract = "VSDctestrevert00000000000000000000000"

        runtime = bytes.fromhex("60006000fd")  # PUSH1 0; PUSH1 0; REVERT
        code_hash = sha256(runtime)
        st.save_contract_code(code_hash, runtime)
        st.save_contract(contract, code_hash, sender, int(time.time()))
        st.credit_sat(sender, 2_000_000_000)
        st.credit_sat(miner, 2_000_000_000)

        before_bal = _balances(st, sender, contract, miner)
        before_total = st.sum_all_balances_satoshi()
        before_root = st.compute_state_root()
        before_nonce = st.get_nonce(sender)

        tx = Transaction(
            sender=sender,
            receiver=contract,
            amount=3.0,
            fee=0.0,
            nonce=before_nonce,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=10_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        tx.sign(sender_w)
        _apply_single_tx(bc, st, tx, miner)

        receipt = st.get_vvm_receipt(tx.tx_id)
        assert receipt is not None
        assert receipt["success"] is False
        assert receipt["revert_reason"] == "Reverted"

        rb_ok, rb_msg = bc.rollback(0)
        assert rb_ok, rb_msg

        assert _balances(st, sender, contract, miner) == before_bal
        assert st.sum_all_balances_satoshi() == before_total
        assert st.compute_state_root() == before_root
        assert st.get_nonce(sender) == before_nonce


def test_successful_call_value_rollback_remains_exact():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sender, miner = sender_w.address, miner_w.address
        contract = "VSDctestsuccess0000000000000000000000"

        # Runtime returns 7: PUSH1 3, PUSH1 4, ADD, MSTORE, RETURN.
        runtime = bytes.fromhex("600360040160005260206000f3")
        code_hash = sha256(runtime)
        st.save_contract_code(code_hash, runtime)
        st.save_contract(contract, code_hash, sender, int(time.time()))
        st.credit_sat(sender, 2_000_000_000)
        st.credit_sat(miner, 2_000_000_000)

        before_bal = _balances(st, sender, contract, miner)
        before_total = st.sum_all_balances_satoshi()
        before_root = st.compute_state_root()
        before_nonce = st.get_nonce(sender)

        tx = Transaction(
            sender=sender,
            receiver=contract,
            amount=3.0,
            fee=0.0,
            nonce=before_nonce,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        tx.sign(sender_w)
        _apply_single_tx(bc, st, tx, miner)

        receipt = st.get_vvm_receipt(tx.tx_id)
        assert receipt is not None and receipt["success"] is True
        assert st.get_balance_sat(contract) == before_bal[1] + 300_000_000

        rb_ok, rb_msg = bc.rollback(0)
        assert rb_ok, rb_msg
        assert _balances(st, sender, contract, miner) == before_bal
        assert st.sum_all_balances_satoshi() == before_total
        assert st.compute_state_root() == before_root
        assert st.get_nonce(sender) == before_nonce


def test_deploy_value_rollback_removes_contract_and_value():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sender, miner = sender_w.address, miner_w.address
        st.credit_sat(sender, 2_000_000_000)
        st.credit_sat(miner, 2_000_000_000)

        before_bal = _balances(st, sender, miner)
        before_total = st.sum_all_balances_satoshi()
        before_root = st.compute_state_root()
        before_nonce = st.get_nonce(sender)

        runtime = bytes.fromhex("600060005260206000f3")
        init = bytes.fromhex("600c600c600039600c6000f3") + runtime
        tx = Transaction(
            sender=sender,
            receiver="",
            amount=5.0,
            fee=0.0,
            nonce=before_nonce,
            tx_type=Transaction.TYPE_DEPLOY,
            data=init.hex(),
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        tx.sign(sender_w)
        block = _apply_single_tx(bc, st, tx, miner)

        receipt = st.get_vvm_receipt(tx.tx_id)
        assert receipt is not None and receipt["success"] is True
        deployed = receipt["contract_addr"]
        assert deployed and st.get_contract(deployed) is not None
        assert st.get_balance_sat(deployed) == 500_000_000

        rb_ok, rb_msg = bc.rollback(0)
        assert rb_ok, rb_msg
        assert st.get_contract(deployed) is None
        assert st.get_balance_sat(deployed) == 0
        assert _balances(st, sender, miner) == before_bal
        assert st.sum_all_balances_satoshi() == before_total
        assert st.compute_state_root() == before_root
        assert st.get_nonce(sender) == before_nonce


if __name__ == "__main__":
    test_reverted_call_value_rollback_is_supply_neutral()
    test_successful_call_value_rollback_remains_exact()
    test_deploy_value_rollback_removes_contract_and_value()
    print("VVM_ROLLBACK_REGRESSIONS: 3/3 passed")


def test_same_block_deploy_then_call_is_valid_and_rolls_back_exactly():
    """A top-level deploy may create the target for a later CALL in the same block."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sender, miner = sender_w.address, miner_w.address
        st.credit_sat(sender, 20_000_000_000)

        # Init code copies a tiny runtime that returns the value 7.
        runtime = bytes.fromhex("600360040160005260206000f3")
        init = bytes.fromhex("600d600c600039600d6000f3") + runtime

        before_root = st.compute_state_root()
        before_total = st.sum_all_balances_satoshi()
        before_sender = st.get_balance_sat(sender)
        before_nonce = st.get_nonce(sender)

        deploy = Transaction(
            sender=sender,
            receiver="",
            amount=5.0,
            fee=0.0,
            nonce=before_nonce,
            tx_type=Transaction.TYPE_DEPLOY,
            data=init.hex(),
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        deploy.sign(sender_w)
        contract = derive_contract_address(sender, deploy.nonce, deploy.tx_id)

        call = Transaction(
            sender=sender,
            receiver=contract,
            amount=3.0,
            fee=0.0,
            nonce=before_nonce + 1,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        call.sign(sender_w)

        height = bc.height() + 1
        coinbase = Transaction.coinbase(
            miner, bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD, height
        )
        txs = [coinbase, deploy, call]
        state_root = bc.dry_run_state_root(txs, miner, height)
        block = Block(
            index=height,
            prev_hash=bc.latest_block().block_hash,
            transactions=txs,
            miner_address=miner,
            difficulty=bc.get_difficulty(),
            state_root=state_root,
        )
        assert block.mine()

        # This is the exact regression: validation must see the earlier deploy
        # in the same ordered block, while still rejecting unrelated absent calls.
        ok_valid, valid_msg = bc.validate_block(block)
        assert ok_valid, valid_msg
        ok_apply, apply_msg = bc.apply_block(block)
        assert ok_apply, apply_msg

        deploy_receipt = st.get_vvm_receipt(deploy.tx_id)
        call_receipt = st.get_vvm_receipt(call.tx_id)
        assert deploy_receipt is not None and deploy_receipt["success"] is True
        assert call_receipt is not None and call_receipt["success"] is True
        assert st.get_contract(contract) is not None
        assert st.get_balance_sat(contract) == 800_000_000

        rb_ok, rb_msg = bc.rollback(0)
        assert rb_ok, rb_msg

        assert st.get_contract(contract) is None
        assert st.get_balance_sat(contract) == 0
        assert st.get_balance_sat(sender) == before_sender
        assert st.sum_all_balances_satoshi() == before_total
        assert st.compute_state_root() == before_root
        assert st.get_nonce(sender) == before_nonce
        assert st.get_vvm_receipt(deploy.tx_id) is None
        assert st.get_vvm_receipt(call.tx_id) is None


def test_absent_contract_call_is_still_rejected_when_no_prior_deploy_exists():
    """The same-block exception must not turn arbitrary absent CALLs valid."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        st.credit_sat(sender_w.address, 2_000_000_000)

        call = Transaction(
            sender=sender_w.address,
            receiver="VSDc0000000000000000000000000000000000",
            amount=0.0,
            fee=0.0,
            nonce=0,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        call.sign(sender_w)
        height = bc.height() + 1
        coinbase = Transaction.coinbase(
            miner_w.address,
            bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
            height,
        )
        txs = [coinbase, call]
        root = bc.dry_run_state_root(txs, miner_w.address, height)
        block = Block(
            index=height,
            prev_hash=bc.latest_block().block_hash,
            transactions=txs,
            miner_address=miner_w.address,
            difficulty=bc.get_difficulty(),
            state_root=root,
        )
        assert block.mine()
        ok, msg = bc.validate_block(block)
        assert not ok
        assert "Contract not found for CALL" in msg


def test_name_collision_value_deploy_rollback_restores_exact_state_root():
    """A collision penalty is charged to the sender but must never enter the reward pool."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sender, miner = sender_w.address, miner_w.address

        st.credit_sat(sender, 20_000_000_000)
        st.credit_sat(miner, 2_000_000_000)

        # Install an existing named contract so the new DEPLOY is rejected by
        # the consensus name gate before the VM executes.
        runtime = bytes.fromhex("600060005260206000f3")
        code_hash = sha256(runtime)
        collision_addr = "VSDccollisionexisting000000000000000"
        st.save_contract_code(code_hash, runtime)
        st.save_contract(
            collision_addr,
            code_hash,
            sender,
            int(time.time()),
            contract_name="collision-name",
        )

        before_sender = st.get_balance_sat(sender)
        before_miner = st.get_balance_sat(miner)
        before_total = st.sum_all_balances_satoshi()
        before_nonce = st.get_nonce(sender)
        before_root = st.compute_state_root()

        init = bytes.fromhex("600c600c600039600c6000f3") + runtime
        tx = Transaction(
            sender=sender,
            receiver="",
            amount=5.0,
            fee=0.0,
            nonce=before_nonce,
            tx_type=Transaction.TYPE_DEPLOY,
            data=init.hex(),
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
            contract_name="collision-name",
        )
        tx.sign(sender_w)

        height = bc.height() + 1
        coinbase = Transaction.coinbase(
            miner,
            bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
            height,
        )
        root = bc.dry_run_state_root([coinbase, tx], miner, height)
        block = Block(
            index=height,
            prev_hash=bc.latest_block().block_hash,
            transactions=[coinbase, tx],
            miner_address=miner,
            difficulty=bc.get_difficulty(),
            state_root=root,
        )
        assert block.mine()

        ok, msg = bc.apply_block(block)
        assert ok, msg
        receipt = st.get_vvm_receipt(tx.tx_id)
        assert receipt is not None
        assert receipt["success"] is False
        assert receipt["revert_reason"] == "Contract name already exists"
        assert (receipt.get("storage_delta") or {}).get("__fee_pool_sat__") == 0

        # The collision penalty is deliberately retained by nobody: the
        # sender pays it during the attempted deploy, but _apply_vvm_tx returns
        # zero to the reward pool.  Forward state may therefore differ from the
        # pre-block state, but rollback must restore it exactly.
        assert st.get_balance_sat(sender) < before_sender
        assert st.get_balance_sat(miner) > before_miner

        rb_ok, rb_msg = bc.rollback(0)
        assert rb_ok, rb_msg

        assert st.get_balance_sat(sender) == before_sender
        assert st.get_balance_sat(miner) == before_miner
        assert st.sum_all_balances_satoshi() == before_total
        assert st.get_nonce(sender) == before_nonce
        assert st.compute_state_root() == before_root
        assert st.get_contract(collision_addr) is not None
        assert st.get_vvm_receipt(tx.tx_id) is None
