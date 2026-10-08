"""Regression tests for VVM SELFDESTRUCT accounting and rollback."""

from __future__ import annotations

import os
import tempfile
import time

from visold.chain.blockchain import Blockchain
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.vm.frame import _VMFrame
from visold.vm.naming import derive_contract_address
from visold.wallet.wallet import Wallet


def _make_chain(td: str):
    st = Storage(os.path.join(td, "selfdestruct_regression.db"))
    return st, Blockchain(st)


def _addr(value: int) -> str:
    return _VMFrame._int_to_addr(_VMFrame.__new__(_VMFrame), value)


def _make_block(bc: Blockchain, miner: str, txs):
    height = bc.height() + 1
    coinbase = Transaction.coinbase(
        miner,
        bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
        height,
    )
    transactions = [coinbase, *txs]
    state_root = bc.dry_run_state_root(transactions, miner, height)
    block = Block(
        index=height,
        prev_hash=bc.latest_block().block_hash,
        transactions=transactions,
        miner_address=miner,
        difficulty=bc.get_difficulty(),
        state_root=state_root,
    )
    assert block.mine(), "SELFDESTRUCT regression block failed to mine"
    ok, msg = bc.validate_block(block)
    assert ok, msg
    ok, msg = bc.apply_block(block)
    assert ok, msg
    return block, state_root


def _install_contract(st: Storage, address: str, runtime: bytes, creator: str):
    code_hash = sha256(runtime)
    st.save_contract_code(code_hash, runtime)
    st.save_contract(address, code_hash, creator, int(time.time()))


def test_selfdestruct_top_level_value_moves_value_once_and_rolls_back_exactly():
    """5 VSD sent to a contract and immediately self-destructed must remain supply-neutral."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sender, miner = sender_w.address, miner_w.address
        contract = "VSDcselfdestructreg000000000000000"
        beneficiary = _addr(2)

        _install_contract(st, contract, bytes.fromhex("6002ff"), sender)
        st.credit_sat(sender, 20_000_000_000)
        st.credit_sat(miner, 2_000_000_000)
        st.set_balance(contract, 0.0)

        before = {
            "sender": st.get_balance_sat(sender),
            "contract": st.get_balance_sat(contract),
            "beneficiary": st.get_balance_sat(beneficiary),
            "miner": st.get_balance_sat(miner),
            "supply": st.sum_all_balances_satoshi(),
            "root": st.compute_state_root(),
            "nonce": st.get_nonce(sender),
        }

        tx = Transaction(
            sender=sender,
            receiver=contract,
            amount=5.0,
            fee=0.0,
            nonce=before["nonce"],
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        tx.sign(sender_w)

        block, dry_root = _make_block(bc, miner, [tx])
        assert block.state_root == dry_root
        assert st.compute_state_root() == dry_root
        assert st.get_balance_sat(contract) == 0
        assert st.get_balance_sat(beneficiary) == 500_000_000
        assert st.sum_all_balances_satoshi() == before["supply"] + bc.compute_reward_sat(1)
        assert st.get_contract(contract) is None  # destroyed rows are hidden by canonical lookup

        receipt = st.get_vvm_receipt(tx.tx_id)
        assert receipt is not None and receipt["success"] is True
        assert (receipt.get("storage_delta") or {}).get(
            "__self_destruct_transfers__") == [[contract, beneficiary, 500_000_000]]

        rb_ok, rb_msg = bc.rollback(0)
        assert rb_ok, rb_msg
        assert st.get_balance_sat(sender) == before["sender"]
        assert st.get_balance_sat(contract) == before["contract"]
        assert st.get_balance_sat(beneficiary) == before["beneficiary"]
        assert st.get_balance_sat(miner) == before["miner"]
        assert st.sum_all_balances_satoshi() == before["supply"]
        assert st.compute_state_root() == before["root"]
        assert st.get_nonce(sender) == before["nonce"]
        restored = st.get_contract(contract)
        assert restored is not None and not restored.get("destroyed", False)


def test_selfdestruct_with_existing_contract_balance_transfers_full_balance_once():
    """An existing 5 VSD balance plus 3 VSD CALLVALUE must transfer 8 VSD, not 3 or 5."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sender, miner = sender_w.address, miner_w.address
        contract = "VSDcselfdestructfunded000000000000"
        beneficiary = _addr(2)

        _install_contract(st, contract, bytes.fromhex("6002ff"), sender)
        st.credit_sat(sender, 20_000_000_000)
        st.credit_sat(miner, 2_000_000_000)
        st.set_balance(contract, 5.0)

        before_supply = st.sum_all_balances_satoshi()
        before_sender = st.get_balance_sat(sender)
        before_miner = st.get_balance_sat(miner)
        before_root = st.compute_state_root()
        tx = Transaction(
            sender=sender,
            receiver=contract,
            amount=3.0,
            fee=0.0,
            nonce=0,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        tx.sign(sender_w)

        _make_block(bc, miner, [tx])
        assert st.get_balance_sat(contract) == 0
        assert st.get_balance_sat(beneficiary) == 800_000_000
        assert st.sum_all_balances_satoshi() == before_supply + bc.compute_reward_sat(1)
        assert st.compute_state_root() != before_root

        ok, msg = bc.rollback(0)
        assert ok, msg
        assert st.get_balance_sat(sender) == before_sender
        assert st.get_balance_sat(contract) == 500_000_000
        assert st.get_balance_sat(beneficiary) == 0
        assert st.get_balance_sat(miner) == before_miner
        assert st.sum_all_balances_satoshi() == before_supply
        assert st.compute_state_root() == before_root


def test_same_block_deploy_then_selfdestruct_dry_run_and_rollback_are_exact():
    """A newly deployed contract can self-destruct later in the same block."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sender, miner = sender_w.address, miner_w.address
        beneficiary = _addr(2)

        runtime = bytes.fromhex("6002ff")
        init = bytes.fromhex("6003600c60003960036000f3") + runtime
        deploy = Transaction(
            sender=sender,
            receiver="",
            amount=5.0,
            fee=0.0,
            nonce=0,
            tx_type=Transaction.TYPE_DEPLOY,
            data=init.hex(),
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        deploy.sign(sender_w)
        contract = derive_contract_address(sender, deploy.nonce, deploy.tx_id)
        destruct = Transaction(
            sender=sender,
            receiver=contract,
            amount=0.0,
            fee=0.0,
            nonce=1,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        destruct.sign(sender_w)

        st.credit_sat(sender, 20_000_000_000)
        st.credit_sat(miner, 2_000_000_000)
        before = (
            st.get_balance_sat(sender),
            st.get_balance_sat(miner),
            st.get_balance_sat(beneficiary),
            st.sum_all_balances_satoshi(),
            st.compute_state_root(),
            st.get_nonce(sender),
        )

        block, dry_root = _make_block(bc, miner, [deploy, destruct])
        assert st.compute_state_root() == dry_root
        assert st.get_balance_sat(contract) == 0
        assert st.get_balance_sat(beneficiary) == 500_000_000
        assert st.get_contract(contract) is None

        ok, msg = bc.rollback(0)
        assert ok, msg
        assert st.get_balance_sat(sender) == before[0]
        assert st.get_balance_sat(miner) == before[1]
        assert st.get_balance_sat(beneficiary) == before[2]
        assert st.sum_all_balances_satoshi() == before[3]
        assert st.compute_state_root() == before[4]
        assert st.get_nonce(sender) == before[5]
        assert st.get_contract(contract) is None


def test_selfdestruct_spent_beneficiary_refuses_rollback_atomically():
    """Once the beneficiary spends the destructed contract's funds, rollback must refuse without mutation."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sender, miner = sender_w.address, miner_w.address
        contract = "VSDcselfdestructspent00000000000000"
        beneficiary = _addr(2)

        _install_contract(st, contract, bytes.fromhex("6002ff"), sender)
        st.credit_sat(sender, 20_000_000_000)
        st.credit_sat(miner, 2_000_000_000)
        st.set_balance(contract, 5.0)
        tx = Transaction(
            sender=sender,
            receiver=contract,
            amount=0.0,
            fee=0.0,
            nonce=0,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        tx.sign(sender_w)
        _make_block(bc, miner, [tx])

        assert st.debit_sat(beneficiary, 500_000_000)
        before = (
            st.get_balance_sat(sender),
            st.get_balance_sat(contract),
            st.get_balance_sat(beneficiary),
            st.get_balance_sat(miner),
            st.sum_all_balances_satoshi(),
            st.compute_state_root(),
            st.get_nonce(sender),
            bc.height(),
        )
        ok, _ = bc.rollback(0)
        assert not ok
        after = (
            st.get_balance_sat(sender),
            st.get_balance_sat(contract),
            st.get_balance_sat(beneficiary),
            st.get_balance_sat(miner),
            st.sum_all_balances_satoshi(),
            st.compute_state_root(),
            st.get_nonce(sender),
            bc.height(),
        )
        assert after == before
