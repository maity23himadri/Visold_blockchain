"""Regression coverage for the two confirmed 2026-10-06 audit findings.

These tests deliberately exercise the real block validation/mempool paths and
also cover the intended top-up semantics so the fix does not over-tighten the
protocol.
"""

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
from visold.wallet.wallet import Wallet


def _fast_chain(td: str):
    old_min = Config.MIN_DIFFICULTY
    old_init = Config.INITIAL_DIFFICULTY
    Config.MIN_DIFFICULTY = 0.001
    Config.INITIAL_DIFFICULTY = 0.001
    st = Storage(os.path.join(td, "repair_regression.db"))
    bc = Blockchain(st)
    return st, bc, old_min, old_init


def _restore_diff(old_min: float, old_init: float) -> None:
    Config.MIN_DIFFICULTY = old_min
    Config.INITIAL_DIFFICULTY = old_init


def _mined_block(bc: Blockchain, txs: list[Transaction], miner: str, height: int | None = None) -> Block:
    height = bc.height() + 1 if height is None else height
    root = bc.dry_run_state_root(txs, miner, height)
    prev = bc.latest_block()
    block = Block(
        index=height,
        prev_hash=prev.block_hash if prev else "0" * 64,
        transactions=list(txs),
        miner_address=miner,
        difficulty=bc.get_difficulty(),
        state_root=root,
    )
    assert block.mine()
    return block


def _register_tx(wallet: Wallet, amount: float, role: str, nonce: int) -> Transaction:
    tx = Transaction(
        sender=wallet.address,
        receiver="",
        amount=amount,
        fee=round(amount * Config.TX_FEE_RATE, 8),
        memo=role,
        nonce=nonce,
        tx_type=Transaction.TYPE_REGISTER,
    )
    tx.sign(wallet)
    return tx


def _call_tx(wallet: Wallet, contract: str, gas_limit: int, nonce: int) -> Transaction:
    tx = Transaction(
        sender=wallet.address,
        receiver=contract,
        amount=0.0,
        fee=0.0,
        nonce=nonce,
        tx_type=Transaction.TYPE_CALL,
        data="",
        gas_limit=gas_limit,
        gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    tx.sign(wallet)
    return tx


def _install_stop_contract(st: Storage, address: str, creator: str) -> None:
    code = bytes((0x00,))  # STOP
    code_hash = sha256(code)
    st.save_contract_code(code_hash, code)
    st.save_contract(address, code_hash, creator, int(time.time()))


def test_consensus_rejects_initial_miner_registration_below_minimum():
    with tempfile.TemporaryDirectory() as td:
        st, bc, old_min, old_init = _fast_chain(td)
        try:
            owner = Wallet.generate()
            miner = Wallet.generate()
            st.credit_sat(owner.address, 20 * Config.SATOSHI_PER_VSD)

            tx = _register_tx(owner, 1.0, "miner", st.get_nonce(owner.address))
            cb = Transaction.coinbase(
                miner.address,
                bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
                1,
            )
            block = _mined_block(bc, [cb, tx], miner.address, 1)

            ok, msg = bc.validate_block(block)
            assert not ok
            assert "REGISTER(miner) stake below minimum" in msg
        finally:
            _restore_diff(old_min, old_init)


def test_consensus_rejects_initial_investor_registration_below_minimum():
    with tempfile.TemporaryDirectory() as td:
        st, bc, old_min, old_init = _fast_chain(td)
        try:
            owner = Wallet.generate()
            miner = Wallet.generate()
            st.credit_sat(owner.address, 250 * Config.SATOSHI_PER_VSD)

            tx = _register_tx(owner, 199.0, "investor", st.get_nonce(owner.address))
            cb = Transaction.coinbase(
                miner.address,
                bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
                1,
            )
            block = _mined_block(bc, [cb, tx], miner.address, 1)

            ok, msg = bc.validate_block(block)
            assert not ok
            assert "REGISTER(investor) stake below minimum" in msg
        finally:
            _restore_diff(old_min, old_init)


def test_existing_same_role_top_up_below_minimum_remains_valid():
    with tempfile.TemporaryDirectory() as td:
        st, bc, old_min, old_init = _fast_chain(td)
        try:
            owner = Wallet.generate()
            miner = Wallet.generate()
            st.credit_sat(owner.address, 20 * Config.SATOSHI_PER_VSD)
            st.set_role(owner.address, "miner", 10.0)

            tx = _register_tx(owner, 0.1, "miner", st.get_nonce(owner.address))
            cb = Transaction.coinbase(
                miner.address,
                bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
                1,
            )
            block = _mined_block(bc, [cb, tx], miner.address, 1)

            ok, msg = bc.validate_block(block)
            assert ok, msg
            ok, msg = bc.apply_block(block)
            assert ok, msg
            role = st.get_role(owner.address)
            assert role is not None
            assert role["role"] == "miner"
            assert role["stake"] == 10.1
        finally:
            _restore_diff(old_min, old_init)


def test_mempool_rejects_initial_subminimum_role_registration():
    with tempfile.TemporaryDirectory() as td:
        st, bc, old_min, old_init = _fast_chain(td)
        try:
            owner = Wallet.generate()
            st.credit_sat(owner.address, 20 * Config.SATOSHI_PER_VSD)
            tx = _register_tx(owner, 1.0, "miner", st.get_nonce(owner.address))

            ok, msg = bc.mempool.add(tx)
            assert not ok
            assert "Minimum miner stake" in msg
        finally:
            _restore_diff(old_min, old_init)


def test_consensus_rejects_block_when_aggregate_vvm_gas_exceeds_limit():
    old_limit = Config.VVM_BLOCK_GAS_LIMIT
    with tempfile.TemporaryDirectory() as td:
        st, bc, old_min, old_init = _fast_chain(td)
        try:
            Config.VVM_BLOCK_GAS_LIMIT = 100
            sender1 = Wallet.generate()
            sender2 = Wallet.generate()
            miner = Wallet.generate()
            st.credit_sat(sender1.address, 1 * Config.SATOSHI_PER_VSD)
            st.credit_sat(sender2.address, 1 * Config.SATOSHI_PER_VSD)
            contract = "VSDc" + "12" * 18
            _install_stop_contract(st, contract, miner.address)

            tx1 = _call_tx(sender1, contract, 60, st.get_nonce(sender1.address))
            tx2 = _call_tx(sender2, contract, 60, st.get_nonce(sender2.address))
            cb = Transaction.coinbase(
                miner.address,
                bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
                1,
            )
            block = _mined_block(bc, [cb, tx1, tx2], miner.address, 1)

            ok, msg = bc.validate_block(block)
            assert not ok
            assert "Block VVM gas limit exceeded" in msg
        finally:
            _restore_diff(old_min, old_init)
            Config.VVM_BLOCK_GAS_LIMIT = old_limit


def test_consensus_accepts_block_at_exact_aggregate_vvm_gas_limit():
    old_limit = Config.VVM_BLOCK_GAS_LIMIT
    with tempfile.TemporaryDirectory() as td:
        st, bc, old_min, old_init = _fast_chain(td)
        try:
            Config.VVM_BLOCK_GAS_LIMIT = 100
            sender1 = Wallet.generate()
            sender2 = Wallet.generate()
            miner = Wallet.generate()
            st.credit_sat(sender1.address, 1 * Config.SATOSHI_PER_VSD)
            st.credit_sat(sender2.address, 1 * Config.SATOSHI_PER_VSD)
            contract = "VSDc" + "34" * 18
            _install_stop_contract(st, contract, miner.address)

            tx1 = _call_tx(sender1, contract, 50, st.get_nonce(sender1.address))
            tx2 = _call_tx(sender2, contract, 50, st.get_nonce(sender2.address))
            cb = Transaction.coinbase(
                miner.address,
                bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
                1,
            )
            block = _mined_block(bc, [cb, tx1, tx2], miner.address, 1)

            ok, msg = bc.validate_block(block)
            assert ok, msg
        finally:
            _restore_diff(old_min, old_init)
            Config.VVM_BLOCK_GAS_LIMIT = old_limit
