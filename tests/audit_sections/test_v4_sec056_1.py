"""V4 Regression Tests for Section 56: Transaction Fee Aggregation and Block Fee Accounting."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.kernel.units import conservation_check, from_satoshi, gas_fee_to_sat
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_chain(td: str):
    db = os.path.join(td, "sec56_audit.db")
    st = Storage(db)
    bc = Blockchain(st)
    return st, bc


def _mine_and_apply(bc: Blockchain, txs: list[Transaction], miner: str) -> Block:
    height = bc.height() + 1
    coinbase = Transaction.coinbase(
        miner,
        bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
        height,
    )
    all_txs = [coinbase] + list(txs)
    state_root = bc.dry_run_state_root(all_txs, miner, height)
    block = Block(
        index=height,
        prev_hash=bc.latest_block().block_hash,
        transactions=all_txs,
        miner_address=miner,
        difficulty=bc.get_difficulty(),
        state_root=state_root,
    )
    assert block.mine(), "failed to mine block"
    ok_val, msg_val = bc.validate_block(block)
    assert ok_val, f"validate_block failed: {msg_val}"
    ok_app, msg_app = bc.apply_block(block)
    assert ok_app, f"apply_block failed: {msg_app}"
    return block


def test_vvm_name_collision_penalty_credits_burn_address_and_preserves_conservation():
    """V4 Fix:
    VVM DEPLOY name-collision penalty debits collision_fee_sat from sender and
    credits Config.BURN_ADDRESS, preserving conservation_check() on apply and rollback.
    """
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        deployer_w = Wallet.generate()
        miner_w = Wallet.generate()
        deployer = deployer_w.address
        miner = miner_w.address

        # Block 1: fund deployer with block subsidy
        _mine_and_apply(bc, [], deployer)
        assert conservation_check(st) is True

        init_hex = "00"
        now = int(time.time())

        # Block 2: deploy contract named "my_token"
        tx1 = Transaction(
            sender=deployer,
            receiver="",
            amount=0.0,
            fee=0.0,
            timestamp=now,
            nonce=0,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_DEPLOY,
            data=init_hex,
            gas_limit=100_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
            contract_name="my_token",
        )
        tx1.sign(deployer_w)
        _mine_and_apply(bc, [tx1], miner)
        assert conservation_check(st) is True

        # Block 3: second deploy with the same contract_name triggers collision
        tx2 = Transaction(
            sender=deployer,
            receiver="",
            amount=0.0,
            fee=0.0,
            timestamp=now + 1,
            nonce=1,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_DEPLOY,
            data=init_hex,
            gas_limit=50_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
            contract_name="my_token",
        )
        tx2.sign(deployer_w)

        bal_before = st.get_balance_sat(deployer)
        burn_before = st.get_balance_sat(Config.BURN_ADDRESS)
        _mine_and_apply(bc, [tx2], miner)

        expected_penalty = gas_fee_to_sat(
            min(Config.VVM_DEPLOY_GAS_BASE, tx2.gas_limit), tx2.gas_price
        )
        assert expected_penalty == 32_000

        receipt = st.get_vvm_receipt(tx2.tx_id)
        assert receipt is not None
        assert receipt["revert_reason"] == "Contract name already exists"
        assert receipt["gas_used"] == Config.VVM_DEPLOY_GAS_BASE
        assert receipt["storage_delta"]["__fee_pool_sat__"] == 0

        assert st.get_balance_sat(deployer) == bal_before - expected_penalty
        assert st.get_balance_sat(Config.BURN_ADDRESS) == burn_before + expected_penalty
        assert st.sum_all_balances_satoshi() == st.get_total_issued_satoshi()
        assert conservation_check(st) is True

        bc.rollback(2)
        assert conservation_check(st) is True


def test_block_total_tx_fees_and_compute_fee_consistency():
    """V4 Fix:
    VVM transactions compute fees from gas_limit * gas_price, and fixed-fee
    transactions return non-zero fees from compute_fee(), total_tx_fees(), and mempool_add().
    """
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        w = Wallet.generate()
        now = int(time.time())

        vvm_zero_val = Transaction(
            sender=w.address,
            receiver="VSDc" + "1" * 36,
            amount=0.0,
            fee=0.0,
            timestamp=now,
            nonce=0,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_CALL,
            data="00",
            gas_limit=50_000,
            gas_price=0.0001,
        )
        vvm_high_val = Transaction(
            sender=w.address,
            receiver="VSDc" + "1" * 36,
            amount=100.0,
            fee=0.0,
            timestamp=now,
            nonce=1,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_CALL,
            data="00",
            gas_limit=21_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )

        cb = Transaction.coinbase(w.address, 10.0, 1)
        blk_vvm = Block(
            index=1,
            prev_hash="0" * 64,
            transactions=[cb, vvm_zero_val, vvm_high_val],
            miner_address=w.address,
            difficulty=1.0,
        )
        expected_zero_val_fee = gas_fee_to_sat(50_000, 0.0001)
        expected_high_val_fee = gas_fee_to_sat(21_000, Config.VVM_MIN_GAS_PRICE)
        assert vvm_zero_val.compute_fee_sat() == expected_zero_val_fee
        assert vvm_high_val.compute_fee_sat() == expected_high_val_fee
        assert blk_vvm.total_tx_fees_sat() == expected_zero_val_fee + expected_high_val_fee

        min_fee_vsd = from_satoshi(Config.MIN_TX_FEE_SAT)
        mev_commit = Transaction(
            sender=w.address,
            receiver=w.address,
            amount=0.0,
            fee=min_fee_vsd,
            timestamp=now,
            nonce=2,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_TRANSFER,
            data=Config.MEV_COMMIT_PREFIX + "a" * 64,
        )
        id_claim = Transaction(
            sender=w.address,
            receiver="",
            amount=0.0,
            fee=min_fee_vsd,
            timestamp=now,
            nonce=3,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_REGISTER,
            memo=Transaction.IDENTITY_MEMO_PREFIX + "alice",
        )
        unstake_tx = Transaction(
            sender=w.address,
            receiver="",
            amount=0.0,
            fee=min_fee_vsd,
            timestamp=now,
            nonce=4,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_REGISTER,
            memo="none",
        )

        for tx in (mev_commit, id_claim, unstake_tx):
            assert tx.compute_fee_sat() == Config.MIN_TX_FEE_SAT
            assert tx.compute_fee() == pytest.approx(min_fee_vsd)

        blk_fixed = Block(
            index=2,
            prev_hash="0" * 64,
            transactions=[cb, mev_commit, id_claim, unstake_tx],
            miner_address=w.address,
            difficulty=1.0,
        )
        assert blk_fixed.total_tx_fees_sat() == 3 * Config.MIN_TX_FEE_SAT
        assert blk_fixed.total_tx_fees() == pytest.approx(3 * min_fee_vsd)

        st.mempool_add(mev_commit)
        row = st._conn().execute(
            "SELECT fee FROM mempool WHERE tx_id=?", (mev_commit.tx_id,)
        ).fetchone()
        assert row is not None
        assert row["fee"] == pytest.approx(min_fee_vsd)


def test_normal_transfer_and_vvm_fee_aggregation_consistency():
    """Verify normal transfer + successful VVM deploy fee aggregation preserves
    conservation_check() across forward apply and rollback."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        alice_w = Wallet.generate()
        bob_w = Wallet.generate()
        miner_w = Wallet.generate()

        _mine_and_apply(bc, [], alice_w.address)
        now = int(time.time())

        tx_xfer = Transaction(
            sender=alice_w.address,
            receiver=bob_w.address,
            amount=2.0,
            fee=0.02,
            timestamp=now,
            nonce=0,
            expiry=now + 3600,
        )
        tx_xfer.sign(alice_w)

        tx_deploy = Transaction(
            sender=alice_w.address,
            receiver="",
            amount=0.0,
            fee=0.0,
            timestamp=now,
            nonce=1,
            expiry=now + 3600,
            tx_type=Transaction.TYPE_DEPLOY,
            data="00",
            gas_limit=50_000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
            contract_name="clean_contract",
        )
        tx_deploy.sign(alice_w)

        _mine_and_apply(bc, [tx_xfer, tx_deploy], miner_w.address)
        assert conservation_check(st) is True
        bc.rollback(1)
        assert conservation_check(st) is True
