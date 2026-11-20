"""V4 regression tests for Section 22 (Session 02): Address Validation and Sender-Recipient Integrity."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.kernel.units import from_satoshi
from visold.ledger.addressing import (
    is_canonical_contract_address,
    is_valid_protocol_address,
)
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, L2_WITHDRAW_ADDRESS, Layer2State
from visold.storage.storage import Storage
from visold.vm.naming import derive_contract_address
from visold.wallet.wallet import Wallet


def _make_chain(tmp_path):
    db_path = str(tmp_path / "visold.db")
    st = Storage(db_path)
    bc = Blockchain(st)
    l2 = Layer2State(st)
    bc.layer2 = l2
    return st, bc, l2


def _mine_block_with_miner(bc: Blockchain, miner_address: str, extra_txs=None) -> Block:
    height = bc.storage.chain_height() + 1
    tip = bc.storage.get_block(height - 1)
    reward = from_satoshi(bc.compute_reward_sat(height))
    cb = Transaction.coinbase(miner_address, reward, height)
    txs = [cb] + list(extra_txs or [])
    ts = max(int(time.time()), tip.timestamp + 1)
    blk = Block(
        index=height,
        prev_hash=tip.block_hash,
        timestamp=ts,
        transactions=txs,
        difficulty=bc.get_difficulty(),
        miner_address=miner_address,
    )
    blk.state_root = bc.dry_run_state_root(txs, miner_address, height)
    blk.mine()
    return blk


def test_validate_block_rejects_non_canonical_and_l2_bridge_miner_address(tmp_path):
    """Blockchain.validate_block() rejects non-canonical and L2_BRIDGE_ADDRESS miner addresses."""
    st, bc, l2 = _make_chain(tmp_path)
    assert l2.supply_invariant_ok()[0]

    bad_block = _mine_block_with_miner(bc, "not_a_canonical_wallet_address")
    ok, _msg = bc.validate_block(bad_block)
    assert ok is False

    bridge_block = _mine_block_with_miner(bc, L2_BRIDGE_ADDRESS)
    ok_b, _msg_b = bc.validate_block(bridge_block)
    assert ok_b is False
    assert l2.supply_invariant_ok()[0] is True


def test_type_register_rejects_unsigned_coinbase_sender(tmp_path):
    """Transaction.is_valid() rejects unsigned COINBASE TYPE_REGISTER transactions."""
    tx = Transaction(
        sender="COINBASE",
        receiver="",
        amount=10.0,
        fee=0.0,
        memo="miner",
        nonce=0,
        expiry=int(time.time()) + 3600,
        tx_type=Transaction.TYPE_REGISTER,
        pub_hex="",
        sig_hex="",
    )
    ok, _msg = tx.is_valid()
    assert ok is False


def test_type_call_rejects_non_canonical_vsdc_receivers(tmp_path):
    """Transaction.is_valid() and Mempool.add() reject non-canonical TYPE_CALL receivers."""
    st, bc, _ = _make_chain(tmp_path)
    wallet = Wallet.generate()
    st.credit_sat(wallet.address, 100 * Config.SATOSHI_PER_VSD)
    mempool = bc.mempool

    malformed_receivers = [
        "VSDc",
        "VSDc_not_hex_garbage",
        L2_BRIDGE_ADDRESS,
        L2_WITHDRAW_ADDRESS,
    ]
    for idx, bad_recv in enumerate(malformed_receivers):
        assert is_canonical_contract_address(bad_recv) is False
        tx = Transaction(
            sender=wallet.address,
            receiver=bad_recv,
            amount=0.0,
            fee=0.0,
            nonce=idx,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=21000,
            gas_price=Config.VVM_MIN_GAS_PRICE,
        )
        tx.sign(wallet)
        ok, _msg = tx.is_valid()
        assert ok is False

        m_ok, _m_msg = mempool.add(tx)
        assert m_ok is False


def test_mempool_rejects_unsigned_coinbase_transfer(tmp_path):
    """Mempool.add() and Transaction.is_valid() reject unsigned TYPE_TRANSFER with sender='COINBASE'."""
    st, bc, _ = _make_chain(tmp_path)
    mempool = bc.mempool

    tx = Transaction(
        sender="COINBASE",
        receiver="ARBITRARY_INVALID_RECEIVER",
        amount=1.0,
        fee=0.0,
        memo="forged",
        nonce=0,
        expiry=0,
        tx_type=Transaction.TYPE_TRANSFER,
        pub_hex="",
        sig_hex="",
    )
    ok_add, _msg_add = mempool.add(tx)
    assert ok_add is False
    assert tx.tx_id not in mempool._pending_tx_ids


def test_canonical_contract_address_rejects_uppercase_hex_mismatch(tmp_path):
    """is_canonical_contract_address() rejects uppercase hex, preventing key mismatch."""
    st, bc, _ = _make_chain(tmp_path)
    wallet = Wallet.generate()
    st.credit_sat(wallet.address, 100 * Config.SATOSHI_PER_VSD)

    lower_addr = derive_contract_address(wallet.address, 0, "a" * 64)
    upper_addr = "VSDc" + lower_addr[4:].upper()

    assert lower_addr != upper_addr
    assert is_canonical_contract_address(lower_addr) is True
    assert is_canonical_contract_address(upper_addr) is False
    assert is_valid_protocol_address(upper_addr, allow_contract=True) is False

    tx = Transaction(
        sender=wallet.address,
        receiver=upper_addr,
        amount=1.0,
        fee=round(1.0 * Config.TX_FEE_RATE, 8),
        nonce=0,
        tx_type=Transaction.TYPE_TRANSFER,
    )
    tx.sign(wallet)
    ok, _msg = tx.is_valid()
    assert ok is False
