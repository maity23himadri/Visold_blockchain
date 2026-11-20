"""V4 Regression Tests for Section 57: Block Reward Validation and Overpayment Prevention."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.chain.blockchain import Blockchain
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _chain(td: str):
    st = Storage(os.path.join(td, "audit57.db"))
    return st, Blockchain(st)


def _mined_block(
    bc: Blockchain,
    txs: list[Transaction],
    miner: str,
    height: int | None = None,
    timestamp: int | None = None,
) -> Block:
    height = bc.height() + 1 if height is None else height
    txs = list(txs)
    state_root = bc.dry_run_state_root(txs, miner, height, timestamp=timestamp)
    prev = bc.latest_block()
    kwargs = dict(
        index=height,
        prev_hash=prev.block_hash if prev else "0" * 64,
        transactions=txs,
        miner_address=miner,
        difficulty=bc.get_difficulty(),
        state_root=state_root,
    )
    if timestamp is not None:
        kwargs["timestamp"] = timestamp
    block = Block(**kwargs)
    assert block.mine(), "audit block failed to mine"
    return block


def test_coinbase_register_tx_rejected_and_cannot_siphon_rewards():
    """V4 Fix:
    validate_block() rejects coinbase transactions with tx_type != 'transfer'
    (such as TYPE_REGISTER), preventing COINBASE from registering as an investor.
    """
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        subsidy1 = bc.compute_reward(1)

        malicious_cb = Transaction(
            sender="COINBASE",
            receiver=miner.address,
            amount=subsidy1,
            memo="investor",
            nonce=0,
            expiry=0,
            tx_type=Transaction.TYPE_REGISTER,
        )
        b1 = _mined_block(bc, [malicious_cb], miner.address, height=1)

        ok_val, _msg_val = bc.validate_block(b1)
        assert not ok_val, "Coinbase with TYPE_REGISTER must be rejected"
        assert st.get_role("COINBASE") is None


def test_duplicate_coinbase_txid_across_blocks_rejected():
    """V4 Fix:
    validate_block() enforces coinbase memo binding to block.index and rejects
    duplicate coinbase tx_ids across blocks.
    """
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        subsidy = bc.compute_reward(1)
        assert bc.compute_reward_sat(1) == bc.compute_reward_sat(2)

        cb_shared = Transaction(
            sender="COINBASE",
            receiver=miner.address,
            amount=subsidy,
            memo="coinbase:1",
            nonce=0,
            expiry=0,
            timestamp=1_700_000_000,
        )
        b1 = _mined_block(bc, [cb_shared], miner.address, height=1)
        assert bc.apply_block(b1)[0]

        cb_dup = Transaction.from_dict(cb_shared.to_dict())
        assert cb_dup.tx_id == cb_shared.tx_id

        b2 = _mined_block(bc, [cb_dup], miner.address, height=2)
        ok_val2, _msg_val2 = bc.validate_block(b2)
        assert not ok_val2, "Duplicate/unbound coinbase in block 2 must be rejected"

        row = st._conn().execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total "
            "FROM transactions WHERE sender='COINBASE'"
        ).fetchone()
        assert row["cnt"] == 1
        assert row["total"] == subsidy


def test_miner_address_l2_bridge_rejected():
    """V4 Fix:
    validate_block() rejects reserved sentinel addresses such as L2_BRIDGE_ADDRESS
    as block.miner_address.
    """
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        subsidy1 = bc.compute_reward(1)
        cb1 = Transaction.coinbase(L2_BRIDGE_ADDRESS, subsidy1, 1)
        b1 = _mined_block(bc, [cb1], L2_BRIDGE_ADDRESS, height=1)

        ok_val, _msg_val = bc.validate_block(b1)
        assert not ok_val, "L2_BRIDGE_ADDRESS must be rejected as miner_address"
        assert st.get_balance_sat(L2_BRIDGE_ADDRESS) == 0
