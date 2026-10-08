"""Regression tests for the four confirmed Visold consensus/state bugs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from unittest.mock import patch

from visold.chain.blockchain import Blockchain
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _chain(td: str):
    st = Storage(os.path.join(td, "regression.db"))
    return st, Blockchain(st)


def _signed_transfer(st: Storage, wallet: Wallet, receiver: str, amount: float) -> Transaction:
    nonce = st.get_nonce(wallet.address)
    tx = Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount=amount,
        fee=amount * Config.TX_FEE_RATE,
        nonce=nonce,
    )
    tx.sign(wallet)
    return tx


def _mined_block(bc: Blockchain, txs: list[Transaction], miner: str, height: int | None = None) -> Block:
    height = bc.height() + 1 if height is None else height
    txs = list(txs)
    state_root = bc.dry_run_state_root(txs, miner, height)
    prev = bc.latest_block()
    block = Block(
        index=height,
        prev_hash=prev.block_hash if prev else "0" * 64,
        transactions=txs,
        miner_address=miner,
        difficulty=bc.get_difficulty(),
        state_root=state_root,
    )
    assert block.mine(), "regression block failed to mine"
    return block


def test_consensus_rejects_spending_active_stake():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        sender = Wallet.generate()
        receiver = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(sender.address, 20 * Config.SATOSHI_PER_VSD)
        st.set_role(sender.address, "miner", 15.0)

        tx = _signed_transfer(st, sender, receiver.address, 10.0)
        coinbase = Transaction.coinbase(
            miner.address,
            bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
            1,
        )
        block = _mined_block(bc, [coinbase, tx], miner.address, height=1)

        ok, msg = bc.validate_block(block)
        assert not ok
        assert "Insufficient balance" in msg
        assert st.get_balance_sat(sender.address) == 20 * Config.SATOSHI_PER_VSD
        role = st.get_role(sender.address)
        assert role is not None and role["role"] == "miner"
        assert role["stake"] == 15.0


def test_same_block_register_stake_is_also_reserved():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        sender = Wallet.generate()
        receiver = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(sender.address, 15 * Config.SATOSHI_PER_VSD)

        reg = Transaction(
            sender=sender.address,
            receiver="",
            amount=10.0,
            fee=10.0 * Config.TX_FEE_RATE,
            memo="miner",
            nonce=st.get_nonce(sender.address),
            tx_type=Transaction.TYPE_REGISTER,
        )
        reg.sign(sender)
        spend = Transaction(
            sender=sender.address, receiver=receiver.address, amount=6.0,
            fee=6.0 * Config.TX_FEE_RATE, nonce=1,
        )
        spend.sign(sender)
        coinbase = Transaction.coinbase(
            miner.address,
            bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
            1,
        )
        block = _mined_block(bc, [coinbase, reg, spend], miner.address, height=1)

        ok, msg = bc.validate_block(block)
        assert not ok
        assert "Insufficient balance" in msg


def test_same_block_register_with_sufficient_backing_remains_valid():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        sender = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(sender.address, 15 * Config.SATOSHI_PER_VSD)

        reg = Transaction(
            sender=sender.address,
            receiver="",
            amount=10.0,
            fee=10.0 * Config.TX_FEE_RATE,
            memo="miner",
            nonce=st.get_nonce(sender.address),
            tx_type=Transaction.TYPE_REGISTER,
        )
        reg.sign(sender)
        coinbase = Transaction.coinbase(
            miner.address,
            bc.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
            1,
        )
        block = _mined_block(bc, [coinbase, reg], miner.address, height=1)

        ok, msg = bc.validate_block(block)
        assert ok, msg
        ok, msg = bc.apply_block(block)
        assert ok, msg
        role = st.get_role(sender.address)
        assert role is not None
        assert role["role"] == "miner"
        assert role["stake"] == 10.0


def _apply_and_rollback_register(st: Storage, bc: Blockchain, tx: Transaction, miner: str):
    block = _mined_block(
        bc,
        [
            Transaction.coinbase(
                miner,
                bc.compute_reward_sat(bc.height() + 1) / Config.SATOSHI_PER_VSD,
                bc.height() + 1,
            ),
            tx,
        ],
        miner,
    )
    ok, msg = bc.apply_block(block)
    assert ok, msg
    rb_ok, rb_msg = bc.rollback(0)
    assert rb_ok, rb_msg


def test_unregister_rollback_restores_exact_prior_role_metadata():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        owner = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(owner.address, 100 * Config.SATOSHI_PER_VSD)
        st.set_role(owner.address, "miner", 20.0, score=3.25)
        before = st.get_role(owner.address)
        assert before is not None
        before = dict(before)
        before_root = st.compute_state_root()
        before_balance = st.get_balance_sat(owner.address)

        tx = Transaction(
            sender=owner.address,
            receiver="",
            amount=0.0,
            fee=Config.MIN_TX_FEE_SAT / Config.SATOSHI_PER_VSD,
            memo="none",
            nonce=st.get_nonce(owner.address),
            tx_type=Transaction.TYPE_REGISTER,
        )
        tx.sign(owner)
        _apply_and_rollback_register(st, bc, tx, miner.address)

        after = st.get_role(owner.address)
        assert after is not None
        assert after["role"] == before["role"]
        assert after["stake"] == before["stake"]
        assert after["score"] == before["score"]
        assert int(after["slashed"]) == int(before["slashed"])
        assert int(after["registered_at"]) == int(before["registered_at"])
        assert st.get_balance_sat(owner.address) == before_balance
        assert st.compute_state_root() == before_root


def test_ignored_register_rollback_does_not_unstake_or_unslash():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        owner = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(owner.address, 100 * Config.SATOSHI_PER_VSD)
        st.set_role(owner.address, "miner", 20.0, score=2.75)
        st.slash(owner.address)
        before = dict(st.get_role(owner.address))
        before_balance = st.get_balance_sat(owner.address)
        before_root = st.compute_state_root()

        tx = Transaction(
            sender=owner.address,
            receiver="",
            amount=5.0,
            fee=5.0 * Config.TX_FEE_RATE,
            memo="miner",
            nonce=st.get_nonce(owner.address),
            tx_type=Transaction.TYPE_REGISTER,
        )
        tx.sign(owner)
        _apply_and_rollback_register(st, bc, tx, miner.address)

        after = st.get_role(owner.address)
        assert after is not None
        assert after["role"] == before["role"]
        assert after["stake"] == before["stake"]
        assert after["score"] == before["score"]
        assert int(after["slashed"]) == int(before["slashed"])
        assert int(after["registered_at"]) == int(before["registered_at"])
        assert st.get_balance_sat(owner.address) == before_balance
        assert st.compute_state_root() == before_root


def test_orphaned_validator_votes_remain_visible_by_height():
    with tempfile.TemporaryDirectory() as td:
        st, _ = _chain(td)
        validator = Wallet.generate().address
        st.record_validator_vote("A" * 64, validator, "sigA", "pubA", block_idx=7)
        st.record_validator_vote("B" * 64, validator, "sigB", "pubB", block_idx=7)
        votes = st.get_validator_votes_at_height(7)
        assert {v["block_hash"] for v in votes} == {"A" * 64, "B" * 64}
        assert len(votes) == 2


def test_process_death_before_block_save_rolls_back_sqlite_transaction():
    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "crash.db")
        marker = os.path.join(td, "marker.json")
        script = r'''
import json, os, sys
from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

db, marker = sys.argv[1], sys.argv[2]
st = Storage(db)
bc = Blockchain(st)
sender = Wallet.generate()
miner = Wallet.generate()
st.credit_sat(sender.address, 20 * Config.SATOSHI_PER_VSD)
recipient = Wallet.generate()
tx = Transaction(sender=sender.address, receiver=recipient.address, amount=5.0,
                 fee=5.0 * Config.TX_FEE_RATE, nonce=st.get_nonce(sender.address))
tx.sign(sender)
height = bc.height() + 1
coinbase = Transaction.coinbase(miner.address,
    bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD, height)
root = bc.dry_run_state_root([coinbase, tx], miner.address, height)
block = Block(index=height, prev_hash=bc.latest_block().block_hash,
              transactions=[coinbase, tx], miner_address=miner.address,
              difficulty=bc.get_difficulty(), state_root=root)
assert block.mine()
json.dump({"sender": sender.address,
           "balance": st.get_balance_sat(sender.address),
           "root": st.compute_state_root()}, open(marker, "w"))
def crash(_block):
    os._exit(77)
st.save_block = crash
bc.apply_block(block)
os._exit(78)
'''
        env = dict(os.environ)
        env["VISOLD_STORAGE"] = "sqlite"
        env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", script, db, marker],
            cwd=os.getcwd(), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60,
        )
        assert proc.returncode == 77, proc.stderr.decode(errors="replace")

        meta = json.load(open(marker))
        st = Storage(db)
        assert st.get_block(1) is None
        assert Blockchain(st).height() == 0
        assert st.get_balance_sat(meta["sender"]) == meta["balance"]
        assert st.compute_state_root() == meta["root"]
