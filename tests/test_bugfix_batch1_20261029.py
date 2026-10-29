from __future__ import annotations

import math
import os
import sqlite3
import threading
from types import SimpleNamespace

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.kernel.config import Config
from visold.kernel.units import VSD_GLOBAL_MARKET, to_satoshi
from visold.ledger.addressing import is_canonical_wallet_address
from visold.ledger.transaction import Transaction
from visold.rollup.l2_state import (
    L2Transaction,
    L2_BRIDGE_ADDRESS,
    L2_WITHDRAW_ADDRESS,
)
from visold.storage.sqlite_serialized import _SerializedSQLiteConnection
from visold.storage.storage import Storage
from visold.node.visold_node import VisoldNode
from visold.wallet.wallet import Wallet

FAR_EXPIRY = 2_000_000_000


def _signed_transfer(sender: Wallet, receiver: str, amount: float = 1.0, nonce: int = 0):
    tx = Transaction(
        sender=sender.address,
        receiver=receiver,
        amount=amount,
        fee=round(amount * Config.TX_FEE_RATE, 8),
        nonce=nonce,
        expiry=FAR_EXPIRY,
    )
    tx.sign(sender)
    return tx


def test_bug1_validate_block_rejects_empty_miner_before_deeper_processing(tmp_path):
    storage = Storage(str(tmp_path / "bug1.db"))
    chain = Blockchain(storage)

    class EmptyMinerBlock:
        is_pruned = False
        miner_address = ""
        difficulty = 1.0
        timestamp = 1.0

        def integrity_check(self, *args, **kwargs):  # pragma: no cover: must not run
            raise AssertionError("empty miner must be rejected before integrity/application")

    ok, msg = chain.validate_block(EmptyMinerBlock())
    assert not ok
    assert "miner_address" in msg


def test_bug2_l1_rejects_malformed_receiver_and_accepts_protocol_receivers():
    sender = Wallet.generate()
    for bad in ("", "x", "garbage-not-an-address", "VSD!!!"):
        tx = _signed_transfer(sender, bad)
        ok, _ = tx.is_valid()
        assert not ok, bad

    wallet_receiver = Wallet.generate().address
    assert is_canonical_wallet_address(wallet_receiver)
    for good in (
        wallet_receiver,
        "VSDc" + "ab" * 18,
        VSD_GLOBAL_MARKET,
        Config.BURN_ADDRESS,
        L2_BRIDGE_ADDRESS,
        L2_WITHDRAW_ADDRESS,
    ):
        tx = _signed_transfer(sender, good)
        ok, msg = tx.is_valid()
        assert ok, (good, msg)


def test_bug2_receiver_validation_does_not_change_register_empty_receiver_semantics():
    sender = Wallet.generate()
    tx = Transaction(
        sender=sender.address,
        receiver="",
        amount=1.0,
        fee=0.01,
        memo="miner",
        nonce=0,
        expiry=FAR_EXPIRY,
        tx_type=Transaction.TYPE_REGISTER,
    )
    tx.sign(sender)
    ok, msg = tx.is_valid()
    assert ok, msg


def test_bug21_l2_rejects_malformed_receiver_before_application(tmp_path):
    sender = Wallet.generate()
    valid_receiver = Wallet.generate().address
    storage = Storage(str(tmp_path / "l2.db"))
    layer2 = Blockchain(storage).layer2
    assert layer2.L2_deposit(sender.address, 100, l1_height=-1)[0]

    valid = sender.sign_l2_tx(valid_receiver, amount_sat=10, nonce=0, timestamp=123)
    ok, msg = valid.is_valid()
    assert ok, msg

    for bad in ("x", "garbage-not-an-address", "VSD!!!"):
        tx = sender.sign_l2_tx(bad, amount_sat=10, nonce=0, timestamp=123)
        ok, msg = tx.is_valid()
        assert not ok, (bad, msg)
        before = layer2.root()
        ok, _ = layer2.apply_l2_tx(tx)
        assert not ok
        assert layer2.root() == before
        assert layer2.get_balance_sat(bad) == 0


def test_bug10_failed_atomic_commit_rolls_back_and_connection_recovers(tmp_path):
    db = str(tmp_path / "commit-failure.db")
    writer = sqlite3.connect(db, timeout=0.05, check_same_thread=False)
    reader = sqlite3.connect(db, timeout=0.05, check_same_thread=False)
    try:
        writer.execute("PRAGMA journal_mode=DELETE")
        writer.execute("CREATE TABLE items(value INTEGER NOT NULL)")
        writer.commit()

        # Hold a read transaction so the writer's rollback-journal COMMIT
        # cannot obtain the exclusive lock.
        reader.execute("BEGIN")
        assert reader.execute("SELECT * FROM items").fetchall() == []

        shared = _SerializedSQLiteConnection(writer, threading.RLock())
        shared.begin_atomic()
        shared.execute("INSERT INTO items(value) VALUES (1)").close()
        try:
            shared.commit_atomic()
        except sqlite3.OperationalError as exc:
            assert "locked" in str(exc).lower()
        else:  # pragma: no cover - platform should reproduce the lock conflict
            raise AssertionError("expected SQLite COMMIT lock failure")

        assert shared.atomic_active() is False
        assert writer.in_transaction is False
        reader.rollback()
        assert writer.execute("SELECT value FROM items").fetchall() == []

        # The same connection remains usable for a later atomic block.
        shared.begin_atomic()
        shared.execute("INSERT INTO items(value) VALUES (2)").close()
        shared.commit_atomic()
        assert writer.execute("SELECT value FROM items").fetchall() == [(2,)]
    finally:
        try:
            reader.rollback()
        except Exception:
            pass
        reader.close()
        writer.close()


def test_bug45_l2_withdrawal_releases_escrow_without_l1_prefund_and_rolls_back(tmp_path, monkeypatch):
    storage = Storage(str(tmp_path / "withdraw.db"))
    chain = Blockchain(storage)
    # Keep this focused on settlement semantics, not async pruning.
    chain._rolling_pruner.prune_async = lambda _height: None

    miner = Wallet.generate()
    user = Wallet.generate()
    amount_sat = 400_000_000
    amount_vsd = amount_sat / Config.SATOSHI_PER_VSD
    fee_sat = amount_sat * int(round(Config.TX_FEE_RATE * 10_000)) // 10_000

    # Pre-state represents a valid prior deposit: L2 supply == bridge escrow.
    storage.credit_sat(L2_BRIDGE_ADDRESS, amount_sat)
    assert chain.layer2.L2_deposit(user.address, amount_sat, l1_height=chain.height())[0]
    assert storage.get_balance_sat(user.address) == 0
    assert storage.get_balance_sat(L2_WITHDRAW_ADDRESS) == 0

    tx = Transaction(
        sender=user.address,
        receiver=L2_WITHDRAW_ADDRESS,
        amount=amount_vsd,
        fee=fee_sat / Config.SATOSHI_PER_VSD,
        memo="L2_WITHDRAW",
        nonce=storage.get_nonce(user.address),
        expiry=FAR_EXPIRY,
    )
    tx.sign(user)
    ok, msg = chain.mempool.add(tx)
    assert ok, msg

    candidate = ConsensusEngine(chain, miner).build_candidate_block(miner.address)
    assert any(t.tx_id == tx.tx_id for t in candidate.transactions)
    assert candidate.mine(), "withdrawal candidate failed to mine"
    ok, msg = chain.apply_block(candidate)
    assert ok, msg

    assert storage.get_balance_sat(user.address) == amount_sat - fee_sat
    assert chain.layer2.get_balance_sat(user.address) == 0
    assert storage.get_balance_sat(L2_BRIDGE_ADDRESS) == 0
    assert storage.get_balance_sat(L2_WITHDRAW_ADDRESS) == 0
    assert chain.layer2.supply_invariant_ok()[0]

    ok, msg = chain.rollback(candidate.index - 1)
    assert ok, msg
    assert storage.get_balance_sat(user.address) == 0
    assert chain.layer2.get_balance_sat(user.address) == amount_sat
    assert storage.get_balance_sat(L2_BRIDGE_ADDRESS) == amount_sat
    assert storage.get_balance_sat(L2_WITHDRAW_ADDRESS) == 0
    assert chain.layer2.supply_invariant_ok()[0]


def test_bug1_reward_rollback_is_exact_inverse_even_for_legacy_empty_miner(tmp_path):
    storage = Storage(str(tmp_path / "bug1-reward.db"))
    chain = Blockchain(storage)
    role_wallet = Wallet.generate()
    storage.set_role(role_wallet.address, "miner", 1.0)
    block = SimpleNamespace(index=1, miner_address="", transactions=[])
    before_empty = storage.get_balance_sat("")
    before_burn = storage.get_balance_sat(Config.BURN_ADDRESS)
    chain._distribute_rewards(block, 0)
    assert storage.get_balance_sat("") > before_empty
    chain._rollback_rewards(block)
    assert storage.get_balance_sat("") == before_empty
    assert storage.get_balance_sat(Config.BURN_ADDRESS) == before_burn


def test_bug45_node_withdrawal_submission_does_not_require_l1_amount_prefund(tmp_path):
    storage = Storage(str(tmp_path / "withdraw-node.db"))
    chain = Blockchain(storage)
    user = Wallet.generate()
    amount_sat = 400_000_000
    storage.credit_sat(L2_BRIDGE_ADDRESS, amount_sat)
    assert chain.layer2.L2_deposit(user.address, amount_sat, l1_height=chain.height())[0]
    assert storage.get_balance_sat(user.address) == 0

    captured = {}

    class _StateEngine:
        def post_sync(self, event):
            captured["event"] = event
            return True, "accepted"

    holder = SimpleNamespace(
        blockchain=chain,
        storage=storage,
        wallet=user,
        state_engine=_StateEngine(),
    )
    ok, msg = VisoldNode.withdraw_from_l2(holder, 4.0)
    assert ok, msg
    payload = captured["event"].payload["tx"]
    tx = Transaction.from_dict(payload)
    assert tx.sender == user.address
    assert tx.receiver == L2_WITHDRAW_ADDRESS
    assert to_satoshi(tx.amount) == amount_sat
    assert tx.compute_fee_sat() == 4_000_000
    ok, reason = tx.is_valid()
    assert ok, reason
