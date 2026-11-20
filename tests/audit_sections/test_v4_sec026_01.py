"""V4 regression tests for Section 26 (Session 01): Transaction Validation and State-Dependent Rules."""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.kernel.units import VSD_GLOBAL_MARKET, to_satoshi
from visold.ledger.transaction import Transaction
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_chain(tmp_path):
    db_path = str(tmp_path / "visold_test.db")
    storage = Storage(db_path=db_path)
    bc = Blockchain(storage=storage)
    return storage, bc


def test_forged_tx_id_rejected_by_mempool_and_state_engine(tmp_path):
    storage, bc = _make_chain(tmp_path)
    sender = Wallet.generate()
    receiver = Wallet.generate()
    storage.credit_sat(sender.address, to_satoshi(100.0))

    now = int(time.time())
    tx = Transaction(
        sender=sender.address,
        receiver=receiver.address,
        amount=1.0,
        fee=0.01,
        timestamp=now,
        nonce=0,
        expiry=now + 3600,
    )
    tx.sign(sender)
    canonical_id = tx.tx_id

    forged_dict = tx.to_dict()
    forged_id = "f" * 64
    assert forged_id != canonical_id
    forged_dict["tx_id"] = forged_id

    engine = StateEngine(blockchain=bc, storage=storage, governance=bc._governance)
    ok, _msg = engine._handle_new_tx({"tx": forged_dict}, source_peer="peer-1")
    assert ok is False
    assert forged_id not in bc.mempool._pending_tx_ids


def test_vsd_global_market_enforces_mempool_nonce_check(tmp_path):
    storage, bc = _make_chain(tmp_path)
    sender = Wallet.generate()
    storage.credit_sat(sender.address, to_satoshi(100.0))

    now = int(time.time())
    # 1. Gapped nonce (chain_nonce=0, tx.nonce=5) is rejected for VSD_GLOBAL_MARKET
    tx_gap = Transaction(
        sender=sender.address,
        receiver=VSD_GLOBAL_MARKET,
        amount=1.0,
        fee=0.01,
        timestamp=now,
        nonce=5,
        expiry=now + 3600,
    )
    tx_gap.sign(sender)
    ok_gap, _msg_gap = bc.mempool.add(tx_gap)
    assert ok_gap is False

    # 2. Duplicate same-nonce VSD_GLOBAL_MARKET txs: second is rejected
    tx_0a = Transaction(
        sender=sender.address,
        receiver=VSD_GLOBAL_MARKET,
        amount=1.0,
        fee=0.01,
        timestamp=now,
        nonce=0,
        expiry=now + 3600,
        memo="order-a",
    )
    tx_0a.sign(sender)
    tx_0b = Transaction(
        sender=sender.address,
        receiver=VSD_GLOBAL_MARKET,
        amount=1.0,
        fee=0.01,
        timestamp=now + 1,
        nonce=0,
        expiry=now + 3600,
        memo="order-b",
    )
    tx_0b.sign(sender)

    assert bc.mempool.add(tx_0a) == (True, "OK")
    assert bc.mempool.add(tx_0b)[0] is False


def test_coinbase_tx_rejected_by_mempool_and_state_engine(tmp_path):
    storage, bc = _make_chain(tmp_path)
    attacker = Wallet.generate()
    now = int(time.time())

    fake_cb = Transaction(
        sender="COINBASE",
        receiver=attacker.address,
        amount=50.0,
        fee=0.0,
        timestamp=now,
        nonce=0,
        expiry=0,
    )
    engine = StateEngine(blockchain=bc, storage=storage, governance=bc._governance)
    ok, _msg = engine._handle_new_tx({"tx": fake_cb.to_dict()}, source_peer="peer-1")
    assert ok is False
    assert fake_cb.tx_id not in bc.mempool._pending_tx_ids
