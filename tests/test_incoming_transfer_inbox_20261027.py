"""Regression tests for recipient-side, mempool-gated transfer notifications."""
from __future__ import annotations

import json
import threading
from types import SimpleNamespace
from threading import RLock

from visold.cli.interactive import CLI
from visold.kernel.config import Config
from visold.ledger.transaction import Transaction
from visold.node.visold_node import VisoldNode
from visold.state.engine import StateEngine


RECIPIENT = "VSD_receiver_address_1234567890"
SENDER = "VSD_sender_address_1234567890"


class _InboxStorage:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key, default=None):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = str(value)

    def get_uid_by_wallet(self, address):
        return "alice" if address == SENDER else None

    def resolve_name_claim(self, user_id):
        if user_id == "alice":
            return {"user_id": "alice", "wallet_addr": SENDER}
        return None



def _node(storage=None):
    node = VisoldNode.__new__(VisoldNode)
    node.wallet = SimpleNamespace(address=RECIPIENT)
    node.storage = storage or _InboxStorage()
    node._incoming_transfer_lock = threading.RLock()
    return node


def _tx(*, sender=SENDER, receiver=RECIPIENT, amount=2.5,
        tx_type=Transaction.TYPE_TRANSFER, tx_id=""):
    return Transaction(
        sender=sender,
        receiver=receiver,
        amount=amount,
        fee=round(amount * Config.TX_FEE_RATE, 8),
        nonce=1,
        tx_type=tx_type,
        tx_id=tx_id,
    )


def test_incoming_transfer_is_persisted_once_and_name_is_claim_verified():
    node = _node()
    tx = _tx()

    assert node.record_incoming_transfer(tx) is True
    assert node.record_incoming_transfer(tx) is False

    inbox = node.get_incoming_transfer_inbox()
    assert inbox["total_count"] == 1
    assert len(inbox["entries"]) == 1
    item = inbox["entries"][0]
    assert item["tx_id"] == tx.tx_id
    assert item["sender"] == SENDER
    assert item["sender_name"] == "alice"
    assert item["amount_sat"] == 250_000_000

    # The inbox is stored in the node's local metadata, not merely in RAM.
    key = node._incoming_transfer_meta_key()
    decoded = json.loads(node.storage.meta[key])
    assert decoded["total_count"] == 1
    assert len(decoded["entries"]) == 1


def test_nonrecipient_self_transfer_and_nontransfer_do_not_create_inbox_entries():
    node = _node()
    assert node.record_incoming_transfer(_tx(receiver="VSD_other_address_1234567890")) is False
    assert node.record_incoming_transfer(_tx(sender=RECIPIENT)) is False
    assert node.record_incoming_transfer(_tx(tx_type=Transaction.TYPE_REGISTER)) is False
    assert node.record_incoming_transfer(_tx(amount=0)) is False
    assert node.get_incoming_transfer_total() == 0


def test_unverified_directory_name_falls_back_to_sender_address():
    storage = _InboxStorage()
    storage.resolve_name_claim = lambda _name: None
    node = _node(storage)
    tx = _tx()

    assert node.record_incoming_transfer(tx) is True
    item = node.get_incoming_transfer_inbox()["entries"][0]
    assert item["sender_name"] == ""
    assert item["sender"] == SENDER


def test_inbox_history_is_bounded_but_cumulative_count_keeps_increasing():
    node = _node()
    for index in range(505):
        assert node.record_incoming_transfer(_tx(tx_id=f"synthetic-test-tx-{index}")) is True
    inbox = node.get_incoming_transfer_inbox()
    assert inbox["total_count"] == 505
    assert len(inbox["entries"]) == node._INCOMING_TRANSFER_MAX_ENTRIES == 500


def test_state_engine_records_only_successfully_admitted_remote_tx():
    tx = _tx()
    recorded = []

    class _Mempool:
        accept = True

        def add(self, candidate):
            assert candidate.tx_id == tx.tx_id
            return (self.accept, "accepted" if self.accept else "rejected")

    class _Network:
        def __init__(self):
            self.gossiped = []

        def _gossip(self, message, exclude=None):
            self.gossiped.append((message, exclude))

        def broadcast_tx(self, _candidate):
            raise AssertionError("remote tx must not use local-origin broadcast")

    engine = StateEngine.__new__(StateEngine)
    engine._blockchain = SimpleNamespace(mempool=_Mempool())
    engine._network = _Network()
    engine._node_ref = SimpleNamespace(record_incoming_transfer=lambda candidate: recorded.append(candidate.tx_id))

    ok, _ = engine._handle_new_tx({"tx": tx.to_dict()}, "remote-peer-id")
    assert ok is True
    assert recorded == [tx.tx_id]
    assert engine._network.gossiped

    engine._blockchain.mempool.accept = False
    ok, _ = engine._handle_new_tx({"tx": tx.to_dict()}, "remote-peer-id-2")
    assert ok is False
    assert recorded == [tx.tx_id]


def test_menu_label_shows_cumulative_incoming_count():
    cli = CLI.__new__(CLI)
    cli.node = _node()
    cli.node.record_incoming_transfer(_tx())
    assert cli._incoming_transfers_menu_label() == "Incoming Transfers [1]"


def test_incoming_transfers_screen_warns_about_pending_and_never_displays_memo(
    capsys,
):
    tx_id = "a" * 64
    item = {
        "tx_id": tx_id,
        "sender": SENDER,
        "sender_name": "alice",
        "amount_sat": 125_000_000,
        "timestamp": 1793088000,
        "received_at": 1793088001,
    }
    mempool = SimpleNamespace(_lock=RLock(), _pending_tx_ids={tx_id})
    cli = CLI.__new__(CLI)
    cli.node = SimpleNamespace(
        get_incoming_transfer_inbox=lambda: {"total_count": 1, "entries": [item]},
        storage=SimpleNamespace(tx_exists=lambda _tx_id: False),
        blockchain=SimpleNamespace(mempool=mempool),
    )

    cli._incoming_transfers()
    output = capsys.readouterr().out
    assert "Incoming Transfers" in output
    assert "1.25000000 VSD" in output
    assert "alice (VSD_sender_address_1234567890)" in output
    assert "PENDING" in output
    assert "NOT confirmation" in output
    assert "memo" not in output.lower()
