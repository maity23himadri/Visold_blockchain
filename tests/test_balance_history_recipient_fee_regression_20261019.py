"""Regression tests for sender-paid fees in CLI Balance History."""
from __future__ import annotations

from types import SimpleNamespace

from visold.cli.interactive import CLI


SENDER = "VSD_sender_address_1234567890"
RECEIVER = "VSD_receiver_address_1234567890"


class _HistoryStorage:
    def __init__(self, txs, balance=20.0):
        self._txs = txs
        self._balance = balance

    def get_address_txs(self, address):
        assert address in (SENDER, RECEIVER)
        return list(self._txs)

    def get_balance(self, address):
        return self._balance

    def get_uid_by_wallet(self, address):
        return None


def _tx(*, sender=SENDER, receiver=RECEIVER, amount=20.0, fee=0.2,
        block_idx=41, memo="test transfer"):
    return {
        "tx_id": "test-tx",
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "fee": fee,
        "tx_type": 0,
        "timestamp": 1792373100,
        "block_idx": block_idx,
        "memo": memo,
    }


def _render_history(monkeypatch, *, address, txs, balance=20.0, capsys):
    # Construct only the UI shell; _balance_history depends on these node fields.
    cli = CLI.__new__(CLI)
    storage = _HistoryStorage(txs, balance=balance)
    cli.node = SimpleNamespace(
        wallet=SimpleNamespace(address=address),
        storage=storage,
    )
    cli._balance_history()
    return capsys.readouterr().out


def test_incoming_history_shows_full_amount_and_does_not_subtract_sender_fee(
    monkeypatch, capsys
):
    out = _render_history(
        monkeypatch, address=RECEIVER, txs=[_tx()], capsys=capsys
    )

    assert "+20.00000000" in out
    assert "+19.80000000" not in out
    assert "net of 0.20000000 fee" not in out


def test_same_block_reward_merged_with_incoming_transfer_keeps_full_transfer_amount(
    monkeypatch, capsys
):
    transfer = _tx()
    reward = {
        "tx_id": "test-coinbase",
        "sender": "COINBASE",
        "receiver": RECEIVER,
        "amount": 10.0,
        "fee": 0.0,
        "tx_type": 0,
        "timestamp": transfer["timestamp"],
        "block_idx": transfer["block_idx"],
        "memo": "coinbase:test",
    }
    out = _render_history(
        monkeypatch,
        address=RECEIVER,
        txs=[transfer, reward],
        balance=30.0,
        capsys=capsys,
    )

    assert "+20.00000000,+10.00000000" in out
    assert "+19.80000000" not in out
    assert "net of 0.20000000 fee" not in out


def test_outgoing_history_still_shows_amount_plus_sender_paid_fee(monkeypatch, capsys):
    out = _render_history(
        monkeypatch, address=SENDER, txs=[_tx()], balance=79.8, capsys=capsys
    )

    assert "-20.20000000" in out
    assert "fee 0.20000000" in out
