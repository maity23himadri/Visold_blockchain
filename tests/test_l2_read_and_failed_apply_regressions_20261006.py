from __future__ import annotations
import os, tempfile
from visold.rollup.l2_state import L2StateTree, Layer2State
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

def test_read_only_l2_lookups_do_not_create_accounts_or_change_root():
    with tempfile.TemporaryDirectory() as td:
        l2 = Layer2State(Storage(os.path.join(td, 'l2-read.db')))
        address = Wallet.generate().address
        before_root, before_count = l2.root(), l2.account_count()
        assert l2.get_balance_sat(address) == 0
        assert l2.get_nonce(address) == 0
        assert l2.root() == before_root
        assert l2.account_count() == before_count == 0
        assert not l2._tree.has(address)

def test_failed_l2_transfer_from_missing_sender_is_state_free():
    with tempfile.TemporaryDirectory() as td:
        l2 = Layer2State(Storage(os.path.join(td, 'l2-failed-transfer.db')))
        sender, receiver = Wallet.generate(), Wallet.generate()
        tx = sender.sign_l2_tx(receiver.address, amount_sat=1, nonce=0, timestamp=123)
        before_root, before_count = l2.root(), l2.account_count()
        ok, msg = l2.apply_l2_tx(tx)
        assert not ok and msg == 'insufficient L2 balance'
        assert l2.root() == before_root
        assert l2.account_count() == before_count == 0
        assert not l2._tree.has(sender.address)

def test_failed_l2_debit_from_missing_account_is_state_free():
    tree = L2StateTree()
    address = Wallet.generate().address
    before_root, before_count = tree.root(), tree.account_count()
    ok, msg = tree.debit(address, 1)
    assert not ok and msg == 'insufficient L2 balance'
    assert tree.root() == before_root
    assert tree.account_count() == before_count == 0
    assert not tree.has(address)

def test_failed_l2_tx_cannot_poison_a_batch_state_root():
    with tempfile.TemporaryDirectory() as td:
        sender, receiver, attacker = Wallet.generate(), Wallet.generate(), Wallet.generate()
        l2 = Layer2State(Storage(os.path.join(td, 'l2-batch-poison.db')))
        assert l2.L2_deposit(sender.address, 100, l1_height=-1)[0]
        failed = attacker.sign_l2_tx(receiver.address, amount_sat=1, nonce=0, timestamp=100)
        valid = sender.sign_l2_tx(receiver.address, amount_sat=10, nonce=0, timestamp=101)
        before_root = l2.root()
        ok, msg = l2.apply_l2_tx(failed)
        assert not ok and msg == 'insufficient L2 balance'
        assert l2.root() == before_root
        ok, msg = l2.apply_l2_tx(valid)
        assert ok, msg
        mixed_root = l2.root()
        clean = Layer2State(Storage(os.path.join(td, 'l2-clean.db')))
        assert clean.L2_deposit(sender.address, 100, l1_height=-1)[0]
        ok, msg = clean.apply_l2_tx(valid)
        assert ok, msg
        assert clean.root() == mixed_root
