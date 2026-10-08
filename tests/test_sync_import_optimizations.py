from __future__ import annotations

import os
import tempfile
from unittest.mock import patch

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _chain(td: str):
    st = Storage(os.path.join(td, "sync-opt.db"))
    return st, Blockchain(st)


def _signed_transfer(st, wallet, receiver, nonce, amount=1.0):
    tx = Transaction(
        sender=wallet.address,
        receiver=receiver.address,
        amount=amount,
        fee=amount * Config.TX_FEE_RATE,
        nonce=nonce,
        expiry=2_000_000_000,
    )
    tx.sign(wallet)
    return tx


def _make_block(bc, txs, miner, height=1):
    root = bc.dry_run_state_root(txs, miner.address, height)
    prev = bc.latest_block()
    block = Block(
        index=height,
        prev_hash=prev.block_hash,
        transactions=txs,
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        timestamp=prev.timestamp + 1,
        state_root=root,
    )
    block.validate_pow = lambda: True
    return block


def test_validation_reuses_integrity_commitments_without_duplicate_encoding():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        sender = Wallet.generate()
        receiver = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(sender.address, 20 * Config.SATOSHI_PER_VSD)
        tx = _signed_transfer(st, sender, receiver, st.get_nonce(sender.address))
        cb = Transaction.coinbase(miner.address, bc.compute_reward(1), 1)
        block = _make_block(bc, [cb, tx], miner)

        signing_bytes_calls = {"n": 0}
        merkle_calls = {"n": 0}
        original_signing_bytes = tx.signing_bytes
        original_merkle = block._merkle

        def counted_signing_bytes(*args, **kwargs):
            signing_bytes_calls["n"] += 1
            return original_signing_bytes(*args, **kwargs)

        def counted_merkle(*args, **kwargs):
            merkle_calls["n"] += 1
            return original_merkle(*args, **kwargs)

        with patch.object(tx, "signing_bytes", side_effect=counted_signing_bytes), \
             patch.object(block, "_merkle", side_effect=counted_merkle):
            ok, msg = bc.validate_block(block)

        assert ok, msg
        # The canonical signing/txid preimage is constructed once for this tx
        # and reused by the signature-verification stage.
        assert signing_bytes_calls["n"] == 1
        # Merkle is established once by integrity_check and then reused.
        assert merkle_calls["n"] == 1


def test_validation_caches_sender_balance_within_block():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        sender = Wallet.generate()
        receiver = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(sender.address, 100 * Config.SATOSHI_PER_VSD)
        base_nonce = st.get_nonce(sender.address)
        txs = [Transaction.coinbase(miner.address, bc.compute_reward(1), 1)]
        for i in range(5):
            txs.append(_signed_transfer(st, sender, receiver, base_nonce + i, amount=1.0))
        block = _make_block(bc, txs, miner)

        original = st.get_balance_sat
        calls = {"n": 0}

        def counted(address):
            calls["n"] += 1
            return original(address)

        with patch.object(st, "get_balance_sat", side_effect=counted):
            ok, msg = bc.validate_block(block)

        assert ok, msg
        assert calls["n"] == 0


def test_mtp_uses_timestamp_projection_without_changing_result():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        sender = Wallet.generate()
        receiver = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(sender.address, 10 * Config.SATOSHI_PER_VSD)
        tx = _signed_transfer(st, sender, receiver, st.get_nonce(sender.address))
        cb = Transaction.coinbase(miner.address, bc.compute_reward(1), 1)
        block = _make_block(bc, [cb, tx], miner)

        calls = {"n": 0}
        original = st.get_block_timestamps

        def counted(start_idx, end_idx):
            calls["n"] += 1
            return original(start_idx, end_idx)

        with patch.object(st, "get_block_timestamps", side_effect=counted):
            ok, msg = bc.validate_block(block)

        assert ok, msg
        assert calls["n"] == 1


def test_tampered_transaction_still_fails_integrity_before_semantic_validation():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        sender = Wallet.generate()
        receiver = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(sender.address, 10 * Config.SATOSHI_PER_VSD)
        tx = _signed_transfer(st, sender, receiver, st.get_nonce(sender.address))
        cb = Transaction.coinbase(miner.address, bc.compute_reward(1), 1)
        block = _make_block(bc, [cb, tx], miner)

        tx.amount = tx.amount + 1.0
        ok, msg = bc.validate_block(block)

        assert not ok
        assert "tx_id" in msg or "merkle_root" in msg


def test_prev_hash_validation_uses_hash_only_storage_path():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        sender = Wallet.generate()
        receiver = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(sender.address, 10 * Config.SATOSHI_PER_VSD)
        tx = _signed_transfer(st, sender, receiver, st.get_nonce(sender.address))
        cb = Transaction.coinbase(miner.address, bc.compute_reward(1), 1)
        block = _make_block(bc, [cb, tx], miner)

        calls = {"n": 0}
        original = st.get_block_hash

        def counted(idx):
            calls["n"] += 1
            return original(idx)

        with patch.object(st, "get_block_hash", side_effect=counted):
            ok, msg = bc.validate_block(block)

        assert ok, msg
        assert calls["n"] == 1


def test_validation_uses_block_level_storage_prefetches():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        sender = Wallet.generate()
        receiver = Wallet.generate()
        miner = Wallet.generate()
        st.credit_sat(sender.address, 20 * Config.SATOSHI_PER_VSD)
        tx = _signed_transfer(st, sender, receiver, st.get_nonce(sender.address))
        cb = Transaction.coinbase(miner.address, bc.compute_reward(1), 1)
        block = _make_block(bc, [cb, tx], miner)

        with patch.object(st, "existing_tx_ids", wraps=st.existing_tx_ids) as txq, \
             patch.object(st, "get_balances_sat", wraps=st.get_balances_sat) as balq:
            ok, msg = bc.validate_block(block)

        assert ok, msg
        assert txq.call_count == 1
        assert balq.call_count == 1
