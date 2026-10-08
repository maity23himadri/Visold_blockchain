from __future__ import annotations

import time
import os
import tempfile

from visold.chain.blockchain import Blockchain
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def test_nonfinite_difficulty_cannot_bypass_pow_or_block_validation():
    assert DifficultyEngine.validate_pow_target("f" * 64, float("nan")) is False
    try:
        DifficultyEngine.difficulty_to_target(float("nan"))
    except ValueError as exc:
        assert "finite" in str(exc)
    else:
        raise AssertionError("difficulty_to_target accepted NaN")

    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "chain.db"))
        bc = Blockchain(st)
        miner = Wallet.generate()
        cb = Transaction.coinbase(miner.address, 0.0, 1)
        bad = Block(
            index=1,
            prev_hash=bc.latest_block().block_hash,
            transactions=[cb],
            miner_address=miner.address,
            difficulty=float("nan"),
            timestamp=bc.latest_block().timestamp + 1,
            nonce=0,
        )
        ok, msg = bc.validate_block(bad)
        assert not ok
        assert "difficulty" in msg.lower()


def test_nonfinite_timestamp_cannot_pass_timestamp_validation_or_block_validation():
    assert DifficultyEngine.validate_timestamp(
        float("nan"), [100, 110], 120
    )[0] is False
    assert DifficultyEngine.validate_timestamp(
        float("inf"), [100, 110], 120
    )[0] is False

    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "chain.db"))
        bc = Blockchain(st)
        miner = Wallet.generate()
        cb = Transaction.coinbase(miner.address, 0.0, 1)
        bad = Block(
            index=1,
            prev_hash=bc.latest_block().block_hash,
            transactions=[cb],
            miner_address=miner.address,
            difficulty=Config.INITIAL_DIFFICULTY,
            timestamp=float("nan"),
            nonce=0,
        )
        ok, msg = bc.validate_block(bad)
        assert not ok
        assert "timestamp" in msg.lower()


def test_transaction_signature_and_id_are_field_boundary_safe():
    wallet = Wallet.generate()
    common = dict(
        sender=wallet.address,
        receiver=Wallet.generate().address,
        amount=1.0,
        fee=0.01,
        timestamp=int(time.time()),
        expiry=int(time.time()) + 10_000,
        tx_type=Transaction.TYPE_TRANSFER,
        data="",
        gas_limit=0,
        gas_price=0.0,
    )

    original = Transaction(memo="", nonce=123, **common)
    original.sign(wallet)

    rewritten = Transaction(memo="1", nonce=23, **common)
    rewritten.pub_hex = original.pub_hex
    rewritten.sig_hex = original.sig_hex
    rewritten.tx_id = original.tx_id

    assert original.signing_bytes() != rewritten.signing_bytes()
    assert original._compute_id() != rewritten._compute_id()
    assert rewritten.verify_signature() is False
    ok, msg = rewritten.is_valid()
    assert not ok
    assert "signature" in msg.lower()


def test_new_canonical_transaction_is_accepted_by_mempool():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "chain.db"))
        from visold.mempool.pool import Mempool

        pool = Mempool(st)
        sender = Wallet.generate()
        receiver = Wallet.generate()
        st.credit_sat(sender.address, 10 * Config.SATOSHI_PER_VSD)
        tx = Transaction(
            sender=sender.address,
            receiver=receiver.address,
            amount=1.0,
            fee=0.01,
            nonce=st.get_nonce(sender.address),
        )
        tx.sign(sender)
        ok, msg = pool.add(tx)
        assert ok, msg


def test_historical_legacy_signature_and_txid_remain_explicitly_compatible():
    old_activation = Config.TXID_CANONICAL_V3_ACTIVATION_HEIGHT
    old_legacy = Config.TXID_CANONICAL_V2_LEGACY_ENABLED
    Config.TXID_CANONICAL_V3_ACTIVATION_HEIGHT = 100
    Config.TXID_CANONICAL_V2_LEGACY_ENABLED = True
    try:
        wallet = Wallet.generate()
        tx = Transaction(
            sender=wallet.address,
            receiver=Wallet.generate().address,
            amount=1.0,
            fee=0.01,
            timestamp=1000,
            expiry=2000,
            nonce=7,
        )
        legacy_payload = tx._legacy_signing_bytes()
        legacy_sig = wallet.sign(legacy_payload)
        from visold.crypto.ecc import sig_to_hex

        tx.pub_hex = wallet.pub_hex
        tx.sig_hex = sig_to_hex(legacy_sig)
        legacy_id = tx._compute_legacy_id(50)
        tx.tx_id = legacy_id

        assert tx.verify_signature(block_height=50) is True
        assert tx.verify_signature(block_height=150) is False
        assert tx._compute_id() != legacy_id
    finally:
        Config.TXID_CANONICAL_V3_ACTIVATION_HEIGHT = old_activation
        Config.TXID_CANONICAL_V2_LEGACY_ENABLED = old_legacy


def test_historical_v1_truncated_txid_rule_is_reproduced_exactly():
    old_v2_activation = Config.TXID_V2_ACTIVATION_HEIGHT
    old_v1_legacy = Config.TXID_V1_LEGACY_ENABLED
    old_v3_activation = Config.TXID_CANONICAL_V3_ACTIVATION_HEIGHT
    old_v3_legacy = Config.TXID_CANONICAL_V2_LEGACY_ENABLED
    Config.TXID_V2_ACTIVATION_HEIGHT = 100
    Config.TXID_V1_LEGACY_ENABLED = True
    Config.TXID_CANONICAL_V3_ACTIVATION_HEIGHT = 200
    Config.TXID_CANONICAL_V2_LEGACY_ENABLED = True
    try:
        tx = Transaction(
            sender=Wallet.generate().address,
            receiver=Wallet.generate().address,
            amount=1.0, fee=0.01, timestamp=1000, expiry=2000, nonce=1,
            data="a" * 64 + "b" * 64,
        )
        import hashlib
        core = (f"{tx.sender}{tx.receiver}{tx.amount}{tx.fee}"
                f"{tx.timestamp}{tx.memo}{tx.nonce}{tx.expiry}"
                f"{tx.tx_type}{tx.data[:64]}{tx.gas_limit}{tx.gas_price}"
                f"{tx.contract_name}")
        expected = hashlib.sha256(core.encode()).hexdigest()
        assert tx._compute_legacy_id(50) == expected
        assert tx._compute_legacy_id(150) != expected
    finally:
        Config.TXID_V2_ACTIVATION_HEIGHT = old_v2_activation
        Config.TXID_V1_LEGACY_ENABLED = old_v1_legacy
        Config.TXID_CANONICAL_V3_ACTIVATION_HEIGHT = old_v3_activation
        Config.TXID_CANONICAL_V2_LEGACY_ENABLED = old_v3_legacy


def test_historical_legacy_transaction_survives_full_block_integrity_check():
    old_activation = Config.TXID_V2_ACTIVATION_HEIGHT
    old_v1_legacy = Config.TXID_V1_LEGACY_ENABLED
    old_v3_activation = Config.TXID_CANONICAL_V3_ACTIVATION_HEIGHT
    old_v3_legacy = Config.TXID_CANONICAL_V2_LEGACY_ENABLED
    Config.TXID_V2_ACTIVATION_HEIGHT = 0
    Config.TXID_V1_LEGACY_ENABLED = False
    Config.TXID_CANONICAL_V3_ACTIVATION_HEIGHT = 100
    Config.TXID_CANONICAL_V2_LEGACY_ENABLED = True
    try:
        wallet = Wallet.generate()
        coinbase_wallet = Wallet.generate()
        tx = Transaction(
            sender=wallet.address, receiver=Wallet.generate().address,
            amount=1.0, fee=0.01, timestamp=1_000, expiry=2_000, nonce=0,
        )
        from visold.crypto.ecc import sig_to_hex
        tx.pub_hex = wallet.pub_hex
        tx.sig_hex = sig_to_hex(wallet.sign(tx._legacy_signing_bytes()))
        tx.tx_id = tx._compute_legacy_id(50)
        cb = Transaction.coinbase(coinbase_wallet.address, 0.0, 50)
        block = Block(
            index=50, prev_hash="p" * 64, transactions=[cb, tx],
            miner_address=coinbase_wallet.address, difficulty=Config.INITIAL_DIFFICULTY,
            timestamp=2_000, nonce=0,
        )
        ok, msg = block.integrity_check()
        assert ok, msg
    finally:
        Config.TXID_V2_ACTIVATION_HEIGHT = old_activation
        Config.TXID_V1_LEGACY_ENABLED = old_v1_legacy
        Config.TXID_CANONICAL_V3_ACTIVATION_HEIGHT = old_v3_activation
        Config.TXID_CANONICAL_V2_LEGACY_ENABLED = old_v3_legacy


def test_malformed_pow_input_fails_closed_and_network_json_rejects_nonfinite_constants():
    wallet = Wallet.generate()
    cb = Transaction.coinbase(wallet.address, 0.0, 1)
    bad = Block(
        index=1, prev_hash="p" * 64, transactions=[cb],
        miner_address=wallet.address, difficulty=float("nan"),
        timestamp=123, nonce=0,
    )
    assert bad.mine() is False

    from visold.network.p2p import _reject_nonfinite_json_constant
    for value in ("NaN", "Infinity", "-Infinity"):
        try:
            _reject_nonfinite_json_constant(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"network JSON accepted {value}")


def test_canonical_signature_still_verifies_for_normal_transaction():
    wallet = Wallet.generate()
    tx = Transaction(
        sender=wallet.address, receiver=Wallet.generate().address,
        amount=1.25, fee=0.0125, nonce=0,
    )
    tx.sign(wallet)
    assert tx.verify_signature() is True
    assert tx.is_valid()[0] is True
