import hashlib
import pickle

from visold.crypto.ecc import (
    ECPoint, _COINCURVE_SELFTEST_OK, ecdsa_sign, ecdsa_verify, pub_from_hex,
    pub_to_hex, sig_from_hex, sig_to_hex,
)
from visold.ledger.block import Block
from visold.crypto.parallel_verify import _par_verify_sig_batch
from visold.wallet.wallet import Wallet


def test_wallet_sign_verify_and_serialization_remain_compatible():
    wallet = Wallet.generate()
    data = b"Visold crypto acceleration regression"
    sig = wallet.sign(data)
    assert ecdsa_verify(wallet.pub, hashlib.sha256(data).digest(), sig) is True
    assert ecdsa_verify(wallet.pub, hashlib.sha256(data + b"!").digest(), sig) is False

    tx_sig = sig_to_hex(sig)
    assert sig_from_hex(tx_sig) == sig
    restored = Wallet.from_dict(wallet.to_dict())
    assert restored.address == wallet.address
    assert restored.pub_hex == pub_to_hex(restored.pub)
    restored_sig = restored.sign(data)
    assert restored_sig and ecdsa_verify(restored.pub, hashlib.sha256(data).digest(), restored_sig)


def test_high_and_low_s_signatures_verify():
    wallet = Wallet.generate()
    msg_hash = hashlib.sha256(b"high-s compatibility").digest()
    r, s = ecdsa_sign(wallet.priv, msg_hash)
    assert ecdsa_verify(wallet.pub, msg_hash, (r, s))
    high_s = ECPoint.N - s
    assert 1 <= high_s < ECPoint.N
    assert ecdsa_verify(wallet.pub, msg_hash, (r, high_s))


def test_optional_backend_never_changes_public_key_encoding():
    wallet = Wallet.generate()
    pub = pub_from_hex(wallet.pub_hex)
    assert pub_to_hex(pub) == wallet.pub_hex
    assert isinstance(_COINCURVE_SELFTEST_OK, bool)



def test_wallet_native_signing_cache_is_not_serialized():
    wallet = Wallet.generate()
    restored = pickle.loads(pickle.dumps(wallet))
    assert restored.address == wallet.address
    sig = restored.sign(b"pickle-cache-regression")
    assert ecdsa_verify(restored.pub, hashlib.sha256(b"pickle-cache-regression").digest(), sig)


def test_block_validation_does_not_verify_each_signature_twice():
    import os
    import tempfile
    from unittest.mock import patch

    from visold.chain.blockchain import Blockchain
    from visold.kernel.config import Config
    from visold.ledger.transaction import Transaction
    from visold.storage.storage import Storage

    with tempfile.TemporaryDirectory() as td:
        storage = Storage(os.path.join(td, "batch-opt.db"))
        bc = Blockchain(storage)
        sender = Wallet.generate()
        receiver = Wallet.generate()
        storage.credit_sat(sender.address, 10 * Config.SATOSHI_PER_VSD)
        tx = Transaction(
            sender=sender.address, receiver=receiver.address, amount=1.0,
            fee=0.01, nonce=storage.get_nonce(sender.address),
            expiry=2_000_000_000,
        )
        tx.sign(sender)
        cb = Transaction.coinbase(receiver.address, bc.compute_reward(1), 1)
        prev = bc.latest_block()
        block = Block(
            index=1, prev_hash=prev.block_hash, transactions=[cb, tx],
            miner_address=receiver.address, difficulty=bc.get_difficulty(),
            timestamp=prev.timestamp + 1,
        )

        calls = {"n": 0}
        import visold.ledger.block as block_module
        original = block_module._par_verify_sig

        def counted(*args, **kwargs):
            calls["n"] += 1
            return original(*args, **kwargs)

        # Visold 10 intentionally bypasses the high-level Transaction.verify_signature()
        # method in the block-integrity hot path.  Instrument the actual lower-level
        # verifier used by that path so this test checks the security property rather
        # than a historical call topology.
        with patch.object(block_module, "_par_verify_sig", side_effect=counted), \
             patch.object(block, "validate_pow", return_value=True):
            ok, msg = bc.validate_block(block)

        assert ok, msg
        assert calls["n"] == 1


def test_parallel_signature_batch_matches_single_signature_verifier():
    wallet = Wallet.generate()
    items = []
    for i in range(9):
        payload = f"batch-regression-{i}".encode()
        sig = wallet.sign(payload)
        items.append((wallet.pub_hex, sig_to_hex(sig), payload, wallet.address, None))

    assert _par_verify_sig_batch(items) == -1

    # A bad signature must fail closed and identify the first failing item.
    bad = list(items[5])
    bad[1] = sig_to_hex((1, 1))
    bad_items = list(items)
    bad_items[5] = tuple(bad)
    assert _par_verify_sig_batch(bad_items) == 5

    # Sender binding is part of the worker's validation contract.
    wrong_sender = list(items[2])
    wrong_sender[3] = "VSD111111111111111111111111"
    wrong_items = list(items)
    wrong_items[2] = tuple(wrong_sender)
    assert _par_verify_sig_batch(wrong_items) == 2
