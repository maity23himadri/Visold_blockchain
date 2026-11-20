"""Section 13 V4 Regression Tests: Hashing Algorithms, Domain Separation, Hash Integrity."""

import hashlib
from pathlib import Path
import sys

import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.crypto.ecc import (
    _effective_ecdsa_digest,
    ecdsa_keygen,
    ecdsa_sign,
    ecdsa_verify,
)
from visold.crypto.hashing import hash_obj, sha256, sha256d
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.wallet.wallet import Wallet


def test_hashing_primitives_determinism_and_types():
    data = b"visold-hashing-test"
    hex_digest = sha256(data)
    assert isinstance(hex_digest, str)
    assert len(hex_digest) == 64
    assert hex_digest == hashlib.sha256(data).hexdigest()

    double_digest = sha256d(data)
    assert isinstance(double_digest, bytes)
    assert len(double_digest) == 32
    assert double_digest == hashlib.sha256(hashlib.sha256(data).digest()).digest()

    assert hash_obj({"b": 2, "a": 1}) == hash_obj({"a": 1, "b": 2})


def test_effective_ecdsa_digest_validation_and_sign_verify_parity():
    with pytest.raises(TypeError):
        _effective_ecdsa_digest("not-bytes")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _effective_ecdsa_digest(b"\x00" * 31)
    with pytest.raises(ValueError):
        _effective_ecdsa_digest(b"\x00" * 33)

    msg_hash = hashlib.sha256(b"domain-test").digest()
    assert _effective_ecdsa_digest(msg_hash) == hashlib.sha256(msg_hash).digest()

    priv, pub = ecdsa_keygen()
    sig = ecdsa_sign(priv, msg_hash)
    assert ecdsa_verify(pub, msg_hash, sig) is True
    assert ecdsa_verify(pub, hashlib.sha256(b"other").digest(), sig) is False


def test_transaction_v2_length_delimited_boundary_collision_resistance():
    w = Wallet.generate()
    tx1 = Transaction(
        sender=w.address,
        receiver=w.address,
        amount=1.0,
        fee=0.01,
        timestamp=1_798_000_000,
        memo="",
        nonce=123,
        expiry=1_798_003_600,
    )
    tx2 = Transaction(
        sender=w.address,
        receiver=w.address,
        amount=1.0,
        fee=0.01,
        timestamp=1_798_000_000,
        memo="1",
        nonce=23,
        expiry=1_798_003_600,
    )
    assert tx1.signing_bytes().startswith(b"VSD-TX-V2\x00")
    assert tx1.signing_bytes() != tx2.signing_bytes()
    assert tx1.tx_id != tx2.tx_id
    assert tx1.tx_id == sha256(tx1.signing_bytes())


def test_block_merkle_v2_odd_leaf_domain_separation():
    w = Wallet.generate()
    txs = []
    for i in range(3):
        tx = Transaction(
            sender=w.address,
            receiver=w.address,
            amount=1.0,
            fee=0.01,
            timestamp=1_798_000_000 + i,
            nonce=i,
            expiry=1_798_003_600,
        )
        tx.sign(w)
        txs.append(tx)

    b_odd = Block(index=1, prev_hash="0" * 64, transactions=txs, miner_address=w.address, difficulty=4.0, timestamp=1_798_000_010)
    b_dup = Block(index=1, prev_hash="0" * 64, transactions=txs + [txs[-1]], miner_address=w.address, difficulty=4.0, timestamp=1_798_000_010)
    assert b_odd.merkle_root != b_dup.merkle_root

    b_empty = Block(index=1, prev_hash="0" * 64, transactions=[], miner_address=w.address, difficulty=4.0, timestamp=1_798_000_010)
    assert b_empty.merkle_root == sha256(b"empty")
    assert b_empty.compute_hash() == hash_obj(b_empty.header_dict())


def test_chain_id_domain_separation_l1_and_l2():
    orig = Config.CHAIN_ID
    try:
        w = Wallet.generate()
        Config.CHAIN_ID = "vsd-testnet-1"
        l1_tx = Transaction(
            sender=w.address,
            receiver=w.address,
            amount=1.0,
            fee=0.01,
            timestamp=1_798_000_000,
            nonce=1,
            expiry=1_798_003_600,
        )
        l1_tx.sign(w)
        l2_tx = w.sign_l2_tx(w.address, 100_000_000, nonce=1, timestamp=1_798_000_000)

        assert l1_tx.verify_signature() is True
        assert l2_tx.signing_bytes().startswith(b"VSD-L2|vsd-testnet-1|")

        Config.CHAIN_ID = "vsd-mainnet-1"
        assert l1_tx.verify_signature() is False
        assert l2_tx.signing_bytes().startswith(b"VSD-L2|vsd-mainnet-1|")
    finally:
        Config.CHAIN_ID = orig
