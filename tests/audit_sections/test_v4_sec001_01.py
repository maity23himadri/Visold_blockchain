"""V4 regression tests for Audit Section 001: Genesis Block Integrity & Pinning."""

import os
import tempfile
import unittest.mock as mock

import pytest

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.node.security_gate import SecurityGate
from visold.storage.storage import Storage


def _make_storage(tmpdir: str) -> Storage:
    return Storage(os.path.join(tmpdir, "visold.db"))


def test_verify_genesis_hash_fails_when_block_zero_missing():
    """SecurityGate.verify_genesis_hash returns False when block 0 is missing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = _make_storage(tmpdir)
        bc = Blockchain(storage)
        stored_hash = storage.get_meta("genesis_hash")
        assert stored_hash, "genesis_hash should be stored after Blockchain init"

        with mock.patch.object(bc, "get_block", return_value=None):
            ok, msg = SecurityGate.verify_genesis_hash(storage, bc)

        assert ok is False
        assert msg != "Genesis OK"


def test_genesis_hash_pin_enforced_on_existing_db():
    """Config.GENESIS_HASH_PIN is enforced even when reopening an existing database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = _make_storage(tmpdir)
        bc = Blockchain(storage)
        real_hash = storage.get_meta("genesis_hash")
        assert real_hash

        wrong_pin = "f" * 64
        assert wrong_pin != real_hash.lower()

        with mock.patch.object(Config, "GENESIS_HASH_PIN", wrong_pin):
            with pytest.raises(RuntimeError, match="GENESIS_HASH_PIN"):
                Blockchain(storage)


def test_validate_block_rejects_forged_genesis_when_meta_missing():
    """Blockchain.validate_block rejects a forged genesis block even if genesis_hash meta is empty."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = _make_storage(tmpdir)
        bc = Blockchain(storage)
        storage.set_meta("genesis_hash", "")

        forged_tx = Transaction(
            sender="COINBASE",
            receiver="VSD_ATTACKER_ADDRESS",
            amount=1_000_000_000_000,
            fee=0.0,
            timestamp=9999999999,
            memo="forged-genesis",
            nonce=999,
            expiry=0,
        )
        forged_genesis = Block(
            index=0,
            prev_hash="1" * 64,
            transactions=[forged_tx],
            miner_address="VSD_ATTACKER_ADDRESS",
            difficulty=1.0,
            timestamp=9999999999,
            nonce=12345,
        )
        forged_genesis.seal()

        ok, msg = bc.validate_block(forged_genesis)
        assert ok is False
        assert "Genesis block hash mismatch" in msg
