"""Regression checks for Visold's explicit testnet chain domain."""

from visold.kernel.config import Config
from visold.ledger.transaction import Transaction
from visold.wallet.wallet import Wallet


def test_repository_defaults_to_testnet_chain_id():
    assert Config.CHAIN_ID == "vsd-testnet-1"


def test_transaction_signature_and_id_are_bound_to_testnet_chain_id():
    original_chain_id = Config.CHAIN_ID
    try:
        Config.CHAIN_ID = "vsd-testnet-1"
        wallet = Wallet.generate()
        tx = Transaction(
            sender=wallet.address,
            receiver=wallet.address,
            amount=1.0,
            fee=0.01,
            timestamp=1_798_000_000,
            nonce=1,
            expiry=1_798_003_600,
        )
        tx.sign(wallet)
        testnet_tx_id = tx.tx_id

        assert tx.verify_signature() is True
        assert dict(tx._canonical_fields())["chain_id"] == "vsd-testnet-1"

        # A signature and transaction ID made for the testnet must not validate
        # under a different network domain.
        Config.CHAIN_ID = "vsd-mainnet-1"
        assert tx.verify_signature() is False
        assert tx._compute_id() != testnet_tx_id
    finally:
        Config.CHAIN_ID = original_chain_id
