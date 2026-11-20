"""V4 regression tests for Section 80 (Session 06): Naming, Identity Resolution, and Block Validation."""

import os
import tempfile
import unittest

from visold.chain.blockchain import Blockchain
from visold.consensus.difficulty import DifficultyEngine
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.units import to_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.vm.naming import derive_contract_address
from visold.wallet.wallet import Wallet


class TestAuditSection80(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_data_dir = Config.DATA_DIR
        self._orig_rocks = Config.ROCKSDB_PATH
        self._orig_level = Config.LEVELDB_PATH
        Config.DATA_DIR = self._tmpdir.name
        Config.ROCKSDB_PATH = os.path.join(self._tmpdir.name, "rocks")
        Config.LEVELDB_PATH = os.path.join(self._tmpdir.name, "level")
        self.db_path = os.path.join(self._tmpdir.name, "test.db")
        self.storage = Storage(self.db_path)

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        Config.DATA_DIR = self._orig_data_dir
        Config.ROCKSDB_PATH = self._orig_rocks
        Config.LEVELDB_PATH = self._orig_level
        self._tmpdir.cleanup()

    def test_resolve_identity_normalized_user_id_preserves_directory_metadata(self):
        """Storage.resolve_identity() normalizes user_id and preserves multiaddrs/last_seen."""
        wallet = Wallet.generate()
        peer_id = sha256(wallet.pub_hex.encode())
        maddrs = [f"/ip4/127.0.0.1/tcp/8333/p2p/{peer_id}"]

        self.storage.save_name_claim(
            user_id="alice",
            wallet_addr=wallet.address,
            pub_hex=wallet.pub_hex,
            registered_height=1,
            tx_id="tx_claim_001",
        )
        self.storage.save_identity(
            user_id="alice",
            peer_id=peer_id,
            wallet_addr=wallet.address,
            pub_hex=wallet.pub_hex,
            multiaddrs=maddrs,
        )

        canon = self.storage.resolve_identity("alice")
        self.assertIsNotNone(canon)
        self.assertEqual(canon["multiaddrs"], maddrs)
        self.assertGreater(canon["last_seen"], 0)

        mixed = self.storage.resolve_identity("Alice")
        self.assertIsNotNone(mixed)
        self.assertEqual(mixed["wallet_addr"], wallet.address)
        self.assertEqual(mixed["multiaddrs"], maddrs)
        self.assertGreater(mixed["last_seen"], 0)
        self.assertEqual(mixed["user_id"], "alice")

    def test_validate_block_accepts_valid_named_deploy_after_reverted_same_name_deploy(self):
        """Blockchain.validate_block() accepts a valid named deploy after an earlier reverted same-name deploy."""
        bc = Blockchain(self.storage)
        wallet = Wallet.generate()
        sender = wallet.address
        self.storage.credit_sat(sender, to_satoshi(1000.0))

        revert_bytecode = "60006000fd"
        ok_bytecode = "60016000f3"

        gas_limit = Config.VVM_DEPLOY_GAS_BASE + 10000
        gas_price = Config.VVM_MIN_GAS_PRICE
        fee = round(gas_limit * gas_price, 8)

        tx0 = Transaction(
            sender=sender,
            receiver="",
            amount=0.0,
            fee=fee,
            nonce=0,
            tx_type=Transaction.TYPE_DEPLOY,
            data=revert_bytecode,
            gas_limit=gas_limit,
            gas_price=gas_price,
            contract_name="mytoken",
        )
        tx0.sign(wallet)

        tx1 = Transaction(
            sender=sender,
            receiver="",
            amount=0.0,
            fee=fee,
            nonce=1,
            tx_type=Transaction.TYPE_DEPLOY,
            data=ok_bytecode,
            gas_limit=gas_limit,
            gas_price=gas_price,
            contract_name="mytoken",
        )
        tx1.sign(wallet)

        addr1 = derive_contract_address(sender, tx1.nonce, tx1.tx_id)
        call_gas = 50000
        tx2 = Transaction(
            sender=sender,
            receiver=addr1,
            amount=0.0,
            fee=round(call_gas * gas_price, 8),
            nonce=2,
            tx_type=Transaction.TYPE_CALL,
            data="",
            gas_limit=call_gas,
            gas_price=gas_price,
        )
        tx2.sign(wallet)

        tip = bc.latest_block()
        height = tip.index + 1
        txs = [tx0, tx1, tx2]

        state_root = bc.dry_run_state_root(
            txs,
            height=height,
            miner_address=sender,
            difficulty=tip.difficulty,
            timestamp=tip.timestamp + 10,
        )
        self.assertTrue(bool(state_root))

        reward = Config.INITIAL_REWARD / Config.SATOSHI_PER_VSD
        coinbase = Transaction.coinbase(sender, reward, height)
        block = Block(
            index=height,
            prev_hash=tip.block_hash,
            transactions=[coinbase] + txs,
            miner_address=sender,
            difficulty=tip.difficulty,
            timestamp=tip.timestamp + 10,
            state_root=state_root,
        )
        while not DifficultyEngine.validate_pow_target(block.block_hash, block.difficulty):
            block.nonce += 1
            block.block_hash = block.compute_hash()

        ok, reason = bc.validate_block(block)
        self.assertTrue(ok, reason)
