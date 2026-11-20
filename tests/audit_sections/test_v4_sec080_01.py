"""V4 regression tests for Section 80: Contract Naming, Address Derivation, and Identity Resolution."""

import os
import tempfile
import threading
import unittest
from types import SimpleNamespace

from visold.kernel.lru_cache import LRUCache
from visold.network.p2p import P2PNetwork
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet
from visold.crypto.hashing import sha256


class TestSection80IdentityResolution(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmpdir.name, "test.db")
        self.storage = Storage(self.db_path)

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        self._tmpdir.cleanup()

    def test_id_cache_invalidated_after_reorg_removes_claim(self):
        """After a reorg removes a name_claim, resolve_user_id() does not serve stale _id_cache."""
        w = Wallet.generate()
        peer_id = sha256(w.pub_hex.encode())
        uid = "alice"
        self.storage.save_name_claim(uid, w.address, w.pub_hex, 10, "tx_claim_1")
        self.storage.save_identity(
            uid, peer_id, w.address, w.pub_hex, [f"/ip4/127.0.0.1/tcp/5000/p2p/{peer_id}"]
        )

        net = P2PNetwork.__new__(P2PNetwork)
        net.storage = self.storage
        net._id_cache = LRUCache(128)
        net._lock = threading.RLock()
        net.peers = {}
        net.router = SimpleNamespace(get_closest=lambda k: [])

        resolved = net.resolve_user_id(uid)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["wallet_addr"], w.address)

        self.storage.rebuild_name_claims_from_transactions(10)
        self.assertIsNone(self.storage.resolve_identity(uid))

        after_reorg = net.resolve_user_id(uid)
        self.assertIsNone(after_reorg)

    def test_resolve_identity_normalizes_identities_query(self):
        """Storage.resolve_identity() normalizes user_id so multiaddrs and user_id are preserved."""
        w = Wallet.generate()
        peer_id = sha256(w.pub_hex.encode())
        multiaddrs = [f"/ip4/127.0.0.1/tcp/5000/p2p/{peer_id}"]
        self.storage.save_name_claim("alice", w.address, w.pub_hex, 5, "tx_claim_2")
        self.storage.save_identity("alice", peer_id, w.address, w.pub_hex, multiaddrs)

        canon = self.storage.resolve_identity("alice")
        self.assertIsNotNone(canon)
        self.assertEqual(canon["multiaddrs"], multiaddrs)
        self.assertEqual(canon["user_id"], "alice")

        unnorm = self.storage.resolve_identity(" Alice ")
        self.assertIsNotNone(unnorm)
        self.assertEqual(unnorm["multiaddrs"], multiaddrs)
        self.assertEqual(unnorm["user_id"], "alice")
