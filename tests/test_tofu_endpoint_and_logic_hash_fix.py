"""Regression tests for endpoint-scoped TLS TOFU and non-empty logic hashes."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from visold.kernel import source_identity
from visold.network.tls import TLSManager


class TestEndpointScopedTofu(unittest.TestCase):
    def setUp(self):
        self.original_store = dict(TLSManager._ip_fp_store)
        self.original_bootstrap = set(TLSManager._bootstrap_fp_keys)

    def tearDown(self):
        TLSManager._ip_fp_store.clear()
        TLSManager._ip_fp_store.update(self.original_store)
        TLSManager._bootstrap_fp_keys.clear()
        TLSManager._bootstrap_fp_keys.update(self.original_bootstrap)

    def test_ipv6_endpoint_key_includes_port(self):
        self.assertEqual(
            TLSManager.endpoint_pin_key("2401:4900::1", 8338),
            "[2401:4900::1]:8338")
        self.assertNotEqual(
            TLSManager.endpoint_pin_key("2401:4900::1", 8338),
            TLSManager.endpoint_pin_key("2401:4900::1", 8400))

    def test_ipv4_endpoint_key_includes_port(self):
        self.assertEqual(TLSManager.endpoint_pin_key("106.192.84.42", 8338),
                         "106.192.84.42:8338")
        self.assertNotEqual(
            TLSManager.endpoint_pin_key("106.192.84.42", 8338),
            TLSManager.endpoint_pin_key("106.192.84.42", 8400))

    def test_two_visold_nodes_on_same_ipv6_do_not_collide(self):
        ip = "2401:4900:b7ae:2440:3a1c:64f2:c345:3103"
        self.assertIsNone(TLSManager.record_verified_endpoint_fingerprint(ip, 8338, "a" * 64))
        self.assertIsNone(TLSManager.record_verified_endpoint_fingerprint(ip, 8400, "b" * 64))
        self.assertEqual(TLSManager._ip_fp_store[TLSManager.endpoint_pin_key(ip, 8338)], "a" * 64)
        self.assertEqual(TLSManager._ip_fp_store[TLSManager.endpoint_pin_key(ip, 8400)], "b" * 64)

    def test_bootstrap_endpoint_pin_preferred_over_ip_wildcard(self):
        ip = "2401:4900::1"
        exact = TLSManager.endpoint_pin_key(ip, 8338).lower()
        TLSManager._ip_fp_store[ip] = "1" * 64
        TLSManager._bootstrap_fp_keys.add(ip)
        TLSManager._ip_fp_store[exact] = "2" * 64
        TLSManager._bootstrap_fp_keys.add(exact)
        self.assertEqual(TLSManager.bootstrap_fingerprint_for_endpoint(ip, 8338), "2" * 64)
        self.assertEqual(TLSManager.bootstrap_fingerprint_for_endpoint(ip, 8400), "1" * 64)


class TestLogicHashFallback(unittest.TestCase):
    def test_current_package_hash_is_not_empty_tree_hash(self):
        blob = source_identity.package_source_blob()
        digest = source_identity.compute_node_logic_hash()
        self.assertTrue(blob)
        self.assertNotEqual(digest, hashlib.sha256(b"").hexdigest()[:32])
        self.assertEqual(digest, hashlib.sha256(blob).hexdigest()[:32])
        self.assertEqual(source_identity._NODE_LOGIC_HASH, digest)

    def test_manifest_matches_full_source_tree(self):
        root = Path(source_identity._package_root())
        manifest = json.loads((root / "_build_identity.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["algorithm"], "visold-package-source-v1")
        blob = source_identity.package_source_blob(str(root))
        self.assertEqual(manifest["package_source_sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual(source_identity.compute_node_logic_hash(str(root)),
                         manifest["package_source_sha256"][:32])

    def test_bytecode_only_package_uses_build_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            digest = "0123456789abcdef" * 4
            manifest = {
                "algorithm": "visold-package-source-v1",
                "package_source_sha256": digest,
                "source_file_count": 3,
            }
            Path(tmp, "_build_identity.json").write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(source_identity.compute_node_logic_hash(tmp), digest[:32])

    def test_package_root_handles_sourceless_pyc_under_pycache(self):
        original = source_identity.__file__
        try:
            source_identity.__file__ = "/tmp/site/visold/kernel/__pycache__/source_identity.cpython-313.pyc"
            self.assertEqual(source_identity._package_root(), "/tmp/site/visold")
        finally:
            source_identity.__file__ = original

    def test_missing_sources_and_manifest_are_unknown_not_empty_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(source_identity.compute_node_logic_hash(tmp), "unknown")

    def test_partially_stripped_source_tree_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "module.py").write_text("VALUE = 1\n", encoding="utf-8")
            digest = "f" * 64
            Path(tmp, "_build_identity.json").write_text(json.dumps({
                "algorithm": "visold-package-source-v1",
                "package_source_sha256": digest,
                "source_file_count": 4,
            }), encoding="utf-8")
            self.assertEqual(source_identity.compute_node_logic_hash(tmp), "unknown")


if __name__ == "__main__":
    unittest.main()
