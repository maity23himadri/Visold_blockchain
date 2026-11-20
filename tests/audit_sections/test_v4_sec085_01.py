import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.kernel.config import Config
from visold.rollup.proofs import (
    IProofBackend,
    LocalDevBackend,
    ProofRegistry,
    SimulatedProofBackend,
    SubprocessSNARKBackend,
    UnsafeBackendOnMainnetError,
    _is_unsafe_backend,
)


class _UnreadyCustomBackend(IProofBackend):
    """Custom IProofBackend that has a clean security label but has NOT
    opted into production readiness (inherits default False)."""

    def name(self) -> str:
        return "custom-groth16-unready"

    def security(self) -> str:
        return "zk-groth16-bn254"

    def prove(self, prev_root: str, new_root: str,
              batch_hash: str, witness: bytes = b"") -> bytes:
        return b"\x01" * 32

    def verify(self, prev_root: str, new_root: str,
               batch_hash: str, proof_bytes: bytes) -> bool:
        return True


class _BrokenReadinessCustomBackend(IProofBackend):
    """Custom IProofBackend whose is_production_ready() raises."""

    def name(self) -> str:
        return "custom-broken-readiness"

    def security(self) -> str:
        return "zk-plonk-bls12-381"

    def is_production_ready(self) -> bool:
        raise RuntimeError("proving key check failed")

    def prove(self, prev_root: str, new_root: str,
              batch_hash: str, witness: bytes = b"") -> bytes:
        return b"\x01" * 32

    def verify(self, prev_root: str, new_root: str,
               batch_hash: str, proof_bytes: bytes) -> bool:
        return True


class _ReadyCustomBackend(IProofBackend):
    """Custom IProofBackend that explicitly asserts production readiness."""

    def name(self) -> str:
        return "custom-groth16-ready"

    def security(self) -> str:
        return "zk-groth16-bn254"

    def is_production_ready(self) -> bool:
        return True

    def prove(self, prev_root: str, new_root: str,
              batch_hash: str, witness: bytes = b"") -> bytes:
        return b"\x01" * 32

    def verify(self, prev_root: str, new_root: str,
               batch_hash: str, proof_bytes: bytes) -> bool:
        return True


class TestV4Section85ProofRegistry(unittest.TestCase):

    def setUp(self):
        self._orig_backends = dict(ProofRegistry._backends)
        self._orig_cfg_backend = Config.L2_PROOF_BACKEND

    def tearDown(self):
        ProofRegistry._backends.clear()
        ProofRegistry._backends.update(self._orig_backends)
        Config.L2_PROOF_BACKEND = self._orig_cfg_backend

    def test_mainnet_rejects_dev_and_missing_backends(self):
        with patch.dict(os.environ, {"VISOLD_NETWORK": "mainnet"}):
            Config.L2_PROOF_BACKEND = "no-backend-configured"
            with self.assertRaises(UnsafeBackendOnMainnetError):
                ProofRegistry.get_configured()

            Config.L2_PROOF_BACKEND = "local-dev"
            with self.assertRaises(UnsafeBackendOnMainnetError):
                ProofRegistry.get_configured()

            Config.L2_PROOF_BACKEND = "simulated"
            with self.assertRaises(UnsafeBackendOnMainnetError):
                ProofRegistry.get_configured()

            stub = SubprocessSNARKBackend()
            ProofRegistry.register(stub)
            Config.L2_PROOF_BACKEND = stub.name()
            with self.assertRaises(UnsafeBackendOnMainnetError):
                ProofRegistry.get_configured()

    def test_devnet_falls_back_to_local_dev_when_unconfigured(self):
        with patch.dict(os.environ, {"VISOLD_NETWORK": "dev"}):
            Config.L2_PROOF_BACKEND = "no-backend-configured"
            backend = ProofRegistry.get_configured()
            self.assertIsInstance(backend, LocalDevBackend)

    def test_mainnet_accepts_production_ready_custom_backend(self):
        ready = _ReadyCustomBackend()
        ProofRegistry.register(ready)
        self.assertFalse(_is_unsafe_backend(ready))
        with patch.dict(os.environ, {"VISOLD_NETWORK": "mainnet"}):
            Config.L2_PROOF_BACKEND = ready.name()
            self.assertIs(ProofRegistry.get_configured(), ready)

    def test_unready_custom_backend_rejected_by_mainnet_guard(self):
        """V4 fix: _is_unsafe_backend() checks is_production_ready() for all
        IProofBackend subclasses, so get_configured() raises on mainnet."""
        unready = _UnreadyCustomBackend()
        ProofRegistry.register(unready)
        self.assertFalse(unready.is_production_ready())

        self.assertTrue(_is_unsafe_backend(unready))
        with patch.dict(os.environ, {"VISOLD_NETWORK": "mainnet"}):
            Config.L2_PROOF_BACKEND = unready.name()
            with self.assertRaises(UnsafeBackendOnMainnetError):
                ProofRegistry.get_configured()

    def test_broken_readiness_custom_backend_rejected_by_mainnet_guard(self):
        """V4 fix: _is_unsafe_backend() catches exceptions from is_production_ready()
        and treats the backend as unsafe on mainnet."""
        broken = _BrokenReadinessCustomBackend()
        ProofRegistry.register(broken)

        self.assertTrue(_is_unsafe_backend(broken))
        with patch.dict(os.environ, {"VISOLD_NETWORK": "mainnet"}):
            Config.L2_PROOF_BACKEND = broken.name()
            with self.assertRaises(UnsafeBackendOnMainnetError):
                ProofRegistry.get_configured()


if __name__ == "__main__":
    unittest.main()
