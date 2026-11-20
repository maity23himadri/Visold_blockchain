# -*- coding: utf-8 -*-
"""V4 regression tests for Section 84: Rollup Proof Generation and Verification."""

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.chain.sequencer import Sequencer
from visold.kernel.config import Config
from visold.rollup.batches import RollupBatch, RollupSubmission
from visold.rollup.compact_codec import l2_pub_compact, l2_sig_compact
from visold.rollup.l2_state import L2Transaction, Layer2State
from visold.rollup.proofs import (
    IProofBackend,
    LocalDevBackend,
    ProofBackendError,
    ProofRegistry,
    SimulatedProofBackend,
    SubprocessSNARKBackend,
)
from visold.storage.storage import Storage
from visold.vm.precompiles import VVMPrecompiles
from visold.wallet.wallet import Wallet


class TestV4Section84Proofs(unittest.TestCase):
    def setUp(self):
        self._orig_backend = Config.L2_PROOF_BACKEND
        self._orig_net = os.environ.get("VISOLD_NETWORK")
        self._orig_secret = os.environ.get("VISOLD_L2_DEV_SECRET")
        os.environ.pop("VISOLD_NETWORK", None)
        os.environ.pop("VISOLD_L2_DEV_SECRET", None)
        Config.L2_PROOF_BACKEND = "local-dev"

    def tearDown(self):
        Config.L2_PROOF_BACKEND = self._orig_backend
        if self._orig_net is None:
            os.environ.pop("VISOLD_NETWORK", None)
        else:
            os.environ["VISOLD_NETWORK"] = self._orig_net
        if self._orig_secret is None:
            os.environ.pop("VISOLD_L2_DEV_SECRET", None)
        else:
            os.environ["VISOLD_L2_DEV_SECRET"] = self._orig_secret

    def test_local_dev_and_simulated_roundtrip_and_tamper(self):
        b1 = LocalDevBackend()
        b2 = SimulatedProofBackend()
        prev_r = "a" * 64
        new_r = "b" * 64
        bh = "c" * 64

        proof = b1.prove(prev_r, new_r, bh, b"witness")
        self.assertEqual(len(proof), 32)
        self.assertTrue(b1.verify(prev_r, new_r, bh, proof))
        self.assertTrue(b2.verify(prev_r, new_r, bh, proof))

        self.assertFalse(b1.verify("d" * 64, new_r, bh, proof))
        self.assertFalse(b1.verify(prev_r, "d" * 64, bh, proof))
        self.assertFalse(b1.verify(prev_r, new_r, "d" * 64, proof))
        self.assertFalse(b1.verify(prev_r, new_r, bh, bytes([proof[0] ^ 0xFF]) + proof[1:]))
        self.assertFalse(b1.verify(prev_r, new_r, bh, b"short"))
        self.assertFalse(b1.verify(prev_r, new_r, bh, None))  # type: ignore[arg-type]
        self.assertFalse(b1.verify(prev_r, new_r, bh, "not-bytes"))  # type: ignore[arg-type]

    def test_local_dev_secret_isolation(self):
        b_a = LocalDevBackend(sequencer_secret=b"\x01" * 32)
        b_b = LocalDevBackend(sequencer_secret=b"\x02" * 32)
        os.environ["VISOLD_L2_DEV_SECRET"] = ("01" * 32)
        b_env = LocalDevBackend()

        proof = b_a.prove("a" * 64, "b" * 64, "c" * 64)
        self.assertTrue(b_env.verify("a" * 64, "b" * 64, "c" * 64, proof))
        self.assertFalse(b_b.verify("a" * 64, "b" * 64, "c" * 64, proof))

    def test_subprocess_snark_stub_and_configured(self):
        stub = SubprocessSNARKBackend()
        self.assertFalse(stub.is_production_ready())
        with self.assertRaises(ProofBackendError):
            stub.prove("a" * 64, "b" * 64, "c" * 64)
        self.assertFalse(stub.verify("a" * 64, "b" * 64, "c" * 64, b"\x00" * 32))

        _base_84 = os.path.dirname(os.path.abspath(__file__))
        _exec_84 = _base_84
        with tempfile.TemporaryDirectory(dir=_base_84) as _probe_dir:
            _probe = os.path.join(_probe_dir, "_probe.sh")
            with open(_probe, "w") as _pf:
                _pf.write("#!/bin/sh\n")
            os.chmod(_probe, 0o755)
            if not os.access(_probe, os.X_OK) or _base_84.startswith("/storage/emulated"):
                _exec_84 = tempfile.gettempdir()
        with tempfile.TemporaryDirectory(dir=_exec_84) as tmp:
            vk = os.path.join(tmp, "vk.json")
            pk = os.path.join(tmp, "pk.json")
            with open(vk, "w") as f:
                f.write("{}")
            with open(pk, "w") as f:
                f.write("{}")

            prover = os.path.join(tmp, "prover.py")
            with open(prover, "w") as f:
                f.write(
                    "#!/usr/bin/env python3\n"
                    "import json, sys\n"
                    "req = json.loads(sys.stdin.readline())\n"
                    "print(json.dumps({'ok': True, 'proof': 'deadbeef'}))\n"
                )
            os.chmod(prover, os.stat(prover).st_mode | stat.S_IXUSR)

            verifier = os.path.join(tmp, "verifier.py")
            with open(verifier, "w") as f:
                f.write(
                    "#!/usr/bin/env python3\n"
                    "import json, sys\n"
                    "req = json.loads(sys.stdin.readline())\n"
                    "ok = (req.get('proof') == 'deadbeef')\n"
                    "print(json.dumps({'ok': ok}))\n"
                )
            os.chmod(verifier, os.stat(verifier).st_mode | stat.S_IXUSR)

            with patch.dict(os.environ, {"VISOLD_SNARK_AUDITED": "1"}):
                backend = SubprocessSNARKBackend(
                    verifier_bin=verifier,
                    prover_bin=prover,
                    vk_path=vk,
                    pk_path=pk,
                    security_label="zk-groth16-bn254",
                )
                self.assertTrue(backend.is_production_ready())
                proof = backend.prove("a" * 64, "b" * 64, "c" * 64, b"wit")
                self.assertEqual(proof, b"\xde\xad\xbe\xef")
                self.assertTrue(backend.verify("a" * 64, "b" * 64, "c" * 64, proof))
                self.assertFalse(backend.verify("a" * 64, "b" * 64, "c" * 64, b"\x00\x01"))

                v_only = SubprocessSNARKBackend(
                    verifier_bin=verifier,
                    prover_bin="",
                    vk_path=vk,
                    security_label="zk-groth16-bn254",
                )
                self.assertTrue(v_only.is_production_ready())
                self.assertTrue(v_only.verify("a" * 64, "b" * 64, "c" * 64, proof))
                with self.assertRaises(ProofBackendError):
                    v_only.prove("a" * 64, "b" * 64, "c" * 64, b"wit")

    def test_l2_verifier_precompile_paths(self):
        backend = ProofRegistry.get_configured()
        prev_r = "11" * 32
        new_r = "22" * 32
        bh = "33" * 32
        proof = backend.prove(prev_r, new_r, bh)

        calldata = json.dumps({
            "previous_l2_root": prev_r,
            "new_l2_root": new_r,
            "batch_hash": bh,
            "zk_proof": proof.hex(),
        }).encode("utf-8")

        expected_gas = 150_000 + 20 * len(proof)
        ok, ret, gas = VVMPrecompiles.execute(VVMPrecompiles.L2_VERIFIER, calldata, 2_000_000)
        self.assertTrue(ok)
        self.assertEqual(ret, b"\x01" + bytes.fromhex(bh))
        self.assertEqual(gas, expected_gas)

        ok, ret, gas = VVMPrecompiles.execute(VVMPrecompiles.L2_VERIFIER, calldata, 100_000)
        self.assertFalse(ok)
        self.assertEqual(ret, b"\x00NGAS")
        self.assertEqual(gas, 100_000)

        ok, ret, gas = VVMPrecompiles.execute(VVMPrecompiles.L2_VERIFIER, calldata, expected_gas - 1)
        self.assertFalse(ok)
        self.assertEqual(ret, b"\x00NGAS")

        ok, ret, _ = VVMPrecompiles.execute(VVMPrecompiles.L2_VERIFIER, b"{bad", 2_000_000)
        self.assertFalse(ok)
        self.assertEqual(ret, b"\x00JSON")

        ok, ret, _ = VVMPrecompiles.execute(VVMPrecompiles.L2_VERIFIER, b"{}", 2_000_000)
        self.assertFalse(ok)
        self.assertEqual(ret, b"\x00FLDS")

        bad_root = json.dumps({
            "previous_l2_root": "aa",
            "new_l2_root": new_r,
            "batch_hash": bh,
            "zk_proof": proof.hex(),
        }).encode("utf-8")
        ok, ret, _ = VVMPrecompiles.execute(VVMPrecompiles.L2_VERIFIER, bad_root, 2_000_000)
        self.assertFalse(ok)
        self.assertEqual(ret, b"\x00ROOT")

        bad_proof = json.dumps({
            "previous_l2_root": prev_r,
            "new_l2_root": new_r,
            "batch_hash": bh,
            "zk_proof": ("00" * 32),
        }).encode("utf-8")
        ok, ret, _ = VVMPrecompiles.execute(VVMPrecompiles.L2_VERIFIER, bad_proof, 2_000_000)
        self.assertFalse(ok)
        self.assertEqual(ret, b"\x00FAIL")

        os.environ["VISOLD_NETWORK"] = "mainnet"
        ok, ret, _ = VVMPrecompiles.execute(VVMPrecompiles.L2_VERIFIER, calldata, 2_000_000)
        self.assertFalse(ok)
        self.assertEqual(ret, b"\x00VERR")

    def test_sequencer_seal_one_and_generate_batch_proof(self):
        with tempfile.TemporaryDirectory(dir=os.path.dirname(__file__)) as tmp:
            storage = Storage(os.path.join(tmp, "db"))
            l2 = Layer2State(storage)
            w_seq = Wallet.generate()
            w_alice = Wallet.generate()
            w_bob = Wallet.generate()
            l2.L2_deposit(w_alice.address, 100_000, l1_height=1, l1_block_hash="h1")
            pre_root = l2.root()

            bc = MagicMock()
            bc.storage = storage
            seq = Sequencer(l2, w_seq, bc)
            seq._running = True

            l2tx = L2Transaction(
                sender=w_alice.address,
                receiver=w_bob.address,
                amount_sat=25_000,
                nonce=0,
                timestamp=1700000000,
                pub=l2_pub_compact(w_alice.pub_hex),
            )
            import hashlib
            from visold.crypto.ecc import ecdsa_sign, sig_to_hex
            priv_int = w_alice.priv
            digest = hashlib.sha256(l2tx.signing_bytes()).digest()
            l2tx.sig = l2_sig_compact(sig_to_hex(ecdsa_sign(priv_int, digest)))
            l2tx.l2_tx_id = l2tx._compute_id()

            ok, msg = seq.add_l2_tx(l2tx)
            self.assertTrue(ok, msg)

            sealed = seq._seal_one()
            self.assertIsNotNone(sealed)
            l1_tx, batch_id, applied = sealed  # type: ignore[misc]
            try:
                self.assertEqual(batch_id, 0)
                self.assertEqual(len(applied), 1)
                self.assertEqual(l2.root(), pre_root)

                sub = RollupSubmission.from_json(l1_tx.data)
                self.assertEqual(sub.previous_l2_root, pre_root)
                self.assertNotEqual(sub.new_l2_root, pre_root)
                bh = RollupSubmission.batch_hash(sub.compressed_data)
                calldata = json.dumps({
                    "previous_l2_root": sub.previous_l2_root,
                    "new_l2_root": sub.new_l2_root,
                    "batch_hash": bh,
                    "zk_proof": sub.zk_proof.hex(),
                }).encode("utf-8")
                ok_v, ret_v, _ = VVMPrecompiles.execute(VVMPrecompiles.L2_VERIFIER, calldata, 2_000_000)
                self.assertTrue(ok_v)
                self.assertEqual(ret_v, b"\x01" + bytes.fromhex(bh))
            finally:
                seq._abandon_seal()

            with patch.object(seq, "generate_batch_proof", side_effect=ProofBackendError("boom")):
                with self.assertRaises(ProofBackendError):
                    seq._seal_one()
            self.assertTrue(seq._seal_cycle_lock.acquire(blocking=False))
            seq._seal_cycle_lock.release()


if __name__ == "__main__":
    unittest.main()
