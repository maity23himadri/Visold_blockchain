from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

from visold.chain.sequencer import Sequencer
from visold.kernel.config import Config
from visold.rollup.batches import RollupBatch, RollupSubmission
from visold.rollup.proofs import IProofBackend, ProofRegistry, SubprocessSNARKBackend


class CaptureBackend(IProofBackend):
    def __init__(self):
        self.last = None
    def name(self): return "capture-witness-test"
    def security(self): return "test-only-capture"
    def prove(self, prev_root, new_root, batch_hash, witness=b""):
        self.last = (prev_root, new_root, batch_hash, witness)
        return b"proof"
    def verify(self, prev_root, new_root, batch_hash, proof_bytes):
        return proof_bytes == b"proof"


def test_sequencer_passes_canonical_nonempty_transition_witness():
    backend = CaptureBackend()
    ProofRegistry.register(backend)
    old = Config.L2_PROOF_BACKEND
    Config.L2_PROOF_BACKEND = backend.name()
    try:
        prev = "11" * 32
        new = "22" * 32
        batch = RollupBatch(7, prev)
        batch.new_root = new
        batch.sealed = True
        compressed = RollupSubmission.compress_batch([])
        snap = {
            "VSDalice": {"address": "VSDalice", "balance_sat": 25, "nonce": 3}
        }
        proof = Sequencer.generate_batch_proof(None, batch, compressed, snap)
        assert proof == b"proof"
        got_prev, got_new, got_hash, witness = backend.last
        assert got_prev == prev and got_new == new
        assert got_hash == RollupSubmission.batch_hash(compressed)
        obj = json.loads(witness.decode("utf-8"))
        assert obj["version"] == "visold_l2_witness_v1"
        assert obj["previous_l2_root"] == prev
        assert obj["new_l2_root"] == new
        assert obj["batch_hash"] == got_hash
        assert bytes.fromhex(obj["compressed_data"]) == compressed
        assert obj["pre_state"] == snap
        assert obj["transactions"] == []
    finally:
        Config.L2_PROOF_BACKEND = old


def _write_backend(path: Path, role: str):
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json,sys\n"
        "args=sys.argv[1:]\n"
        "payload=json.loads(sys.stdin.readline())\n"
        f"role={role!r}\n"
        "if role=='prove':\n"
        "  ok=('--pk' in args and payload.get('witness'))\n"
        "  print(json.dumps({'ok':bool(ok),'proof':'aabb' if ok else ''}))\n"
        "else:\n"
        "  ok=('--vk' in args and payload.get('proof')=='aabb')\n"
        "  print(json.dumps({'ok':bool(ok)}))\n"
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_subprocess_backend_uses_explicit_pk_vk_flags_not_filename_heuristics(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        # Deliberately names that do NOT contain 'verif'/'prov'.
        prover = td / "alpha"
        verifier = td / "beta"
        pk = td / "circuit.pk"
        vk = td / "circuit.vk"
        pk.write_bytes(b"pk")
        vk.write_bytes(b"vk")
        _write_backend(prover, "prove")
        _write_backend(verifier, "verify")
        monkeypatch.setenv("VISOLD_SNARK_AUDITED", "1")
        b = SubprocessSNARKBackend(
            verifier_bin=str(verifier), prover_bin=str(prover),
            vk_path=str(vk), pk_path=str(pk),
            security_label="zk-groth16-bn254-integration-test")
        assert b.is_production_ready()
        proof = b.prove("11"*32, "22"*32, "33"*32, b"real-witness-bytes")
        assert proof == bytes.fromhex("aabb")
        assert b.verify("11"*32, "22"*32, "33"*32, proof)
        assert not b.verify("11"*32, "22"*32, "33"*32, b"bad")
