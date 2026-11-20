import hashlib
import json
import os
import time

from visold.chain.blockchain import Blockchain
from visold.crypto.ecc import ecdsa_keygen, ecdsa_sign, pub_to_hex, sig_to_hex
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.node.security_gate import SecurityGate
from visold.resilience.hardened_core import (
    _HardenedSystemMode,
    _hc_panic_cb,
    apply_hardened_overlay,
)
from visold.storage.storage import Storage


def _reset_hardened_cb():
    with _hc_panic_cb._mode_lock:
        _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
        _hc_panic_cb._subsystems.clear()
        _hc_panic_cb._corruption_count = 0
        _hc_panic_cb._corruption_timestamps.clear()
        _hc_panic_cb._read_only_since = 0.0


def test_verify_genesis_hash_fails_when_genesis_block_missing(tmp_path):
    """
    V4 regression (Finding 1): SecurityGate.verify_genesis_hash() returns
    (False, reason) when genesis_hash is anchored in metadata but block 0 is missing.
    """
    db_path = str(tmp_path / "visold_test.db")
    storage = Storage(db_path)
    bc = Blockchain(storage)

    stored_hash = storage.get_meta("genesis_hash")
    assert stored_hash
    assert bc.get_block(0) is not None

    with storage._conn() as conn:
        conn.execute("DELETE FROM blocks WHERE idx = 0")
        conn.commit()

    assert bc.get_block(0) is None
    ok, msg = SecurityGate.verify_genesis_hash(storage, bc)
    assert ok is False
    assert msg


def test_verify_startup_enforces_node_id_pubkey_binding(tmp_path, monkeypatch):
    """
    V4 regression (Finding 2a): SecurityGate.verify_startup() rejects a
    node_id that does not match sha256(pub_hex.encode()).
    """
    monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
    Config.ensure_dirs()

    priv, pub = ecdsa_keygen()
    pub_hex = pub_to_hex(pub)
    spoofed_node_id = "f" * 64
    assert spoofed_node_id != sha256(pub_hex.encode())

    sig = ecdsa_sign(priv, hashlib.sha256(spoofed_node_id.encode()).digest())
    with open(Config.KEY_FILE, "w") as f:
        f.write(pub_hex)
    with open(Config.SIG_FILE, "w") as f:
        json.dump({"node_id": spoofed_node_id, "sig": sig_to_hex(sig)}, f)

    ok, msg = SecurityGate.verify_startup()
    assert ok is False
    assert msg


def test_verify_startup_detects_partial_file_deletion(tmp_path, monkeypatch):
    """
    V4 regression (Finding 2b): If SIG_FILE is deleted while KEY_FILE remains,
    verify_startup() detects tampering and returns (False, reason).
    """
    monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
    Config.ensure_dirs()

    ok1, _ = SecurityGate.verify_startup()
    assert ok1 is True

    os.remove(Config.SIG_FILE)
    assert os.path.exists(Config.KEY_FILE)
    assert not os.path.exists(Config.SIG_FILE)

    ok2, msg2 = SecurityGate.verify_startup()
    assert ok2 is False
    assert msg2


def test_hardened_apply_block_gate5_rolls_back_on_conservation_violation(tmp_path, monkeypatch):
    """
    V4 regression (Finding 3): When Gate 5 (assert_conservation) fires in
    hardened_apply_block(), it rolls back the committed block and balance mutation.
    """
    _reset_hardened_cb()
    try:
        db_path = str(tmp_path / "hardened_test.db")
        storage = Storage(db_path)
        bc = Blockchain(storage)

        class _DummyCommitChain(Blockchain):
            def apply_block(self, block, *, defer_finality=False):
                with self.storage._conn() as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO blocks (idx, block_hash, data_json) VALUES (?, ?, ?)",
                        (block.index, block.block_hash, json.dumps(block.to_dict())),
                    )
                    conn.commit()
                self.storage.credit_sat("VSD_UNISSUED_TEST_ADDR", 123456)
                return True, "OK"

        dummy_bc = _DummyCommitChain(storage)
        apply_hardened_overlay(dummy_bc, storage_instance=storage, start_ntp_clock=False)

        cb = Transaction.coinbase("VSD_MINER_ADDR", 50.0, block_height=100)
        blk = Block(
            index=100,
            prev_hash="0" * 64,
            timestamp=int(time.time()),
            transactions=[cb],
            difficulty=1.0,
            miner_address="VSD_MINER_ADDR",
        )
        ok, msg = dummy_bc.apply_block(blk)
        assert ok is False
        assert "CONSERVATION VIOLATION" in msg
        assert _hc_panic_cb.mode == _HardenedSystemMode.READ_ONLY
        with storage._conn() as conn:
            row = conn.execute("SELECT idx FROM blocks WHERE idx = 100").fetchone()
        assert row is None
    finally:
        _reset_hardened_cb()
