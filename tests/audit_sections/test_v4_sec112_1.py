"""Section 112 V4 Regression Tests: Security Gate, Startup Validation, Runtime Access Controls."""

import hashlib
import json
import os
import socket
import urllib.request
from types import SimpleNamespace

from visold.api.rpc_server import RPCServer
from visold.crypto.ecc import ecdsa_keygen, ecdsa_sign, pub_to_hex, sig_to_hex
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.node.security_gate import SecurityGate
from visold.resilience.hardened_core import (
    _HC_MIN_TIMESTAMP_UNIX,
    _make_hardened_apply_block,
)
from visold.storage.storage import Storage


def test_security_gate_partial_deletion_fails_closed(tmp_path, monkeypatch):
    """Deleting signature.sig while public_key.key remains fails closed instead of silently reinitializing."""
    monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(Config, "SIG_FILE", str(tmp_path / "signature.sig"))
    monkeypatch.setattr(Config, "KEY_FILE", str(tmp_path / "public_key.key"))
    monkeypatch.setattr(Config, "ensure_dirs", classmethod(lambda cls: None))

    ok, msg = SecurityGate.verify_startup()
    assert ok is True
    assert msg == "Node signature initialized"
    orig_pub = (tmp_path / "public_key.key").read_text().strip()

    # Simulate tampering: delete signature.sig while public_key.key remains
    os.remove(Config.SIG_FILE)
    ok2, msg2 = SecurityGate.verify_startup()

    assert ok2 is False
    assert (tmp_path / "public_key.key").read_text().strip() == orig_pub


def test_security_gate_rejects_mismatched_node_id_and_pubkey(tmp_path, monkeypatch):
    """verify_startup() verifies that node_id == sha256(pub_hex.encode())."""
    monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(Config, "SIG_FILE", str(tmp_path / "signature.sig"))
    monkeypatch.setattr(Config, "KEY_FILE", str(tmp_path / "public_key.key"))
    monkeypatch.setattr(Config, "ensure_dirs", classmethod(lambda cls: None))

    priv, pub = ecdsa_keygen()
    pub_hex = pub_to_hex(pub)
    forged_node_id = "deadbeef" * 8  # Does NOT equal sha256(pub_hex.encode())
    assert forged_node_id != sha256(pub_hex.encode())

    sig = ecdsa_sign(priv, hashlib.sha256(forged_node_id.encode()).digest())
    (tmp_path / "public_key.key").write_text(pub_hex)
    (tmp_path / "signature.sig").write_text(
        json.dumps({"node_id": forged_node_id, "sig": sig_to_hex(sig)})
    )

    ok, msg = SecurityGate.verify_startup()
    assert ok is False


def test_rpc_getbalances_and_listcontracts_rejects_negative_limit(tmp_path, monkeypatch):
    """Passing limit=-1 to getbalances/listcontracts is rejected rather than bypassing the 500-row cap."""
    db_path = str(tmp_path / "test.db")
    storage = Storage(db_path)

    conn = storage._conn()
    for i in range(505):
        conn.execute(
            "INSERT INTO balances (address, balance) VALUES (?, ?)",
            (f"VSD_TEST_{i:04d}", i + 1),
        )
        conn.execute(
            "INSERT INTO contract_accounts "
            "(address, code_hash, storage_root, creator, created_at, nonce, destroyed, contract_name) "
            "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
            (f"VSD_C_{i:04d}", "00" * 32, "00" * 32, "VSD_CREATOR", i, 0, f"c{i}"),
        )
    conn.commit()

    monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(RPCServer, "TOKEN_FILE", str(tmp_path / "rpc_token"))

    fake_node = SimpleNamespace(storage=storage)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    srv = RPCServer(fake_node, rpc_port=port)
    srv.start()
    try:
        def call_rpc(method, params):
            payload = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {srv._token}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode())

        res_bal = call_rpc("getbalances", [-1])
        assert "error" in res_bal
        assert "limit" in res_bal["error"]["message"].lower()

        res_ctr = call_rpc("listcontracts", [-1])
        assert "error" in res_ctr
        assert "limit" in res_ctr["error"]["message"].lower()
    finally:
        srv.stop()
        storage.close()


def test_rpc_server_token_file_respects_runtime_data_dir_change(tmp_path, monkeypatch):
    """RPCServer._load_or_create_token() uses runtime Config.DATA_DIR rather than a frozen import-time path."""
    new_dir = tmp_path / "custom_node"
    new_dir.mkdir()

    monkeypatch.setattr(Config, "DATA_DIR", str(new_dir))
    monkeypatch.setattr(Config, "SIG_FILE", str(new_dir / "signature.sig"))
    monkeypatch.setattr(Config, "KEY_FILE", str(new_dir / "public_key.key"))
    Config.ensure_dirs()

    tok = RPCServer._load_or_create_token()
    assert tok
    assert (new_dir / "rpc_token").exists()


def test_hardened_apply_block_enforces_timestamp_floor_and_rejects_none():
    """Gate 2 enforces _HC_MIN_TIMESTAMP_UNIX and returns (False, ...) cleanly on None timestamp or tx_id."""
    called = []

    def fake_apply(self_bc, block):
        called.append(block.index)
        return True, "OK"

    wrapped = _make_hardened_apply_block(fake_apply)

    class FakeStorage:
        def chain_height(self):
            return 0
        def get_balance_sat(self, addr):
            return 1000
        def compute_state_root(self):
            return ""

    bc = SimpleNamespace(storage=FakeStorage())

    # 1. Pre-floor timestamp (0 < _HC_MIN_TIMESTAMP_UNIX) is rejected.
    old_block = SimpleNamespace(index=1, timestamp=0, transactions=[])
    assert old_block.timestamp < _HC_MIN_TIMESTAMP_UNIX
    ok, msg = wrapped(bc, old_block)
    assert ok is False
    assert called == []

    # 2. None timestamp returns (False, ...) cleanly instead of raising TypeError.
    none_ts_block = SimpleNamespace(index=2, timestamp=None, transactions=[])
    ok2, msg2 = wrapped(bc, none_ts_block)
    assert ok2 is False

    # 3. None tx_id returns (False, ...) cleanly instead of raising TypeError.
    bad_tx = SimpleNamespace(sender="VSD_A", tx_id=None)
    none_txid_block = SimpleNamespace(index=3, timestamp=1_700_000_000, transactions=[bad_tx])
    ok3, msg3 = wrapped(bc, none_txid_block)
    assert ok3 is False
