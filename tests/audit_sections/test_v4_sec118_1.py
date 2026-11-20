"""Section 118 V4 Regression Tests: JSON-RPC Server Security, Input Validation, Access Boundaries."""

import http.client
import json
import os
import types

from visold.api.rpc_server import RPCServer
from visold.kernel.config import Config
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_minimal_node(tmp_path):
    st = Storage(str(tmp_path / "node.db"))
    w = Wallet.generate()
    # Seed 600 balances to exceed the 500-row cap
    with st._conn() as conn:
        for i in range(600):
            conn.execute(
                "INSERT OR REPLACE INTO balances(address, balance) VALUES(?, ?)",
                (f"VSDaddr{i:04d}", float(i + 1)),
            )
    node = types.SimpleNamespace(
        storage=st,
        wallet=w,
        blockchain=types.SimpleNamespace(
            height=lambda: 0,
            get_difficulty=lambda: 1,
            mempool=types.SimpleNamespace(
                size=lambda: 0,
                all_txs=lambda: [],
                _pending_nonces={},
                pending_outflow_sat=lambda _addr: (0, 0, 0),
            ),
            layer2=None,
            _governance=types.SimpleNamespace(get_active_version=lambda: 1),
            _proto_mgr=types.SimpleNamespace(current_version=lambda: 1),
        ),
        network=types.SimpleNamespace(
            active_peer_count=lambda: [],
            peer_list=lambda: [],
            broadcast_tx=lambda _tx: None,
        ),
        state_engine=types.SimpleNamespace(
            post_sync=lambda _evt, timeout=5.0: (True, "ok"),
        ),
    )
    return node


def _post_rpc(port: int, token: str, method: str, params: list):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    conn.request(
        "POST",
        "/",
        body=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    resp = conn.getresponse()
    data = json.loads(resp.read().decode("utf-8"))
    conn.close()
    return resp.status, data


def test_rpc_getbalances_negative_limit_rejected(tmp_path, monkeypatch):
    """getbalances rejects negative limit instead of bypassing the 500-row cap."""
    monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(RPCServer, "TOKEN_FILE", str(tmp_path / "rpc_token"))
    node = _make_minimal_node(tmp_path)
    srv = RPCServer(node, 0)
    srv.start()
    try:
        port = srv._server.server_address[1]
        status, data = _post_rpc(port, srv._token, "getbalances", [-1])
        assert status == 200
        assert "error" in data
        assert "limit" in data["error"]["message"].lower()
    finally:
        srv.stop()
        node.storage.close()


def test_rpc_token_file_uses_runtime_data_dir_and_creates_with_0600(tmp_path, monkeypatch):
    """
    RPCServer._load_or_create_token() resolves Config.DATA_DIR at runtime and
    creates the token file with 0o600 permissions before any write.
    """
    dir_b = tmp_path / "node_b"
    dir_b.mkdir()

    monkeypatch.setattr(Config, "DATA_DIR", str(dir_b))

    observed_modes = []
    orig_chmod = os.chmod

    def _spy_chmod(path, mode, *args, **kwargs):
        if os.path.abspath(path) == os.path.abspath(dir_b / "rpc_token"):
            observed_modes.append(os.stat(path).st_mode & 0o777)
        return orig_chmod(path, mode, *args, **kwargs)

    old_umask = os.umask(0o022)
    try:
        monkeypatch.setattr(os, "chmod", _spy_chmod)
        tok = RPCServer._load_or_create_token()
        assert tok
        assert (dir_b / "rpc_token").exists()
        assert observed_modes == [0o600]
        assert (os.stat(dir_b / "rpc_token").st_mode & 0o777) == 0o600
    finally:
        os.umask(old_umask)


def test_rpc_deploycontract_negative_gas_limit_rejected(tmp_path, monkeypatch):
    """deploycontract rejects negative gas_limit instead of bypassing spendability checks."""
    monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(RPCServer, "TOKEN_FILE", str(tmp_path / "rpc_token"))
    node = _make_minimal_node(tmp_path)
    assert node.storage.get_balance_sat(node.wallet.address) == 0

    srv = RPCServer(node, 0)
    srv.start()
    try:
        port = srv._server.server_address[1]
        status, data = _post_rpc(
            port,
            srv._token,
            "deploycontract",
            ["6000", -1000, 1.0, 0.0],
        )
        assert status == 200
        assert "error" in data
        assert "gas_limit" in data["error"]["message"].lower()
    finally:
        srv.stop()
        node.storage.close()
