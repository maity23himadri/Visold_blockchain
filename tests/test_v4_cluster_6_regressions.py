"""Positive V4 regression tests for Visold Cluster 6.

Converted from test_cluster_6_adversarial.py to assert the fixed V4 behavior
across node, resilience, api, cli, testing, and selfhealing modules.

All tests run in isolated temporary directories and restore any modified
module/Config state so they are safe and repeatable.
"""

import hashlib
import http.client
import json
import os
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from visold.api.rpc_server import RPCServer
from visold.cli.handler import CLIHandler
from visold.crypto.ecc import ecdsa_keygen, ecdsa_sign, pub_to_hex, sig_to_hex
from visold.kernel.config import Config
from visold.node.security_gate import SecurityGate
from visold.node.visold_node import VisoldNode
from visold.resilience.hardened_core import (
    TimestampAnomalyError,
    _HardenedCBSingleton,
    _HardenedSystemMode,
    _hc_panic_cb,
    _make_hardened_apply_block,
    SystemInvariantGate,
)
from visold.resilience.safety_invariants import SafetyInvariantChecker
from visold.selfhealing.detection import AnomalyDetectionEngine, StatisticalDetector
from visold.selfhealing.hardening.patches import (
    _dry_run_preview,
    apply_hardening_patch,
)
from visold.selfhealing.model import AnomalyKind, AnomalyReport
from visold.selfhealing.monitors import MonitorBus, TransactionMonitor
from visold.selfhealing.orchestrator import SelfHealingSystem
from visold.storage.storage import Storage
from visold.testing.hardened_verification import HardenedVerificationSuite
from visold.wallet.wallet import Wallet


@pytest.fixture
def isolated_data_dir(tmp_path):
    """Temporarily point Config.DATA_DIR and derived paths to a fresh tmpdir."""
    orig = {
        "DATA_DIR": Config.DATA_DIR,
        "DB_PATH": Config.DB_PATH,
        "WALLET_FILE": Config.WALLET_FILE,
        "KEYSTORE_FILE": Config.KEYSTORE_FILE,
        "SIG_FILE": Config.SIG_FILE,
        "KEY_FILE": Config.KEY_FILE,
        "NODE_STATUS_FILE": Config.NODE_STATUS_FILE,
    }
    dd = str(tmp_path)
    Config.DATA_DIR = dd
    Config.ensure_dirs()
    try:
        yield dd
    finally:
        for k, v in orig.items():
            setattr(Config, k, v)


# ─────────────────────────────────────────────────────────────────────────────
# NEW VULNERABILITY REGRESSION TESTS (FIXED IN V4)
# ─────────────────────────────────────────────────────────────────────────────


def test_new_01_rpc_privileged_methods_require_admin_check(tmp_path):
    """NEW-01: Privileged RPC methods (resetcircuitbreaker, shbs_unfreeze,
    sendtransaction, vsd_triggerManualRollup) require X-Admin-Token when
    rpc_admin_token is configured, and succeed when X-Admin-Token is supplied."""
    orig_dd = Config.DATA_DIR
    orig_tok = RPCServer.TOKEN_FILE
    Config.DATA_DIR = str(tmp_path)
    Config.ensure_dirs()
    admin_file = os.path.join(str(tmp_path), "rpc_admin_token")
    with open(admin_file, "w") as f:
        f.write("super-secret-admin-token")
    RPCServer.TOKEN_FILE = os.path.join(str(tmp_path), "rpc_token")

    node = MagicMock()
    node.circuit_breaker.reset.return_value = (True, "Circuit breaker CLOSED")
    node.shbs.unfreeze.return_value = (True, "Unfrozen: VSDattacker")
    node.send_transaction.return_value = (True, "tx_sent")
    node.sequencer = None

    srv = RPCServer(node, rpc_port=0)
    srv.start()
    port = srv._server.server_address[1]
    try:
        def _post(method, params, admin_token=None):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {srv._token}",
            }
            if admin_token is not None:
                headers["X-Admin-Token"] = admin_token
            conn.request("POST", "/", body=body, headers=headers)
            resp = conn.getresponse()
            data = json.loads(resp.read().decode())
            conn.close()
            return data

        # Standard Bearer token without X-Admin-Token must be rejected:
        for method, params in (
            ("resetcircuitbreaker", []),
            ("shbs_unfreeze", ["VSDattacker"]),
            ("sendtransaction", ["VSDattacker", 10.0]),
            ("vsd_triggerManualRollup", []),
        ):
            r = _post(method, params)
            assert "error" in r
            assert "admin token required" in r["error"]["message"].lower()

        node.circuit_breaker.reset.assert_not_called()
        node.shbs.unfreeze.assert_not_called()
        node.send_transaction.assert_not_called()

        # With valid X-Admin-Token, privileged ops succeed:
        r_cb = _post("resetcircuitbreaker", [], admin_token="super-secret-admin-token")
        assert r_cb["result"]["ok"] is True
        node.circuit_breaker.reset.assert_called_once()

        r_uf = _post("shbs_unfreeze", ["VSDattacker"], admin_token="super-secret-admin-token")
        assert r_uf["result"]["ok"] is True
        node.shbs.unfreeze.assert_called_once_with("VSDattacker")

        r_tx = _post("sendtransaction", ["VSDattacker", 10.0], admin_token="super-secret-admin-token")
        assert r_tx["result"]["ok"] is True
    finally:
        srv.stop()
        RPCServer.TOKEN_FILE = orig_tok
        Config.DATA_DIR = orig_dd


def test_new_02_hardened_apply_block_state_root_mismatch_rolls_back():
    """NEW-02: hardened_apply_block Gate 4 detects StateRootMismatch after
    original_apply_block and rolls back the committed block."""
    orig_mode = _hc_panic_cb._mode
    orig_subs = dict(_hc_panic_cb._subsystems)
    orig_ts = list(_hc_panic_cb._corruption_timestamps)
    orig_cnt = _hc_panic_cb._corruption_count
    try:
        _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
        _hc_panic_cb._subsystems.clear()
        _hc_panic_cb._corruption_timestamps.clear()
        _hc_panic_cb._corruption_count = 0

        committed = {"height": 0, "rolled_back": False}

        def fake_original_apply(self_bc, blk):
            committed["height"] = blk.index
            return True, "applied"

        bc = MagicMock()
        bc.storage.chain_height.return_value = 0
        bc.storage.compute_state_root.return_value = "b" * 64
        bc.storage.get_balance_sat.return_value = 1000
        bc.rollback = MagicMock(side_effect=lambda h: committed.__setitem__("rolled_back", True))

        blk = SimpleNamespace(
            index=1,
            timestamp=int(time.time()),
            transactions=[],
            state_root="a" * 64,  # mismatches computed "b"*64
        )

        hardened = _make_hardened_apply_block(fake_original_apply)
        ok, msg = hardened(bc, blk)

        assert ok is False
        assert "STATE ROOT MISMATCH" in msg
        assert committed["height"] == 1
        assert committed["rolled_back"] is True
        bc.rollback.assert_called_once_with(0)
    finally:
        _hc_panic_cb._mode = orig_mode
        _hc_panic_cb._subsystems = orig_subs
        _hc_panic_cb._corruption_timestamps = orig_ts
        _hc_panic_cb._corruption_count = orig_cnt


def test_new_03_rpc_non_dict_json_and_negative_simulatecall_gas(tmp_path):
    """NEW-03: do_POST returns -32600 Invalid Request on non-dict JSON payloads,
    and simulatecall rejects negative gas_limit values."""
    orig_dd = Config.DATA_DIR
    orig_tok = RPCServer.TOKEN_FILE
    Config.DATA_DIR = str(tmp_path)
    Config.ensure_dirs()
    RPCServer.TOKEN_FILE = os.path.join(str(tmp_path), "rpc_token")

    node = MagicMock()
    node.storage.get_contract.return_value = {"address": "VSDc1", "code_hash": "00" * 32}
    node.wallet.address = "VSDcaller"
    node.blockchain.latest_block.return_value = None

    srv = RPCServer(node, rpc_port=0)
    srv.start()
    port = srv._server.server_address[1]
    try:
        def _post_raw(raw_body):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request(
                "POST",
                "/",
                body=raw_body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {srv._token}",
                },
            )
            resp = conn.getresponse()
            data = json.loads(resp.read().decode())
            conn.close()
            return data

        data_arr = _post_raw("[1, 2, 3]")
        assert data_arr["error"]["code"] == -32600
        assert "Invalid Request" in data_arr["error"]["message"]

        data_gas = _post_raw(json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "simulatecall",
            "params": ["VSDc1", "", -100],
        }))
        assert "error" in data_gas
        assert "gas_limit" in data_gas["error"]["message"]
    finally:
        srv.stop()
        RPCServer.TOKEN_FILE = orig_tok
        Config.DATA_DIR = orig_dd


def test_new_04_machine_secret_created_atomically_with_0600(isolated_data_dir):
    """NEW-04: VisoldNode._get_or_create_machine_secret creates .node_secret
    atomically with 0o600 permissions even under a permissive umask."""
    old_umask = os.umask(0o022)
    try:
        secret = VisoldNode._get_or_create_machine_secret()
        assert len(secret) == 64
        secret_path = os.path.join(isolated_data_dir, ".node_secret")
        assert os.path.exists(secret_path)
        mode = os.stat(secret_path).st_mode & 0o777
        assert mode == 0o600
    finally:
        os.umask(old_umask)


def test_new_05_hardened_cb_writes_flag_to_config_data_dir(tmp_path, monkeypatch):
    """NEW-05: _HardenedCBSingleton._transition writes PANIC_*.flag to
    Config.DATA_DIR rather than hardcoded ~/.visold."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    custom_data_dir = tmp_path / "custom_node_data"
    custom_data_dir.mkdir()

    monkeypatch.setenv("HOME", str(fake_home))
    orig_dd = Config.DATA_DIR
    Config.DATA_DIR = str(custom_data_dir)

    orig_mode = _hc_panic_cb._mode
    orig_subs = dict(_hc_panic_cb._subsystems)
    try:
        _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
        _hc_panic_cb._transition(_HardenedSystemMode.READ_ONLY, "test_isolation")
        assert (custom_data_dir / "PANIC_READ_ONLY.flag").exists()
        assert not (fake_home / ".visold" / "PANIC_READ_ONLY.flag").exists()
    finally:
        _hc_panic_cb._mode = orig_mode
        _hc_panic_cb._subsystems = orig_subs
        Config.DATA_DIR = orig_dd


def test_new_06_verify_genesis_hash_fails_closed_when_block0_missing():
    """NEW-06: SecurityGate.verify_genesis_hash fails closed when genesis_hash
    is pinned in meta and blockchain.get_block(0) returns None."""
    storage = MagicMock()
    storage.get_meta.return_value = "ab" * 32
    bc = MagicMock()
    bc.get_block.return_value = None

    ok, msg = SecurityGate.verify_genesis_hash(storage, bc)
    assert ok is False
    assert "missing" in msg.lower()


# ─────────────────────────────────────────────────────────────────────────────
# HISTORICAL FINDINGS REGRESSION TESTS (SECTIONS 111-120, FIXED IN V4)
# ─────────────────────────────────────────────────────────────────────────────


def test_hist_111_hardened_cb_singleton_shared():
    """Sec 111 F1: _HardenedCBSingleton returns the same instance across calls."""
    cb1 = _HardenedCBSingleton()
    cb2 = _HardenedCBSingleton()
    assert cb1 is cb2 is _hc_panic_cb


def test_hist_112_security_gate_rejects_partial_deletion_and_unbound_node_id(isolated_data_dir):
    """Sec 112 F1: Deleting one of SIG_FILE/KEY_FILE fails closed, and
    swapping node_id without matching sha256(pub_hex) is rejected."""
    ok1, msg1 = SecurityGate.verify_startup()
    assert ok1 is True
    assert "initialized" in msg1.lower()

    os.remove(Config.SIG_FILE)
    ok2, msg2 = SecurityGate.verify_startup()
    assert ok2 is False
    assert "partial identity" in msg2.lower()

    # Forge a valid signature over a mismatched node_id using a fresh keypair
    priv, pub = ecdsa_keygen()
    pub_hex = pub_to_hex(pub)
    fake_id = "tampered_node_id"
    sig = ecdsa_sign(priv, hashlib.sha256(fake_id.encode()).digest())
    with open(Config.KEY_FILE, "w") as f:
        f.write(pub_hex)
    with open(Config.SIG_FILE, "w") as f:
        json.dump({"node_id": fake_id, "sig": sig_to_hex(sig)}, f)
    ok3, msg3 = SecurityGate.verify_startup()
    assert ok3 is False
    assert "does not match" in msg3.lower()


def test_hist_113_tx_monitor_handles_block_obj_and_detects_100pct_drain():
    """Sec 113 F1 & F2: _get_prev_ts handles Block objects and Rule 3 detects
    100% account drains when post-block balance is 0."""
    bus = MonitorBus()
    storage = MagicMock()
    storage.get_block.return_value = SimpleNamespace(timestamp=1000.0)
    storage.get_balance.return_value = 0.0  # Post-block balance after 100% drain
    storage.mempool_size.return_value = 0

    mon = TransactionMonitor(bus, storage, MagicMock())
    blk = SimpleNamespace(
        index=5,
        timestamp=1001.0,
        transactions=[SimpleNamespace(sender="VSDvictim", amount=500.0, gas_limit=21000, tx_id="aa" * 32)],
    )
    anomalies = mon.observe_block(blk)
    assert any(a.kind == AnomalyKind.FUND_DRAIN for a in anomalies)


def test_hist_114_dedup_preserves_source_and_stat_detect_ignores_negative_z():
    """Sec 114 F1 & F3: StatisticalDetector ignores negative z-score drops, and
    _dedup includes source in the key so distinct sources are not collapsed."""
    bus = MonitorBus()
    buf = bus.register_buffer("tps", 300)
    tracker = bus.get_baseline("tps")
    for i in range(210):
        val = 100.0 + (i % 3)
        buf.push(val)
        tracker.update(val)
    buf.push(0.0)  # sharp drop -> negative z-score (should not fire TPS_SPIKE)

    stat = StatisticalDetector(bus)
    reports = stat.detect(height=211)
    assert reports == []

    ade = AnomalyDetectionEngine(
        bus,
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        stat,
    )
    r_rule = AnomalyReport(
        kind=AnomalyKind.TPS_SPIKE,
        detected_at=time.time(),
        description="rule",
        evidence={},
        source="rule",
        confidence=0.95,
    )
    r_stat = AnomalyReport(
        kind=AnomalyKind.TPS_SPIKE,
        detected_at=time.time(),
        description="stat",
        evidence={},
        source="stat",
        confidence=0.90,
    )
    deduped = ade._dedup([r_rule, r_stat])
    assert len(deduped) == 2
    assert {r.source for r in deduped} == {"rule", "stat"}


def test_hist_115_hardened_decide_keeps_double_sign_critical():
    """Sec 115 F1: Hardened DecisionEngine keeps DOUBLE_SIGN at CRITICAL
    with slash_validator after multi-block confirmation."""
    storage = MagicMock()
    storage.get_validators.return_value = [{"address": f"VSDv{i}"} for i in range(4)]
    storage.get_total_supply.return_value = 100000.0
    storage.get_vvm_receipts_for_block.return_value = []

    bc = MagicMock()
    bc.height.return_value = 10
    bc.current_tps.return_value = 50.0
    se = MagicMock()
    p2p = MagicMock()

    shbs = SelfHealingSystem(bc, storage, se, p2p)
    apply_hardening_patch(shbs)

    decisions = []
    for h in (10, 11, 12):
        rep = AnomalyReport(
            kind=AnomalyKind.DOUBLE_SIGN,
            detected_at=time.time(),
            description="double sign",
            evidence={"addr": "VSDv0", "height": h},
            source="rule",
            confidence=1.0,
            affected_addr="VSDv0",
            block_height=h,
        )
        decisions.append(shbs.decision_eng.decide(rep, h))

    assert decisions[-1].action_stage == "CRITICAL"
    assert "slash_validator" in decisions[-1].action_tags


def test_hist_116_dry_run_preview_handles_block_object():
    """Sec 116 F1: _dry_run_preview handles Block objects returned by get_block()."""
    executor = MagicMock()
    executor._blockchain.height.return_value = 2
    executor._storage.get_block.return_value = SimpleNamespace(index=2, transactions=[])

    preview = _dry_run_preview(executor, target_height=1, flagged=set())
    assert preview.preview_ok is True
    assert preview.reason == "ok"


def test_hist_117_safety_invariant_detects_conflicting_finality_and_timestamp_nan():
    """Sec 117 F1 & F2: assert_timestamp_valid raises TimestampAnomalyError on NaN,
    and _check_safety detects conflicting finalized blocks at the same height."""
    with pytest.raises(TimestampAnomalyError):
        SystemInvariantGate.assert_timestamp_valid(float("nan"), "test")

    storage = MagicMock()
    blk0 = SimpleNamespace(index=0, block_hash="0" * 64, prev_hash="", finalized=True)
    blk1a = SimpleNamespace(index=1, block_hash="a" * 64, prev_hash="0" * 64, finalized=True)
    blk1b = SimpleNamespace(index=1, block_hash="b" * 64, prev_hash="0" * 64, finalized=True)
    storage.get_block.side_effect = lambda idx: blk0 if idx == 0 else blk1a
    storage.get_blocks_at_height.side_effect = lambda idx: [blk0] if idx == 0 else [blk1a, blk1b]

    bc = MagicMock()
    bc.height.return_value = 1
    net = MagicMock()
    net.active_peer_count.return_value = []
    checker = SafetyInvariantChecker(storage, bc, net)
    violations = []
    assert checker._check_safety(violations, full_scan=True) is False
    assert any("conflicting finality" in v.lower() for v in violations)


def test_hist_118_rpc_rejects_negative_limit_and_caps_getbalances(tmp_path):
    """Sec 118 F1 & F3: getbalances(-1) is rejected and positive limits are
    capped at 500 rows."""
    orig_dd = Config.DATA_DIR
    orig_tok = RPCServer.TOKEN_FILE
    Config.DATA_DIR = str(tmp_path)
    Config.ensure_dirs()
    RPCServer.TOKEN_FILE = os.path.join(str(tmp_path), "rpc_token")

    st = Storage(str(tmp_path / "test.db"))
    with st._sqlite_api_lock:
        c = st._conn()
        for i in range(510):
            c.execute("INSERT INTO balances (address, balance) VALUES (?, ?)", (f"VSD{i:04d}", i))
        c.commit()

    node = MagicMock()
    node.storage = st
    srv = RPCServer(node, rpc_port=0)
    srv.start()
    port = srv._server.server_address[1]
    try:
        def _post(params):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request(
                "POST",
                "/",
                body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getbalances", "params": params}),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {srv._token}"},
            )
            data = json.loads(conn.getresponse().read().decode())
            conn.close()
            return data

        r_neg = _post([-1])
        assert "error" in r_neg
        assert "limit" in r_neg["error"]["message"].lower()

        r_cap = _post([1000])
        assert len(r_cap["result"]) == 500
    finally:
        srv.stop()
        st.close()
        RPCServer.TOKEN_FILE = orig_tok
        Config.DATA_DIR = orig_dd


def test_hist_119_cmd_send_l2_rejects_missing_keystore(isolated_data_dir, capsys):
    """Sec 119 F1: cmd_send_l2 fails with non-zero exit code when an explicit
    --keystore path does not exist, without falling back to wallet_cli.json."""
    w = Wallet.generate()
    cli_path = os.path.join(isolated_data_dir, "wallet_cli.json")
    w.save(cli_path)

    args = SimpleNamespace(
        keystore=os.path.join(isolated_data_dir, "nonexistent_wallet.json"),
        password=None,
        to="VSDrecipient123456",
        amount="1.0",
        rpc_port=19999,
    )
    rc = CLIHandler.cmd_send_l2(args)
    assert rc == 2
    err = capsys.readouterr().err
    assert "keystore not found" in err.lower()


def test_hist_120_hardened_verification_clears_corruption_timestamps():
    """Sec 120 F1: HardenedVerificationSuite.run() clears
    _hc_panic_cb._corruption_timestamps so a single subsequent corruption event
    only transitions to READ_ONLY rather than immediate SAFE_SHUTDOWN."""
    orig_mode = _hc_panic_cb._mode
    orig_subs = dict(_hc_panic_cb._subsystems)
    orig_ts = list(_hc_panic_cb._corruption_timestamps)
    orig_cnt = _hc_panic_cb._corruption_count
    try:
        _hc_panic_cb._corruption_timestamps.clear()
        suite = HardenedVerificationSuite()
        assert suite.run() is True
        assert len(_hc_panic_cb._corruption_timestamps) == 0

        _hc_panic_cb.record_failure("post_verify", RuntimeError("single_fault"), corruption_level=True)
        assert _hc_panic_cb.mode == _HardenedSystemMode.READ_ONLY
    finally:
        _hc_panic_cb._mode = orig_mode
        _hc_panic_cb._subsystems = orig_subs
        _hc_panic_cb._corruption_timestamps = orig_ts
        _hc_panic_cb._corruption_count = orig_cnt
