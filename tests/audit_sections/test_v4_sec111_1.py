"""V4 regression tests for Section 111: Node Initialization, Shutdown and Multi-Instance Isolation."""

import json
import os
import sys
import threading
from types import SimpleNamespace

import pytest

from visold.chain.blockchain import Blockchain
from visold.cli import entry as cli_entry
from visold.kernel.config import Config
from visold.node.security_gate import SecurityGate
from visold.node.visold_node import VisoldNode
from visold.resilience import hardened_core as hc
from visold.storage.storage import Storage


def test_hardened_cb_singleton_isolated_across_instances(tmp_path):
    """Tripping _hc_panic_cb on instance 1 does not lock instance 2 in READ_ONLY mode."""
    orig_data_dir = Config.DATA_DIR
    cb = hc._hc_panic_cb
    with cb._mode_lock:
        orig_mode = cb._mode
        orig_subsystems = dict(cb._subsystems)
        orig_corr_count = cb._corruption_count
        orig_corr_ts = list(cb._corruption_timestamps)
        orig_ro_since = cb._read_only_since

    st1 = st2 = None
    try:
        dir1 = tmp_path / "node1"
        dir2 = tmp_path / "node2"
        dir1.mkdir()
        dir2.mkdir()

        Config.DATA_DIR = str(dir1)
        Config.ensure_dirs()
        st1 = Storage(Config.DB_PATH)
        bc1 = Blockchain(st1)
        hc.apply_hardened_overlay(bc1, st1, start_ntp_clock=False)

        Config.DATA_DIR = str(dir2)
        Config.ensure_dirs()
        st2 = Storage(Config.DB_PATH)
        bc2 = Blockchain(st2)
        hc.apply_hardened_overlay(bc2, st2, start_ntp_clock=False)

        # Healthy write on instance 2 succeeds before instance 1 trips.
        st2.credit_sat("VSD_addr_healthy_2", 1000)

        # Instance 1 encounters a corruption-level failure.
        cb.record_failure(
            "node1_apply_block",
            RuntimeError("simulated corruption on node 1"),
            corruption_level=True,
        )
        assert cb.mode == hc._HardenedSystemMode.READ_ONLY

        # Instance 2 (separate Storage/Blockchain/DATA_DIR) remains writable.
        st2.credit_sat("VSD_addr_healthy_2", 500)
        assert st2.get_balance_sat("VSD_addr_healthy_2") == 1500
    finally:
        with cb._mode_lock:
            cb._mode = orig_mode
            cb._subsystems = orig_subsystems
            cb._corruption_count = orig_corr_count
            cb._corruption_timestamps = orig_corr_ts
            cb._read_only_since = orig_ro_since
        if st1 is not None:
            st1.close()
        if st2 is not None:
            st2.close()
        Config.DATA_DIR = orig_data_dir
        Config.ensure_dirs()


def test_node_status_writer_stopped_and_isolated_on_stop(tmp_path):
    """node-status-writer thread stops cleanly on stop() and does not overwrite another instance's status file."""
    orig_data_dir = Config.DATA_DIR
    try:
        dir1 = tmp_path / "node1"
        dir2 = tmp_path / "node2"
        dir1.mkdir()
        dir2.mkdir()

        Config.DATA_DIR = str(dir1)
        Config.ensure_dirs()
        status1_path = Config.NODE_STATUS_FILE

        ice_ready = threading.Event()
        fake_ice = SimpleNamespace(_ready=ice_ready, _relay_port=18345)

        node1 = VisoldNode.__new__(VisoldNode)
        node1._shutdown_lock = threading.Lock()
        node1._shutdown_started = False
        node1._shutdown_complete = False
        node1._startup_timers = []
        node1.port = 18338
        node1.wallet = SimpleNamespace(address="VSD_test_wallet_1")
        node1.state_engine = SimpleNamespace(start=lambda: None, stop=lambda: None)
        node1.network = SimpleNamespace(
            start=lambda: None,
            stop=lambda: None,
            _ice=fake_ice,
            _running=False,
        )
        node1.rpc = SimpleNamespace(start=lambda: None, stop=lambda: None)
        node1.storage = SimpleNamespace(
            get_meta=lambda k, d=None: None,
            sum_all_balances_satoshi=lambda: 0,
            close=lambda: None,
        )
        node1.blockchain = SimpleNamespace(height=lambda: 0)
        node1.sentinel = SimpleNamespace(start=lambda: None, stop=lambda: None)
        node1.shbs = None
        node1.capability_router = SimpleNamespace(
            update_own_capabilities=lambda s: None,
            build_adv_message=lambda: None,
            own_capabilities=lambda: [],
        )
        node1.invariant_checker = SimpleNamespace(
            check_all=lambda full_scan=True: {
                "violations": [],
                "safety_ok": True,
                "liveness_ok": True,
                "consistency_ok": True,
            }
        )
        node1.circuit_breaker = SimpleNamespace(stop=lambda: None)
        node1.mining = SimpleNamespace(stop=lambda: None)
        node1.sequencer = None

        node1.start()
        assert os.path.exists(status1_path)

        # Switch global Config to Node 2's directory and write Node 2's status file.
        Config.DATA_DIR = str(dir2)
        Config.ensure_dirs()
        status2_path = Config.NODE_STATUS_FILE
        node2_status = {"p2p_port": 19338, "rpc_port": 19339, "relay_port": 19340}
        with open(status2_path, "w") as f:
            json.dump(node2_status, f)

        # Stop Node 1 before ICE finishes.
        node1.stop()

        # Now ICE finishes for the already-stopped Node 1.
        ice_ready.set()
        for t in threading.enumerate():
            if t.name == "node-status-writer":
                t.join(timeout=2.0)

        # Node 2's .node_status.json must remain untouched.
        with open(status2_path) as f:
            after = json.load(f)
        assert after["p2p_port"] == 19338
        assert after["relay_port"] == 19340
    finally:
        Config.DATA_DIR = orig_data_dir
        Config.ensure_dirs()


def test_cli_entry_main_passes_positional_port_arg(monkeypatch):
    """visold.cli.entry.main() passes sys.argv[1] port to CLI(port=...)."""
    observed = {}

    class DummyCLI:
        def __init__(self, *args, **kwargs):
            observed["init_args"] = args
            observed["init_kwargs"] = kwargs

        def run(self):
            observed["default_port_at_run"] = Config.DEFAULT_PORT

        def shutdown_node(self):
            pass

        def _leave_alt_screen(self):
            pass

    monkeypatch.setattr(sys, "argv", ["visold_vsd_.py", "9123"])
    monkeypatch.setattr(cli_entry, "CLI", DummyCLI)
    monkeypatch.setattr(cli_entry.signal, "signal", lambda *a, **kw: None)

    cli_entry.main()

    assert observed["init_kwargs"].get("port") == 9123


def test_visold_node_init_closes_storage_on_genesis_failure(tmp_path, monkeypatch):
    """VisoldNode.__init__ closes Storage before calling sys.exit(1) on genesis failure."""
    orig_data_dir = Config.DATA_DIR
    close_calls = []
    orig_close = Storage.close

    def tracked_close(self):
        close_calls.append(self)
        return orig_close(self)

    try:
        d = tmp_path / "genesis_leak"
        d.mkdir()
        Config.DATA_DIR = str(d)
        Config.ensure_dirs()

        monkeypatch.setattr(Storage, "close", tracked_close)
        monkeypatch.setattr(SecurityGate, "verify_startup", staticmethod(lambda: (True, "OK")))
        monkeypatch.setattr(
            SecurityGate,
            "verify_genesis_hash",
            staticmethod(lambda s, b: (False, "CRITICAL: Genesis block tampered!")),
        )

        with pytest.raises(SystemExit) as exc_info:
            VisoldNode(port=18448)

        assert exc_info.value.code == 1
        assert len(close_calls) >= 1
    finally:
        Config.DATA_DIR = orig_data_dir
        Config.ensure_dirs()
