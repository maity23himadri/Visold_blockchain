"""Ensure the node orchestrator uses the port P2P actually bound."""
import json
from types import SimpleNamespace

from visold.kernel.config import Config
from visold.node import visold_node as node_module


class _FakeWallet:
    pub_hex = "ab" * 33
    address = "VSD_TEST_ADDRESS"


class _FakeStorage:
    def __init__(self, _path):
        self.meta = {}

    def set_meta(self, key, value):
        self.meta[key] = value


class _FakeBlockchain:
    def __init__(self, _storage):
        self._governance = object()
        self.layer2 = object()
        self._vvm_engine = None
        self._event_index = None

    def set_network(self, network):
        self.network = network


class _FakeStateEngine:
    def __init__(self, **_kwargs):
        pass

    def set_network(self, network):
        self.network = network


class _FakeNetwork:
    def __init__(self, _chain, _wallet, _storage, *, port, node_id):
        self.requested_port = port
        self.port = port + 11  # emulate Auto mode finding a different free port
        self.node_id = node_id

    def set_state_engine(self, _value):
        pass

    def set_sequencer(self, _value):
        pass

    def set_mining_engine(self, _value):
        pass


class _FakeRPCServer:
    def __init__(self, _node, port):
        self.rpc_port = port


def test_node_rpc_uses_actual_auto_selected_p2p_port(monkeypatch, tmp_path):
    # Config must load before VisoldNode chooses its default listen port.
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"port": 18338, "port_mode": "auto"}), encoding="utf-8")
    monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(Config, "_PORT_SETTINGS_INITIALIZED", False)
    monkeypatch.setattr(Config, "DEFAULT_PORT", 8338)
    monkeypatch.setattr(Config, "PORT_MODE", "auto")
    for env_name in ("VISOLD_PORT", "VISOLD_PORT_MODE", "VISOLD_PEERS"):
        monkeypatch.delenv(env_name, raising=False)
    # ensure_dirs populates these fields; restore them after this isolated test.
    for attr in (
        "DB_PATH", "PEERS_FILE", "WALLET_FILE", "KEYSTORE_FILE", "SIG_FILE",
        "KEY_FILE", "GENESIS_HASH_FILE", "TLS_CERT_FILE", "TLS_KEY_FILE",
        "LEVELDB_PATH", "ROCKSDB_PATH", "NODE_STATUS_FILE",
    ):
        monkeypatch.setattr(Config, attr, getattr(Config, attr))

    monkeypatch.setattr(node_module.SecurityGate, "verify_startup", staticmethod(lambda: (True, "")))
    monkeypatch.setattr(node_module.SecurityGate, "verify_genesis_hash", staticmethod(lambda *_a: (True, "")))
    monkeypatch.setattr(node_module.VisoldNode, "_load_or_create_wallet", lambda _self: _FakeWallet())
    monkeypatch.setattr(node_module, "Storage", _FakeStorage)
    monkeypatch.setattr(node_module, "Blockchain", _FakeBlockchain)
    monkeypatch.setattr(node_module.DifficultyEngine, "invalidate_cache", staticmethod(lambda **_kw: None))
    monkeypatch.setattr(node_module, "ConsensusEngine", lambda *_a, **_kw: SimpleNamespace(set_network=lambda _n: None))
    monkeypatch.setattr(node_module, "StateEngine", _FakeStateEngine)
    monkeypatch.setattr(node_module, "P2PNetwork", _FakeNetwork)
    # Constructors below are unrelated to the port wiring being tested.
    monkeypatch.setattr(node_module, "Sequencer", lambda **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "MiningEngine", lambda *_a, **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "RoleManager", lambda *_a, **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "IdentitySystem", lambda *_a, **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "RPCServer", _FakeRPCServer)
    monkeypatch.setattr(node_module, "SafetyInvariantChecker", lambda **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "PanicCircuitBreaker", lambda **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "PeerReputationManager", lambda *_a, **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "CapabilityRouter", lambda *_a, **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "StatePruner", lambda *_a, **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "SlashingEvidenceProtocol", lambda *_a, **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "RateDefectionAuditor", lambda *_a, **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "SentinelNode", lambda *_a, **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "SelfHealingSystem", lambda **_kw: SimpleNamespace())
    monkeypatch.setattr(node_module, "_patch_storage_for_shbs", lambda _storage: None)
    monkeypatch.setattr(node_module, "apply_hardened_overlay", lambda **_kw: None)
    monkeypatch.setattr(node_module, "install_supply_diagnostics", lambda *_a, **_kw: None)

    node = node_module.VisoldNode()

    assert node.network.requested_port == 18338
    assert node.port == 18349
    assert node.rpc.rpc_port == 18349 + Config.RPC_PORT_OFFSET
