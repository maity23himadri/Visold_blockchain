"""V4 regression tests for Audit Section 002: Config Parsing & Startup Identity."""

import json
import os
import tempfile

import pytest

from visold.kernel.config import Config
from visold.node.security_gate import SecurityGate


@pytest.fixture
def isolated_config():
    """Snapshot and restore Config class attributes mutated by ensure_dirs()."""
    saved = {
        "DATA_DIR": Config.DATA_DIR,
        "DEFAULT_PORT": Config.DEFAULT_PORT,
        "PORT_MODE": Config.PORT_MODE,
        "_PORT_SETTINGS_INITIALIZED": Config._PORT_SETTINGS_INITIALIZED,
        "MAX_PEERS": Config.MAX_PEERS,
        "SEED_NODE_MODE": Config.SEED_NODE_MODE,
        "LOG_FORMAT": Config.LOG_FORMAT,
        "DNS_SEEDS": list(Config.DNS_SEEDS),
        "BIND_ADDRESS": Config.BIND_ADDRESS,
        "LOOPBACK_ADDRESS": Config.LOOPBACK_ADDRESS,
        "TOPOLOGY_TARGET_PEERS": Config.TOPOLOGY_TARGET_PEERS,
        "NODE_CAPABILITIES": list(Config.NODE_CAPABILITIES),
        "SEED_PEERS": list(Config.SEED_PEERS),
        "DB_PATH": Config.DB_PATH,
        "SIG_FILE": Config.SIG_FILE,
        "KEY_FILE": Config.KEY_FILE,
    }
    try:
        yield
    finally:
        for k, v in saved.items():
            setattr(Config, k, v)


def test_malformed_port_in_config_json_preserves_other_valid_settings(isolated_config):
    """A non-integer 'port' in config.json is ignored without discarding subsequent valid settings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        Config.DATA_DIR = tmpdir
        Config._PORT_SETTINGS_INITIALIZED = False
        Config.MAX_PEERS = 30
        Config.TOPOLOGY_TARGET_PEERS = 3
        Config.LOG_FORMAT = "text"

        cfg_path = os.path.join(tmpdir, "config.json")
        with open(cfg_path, "w") as f:
            json.dump(
                {
                    "port": "not-an-int",
                    "max_peers": 50,
                    "topology_target_peers": 8,
                    "log_format": "json",
                },
                f,
            )

        Config.ensure_dirs()

        assert Config.MAX_PEERS == 50
        assert Config.TOPOLOGY_TARGET_PEERS == 8
        assert Config.LOG_FORMAT == "json"


def test_null_bind_and_loopback_ignored_without_none_coercion(isolated_config):
    """null bind_address/loopback in config.json are ignored instead of being coerced to 'None'."""
    with tempfile.TemporaryDirectory() as tmpdir:
        Config.DATA_DIR = tmpdir
        Config._PORT_SETTINGS_INITIALIZED = False

        cfg_path = os.path.join(tmpdir, "config.json")
        with open(cfg_path, "w") as f:
            json.dump(
                {
                    "bind_address": None,
                    "loopback": None,
                },
                f,
            )

        Config.ensure_dirs()

        assert Config.BIND_ADDRESS != "None"
        assert Config.LOOPBACK_ADDRESS != "None"


def test_verify_startup_refuses_to_regenerate_identity_when_only_sig_missing(isolated_config):
    """Deleting only signature.sig causes SecurityGate.verify_startup() to fail without overwriting public_key.key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        Config.DATA_DIR = tmpdir
        Config._PORT_SETTINGS_INITIALIZED = False

        ok1, _ = SecurityGate.verify_startup()
        assert ok1 is True
        with open(Config.KEY_FILE) as f:
            original_pub = f.read().strip()

        os.remove(Config.SIG_FILE)
        assert os.path.exists(Config.KEY_FILE)
        assert not os.path.exists(Config.SIG_FILE)

        ok2, _msg2 = SecurityGate.verify_startup()
        with open(Config.KEY_FILE) as f:
            new_pub = f.read().strip()

        assert ok2 is False
        assert new_pub == original_pub
