"""Section 119 V4 Regression Tests: CLI, Terminal UI, Input Diagnostics, Network Port Management."""

import os
import pty
import threading

from visold.cli.handler import CLIHandler
from visold.cli.interactive import CLI
from visold.kernel.config import Config
from visold.wallet.wallet import Wallet


def test_cmd_send_l2_explicit_missing_keystore_fails_instead_of_fallback(tmp_path, monkeypatch):
    """
    CLIHandler.cmd_send_l2() fails when --keystore points to a nonexistent file
    rather than silently falling back to Config.DATA_DIR/wallet_cli.json.
    """
    monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))

    cli_wallet = Wallet.generate()
    cli_wallet_path = tmp_path / "wallet_cli.json"
    cli_wallet.save(str(cli_wallet_path))

    missing_keystore = tmp_path / "explicit_nonexistent_wallet.json"
    assert not missing_keystore.exists()

    recipient = Wallet.generate().address
    seen_senders = []

    def _fake_rpc_call(cls, rpc_port, method, params, admin=False, timeout=10.0):
        if method == "vsd_getBalance":
            seen_senders.append(params[0])
            return {"l2_nonce": 0, "l2_sat": 1_000_000_000}
        if method == "vsd_sendL2Transaction":
            return {"ok": True, "accepted_locally": True, "sequencer_msg": "ok", "gossiped": False}
        raise AssertionError(f"Unexpected RPC method: {method}")

    monkeypatch.setattr(CLIHandler, "_rpc_call", classmethod(_fake_rpc_call))

    rc = CLIHandler.run([
        "send-l2",
        "--keystore", str(missing_keystore),
        "--to", recipient,
        "--amount", "1.0",
    ])
    assert rc != 0
    assert seen_senders == []


def test_cmd_wallet_create_creates_keystore_with_0600_permissions(tmp_path, monkeypatch):
    """
    CLIHandler.cmd_wallet_create() creates the unencrypted keystore with 0o600
    permissions directly rather than writing with umask 0o644 first.
    """
    out_path = tmp_path / "plain_wallet.json"
    observed_modes = []
    orig_chmod = os.chmod

    def _spy_chmod(path, mode, *args, **kwargs):
        if os.path.abspath(path) == os.path.abspath(out_path):
            observed_modes.append(os.stat(path).st_mode & 0o777)
        return orig_chmod(path, mode, *args, **kwargs)

    old_umask = os.umask(0o022)
    try:
        monkeypatch.setattr(os, "chmod", _spy_chmod)
        rc = CLIHandler.run(["wallet", "create", "--out", str(out_path)])
        assert rc == 0
        assert observed_modes
        assert all(m == 0o600 for m in observed_modes)
        assert (os.stat(out_path).st_mode & 0o777) == 0o600
    finally:
        os.umask(old_umask)


def test_read_tty_line_split_crlf_swallows_trailing_lf():
    """
    CLI._read_tty_line() swallows a trailing LF arriving in the next read after CR
    instead of returning a phantom empty line.
    """
    cli = CLI.__new__(CLI)
    cli._input_pending_bytes = bytearray()
    cli._ui_lock = threading.Lock()
    cli._refresh_thread = None
    cli._refresh_stop = threading.Event()

    master_fd, slave_fd = pty.openpty()
    try:
        os.set_blocking(slave_fd, False)
        cli._prepare_raw_tty_input(slave_fd)
        os.write(master_fd, b"cmd1\r")
        first = cli._read_tty_line(slave_fd, echo_input=False)
        assert first == "cmd1"

        # Now the trailing LF of the CRLF pair arrives followed by the next command
        os.write(master_fd, b"\ncmd2\n")
        second = cli._read_tty_line(slave_fd, echo_input=False)
        assert second == "cmd2"
    finally:
        os.close(master_fd)
        os.close(slave_fd)
