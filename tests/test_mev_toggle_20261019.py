"""MEV protection is off by default and can be switched on and off on the node (terminal
menu item 27). The choice is stored on the node and survives a restart."""

from __future__ import annotations

import inspect
import os

from visold.chain.blockchain import Blockchain
from visold.cli.interactive import CLI
from visold.kernel.config import Config
from visold.mempool import mev
from visold.node.visold_node import VisoldNode
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def test_protection_is_off_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "MEV_PROTECTION_ENABLED", False)
    st = Storage(os.path.join(str(tmp_path), "default.db"))
    assert mev.protection_default(st) is False
    assert mev.protection_status(st)["enabled"] is False


def test_the_stored_switch_survives_a_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "MEV_PROTECTION_ENABLED", False)
    path = os.path.join(str(tmp_path), "switch.db")
    mev.set_protection_default(Storage(path), True)
    assert mev.protection_default(Storage(path)) is True
    assert mev.protection_status(Storage(path))["enabled"] is True
    mev.set_protection_default(Storage(path), False)
    assert mev.protection_default(Storage(path)) is False


def test_the_stored_choice_overrides_the_environment_starting_value(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "MEV_PROTECTION_ENABLED", True)
    st = Storage(os.path.join(str(tmp_path), "env.db"))
    assert mev.protection_default(st) is True        # no choice stored yet: starting value
    mev.set_protection_default(st, False)
    assert mev.protection_default(st) is False       # the stored choice wins
    mev.set_protection_default(st, True)
    assert mev.protection_default(st) is True


class _Net:
    def __init__(self):
        self.sent = []

    def broadcast_tx(self, tx):
        self.sent.append(tx.tx_id)

    def _gossip(self, *args, **kwargs):
        pass


class _Wrapper:
    def __init__(self, eng):
        self.eng = eng

    def post_sync(self, evt, timeout=None):
        return self.eng._handle_new_tx(evt.payload, evt.source_peer_id)


def _node_with_switch(tmp_path, name, on, monkeypatch):
    monkeypatch.setattr(Config, "MEV_PROTECTION_ENABLED", False)
    st = Storage(os.path.join(str(tmp_path), name))
    bc = Blockchain(st)
    wallet = Wallet.generate()
    st.credit(wallet.address, 10.0)
    eng = StateEngine.__new__(StateEngine)
    eng._storage = st
    eng._blockchain = bc
    eng._network = _Net()
    eng._mev_wallet = wallet
    node = VisoldNode.__new__(VisoldNode)
    node.storage = st
    node.blockchain = bc
    node.wallet = wallet
    node.identity = None
    node.state_engine = _Wrapper(eng)
    mev.set_protection_default(st, on)
    return node, st, bc


def test_sends_follow_the_stored_switch(tmp_path, monkeypatch):
    recipient = Wallet.generate().address
    node, st, bc = _node_with_switch(tmp_path, "on.db", True, monkeypatch)
    ok, msg = node.send_transaction(recipient, 1.0, "")      # no protected argument given
    assert ok, msg
    assert mev.load_flight(st) is not None                   # went out as a protected transfer
    node, st, bc = _node_with_switch(tmp_path, "off.db", False, monkeypatch)
    ok, msg = node.send_transaction(recipient, 1.0, "")
    assert ok, msg
    assert mev.load_flight(st) is None                       # went out as an ordinary transfer
    assert bc.mempool.size() == 1
    assert bc.mempool.get_top(1)[0].data == ""


class _Terminal:
    """Just enough of the terminal screen for the menu handler to run."""

    def __init__(self, storage, answer):
        self.node = type("Node", (), {"storage": storage})()
        self._answer = answer
        self.asked = []

    def _read_input(self, prompt="", **kwargs):
        self.asked.append(prompt)
        return self._answer


def test_menu_item_27_shows_the_state_and_switches_after_a_yes(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "MEV_PROTECTION_ENABLED", False)
    assert dict(CLI.MENU)["27"].startswith("MEV protection")
    assert '"27": self._toggle_mev_protection' in inspect.getsource(CLI)
    st = Storage(os.path.join(str(tmp_path), "menu.db"))
    term = _Terminal(st, "y")
    assert CLI._mev_menu_label(term) == "MEV protection: OFF"
    CLI._toggle_mev_protection(term)
    assert mev.protection_default(st) is True
    assert CLI._mev_menu_label(term) == "MEV protection: ON"
    assert "(y/n)" in term.asked[0] and "ON" in term.asked[0]


def test_menu_item_27_changes_nothing_without_a_yes(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "MEV_PROTECTION_ENABLED", False)
    st = Storage(os.path.join(str(tmp_path), "menu_no.db"))
    term = _Terminal(st, "n")
    CLI._toggle_mev_protection(term)
    assert mev.protection_default(st) is False


def test_the_menu_draws_the_privacy_section_with_the_current_state(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "MEV_PROTECTION_ENABLED", False)
    st = Storage(os.path.join(str(tmp_path), "render.db"))
    term = CLI.__new__(CLI)
    term.node = type("Node", (), {"storage": st})()
    term._layout = {}
    rendered = []
    CLI._print_menu(term, emit=rendered.append)
    text = "\n".join(rendered)
    assert "PRIVACY" in text
    assert "MEV protection: OFF" in text
    mev.set_protection_default(st, True)
    rendered.clear()
    CLI._print_menu(term, emit=rendered.append)
    text = "\n".join(rendered)
    assert "MEV protection: ON" in text and "MEV protection: OFF" not in text
