import json
from pathlib import Path
import sys

import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.kernel.config import Config
from visold.node.visold_node import UserAccount
from visold.wallet.wallet import Wallet


def test_recover_uppercase_hex_secret_derives_matching_wallet(tmp_path, monkeypatch):
    """V4 fix: UserAccount.recover() normalizes uppercase hex to match register()."""
    data_dir = tmp_path / "node_data"
    data_dir.mkdir()
    monkeypatch.setattr(Config, "DATA_DIR", str(data_dir))
    monkeypatch.setattr(Config, "KEYSTORE_FILE", str(data_dir / "keystore.json"))
    monkeypatch.setattr(UserAccount, "ACCOUNTS_FILE", str(data_dir / "account.json"))

    ok, user_id, secret = UserAccount.register("alice")
    assert ok
    assert secret == secret.lower()
    with open(UserAccount.ACCOUNTS_FILE) as f:
        orig_addr = json.load(f)["wallet_addr"]

    (data_dir / "account.json").unlink()
    (data_dir / "keystore.json").unlink()

    ok_rec, msg_rec = UserAccount.recover(user_id, secret.upper())
    assert ok_rec, msg_rec

    with open(UserAccount.ACCOUNTS_FILE) as f:
        rec_addr = json.load(f)["wallet_addr"]

    assert rec_addr == orig_addr
    ok_login, _ = UserAccount.login(user_id, secret)
    assert ok_login


def test_load_keystore_and_from_dict_reject_mismatched_pub_hex(tmp_path):
    """V4 fix: Wallet.load_keystore() and Wallet.from_dict() reject mismatched pub_hex."""
    w1 = Wallet.generate()
    w2 = Wallet.generate()
    assert w1.address != w2.address

    ks_path = tmp_path / "keystore.json"
    w1.save_keystore(str(ks_path), "strong-pass")

    with open(ks_path) as f:
        ks = json.load(f)
    ks["pub_hex"] = w2.pub_hex
    ks["address"] = w2.address
    with open(ks_path, "w") as f:
        json.dump(ks, f)

    with pytest.raises(ValueError, match="does not match"):
        Wallet.load_keystore(str(ks_path), "strong-pass")

    d = w1.to_dict()
    d["pub_hex"] = w2.pub_hex
    with pytest.raises(ValueError, match="does not match"):
        Wallet.from_dict(d)
