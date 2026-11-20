import hashlib
import json
from pathlib import Path
import sys

import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.crypto.ecc import (
    ecdsa_keygen,
    ecdsa_verify,
    sig_from_hex,
)
from visold.wallet.wallet import Wallet


def test_ecdsa_verify_returns_false_on_malformed_sig():
    _, pub = ecdsa_keygen()
    msg_hash = hashlib.sha256(b"test-message").digest()

    assert ecdsa_verify(pub, msg_hash, None) is False  # type: ignore[arg-type]
    assert ecdsa_verify(pub, msg_hash, (1,)) is False  # type: ignore[arg-type]
    assert ecdsa_verify(pub, msg_hash, (1, 2, 3)) is False  # type: ignore[arg-type]
    assert ecdsa_verify(pub, msg_hash, ("not_an_int", "also_not_an_int")) is False  # type: ignore[arg-type]
    assert ecdsa_verify(pub, msg_hash, (None, 1)) is False  # type: ignore[arg-type]

    # sig_from_hex also rejects non-integer components with ValueError
    with pytest.raises(ValueError, match="integers"):
        sig_from_hex('["not_an_int", "also_not_an_int"]')
    with pytest.raises(ValueError, match="integers"):
        sig_from_hex("[null, 1]")


def test_wallet_load_keystore_rejects_mismatched_unauthenticated_pub_hex(tmp_path):
    w1 = Wallet.generate()
    w2 = Wallet.generate()
    ks_path = tmp_path / "wallet.ks.json"
    w1.save_keystore(str(ks_path), "strong-password")

    # Tamper with the unauthenticated plaintext pub_hex field in the keystore
    data = json.loads(ks_path.read_text())
    data["pub_hex"] = w2.pub_hex
    ks_path.write_text(json.dumps(data))

    with pytest.raises(ValueError, match="does not match"):
        Wallet.load_keystore(str(ks_path), "strong-password")
