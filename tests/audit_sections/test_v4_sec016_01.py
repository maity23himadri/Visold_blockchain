import hashlib
from pathlib import Path
import sys

import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.crypto.ecc import ECPoint, ecdsa_verify
from visold.crypto.mnemonic import _MNEMONIC_WORDS, mnemonic_from_priv, priv_from_mnemonic
from visold.wallet.wallet import Wallet


def _make_raw_mnemonic(val: int) -> str:
    data = val.to_bytes(32, "big")
    checksum = hashlib.sha256(data).digest()[0]
    bits = int.from_bytes(data + bytes([checksum]), "big")
    words = []
    for _ in range(24):
        words.append(_MNEMONIC_WORDS[bits & 0x7FF])
        bits >>= 11
    return " ".join(reversed(words))


class TestSection16FixedRegressions:
    def test_zero_and_order_n_priv_rejected(self):
        """V4 fix for BUG-16-01 (Part A): mnemonic_from_priv, priv_from_mnemonic,
        and Wallet.from_mnemonic reject 0 and ECPoint.N with ValueError."""
        for bad_priv in (0, ECPoint.N):
            with pytest.raises(ValueError):
                mnemonic_from_priv(bad_priv)

            phrase = _make_raw_mnemonic(bad_priv)
            with pytest.raises(ValueError):
                priv_from_mnemonic(phrase)

            with pytest.raises(ValueError):
                Wallet.from_mnemonic(phrase)

    def test_out_of_range_priv_gt_n_rejected(self):
        """V4 fix for BUG-16-01 (Part B): scalars >= ECPoint.N are rejected."""
        out_of_range_priv = ECPoint.N + 1

        with pytest.raises(ValueError):
            mnemonic_from_priv(out_of_range_priv)

        phrase = _make_raw_mnemonic(out_of_range_priv)
        with pytest.raises(ValueError):
            priv_from_mnemonic(phrase)

        with pytest.raises(ValueError):
            Wallet.from_mnemonic(phrase)

    def test_valid_wallet_mnemonic_roundtrip_control(self):
        """Control: valid Wallet.generate() round-trips and signs cleanly."""
        w1 = Wallet.generate()
        phrase = w1.mnemonic
        w2 = Wallet.from_mnemonic(phrase)
        assert w2.priv == w1.priv
        assert w2.address == w1.address
        sig = w2.sign(b"hello visold")
        assert ecdsa_verify(w2.pub, hashlib.sha256(b"hello visold").digest(), sig)
