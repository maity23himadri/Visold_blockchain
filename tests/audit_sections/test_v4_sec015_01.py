"""V4 regression tests for VISOLD Section 15: Base58 Encoding, Decoding and Address Integrity."""

import hashlib
from pathlib import Path
import sys
import time

import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.crypto.base58 import B58_ALPHABET, b58decode, b58encode
from visold.crypto.ecc import ecdsa_keygen, pub_to_address, pub_to_bytes
from visold.ledger.addressing import (
    is_canonical_contract_address,
    is_canonical_wallet_address,
    is_valid_protocol_address,
)
from visold.ledger.transaction import Transaction
from visold.rollup.l2_state import L2Transaction
from visold.vm.frame import _VMFrame
from visold.wallet.wallet import Wallet


class TestSection15Base58AndAddressInvariants:
    """Baseline invariants for Base58 and pub_to_address."""

    @pytest.mark.parametrize(
        "payload",
        [
            b"",
            b"\x00",
            b"\x00\x00\x00",
            b"\x00\x00\x01\x02\x03",
            b"\xff" * 20,
            b"\x00" * 20,
            bytes(range(20)),
        ],
    )
    def test_base58_roundtrip(self, payload: bytes):
        encoded = b58encode(payload)
        assert all(ch.encode() in B58_ALPHABET for ch in encoded)
        assert b58decode(encoded) == payload

    @pytest.mark.parametrize("bad_char", ["0", "O", "I", "l", " ", "+", "/", "١"])
    def test_base58_rejects_invalid_characters(self, bad_char: str):
        with pytest.raises(ValueError, match="Invalid Base58 character"):
            b58decode("123" + bad_char + "456")

    def test_pub_to_address_matches_double_sha256_and_canonical_wallet(self):
        _, pub = ecdsa_keygen()
        addr = pub_to_address(pub)
        pub_bytes = pub_to_bytes(pub)
        expected_digest = hashlib.sha256(hashlib.sha256(pub_bytes).digest()).digest()[:20]
        assert addr == "VSD" + b58encode(expected_digest)
        assert is_canonical_wallet_address(addr) is True
        assert is_canonical_contract_address(addr) is False
        assert is_valid_protocol_address(addr) is True

    def test_wallet_address_starting_with_vsdc_remains_valid_eoa(self):
        for first_byte in range(1, 256):
            cand = bytes([first_byte]) + b"\x00" * 19
            enc = b58encode(cand)
            if enc.startswith("c"):
                addr = "VSD" + enc
                assert is_canonical_wallet_address(addr) is True
                assert is_canonical_contract_address(addr) is False
                return
        pytest.fail("Could not construct a 20-byte Base58 payload starting with 'c'")


class TestSection15FixedRegressions:
    """Positive V4 regression tests for Section 15 fixes."""

    def test_is_canonical_contract_address_rejects_uppercase_and_mixed_hex(self):
        """V4 fix for BUG-15-01: only lowercase hex is accepted for VSDc contract addresses."""
        canonical_lower = "VSDc" + "ab12cd34ef56" * 3
        non_canonical_upper = "VSDc" + "AB12CD34EF56" * 3
        non_canonical_mixed = "VSDc" + "Ab12Cd34Ef56" * 3

        assert len(canonical_lower) == 40
        assert is_canonical_contract_address(canonical_lower) is True

        assert is_canonical_contract_address(non_canonical_upper) is False
        assert is_canonical_contract_address(non_canonical_mixed) is False
        assert is_valid_protocol_address(non_canonical_upper) is False
        assert is_valid_protocol_address(non_canonical_mixed) is False

        # Consensus L1 Transaction.is_valid() rejects the non-canonical uppercase destination for user transfers
        w = Wallet.generate()
        tx = Transaction(
            sender=w.address,
            receiver=non_canonical_upper,
            amount=10.0,
            fee=0.01,
        )
        tx.sign(w)
        ok_l1, reason_l1 = tx.is_valid()
        assert ok_l1 is False
        assert "receiver" in reason_l1.lower()

        # VVM _VMFrame normalizes hex to lowercase on round-trip
        frame = _VMFrame.__new__(_VMFrame)
        roundtrip_addr = frame._int_to_addr(frame._addr_to_int(non_canonical_upper))
        assert roundtrip_addr == canonical_lower

    def test_is_canonical_wallet_address_rejects_oversized_input_without_quadratic_dos(self):
        """V4 fix for BUG-15-02: oversized VSD... addresses are rejected in O(1) before Base58 decode."""
        assert len(b58encode(b"\x00" * 20)) == 20
        assert len(b58encode(b"\xff" * 20)) == 28

        tx_25k = Transaction(
            sender="VSD11111111111111111111",
            receiver="VSD" + "z" * 25_000,
            amount=1.0,
            fee=0.01,
        )
        t0 = time.perf_counter()
        ok_25k, _ = tx_25k.is_valid()
        dt_25k = time.perf_counter() - t0
        assert ok_25k is False

        tx_50k = Transaction(
            sender="VSD11111111111111111111",
            receiver="VSD" + "z" * 50_000,
            amount=1.0,
            fee=0.01,
        )
        t1 = time.perf_counter()
        ok_50k, _ = tx_50k.is_valid()
        dt_50k = time.perf_counter() - t1
        assert ok_50k is False

        # Rejection is fast (sub-50ms) rather than quadratic O(N^2)
        assert dt_25k < 0.05
        assert dt_50k < 0.05

        l2_tx = L2Transaction(
            sender="VSD11111111111111111111",
            receiver="VSD" + "z" * 25_000,
            amount_sat=100,
            nonce=0,
        )
        ok_l2, reason_l2 = l2_tx.is_valid()
        assert ok_l2 is False
        assert reason_l2 == "invalid receiver address"
