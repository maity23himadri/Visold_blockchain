from pathlib import Path
import sys

import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.crypto.ecc import (
    ECPoint,
    G,
    _recover_y_from_compressed,
    pub_from_bytes,
    pub_from_hex,
)


def _find_off_curve_x() -> int:
    p = ECPoint.P
    for x in range(1, 100):
        rhs = (pow(x, 3, p) + 7) % p
        if pow(rhs, (p - 1) // 2, p) != 1:
            return x
    raise RuntimeError("No quadratic non-residue found")


def test_pub_from_bytes_and_hex_reject_off_curve_point():
    """V4 regression: pub_from_bytes / pub_from_hex verify y^2 == x^3 + 7 (mod P)."""
    x = _find_off_curve_x()
    bad_bytes = b"\x02" + x.to_bytes(32, "big")
    bad_hex = bad_bytes.hex()

    with pytest.raises(ValueError, match="not on secp256k1"):
        pub_from_bytes(bad_bytes)

    with pytest.raises(ValueError, match="not on secp256k1"):
        pub_from_hex(bad_hex)


def test_recover_y_from_compressed_validation():
    """V4 regression: _recover_y_from_compressed enforces length, prefix, x-range, and curve equation."""
    p = ECPoint.P
    x = _find_off_curve_x()
    bad_bytes = b"\x02" + x.to_bytes(32, "big")

    with pytest.raises(ValueError, match="not on secp256k1"):
        _recover_y_from_compressed(bad_bytes)

    # Invalid prefix 0x04 must be rejected
    bad_prefix_bytes = b"\x04" + ECPoint.Gx.to_bytes(32, "big")
    with pytest.raises(ValueError):
        _recover_y_from_compressed(bad_prefix_bytes)

    # x >= P must be rejected
    x_ge_p_bytes = b"\x02" + p.to_bytes(32, "big")
    with pytest.raises(ValueError):
        _recover_y_from_compressed(x_ge_p_bytes)

    # Oversized input (65 bytes) must be rejected
    oversized = b"\x02" + ECPoint.Gx.to_bytes(32, "big") + b"\xff" * 32
    with pytest.raises(ValueError):
        _recover_y_from_compressed(oversized)


def test_ecpoint_eq_with_non_ecpoint_returns_false():
    """V4 regression: ECPoint.__eq__ returns False when compared to non-ECPoint objects."""
    assert (G == None) is False  # noqa: E711
    assert (G != None) is True  # noqa: E711
    assert (G == "not-an-ecpoint") is False
