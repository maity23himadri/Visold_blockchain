"""V4 regression tests for Audit Section 008: Bounded Decompression and Input Resource Limits."""

import zlib

import pytest

from visold.kernel.compression_utils import (
    DecompressedSizeLimitError,
    bounded_zlib_decompress,
)
from visold.network.udp.wire import _udp_decompress
from visold.rollup.compact_codec import (
    l2_pub_compact,
    l2_pub_expand,
    l2_sig_compact,
    l2_sig_expand,
)

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def test_udp_decompress_propagates_decompressed_size_limit_error():
    """_udp_decompress() propagates DecompressedSizeLimitError rather than returning zip-bomb bytes."""
    oversized_payload = b"A" * (32 * 1024 * 1024 + 1)
    zip_bomb = zlib.compress(oversized_payload, level=9)

    with pytest.raises(DecompressedSizeLimitError):
        bounded_zlib_decompress(zip_bomb, 32 * 1024 * 1024)

    with pytest.raises(DecompressedSizeLimitError):
        _udp_decompress(zip_bomb)


def test_l2_pub_expand_rejects_out_of_field_x_ge_p():
    """l2_pub_expand() rejects x >= P and returns ''."""
    x_bad = SECP256K1_P + 1
    assert x_bad < (1 << 256)
    compact_bad = "02" + f"{x_bad:064x}"
    assert len(compact_bad) == 66

    assert l2_pub_expand(compact_bad) == ""


def test_l2_pub_compact_rejects_invalid_non_hex_strings():
    """l2_pub_compact() returns '' for non-hex compressed and uncompressed pubkey strings."""
    bad_compressed = "02" + ("z" * 64)
    assert l2_pub_compact(bad_compressed) == ""

    bad_uncompressed = "04" + ("z" * 64) + ("0" * 64)
    assert l2_pub_compact(bad_uncompressed) == ""


def test_l2_sig_codec_rejects_malformed_and_degenerate_inputs():
    """l2_sig_expand() and l2_sig_compact() return '' for malformed or degenerate inputs."""
    assert l2_sig_expand("[not_valid_json") == ""
    assert l2_sig_compact("[0, 0]") == ""
    assert l2_sig_compact("[true, false]") == ""
    assert l2_sig_compact("[1, 2, 999]") == ""
