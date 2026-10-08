# ─────────────────────────────────────────────────────────────────────────────
#  Visold (VSD) Blockchain Protocol
#  Copyright (c) 2025 Visold Contributors
#  Licensed under the MIT License.
# ─────────────────────────────────────────────────────────────────────────────
"""Small dependency-free compression safety helpers shared by bounded contexts.

This module intentionally lives in ``kernel`` so lower layers (rollup/storage)
do not depend upward on the P2P/network layer.
"""

import zlib


def bounded_zlib_decompress(data: bytes, max_output_size: int) -> bytes:
    """Safely zlib-decompress ``data`` without an unbounded inflate.

    The decompressor requests at most ``limit + 1`` bytes at each step so a
    malicious compressed input cannot expand into an unbounded allocation.
    Truncated and concatenated streams are rejected as malformed frames.
    """
    limit = int(max_output_size)
    if limit <= 0:
        raise ValueError("max_output_size must be positive")

    dec = zlib.decompressobj(wbits=15)
    out = bytearray()
    remaining_input = bytes(data)

    while remaining_input:
        allowance = limit - len(out) + 1
        if allowance <= 0:
            raise ValueError("decompressed output exceeds configured limit")
        part = dec.decompress(remaining_input, allowance)
        out.extend(part)
        if len(out) > limit:
            raise ValueError("decompressed output exceeds configured limit")
        remaining_input = dec.unconsumed_tail
        if not remaining_input:
            break

    if not dec.eof:
        allowance = limit - len(out) + 1
        if allowance <= 0:
            raise ValueError("decompressed output exceeds configured limit")
        tail = dec.flush(allowance)
        out.extend(tail)
        if len(out) > limit:
            raise ValueError("decompressed output exceeds configured limit")
        if not dec.eof:
            raise ValueError("truncated zlib stream")

    if dec.unused_data:
        raise ValueError("concatenated zlib streams are not permitted")

    return bytes(out)
