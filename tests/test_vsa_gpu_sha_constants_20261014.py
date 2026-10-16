"""Regression test for audit finding VSA-29: SHA-256 round constant K[60] in the
CUDA and OpenCL kernels.

The expected table is derived from first principles (the first 32 fractional
bits of the cube roots of the first 64 primes), not copied from the kernel.
The test parses every ``K[64] = { ... }`` table in visold/mining/gpu_kernels.py
and requires exactly two tables, each matching the standard table entry by entry.
"""

from __future__ import annotations

import pathlib
import re


def _first_primes(count: int) -> list[int]:
    found: list[int] = []
    candidate = 2
    while len(found) < count:
        if all(candidate % p for p in found if p * p <= candidate):
            found.append(candidate)
        candidate += 1
    return found


def _cbrt_fraction_bits(prime: int) -> int:
    """Low 32 bits of floor(cbrt(prime) * 2^32), computed with integers only."""
    target = prime * (1 << 96)          # (cbrt(p) * 2^32)^3 == p * 2^96
    lo, hi = 0, 1 << 40
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** 3 <= target:
            lo = mid
        else:
            hi = mid - 1
    return lo & 0xFFFFFFFF


def _standard_sha256_k() -> list[int]:
    return [_cbrt_fraction_bits(p) for p in _first_primes(64)]


def _kernel_tables() -> list[list[int]]:
    source_path = pathlib.Path(__file__).resolve().parents[1] / "visold" / "mining" / "gpu_kernels.py"
    source = source_path.read_text(encoding="utf-8")
    bodies = re.findall(r"K\[64\]\s*=\s*\{(.*?)\};", source, flags=re.S)
    return [[int(h, 16) for h in re.findall(r"0x([0-9a-fA-F]+)u", body)] for body in bodies]


def test_standard_table_reference_is_sound():
    expected = _standard_sha256_k()
    assert expected[0] == 0x428A2F98
    assert expected[1] == 0x71374491
    assert expected[60] == 0x90BEFFFA


def test_gpu_kernel_sha256_round_constants_match_the_standard_table():
    expected = _standard_sha256_k()
    tables = _kernel_tables()
    assert len(tables) == 2, f"expected CUDA and OpenCL K tables, found {len(tables)}"
    for number, table in enumerate(tables):
        assert len(table) == 64, f"table {number} has {len(table)} entries"
        mismatches = [(i, hex(table[i]), hex(expected[i]))
                      for i in range(64) if table[i] != expected[i]]
        assert not mismatches, f"table {number} differs from SHA-256 K (VSA-29): {mismatches}"
