"""Consensus address-shape validation helpers.

These helpers validate only canonical wire/address shape.  They do not prove
that an address has a known private key or that a contract exists.
"""
from __future__ import annotations

import string
from typing import Iterable

from visold.crypto.base58 import b58decode, b58encode

_HEX = frozenset(string.hexdigits)


def is_canonical_wallet_address(address: str) -> bool:
    """Return True for canonical ``VSD`` + Base58(20-byte) wallet addresses."""
    if not isinstance(address, str) or not address.startswith("VSD"):
        return False
    suffix = address[3:]
    if not suffix:
        return False
    try:
        raw = b58decode(suffix)
    except Exception:
        return False
    return len(raw) == 20 and b58encode(raw) == suffix


def is_canonical_contract_address(address: str) -> bool:
    """Return True for deterministic VVM addresses: ``VSDc`` + 36 hex chars."""
    if not isinstance(address, str) or len(address) != 40 or not address.startswith("VSDc"):
        return False
    return all(ch in _HEX for ch in address[4:])


def is_valid_protocol_address(address: str, *, specials: Iterable[str] = (),
                              allow_contract: bool = True) -> bool:
    """Validate a consensus receiver address, including explicit sentinels."""
    if not isinstance(address, str) or not address:
        return False
    if address in specials:
        return True
    if is_canonical_wallet_address(address):
        return True
    return bool(allow_contract and is_canonical_contract_address(address))
