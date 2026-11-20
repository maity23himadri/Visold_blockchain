# ─────────────────────────────────────────────────────────────────────────────
#  Visold (VSD) Blockchain Protocol
#  Copyright (c) 2025 Visold Contributors
#  Licensed under the MIT License.
#
#  The original and canonical source is maintained by the Visold Project.
#  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#  the license agreement.
# ─────────────────────────────────────────────────────────────────────────────
# cython: language_level=3
# cython: boundscheck=True
# cython: wraparound=True
# cython: cdivision=True
# cython: nonecheck=True
# cython: initializedcheck=False
# cython: infer_types=True
# cython: optimize.use_switch=True
# cython: optimize.unpack_method_calls=True
"""visold.vm.abi

Original section: SECTION 7B1A: VVM ABI ENCODER / DECODER  (SC-FIX-7)

Defines: VVMABIEncoder, VVMABIDecoder
Origin: visold_vsd_.py L21782-21877, L21880-21945
"""

import re

from visold.crypto.base58 import b58decode, b58encode
from visold.crypto.hashing import sha256


_ADDR_TAG_EOA = 0x01
_ADDR_TAG_CONTRACT = 0x02


def _strip_0x_prefix(s: str) -> str:
    """Strip a single leading '0x' or '0X' prefix without stripping leading '0' digits."""
    if s.startswith(("0x", "0X")):
        return s[2:]
    return s


def _parse_array_type(ptype: str):
    """Return (elem_type, count_or_None) for 'T[]' or 'T[N]', else None."""
    if ptype.endswith("[]"):
        elem = ptype[:-2]
        if not elem:
            raise ValueError(f"Invalid ABI array type: {ptype}")
        return elem, None
    m = re.fullmatch(r"(.+)\[(\d+)\]", ptype)
    if m:
        return m.group(1), int(m.group(2))
    return None


def _parse_int_type(ptype: str):
    """Return (is_signed, bits) for valid ABI uintM/intM types, else None."""
    if ptype in ("uint", "uint256"):
        return False, 256
    if ptype in ("int", "int256"):
        return True, 256
    if ptype.startswith("uint"):
        suffix = ptype[4:]
        if suffix.isdigit():
            bits = int(suffix)
            if 8 <= bits <= 256 and bits % 8 == 0:
                return False, bits
        raise ValueError(f"Unsupported static ABI type: {ptype}")
    if ptype.startswith("int"):
        suffix = ptype[3:]
        if suffix.isdigit():
            bits = int(suffix)
            if 8 <= bits <= 256 and bits % 8 == 0:
                return True, bits
        raise ValueError(f"Unsupported static ABI type: {ptype}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7B1A: VVM ABI ENCODER / DECODER  (SC-FIX-7)
#
# Implements the Ethereum ABI specification for VVM contracts so that:
#   • Callers can encode function calls by name + arguments
#   • Contracts can decode received calldata into typed Python values
#   • Off-chain tooling and front-ends can interoperate with VSD contracts
#
# Supported types: uint256, int256, bool, address, bytes32,
#                  bytes (dynamic), string (dynamic), and fixed-size/dynamic arrays.
#
# Function selector: first 4 bytes of sha256("functionName(type1,type2,...)")
# This uses SHA-256 (VSD native) rather than Keccak-256 (Ethereum).
# ─────────────────────────────────────────────────────────────────────────────

class VVMABIEncoder:
    """
    ABI-encode calldata for VVM smart contract calls.

    Usage:
        # Call transfer(address, uint256) with value 100
        calldata = VVMABIEncoder.encode_call(
            "transfer", ["address", "uint256"],
            ["VSDabc123...", 100]
        )
        result = vvm.call(..., calldata=calldata, ...)

        # Deploy with constructor(uint256 initialSupply)
        encoded_args = VVMABIEncoder.encode_args(["uint256"], [1000000])
        deploy_bytecode = raw_bytecode + encoded_args
    """

    @staticmethod
    def function_selector(name: str, param_types: list) -> bytes:
        """Compute the 4-byte function selector (SHA-256 of signature)."""
        sig = f"{name}({','.join(param_types)})"
        return bytes.fromhex(sha256(sig.encode()))[:4]

    @staticmethod
    def encode_call(name: str, param_types: list, values: list) -> bytes:
        """Encode a full function call: selector + ABI-encoded arguments."""
        selector = VVMABIEncoder.function_selector(name, param_types)
        return selector + VVMABIEncoder.encode_args(param_types, values)

    @staticmethod
    def encode_args(param_types: list, values: list) -> bytes:
        """ABI-encode a list of (type, value) pairs without a selector."""
        if len(param_types) != len(values):
            raise ValueError("param_types and values length mismatch")

        # Two-pass: compute heads (fixed-size slots) and tails (dynamic data)
        heads = []
        tails = []
        dynamic_offset = sum(VVMABIEncoder._head_size(t) for t in param_types)

        for ptype, val in zip(param_types, values):
            if VVMABIEncoder._is_dynamic(ptype):
                # Head = offset pointer; tail = actual data
                heads.append(dynamic_offset.to_bytes(32, 'big'))
                tail = VVMABIEncoder._encode_dynamic(ptype, val)
                tails.append(tail)
                dynamic_offset += len(tail)
            else:
                arr = _parse_array_type(ptype)
                if arr is not None:
                    elem, count = arr
                    if not isinstance(val, (list, tuple)) or len(val) != count:
                        raise ValueError(
                            f"ABI encode: expected sequence of length {count} for {ptype}"
                        )
                    heads.append(VVMABIEncoder.encode_args([elem] * count, list(val)))
                else:
                    heads.append(VVMABIEncoder._encode_static(ptype, val))

        return b"".join(heads) + b"".join(tails)

    @staticmethod
    def _is_dynamic(ptype: str) -> bool:
        if ptype in ("bytes", "string"):
            return True
        arr = _parse_array_type(ptype)
        if arr is not None:
            elem, count = arr
            if count is None:
                return True
            return VVMABIEncoder._is_dynamic(elem)
        return False

    @staticmethod
    def _head_size(ptype: str) -> int:
        if VVMABIEncoder._is_dynamic(ptype):
            return 32
        arr = _parse_array_type(ptype)
        if arr is not None:
            elem, count = arr
            return count * VVMABIEncoder._head_size(elem)
        return 32

    @staticmethod
    def _encode_static(ptype: str, val) -> bytes:
        """Encode a static (fixed-size) type to 32 bytes."""
        int_spec = _parse_int_type(ptype)
        if int_spec is not None:
            is_signed, bits = int_spec
            v = int(val)
            if is_signed:
                lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
                if not (lo <= v <= hi):
                    raise ValueError(f"ABI encode: {v} out of range for {ptype}")
                return v.to_bytes(32, 'big', signed=True) if v < 0 else v.to_bytes(32, 'big')
            else:
                hi = (1 << bits) - 1
                if not (0 <= v <= hi):
                    raise ValueError(f"ABI encode: {v} out of range for {ptype}")
                return v.to_bytes(32, 'big')
        if ptype == "bool":
            return (1 if val else 0).to_bytes(32, 'big')
        if ptype == "address":
            addr_str = str(val)
            if addr_str.startswith("VSDc") and len(addr_str) == 40:
                try:
                    suffix = bytes.fromhex(addr_str[4:])
                    if len(suffix) == 18:
                        return (bytes([_ADDR_TAG_CONTRACT]) + suffix).ljust(32, b"\x00")
                except ValueError:
                    pass
            if addr_str.startswith("VSD"):
                raw20 = b58decode(addr_str[3:])
                if len(raw20) != 20:
                    raise ValueError(f"Invalid VSD wallet address length: {addr_str!r}")
                return int.from_bytes(raw20, 'big').to_bytes(32, 'big')
            raw20 = bytes.fromhex(_strip_0x_prefix(addr_str))
            if len(raw20) != 20:
                raise ValueError(f"Invalid hex address length: {addr_str!r}")
            return int.from_bytes(raw20, 'big').to_bytes(32, 'big')
        if ptype == "bytes32":
            raw = (
                bytes(val)
                if isinstance(val, (bytes, bytearray))
                else bytes.fromhex(_strip_0x_prefix(str(val)))
            )
            if len(raw) > 32:
                raise ValueError(f"ABI encode: bytes32 input exceeds 32 bytes ({len(raw)})")
            return raw.ljust(32, b'\x00')
        raise ValueError(f"Unsupported static ABI type: {ptype}")

    @staticmethod
    def _encode_dynamic(ptype: str, val) -> bytes:
        """Encode a dynamic type: length-prefixed, padded to 32-byte boundary."""
        if ptype == "bytes":
            data = (
                bytes(val)
                if isinstance(val, (bytes, bytearray))
                else bytes.fromhex(_strip_0x_prefix(str(val)))
            )
            length_prefix = len(data).to_bytes(32, 'big')
            pad = (32 - len(data) % 32) % 32
            return length_prefix + data + b'\x00' * pad
        if ptype == "string":
            data = str(val).encode("utf-8")
            length_prefix = len(data).to_bytes(32, 'big')
            pad = (32 - len(data) % 32) % 32
            return length_prefix + data + b'\x00' * pad
        arr = _parse_array_type(ptype)
        if arr is not None:
            elem, count = arr
            if not isinstance(val, (list, tuple)):
                raise ValueError(f"ABI encode: expected sequence for {ptype}")
            if count is None:
                return len(val).to_bytes(32, 'big') + VVMABIEncoder.encode_args(
                    [elem] * len(val), list(val)
                )
            if len(val) != count:
                raise ValueError(
                    f"ABI encode: expected sequence of length {count} for {ptype}"
                )
            return VVMABIEncoder.encode_args([elem] * count, list(val))
        raise ValueError(f"Unsupported dynamic ABI type: {ptype}")


class VVMABIDecoder:
    """
    ABI-decode calldata or return data from VVM smart contracts.

    Usage:
        # Decode return data from balanceOf(address) → uint256
        (balance,) = VVMABIDecoder.decode(["uint256"], return_data)

        # Decode incoming calldata (skip 4-byte selector)
        (from_addr, to_addr, amount) = VVMABIDecoder.decode(
            ["address", "address", "uint256"],
            calldata[4:]
        )
    """

    @staticmethod
    def decode(param_types: list, data: bytes) -> tuple:
        """Decode ABI-encoded bytes into Python values."""
        head_size = sum(VVMABIEncoder._head_size(t) for t in param_types)
        if len(data) < head_size:
            raise ValueError("ABI decode: truncated head")
        results = []
        cursor = 0
        for ptype in param_types:
            slot_size = VVMABIEncoder._head_size(ptype)
            if VVMABIEncoder._is_dynamic(ptype):
                offset = int.from_bytes(data[cursor:cursor+32], 'big')
                cursor += 32
                if offset < head_size or offset > len(data):
                    raise ValueError("ABI decode: dynamic offset out of range")
                val = VVMABIDecoder._decode_dynamic(ptype, data, offset)
            else:
                arr = _parse_array_type(ptype)
                if arr is not None:
                    elem, count = arr
                    val = list(
                        VVMABIDecoder.decode(
                            [elem] * count, data[cursor:cursor+slot_size]
                        )
                    )
                else:
                    val = VVMABIDecoder._decode_static(ptype, data[cursor:cursor+32])
                cursor += slot_size
            results.append(val)
        return tuple(results)

    @staticmethod
    def _decode_static(ptype: str, slot: bytes):
        int_spec = _parse_int_type(ptype)
        if int_spec is not None:
            is_signed, bits = int_spec
            val = int.from_bytes(slot, 'big')
            if is_signed:
                if val >= (1 << 255):
                    val -= (1 << 256)
                lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
                if not (lo <= val <= hi):
                    raise ValueError(f"ABI decode: {val} out of range for {ptype}")
                return val
            else:
                hi = (1 << bits) - 1
                if val > hi:
                    raise ValueError(f"ABI decode: {val} out of range for {ptype}")
                return val
        if ptype == "bool":
            return bool(int.from_bytes(slot, 'big'))
        if ptype == "address":
            if slot[0] == _ADDR_TAG_CONTRACT and slot[19:] == b"\x00" * 13:
                return "VSDc" + slot[1:19].hex()
            if slot[:12] == b"\x00" * 12:
                return "VSD" + b58encode(slot[12:])
            if slot[0] == _ADDR_TAG_EOA and slot[1:12] == b"\x00" * 11:
                return "VSD" + b58encode(slot[-20:])
            raise ValueError("ABI decode: invalid address slot")
        if ptype == "bytes32":
            return slot
        raise ValueError(f"Unsupported static ABI type: {ptype}")

    @staticmethod
    def _decode_dynamic(ptype: str, data: bytes, offset: int):
        if ptype in ("bytes", "string"):
            if offset < 0 or offset + 32 > len(data):
                raise ValueError("ABI decode: dynamic offset out of range")
            length = int.from_bytes(data[offset:offset+32], 'big')
            start  = offset + 32
            if start + length > len(data):
                raise ValueError("ABI decode: truncated dynamic payload")
            raw    = data[start:start+length]
            if ptype == "string":
                return raw.decode("utf-8", errors="replace")
            return raw
        arr = _parse_array_type(ptype)
        if arr is not None:
            elem, count = arr
            if count is None:
                if offset < 0 or offset + 32 > len(data):
                    raise ValueError("ABI decode: dynamic array offset out of range")
                length = int.from_bytes(data[offset:offset+32], 'big')
                start = offset + 32
                if length * 32 > len(data) - start:
                    raise ValueError("ABI decode: truncated dynamic array payload")
                return list(VVMABIDecoder.decode([elem] * length, data[start:]))
            return list(VVMABIDecoder.decode([elem] * count, data[offset:]))
        raise ValueError(f"Unsupported dynamic ABI type: {ptype}")
