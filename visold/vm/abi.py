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

from visold.crypto.base58 import b58decode, b58encode
from visold.crypto.hashing import sha256


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7B1A: VVM ABI ENCODER / DECODER  (SC-FIX-7)
#
# Implements the Ethereum ABI specification for VVM contracts so that:
#   • Callers can encode function calls by name + arguments
#   • Contracts can decode received calldata into typed Python values
#   • Off-chain tooling and front-ends can interoperate with VSD contracts
#
# Supported types: uint256, int256, bool, address, bytes32,
#                  bytes (dynamic), string (dynamic), and fixed-size arrays.
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

        # Two-pass: compute heads (fixed 32-byte slots) and tails (dynamic data)
        heads = []
        tails = []
        dynamic_offset = len(param_types) * 32  # offset to first dynamic item

        for ptype, val in zip(param_types, values):
            if VVMABIEncoder._is_dynamic(ptype):
                # Head = offset pointer; tail = actual data
                heads.append(dynamic_offset.to_bytes(32, 'big'))
                tail = VVMABIEncoder._encode_dynamic(ptype, val)
                tails.append(tail)
                dynamic_offset += len(tail)
            else:
                heads.append(VVMABIEncoder._encode_static(ptype, val))

        return b"".join(heads) + b"".join(tails)

    @staticmethod
    def _is_dynamic(ptype: str) -> bool:
        return ptype in ("bytes", "string") or ptype.endswith("[]")

    @staticmethod
    def _encode_static(ptype: str, val) -> bytes:
        """Encode a static (fixed-size) type to 32 bytes."""
        if ptype in ("uint256", "uint") or ptype.startswith("uint"):
            return int(val).to_bytes(32, 'big')
        if ptype in ("int256", "int") or ptype.startswith("int"):
            v = int(val)
            return v.to_bytes(32, 'big', signed=True) if v < 0 else v.to_bytes(32, 'big')
        if ptype == "bool":
            return (1 if val else 0).to_bytes(32, 'big')
        if ptype == "address":
            # Encode VSD address: strip the 'VSD' prefix, Base58-decode the
            # payload back to the original 20 raw bytes, then store as uint160.
            # This is the exact inverse of pub_to_address() and of the decoder
            # below, ensuring a lossless round-trip for smart-contract calls.
            addr_str = str(val)
            if addr_str.startswith("VSD"):
                raw20 = b58decode(addr_str[3:])
            else:
                # Fallback: treat as hex
                raw20 = bytes.fromhex(addr_str.lstrip("0x"))
            raw20 = raw20[:20].ljust(20, b'\x00')
            return int.from_bytes(raw20, 'big').to_bytes(32, 'big')
        if ptype == "bytes32":
            raw = bytes(val) if isinstance(val, (bytes, bytearray)) else bytes.fromhex(str(val).lstrip("0x"))
            return raw[:32].ljust(32, b'\x00')
        raise ValueError(f"Unsupported static ABI type: {ptype}")

    @staticmethod
    def _encode_dynamic(ptype: str, val) -> bytes:
        """Encode a dynamic type: length-prefixed, padded to 32-byte boundary."""
        if ptype in ("bytes",):
            data = bytes(val) if isinstance(val, (bytes, bytearray)) else bytes.fromhex(str(val).lstrip("0x"))
        elif ptype == "string":
            data = str(val).encode("utf-8")
        else:
            raise ValueError(f"Unsupported dynamic ABI type: {ptype}")
        length_prefix = len(data).to_bytes(32, 'big')
        pad = (32 - len(data) % 32) % 32
        return length_prefix + data + b'\x00' * pad


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
        results = []
        cursor = 0
        for ptype in param_types:
            if VVMABIEncoder._is_dynamic(ptype):
                if cursor + 32 > len(data):
                    raise ValueError("ABI decode: truncated offset")
                offset = int.from_bytes(data[cursor:cursor+32], 'big')
                cursor += 32
                val = VVMABIDecoder._decode_dynamic(ptype, data, offset)
            else:
                if cursor + 32 > len(data):
                    raise ValueError("ABI decode: truncated static slot")
                val = VVMABIDecoder._decode_static(ptype, data[cursor:cursor+32])
                cursor += 32
            results.append(val)
        return tuple(results)

    @staticmethod
    def _decode_static(ptype: str, slot: bytes):
        if ptype in ("uint256", "uint") or ptype.startswith("uint"):
            return int.from_bytes(slot, 'big')
        if ptype in ("int256", "int") or ptype.startswith("int"):
            val = int.from_bytes(slot, 'big')
            if val >= (1 << 255):
                val -= (1 << 256)
            return val
        if ptype == "bool":
            return bool(int.from_bytes(slot, 'big'))
        if ptype == "address":
            # Decode uint160 back to a VSD address: take the low 20 bytes,
            # Base58-encode them, and prepend 'VSD' — exactly reversing the
            # encoder above and matching the pub_to_address() format.
            raw20 = slot[-20:]
            return "VSD" + b58encode(raw20)
        if ptype == "bytes32":
            return slot
        raise ValueError(f"Unsupported static ABI type: {ptype}")

    @staticmethod
    def _decode_dynamic(ptype: str, data: bytes, offset: int):
        if offset + 32 > len(data):
            raise ValueError("ABI decode: dynamic offset out of range")
        length = int.from_bytes(data[offset:offset+32], 'big')
        start  = offset + 32
        raw    = data[start:start+length]
        if ptype == "string":
            return raw.decode("utf-8", errors="replace")
        return raw  # bytes
