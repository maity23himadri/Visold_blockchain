"""V4 regression tests for Section 75 (Session 06): ABI Encoding, Decoding and Input Validation."""

import os
import tempfile
import unittest

from visold.vm.abi import VVMABIEncoder, VVMABIDecoder
from visold.vm.engine import VVMEngine
from visold.storage.storage import Storage


class _DummyTx:
    tx_id = "00" * 32
    gas_price = 0.0


class TestAuditSection75(unittest.TestCase):
    """Positive V4 regression tests for Section 75 (ABI & VVMEngine input validation)."""

    def test_contract_address_vsdc_roundtrips_cleanly(self):
        contract_with_zero = "VSDc0123456789abcdef0123456789abcdef0123"
        encoded_0 = VVMABIEncoder.encode_args(["address"], [contract_with_zero])
        (decoded_0,) = VVMABIDecoder.decode(["address"], encoded_0)
        self.assertEqual(decoded_0, contract_with_zero)

        contract_no_zero = "VSDc123456789abcdef123456789abcdef123456"
        encoded = VVMABIEncoder.encode_args(["address"], [contract_no_zero])
        (decoded,) = VVMABIDecoder.decode(["address"], encoded)
        self.assertEqual(decoded, contract_no_zero)

    def test_hex_0x_prefix_preserves_leading_zero_bytes(self):
        enc_b = VVMABIEncoder.encode_args(["bytes"], ["0x0123"])
        self.assertEqual(VVMABIDecoder.decode(["bytes"], enc_b), (b"\x01\x23",))

        hex_32_a = "0x0001" + "11" * 30
        enc_b32_a = VVMABIEncoder.encode_args(["bytes32"], [hex_32_a])
        self.assertEqual(
            VVMABIDecoder.decode(["bytes32"], enc_b32_a),
            (bytes.fromhex(hex_32_a[2:]),),
        )

        encoded_bytes = VVMABIEncoder.encode_args(["bytes"], ["0x00112233"])
        (decoded_bytes,) = VVMABIDecoder.decode(["bytes"], encoded_bytes)
        self.assertEqual(decoded_bytes, b"\x00\x11\x22\x33")

        hex_32 = "0x00" + "11" * 31
        encoded_b32 = VVMABIEncoder.encode_args(["bytes32"], [hex_32])
        (decoded_b32,) = VVMABIDecoder.decode(["bytes32"], encoded_b32)
        self.assertEqual(decoded_b32, bytes.fromhex(hex_32[2:]))

    def test_decode_dynamic_bounds_check_and_array_type(self):
        malformed = (
            (32).to_bytes(32, "big")
            + (1000).to_bytes(32, "big")
            + b"\xaa\xbb\xcc\xdd"
        )
        with self.assertRaises(ValueError):
            VVMABIDecoder.decode(["bytes"], malformed)

        encoded_arr = VVMABIEncoder.encode_args(["uint256[]"], [[1, 2]])
        (decoded_arr,) = VVMABIDecoder.decode(["uint256[]"], encoded_arr)
        self.assertEqual(decoded_arr, [1, 2])

    def test_narrow_int_bounds_and_head_tail_offset_aliasing(self):
        with self.assertRaises(ValueError):
            VVMABIEncoder.encode_args(["uint8"], [300])

        with self.assertRaises(ValueError):
            VVMABIEncoder.encode_args(["int8"], [-200])

        with self.assertRaises(ValueError):
            VVMABIEncoder.encode_args(["uintfoo"], [42])

        aliased = (32).to_bytes(32, "big") + (5).to_bytes(32, "big") + b"hello" + b"\x00" * 27
        with self.assertRaises(ValueError):
            VVMABIDecoder.decode(["bytes", "uint256"], aliased)

    def test_vvm_engine_call_gas_limit_validation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            storage = Storage(db_path)
            engine = VVMEngine(storage)

            res = engine.call(
                caller="VSD11111111111111111111111111111111",
                contract="VSDc" + "ab" * 18,
                calldata=b"",
                call_value=0,
                gas_limit=5000,
                block_ctx=None,
                tx=_DummyTx(),
            )
            self.assertFalse(res.success)
            self.assertLessEqual(res.gas_used, 5000)

            c_addr = "VSDc" + "cd" * 18
            code_hash = "00" * 32
            storage.save_contract_code(code_hash, b"")
            storage.save_contract(
                address=c_addr,
                code_hash=code_hash,
                creator="VSD11111111111111111111111111111111",
                created_at=0,
            )
            res_neg = engine.call(
                caller="VSD11111111111111111111111111111111",
                contract=c_addr,
                calldata=b"",
                call_value=0,
                gas_limit=-10,
                block_ctx=None,
                tx=_DummyTx(),
            )
            self.assertFalse(res_neg.success)
            self.assertEqual(res_neg.gas_used, 0)
