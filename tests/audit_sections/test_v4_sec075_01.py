"""V4 regression tests for Section 75: ABI Encoding, Decoding and Input Validation."""

import hashlib
import pytest

from visold.vm.abi import VVMABIEncoder, VVMABIDecoder
from visold.vm.engine import VVMEngine
from visold.vm.opcodes import Op


class _MinimalStorage:
    """Minimal in-memory storage stub for VVMEngine.call/deploy tests."""

    def __init__(self):
        self._contracts = {}
        self._codes = {}
        self._nonces = {}
        self._balances = {}
        self._storage = {}
        self._tags = {}

    def install_contract(self, addr: str, runtime_code: bytes, balance_sat: int = 0):
        code_hash = hashlib.sha256(runtime_code).hexdigest()
        self._codes[code_hash] = runtime_code
        self._contracts[addr] = {"code_hash": code_hash, "creator": "VSDtest", "created_at": 1}
        self._balances[addr] = balance_sat

    def get_contract(self, addr: str):
        return self._contracts.get(addr)

    def get_contract_code(self, code_hash: str):
        return self._codes.get(code_hash)

    def get_nonce(self, addr: str) -> int:
        return self._nonces.get(addr, 0)

    def get_balance_sat(self, addr: str) -> int:
        return self._balances.get(addr, 0)

    def sload(self, addr: str, slot: str) -> int:
        return self._storage.get((addr, slot), 0)

    def get_storage_tag(self, addr: str, slot: str) -> int:
        return self._tags.get((addr, slot), 0)

    def begin_state_channel_journal(self):
        return []

    def end_state_channel_journal(self, journal):
        pass

    def restore_state_channel_journal(self, journal):
        pass


class _DummyTx:
    tx_id = "tx_sec75_test"
    gas_price = 0.0001


class _DummyBlockCtx:
    height = 1
    timestamp = 1700000000
    difficulty = 1.0
    miner = "VSDminer"
    chain_id = 1


def test_hex_0x_prefix_handled_without_stripping_leading_zeros():
    hex_odd_after_lstrip = "0x01" + "ab" * 31
    encoded_1a = VVMABIEncoder.encode_args(["bytes32"], [hex_odd_after_lstrip])
    (decoded_1a,) = VVMABIDecoder.decode(["bytes32"], encoded_1a)
    assert decoded_1a == bytes.fromhex("01" + "ab" * 31)

    hex_leading_zero_byte = "0x00" + "ab" * 31
    encoded_1b = VVMABIEncoder.encode_args(["bytes32"], [hex_leading_zero_byte])
    assert encoded_1b == bytes.fromhex("00" + "ab" * 31)

    encoded_dyn = VVMABIEncoder.encode_args(["bytes"], ["0x00abcd"])
    (decoded_dyn,) = VVMABIDecoder.decode(["bytes"], encoded_dyn)
    assert decoded_dyn == b"\x00\xab\xcd"

    encoded_addr = VVMABIEncoder.encode_args(["address"], ["0x01" + "22" * 19])
    (decoded_addr,) = VVMABIDecoder.decode(["address"], encoded_addr)
    assert decoded_addr.startswith("VSD")


def test_contract_address_vsdc_roundtrips_cleanly():
    contract_addr_with_zero = "VSDc" + "0123456789abcdef0123456789abcdef0123"
    encoded_0 = VVMABIEncoder.encode_args(["address"], [contract_addr_with_zero])
    (decoded_0,) = VVMABIDecoder.decode(["address"], encoded_0)
    assert decoded_0 == contract_addr_with_zero

    contract_addr_no_zero = "VSDc" + "a" * 36
    encoded = VVMABIEncoder.encode_args(["address"], [contract_addr_no_zero])
    (decoded,) = VVMABIDecoder.decode(["address"], encoded)
    assert decoded == contract_addr_no_zero


def test_decode_dynamic_rejects_truncation_and_head_overlap():
    head = (32).to_bytes(32, "big")
    tail_len = (100).to_bytes(32, "big")
    tail_data = b"abcd"
    malformed = head + tail_len + tail_data

    with pytest.raises(ValueError, match="truncated"):
        VVMABIDecoder.decode(["bytes"], malformed)

    overlap_data = (0).to_bytes(32, "big") + (1).to_bytes(32, "big")
    with pytest.raises(ValueError, match="out of range|overlap"):
        VVMABIDecoder.decode(["bytes"], overlap_data)


def test_array_types_encode_and_decode_cleanly():
    encoded_dyn = VVMABIEncoder.encode_args(["uint256[]"], [[1, 2]])
    (decoded_dyn,) = VVMABIDecoder.decode(["uint256[]"], encoded_dyn)
    assert decoded_dyn == [1, 2]

    encoded_fixed = VVMABIEncoder.encode_args(["uint256[2]"], [[1, 2]])
    (decoded_fixed,) = VVMABIDecoder.decode(["uint256[2]"], encoded_fixed)
    assert decoded_fixed == [1, 2]


def test_sized_integers_enforce_bounds():
    with pytest.raises(ValueError, match="out of range"):
        VVMABIEncoder.encode_args(["uint8"], [300])

    slot_255 = (255).to_bytes(32, "big")
    with pytest.raises(ValueError, match="out of range"):
        VVMABIDecoder.decode(["int8"], slot_255)


def test_vvm_engine_call_rejects_negative_gas_limit_and_call_value():
    storage = _MinimalStorage()
    contract_addr = "VSDc" + "11" * 18
    code = bytes([
        Op.CALLVALUE,
        Op.PUSH1, 0x00,
        Op.MSTORE,
        Op.PUSH1, 0x20,
        Op.PUSH1, 0x00,
        Op.RETURN,
    ])
    storage.install_contract(contract_addr, code)
    engine = VVMEngine(storage=storage)

    res_neg_gas = engine.call(
        caller="VSDcaller",
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=-100,
        block_ctx=_DummyBlockCtx(),
        tx=_DummyTx(),
    )
    assert res_neg_gas.success is False
    assert res_neg_gas.gas_used == 0

    res_neg_val = engine.call(
        caller="VSDcaller",
        contract=contract_addr,
        calldata=b"",
        call_value=-50,
        gas_limit=50000,
        block_ctx=_DummyBlockCtx(),
        tx=_DummyTx(),
    )
    assert res_neg_val.success is False
