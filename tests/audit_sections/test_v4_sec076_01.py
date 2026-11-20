"""V4 regression tests for Section 76: Precompiled Contracts and Their Gas Requirements."""

from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op
from visold.vm.precompiles import VVMPrecompiles, _ripemd160_portable


class _DummyStorage:
    """Minimal in-memory storage stub for VVMEngine tests."""

    def __init__(self):
        self.contracts = {}
        self.codes = {}
        self.balances = {}

    def get_contract(self, addr):
        return self.contracts.get(addr)

    def get_contract_code(self, code_hash):
        return self.codes.get(code_hash)

    def get_balance_sat(self, addr):
        return self.balances.get(addr, 0)

    def sload(self, addr, slot):
        return 0

    def get_storage_tag(self, addr, slot):
        return 0

    def begin_state_channel_journal(self):
        return {}

    def end_state_channel_journal(self, journal):
        pass

    def restore_state_channel_journal(self, journal):
        pass


class _DummyTx:
    tx_id = "test_tx_76"
    gas_price = 0.0


def _push_bytes(data: bytes) -> bytes:
    assert 1 <= len(data) <= 32
    opcode = Op.PUSH1 + len(data) - 1
    return bytes([opcode]) + data


def _build_staticcall_contract(precompile_addr: str, gas_arg: int,
                               in_data: bytes = b"") -> bytes:
    code = bytearray()
    for off in range(0, len(in_data), 32):
        chunk = in_data[off:off + 32].ljust(32, b"\x00")
        code += _push_bytes(chunk)
        code += _push_bytes(off.to_bytes(1, "big"))
        code.append(Op.MSTORE)

    tmp_frame = _VMFrame.__new__(_VMFrame)
    addr_word = tmp_frame._addr_to_int(precompile_addr).to_bytes(32, "big")

    code += bytes([Op.PUSH1, 0])
    code += bytes([Op.PUSH1, 0])
    in_size_bytes = len(in_data).to_bytes(max(1, (len(in_data).bit_length() + 7) // 8), "big")
    code += _push_bytes(in_size_bytes)
    code += bytes([Op.PUSH1, 0])
    code += _push_bytes(addr_word)
    gas_bytes = gas_arg.to_bytes(max(1, (gas_arg.bit_length() + 7) // 8), "big")
    code += _push_bytes(gas_bytes)
    code.append(Op.STATICCALL)

    code += bytes([Op.PUSH1, 0, Op.MSTORE])
    code += bytes([Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    return bytes(code)


def test_ripemd160_portable_vectors():
    assert _ripemd160_portable(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert _ripemd160_portable(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"


def test_internal_call_precompile_no_double_64th_deduction():
    """Precompile dispatch does not double-deduct 1/64th gas and returns unused 1/64th."""
    storage = _DummyStorage()
    engine = VVMEngine(storage)

    bytecode = _build_staticcall_contract(VVMPrecompiles.ECRECOVER, gas_arg=10000)
    code = bytearray(bytecode[:-8])
    code.append(Op.STOP)
    code_hash = "h_ecrecover"
    contract_addr = "VSDc" + "11" * 18
    storage.contracts[contract_addr] = {"code_hash": code_hash}
    storage.codes[code_hash] = bytes(code)

    # 18 gas for 6 pushes + 3000 ECRECOVER = 3018 gas used; 50 gas_remaining
    res = engine.call(
        caller="VSDcaller",
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=3068,
        block_ctx=None,
        tx=_DummyTx(),
    )
    assert res.success is True
    assert res.gas_used == 3018

    frame = _VMFrame(
        code=bytes(code),
        calldata=b"",
        caller="VSDcaller",
        address=contract_addr,
        origin="VSDcaller",
        call_value=0,
        gas_limit=3068,
        storage_ref=storage,
    )
    engine._execute(frame)
    assert not frame.reverted
    assert frame.stack == [1]
    assert frame.gas_remaining == 50


def test_modexp_enforces_gas_limit_on_short_calldata_and_zero_mod():
    """VVMPrecompiles._modexp() fails with OOG when gas_limit < 200."""
    ok_short, ret_short, gas_short = VVMPrecompiles.execute(
        VVMPrecompiles.MODEXP, b"", gas_limit=10
    )
    assert ok_short is False
    assert gas_short <= 10

    header = (1).to_bytes(32, "big") + (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
    calldata_zero_mod = header + b"\x02\x03\x00"
    ok_zmod, ret_zmod, gas_zmod = VVMPrecompiles.execute(
        VVMPrecompiles.MODEXP, calldata_zero_mod, gas_limit=10
    )
    assert ok_zmod is False
    assert gas_zmod <= 10

    storage = _DummyStorage()
    engine = VVMEngine(storage)
    code = _build_staticcall_contract(VVMPrecompiles.MODEXP, gas_arg=10)
    code_hash = "h_modexp"
    contract_addr = "VSDc" + "22" * 18
    storage.contracts[contract_addr] = {"code_hash": code_hash}
    storage.codes[code_hash] = code

    res = engine.call(
        caller="VSDcaller",
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=5000,
        block_ctx=None,
        tx=_DummyTx(),
    )
    assert res.success is True
    assert int.from_bytes(res.return_data, "big") == 0


def test_unknown_precompile_caps_gas_charge_to_gas_limit():
    """Unknown precompile caps gas_used to gas_limit instead of draining 21,000 gas."""
    unknown_addr = "VSDcPRECOMPILE000000000000099"
    assert VVMPrecompiles.is_precompile(unknown_addr) is True

    ok, ret, gas_used = VVMPrecompiles.execute(unknown_addr, b"", gas_limit=100)
    assert ok is False
    assert ret == b"unknown precompile"
    assert gas_used <= 100

    storage = _DummyStorage()
    engine = VVMEngine(storage)
    code = _build_staticcall_contract(unknown_addr, gas_arg=100)
    code_hash = "h_unknown"
    contract_addr = "VSDc" + "33" * 18
    storage.contracts[contract_addr] = {"code_hash": code_hash}
    storage.codes[code_hash] = code

    res = engine.call(
        caller="VSDcaller",
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=5000,
        block_ctx=None,
        tx=_DummyTx(),
    )
    assert res.success is True
    assert int.from_bytes(res.return_data, "big") == 0


def test_modexp_short_calldata_right_padded_with_zeros():
    """EIP-198: short calldata after 96-byte header is right-padded with 0x00 bytes."""
    header = (1).to_bytes(32, "big") + (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    short_calldata = header + b"\x02\x02\x01"
    ok, ret, _ = VVMPrecompiles.execute(VVMPrecompiles.MODEXP, short_calldata, gas_limit=10000)
    assert ok is True
    assert ret == b"\x00\x04"
