"""V4 regression tests for Section 71: VVM Opcode Implementation and Execution Semantics."""

from types import SimpleNamespace

from visold.crypto.ecc import ECPoint, ecdsa_sign_digest, pub_to_address
from visold.crypto.hashing import sha256
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine, _chan_state_msg
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op
from visold.vm.static_analyzer import VVMStaticAnalyzer


def _make_keypair(priv_int: int):
    G = ECPoint(ECPoint.Gx, ECPoint.Gy)
    pub = priv_int * G
    addr = pub_to_address(pub)
    return priv_int, addr


def _deploy_runtime(storage: Storage, sender: str,
                    runtime_code: bytes, tx_id: str = "tx_deploy") -> str:
    code_hash = sha256(runtime_code)
    addr = "VSDc" + sha256(f"{sender}:{tx_id}:{code_hash}".encode())[:36]
    storage.save_contract_code(code_hash, runtime_code)
    storage.save_contract(addr, code_hash, sender, created_at=1, contract_name="")
    return addr


def _push_bytes(val: int, size: int = 32) -> bytes:
    assert 1 <= size <= 32
    return bytes([Op.PUSH1 + size - 1]) + val.to_bytes(size, "big")


def test_chan_dispute_unauthorized_caller_cannot_force_close_disputed_channel(tmp_path):
    storage = Storage(str(tmp_path / "db1a.sqlite"))
    engine = VVMEngine(storage)

    priv_a, opener = _make_keypair(0x1111)
    priv_b, counterparty = _make_keypair(0x2222)
    _, attacker = _make_keypair(0x3333)

    storage.credit_sat(opener, 10_000_000)
    storage.credit_sat(counterparty, 1_000_000)
    storage.credit_sat(attacker, 1_000_000)

    # Contract that runs CHAN_DISPUTE and pops two 32-byte words from stack
    code_two = bytearray()
    for off in (160, 128, 96, 64, 32, 0):
        code_two += bytes([Op.PUSH1, off, Op.CALLDATALOAD])
    code_two += bytes([
        Op.CHAN_DISPUTE,
        Op.PUSH1, 0, Op.MSTORE,
        Op.PUSH1, 32, Op.MSTORE,
        Op.PUSH1, 64, Op.PUSH1, 0, Op.RETURN,
    ])
    two_ret_contract = _deploy_runtime(storage, opener, bytes(code_two), "d1a_two")

    # Contract that pops one word from stack
    code_one = bytearray()
    for off in (160, 128, 96, 64, 32, 0):
        code_one += bytes([Op.PUSH1, off, Op.CALLDATALOAD])
    code_one += bytes([
        Op.CHAN_DISPUTE,
        Op.PUSH1, 0, Op.MSTORE,
        Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN,
    ])
    one_ret_contract = _deploy_runtime(storage, opener, bytes(code_one), "d1a_one")

    dummy_frame = _VMFrame(code=b"", calldata=b"", caller=opener, address=one_ret_contract,
                           origin=opener, call_value=0, gas_limit=100000, storage_ref=storage)
    counter_int = dummy_frame._addr_to_int(counterparty)
    open_code = (
        _push_bytes(20, 1)
        + _push_bytes(1000, 2)
        + _push_bytes(counter_int, 32)
        + bytes([Op.CHAN_OPEN, Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    )
    open_contract = _deploy_runtime(storage, opener, open_code, "open1a")

    res_open = engine.call(
        caller=opener,
        contract=open_contract,
        calldata=b"",
        call_value=0,
        gas_limit=200_000,
        block_ctx=SimpleNamespace(index=10, timestamp=100, difficulty=1.0, miner_address=opener),
        tx=SimpleNamespace(tx_id="tx_open_1a", gas_price=0.0),
    )
    assert res_open.success
    chan_id_int = int.from_bytes(res_open.return_data, "big")
    assert chan_id_int != 0
    chan_id_hex = format(chan_id_int, "064x")

    # Opener raises dispute with counterparty's signature at block 11
    msg_hash = _chan_state_msg(chan_id_hex, 1, 600, 400)
    r, s = ecdsa_sign_digest(priv_b, msg_hash)
    cd_dispute = (
        chan_id_int.to_bytes(32, "big")
        + (1).to_bytes(32, "big")
        + (600).to_bytes(32, "big")
        + (400).to_bytes(32, "big")
        + r.to_bytes(32, "big")
        + s.to_bytes(32, "big")
    )
    res_disp = engine.call(
        caller=opener,
        contract=one_ret_contract,
        calldata=cd_dispute,
        call_value=0,
        gas_limit=200_000,
        block_ctx=SimpleNamespace(index=11, timestamp=110, difficulty=1.0, miner_address=opener),
        tx=SimpleNamespace(tx_id="tx_disp_1a", gas_price=0.0),
    )
    assert res_disp.success
    assert int.from_bytes(res_disp.return_data, "big") == 2
    assert storage.get_channel(chan_id_hex)["status"] == "DISPUTED"

    # At block 35 (timeout expired), an unauthorized third party calls CHAN_DISPUTE:
    # V4 rejects the unauthorized caller and leaves the channel DISPUTED.
    res_attack = engine.call(
        caller=attacker,
        contract=two_ret_contract,
        calldata=chan_id_int.to_bytes(32, "big") + b"\x00" * 160,
        call_value=0,
        gas_limit=200_000,
        block_ctx=SimpleNamespace(index=35, timestamp=350, difficulty=1.0, miner_address=opener),
        tx=SimpleNamespace(tx_id="tx_attack_1a", gas_price=0.0),
    )
    assert not res_attack.success
    assert storage.get_channel(chan_id_hex)["status"] == "DISPUTED"


def test_chan_dispute_unauthorized_caller_cannot_raise_dispute_on_open_channel(tmp_path):
    storage = Storage(str(tmp_path / "db1b.sqlite"))
    engine = VVMEngine(storage)

    priv_a, opener = _make_keypair(0x1111)
    _, counterparty = _make_keypair(0x2222)
    _, attacker = _make_keypair(0x3333)

    storage.credit_sat(opener, 10_000_000)

    dummy_frame = _VMFrame(code=b"", calldata=b"", caller=opener, address=opener,
                           origin=opener, call_value=0, gas_limit=100000, storage_ref=storage)
    counter_int = dummy_frame._addr_to_int(counterparty)

    open_code = (
        _push_bytes(20, 1)
        + _push_bytes(1000, 2)
        + _push_bytes(counter_int, 32)
        + bytes([Op.CHAN_OPEN, Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    )
    open_contract = _deploy_runtime(storage, opener, open_code, "open1b")
    res_open = engine.call(
        caller=opener,
        contract=open_contract,
        calldata=b"",
        call_value=0,
        gas_limit=200_000,
        block_ctx=SimpleNamespace(index=10, timestamp=100, difficulty=1.0, miner_address=opener),
        tx=SimpleNamespace(tx_id="tx_open_1b", gas_price=0.0),
    )
    chan_id_int = int.from_bytes(res_open.return_data, "big")
    chan_id_hex = format(chan_id_int, "064x")

    # Opener signed a state update (seq=5, opener=300, counterparty=700)
    msg_hash = _chan_state_msg(chan_id_hex, 5, 300, 700)
    r, s = ecdsa_sign_digest(priv_a, msg_hash)

    code = bytearray()
    for off in (160, 128, 96, 64, 32, 0):
        code += bytes([Op.PUSH1, off, Op.CALLDATALOAD])
    code += bytes([
        Op.CHAN_DISPUTE,
        Op.PUSH1, 0, Op.MSTORE,
        Op.PUSH1, 32, Op.MSTORE,
        Op.PUSH1, 64, Op.PUSH1, 0, Op.RETURN,
    ])
    disp_contract = _deploy_runtime(storage, opener, bytes(code), "disp1b")

    # Unauthorized attacker submits opener's signed state
    cd = (
        chan_id_int.to_bytes(32, "big")
        + (5).to_bytes(32, "big")
        + (700).to_bytes(32, "big")
        + (300).to_bytes(32, "big")
        + r.to_bytes(32, "big")
        + s.to_bytes(32, "big")
    )
    res = engine.call(
        caller=attacker,
        contract=disp_contract,
        calldata=cd,
        call_value=0,
        gas_limit=200_000,
        block_ctx=SimpleNamespace(index=12, timestamp=120, difficulty=1.0, miner_address=opener),
        tx=SimpleNamespace(tx_id="tx_attack_1b", gas_price=0.0),
    )
    assert not res.success
    assert storage.get_channel(chan_id_hex)["status"] == "OPEN"


def test_jump_into_push_immediate_jumpdest_rejected(tmp_path):
    storage = Storage(str(tmp_path / "db2.sqlite"))
    engine = VVMEngine(storage)
    _, sender = _make_keypair(0x4444)

    # Offset 0: PUSH1 0x04
    # Offset 2: JUMP
    # Offset 3: PUSH1 0x5B  (0x5B at offset 4 is an immediate byte, NOT a JUMPDEST!)
    bytecode = bytes([
        Op.PUSH1, 0x04,
        Op.JUMP,
        Op.PUSH1, Op.JUMPDEST,
        Op.PUSH1, 0x2A,
        Op.PUSH1, 0x00,
        Op.MSTORE,
        Op.PUSH1, 0x20,
        Op.PUSH1, 0x00,
        Op.RETURN,
    ])

    findings = VVMStaticAnalyzer().analyze(bytecode).findings
    assert any("not a JUMPDEST" in f.description for f in findings)

    contract_addr = _deploy_runtime(storage, sender, bytecode, "jump2")
    res = engine.call(
        caller=sender,
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=100_000,
        block_ctx=SimpleNamespace(index=1, timestamp=10, difficulty=1.0, miner_address=sender),
        tx=SimpleNamespace(tx_id="tx_jump2", gas_price=0.0),
    )
    assert not res.success


def test_rswap_does_not_leak_previous_stack_type_tag_onto_register_value(tmp_path):
    storage = Storage(str(tmp_path / "db3.sqlite"))
    engine = VVMEngine(storage)
    _, sender = _make_keypair(0x5555)

    bytecode = bytes([
        Op.ADDRESS,
        Op.RSWAP_R0,
        Op.PUSH1, Op.VTYPE_ADDRESS,
        Op.TYPEASSERT,
        Op.TYPEOF,
        Op.PUSH1, 0x00,
        Op.MSTORE,
        Op.PUSH1, 0x20,
        Op.PUSH1, 0x00,
        Op.RETURN,
    ])
    contract_addr = _deploy_runtime(storage, sender, bytecode, "rswap3")
    res = engine.call(
        caller=sender,
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=100_000,
        block_ctx=SimpleNamespace(index=1, timestamp=10, difficulty=1.0, miner_address=sender),
        tx=SimpleNamespace(tx_id="tx_rswap3", gas_price=0.0),
    )
    assert not res.success


def test_internal_call_create_produces_distinct_addresses(tmp_path):
    storage = Storage(str(tmp_path / "db4.sqlite"))
    engine = VVMEngine(storage)
    _, sender = _make_keypair(0x6666)

    init_code = bytes([Op.PUSH1, 0x00, Op.PUSH1, 0x00, Op.RETURN])

    factory_code = bytearray()
    for i, b in enumerate(init_code):
        factory_code += bytes([Op.PUSH1, b, Op.PUSH1, i, Op.MSTORE8])
    factory_code += bytes([
        Op.PUSH1, len(init_code),
        Op.PUSH1, 0,
        Op.PUSH1, 0,
        Op.CREATE,
        Op.PUSH1, 0, Op.MSTORE,
        Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN,
    ])
    factory_addr = _deploy_runtime(storage, sender, bytes(factory_code), "factory4")

    dummy_frame = _VMFrame(code=b"", calldata=b"", caller=sender, address=factory_addr,
                           origin=sender, call_value=0, gas_limit=100000, storage_ref=storage)
    factory_int = dummy_frame._addr_to_int(factory_addr)

    caller_code = bytearray()
    for out_off in (0, 32):
        caller_code += bytes([
            Op.PUSH1, 32,
            Op.PUSH1, out_off,
            Op.PUSH1, 0,
            Op.PUSH1, 0,
            Op.PUSH1, 0,
        ])
        caller_code += _push_bytes(factory_int, 32)
        caller_code += bytes([
            Op.PUSH3, 0x03, 0x00, 0x00,
            Op.CALL,
            Op.POP,
        ])
    caller_code += bytes([Op.PUSH1, 64, Op.PUSH1, 0, Op.RETURN])
    caller_addr = _deploy_runtime(storage, sender, bytes(caller_code), "caller4")

    res = engine.call(
        caller=sender,
        contract=caller_addr,
        calldata=b"",
        call_value=0,
        gas_limit=1_000_000,
        block_ctx=SimpleNamespace(index=1, timestamp=10, difficulty=1.0, miner_address=sender),
        tx=SimpleNamespace(tx_id="tx_caller4", gas_price=0.0),
    )
    assert res.success
    addr1 = int.from_bytes(res.return_data[:32], "big")
    addr2 = int.from_bytes(res.return_data[32:64], "big")
    assert addr1 != 0
    assert addr2 != 0
    assert addr1 != addr2
    assert len(res.pending_deployments) == 2
    assert res.pending_deployments[0]["address"] != res.pending_deployments[1]["address"]
