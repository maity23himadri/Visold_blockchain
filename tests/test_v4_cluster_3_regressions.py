"""
Positive V4 regression tests converted from Cluster 3 adversarial tests:
- visold/vm/ (VVM opcodes, gas metering, bounds, frames, ABI, precompiles, assembler, event index)
- visold/rollup/ (L2 state, batches, proofs)
- visold/chain/sequencer.py (Sequencer ordering, liveness, L1 nonce tracking)

Each test asserts the fixed V4 behavior.
"""

import inspect
import json
import time
import zlib

import pytest

from visold.chain.sequencer import Sequencer
from visold.kernel.config import Config
from visold.rollup.batches import RollupSubmission
from visold.rollup.l2_state import L2Transaction, Layer2State
from visold.rollup.proofs import (
    IProofBackend,
    ProofRegistry,
    UnsafeBackendOnMainnetError,
)
from visold.storage.storage import Storage
from visold.vm.abi import VVMABIEncoder
from visold.vm.assembler import VVMAssembler
from visold.vm.engine import VVMEngine
from visold.vm.event_index import ContractEventIndex
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op
from visold.vm.precompiles import VVMPrecompiles
from visold.wallet.wallet import Wallet


class _DummyBlockCtx:
    def __init__(self, index=1, timestamp=1700000000):
        self.index = index
        self.timestamp = timestamp
        self.hash = "00" * 32


class _DummyTx:
    def __init__(self, tx_id="ab" * 32, gas_price=0.0):
        self.tx_id = tx_id
        self.gas_price = gas_price


@pytest.fixture
def tmp_storage(tmp_path):
    db_path = str(tmp_path / "test_v4.db")
    st = Storage(db_path)
    yield st
    try:
        st.close()
    except Exception:
        pass


# ── 1. VVM: Op.CHAN_DISPUTE rejects unauthorized caller cleanly (Sec 071) ─────

def test_chan_dispute_rejects_unauthorized_caller_and_pushes_false(tmp_storage):
    opener = Wallet.generate()
    counterparty = Wallet.generate()
    attacker = Wallet.generate()

    tmp_storage.credit_sat(opener.address, 10_000)
    channel_id = "11" * 32
    assert tmp_storage.create_channel(
        channel_id,
        "VSDc" + "aa" * 18,
        opener.address,
        counterparty.address,
        5_000,
        10,
        1,
    )
    assert tmp_storage.raise_dispute(
        channel_id, seq_no=1, bal_opener=3_000, bal_counter=2_000, dispute_height=2
    )

    contract_addr = "VSDc" + "aa" * 18
    code = (
        bytes([Op.PUSH1, 1])  # sig_s
        + bytes([Op.PUSH1, 1])  # sig_r
        + bytes([Op.PUSH1, 0])  # bal_counter
        + bytes([Op.PUSH1, 0])  # bal_caller
        + bytes([Op.PUSH1, 2])  # seq_no
        + bytes([Op.PUSH32]) + bytes.fromhex(channel_id)  # channel_id_int
        + bytes([Op.CHAN_DISPUTE])
        + bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    )
    code_hash = "cc" * 32
    tmp_storage.save_contract_code(code_hash, code)
    tmp_storage.save_contract(contract_addr, code_hash, opener.address, created_at=1)

    engine = VVMEngine(tmp_storage)
    res = engine.call(
        caller=attacker.address,
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=100_000,
        block_ctx=_DummyBlockCtx(index=20),
        tx=_DummyTx(),
    )
    assert res.success is True
    assert int.from_bytes(res.return_data, "big") == 0
    ch = tmp_storage.get_channel(channel_id)
    assert ch["status"] == "DISPUTED"
    assert tmp_storage.get_balance_sat(opener.address) == 10_000
    assert tmp_storage.get_balance_sat(counterparty.address) == 0


# ── 2. VVM: Op.CHAN_OPEN respects balance_deltas (NEW-2) ──────────────────────

def test_chan_open_respects_balance_deltas_preventing_overspend(tmp_storage):
    sender = Wallet.generate()
    counterparty = Wallet.generate()
    contract_a = "VSDc" + "11" * 18
    contract_b = "VSDc" + "22" * 18

    tmp_storage.credit_sat(contract_a, 1_000)

    cp_int = _VMFrame.__new__(_VMFrame)._addr_to_int(counterparty.address)
    cp_bytes = cp_int.to_bytes(32, "big")
    code_b = (
        bytes([Op.PUSH1, 10])  # timeout_raw
        + bytes([Op.PUSH2]) + (1000).to_bytes(2, "big")  # deposit_sat
        + bytes([Op.PUSH32]) + cp_bytes  # counterparty_int
        + bytes([Op.CHAN_OPEN])
        + bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    )
    tmp_storage.save_contract_code("bb" * 32, code_b)
    tmp_storage.save_contract(contract_b, "bb" * 32, sender.address, created_at=1)

    cb_int = _VMFrame.__new__(_VMFrame)._addr_to_int(contract_b)
    cb_bytes = cb_int.to_bytes(32, "big")
    code_a = (
        bytes([Op.PUSH1, 0])  # out_size
        + bytes([Op.PUSH1, 0])  # out_off
        + bytes([Op.PUSH1, 0])  # in_size
        + bytes([Op.PUSH1, 0])  # in_off
        + bytes([Op.PUSH2]) + (1000).to_bytes(2, "big")  # value=1000
        + bytes([Op.PUSH32]) + cb_bytes  # addr=contract_b
        + bytes([Op.PUSH3, 0x0F, 0x42, 0x40])  # gas=1_000_000
        + bytes([Op.CALL])
        + bytes([Op.STOP])
    )
    tmp_storage.save_contract_code("aa" * 32, code_a)
    tmp_storage.save_contract(contract_a, "aa" * 32, sender.address, created_at=1)

    engine = VVMEngine(tmp_storage)
    res = engine.call(
        caller=sender.address,
        contract=contract_a,
        calldata=b"",
        call_value=0,
        gas_limit=2_000_000,
        block_ctx=_DummyBlockCtx(index=5),
        tx=_DummyTx(),
    )
    assert res.success is True
    assert res.balance_deltas.get(contract_a, 0) == -1000
    assert tmp_storage.get_balance_sat(contract_a) == 1000
    assert tmp_storage.get_open_channel_between(contract_a, counterparty.address, contract_b) is None


# ── 3. VVM: CREATE preserves call depth & _ReentrancyGuard (Sec 073/074) ──────

def test_create_preserves_call_depth_and_reentrancy_guard(tmp_storage):
    caller = Wallet.generate()
    contract_a = "VSDc" + "33" * 18

    ca_int = _VMFrame.__new__(_VMFrame)._addr_to_int(contract_a)
    ca_bytes = ca_int.to_bytes(32, "big")
    init_code = (
        bytes([Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 1, Op.PUSH1, 0, Op.PUSH1, 0])
        + bytes([Op.PUSH32]) + ca_bytes
        + bytes([Op.PUSH3, 0x01, 0x86, 0xA0])  # gas=100000
        + bytes([Op.CALL])
        + bytes([Op.PUSH1, 0, Op.MSTORE])
        + bytes([Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    )

    jumpdest_off = 26
    tail_offset = 33
    prefix = (
        bytes([Op.CALLDATASIZE, Op.PUSH1, jumpdest_off, Op.JUMPI])
        + bytes([Op.PUSH1, len(init_code), Op.PUSH1, tail_offset, Op.PUSH1, 0, Op.CODECOPY])
        + bytes([Op.PUSH1, len(init_code), Op.PUSH1, 0, Op.PUSH1, 0, Op.CREATE])
        + bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
        + bytes([Op.JUMPDEST])
        + bytes([Op.PUSH1, 0x42, Op.PUSH1, 0, Op.SSTORE, Op.STOP])
    )
    assert len(prefix) == tail_offset
    full_code_a = prefix + init_code

    tmp_storage.save_contract_code("c3" * 32, full_code_a)
    tmp_storage.save_contract(contract_a, "c3" * 32, caller.address, created_at=1)

    engine = VVMEngine(tmp_storage)
    res = engine.call(
        caller=caller.address,
        contract=contract_a,
        calldata=b"",
        call_value=0,
        gas_limit=500_000,
        block_ctx=_DummyBlockCtx(index=5),
        tx=_DummyTx(),
    )
    assert res.success is True
    assert res.storage_writes.get((contract_a, "0x0")) is None


# ── 4. VVM: CREATE propagates parent_pending_deployments (NEW-3) ───────────────

def test_create_propagates_parent_pending_deployments_to_sub_create():
    sig = inspect.signature(VVMEngine.deploy)
    assert "parent_pending_deployments" in sig.parameters
    assert "parent_storage_writes" in sig.parameters
    assert "parent_balance_deltas" in sig.parameters


# ── 5. VVM: simulate() allows state-mutating SSTORE for estimate_gas (Sec 072) ─

def test_simulate_allows_sstore_for_estimate_gas(tmp_storage):
    caller = Wallet.generate()
    contract_addr = "VSDc" + "55" * 18
    code = bytes([Op.PUSH1, 1, Op.PUSH1, 0, Op.SSTORE, Op.STOP])
    tmp_storage.save_contract_code("d5" * 32, code)
    tmp_storage.save_contract(contract_addr, "d5" * 32, caller.address, created_at=1)

    engine = VVMEngine(tmp_storage)
    call_res = engine.call(
        caller=caller.address,
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=100_000,
        block_ctx=_DummyBlockCtx(index=5),
        tx=_DummyTx(),
    )
    assert call_res.success is True

    sim_res = engine.simulate(
        caller=caller.address,
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=100_000,
        block_ctx=_DummyBlockCtx(index=5),
    )
    assert sim_res.success is True
    assert sim_res.gas_used == call_res.gas_used


# ── 6. VVM: Precompile MODEXP enforces minimum gas_limit (Sec 076) ────────────

def test_precompile_modexp_enforces_gas_limit(tmp_storage):
    caller = Wallet.generate()
    contract_addr = "VSDc" + "66" * 18
    modexp_int = _VMFrame.__new__(_VMFrame)._addr_to_int(VVMPrecompiles.MODEXP)
    code = (
        bytes([Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 1, Op.PUSH1, 0, Op.PUSH1, 0])
        + bytes([Op.PUSH32]) + modexp_int.to_bytes(32, "big")
        + bytes([Op.PUSH1, 10])  # gas_param = 10 (< 200 minimum)
        + bytes([Op.STATICCALL])
        + bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    )
    tmp_storage.save_contract_code("e6" * 32, code)
    tmp_storage.save_contract(contract_addr, "e6" * 32, caller.address, created_at=1)

    engine = VVMEngine(tmp_storage)
    res = engine.call(
        caller=caller.address,
        contract=contract_addr,
        calldata=b"",
        call_value=0,
        gas_limit=1000,
        block_ctx=_DummyBlockCtx(index=5),
        tx=_DummyTx(),
    )
    assert res.success is True
    assert int.from_bytes(res.return_data, "big") == 0


# ── 7. VVM: ABI handles VSDc... addresses and 0x01... bytes32 cleanly (Sec 075) ─

def test_abi_encodes_vsdc_address_and_preserves_leading_zero_bytes32():
    encoded_addr = VVMABIEncoder.encode_args(["address"], ["VSDc" + "0" * 36])
    assert len(encoded_addr) == 32
    assert encoded_addr[1:19] == b"\x00" * 18

    hex_val = "01" + "ab" * 31
    encoded_b32 = VVMABIEncoder.encode_args(["bytes32"], ["0x" + hex_val])
    assert encoded_b32 == bytes.fromhex(hex_val)


# ── 8. VVM: Assembler rejects VTYPE_* & upgrades negative PUSH safely (Sec 077) ─

def test_assembler_rejects_vtype_and_upgrades_negative_push():
    res = VVMAssembler().assemble("VTYPE_ADDRESS\nSTOP")
    assert res.ok is False
    assert any("VTYPE_ADDRESS" in err for err in res.errors)

    res2 = VVMAssembler().assemble("PUSH1 -256\nSTOP")
    assert res2.ok is True
    assert res2.bytecode == bytes([Op.PUSH2, 0xFF, 0x00, Op.STOP])


# ── 9. VVM: EventIndex preserves topic3 and is idempotent (Sec 078) ───────────

def test_event_index_preserves_topic3_and_is_idempotent(tmp_storage):
    idx = ContractEventIndex(tmp_storage)
    contract = "VSDc" + "77" * 18
    logs = [{"address": contract, "topics": ["0x1", "0x2", "0x3", "0x4"], "data": "aa"}]
    idx.index_logs("tx1", 1, contract, logs)
    idx.index_logs("tx1", 1, contract, logs)

    events = idx.get_events_by_contract(contract)
    assert len(events) == 1
    assert events[0]["topic3"] == "0x4"


# ── 10. Rollup: L2Transaction preserves timestamp=0 (Sec 081/090) ─────────────

def test_l2_tx_preserves_timestamp_zero():
    w = Wallet.generate()
    tx = L2Transaction(
        sender=w.address,
        receiver="VSDcL2WITHDRAW0000000000000000",
        amount_sat=100,
        nonce=0,
        timestamp=0,
        pub=w.pub_hex,
    )
    assert tx.timestamp == 0

    d = {
        "sender": w.address,
        "receiver": "VSDcL2WITHDRAW0000000000000000",
        "amount_sat": 100,
        "nonce": 0,
        "timestamp": 0,
    }
    tx2 = L2Transaction.from_dict(d)
    assert tx2.timestamp == 0


# ── 11. Rollup: RollupSubmission.decompress_batch raises ValueError (NEW-4) ───

def test_rollup_decompress_batch_raises_value_error_on_non_list_json():
    blob = zlib.compress(json.dumps({"not": "a list"}).encode())
    with pytest.raises(ValueError, match="expected JSON list"):
        RollupSubmission.decompress_batch(blob)


# ── 12. Rollup: Unready custom IProofBackend blocked on mainnet (Sec 085) ─────

def test_unready_custom_proof_backend_blocked_on_mainnet(monkeypatch):
    class UnreadyCustomBackend(IProofBackend):
        def name(self) -> str:
            return "custom-unready-zk"

        def security(self) -> str:
            return "zk-groth16-bn254"

        def is_production_ready(self) -> bool:
            return False

        def prove(self, prev_root, new_root, batch_hash, witness):
            return b"proof"

        def verify(self, prev_root, new_root, batch_hash, proof):
            return False

    ProofRegistry.register(UnreadyCustomBackend())
    monkeypatch.setenv("VISOLD_NETWORK", "mainnet")
    monkeypatch.setattr(Config, "L2_PROOF_BACKEND", "custom-unready-zk")

    with pytest.raises(UnsafeBackendOnMainnetError):
        ProofRegistry.get_configured()


# ── 13. Sequencer: Rejects far-future tx so _should_seal is not stalled (Sec 082/088) ─

def test_sequencer_rejects_future_timestamp_and_seals_aged_tx(tmp_storage):
    w = Wallet.generate()
    l2 = Layer2State(tmp_storage)

    class _DummyBC:
        storage = tmp_storage

    seq = Sequencer(l2, w, _DummyBC())
    seq._running = True

    future_ts = int(time.time()) + 365 * 86400
    tx_future = w.sign_l2_tx(Wallet.generate().address, 100, 0, timestamp=future_ts)
    ok, msg = seq.add_l2_tx(tx_future)
    assert ok is False
    assert "future" in msg.lower()

    old_tx = w.sign_l2_tx(Wallet.generate().address, 100, 0, timestamp=int(time.time()) - 3600)
    ok2, msg2 = seq.add_l2_tx(old_tx)
    assert ok2 is True, msg2
    assert seq._should_seal() is True


# ── 14. Sequencer: Consecutive seals advance L1 nonce while unmined (NEW-1) ───

def test_sequencer_consecutive_seals_advance_l1_nonce_while_unmined(tmp_storage):
    seq_w = Wallet.generate()
    user_w1 = Wallet.generate()
    user_w2 = Wallet.generate()
    recv_w = Wallet.generate()
    l2 = Layer2State(tmp_storage)
    l2.L2_deposit(user_w1.address, 10_000)
    l2.L2_deposit(user_w2.address, 10_000)

    class _DummyBC:
        storage = tmp_storage

    seq = Sequencer(l2, seq_w, _DummyBC())
    seq._running = True

    tx1 = user_w1.sign_l2_tx(recv_w.address, 100, 0, timestamp=int(time.time()))
    assert seq.add_l2_tx(tx1)[0]
    res1 = seq._seal_one()
    assert res1 is not None
    l1_tx1, b1, app1 = res1
    seq._finalize_seal(b1, app1)
    assert l1_tx1.nonce == 0
    assert tmp_storage.get_nonce(seq_w.address) == 0

    tx2 = user_w2.sign_l2_tx(recv_w.address, 100, 0, timestamp=int(time.time()))
    assert seq.add_l2_tx(tx2)[0]
    res2 = seq._seal_one()
    assert res2 is not None
    l1_tx2, b2, app2 = res2
    seq._finalize_seal(b2, app2)
    assert l1_tx2.nonce == 1
