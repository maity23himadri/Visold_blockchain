from __future__ import annotations

import os
import tempfile
import time
from types import SimpleNamespace

from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op
from visold.wallet.wallet import Wallet


class _Tx:
    gas_price = 0.0
    tx_id = "0" * 64


def _install(st: Storage, address: str, runtime: bytes, creator: str) -> None:
    code_hash = sha256(runtime)
    st.save_contract_code(code_hash, runtime)
    st.save_contract(address, code_hash, creator, int(time.time()))


def _push1(value: int) -> bytes:
    return bytes((Op.PUSH1, value & 0xFF))


def _push32(value: int) -> bytes:
    return bytes((Op.PUSH32,)) + int(value).to_bytes(32, "big")


def _chan_open_runtime(counterparty: str, deposit_sat: int = 100, *, revert: bool) -> bytes:
    frame = _VMFrame.__new__(_VMFrame)
    counterparty_word = frame._addr_to_int(counterparty)
    runtime = (
        _push1(10)
        + bytes((Op.PUSH2, (deposit_sat >> 8) & 0xFF, deposit_sat & 0xFF))
        + _push32(counterparty_word)
        + bytes((Op.CHAN_OPEN,))
    )
    if revert:
        runtime += _push1(0) + _push1(0) + bytes((Op.REVERT,))
    else:
        runtime += bytes((Op.STOP,))
    return runtime


def _call_runtime(callee: str, gas: int = 100_000) -> bytes:
    callee_word = _VMFrame.__new__(_VMFrame)._addr_to_int(callee)
    gas_bytes = int(gas).to_bytes(4, "big")
    push_gas = bytes((Op.PUSH4,)) + gas_bytes
    return (
        _push1(0)  # out_size
        + _push1(0)  # out_off
        + _push1(0)  # in_size
        + _push1(0)  # in_off
        + _push1(0)  # value
        + _push32(callee_word)
        + push_gas
        + bytes((Op.CALL, Op.STOP))
    )


def _block_ctx(height: int = 100):
    return SimpleNamespace(index=height, timestamp=1_000_000, miner_address="", difficulty=1.0)


def test_nested_call_revert_rolls_back_direct_channel_and_balance_side_effects():
    """A reverted child CALL must not leak CHAN_OPEN into persistent state."""
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "nested_channel_revert.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        counterparty = Wallet.generate()
        parent = "VSDc" + "61" * 18
        child = "VSDc" + "62" * 18

        _install(st, child, _chan_open_runtime(counterparty.address, 50, revert=True), wallet.address)
        _install(st, parent, _call_runtime(child), wallet.address)
        st.credit_sat(parent, 1000)

        result = vm.call(
            caller=wallet.address, contract=parent, calldata=b"", call_value=0,
            gas_limit=500_000, block_ctx=_block_ctx(), tx=_Tx())

        assert result.success, result.revert_reason
        assert st.get_balance_sat(parent) == 1000
        assert st.get_open_channel_between(
            parent, counterparty.address, child) is None
        assert not st._state_channel_journal_stack()


def test_nested_call_revert_preserves_parent_channel_mutation():
    """Child rollback must not erase a successful direct mutation by its parent."""
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "nested_channel_parent.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        parent_cp = Wallet.generate()
        child_cp = Wallet.generate()
        parent = "VSDc" + "63" * 18
        child = "VSDc" + "64" * 18

        parent_open = _chan_open_runtime(parent_cp.address, 100, revert=False)
        parent_runtime = parent_open[:-1] + _call_runtime(child)  # replace STOP with CALL; CALL ends in STOP
        _install(st, child, _chan_open_runtime(child_cp.address, 50, revert=True), wallet.address)
        _install(st, parent, parent_runtime, wallet.address)
        st.credit_sat(wallet.address, 1000)

        result = vm.call(
            caller=wallet.address, contract=parent, calldata=b"", call_value=0,
            gas_limit=500_000, block_ctx=_block_ctx(), tx=_Tx())

        assert result.success, result.revert_reason
        assert st.get_balance_sat(wallet.address) == 900
        assert st.get_open_channel_between(
            wallet.address, parent_cp.address, parent) is not None
        assert st.get_open_channel_between(
            parent, child_cp.address, child) is None
        assert not st._state_channel_journal_stack()


def test_nested_call_success_commits_direct_channel_and_balance_side_effects():
    """A successful child CALL must keep its direct state-channel mutation."""
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "nested_channel_success.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        counterparty = Wallet.generate()
        parent = "VSDc" + "67" * 18
        child = "VSDc" + "68" * 18

        _install(st, child, _chan_open_runtime(counterparty.address, 50, revert=False), wallet.address)
        _install(st, parent, _call_runtime(child), wallet.address)
        st.credit_sat(parent, 1000)

        result = vm.call(
            caller=wallet.address, contract=parent, calldata=b"", call_value=0,
            gas_limit=500_000, block_ctx=_block_ctx(), tx=_Tx())

        assert result.success, result.revert_reason
        assert st.get_balance_sat(parent) == 950
        assert st.get_open_channel_between(
            parent, counterparty.address, child) is not None
        assert not st._state_channel_journal_stack()


def test_nested_call_success_is_rolled_back_by_parent_revert():
    """A successful child channel mutation must still belong to the parent transaction."""
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "nested_channel_parent_revert.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        counterparty = Wallet.generate()
        parent = "VSDc" + "65" * 18
        child = "VSDc" + "66" * 18

        _install(st, child, _chan_open_runtime(counterparty.address, 50, revert=False), wallet.address)
        parent_runtime = _call_runtime(child)[:-1] + _push1(0) + _push1(0) + bytes((Op.REVERT,))
        _install(st, parent, parent_runtime, wallet.address)
        st.credit_sat(parent, 1000)

        result = vm.call(
            caller=wallet.address, contract=parent, calldata=b"", call_value=0,
            gas_limit=500_000, block_ctx=_block_ctx(), tx=_Tx())

        assert result.success is False
        assert st.get_balance_sat(parent) == 1000
        assert st.get_open_channel_between(
            parent, counterparty.address, child) is None
        assert not st._state_channel_journal_stack()


def test_address_encoding_is_lossless_and_balance_opcode_uses_real_contract_address():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "audit.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        contract = "VSDc" + "ab" * 18

        frame = _VMFrame.__new__(_VMFrame)
        for address in (wallet.address, contract, "VSDclegacy-not-hex", "VSDprecompile"):
            assert frame._int_to_addr(frame._addr_to_int(address)) == address

        runtime = bytes((Op.ADDRESS, Op.BALANCE)) + _push1(0) + bytes((Op.MSTORE,)) \
            + _push1(32) + _push1(0) + bytes((Op.RETURN,))
        _install(st, contract, runtime, wallet.address)
        st.credit_sat(contract, 123)
        result = vm.call(
            caller=wallet.address, contract=contract, calldata=b"", call_value=0,
            gas_limit=500_000, block_ctx=None, tx=_Tx())
        assert result.success, result.revert_reason
        assert int.from_bytes(result.return_data, "big") == 123


def test_value_transfer_is_visible_to_selfbalance_during_execution():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "audit.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        contract = "VSDc" + "44" * 18
        # SELFBALANCE; return the 32-byte result.
        runtime = bytes((Op.SELFBALANCE,)) + _push1(0) + bytes((Op.MSTORE,)) \
            + _push1(32) + _push1(0) + bytes((Op.RETURN,))
        _install(st, contract, runtime, wallet.address)
        st.credit_sat(contract, 100)
        result = vm.call(
            caller=wallet.address, contract=contract, calldata=b"", call_value=50,
            gas_limit=500_000, block_ctx=None, tx=_Tx())
        assert result.success, result.revert_reason
        assert int.from_bytes(result.return_data, "big") == 150


def test_typed_storage_persists_and_explicit_default_shadows_old_tag():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "audit.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        writer = "VSDc" + "11" * 18
        reader = "VSDc" + "12" * 18
        clearer = "VSDc" + "13" * 18

        _install(st, writer, _push1(42) + _push1(3) + bytes((Op.TYPESET,)) + _push1(0) + bytes((Op.SSTORE, Op.STOP)), wallet.address)
        r = vm.call(caller=wallet.address, contract=writer, calldata=b"", call_value=0, gas_limit=500_000, block_ctx=None, tx=_Tx())
        assert r.success
        for (addr, slot), value in r.storage_writes.items():
            st.sstore(addr, slot, value)
            st.set_storage_tag(addr, slot, r.storage_tags.get((addr, slot), 0))
        assert st.get_storage_tag(writer, "0x0") == 3

        load = _push1(0) + bytes((Op.TYPEDLOAD, Op.TYPEOF)) + _push1(1) + bytes((Op.SSTORE, Op.STOP))
        _install(st, reader, load, wallet.address)
        st.sstore(reader, "0x0", 42)
        st.set_storage_tag(reader, "0x0", 3)
        r2 = vm.call(caller=wallet.address, contract=reader, calldata=b"", call_value=0, gas_limit=500_000, block_ctx=None, tx=_Tx())
        assert r2.success
        assert r2.storage_writes[(reader, "0x1")] == 3

        clear = _push1(7) + _push1(0) + bytes((Op.SSTORE,)) + _push1(0) + bytes((Op.TYPEDLOAD, Op.TYPEOF)) + _push1(2) + bytes((Op.SSTORE, Op.STOP))
        _install(st, clearer, clear, wallet.address)
        st.sstore(clearer, "0x0", 42)
        st.set_storage_tag(clearer, "0x0", 3)
        r3 = vm.call(caller=wallet.address, contract=clearer, calldata=b"", call_value=0, gas_limit=500_000, block_ctx=None, tx=_Tx())
        assert r3.success
        assert r3.storage_writes[(clearer, "0x2")] == 0


def test_nested_call_value_moves_only_on_success():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "audit.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        caller = "VSDc" + "33" * 18
        callee = "VSDc" + "22" * 18
        bad_callee = "VSDc" + "23" * 18

        _install(st, callee, bytes((Op.SELFBALANCE,)) + _push1(0) + bytes((Op.SSTORE, Op.STOP)), wallet.address)
        callee_word = _VMFrame.__new__(_VMFrame)._addr_to_int(callee)
        call_runtime = _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push1(50) + _push32(callee_word) + bytes((Op.PUSH3, 0x01, 0x86, 0xA0, Op.CALL, Op.STOP))
        _install(st, caller, call_runtime, wallet.address)
        st.credit_sat(caller, 100)
        result = vm.call(caller=wallet.address, contract=caller, calldata=b"", call_value=0, gas_limit=500_000, block_ctx=None, tx=_Tx())
        assert result.success
        assert result.balance_deltas.get(caller) == -50
        assert result.balance_deltas.get(callee) == 50
        # The callee must observe the transferred value immediately, before
        # the parent transaction commits the balance overlay to storage.
        assert result.storage_writes[(callee, "0x0")] == 50

        _install(st, bad_callee, bytes((0xFE,)), wallet.address)
        bad_caller = "VSDc" + "34" * 18
        bad_word = _VMFrame.__new__(_VMFrame)._addr_to_int(bad_callee)
        bad_runtime = _push1(0) + _push1(0) + _push1(0) + _push1(0) + _push1(50) + _push32(bad_word) + bytes((Op.PUSH3, 0x01, 0x86, 0xA0, Op.CALL, Op.STOP))
        _install(st, bad_caller, bad_runtime, wallet.address)
        st.credit_sat(bad_caller, 100)
        failed = vm.call(caller=wallet.address, contract=bad_caller, calldata=b"", call_value=0, gas_limit=500_000, block_ctx=None, tx=_Tx())
        assert failed.success
        assert failed.balance_deltas == {}


def test_create2_constructor_writes_under_published_address():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "audit.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        parent = "VSDc" + "33" * 18
        init = _push1(42) + _push1(0) + bytes((Op.SSTORE, Op.STOP))
        salt = 7
        # CREATE2 copies the init code from the parent's own bytecode into memory.
        prefix_len = 7 + 10
        parent_runtime = _push1(len(init)) + _push1(prefix_len) + _push1(0) + bytes((Op.CODECOPY,))
        parent_runtime += _push1(salt) + _push1(len(init)) + _push1(0) + _push1(0) + bytes((Op.CREATE2, Op.STOP))
        assert len(parent_runtime) == prefix_len
        parent_runtime += init
        _install(st, parent, parent_runtime, wallet.address)

        code_hash = sha256(init)
        expected = "VSDc" + sha256(b"VSDc2" + parent.encode() + salt.to_bytes(32, "big") + code_hash.encode())[:36]
        result = vm.call(caller=wallet.address, contract=parent, calldata=b"", call_value=0, gas_limit=1_000_000, block_ctx=None, tx=_Tx())
        assert result.success, result.revert_reason
        assert [d["address"] for d in result.pending_deployments] == [expected]
        assert result.storage_writes[(expected, "0x0")] == 42


def test_nonfinite_transaction_values_are_rejected():
    wallet = Wallet.generate()
    base = dict(sender=wallet.address, receiver=wallet.address, amount=1.0, fee=0.0,
                nonce=0, tx_type=Transaction.TYPE_TRANSFER, data="", gas_limit=21_000,
                gas_price=Config.VVM_MIN_GAS_PRICE)
    for field, value in (("amount", float("nan")), ("amount", float("inf")),
                         ("fee", float("nan")), ("gas_price", float("-inf"))):
        args = dict(base)
        args[field] = value
        tx = Transaction(**args)
        tx.sign(wallet)
        ok, _ = tx.is_valid()
        assert not ok


def test_snapshot_rejects_orphan_typed_storage_metadata():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "audit.db"))
        wallet = Wallet.generate()
        contract = "VSDc" + "aa" * 18
        code = bytes((Op.STOP,))
        h = sha256(code)
        st.save_contract_code(h, code)
        st.save_contract(contract, h, wallet.address, int(time.time()))
        root = st._compute_contract_storage_root(contract)
        payload = {
            "version": 3, "height": 1, "anchor_block_hash": "x", "state_root": root,
            "balances": {}, "nonces": {}, "contracts": {contract: {"code_hash": h, "storage_root": root, "nonce": 0, "creator": wallet.address, "created_at": 1, "name": ""}},
            "contract_code": {h: code.hex()}, "contract_storage": {contract: {}},
            "contract_storage_tags": {"VSDc" + "bb" * 18: {"0x0": 3}},
            "roles": {}, "name_claims": {}, "state_channels": {},
        }
        try:
            st.restore_snapshot_state(payload)
        except ValueError as exc:
            assert "unknown contract" in str(exc)
        else:
            raise AssertionError("orphan typed-storage metadata was accepted")
