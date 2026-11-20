"""V4 regression tests for Section 74 (Session 06): Execution Frames, Call Depth and Context Isolation."""

import unittest
from types import SimpleNamespace

from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import _ReentrancyGuard, _VMFrame
from visold.vm.opcodes import Op


class _Tx:
    tx_id = "audit_sec74_tx_001"
    gas_price = 0.0


def _push_bytes(val: bytes) -> bytes:
    assert 1 <= len(val) <= 32
    return bytes([Op.PUSH1 + len(val) - 1]) + val


def _push_int(val: int) -> bytes:
    if val == 0:
        return bytes([Op.PUSH1, 0])
    n = (val.bit_length() + 7) // 8
    return bytes([Op.PUSH1 + n - 1]) + val.to_bytes(n, "big")


def _deploy_raw(st: Storage, addr: str, code: bytes, balance_sat: int = 0):
    ch = sha256(code)
    st.save_contract_code(ch, code)
    st.save_contract(
        address=addr,
        code_hash=ch,
        creator="VSDcreator000000000000000000",
        created_at=1,
        contract_name="",
    )
    if balance_sat > 0:
        st.credit_sat(addr, balance_sat)


def _addr_word(addr: str) -> int:
    dummy = _VMFrame(
        code=b"",
        calldata=b"",
        caller=addr,
        address=addr,
        origin=addr,
        call_value=0,
        gas_limit=1000,
        storage_ref=None,  # type: ignore[arg-type]
    )
    return dummy._addr_to_int(addr)


class TestAuditSection74(unittest.TestCase):
    def test_create_blocked_at_max_call_depth(self):
        """Op.CREATE is rejected when caller frame is at Config.VVM_MAX_CALL_DEPTH."""
        st = Storage(":memory:")
        engine = VVMEngine(st)
        caller = "VSDcaller0000000000000000000"
        callee = "VSDc" + "aa" * 18
        _deploy_raw(st, callee, bytes([Op.STOP]))

        init_code = bytes([
            Op.PUSH1, 0x00, Op.PUSH1, 0x00, Op.MSTORE8,
            Op.PUSH1, 0x01, Op.PUSH1, 0x00, Op.RETURN,
        ])
        padded_init = init_code.ljust(32, b"\x00")
        parent_code = (
            _push_bytes(padded_init)
            + bytes([Op.PUSH1, 0x00, Op.MSTORE])
            + bytes([Op.PUSH1, len(init_code), Op.PUSH1, 0x00, Op.PUSH1, 0x00, Op.CREATE])
            + bytes([Op.PUSH1, 0x00, Op.SSTORE, Op.STOP])
        )

        guard = _ReentrancyGuard()
        guard.enter(caller)
        frame = _VMFrame(
            code=parent_code,
            calldata=b"",
            caller=caller,
            address=caller,
            origin=caller,
            call_value=0,
            gas_limit=5_000_000,
            storage_ref=st,
            depth=Config.VVM_MAX_CALL_DEPTH,
            block_ctx=SimpleNamespace(index=1, timestamp=100, difficulty=1.0, miner_address=caller),
            execution_id="depth_test",
            reentrance_guard=guard,
        )

        ok_call, _ = engine._internal_call(
            caller_frame=frame,
            callee_addr=callee,
            calldata=b"",
            call_value=0,
            gas=100_000,
        )
        self.assertFalse(ok_call)

        engine._execute(frame)
        self.assertFalse(frame.reverted, frame.output)
        created_addr_int = frame.storage_writes.get((caller, "0x0"), 0)
        self.assertEqual(created_addr_int, 0)
        self.assertEqual(len(frame.pending_deployments), 0)

    def test_create_and_create2_preserve_reentrancy_guard(self):
        """Op.CREATE preserves the active _ReentrancyGuard so init_code cannot re-enter ancestor."""
        st = Storage(":memory:")
        engine = VVMEngine(st)
        caller = "VSDcaller0000000000000000000"
        victim = "VSDc" + "11" * 18
        victim_word = _addr_word(victim)

        init_reenter = (
            bytes([Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0])
            + _push_int(victim_word)
            + _push_int(50_000)
            + bytes([Op.CALL])
            + bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
        )
        assert len(init_reenter) <= 64
        word0 = init_reenter[:32].ljust(32, b"\x00")
        word1 = init_reenter[32:].ljust(32, b"\x00")

        body_part = (
            bytes([Op.PUSH1, 1, Op.PUSH1, 0, Op.SSTORE])
            + _push_bytes(word0) + bytes([Op.PUSH1, 0, Op.MSTORE])
            + _push_bytes(word1) + bytes([Op.PUSH1, 32, Op.MSTORE])
            + bytes([Op.PUSH1, len(init_reenter), Op.PUSH1, 0, Op.PUSH1, 0, Op.CREATE])
            + bytes([Op.POP, Op.STOP])
        )
        reentry_offset = 6 + len(body_part)
        victim_code = (
            bytes([Op.PUSH1, 0, Op.SLOAD, Op.PUSH1, reentry_offset, Op.JUMPI])
            + body_part
            + bytes([Op.JUMPDEST, Op.PUSH2, 0xCA, 0xFE, Op.PUSH1, 1, Op.SSTORE, Op.STOP])
        )
        _deploy_raw(st, victim, victim_code)

        res = engine.call(
            caller=caller,
            contract=victim,
            calldata=b"",
            call_value=0,
            gas_limit=2_000_000,
            block_ctx=SimpleNamespace(index=1, timestamp=100, difficulty=1.0, miner_address=caller),
            tx=_Tx(),
        )
        self.assertTrue(res.success, res.revert_reason)
        self.assertIsNone(res.storage_writes.get((victim, "0x1")))

    def test_internal_call_merges_create_nonce_deltas(self):
        """_internal_call() merges create_nonce_deltas so repeated factory CREATEs produce distinct addresses."""
        st = Storage(":memory:")
        engine = VVMEngine(st)
        caller = "VSDcaller0000000000000000000"
        factory = "VSDc" + "22" * 18
        parent = "VSDc" + "33" * 18

        init_code = bytes([
            Op.PUSH1, 0x42, Op.PUSH1, 0x00, Op.MSTORE8,
            Op.PUSH1, 0x01, Op.PUSH1, 0x00, Op.RETURN,
        ])
        init_word = init_code.ljust(32, b"\x00")
        factory_code = (
            _push_bytes(init_word)
            + bytes([Op.PUSH1, 0, Op.MSTORE])
            + bytes([Op.PUSH1, len(init_code), Op.PUSH1, 0, Op.PUSH1, 0, Op.CREATE])
            + bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
        )
        _deploy_raw(st, factory, factory_code)

        factory_word = _addr_word(factory)
        parent_code = (
            bytes([Op.PUSH1, 32, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0])
            + _push_int(factory_word) + _push_int(500_000) + bytes([Op.CALL, Op.POP])
            + bytes([Op.PUSH1, 0, Op.MLOAD, Op.PUSH1, 0, Op.SSTORE])
            + bytes([Op.PUSH1, 32, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0])
            + _push_int(factory_word) + _push_int(500_000) + bytes([Op.CALL, Op.POP])
            + bytes([Op.PUSH1, 0, Op.MLOAD, Op.PUSH1, 1, Op.SSTORE, Op.STOP])
        )
        _deploy_raw(st, parent, parent_code)

        res = engine.call(
            caller=caller,
            contract=parent,
            calldata=b"",
            call_value=0,
            gas_limit=3_000_000,
            block_ctx=SimpleNamespace(index=1, timestamp=100, difficulty=1.0, miner_address=caller),
            tx=_Tx(),
        )
        self.assertTrue(res.success, res.revert_reason)
        addr1 = res.storage_writes[(parent, "0x0")]
        addr2 = res.storage_writes[(parent, "0x1")]
        self.assertNotEqual(addr1, 0)
        self.assertNotEqual(addr2, 0)
        self.assertNotEqual(addr1, addr2)
        self.assertEqual(len(res.pending_deployments), 2)
        self.assertNotEqual(
            res.pending_deployments[0]["address"],
            res.pending_deployments[1]["address"],
        )

    def test_internal_call_child_sees_pending_deployment_extcodesize(self):
        """Unfixed in V4: EXTCODESIZE on pending CREATE deployment returns 0 in child frame; see remaining_071_080.md."""
        st = Storage(":memory:")
        engine = VVMEngine(st)
        caller = "VSDcaller0000000000000000000"
        init_code = bytes([
            Op.PUSH1, 0x42, Op.PUSH1, 0x00, Op.MSTORE8,
            Op.PUSH1, 0x01, Op.PUSH1, 0x00, Op.RETURN,
        ])
        init_word = init_code.ljust(32, b"\x00")
        inspector = "VSDc" + "44" * 18
        inspector_code = bytes([
            Op.PUSH1, 0, Op.CALLDATALOAD, Op.EXTCODESIZE,
            Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN,
        ])
        _deploy_raw(st, inspector, inspector_code)
        inspector_word = _addr_word(inspector)

        parent2 = "VSDc" + "55" * 18
        parent2_code = (
            _push_bytes(init_word) + bytes([Op.PUSH1, 0, Op.MSTORE])
            + bytes([Op.PUSH1, len(init_code), Op.PUSH1, 0, Op.PUSH1, 0, Op.CREATE])
            + bytes([Op.PUSH1, 0, Op.MSTORE])
            + bytes([Op.PUSH1, 32, Op.PUSH1, 32, Op.PUSH1, 32, Op.PUSH1, 0, Op.PUSH1, 0])
            + _push_int(inspector_word) + _push_int(500_000) + bytes([Op.CALL, Op.POP])
            + bytes([Op.PUSH1, 32, Op.MLOAD, Op.PUSH1, 0, Op.SSTORE, Op.STOP])
        )
        _deploy_raw(st, parent2, parent2_code)
        res2 = engine.call(
            caller=caller,
            contract=parent2,
            calldata=b"",
            call_value=0,
            gas_limit=3_000_000,
            block_ctx=SimpleNamespace(index=1, timestamp=100, difficulty=1.0, miner_address=caller),
            tx=_Tx(),
        )
        self.assertTrue(res2.success, res2.revert_reason)
        self.assertNotEqual(res2.storage_writes[(parent2, "0x0")], 0)

    def test_selfdestruct_zeroes_balance_and_prevents_double_spend(self):
        """Op.SELFDESTRUCT zeroes target's balance immediately, preventing double-spend."""
        st = Storage(":memory:")
        engine = VVMEngine(st)
        caller = "VSDcaller0000000000000000000"
        driver = "VSDc" + "66" * 18
        target = "VSDc" + "77" * 18
        beneficiary = "VSDc" + "88" * 18
        recipient = "VSDc" + "99" * 18

        ben_word = _addr_word(beneficiary)
        rec_word = _addr_word(recipient)
        tgt_word = _addr_word(target)

        transfer_branch = (
            bytes([Op.JUMPDEST, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0])
            + bytes([Op.PUSH1, 100])
            + _push_int(rec_word)
            + _push_int(50_000)
            + bytes([Op.CALL, Op.POP, Op.STOP])
        )
        sd_branch = _push_int(ben_word) + bytes([Op.SELFDESTRUCT])
        jump_dest = 4 + len(sd_branch)
        target_code = (
            bytes([Op.CALLDATASIZE, Op.PUSH1, jump_dest, Op.JUMPI])
            + sd_branch
            + transfer_branch
        )
        _deploy_raw(st, target, target_code, balance_sat=100)

        driver_code = (
            bytes([Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0])
            + _push_int(tgt_word) + _push_int(100_000) + bytes([Op.CALL, Op.POP])
            + _push_int(tgt_word) + bytes([Op.BALANCE, Op.PUSH1, 0, Op.SSTORE])
            + bytes([Op.PUSH1, 1, Op.PUSH1, 0, Op.MSTORE8])
            + bytes([Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 1, Op.PUSH1, 0, Op.PUSH1, 0])
            + _push_int(tgt_word) + _push_int(100_000) + bytes([Op.CALL])
            + bytes([Op.PUSH1, 1, Op.SSTORE, Op.STOP])
        )
        _deploy_raw(st, driver, driver_code)

        res = engine.call(
            caller=caller,
            contract=driver,
            calldata=b"",
            call_value=0,
            gas_limit=2_000_000,
            block_ctx=SimpleNamespace(index=1, timestamp=100, difficulty=1.0, miner_address=caller),
            tx=_Tx(),
        )
        self.assertTrue(res.success, res.revert_reason)
        self.assertEqual(res.storage_writes[(driver, "0x0")], 0)
        self.assertEqual(res.balance_deltas.get(recipient, 0), 0)
        self.assertEqual(res.self_destruct_transfers, [(target, beneficiary, 100)])
