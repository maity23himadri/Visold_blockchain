from __future__ import annotations

import os
import tempfile
import threading

from visold.consensus.slashing import SlashingEvidenceProtocol
from visold.crypto.ecc import sig_to_hex
from visold.crypto.hashing import sha256
from visold.selfhealing.rollback import GovernanceRollbackVote
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import VVMResult, _VMFrame
from visold.vm.opcodes import _GAS, Op
from visold.wallet.wallet import Wallet


def _push1(v: int) -> bytes:
    return bytes((Op.PUSH1, v & 0xFF))


def _install(st: Storage, address: str, code: bytes, creator: str) -> None:
    h = sha256(code)
    st.save_contract_code(h, code)
    st.save_contract(address, h, creator, 1)


class _Tx:
    gas_price = 0.0

    def __init__(self, tx_id: str):
        self.tx_id = tx_id


def _factory_create_runtime(init: bytes) -> bytes:
    # Copy appended init code to memory, then CREATE(value=0, offset=0, size=len(init)).
    prefix_len = 15
    prefix = (
        _push1(len(init)) + _push1(prefix_len) + _push1(0) + bytes((Op.CODECOPY,))
        + _push1(len(init)) + _push1(0) + _push1(0) + bytes((Op.CREATE, Op.STOP))
    )
    assert len(prefix) == prefix_len
    return prefix + init


def _factory_create2_runtime(init: bytes, salt: int) -> bytes:
    prefix_len = 17
    prefix = (
        _push1(len(init)) + _push1(prefix_len) + _push1(0) + bytes((Op.CODECOPY,))
        + _push1(salt) + _push1(len(init)) + _push1(0) + _push1(0)
        + bytes((Op.CREATE2, Op.STOP))
    )
    assert len(prefix) == prefix_len
    return prefix + init


def test_bug23_reversed_concurrent_evidence_slashes_exactly_once():
    class _FakeStorage:
        def __init__(self):
            self.stake = 100.0
            self.slashed = False
            self.meta = {}
            self.barrier = threading.Barrier(2)
            self.lock = threading.Lock()

        def get_role(self, _addr):
            # Return a snapshot. Both baseline threads can observe unslashed.
            return {"stake": self.stake, "slashed": self.slashed}

        def slash(self, _addr):
            # Force both baseline callers into the old check-then-act window.
            try:
                self.barrier.wait(timeout=0.25)
            except threading.BrokenBarrierError:
                pass
            with self.lock:
                if self.slashed:
                    return False
                self.stake *= 0.9
                self.slashed = True
                return True

        def set_meta(self, k, v):
            self.meta[k] = v

    st = _FakeStorage()
    p = SlashingEvidenceProtocol(st, object())
    p.verify_evidence = lambda _e: (True, "OK")
    base = {
        "validator": "VSD-validator",
        "block_hash_a": "A" * 64,
        "block_hash_b": "B" * 64,
        "height": 7,
        "submitted_by": "VSD-submit",
    }
    rev = dict(base, block_hash_a=base["block_hash_b"], block_hash_b=base["block_hash_a"])
    results = []

    def run(e):
        results.append(p.apply_evidence(e)[0])

    t1 = threading.Thread(target=run, args=(base,))
    t2 = threading.Thread(target=run, args=(rev,))
    t1.start(); t2.start(); t1.join(2); t2.join(2)
    assert not t1.is_alive() and not t2.is_alive()
    assert sorted(results) == [False, True]
    assert st.stake == 90.0
    assert len(st.meta) == 1


def test_bug23_storage_slash_is_conditional_and_idempotent():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "slash.db"))
        addr = Wallet.generate().address
        st.set_role(addr, "investor", 100.0)
        assert st.slash(addr) is True
        after = st.get_role(addr)
        assert after and after["slashed"]
        assert abs(float(after["stake"]) - 90.0) < 1e-9
        assert st.slash(addr) is False
        after2 = st.get_role(addr)
        assert abs(float(after2["stake"]) - 90.0) < 1e-9


def test_bug25_create_same_factory_across_transactions_gets_distinct_addresses():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "vm.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        parent = "VSDc" + "31" * 18
        init = _push1(42) + _push1(0) + bytes((Op.SSTORE, Op.STOP))
        _install(st, parent, _factory_create_runtime(init), wallet.address)

        r1 = vm.call(caller=wallet.address, contract=parent, calldata=b"", call_value=0,
                     gas_limit=1_000_000, block_ctx=None, tx=_Tx("a" * 64))
        r2 = vm.call(caller=wallet.address, contract=parent, calldata=b"", call_value=0,
                     gas_limit=1_000_000, block_ctx=None, tx=_Tx("b" * 64))
        assert r1.success and r2.success
        a1 = r1.pending_deployments[0]["address"]
        a2 = r2.pending_deployments[0]["address"]
        assert a1 != a2
        assert r1.storage_writes[(a1, "0x0")] == 42
        assert r2.storage_writes[(a2, "0x0")] == 42


def test_bug25_create2_rejects_occupied_target_instead_of_rerunning_init():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "vm.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        parent = "VSDc" + "32" * 18
        init = _push1(7) + _push1(0) + bytes((Op.SSTORE, Op.STOP))
        _install(st, parent, _factory_create2_runtime(init, 9), wallet.address)

        r1 = vm.call(caller=wallet.address, contract=parent, calldata=b"", call_value=0,
                     gas_limit=1_000_000, block_ctx=None, tx=_Tx("c" * 64))
        assert r1.success and len(r1.pending_deployments) == 1
        pd = r1.pending_deployments[0]
        st.save_contract_code(pd["code_hash"], pd["code_bytes"])
        st.save_contract(pd["address"], pd["code_hash"], pd["creator"], pd["created_at"])
        st.sstore(pd["address"], "0x0", 99)

        r2 = vm.call(caller=wallet.address, contract=parent, calldata=b"", call_value=0,
                     gas_limit=1_000_000, block_ctx=None, tx=_Tx("d" * 64))
        assert r2.success
        assert r2.pending_deployments == []
        assert (pd["address"], "0x0") not in r2.storage_writes
        assert st.sload(pd["address"], "0x0") == 99


def test_bug26_create_constructor_origin_and_txsender_are_top_level_eoa():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "vm.db"))
        vm = VVMEngine(st)
        wallet = Wallet.generate()
        parent = "VSDc" + "33" * 18
        # child init stores ORIGIN in slot 0 and TXSENDER in slot 1
        init = (
            bytes((Op.ORIGIN,)) + _push1(0) + bytes((Op.SSTORE,))
            + bytes((Op.TXSENDER,)) + _push1(1) + bytes((Op.SSTORE, Op.STOP))
        )
        _install(st, parent, _factory_create_runtime(init), wallet.address)
        r = vm.call(caller=wallet.address, contract=parent, calldata=b"", call_value=0,
                    gas_limit=1_000_000, block_ctx=None, tx=_Tx("e" * 64))
        assert r.success and len(r.pending_deployments) == 1
        child = r.pending_deployments[0]["address"]
        word = _VMFrame.__new__(_VMFrame)._addr_to_int(wallet.address)
        assert r.storage_writes[(child, "0x0")] == word
        assert r.storage_writes[(child, "0x1")] == word


def test_bug27_create_child_budget_is_computed_after_init_code_fee(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "vm.db"))
        vm = VVMEngine(st)
        captured = []

        def fake_deploy(self, **kwargs):
            captured.append(kwargs["gas_limit"])
            return VVMResult(success=False, gas_used=0, revert_reason="probe")

        monkeypatch.setattr(VVMEngine, "deploy", fake_deploy)
        frame = _VMFrame(code=bytes((Op.CREATE, Op.STOP)), calldata=b"",
                         caller="VSDx", address="VSDc" + "34" * 18,
                         origin="VSDx", call_value=0, gas_limit=200_000,
                         storage_ref=st, execution_id="f" * 64)
        frame.memory = bytearray(b"\x00" * 64)
        frame._mem_words = 2
        frame.push(64); frame.push(0); frame.push(0)
        vm._execute(frame)
        assert len(captured) == 1
        remaining_after_opcode = 200_000 - _GAS[Op.CREATE]
        remaining_after_init_fee = remaining_after_opcode - 64
        expected = remaining_after_init_fee - remaining_after_init_fee // 64
        assert captured[0] == expected


def _install_tip_with_validator_snapshot(st: Storage, validators: list[tuple[str, float]]):
    c = st._conn()
    c.execute(
        """INSERT INTO blocks(idx,block_hash,prev_hash,timestamp,miner,difficulty,nonce,merkle_root,state_root,finalized,data_json)
           VALUES(0,'tiphash','',1,'miner',1.0,0,'m','s',0,NULL)""")
    c.commit()
    rows = []
    for addr, stake in validators:
        st.set_role(addr, "investor", stake)
        rows.append({"address": addr, "stake_sat": int(round(stake * 100_000_000))})
    st.record_block_validator_snapshot(0, "tiphash", rows)


def test_bug28_storage_get_validators_uses_tip_snapshot_and_vote_can_reach_quorum():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "shbs.db"))
        wallets = [Wallet.generate() for _ in range(3)]
        _install_tip_with_validator_snapshot(st, [(w.address, 100.0) for w in wallets])
        vals = st.get_validators()
        assert [v["address"] for v in vals] == sorted(w.address for w in wallets)
        assert all(not v["slashed"] for v in vals)

        vote = GovernanceRollbackVote(st, "proposal-1", 2, {"kind": "test"})
        for w in wallets[:2]:
            msg = b"VSD-SHBS-VOTE|proposal-1|True"
            sig = sig_to_hex(w.sign(msg))
            assert vote.add_vote(w.address, True, sig, w.pub_hex) == "accepted"
        status = vote.quorum_status()
        assert status["required"] == 2
        assert status["approve_count"] == 2
        assert status["reached"] is True


def test_bug28_missing_snapshot_fails_closed_not_autoapprove():
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "shbs.db"))
        w = Wallet.generate()
        c = st._conn()
        c.execute(
            """INSERT INTO blocks(idx,block_hash,prev_hash,timestamp,miner,difficulty,nonce,merkle_root,state_root,finalized,data_json)
               VALUES(0,'tiphash','',1,'miner',1.0,0,'m','s',0,NULL)""")
        c.commit()
        st.set_role(w.address, "investor", 100.0)
        vote = GovernanceRollbackVote(st, "proposal-2", 2, {})
        status = vote.quorum_status()
        assert status["reached"] is False
        assert status["auto_approve"] is False
        assert status.get("error") == "validator_set_unavailable"
