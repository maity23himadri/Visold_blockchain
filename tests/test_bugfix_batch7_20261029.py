from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from types import SimpleNamespace

from visold.api.rpc_server import RPCServer
from visold.crypto.hashing import sha256
from visold.selfhealing.supply_monitor import SupplyConservationMonitor
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine, _chan_state_msg
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op
from visold.vm.precompiles import VVMPrecompiles
from visold.wallet.wallet import Wallet


def _push(v: int, n: int = 32) -> bytes:
    return bytes((Op.PUSH1 + n - 1,)) + int(v).to_bytes(n, "big")


def _push1(v: int) -> bytes:
    return bytes((Op.PUSH1, v & 0xff))


def _install(st: Storage, address: str, code: bytes, creator: str) -> None:
    h = sha256(code)
    st.save_contract_code(h, code)
    st.save_contract(address, h, creator, 1)


class _Tx:
    gas_price = 0.0
    tx_id = "batch7"


def _dispute_program(cid: str, seq: int, bal_caller: int, bal_counter: int,
                     sig_r: int, sig_s: int) -> bytes:
    # CHAN_DISPUTE pops: channel_id, seq, bal_caller, bal_counter, r, s.
    return (
        _push(sig_s) + _push(sig_r) + _push(bal_counter) + _push(bal_caller)
        + _push(seq) + _push(int(cid, 16)) + bytes((Op.CHAN_DISPUTE, Op.STOP))
    )


def test_bug34_newer_state_can_challenge_dispute_before_timeout(tmp_path):
    st = Storage(str(tmp_path / "chan.db"))
    a, b = Wallet.generate(), Wallet.generate()
    contract = "VSDc" + "71" * 18
    cid = "12" * 32
    assert st.create_channel(cid, contract, a.address, b.address, 100, 20, 1)

    # A first submits stale seq=5, signed by B: opener=70, counterparty=30.
    d5 = _chan_state_msg(cid, 5, 70, 30)
    r5, s5 = b.sign_digest(d5)
    vm = VVMEngine(st)
    f1 = _VMFrame(
        code=_dispute_program(cid, 5, 70, 30, r5, s5), calldata=b"",
        caller=a.address, address=contract, origin=a.address, call_value=0,
        gas_limit=300_000, storage_ref=st, block_ctx=SimpleNamespace(index=10),
        execution_id="34" * 32)
    vm._execute(f1)
    assert not f1.reverted
    assert st.get_channel(cid)["dispute_seq"] == 5

    # B possesses newer seq=6 signed by A: opener=20, counterparty=80.
    # From B's perspective bal_caller=80 and bal_counter=20.
    d6 = _chan_state_msg(cid, 6, 20, 80)
    r6, s6 = a.sign_digest(d6)
    f2 = _VMFrame(
        code=_dispute_program(cid, 6, 80, 20, r6, s6), calldata=b"",
        caller=b.address, address=contract, origin=b.address, call_value=0,
        gas_limit=300_000, storage_ref=st, block_ctx=SimpleNamespace(index=11),
        execution_id="35" * 32)
    vm._execute(f2)
    assert not f2.reverted
    ch = st.get_channel(cid)
    assert ch["status"] == "DISPUTED"
    assert ch["dispute_seq"] == 6
    assert ch["dispute_bal_opener"] == 20
    assert ch["dispute_bal_counter"] == 80
    assert ch["dispute_height"] == 11

    # Once the refreshed challenge window expires, settlement must use seq=6's
    # balances, not the stale seq=5 split.
    before_a, before_b = st.get_balance_sat(a.address), st.get_balance_sat(b.address)
    close_prog = _dispute_program(cid, 0, 0, 0, 0, 0)
    f3 = _VMFrame(
        code=close_prog, calldata=b"", caller=a.address, address=contract,
        origin=a.address, call_value=0, gas_limit=300_000, storage_ref=st,
        block_ctx=SimpleNamespace(index=31), execution_id="37" * 32)
    vm._execute(f3)
    assert not f3.reverted
    assert st.get_channel(cid)["status"] == "FORCE_CLOSED"
    assert st.get_balance_sat(a.address) - before_a == 20
    assert st.get_balance_sat(b.address) - before_b == 80

    # Stale/equal challenge remains rejected atomically (fresh channel because
    # the first one is already settled).
    cid2 = "13" * 32
    assert st.create_channel(cid2, contract, a.address, b.address, 100, 20, 1)
    assert st.raise_dispute(cid2, 6, 20, 80, 11) is True
    assert st.raise_dispute(cid2, 6, 99, 1, 12) is False
    assert st.get_channel(cid2)["dispute_bal_opener"] == 20


def test_bug35_pending_deployment_visible_to_internal_call_and_extcodesize(tmp_path):
    st = Storage(str(tmp_path / "vm.db"))
    vm = VVMEngine(st)
    w = Wallet.generate()
    parent = "VSDc" + "72" * 18
    child = "VSDc" + "73" * 18
    # child runtime writes slot 0 = 0x42
    child_code = _push1(0x42) + _push1(0) + bytes((Op.SSTORE, Op.STOP))
    f = _VMFrame(
        code=b"", calldata=b"", caller=w.address, address=parent,
        origin=w.address, call_value=0, gas_limit=500_000,
        storage_ref=st, execution_id="35" * 32,
    )
    f.pending_deployments.append({
        "address": child, "code_hash": sha256(child_code),
        "code_bytes": child_code, "creator": parent,
        "created_at": 1, "contract_name": "",
    })
    ok, _ = vm._internal_call(
        caller_frame=f, callee_addr=child, calldata=b"", call_value=0,
        gas=100_000)
    assert ok is True
    assert f.storage_writes[(child, "0x0")] == 0x42

    # EXTCODESIZE must see the same pending runtime before persistence.
    addr_word = f._addr_to_int(child)
    probe = _VMFrame(
        code=_push(addr_word, 32) + bytes((Op.EXTCODESIZE, Op.STOP)),
        calldata=b"", caller=w.address, address=parent, origin=w.address,
        call_value=0, gas_limit=100_000, storage_ref=st,
        execution_id="36" * 32,
    )
    probe.pending_deployments = list(f.pending_deployments)
    vm._execute(probe)
    assert probe.stack[-1] == len(child_code)

    # EXTCODEHASH must match the pending runtime's committed code hash.
    probe_hash = _VMFrame(
        code=_push(addr_word, 32) + bytes((Op.EXTCODEHASH, Op.STOP)),
        calldata=b"", caller=w.address, address=parent, origin=w.address,
        call_value=0, gas_limit=100_000, storage_ref=st,
        execution_id="38" * 32)
    probe_hash.pending_deployments = list(f.pending_deployments)
    vm._execute(probe_hash)
    assert probe_hash.stack[-1] == int(sha256(child_code), 16)

    # EXTCODECOPY: copy the complete runtime to memory before persistence.
    copy_code = (
        _push1(len(child_code)) + _push1(0) + _push1(0)
        + _push(addr_word, 32) + bytes((Op.EXTCODECOPY, Op.STOP))
    )
    probe_copy = _VMFrame(
        code=copy_code, calldata=b"", caller=w.address, address=parent,
        origin=w.address, call_value=0, gas_limit=100_000, storage_ref=st,
        execution_id="39" * 32)
    probe_copy.pending_deployments = list(f.pending_deployments)
    vm._execute(probe_copy)
    assert bytes(probe_copy.memory[:len(child_code)]) == child_code


def test_bug36_ripemd_fallback_matches_standard_vector(monkeypatch):
    real_new = hashlib.new

    def unavailable(name, *args, **kwargs):
        if str(name).lower().replace("-", "") == "ripemd160":
            raise ValueError("algorithm unavailable")
        return real_new(name, *args, **kwargs)

    monkeypatch.setattr(hashlib, "new", unavailable)
    ok, out, gas = VVMPrecompiles._ripemd160(b"abc", 100_000)
    assert ok and gas > 0
    assert out[-20:].hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    ok2, out2, _ = VVMPrecompiles._ripemd160(b"", 100_000)
    assert ok2
    assert out2[-20:].hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"


def _rpc_call(port: int, token: str, method: str, params: list):
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}", data=data, method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_bug37_getblockheaders_is_charged_as_slow_rpc(monkeypatch, tmp_path):
    # Keep token files isolated from the user's actual Visold data directory.
    monkeypatch.setattr(RPCServer, "TOKEN_FILE", str(tmp_path / "rpc_token"))
    class Chain:
        def get_block(self, _i): return None
    node = SimpleNamespace(blockchain=Chain())
    srv = RPCServer(node, 0)
    srv.start()
    assert srv._server is not None
    port = srv._server.server_address[1]
    try:
        assert _rpc_call(port, srv._token, "getblockheaders", [0, 100]) == 200
        assert _rpc_call(port, srv._token, "getblockheaders", [0, 100]) == 200
        # 20-token bucket, slow methods cost 10. With immediate requests the
        # third expensive call must be throttled; baseline charged only 1.
        assert _rpc_call(port, srv._token, "getblockheaders", [0, 100]) == 429
    finally:
        srv.stop()


def test_bug38_supply_monitor_detects_large_decrease_and_resets_on_rollback():
    class Supply:
        def __init__(self, value): self.value = value
        def get_total_supply_sat(self): return self.value
    class ADE:
        def __init__(self):
            self.reports=[]
            self._listeners = [self.reports.append]
    src = Supply(100_000 * 100_000_000)
    ade = ADE()
    mon = SupplyConservationMonitor(src)
    mon.check(SimpleNamespace(index=50), ade)
    assert not ade.reports

    src.value -= 10_000 * 100_000_000
    mon.check(SimpleNamespace(index=100), ade)
    assert len(ade.reports) == 1
    assert ade.reports[0].evidence["delta_sat"] < 0

    # A rollback to an already-sampled/lower height establishes a fresh branch
    # baseline instead of comparing against the abandoned branch sample.
    src.value = 95_000 * 100_000_000
    mon.check(SimpleNamespace(index=50), ade)
    assert len(ade.reports) == 1
    assert mon._last_checked_supply == src.value
    assert mon._last_checked_height == 50
