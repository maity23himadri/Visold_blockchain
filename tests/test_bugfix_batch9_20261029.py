from __future__ import annotations

import os
import tempfile
from types import SimpleNamespace

from visold.chain.blockchain import Blockchain
from visold.crypto.hashing import sha256
from visold.governance.engine import GovernanceEngine, UpgradePhase
from visold.governance.versioning import ProtocolVersionManager
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.node.visold_node import VisoldNode
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op
from visold.wallet.wallet import Wallet


# ═════════════════════════════════════════════════════════════════════════════
# BUG-18: Block.integrity_check must bind state_root to block_hash
# ═════════════════════════════════════════════════════════════════════════════

def _chain(td: str):
    st = Storage(os.path.join(td, "batch9.db"))
    return st, Blockchain(st)


def _next_block(bc, miner, state_root: str) -> Block:
    height = bc.height() + 1
    prev = bc.latest_block()
    cb = Transaction.coinbase(miner.address, bc.compute_reward(height), height)
    return Block(
        index=height,
        prev_hash=prev.block_hash,
        transactions=[cb],
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        timestamp=prev.timestamp + 1,
        state_root=state_root,
    )


def test_bug18_control_block_hash_commits_to_state_root():
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        miner = Wallet.generate()
        honest = _next_block(bc, miner, "abc123")
        assert honest.compute_hash() != _next_block(bc, miner, "def456").compute_hash()
        ok, msg = honest.integrity_check()
        assert ok, msg


def test_bug18_control_genesis_hash_is_unchanged_by_the_fix():
    # Genesis is built with state_root="".  Its stored block_hash must still be
    # exactly what the header recomputes to, on both the old and the new tree.
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        genesis = bc.storage.get_block(0)
        assert genesis.compute_hash() == genesis.block_hash


def test_bug18_control_empty_state_root_block_hash_is_self_consistent():
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        miner = Wallet.generate()
        blk = _next_block(bc, miner, "")
        assert blk.mine(), "control block failed to mine"
        assert blk.block_hash == blk.compute_hash()


def test_bug18_mutated_state_root_is_rejected_when_hash_has_empty_root():
    # Wire attack: a block whose block_hash commits to state_root="" is
    # re-labelled with a different state_root.  The hash never covered the
    # field, so integrity_check must reject it.
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        miner = Wallet.generate()
        blk = _next_block(bc, miner, "")
        assert blk.mine(), "block failed to mine"
        d = blk.to_dict()
        assert d["block_hash"] == blk.compute_hash()
        d["state_root"] = "abc123"
        forged = Block.from_dict(d)
        ok, msg = forged.integrity_check()
        assert not ok, "state_root changed without changing block_hash was accepted"
        assert "block_hash mismatch" in msg, msg


def test_bug18_relabelled_state_root_never_applies():
    # Apply-level control: the forged block must be refused and leave the chain
    # unchanged.  The refusal comes from the PoW recomputation or from integrity,
    # whichever runs first; either one is a correct rejection.
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        miner = Wallet.generate()
        blk = _next_block(bc, miner, "")
        assert blk.mine(), "block failed to mine"
        d = blk.to_dict()
        d["state_root"] = "abc123"
        forged = Block.from_dict(d)
        before_height = bc.height()
        ok, msg = bc.apply_block(forged)
        assert not ok, msg
        assert ("block_hash mismatch" in msg) or ("Invalid PoW" in msg), msg
        assert bc.height() == before_height


# ═════════════════════════════════════════════════════════════════════════════
# BUG-24: CALLCODE runs callee code in the caller's storage context, with
#         msg.sender = calling contract and msg.value = the value operand.
# ═════════════════════════════════════════════════════════════════════════════

CHILD = "VSDc" + "c3" * 18
PARENT = "VSDc" + "d4" * 18

# Child stores CALLER at slot 0 and CALLVALUE at slot 1.
CHILD_WRITES_CONTEXT = bytes([
    Op.CALLER, Op.PUSH1, 0, Op.SSTORE,
    Op.CALLVALUE, Op.PUSH1, 1, Op.SSTORE,
    Op.STOP,
])

# Child writes slot 0, then reverts.
CHILD_WRITES_THEN_REVERTS = bytes([
    Op.CALLER, Op.PUSH1, 0, Op.SSTORE,
    Op.PUSH1, 0, Op.PUSH1, 0, 0xFD,  # REVERT(0, 0)
])


def _vm_word(addr: str) -> int:
    return object.__new__(_VMFrame)._addr_to_int(addr)


def _push_addr32(addr: str) -> bytes:
    return bytes([Op.PUSH32]) + _vm_word(addr).to_bytes(32, "big")


def _callcode_parent(target: str, value: int) -> bytes:
    # CALLCODE pops: gas, addr, value, in_off, in_size, out_off, out_size
    code = bytearray()
    code += bytes([Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0])
    code += bytes([Op.PUSH1, value])
    code += _push_addr32(target)
    code += bytes([Op.PUSH2, 0xC3, 0x50])      # gas = 50000
    code += bytes([Op.CALLCODE])
    code += bytes([Op.PUSH1, 2, Op.SSTORE])     # slot 2 = success flag
    code += bytes([Op.STOP])
    return bytes(code)


def _delegatecall_parent(target: str) -> bytes:
    # DELEGATECALL pops: gas, addr, in_off, in_size, out_off, out_size
    code = bytearray()
    code += bytes([Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0, Op.PUSH1, 0])
    code += _push_addr32(target)
    code += bytes([Op.PUSH2, 0xC3, 0x50])      # gas = 50000
    code += bytes([Op.DELEGATECALL])
    code += bytes([Op.PUSH1, 2, Op.SSTORE])     # slot 2 = success flag
    code += bytes([Op.STOP])
    return bytes(code)


def _run_parent(parent_code: bytes, child_code: bytes, *, eoa: str,
                parent_value: int, parent_balance_sat: int):
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "bug24.db"))
        if parent_balance_sat:
            st.credit_sat(PARENT, parent_balance_sat)
        code_hash = sha256(child_code)
        st.save_contract_code(code_hash, child_code)
        st.save_contract(CHILD, code_hash, eoa, 0)
        vm = VVMEngine(st)
        frame = _VMFrame(
            code=parent_code,
            calldata=b"",
            caller=eoa,
            address=PARENT,
            origin=eoa,
            call_value=parent_value,
            gas_limit=1_000_000,
            storage_ref=st,
            block_ctx=SimpleNamespace(index=1, miner_address="", timestamp=1,
                                      difficulty=1.0),
            execution_id="b4" * 32,
        )
        vm._execute(frame)
        return frame


def _slot(frame, slot: int):
    return frame.storage_writes.get((PARENT, hex(slot)))


def test_bug24_callcode_uses_calling_contract_as_caller_and_value_operand():
    eoa = Wallet.generate().address
    frame = _run_parent(
        _callcode_parent(CHILD, value=5), CHILD_WRITES_CONTEXT,
        eoa=eoa, parent_value=9, parent_balance_sat=1000)
    assert not frame.reverted, frame.output
    assert _slot(frame, 2) == 1, "CALLCODE did not succeed"
    assert _slot(frame, 0) == _vm_word(PARENT), (
        "CALLCODE msg.sender must be the calling contract, not the external caller")
    assert _slot(frame, 1) == 5, (
        "CALLCODE msg.value must be the value operand, not the parent's call value")


def test_bug24_callcode_value_operand_must_be_covered_by_caller_balance():
    eoa = Wallet.generate().address
    frame = _run_parent(
        _callcode_parent(CHILD, value=5), CHILD_WRITES_CONTEXT,
        eoa=eoa, parent_value=9, parent_balance_sat=0)
    assert not frame.reverted, frame.output
    assert _slot(frame, 2) == 0, "CALLCODE with an uncovered value operand must fail"
    assert _slot(frame, 0) is None and _slot(frame, 1) is None, (
        "a failed CALLCODE must not run the callee")


def test_bug24_callcode_child_revert_discards_child_writes():
    eoa = Wallet.generate().address
    frame = _run_parent(
        _callcode_parent(CHILD, value=0), CHILD_WRITES_THEN_REVERTS,
        eoa=eoa, parent_value=9, parent_balance_sat=0)
    assert not frame.reverted, frame.output
    assert _slot(frame, 2) == 0, "reverting CALLCODE child must report failure"
    assert _slot(frame, 0) is None, "reverted CALLCODE child writes must be discarded"


def test_bug24_delegatecall_semantics_are_unchanged():
    eoa = Wallet.generate().address
    frame = _run_parent(
        _delegatecall_parent(CHILD), CHILD_WRITES_CONTEXT,
        eoa=eoa, parent_value=9, parent_balance_sat=0)
    assert not frame.reverted, frame.output
    assert _slot(frame, 2) == 1
    assert _slot(frame, 0) == _vm_word(eoa), "DELEGATECALL must keep the external caller"
    assert _slot(frame, 1) == 9, "DELEGATECALL must keep the parent's call value"


# ═════════════════════════════════════════════════════════════════════════════
# BUG-12: emergency-disable quorum from signed, gossiped validator votes
# ═════════════════════════════════════════════════════════════════════════════

GEN = "ab" * 32
T0 = 1_800_000_000


def _gov(td: str) -> GovernanceEngine:
    st = Storage(os.path.join(td, "bug12.db"))
    st.set_meta("genesis_hash", GEN)
    gov = GovernanceEngine(st, ProtocolVersionManager(st))
    ok, msg = gov.propose_upgrade(version=2, signal_start_height=10, threshold=0.75)
    assert ok, msg
    return gov


def _eligible(*wallets):
    addrs = {w.address for w in wallets}
    return lambda addr: addr in addrs


def test_bug12_two_distinct_validators_disable_the_upgrade():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a, b = Wallet.generate(), Wallet.generate()
        elig = _eligible(a, b)
        acc1, dis1, _ = gov.record_emergency_vote(
            gov.sign_emergency_vote(a, 2, now=T0), is_eligible=elig, now=T0)
        assert acc1 and not dis1
        acc2, dis2, msg = gov.record_emergency_vote(
            gov.sign_emergency_vote(b, 2, now=T0), is_eligible=elig, now=T0)
        assert acc2 and dis2, msg
        p = gov.get_proposal(2)
        assert p.phase == UpgradePhase.FAILED and p.disabled
        assert 2 in gov._blacklist


def test_bug12_one_validator_cannot_reach_quorum_by_repeating_votes():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a = Wallet.generate()
        elig = _eligible(a)
        accepted = []
        for i in range(3):
            acc, dis, _msg = gov.record_emergency_vote(
                gov.sign_emergency_vote(a, 2, now=T0 + i),
                is_eligible=elig, now=T0 + i)
            accepted.append(acc)
            assert not dis
        assert accepted == [True, False, False]
        assert gov.get_proposal(2).phase != UpgradePhase.FAILED


def test_bug12_forged_vote_claiming_an_eligible_operator_is_rejected():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a, attacker = Wallet.generate(), Wallet.generate()
        elig = _eligible(a)
        v = gov.sign_emergency_vote(attacker, 2, now=T0)
        v["operator"] = a.address
        v["pub_hex"] = a.pub_hex
        acc, dis, msg = gov.record_emergency_vote(v, is_eligible=elig, now=T0)
        assert not acc and not dis
        assert "invalid emergency vote signature" in msg, msg


def test_bug12_vote_from_a_non_validator_is_rejected_even_when_correctly_signed():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a, outsider = Wallet.generate(), Wallet.generate()
        elig = _eligible(a)
        acc, dis, msg = gov.record_emergency_vote(
            gov.sign_emergency_vote(outsider, 2, now=T0), is_eligible=elig, now=T0)
        assert not acc and not dis
        assert "not a validator" in msg, msg


def test_bug12_signature_is_bound_to_version():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a = Wallet.generate()
        elig = _eligible(a)
        v = gov.sign_emergency_vote(a, 2, now=T0)
        v["version"] = 3
        acc, dis, msg = gov.record_emergency_vote(v, is_eligible=elig, now=T0)
        assert not acc and not dis
        assert "invalid emergency vote signature" in msg, msg


def test_bug12_vote_is_bound_to_the_chain_it_was_signed_for():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a = Wallet.generate()
        elig = _eligible(a)
        v = gov.sign_emergency_vote(a, 2, now=T0)
        # The node moves to another chain: the same valid signature must not count.
        gov.storage.set_meta("genesis_hash", "cd" * 32)
        acc, dis, msg = gov.record_emergency_vote(v, is_eligible=elig, now=T0)
        assert not acc and not dis
        assert "different chain" in msg, msg


def test_bug12_replayed_vote_is_not_counted_twice():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a = Wallet.generate()
        elig = _eligible(a)
        v = gov.sign_emergency_vote(a, 2, now=T0)
        acc1, dis1, _ = gov.record_emergency_vote(v, is_eligible=elig, now=T0)
        acc2, dis2, _ = gov.record_emergency_vote(v, is_eligible=elig, now=T0)
        assert acc1 and not acc2 and not dis1 and not dis2
        assert gov.get_proposal(2).phase != UpgradePhase.FAILED


def test_bug12_stale_and_future_votes_are_rejected_and_the_window_is_inclusive():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a = Wallet.generate()
        elig = _eligible(a)
        ttl = gov._EMERGENCY_VOTE_TTL
        stale = gov.sign_emergency_vote(a, 2, now=T0 - ttl - 1)
        acc, _dis, msg = gov.record_emergency_vote(stale, is_eligible=elig, now=T0)
        assert not acc and "stale" in msg, msg
        future = gov.sign_emergency_vote(a, 2, now=T0 + ttl + 1)
        acc, _dis, msg = gov.record_emergency_vote(future, is_eligible=elig, now=T0)
        assert not acc and "stale" in msg, msg
        edge = gov.sign_emergency_vote(a, 2, now=T0 - ttl)
        acc, _dis, msg = gov.record_emergency_vote(edge, is_eligible=elig, now=T0)
        assert acc, msg


def test_bug12_votes_expire_so_stale_votes_cannot_combine_into_quorum():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a, b = Wallet.generate(), Wallet.generate()
        elig = _eligible(a, b)
        ttl = gov._EMERGENCY_VOTE_TTL
        acc_a, _, _ = gov.record_emergency_vote(
            gov.sign_emergency_vote(a, 2, now=T0), is_eligible=elig, now=T0)
        assert acc_a
        # A's vote is now older than the window, so it is pruned before B counts.
        acc_b, dis_b, _ = gov.record_emergency_vote(
            gov.sign_emergency_vote(b, 2, now=T0 + ttl + 1),
            is_eligible=elig, now=T0 + ttl + 1)
        assert acc_b and not dis_b
        assert gov.get_proposal(2).phase != UpgradePhase.FAILED


def test_bug12_disable_is_final_and_later_votes_do_not_reexecute_it():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a, b, c = Wallet.generate(), Wallet.generate(), Wallet.generate()
        elig = _eligible(a, b, c)
        gov.record_emergency_vote(gov.sign_emergency_vote(a, 2, now=T0),
                                  is_eligible=elig, now=T0)
        _acc, dis, _ = gov.record_emergency_vote(gov.sign_emergency_vote(b, 2, now=T0),
                                                 is_eligible=elig, now=T0)
        assert dis
        acc3, dis3, msg3 = gov.record_emergency_vote(
            gov.sign_emergency_vote(c, 2, now=T0), is_eligible=elig, now=T0)
        assert not acc3 and not dis3
        assert "already disabled" in msg3, msg3
        assert gov.get_proposal(2).phase == UpgradePhase.FAILED


def test_bug12_vote_for_unknown_version_is_rejected():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a = Wallet.generate()
        acc, dis, msg = gov.record_emergency_vote(
            gov.sign_emergency_vote(a, 9, now=T0), is_eligible=_eligible(a), now=T0)
        assert not acc and not dis
        assert "No proposal" in msg, msg


def test_bug12_malformed_vote_fields_are_rejected():
    with tempfile.TemporaryDirectory() as td:
        gov = _gov(td)
        a = Wallet.generate()
        elig = _eligible(a)
        good = gov.sign_emergency_vote(a, 2, now=T0)
        for bad in (
            "not-a-dict",
            dict(good, version="2"),
            dict(good, ts=True),
            dict(good, nonce="XYZ"),
            dict(good, sig=None),
        ):
            acc, dis, _msg = gov.record_emergency_vote(bad, is_eligible=elig, now=T0)
            assert not acc and not dis, bad


def test_bug12_tip_snapshot_defines_eligibility(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        a = Wallet.generate()
        zero = Wallet.generate()
        monkeypatch.setattr(
            Blockchain, "get_validator_set_for_block",
            lambda self, block: [{"address": a.address, "stake_sat": 10 ** 9},
                                 {"address": zero.address, "stake_sat": 0}])
        assert bc.emergency_operator_eligible(a.address)
        assert not bc.emergency_operator_eligible(zero.address)
        assert not bc.emergency_operator_eligible(Wallet.generate().address)
        assert not bc.emergency_operator_eligible("")
        monkeypatch.setattr(Blockchain, "get_validator_set_for_block",
                            lambda self, block: None)
        assert not bc.emergency_operator_eligible(a.address)


def test_bug12_node_wallet_signs_and_gossips_its_vote(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        ok, msg = bc._governance.propose_upgrade(version=2, signal_start_height=10,
                                                 threshold=0.75)
        assert ok, msg
        a, b = Wallet.generate(), Wallet.generate()
        eligible = {a.address, b.address}
        monkeypatch.setattr(bc, "emergency_operator_eligible",
                            lambda addr: addr in eligible)
        sent = []
        net = SimpleNamespace(broadcast_emergency_vote=lambda v: sent.append(v))

        node_a = SimpleNamespace(blockchain=bc, wallet=a, network=net)
        ok_a, msg_a = VisoldNode.emergency_disable_upgrade(node_a, 2)
        assert not ok_a and "Vote recorded (1/2)" in msg_a, msg_a
        assert len(sent) == 1

        # The same wallet again is a duplicate: no second broadcast, no quorum.
        ok_a2, msg_a2 = VisoldNode.emergency_disable_upgrade(node_a, 2)
        assert not ok_a2 and len(sent) == 1, msg_a2

        node_b = SimpleNamespace(blockchain=bc, wallet=b, network=net)
        ok_b, msg_b = VisoldNode.emergency_disable_upgrade(node_b, 2)
        assert ok_b, msg_b
        assert len(sent) == 2
        assert bc._governance.get_proposal(2).disabled


def test_bug12_node_that_is_not_a_validator_cannot_vote(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        ok, msg = bc._governance.propose_upgrade(version=2, signal_start_height=10,
                                                 threshold=0.75)
        assert ok, msg
        outsider = Wallet.generate()
        monkeypatch.setattr(bc, "emergency_operator_eligible", lambda addr: False)
        sent = []
        node = SimpleNamespace(blockchain=bc, wallet=outsider,
                               network=SimpleNamespace(broadcast_emergency_vote=sent.append))
        ok_o, msg_o = VisoldNode.emergency_disable_upgrade(node, 2)
        assert not ok_o and "not a validator" in msg_o, msg_o
        assert sent == []
        assert bc._governance.get_proposal(2).phase != UpgradePhase.FAILED


def test_bug12_state_engine_relays_only_new_valid_votes(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        ok, msg = bc._governance.propose_upgrade(version=2, signal_start_height=10,
                                                 threshold=0.75)
        assert ok, msg
        a, b = Wallet.generate(), Wallet.generate()
        eligible = {a.address, b.address}
        monkeypatch.setattr(bc, "emergency_operator_eligible",
                            lambda addr: addr in eligible)
        relayed = []

        class _Net:
            def _gossip(self, msg, exclude=None):
                relayed.append((msg, exclude))

        se = SimpleNamespace(_blockchain=bc, _network=_Net())
        v_a = bc._governance.sign_emergency_vote(a, 2)

        acc, _msg = StateEngine._handle_emergency_vote(se, v_a, "peer-1")
        assert acc
        assert len(relayed) == 1
        relayed_msg, exclude = relayed[0]
        assert exclude == "peer-1"
        assert relayed_msg["type"] == "EMERGENCY_VOTE"
        assert relayed_msg["ttl"] == Config.GOSSIP_TTL
        assert relayed_msg["operator"] == a.address

        # Repeat from another peer: not new, so not relayed.
        acc_r, _ = StateEngine._handle_emergency_vote(se, v_a, "peer-2")
        assert not acc_r and len(relayed) == 1

        # Invalid vote: rejected and not relayed.
        bad = dict(v_a, nonce="00" * 16)
        acc_bad, _ = StateEngine._handle_emergency_vote(se, bad, "peer-3")
        assert not acc_bad and len(relayed) == 1

        # The second validator's vote completes the quorum and is relayed.
        v_b = bc._governance.sign_emergency_vote(b, 2)
        acc_b, msg_b = StateEngine._handle_emergency_vote(se, v_b, "peer-1")
        assert acc_b and len(relayed) == 2, msg_b
        assert bc._governance.get_proposal(2).disabled


def test_bug12_p2p_handler_routes_emergency_vote_to_state_engine():
    from unittest.mock import MagicMock
    from visold.kernel.events import EventType
    from visold.network.p2p import P2PNetwork
    fake = MagicMock()
    fake._check_msg_rate.return_value = True
    fake._seen_msgs.get.return_value = None  # not a duplicate of an earlier message
    peer = SimpleNamespace(peer_id="peer-9")
    msg = {"type": "EMERGENCY_VOTE", "version": 2, "operator": "VSDx",
           "pub_hex": "aa", "sig": "[1,2]", "ts": 1800000000,
           "nonce": "11" * 16, "genesis_hash": GEN, "ttl": 8,
           "unexpected_field": "must not reach the engine"}
    P2PNetwork._handle_message(fake, peer, msg)
    assert fake._state_engine.post.called
    evt = fake._state_engine.post.call_args.args[0]
    assert evt.etype == EventType.EMERGENCY_VOTE
    assert evt.source_peer_id == "peer-9"
    assert evt.payload["operator"] == "VSDx"
    assert evt.payload["nonce"] == "11" * 16
    assert "unexpected_field" not in evt.payload


def test_bug12_state_engine_dispatch_reaches_the_emergency_handler(monkeypatch):
    import types
    from visold.kernel.events import Event, EventType
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        ok, msg = bc._governance.propose_upgrade(version=2, signal_start_height=10,
                                                 threshold=0.75)
        assert ok, msg
        a = Wallet.generate()
        monkeypatch.setattr(bc, "emergency_operator_eligible",
                            lambda addr: addr == a.address)
        relayed = []

        class _Net:
            def _gossip(self, msg, exclude=None):
                relayed.append(exclude)

        class _Engine:
            pass

        se = _Engine()
        se._circuit_breaker = None
        se._blockchain = bc
        se._network = _Net()
        se._handle_emergency_vote = types.MethodType(
            StateEngine._handle_emergency_vote, se)
        vote = bc._governance.sign_emergency_vote(a, 2)
        acc, _msg = StateEngine._handle(
            se, Event(EventType.EMERGENCY_VOTE, vote, source_peer_id="peer-1"))
        assert acc
        assert relayed == ["peer-1"]
