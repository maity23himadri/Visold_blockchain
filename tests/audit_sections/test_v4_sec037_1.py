"""Section 37 Audit: Consensus Engine State Transitions and Validation."""

from __future__ import annotations

import os
import time
from types import SimpleNamespace

import pytest

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.vm.naming import derive_contract_address
from visold.wallet.wallet import Wallet


def _configure(monkeypatch):
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    monkeypatch.setattr(Config, "MIN_VALIDATORS_FOR_BFT", 3)


def _mine_one(bc: Blockchain, miner: Wallet) -> Block:
    cand = ConsensusEngine(bc, miner).build_candidate_block(miner.address)
    assert cand.mine(), "mining failed"
    ok, msg = bc.apply_block(cand)
    assert ok, msg
    return cand


def test_call_to_missing_contract_excluded_by_candidate_builder(
    tmp_path, monkeypatch
):
    """
    V4 regression (Finding 1): ConsensusEngine.build_candidate_block() excludes
    a TYPE_CALL targeting a non-existent contract address so the resulting
    candidate block passes validate_block() and apply_block() cleanly.
    """
    _configure(monkeypatch)
    st = Storage(os.path.join(str(tmp_path), "chain.db"))
    bc = Blockchain(st)
    miner = Wallet.generate()
    _mine_one(bc, miner)

    nonce = st.get_nonce(miner.address)
    missing_contract = derive_contract_address(miner.address, 999, "deadbeef" * 8)
    call_tx = Transaction(
        sender=miner.address,
        receiver=missing_contract,
        amount=0.0,
        fee=0.0,
        tx_type=Transaction.TYPE_CALL,
        nonce=nonce,
        timestamp=int(time.time()),
        expiry=int(time.time()) + 3600,
        gas_limit=50_000,
        gas_price=0.00000001,
        data="00",
    )
    call_tx.sign(miner)

    ok_add, msg_add = bc.mempool.add(call_tx)
    assert ok_add, f"mempool rejected CALL tx unexpectedly: {msg_add}"

    ce = ConsensusEngine(bc, miner)
    cand = ce.build_candidate_block(miner.address)
    assert not any(t.tx_id == call_tx.tx_id for t in cand.transactions), (
        "Candidate block should exclude CALL tx to missing contract"
    )
    assert cand.mine(), "mining candidate failed"

    ok_val, msg_val = bc.validate_block(cand)
    assert ok_val, msg_val

    ok_app, msg_app = bc.apply_block(cand)
    assert ok_app, msg_app


def test_same_height_winning_fork_in_handle_new_block_votes_relays_and_drains_orphans(
    tmp_path, monkeypatch
):
    """
    V4 regression (Finding 2): When StateEngine._handle_new_block() receives a
    competing same-height block that wins fork choice via accept_chain(), it
    runs consensus.validate_and_finalize(block), broadcast_block(), and
    _drain_orphans_for().
    """
    _configure(monkeypatch)
    st = Storage(os.path.join(str(tmp_path), "node.db"))
    bc = Blockchain(st)

    miner = Wallet.generate()
    v1, v2, v3 = Wallet.generate(), Wallet.generate(), Wallet.generate()
    for w in (miner, v1, v2, v3):
        st.set_role(w.address, "investor", 100.0)
        st.credit_sat(w.address, 200 * Config.SATOSHI_PER_VSD)
    _mine_one(bc, miner)

    cand_a = ConsensusEngine(bc, miner).build_candidate_block(miner.address)
    assert cand_a.mine()
    ok_a, msg_a = bc.apply_block(cand_a)
    assert ok_a, msg_a

    st_fork = Storage(os.path.join(str(tmp_path), "fork.db"))
    bc_fork = Blockchain(st_fork)
    b0 = st.get_block(0)
    b1 = st.get_block(1)
    assert b0 is not None and b1 is not None
    for w in (miner, v1, v2, v3):
        st_fork.set_role(w.address, "investor", 100.0)
        st_fork.credit_sat(w.address, 200 * Config.SATOSHI_PER_VSD)
    st_fork.save_block(b0)
    st_fork.set_meta("genesis_hash", b0.block_hash)
    ok_f1, msg_f1 = bc_fork.apply_block(b1)
    assert ok_f1, msg_f1

    ce_fork = ConsensusEngine(bc_fork, v2)
    cand_b = None
    for attempt in range(200):
        c = ce_fork.build_candidate_block(v2.address)
        c.timestamp = cand_a.timestamp + 1 + attempt
        assert c.mine()
        if c.block_hash < cand_a.block_hash:
            cand_b = c
            break
    assert cand_b is not None

    consensus_v1 = ConsensusEngine(bc, v1)
    state_eng = StateEngine(bc, bc._governance, st)
    relayed = []
    fake_net = SimpleNamespace(
        peers={},
        _lock=bc._lock,
        publish_receipts_for_block=lambda blk: None,
        broadcast_block=lambda blk, exclude=None: relayed.append(blk.block_hash),
        _gossip=lambda payload, exclude=None: None,
    )
    state_eng._network = fake_net
    state_eng._node_ref = SimpleNamespace(consensus=consensus_v1, shbs=None)

    ok_fb, msg_fb = bc_fork.apply_block(cand_b)
    assert ok_fb, msg_fb
    child_3 = ConsensusEngine(bc_fork, v2).build_candidate_block(v2.address)
    assert child_3.mine()
    state_eng._stash_orphan(child_3, child_3.to_dict(), "peer1")
    assert child_3.block_hash in state_eng._orphans

    ok_hb, msg_hb = state_eng._handle_new_block({"block": cand_b}, source_peer="peer1")
    assert ok_hb, msg_hb

    canon_2 = st.get_block(2)
    assert canon_2 is not None
    assert canon_2.block_hash == cand_b.block_hash

    votes = st.get_validator_votes_at_height(2)
    v1_votes_for_b = [
        v for v in votes
        if v.get("validator_addr") == v1.address and v.get("block_hash") == cand_b.block_hash
    ]
    assert len(v1_votes_for_b) == 1
    assert child_3.block_hash not in state_eng._orphans
    assert cand_b.block_hash in relayed


def test_consensus_engine_core_invariants(tmp_path, monkeypatch):
    """Verify select_block_proposer, validate_and_finalize, and self-equivocation guard."""
    _configure(monkeypatch)
    st = Storage(os.path.join(str(tmp_path), "inv.db"))
    bc = Blockchain(st)
    miner = Wallet.generate()
    v1, v2, v3 = Wallet.generate(), Wallet.generate(), Wallet.generate()
    for w in (miner, v1, v2, v3):
        st.set_role(w.address, "investor", 100.0)
        st.credit_sat(w.address, 200 * Config.SATOSHI_PER_VSD)
    _mine_one(bc, miner)

    ce_v1 = ConsensusEngine(bc, v1)
    assert ce_v1.select_block_proposer([{"address": v1.address}]) is None
    chosen = ce_v1.select_block_proposer([
        {"address": v1.address, "priv_hex": format(v1.priv, "064x")},
        {"address": v2.address, "priv_hex": format(v2.priv, "064x")},
    ])
    assert chosen is not None and chosen["address"] in (v1.address, v2.address)

    cand = ce_v1.build_candidate_block(miner.address)
    assert cand.mine()
    ok_fin, _ = ce_v1.finalize_applied_block(cand)
    assert not ok_fin

    ok_app, msg_app = bc.apply_block(cand)
    assert ok_app, msg_app
    ok_v, msg_v = ce_v1.validate_and_finalize(cand)
    assert ok_v, msg_v
    assert any(
        v.get("validator_addr") == v1.address and v.get("block_hash") == cand.block_hash
        for v in st.get_validator_votes_at_height(cand.index)
    )
