"""Section 70 V4 Regression Tests: Protocol Upgrade Activation, Failure Recovery, Rollback."""

from __future__ import annotations

import os
import sys
import time
import types

V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if V4_ROOT not in sys.path:
    sys.path.insert(0, V4_ROOT)

from visold.chain.blockchain import Blockchain
from visold.governance.engine import GovernanceEngine, UpgradePhase, UpgradeProposal
from visold.governance.versioning import ProtocolVersionManager
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_gov(tmp_path):
    db_path = str(tmp_path / "gov_test.db")
    storage = Storage(db_path)
    proto_mgr = ProtocolVersionManager(storage)
    gov = GovernanceEngine(storage, proto_mgr)
    return storage, proto_mgr, gov


def _fake_block(index: int, proto_ver: int = 1, finalized: bool = False) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        index=index,
        protocol_version=proto_ver,
        block_hash=f"hash_{index}_{proto_ver}",
        finalized=finalized,
    )


def _mine_child(bc: Blockchain, miner_addr: str, *, proto_ver: int = 1, ts_offset: int = 10) -> Block:
    tip = bc.latest_block()
    idx = tip.index + 1
    diff = bc.get_difficulty()
    ts = int(max(int(tip.timestamp) + ts_offset, int(time.time())))
    cb = Transaction.coinbase(
        miner_addr, bc.compute_reward_sat(idx) / Config.SATOSHI_PER_VSD, idx
    )
    blk = Block(
        index=idx,
        prev_hash=tip.block_hash,
        transactions=[cb],
        timestamp=ts,
        difficulty=diff,
        miner_address=miner_addr,
        protocol_version=proto_ver,
        state_root=bc.dry_run_state_root([cb], miner_addr, idx, int(ts), diff),
    )
    assert blk.mine()
    return blk


class TestV4Section70UpgradeActivationRollback:

    def test_trigger_rollback_rewinds_proto_mgr_allows_reproposal(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(Config, "GOVERNANCE_ACTIVATION_DELAY", 2)
        monkeypatch.setattr(Config, "GOVERNANCE_ROLLBACK_WINDOW", 20)
        monkeypatch.setattr(Config, "GOVERNANCE_ROLLBACK_INVALID_RATE", 0.20)

        storage, proto_mgr, gov = _make_gov(tmp_path)
        try:
            ok, msg = gov.propose_upgrade(
                version=2, signal_start_height=1, threshold=0.75, rollback_window=20
            )
            assert ok, msg

            storage.set_meta("proto_sig:1", "2")
            gov.on_block_applied(_fake_block(1, proto_ver=2, finalized=True))
            p = gov.get_proposal(2)
            assert p is not None and p.phase == UpgradePhase.LOCKED_IN
            assert p.activation_height == 3

            gov.on_block_applied(_fake_block(3, proto_ver=2, finalized=True))
            assert p.phase == UpgradePhase.ACTIVE
            assert proto_mgr.current_version() == 2

            storage.set_meta("block_apply:3", "fail")
            storage.set_meta("block_apply:4", "fail")
            gov.on_block_applied(_fake_block(4, proto_ver=2, finalized=True))
            assert p.phase == UpgradePhase.FAILED

            assert proto_mgr.current_version() == 1
            ok_repropose_v2, reason_v2 = gov.propose_upgrade(
                version=2, signal_start_height=100
            )
            assert ok_repropose_v2 is True, f"Re-proposing v2 should succeed: {reason_v2}"

            ok_skip_v3, _ = gov.propose_upgrade(version=3, signal_start_height=100)
            assert ok_skip_v3 is False
        finally:
            storage.close()

    def test_emergency_disable_rewinds_proto_mgr_active_version_reverts_to_v1(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(Config, "GOVERNANCE_ACTIVATION_DELAY", 2)
        storage, proto_mgr, gov = _make_gov(tmp_path)
        try:
            storage.set_meta("genesis_hash", "00" * 32)
            ok, msg = gov.propose_upgrade(
                version=2, signal_start_height=1, threshold=0.75, rollback_window=20
            )
            assert ok, msg
            storage.set_meta("proto_sig:1", "2")
            gov.on_block_applied(_fake_block(1, proto_ver=2, finalized=True))
            gov.on_block_applied(_fake_block(3, proto_ver=2, finalized=True))
            assert gov.get_proposal(2).phase == UpgradePhase.ACTIVE
            assert proto_mgr.current_version() == 2

            w1 = Wallet.generate()
            w2 = Wallet.generate()
            now = 1_700_000_000
            v1 = gov.sign_emergency_vote(w1, 2, now=now)
            v2 = gov.sign_emergency_vote(w2, 2, now=now)
            acc1, dis1, _ = gov.record_emergency_vote(
                v1, is_eligible=lambda _: True, now=now
            )
            assert acc1 and not dis1
            acc2, dis2, _ = gov.record_emergency_vote(
                v2, is_eligible=lambda _: True, now=now
            )
            assert acc2 and dis2

            p = gov.get_proposal(2)
            assert p.phase == UpgradePhase.FAILED
            assert p.disabled is True

            assert proto_mgr.current_version() == 1
            assert gov.get_active_version() == 1
        finally:
            storage.close()

    def test_trigger_rollback_uses_rollback_height_for_cooldown(
        self, tmp_path
    ):
        storage, proto_mgr, gov = _make_gov(tmp_path)
        try:
            p = UpgradeProposal(
                version=2,
                phase=UpgradePhase.ACTIVE,
                signal_start_height=50,
                signal_end_height=150,
                lock_in_height=100,
                activation_height=200,
                threshold=0.75,
                rollback_window=100,
            )
            gov._proposals[2] = p

            for _ in range(3):
                p.phase = UpgradePhase.ACTIVE
                gov._trigger_rollback(p, "test rollback", height=300)

            assert gov._cooldown_until_height == 500
            ok, _ = gov.propose_upgrade(version=2, signal_start_height=301)
            assert ok is False, "Proposal during cooldown must be rejected"
        finally:
            storage.close()

    def test_accept_chain_enforces_post_activation_version(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(Config, "GOVERNANCE_ACTIVATION_DELAY", 2)
        monkeypatch.setattr(Config, "GOVERNANCE_ROLLBACK_WINDOW", 50)
        monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.5)

        db_path = str(tmp_path / "chain_test.db")
        storage = Storage(db_path)
        bc = Blockchain(storage)
        miner = Wallet.generate().address
        try:
            ok, msg = bc._governance.propose_upgrade(
                version=2, signal_start_height=1, threshold=0.75, rollback_window=50
            )
            assert ok, msg

            b1 = _mine_child(bc, miner, proto_ver=2, ts_offset=10)
            ok1, msg1 = bc.apply_block(b1)
            assert ok1, msg1
            bc._governance.on_block_applied(b1)

            p = bc._governance.get_proposal(2)
            assert p.phase == UpgradePhase.LOCKED_IN
            assert p.activation_height == 3

            b2 = _mine_child(bc, miner, proto_ver=1, ts_offset=10)
            ok2, msg2 = bc.apply_block(b2)
            assert ok2, msg2
            bc._governance.on_block_applied(b2)
            assert p.phase == UpgradePhase.LOCKED_IN

            b3 = _mine_child(bc, miner, proto_ver=1, ts_offset=10)
            db_tmp = str(tmp_path / "helper.db")
            st_tmp = Storage(db_tmp)
            bc_tmp = Blockchain(st_tmp)
            try:
                assert bc_tmp.apply_block(b1)[0]
                assert bc_tmp.apply_block(b2)[0]
                assert bc_tmp.apply_block(b3)[0]
                b4 = _mine_child(bc_tmp, miner, proto_ver=1, ts_offset=10)
            finally:
                st_tmp.close()

            ok_batch, msg_batch = bc.accept_chain([b3, b4])
            assert ok_batch is False, f"accept_chain should reject post-activation old-version blocks: {msg_batch}"
            assert bc.height() == 3
        finally:
            storage.close()
