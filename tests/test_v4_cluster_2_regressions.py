"""V4 positive regression tests converted from Cluster 2 adversarial tests.

Verifies that all 15 Cluster 2 audit findings (new discoveries and historical
findings across chain, consensus, mining, economics, and governance) are fixed
in V4.
"""

import json
import threading
import time
from types import SimpleNamespace

import pytest

from visold.chain.blockchain import Blockchain
from visold.consensus.rate_defection import RateDefectionAuditor
from visold.economics.monitor import EconomicMonitor
from visold.economics.rewards import (
    RewardError,
    build_coinbase,
    validate_block_rewards,
)
from visold.governance.engine import GovernanceEngine, UpgradePhase
from visold.governance.versioning import ProtocolVersionManager
from visold.kernel.config import Config
from visold.kernel.units import to_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mining.parallel_miner import ParallelMiner
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


@pytest.fixture
def tmp_storage(tmp_path):
    db_path = str(tmp_path / "test_v4_cluster2.db")
    st = Storage(db_path=db_path)
    yield st
    st.close()


def _mine_and_apply(bc: Blockchain, miner_addr: str, txs=None, timestamp=None, proto_ver=1):
    tip = bc.latest_block()
    height = tip.index + 1 if tip else 0
    prev_hash = tip.block_hash if tip else "0" * 64
    diff = bc.get_difficulty()
    reward = bc.compute_reward(height)
    cb = Transaction.coinbase(miner_addr, reward, height)
    all_txs = [cb] + list(txs or [])
    ts = timestamp if timestamp is not None else max(int(time.time()), (tip.timestamp + 1) if tip else 1)
    sr = bc.dry_run_state_root(all_txs, miner_addr, height, timestamp=ts, difficulty=diff)
    blk = Block(
        index=height,
        prev_hash=prev_hash,
        transactions=all_txs,
        miner_address=miner_addr,
        difficulty=diff,
        timestamp=ts,
        state_root=sr,
        protocol_version=proto_ver,
    )
    assert blk.mine()
    ok, msg = bc.apply_block(blk)
    assert ok, f"apply_block failed at height {height}: {msg}"
    return blk


# ── NEW FINDINGS REGRESSIONS ─────────────────────────────────────────────────


def test_new_c2_01_gov_check_lock_in_ignores_prewindow_and_expires_past_end(tmp_storage, monkeypatch):
    """NEW-C2-01: _check_lock_in ignores pre-window proto_sig entries and fails past signal_end_height."""
    monkeypatch.setattr(Config, "FORK_SIGNAL_WINDOW", 10)
    monkeypatch.setattr(Config, "FORK_SIGNAL_THRESHOLD", 0.75)
    proto = ProtocolVersionManager(tmp_storage)
    gov = GovernanceEngine(tmp_storage, proto)

    # Miners signal v2 at heights 1..10 BEFORE any proposal exists
    for h in range(1, 11):
        proto.record_block_version(2, h)

    # Proposal has signal_start_height=11, signal_end_height=21
    ok, _ = gov.propose_upgrade(version=2, signal_start_height=11, threshold=0.75)
    assert ok

    # On the first block of the window (height 11) signaling v1, pre-window v2 signals
    # must not bleed in; proposal remains SIGNALING.
    blk11 = Block(index=11, prev_hash="a" * 64, transactions=[], miner_address="VSDminer", difficulty=0.5, protocol_version=1)
    proto.record_block_version(1, 11)
    gov.on_block_applied(blk11)
    assert gov.get_proposal(2).phase == UpgradePhase.SIGNALING

    # Part B: expired window transitions to FAILED when height > signal_end_height
    proto2 = ProtocolVersionManager(tmp_storage)
    gov2 = GovernanceEngine(tmp_storage, proto2)
    gov2._proposals.clear()
    ok, _ = gov2.propose_upgrade(version=2, signal_start_height=20, threshold=0.75)
    assert ok
    for h in range(25, 36):
        proto2.record_block_version(2, h)
    blk35 = Block(index=35, prev_hash="b" * 64, transactions=[], miner_address="VSDminer", difficulty=0.5, protocol_version=2)
    gov2.on_block_applied(blk35)
    assert gov2.get_proposal(2).phase == UpgradePhase.FAILED


def test_new_c2_02_gov_propose_upgrade_rejects_negative_and_bool_signal_start(tmp_storage):
    """NEW-C2-02: propose_upgrade rejects negative and bool signal_start_height."""
    proto = ProtocolVersionManager(tmp_storage)
    gov = GovernanceEngine(tmp_storage, proto)

    for bad_start in (-100, True, False):
        ok, msg = gov.propose_upgrade(version=2, signal_start_height=bad_start)
        assert not ok
        assert "signal_start_height" in msg
        assert gov.get_proposal(2) is None


# ── HISTORICAL FINDINGS REGRESSIONS ──────────────────────────────────────────


def test_sec30_coinbase_register_tx_rejected(tmp_storage, monkeypatch):
    """Sec 30/57 Finding 1: coinbase with tx_type=register is rejected and never registers COINBASE."""
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.5)
    monkeypatch.setattr(Config, "MIN_DIFFICULTY", 0.5)
    bc = Blockchain(tmp_storage)
    miner = Wallet.generate()

    tip = bc.latest_block()
    height = 1
    diff = bc.get_difficulty()
    reward = bc.compute_reward(height)
    cb = Transaction(
        sender="COINBASE",
        receiver=miner.address,
        amount=reward,
        fee=0.0,
        memo="investor",
        nonce=0,
        tx_type=Transaction.TYPE_REGISTER,
    )
    ts = max(int(time.time()), tip.timestamp + 1)
    sr = bc.dry_run_state_root([cb], miner.address, height, timestamp=ts, difficulty=diff)
    blk = Block(
        index=1,
        prev_hash=tip.block_hash,
        transactions=[cb],
        miner_address=miner.address,
        difficulty=diff,
        timestamp=ts,
        state_root=sr,
    )
    assert blk.mine()
    ok_val, msg_val = bc.validate_block(blk)
    assert not ok_val
    assert "transfer" in msg_val.lower()
    ok_app, _ = bc.apply_block(blk)
    assert not ok_app
    assert tmp_storage.get_role("COINBASE") is None


def test_sec30_stale_height_block_rejected(tmp_storage, monkeypatch):
    """Sec 30 (S3) Finding 1: apply_block rejects stale height <= tip and preserves canonical chain."""
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.5)
    monkeypatch.setattr(Config, "MIN_DIFFICULTY", 0.5)
    bc = Blockchain(tmp_storage)
    m1 = Wallet.generate()
    m2 = Wallet.generate()
    b1 = _mine_and_apply(bc, m1.address)
    b2 = _mine_and_apply(bc, m2.address, timestamp=b1.timestamp + 1)

    gen = tmp_storage.get_block(0)
    diff_now = bc.get_difficulty()
    cb_alt = Transaction.coinbase(m2.address, bc.compute_reward(1), 1)
    ts_alt = b2.timestamp + 1
    sr_alt = bc.dry_run_state_root([cb_alt], m2.address, 1, timestamp=ts_alt, difficulty=diff_now)
    b1_alt = Block(
        index=1,
        prev_hash=gen.block_hash,
        transactions=[cb_alt],
        miner_address=m2.address,
        difficulty=diff_now,
        timestamp=ts_alt,
        state_root=sr_alt,
    )
    assert b1_alt.mine()
    ok, msg = bc.apply_block(b1_alt)
    assert not ok
    assert "height" in msg.lower()
    assert tmp_storage.get_block(1).block_hash == b1.block_hash
    assert tmp_storage.get_block(2).prev_hash == tmp_storage.get_block(1).block_hash


def test_sec30_54_57_duplicate_coinbase_txid_rejected(tmp_storage, monkeypatch):
    """Sec 30/54/57 Finding 2: duplicate coinbase tx_id across heights is rejected."""
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.5)
    monkeypatch.setattr(Config, "MIN_DIFFICULTY", 0.5)
    bc = Blockchain(tmp_storage)
    miner = Wallet.generate()
    ts = int(time.time()) + 10
    cb1 = Transaction(
        sender="COINBASE",
        receiver=miner.address,
        amount=bc.compute_reward(1),
        fee=0.0,
        memo="shared",
        nonce=0,
        timestamp=ts,
        tx_type=Transaction.TYPE_TRANSFER,
    )
    tip0 = bc.latest_block()
    sr1 = bc.dry_run_state_root([cb1], miner.address, 1, timestamp=ts, difficulty=bc.get_difficulty())
    b1 = Block(
        index=1,
        prev_hash=tip0.block_hash,
        transactions=[cb1],
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        timestamp=ts,
        state_root=sr1,
    )
    assert b1.mine()
    assert bc.apply_block(b1)[0]

    cb2 = Transaction(
        sender="COINBASE",
        receiver=miner.address,
        amount=bc.compute_reward(2),
        fee=0.0,
        memo="shared",
        nonce=0,
        timestamp=ts,
        tx_type=Transaction.TYPE_TRANSFER,
    )
    assert cb2.tx_id == cb1.tx_id
    sr2 = bc.dry_run_state_root([cb2], miner.address, 2, timestamp=ts + 1, difficulty=bc.get_difficulty())
    b2 = Block(
        index=2,
        prev_hash=b1.block_hash,
        transactions=[cb2],
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        timestamp=ts + 1,
        state_root=sr2,
    )
    assert b2.mine()
    ok, _ = bc.apply_block(b2)
    assert not ok
    assert tmp_storage.tx_exists(cb1.tx_id)


def test_sec55_61_63_same_block_cross_role_reentry_enforces_min_stake(tmp_storage, monkeypatch):
    """Sec 55/61/63: REGISTER(none) + REGISTER(investor, 100 sat) in same block still enforces MIN_INVESTOR_STAKE."""
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.5)
    monkeypatch.setattr(Config, "MIN_DIFFICULTY", 0.5)
    bc = Blockchain(tmp_storage)
    alice = Wallet.generate()
    _mine_and_apply(bc, alice.address)
    b2 = _mine_and_apply(bc, alice.address)

    reg_miner = Transaction(
        sender=alice.address,
        receiver="",
        amount=10.0,
        fee=0.1,
        memo="miner",
        nonce=0,
        expiry=b2.timestamp + 3600,
        tx_type=Transaction.TYPE_REGISTER,
    )
    reg_miner.sign(alice)
    b3 = _mine_and_apply(bc, alice.address, txs=[reg_miner], timestamp=b2.timestamp + 1)

    unreg = Transaction(
        sender=alice.address,
        receiver="",
        amount=0.0,
        fee=0.00001,
        memo="none",
        nonce=1,
        expiry=b3.timestamp + 3600,
        tx_type=Transaction.TYPE_REGISTER,
    )
    unreg.sign(alice)
    re_inv = Transaction(
        sender=alice.address,
        receiver="",
        amount=0.000001,
        fee=0.00001,
        memo="investor",
        nonce=2,
        expiry=b3.timestamp + 3600,
        tx_type=Transaction.TYPE_REGISTER,
    )
    re_inv.sign(alice)

    tip = bc.latest_block()
    height = tip.index + 1
    diff = bc.get_difficulty()
    cb = Transaction.coinbase(alice.address, bc.compute_reward(height), height)
    all_txs = [cb, unreg, re_inv]
    ts = b3.timestamp + 1
    sr = bc.dry_run_state_root(all_txs, alice.address, height, timestamp=ts, difficulty=diff)
    b4 = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=all_txs,
        miner_address=alice.address,
        difficulty=diff,
        timestamp=ts,
        state_root=sr,
    )
    assert b4.mine()
    ok, msg = bc.apply_block(b4)
    assert not ok
    assert "minimum" in msg.lower()
    role = tmp_storage.get_role(alice.address)
    assert role["role"] == "miner"


def test_sec38_62_zero_stake_investor_excluded_from_snapshot(tmp_storage):
    """Sec 38/62: zero-stake investors are excluded from validator snapshots."""
    bc = Blockchain(tmp_storage)
    for _ in range(3):
        w = Wallet.generate()
        tmp_storage.set_role(w.address, "investor", 0.0)
    snap = bc._current_validator_snapshot()
    assert snap == []


def test_sec34_fork_choice_walks_fork_branches(tmp_storage):
    """Sec 34: GovernanceEngine.fork_choice walks prev_hash ancestry for unindexed fork tips."""
    proto = ProtocolVersionManager(tmp_storage)
    gov = GovernanceEngine(tmp_storage, proto)
    Blockchain(tmp_storage)
    gen = tmp_storage.get_block(0)

    b1_canon = Block(
        index=1,
        prev_hash=gen.block_hash,
        transactions=[],
        miner_address="VSDa",
        difficulty=2.0,
        timestamp=gen.timestamp + 1,
    )
    b1_canon.block_hash = "ffff" + "0" * 60
    b1_canon.finalized = True
    tmp_storage.save_block(b1_canon)

    # Fork tip at height 2 builds on b1_canon, so it inherits b1_canon's finality and has higher PoW
    b2_fork = Block(
        index=2,
        prev_hash=b1_canon.block_hash,
        transactions=[],
        miner_address="VSDb",
        difficulty=10.0,
        timestamp=gen.timestamp + 2,
    )
    b2_fork.block_hash = "0000" + "1" * 60
    winner = gov.fork_choice(tmp_storage, b1_canon, b2_fork)
    assert winner.block_hash == b2_fork.block_hash


def test_sec66_68_69_70_governance_restart_and_rollback_sync(tmp_storage):
    """Sec 66/68/69/70: restart restores proto_mgr version, rollback rewinds version and anchors cooldown."""
    proto1 = ProtocolVersionManager(tmp_storage)
    gov1 = GovernanceEngine(tmp_storage, proto1)
    ok, _ = gov1.propose_upgrade(version=2, signal_start_height=1, threshold=0.5)
    assert ok
    p = gov1.get_proposal(2)
    p.phase = UpgradePhase.ACTIVE
    p.lock_in_height = 100
    p.activation_height = 200
    p._persist(tmp_storage)
    proto1.advance_version(2)

    # Restart simulation: _load_persisted_proposals restores proto_mgr to active version 2
    proto2 = ProtocolVersionManager(tmp_storage)
    gov2 = GovernanceEngine(tmp_storage, proto2)
    assert proto2.current_version() == 2
    assert gov2.get_active_version() == 2
    ok_prop, _ = gov2.propose_upgrade(version=3, signal_start_height=250)
    assert ok_prop

    # Rollback rewinds proto_mgr to 1 and anchors cooldown on current height (300)
    gov1._ROLLBACK_LIMIT = 1
    gov1._trigger_rollback(p, "test", height=300)
    assert proto1.current_version() == 1
    assert gov1._cooldown_until_height == 300 + gov1._GOVERNANCE_COOLDOWN_BLOCKS


def test_sec66_propose_upgrade_rejects_zero_and_nan_threshold(tmp_storage):
    """Sec 66 Finding 2: propose_upgrade rejects threshold=0.0 and threshold=NaN."""
    proto = ProtocolVersionManager(tmp_storage)
    gov = GovernanceEngine(tmp_storage, proto)

    for bad_thr in (0.0, float("nan")):
        ok, msg = gov.propose_upgrade(version=2, signal_start_height=1, threshold=bad_thr)
        assert not ok
        assert "threshold" in msg.lower()
        assert gov.get_proposal(2) is None


def test_sec50_60_64_rate_defection_enforces_min_share_on_evidence(tmp_storage, monkeypatch):
    """Sec 50/60/64: handle_received_evidence enforces RATE_AUDIT_MIN_SHARE exemption."""
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.5)
    monkeypatch.setattr(Config, "MIN_DIFFICULTY", 0.5)
    monkeypatch.setattr(Config, "RATE_AUDIT_WINDOW", 10)
    monkeypatch.setattr(Config, "RATE_AUDIT_CADENCE", 10)
    monkeypatch.setattr(Config, "RATE_AUDIT_CONSECUTIVE", 2)
    monkeypatch.setattr(Config, "RATE_AUDIT_THRESHOLD", 2.0)
    monkeypatch.setattr(Config, "RATE_AUDIT_MIN_SHARE", 0.05)
    monkeypatch.setattr(Config, "AUTO_SLASH_RATE_DEFECTION", True)

    bc = Blockchain(tmp_storage)
    miner = Wallet.generate()
    other = Wallet.generate()
    tmp_storage.set_role(miner.address, "miner", 100.0)

    for h in range(1, 21):
        winner = miner.address if h in (10, 20) else other.address
        _mine_and_apply(bc, winner)

    cap_reg = {miner.address: 1.0, other.address: 99.0}
    auditor = RateDefectionAuditor(tmp_storage, bc)
    assert auditor.run_audit_cycle(20, cap_reg) == []

    ev = {
        "miner": miner.address,
        "window_start": 11,
        "window_end": 20,
        "ratio": 10.0,
        "consecutive": 2,
    }
    accepted, msg = auditor.handle_received_evidence(ev, cap_reg)
    assert not accepted
    assert "minimum" in msg.lower() or "unverifiable" in msg.lower()


def test_sec52_53_54_rewards_module_fixes():
    """Sec 52/53/54: Coinbase.to_dict preserves satoshi units and validate_block_rewards rejects non-reward tx_type."""
    w = Wallet.generate()
    cb = build_coinbase(w.address, height=1, subsidy=1_000_000_000, fees=0, consensus="pow")
    d = cb.to_dict()
    tx = Transaction.from_dict(d)
    assert to_satoshi(tx.amount) == 1_000_000_000

    fake_blk = SimpleNamespace(
        height=1,
        index=1,
        transactions=[
            {
                "tx_type": "transfer",
                "sender": "COINBASE",
                "receiver": w.address,
                "amount": 1000,
                "nonce": 1,
                "signature": "",
                "data": json.dumps({"subsidy": 1000, "fees": 0}),
            }
        ],
    )
    with pytest.raises(RewardError):
        validate_block_rewards(fake_blk, expected_subsidy=1000, chain_tip_height=0)


def test_sec52_53_compute_reward_sat_edge_cases(tmp_storage):
    """Sec 52/53: compute_reward_sat(0) == 0 and compute_reward_sat(-1) raises ValueError."""
    bc = Blockchain(tmp_storage)
    assert bc.compute_reward_sat(0) == 0
    with pytest.raises(ValueError):
        bc.compute_reward_sat(-1)


def test_sec31_43_parallel_miner_percent_and_nan():
    """Sec 31/43: ParallelMiner fails closed on NaN difficulty and mines headers containing '%'."""
    pm = ParallelMiner()
    blk_nan = Block(index=1, prev_hash="0" * 64, transactions=[], miner_address="VSDminer", difficulty=float("nan"))
    assert not pm.mine(blk_nan)

    blk_pct = Block(index=1, prev_hash="0" * 64, transactions=[], miner_address="VSD%s_miner", difficulty=0.5)
    stop = threading.Event()
    t = threading.Timer(5.0, stop.set)
    t.start()
    ok = pm.mine(blk_pct, stop_event=stop)
    t.cancel()
    assert ok


def test_sec59_60_economic_monitor_detects_dilution_and_collusion(tmp_storage):
    """Sec 59/60: _check_validator_reward_manipulation isolates validator pool and _check_collusion detects concentration."""
    v1 = Wallet.generate()
    v2 = Wallet.generate()
    v3 = Wallet.generate()
    v4 = Wallet.generate()
    v5 = Wallet.generate()
    tmp_storage.set_role(v1.address, "investor", 20.0)
    tmp_storage.set_role(v2.address, "investor", 20.0)
    tmp_storage.set_role(v3.address, "investor", 20.0)
    tmp_storage.set_role(v4.address, "investor", 20.0)
    tmp_storage.set_role(v5.address, "investor", 20.0)

    mon = EconomicMonitor(tmp_storage)
    for _ in range(10):
        mon.record_block_rewards("VSDminer", {"VSDminer": 650_000_000, v1.address: 350_000_000})

    sigs = [v1.address] * 17 + [v2.address, v3.address, v4.address, v5.address]
    mon.record_validator_sigs(sigs)

    assert any(k[0] == "validator_reward" for k in mon._alert_latches)
    assert any(k[0] == "collusion" for k in mon._alert_latches)
