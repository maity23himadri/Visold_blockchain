"""V4 Regression Tests for Section 60: Economic Monitoring, Collusion Detection & Rate Defection."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.chain.blockchain import Blockchain
from visold.consensus.hashrate_governor import HashrateGovernor
from visold.consensus.rate_defection import RateDefectionAuditor
from visold.economics.monitor import EconomicMonitor
from visold.kernel.config import Config
from visold.kernel.messages import MSG_RATE_DEFECTION_EVIDENCE
from visold.wallet.wallet import Wallet


class _InMemoryRateStorage:
    def __init__(self, blocks: dict[int, SimpleNamespace]):
        self._blocks = blocks
        self._state = None
        self.slashes: list[tuple[str, float]] = []

    def get_block(self, height: int):
        return self._blocks.get(height)

    def get_rate_defection_state(self):
        return self._state

    def set_rate_defection_state(self, payload: dict):
        self._state = {
            "offenses": dict(payload.get("offenses", {})),
            "last_offense_block": dict(payload.get("last_offense_block", {})),
            "banned": list(payload.get("banned", [])),
            "seen_evidence": list(payload.get("seen_evidence", [])),
        }

    def slash_with_rate(self, miner: str, pct: float):
        self.slashes.append((miner, pct))


def _configure_rate_audit(
    monkeypatch,
    *,
    window: int = 10,
    cadence: int = 5,
    threshold: float = 2.0,
    consecutive: int = 3,
    min_share: float = 0.03,
    tolerance: float = 0.10,
    auto_slash: bool = True,
):
    monkeypatch.setattr(Config, "RATE_AUDIT_WINDOW", window)
    monkeypatch.setattr(Config, "RATE_AUDIT_CADENCE", cadence)
    monkeypatch.setattr(Config, "RATE_AUDIT_THRESHOLD", threshold)
    monkeypatch.setattr(Config, "RATE_AUDIT_CONSECUTIVE", consecutive)
    monkeypatch.setattr(Config, "RATE_AUDIT_MIN_SHARE", min_share)
    monkeypatch.setattr(Config, "RATE_AUDIT_VERIFY_TOLERANCE", tolerance)
    monkeypatch.setattr(Config, "AUTO_SLASH_RATE_DEFECTION", auto_slash)
    monkeypatch.setattr(Config, "RATE_SLASH_SCHEDULE", [0.05, 0.25, 0.75])


def test_node_id_mapped_to_miner_address_enables_rate_audit(monkeypatch):
    """V4 Fix:
    _maybe_run_rate_audit maps peer node_ids and local node to miner_address
    via _peer_addresses / _own_address, so rate defection is detected and verified.
    """
    _configure_rate_audit(monkeypatch, window=10, cadence=5, consecutive=1)

    wallet_a = Wallet.generate()
    wallet_b = Wallet.generate()
    node_id_a = hashlib.sha256(wallet_a.pub_hex.encode()).hexdigest()
    node_id_b = hashlib.sha256(wallet_b.pub_hex.encode()).hexdigest()
    assert node_id_a != wallet_a.address
    assert node_id_b != wallet_b.address

    blocks = {
        h: SimpleNamespace(index=h, miner_address=wallet_a.address)
        for h in range(1, 11)
    }
    storage = _InMemoryRateStorage(blocks)

    gov = HashrateGovernor()
    gov.update_local_actual_hashrate(100.0)
    gov.record_peer_hashrate(node_id_b, 300.0)
    gov._peer_addresses = {node_id_b: wallet_b.address}

    mining_engine = SimpleNamespace(get_hashrate_governor=lambda: gov)
    sent = []
    net = SimpleNamespace(
        node_id=node_id_a,
        _mining_engine_ref=mining_engine,
        broadcast_message=lambda msg: sent.append(msg),
    )

    auditor = RateDefectionAuditor(storage, None)
    chain = Blockchain.__new__(Blockchain)
    chain.storage = storage
    chain._network = net
    chain._rate_auditor = auditor
    chain._own_address = wallet_a.address

    chain._maybe_run_rate_audit(10)
    assert len(sent) == 1
    assert sent[0]["miner"] == wallet_a.address

    ev = {
        "type": MSG_RATE_DEFECTION_EVIDENCE,
        "miner": wallet_a.address,
        "window_start": 1,
        "window_end": 10,
        "ratio": 4.0,
        "consecutive": 1,
    }
    cap_registry_from_p2p = {wallet_b.address: 300.0, wallet_a.address: 100.0}
    accepted, reason = auditor.handle_received_evidence(ev, cap_registry_from_p2p)
    assert accepted is True
    assert reason == "slashed"


def test_sliding_window_off_cadence_rejected_no_amplification(monkeypatch):
    """V4 Fix:
    handle_received_evidence() enforces cadence alignment and non-overlapping
    windows, rejecting shifted +1 sliding-window packets.
    """
    _configure_rate_audit(
        monkeypatch, window=20, cadence=5, threshold=2.0, consecutive=3, auto_slash=True
    )

    blocks = {h: SimpleNamespace(index=h, miner_address="M") for h in range(1, 41)}
    storage = _InMemoryRateStorage(blocks)
    auditor = RateDefectionAuditor(storage, None)
    caps = {"M": 1.0, "OTHER": 3.0}

    ev30 = {
        "type": MSG_RATE_DEFECTION_EVIDENCE,
        "miner": "M",
        "window_start": 11,
        "window_end": 30,
        "ratio": 4.0,
        "consecutive": 3,
    }
    accepted, reason = auditor.handle_received_evidence(ev30, caps)
    assert accepted is True
    assert reason == "slashed"

    for w_end in (31, 32, 33):
        ev = {
            "type": MSG_RATE_DEFECTION_EVIDENCE,
            "miner": "M",
            "window_start": w_end - 20 + 1,
            "window_end": w_end,
            "ratio": 4.0,
            "consecutive": 3,
        }
        accepted, _reason = auditor.handle_received_evidence(ev, caps)
        assert accepted is False

    assert auditor.offense_count("M") == 1
    assert auditor.is_banned("M") is False
    assert [pct for _, pct in storage.slashes] == [0.05]


def test_evidence_replay_after_restart_deduplicated(monkeypatch):
    """V4 Fix:
    _seen_evidence is persisted across restarts, so replaying the same packet
    after restart does not re-slash.
    """
    _configure_rate_audit(
        monkeypatch, window=10, cadence=5, threshold=2.0, consecutive=1, auto_slash=True
    )
    blocks = {h: SimpleNamespace(index=h, miner_address="M") for h in range(1, 11)}
    storage = _InMemoryRateStorage(blocks)
    caps = {"M": 1.0, "OTHER": 3.0}
    ev = {
        "type": MSG_RATE_DEFECTION_EVIDENCE,
        "miner": "M",
        "window_start": 1,
        "window_end": 10,
        "ratio": 4.0,
        "consecutive": 1,
    }

    auditor1 = RateDefectionAuditor(storage, None)
    accepted, reason = auditor1.handle_received_evidence(ev, caps)
    assert accepted is True
    assert reason == "slashed"
    assert auditor1.offense_count("M") == 1

    for _ in range(3):
        auditor = RateDefectionAuditor(storage, None)
        accepted, reason = auditor.handle_received_evidence(ev, caps)
        assert auditor.offense_count("M") == 1

    assert auditor.is_banned("M") is False
    assert [pct for _, pct in storage.slashes] == [0.05]


def test_reorg_rollback_rewinds_rate_auditor_to_audit_new_canonical_blocks(monkeypatch):
    """V4 Fix:
    RateDefectionAuditor.on_rollback() rewinds _last_audit_height so new
    canonical blocks at or below the prior tip are audited.
    """
    _configure_rate_audit(
        monkeypatch, window=10, cadence=5, threshold=2.0, consecutive=1, auto_slash=False
    )
    blocks = {h: SimpleNamespace(index=h, miner_address="HONEST") for h in range(1, 21)}
    storage = _InMemoryRateStorage(blocks)
    auditor = RateDefectionAuditor(storage, None)
    caps = {"M": 1.0, "HONEST": 3.0}

    assert auditor.run_audit_cycle(15, caps) == []
    assert auditor._last_audit_height == 15

    auditor.on_rollback(10)
    assert auditor._last_audit_height == 10

    for h in range(1, 16):
        blocks[h] = SimpleNamespace(index=h, miner_address="M")

    evidence = auditor.run_audit_cycle(15, caps)
    assert len(evidence) == 1
    assert evidence[0]["miner"] == "M"


def test_economic_monitor_collusion_detects_multi_block_concentration(monkeypatch):
    """V4 Fix (partial):
    EconomicMonitor.record_validator_sigs() aggregates validator signatures across
    COMPETITION_WINDOW (10) blocks so _check_collusion() detects concentrated top-N
    signers when share exceeds COLLUSION_SIG_OVERLAP (note: default 0.80 remains
    mathematically unreachable for deduplicated sigs in a 10-block window; see remaining_051_060.md).
    """
    monkeypatch.setattr(Config, "COLLUSION_SIG_OVERLAP", 0.70)
    warnings = []
    monkeypatch.setattr("visold.economics.monitor.log.warning", lambda m, *a, **k: warnings.append(str(m)))

    mon = EconomicMonitor(storage=None)
    for b in range(9):
        mon.record_validator_sigs(["val_0", "val_1", "val_2"], block_hash=f"blk_{b}")
    mon.record_validator_sigs([f"val_{i}" for i in range(15)], block_hash="blk_9")

    assert any("collusion" in w.lower() or "signature concentration" in w.lower() for w in warnings)
