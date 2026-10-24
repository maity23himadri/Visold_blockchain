from __future__ import annotations

import os
import tempfile
import threading
from types import SimpleNamespace

import pytest

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.network.bootstrap_sync import verify_bootstrap_header_chain
from visold.network.p2p import P2PNetwork
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


@pytest.fixture
def cfg(monkeypatch):
    DifficultyEngine.invalidate_cache()
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 2)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 3)
    monkeypatch.setattr(Config, "BOOTSTRAP_HEADER_PAGE_SIZE", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 100)
    monkeypatch.setattr(Config, "SNAPSHOT_KEEP", 3)
    monkeypatch.setattr(Config, "SNAPSHOT_FAST_SYNC_ENABLED", True)
    yield
    DifficultyEngine.invalidate_cache()


def _mine_to(bc, miner, height):
    bc._rolling_pruner.prune_async = lambda _h: None
    eng = ConsensusEngine(bc, miner)
    while bc.height() < height:
        b = eng.build_candidate_block(miner.address)
        assert b.mine()
        ok, msg = bc.apply_block(b)
        assert ok, msg


def test_authenticated_import_is_relayable_after_commit_block_arrives(cfg):
    with tempfile.TemporaryDirectory() as td:
        sst = Storage(os.path.join(td, "source.db"))
        source = Blockchain(sst)
        miner = Wallet.generate()
        _mine_to(source, miner, 5)

        entry = next(e for e in source._snapshot_engine.get_manifest() if int(e["height"]) == 4)
        blob = source._snapshot_engine.get_snapshot_blob(4)
        headers = [source.get_block(h).to_dict() for h in range(6)]
        ok, msg, verified, digest = verify_bootstrap_header_chain(
            headers, sst.get_meta("genesis_hash"), 4)
        assert ok, msg
        assert digest == entry["bootstrap_digest"]

        rst = Storage(os.path.join(td, "relay.db"))
        relay = Blockchain(rst)
        ok, msg = relay._snapshot_engine.restore_authenticated_bootstrap(blob, digest, verified)
        assert ok, msg
        # At exact H the H+1 commitment block is not locally present yet, so
        # fail closed for serving even though the verified blob is cached.
        assert all(int(e["height"]) != 4 for e in relay._snapshot_engine.get_servable_manifest())
        assert relay._snapshot_engine.get_snapshot_blob(4) == blob

        relay.layer2._try_restore_from_storage()
        ok, msg = relay.apply_block(source.get_block(5))
        assert ok, msg
        served = relay._snapshot_engine.get_servable_manifest()
        e4 = next(e for e in served if int(e["height"]) == 4)
        assert e4["bootstrap_digest"] == digest
        assert relay._snapshot_engine.get_snapshot_blob(4) == blob


def test_rollback_removes_future_snapshot_and_never_advertises_it(cfg):
    with tempfile.TemporaryDirectory() as td:
        st = Storage(os.path.join(td, "chain.db"))
        bc = Blockchain(st)
        miner = Wallet.generate()
        _mine_to(bc, miner, 5)
        assert any(int(e["height"]) == 4 for e in bc._snapshot_engine.get_manifest())
        assert bc._snapshot_engine.get_snapshot_blob(4)

        # This test targets snapshot metadata rollback, not the pruning guard.
        st.set_meta("rolling_pruned_until", "0")
        ok, msg = bc.rollback(3)
        assert ok, msg
        assert bc.height() == 3
        assert all(int(e["height"]) <= 3 for e in bc._snapshot_engine.get_manifest())
        assert bc._snapshot_engine.get_snapshot_blob(4) is None
        assert all(int(e["height"]) <= 2 for e in bc._snapshot_engine.get_servable_manifest())


def _peer(pid, height):
    return SimpleNamespace(
        peer_id=pid,
        connected=True,
        advertised_chain_height=height,
        chain_height=height,
        _sync_state_lock=threading.Lock(),
        _authenticated_pruned_recovery_active=False,
        _pruned_recovery_last_attempt_at=0.0,
        _pagination_active=SimpleNamespace(clear=lambda: None),
    )


def test_pruned_recovery_fails_over_from_rolled_back_peer_to_higher_peer(cfg):
    net = P2PNetwork.__new__(P2PNetwork)
    net.blockchain = SimpleNamespace(height=lambda: 600, _snapshot_engine=object())
    net._sync_finish = lambda *_a, **_k: None
    net._sync_request = lambda *_a, **_k: True
    net._lock = threading.RLock()
    low = _peer("rolled-back-892", 892)
    high = _peer("healthy-1490", 1490)
    net.peers = {low.peer_id: low, high.peer_id: high}
    calls = []
    done = threading.Event()

    def recover(peer):
        calls.append(peer.peer_id)
        if peer is high:
            done.set()
            return True
        return False

    net._authenticated_pruned_recovery_from_peer = recover
    net._on_chain_sync_result(
        low,
        [SimpleNamespace(index=601)],
        False,
        "Block 601 is pruned/header-only; required historical block body is pruned",
        False,
        0,
        "req-pruned",
    )
    assert done.wait(2), calls
    assert calls[:2] == ["rolled-back-892", "healthy-1490"]
