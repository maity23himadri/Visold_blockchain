import threading
from types import SimpleNamespace

import pytest

from visold.kernel.config import Config
from visold.network.p2p import P2PNetwork


@pytest.mark.parametrize("reason", [
    "Block 3: Bootstrap snapshot commitment mismatch at height 2: declared=x, computed=y",
    "Block 3: Bootstrap commitment parent state is unavailable",
    "Block 3: Cannot compute bootstrap commitment: unable to serialise deterministic bootstrap state",
])
def test_checkpoint_state_failure_dispatches_authenticated_repair_not_genesis_replay(
    monkeypatch, reason
):
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 2)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 3)

    network = P2PNetwork.__new__(P2PNetwork)
    network.blockchain = SimpleNamespace(height=lambda: 2)
    network._sync_finish = lambda *_args, **_kwargs: None
    network._sync_request_calls = []
    network._sync_request = lambda *args, **kwargs: network._sync_request_calls.append((args, kwargs))
    recovered = threading.Event()

    def _recovery(peer, height):
        assert peer.peer_id == "peer-test"
        assert height == 2
        recovered.set()
        return True

    network._recover_same_height_bootstrap_commitment = _recovery
    peer = SimpleNamespace(
        peer_id="peer-test",
        connected=True,
        _pagination_active=threading.Event(),
        _sync_state_lock=threading.Lock(),
        _sync_last_reject_at=0.0,
    )

    network._on_chain_sync_result(
        peer,
        [SimpleNamespace(index=3)],
        False,
        reason,
        False,
        0,
        "test-request",
    )

    assert recovered.wait(timeout=2), "authenticated recovery was not dispatched"
    assert network._sync_request_calls == [], "ineffective legacy 0..199 recovery was sent"


def test_unrelated_checkpoint_block_failure_is_logged_and_does_not_replay_genesis(monkeypatch):
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 2)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 3)

    network = P2PNetwork.__new__(P2PNetwork)
    network.blockchain = SimpleNamespace(height=lambda: 2)
    network._sync_finish = lambda *_args, **_kwargs: None
    network._sync_request_calls = []
    network._sync_request = lambda *args, **kwargs: network._sync_request_calls.append((args, kwargs))
    recovery_calls = []
    network._recover_same_height_bootstrap_commitment = lambda *args: recovery_calls.append(args)
    peer = SimpleNamespace(
        peer_id="peer-test",
        connected=True,
        _pagination_active=threading.Event(),
        _sync_state_lock=threading.Lock(),
        _sync_last_reject_at=0.0,
    )

    network._on_chain_sync_result(
        peer,
        [SimpleNamespace(index=3)],
        False,
        "Block 3: transaction signature invalid",
        False,
        0,
        "test-request",
    )

    assert recovery_calls == [], "unrelated invalid block must not trigger state repair"
    assert network._sync_request_calls == [], "checkpoint rejection must not replay blocks 0..199"
