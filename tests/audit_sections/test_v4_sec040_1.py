"""Section 40 Audit: Consensus Failure Handling and Adversarial Network Conditions.

V4 regression tests verifying:
1. PanicCircuitBreaker OPEN (read-only) blocks P2P MSG_CHAIN fallback.
2. Adversarial MSG_CHAIN with non-integer server_height is rejected cleanly
   without raising TypeError or leaving _sync_pending stuck in 'processing'.
"""

import os
import threading
import time

import pytest

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.kernel.messages import MSG_CHAIN
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.p2p import P2PNetwork
from visold.resilience.panic_breaker import PanicCircuitBreaker
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_chain_env(tmp_path, name="node"):
    db_path = os.path.join(str(tmp_path), f"{name}.db")
    storage = Storage(db_path)
    bc = Blockchain(storage)
    wallet = Wallet.generate()
    return storage, bc, wallet


def _mine_next_block(bc: Blockchain, miner_addr: str) -> Block:
    tip = bc.latest_block()
    height = tip.index + 1
    subsidy = bc.compute_reward(height)
    cb = Transaction.coinbase(miner_addr, subsidy, height)
    diff = bc.get_difficulty()
    ts = max(int(time.time()), int(tip.timestamp) + 1)
    sr = bc.dry_run_state_root(
        [cb], miner_addr, height, timestamp=ts, difficulty=diff
    )
    blk = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=[cb],
        miner_address=miner_addr,
        difficulty=diff,
        timestamp=ts,
        state_root=sr,
    )
    assert blk.mine(), f"Failed to mine block {height}"
    return blk


class _DummyPeer:
    def __init__(self, peer_id="peer_adversary_001", ip="127.0.0.1"):
        self.peer_id = peer_id
        self.ip = ip
        self.port = 9000
        self.connected = True
        self.trust_level = "HIGH"
        self.last_seen = time.time()
        self._sync_state_lock = threading.Lock()
        self._sync_pending = None
        self._sync_last_result = None
        self._sync_request_seq = 0
        self._sync_busy_retries = 0
        self._sync_last_reject_at = 0.0
        self._pagination_active = threading.Event()
        self._fork_sync_buffer = []
        self._fork_sync_buffer_bytes = 0
        self._fork_sync_target_height = -1
        self._bootstrap_header_queue = None
        self._bootstrap_header_request_id = None
        self.sent = []

    def send(self, msg):
        self.sent.append(msg)


def _close_p2p(p2p: P2PNetwork) -> None:
    try:
        p2p.stop()
    except Exception:
        pass
    for attr in ("_listen_sock",):
        sock = getattr(p2p, attr, None)
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    udp = getattr(p2p, "_udp", None)
    if udp is not None and getattr(udp, "_sock", None) is not None:
        try:
            udp._sock.close()
        except Exception:
            pass


@pytest.fixture(scope="module")
def mined_block1(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("mined_b1")
    storage, miner_bc, miner_wallet = _make_chain_env(tmp_dir, "miner")
    blk1 = _mine_next_block(miner_bc, miner_wallet.address)
    ok_m, msg_m = miner_bc.apply_block(blk1)
    assert ok_m, f"miner apply failed: {msg_m}"
    storage.close()
    return blk1


def test_msg_chain_respects_open_panic_circuit_breaker(
    tmp_path, mined_block1
):
    """V4 regression (Finding 1): When PanicCircuitBreaker is OPEN (read-only mode),
    P2PNetwork._handle_message(MSG_CHAIN) drops incoming blocks instead of falling
    back to _apply_chain_direct().
    """
    storage, bc, wallet = _make_chain_env(tmp_path, "target")
    assert bc.height() == 0

    breaker = PanicCircuitBreaker()
    for i in range(max(1, int(Config.CIRCUIT_BREAKER_VIOLATIONS))):
        breaker.record_violation(f"SAFETY VIOLATION: test corruption #{i}")
    assert breaker.is_open, "PanicCircuitBreaker must be OPEN"
    assert breaker.check_allows_write()[0] is False

    engine = StateEngine(bc, bc._governance, storage)
    engine._circuit_breaker = breaker

    p2p = P2PNetwork(bc, wallet, storage, port=29400)
    p2p.set_state_engine(engine)

    try:
        peer = _DummyPeer("peer_sync_001")
        with p2p._lock:
            p2p.peers[peer.peer_id] = peer

        msg = {
            "type": MSG_CHAIN,
            "blocks": [mined_block1.to_dict()],
            "server_height": 1,
            "server_tip_hash": mined_block1.block_hash,
        }

        p2p._handle_message(peer, msg)
        time.sleep(0.2)

        assert bc.height() == 0
    finally:
        _close_p2p(p2p)
        breaker.stop()
        storage.close()


@pytest.mark.parametrize("bad_server_height", [None, "10", {"h": 10}])
def test_msg_chain_non_int_server_height_rejected_cleanly(
    tmp_path, mined_block1, bad_server_height
):
    """V4 regression (Finding 2): Adversarial MSG_CHAIN with non-integer
    server_height is rejected cleanly without raising TypeError or leaving
    _sync_pending stuck in 'processing'.
    """
    storage, bc, wallet = _make_chain_env(tmp_path, "node_h0")
    p2p = P2PNetwork(bc, wallet, storage, port=29410)
    try:
        peer = _DummyPeer("peer_adv_002")
        req_id = "req-adv-1"
        peer._sync_pending = {
            "id": req_id,
            "from_idx": 1,
            "to_idx": 200,
            "kind": "test",
            "sent_at": time.monotonic(),
            "status": "waiting",
        }

        msg = {
            "type": MSG_CHAIN,
            "blocks": [mined_block1.to_dict()],
            "server_height": bad_server_height,
            "request_id": req_id,
        }

        p2p._handle_message(peer, msg)

        assert peer._sync_pending is None or peer._sync_pending.get("status") != "processing"
    finally:
        _close_p2p(p2p)
        storage.close()


def test_msg_chain_fork_branch_non_int_server_height_rejected_cleanly(
    tmp_path, mined_block1
):
    """V4 regression (Finding 2b): Diverging block with non-integer server_height
    is rejected cleanly without raising TypeError or buffering invalid fork blocks.
    """
    storage, bc, wallet = _make_chain_env(tmp_path, "local_fork")
    ok, msg_apply = bc.apply_block(mined_block1)
    assert ok, msg_apply

    _, adv_bc, adv_wallet = _make_chain_env(tmp_path, "adv_fork")
    blk1_fork = _mine_next_block(adv_bc, adv_wallet.address)
    assert blk1_fork.block_hash != mined_block1.block_hash

    p2p = P2PNetwork(bc, wallet, storage, port=29420)
    try:
        peer = _DummyPeer("peer_adv_003")
        req_id = "req-adv-fork-1"
        peer._sync_pending = {
            "id": req_id,
            "from_idx": 0,
            "to_idx": 199,
            "kind": "test-fork",
            "sent_at": time.monotonic(),
            "status": "waiting",
        }

        msg = {
            "type": MSG_CHAIN,
            "blocks": [blk1_fork.to_dict()],
            "server_height": "5",
            "request_id": req_id,
        }

        p2p._handle_message(peer, msg)

        assert peer._sync_pending is None or peer._sync_pending.get("status") != "processing"
        assert len(peer._fork_sync_buffer) == 0
    finally:
        _close_p2p(p2p)
        storage.close()
