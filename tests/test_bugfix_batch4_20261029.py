from __future__ import annotations

import http.client
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from visold.api.rpc_server import RPCServer
from visold.chain.blockchain import Blockchain
from visold.chain.sequencer import Sequencer
from visold.consensus.rate_defection import RateDefectionAuditor
from visold.kernel.config import Config
from visold.kernel.lru_cache import LRUCache
from visold.kernel.messages import MSG_L2TX
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mining.parallel_miner import ParallelMiner
import visold.mining.parallel_miner as miner_mod
from visold.network.p2p import P2PNetwork
from visold.network.peer_connection import PeerConnection
from visold.rollup.l2_state import L2Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


class _RateStorage:
    def __init__(self):
        self.blocks = {h: SimpleNamespace(miner_address="M") for h in range(1, 5)}
    def get_block(self, h): return self.blocks.get(h)
    def get_rate_defection_state(self): return {}
    def set_rate_defection_state(self, payload): self.persisted = payload


def _configure_rate(monkeypatch):
    monkeypatch.setattr(Config, "RATE_AUDIT_WINDOW", 4)
    monkeypatch.setattr(Config, "RATE_AUDIT_CONSECUTIVE", 1)
    monkeypatch.setattr(Config, "RATE_AUDIT_CADENCE", 1)
    monkeypatch.setattr(Config, "RATE_AUDIT_THRESHOLD", 1.5)
    monkeypatch.setattr(Config, "RATE_AUDIT_VERIFY_TOLERANCE", 0.01)
    monkeypatch.setattr(Config, "AUTO_SLASH_RATE_DEFECTION", False)
    monkeypatch.setattr(Config, "RATE_SLASH_SCHEDULE", [0.05, 0.25, 0.75])


def test_previous_bug11_invalid_packet_cannot_poison_genuine_window(monkeypatch):
    _configure_rate(monkeypatch)
    auditor = RateDefectionAuditor(_RateStorage(), None)
    caps = {"M": 1.0, "OTHER": 3.0}
    bad = {"miner":"M", "window_start":1, "window_end":4,
           "ratio":999.0, "consecutive":1, "actual_wins":123}
    ok, _ = auditor.handle_received_evidence(bad, caps)
    assert not ok
    genuine = dict(bad, ratio=4.0, actual_wins=4)
    ok, msg = auditor.handle_received_evidence(genuine, caps)
    assert ok and msg == "observed"
    assert auditor.offense_count("M") == 1


def test_bug16_nonfinite_claimed_ratio_is_rejected(monkeypatch):
    _configure_rate(monkeypatch)
    auditor = RateDefectionAuditor(_RateStorage(), None)
    caps = {"M": 1.0, "OTHER": 3.0}
    for ratio in (float("nan"), float("inf"), float("-inf")):
        ev = {"miner":"M", "window_start":1, "window_end":4,
              "ratio":ratio, "consecutive":1, "actual_wins":4}
        ok, msg = auditor.handle_received_evidence(ev, caps)
        assert not ok and "finite" in msg.lower()
    assert auditor.offense_count("M") == 0


def _coinbase(chain, miner, height):
    tx = Transaction(sender="COINBASE", receiver=miner.address,
                     amount=chain.compute_reward_sat(height)/Config.SATOSHI_PER_VSD,
                     fee=0.0, nonce=height, timestamp=int(time.time())+height,
                     expiry=0)
    tx.tx_id = tx._compute_id()
    return tx


def test_previous_bug5_low_claimed_difficulty_cannot_trigger_reorg(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    st = Storage(str(tmp_path/"fork.db")); bc = Blockchain(st)
    bc._rolling_pruner.prune_async = lambda _h: None
    miner = Wallet.generate(); attacker = Wallet.generate()
    base = int(time.time())
    # Mine three canonical blocks using the real candidate path.
    from visold.chain.consensus_engine import ConsensusEngine
    eng = ConsensusEngine(bc, miner)
    for _ in range(3):
        b = eng.build_candidate_block(miner.address)
        assert b.mine(); assert bc.apply_block(b)[0]
    ancestor = st.get_block(2)
    honest_tip = bc.latest_block().block_hash
    # Claimed D=0 makes PoW essentially free, but it is not the canonical DAA.
    h = 3
    f1 = Block(index=h, prev_hash=ancestor.block_hash,
               transactions=[_coinbase(bc, attacker, h)],
               miner_address=attacker.address, difficulty=0.0,
               timestamp=max(ancestor.timestamp, int(time.time())), state_root="00"*32)
    f1.seal()
    f2 = Block(index=h+1, prev_hash=f1.block_hash,
               transactions=[_coinbase(bc, attacker, h+1)],
               miner_address=attacker.address, difficulty=0.0,
               timestamp=f1.timestamp+1, state_root="11"*32)
    f2.seal()
    calls=[]
    real=bc.reorg
    def spy(*a, **kw): calls.append(1); return real(*a, **kw)
    monkeypatch.setattr(bc, "reorg", spy)
    ok, msg = bc.accept_chain([ancestor, f1, f2])
    assert not ok and "difficulty mismatch" in msg.lower()
    assert calls == []
    assert bc.latest_block().block_hash == honest_tip


class _Peer:
    peer_id="peer-b4"
    trust_level=PeerConnection.TRUST_HIGH
    def __init__(self): self.sent=[]
    def send(self, msg): self.sent.append(msg); return True


def _bare_l2_net():
    net=P2PNetwork.__new__(P2PNetwork)
    net._check_msg_rate=lambda _p,_t: True
    net._seen_msgs=LRUCache(4096, ttl=3600)
    net._lock=threading.RLock(); net.peers={}; net._eager_peers=set()
    net._sequencer=None
    net._callbacks={}
    return net


def test_bug14_l2_gossip_dedup_ignores_ttl_and_extra_envelope_fields():
    w=Wallet.generate(); r=Wallet.generate(); tx=w.sign_l2_tx(r.address, 10, 0, timestamp=123)
    net=_bare_l2_net(); peer=_Peer(); relays=[]
    net._gossip=lambda msg, exclude=None: relays.append((msg,exclude))
    base={"type":MSG_L2TX, "l2_tx":tx.to_dict(), "ttl":5}
    net._handle_message(peer, dict(base, salt=1))
    net._handle_message(peer, dict(base, ttl=4, salt=2))
    net._handle_message(peer, dict(base, ttl=1, salt=999))
    assert len(relays) == 1


class _ScoreStorage:
    def __init__(self): self.scores=[]
    def add_ban_score(self, peer_id, score): self.scores.append((peer_id,score))

class _SeqSock:
    def __init__(self, chunks): self.chunks=list(chunks); self.timeout=None
    def settimeout(self,v): self.timeout=v
    def gettimeout(self): return self.timeout
    def recv(self,_n): return self.chunks.pop(0) if self.chunks else b""
    def fileno(self): return -1
    def getsockopt(self,*a): raise OSError

class _LoopPeer:
    def __init__(self, payload):
        self.peer_id="peer-malformed"; self.ip="127.0.0.1"; self.port=1
        self.local_outbound=True; self.sock=_SeqSock([payload,b""])
        self.connected=True; self._recv_buf=b""; self._fork_sync_buffer=[]
        self._fork_sync_buffer_bytes=0; self._fork_sync_target_height=-1
    def send(self,_m): return False


def _loop_net():
    n=P2PNetwork.__new__(P2PNetwork); n._running=True; n.storage=_ScoreStorage()
    n._on_peer_disconnect=lambda _p: None
    return n

@pytest.mark.parametrize("frame", [b"[]\n", b'{"type":"X","v":NaN}\n'])
def test_bug15_malformed_json_frames_receive_invalid_message_score(frame):
    net=_loop_net(); peer=_LoopPeer(frame)
    P2PNetwork._peer_message_loop(net, peer)
    assert net.storage.scores
    assert all(score == Config.PEER_SCORE_INVALID_MSG for _,score in net.storage.scores)


def _free_port():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p


def test_bug17_non_ascii_bearer_returns_401_not_handler_exception():
    rpc=RPCServer.__new__(RPCServer); rpc.node=SimpleNamespace(); rpc.rpc_port=_free_port()
    rpc._token="ascii-token"; rpc._server=None; rpc._thread=None
    rpc.start()
    try:
        conn=http.client.HTTPConnection("127.0.0.1", rpc.rpc_port, timeout=3)
        body='{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'
        conn.request("POST", "/", body=body, headers={
            "Authorization":"Bearer café",
            "Content-Type":"application/json",
            "Content-Length":str(len(body.encode())),
        })
        resp=conn.getresponse(); resp.read(); conn.close()
        assert resp.status == 401
    finally:
        rpc.stop()


@pytest.mark.parametrize("method", ["_mine_cuda", "_mine_opencl"])
def test_bug20_gpu_fallback_preserves_dynamic_hps_provider(monkeypatch, method):
    pm=ParallelMiner(); captured={}
    monkeypatch.setattr(miner_mod, "_NUMPY_AVAILABLE", False)
    provider=lambda: 123.0
    def fake_cpu(block, stop_event=None, max_hps=0.0, max_hps_provider=None):
        captured.update(max_hps=max_hps, provider=max_hps_provider); return True
    monkeypatch.setattr(pm, "_mine_cpu", fake_cpu)
    ok=getattr(pm, method)(object(), max_hps=7.0, max_hps_provider=provider)
    assert ok and captured == {"max_hps":7.0, "provider":provider}


def test_bug22_wire_l2_id_mismatch_is_rejected_and_canonical_id_is_preserved():
    a=Wallet.generate(); b=Wallet.generate(); honest=a.sign_l2_tx(b.address, 10, 0, timestamp=123)
    wire=honest.to_dict(); wire["l2_tx_id"]="0"*64
    with pytest.raises(ValueError, match="l2_tx_id"):
        L2Transaction.from_dict(wire)
    roundtrip=L2Transaction.from_dict(honest.to_dict())
    assert roundtrip.l2_tx_id == honest.l2_tx_id == roundtrip._compute_id()
