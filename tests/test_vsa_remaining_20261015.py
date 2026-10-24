"""Regression tests for the audit findings still open after the 2026-10-14 pass.

Covers VSA-15 (ban enforcement across address spellings), with further
sections added per finding as each fix lands.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict, deque

from visold.network.p2p import P2PNetwork
from visold.storage.storage import Storage


def _future(seconds: int = 3600) -> str:
    return json.dumps({"until": int(time.time()) + seconds, "reason": "test"})


def _open_storage(tmp_path) -> Storage:
    return Storage(os.path.join(str(tmp_path), "peers.db"))


def _udp_gate(storage: Storage) -> P2PNetwork:
    """Build just enough of P2PNetwork to run the UDP admission gate."""
    net = object.__new__(P2PNetwork)
    net.storage = storage
    net._lock = threading.RLock()
    net._conn_rate = defaultdict(
        lambda: deque(maxlen=P2PNetwork._CONN_RATE_LIMIT + 1))
    return net


# ── VSA-15: the ban and rate-limit checks see one canonical address ────────

def test_udp_admission_refuses_ipv4_mapped_source_under_individual_ban(tmp_path):
    st = _open_storage(tmp_path)
    try:
        st.set_meta("ip_ban:192.168.1.7", _future())
        net = _udp_gate(st)
        # UDP on the dual-stack socket reports this client as "::ffff:...".
        assert net._udp_admit_inbound(("::ffff:192.168.1.7", 9000)) is False
        # Control: a different address is still admitted.
        assert net._udp_admit_inbound(("192.168.1.8", 9000)) is True
    finally:
        st.close()


def test_udp_admission_refuses_ipv4_mapped_source_inside_banned_subnet(tmp_path):
    st = _open_storage(tmp_path)
    try:
        st.set_meta("subnet_ban:192.168.1.0/24", _future())
        net = _udp_gate(st)
        assert net._udp_admit_inbound(("::ffff:192.168.1.200", 9000)) is False
        assert net._udp_admit_inbound(("192.168.2.200", 9000)) is True
    finally:
        st.close()


def test_expired_individual_ban_is_ignored_for_mapped_udp_source(tmp_path):
    st = _open_storage(tmp_path)
    try:
        st.set_meta("ip_ban:192.168.1.7", _future(seconds=-60))
        net = _udp_gate(st)
        assert net._is_ip_banned("::ffff:192.168.1.7") is False
        assert net._udp_admit_inbound(("::ffff:192.168.1.7", 9000)) is True
    finally:
        st.close()


def test_is_ip_banned_matches_both_spellings_of_the_same_address(tmp_path):
    st = _open_storage(tmp_path)
    try:
        st.set_meta("ip_ban:10.20.30.40", _future())
        net = _udp_gate(st)
        assert net._is_ip_banned("10.20.30.40") is True
        assert net._is_ip_banned("::ffff:10.20.30.40") is True
        assert net._is_ip_banned("10.20.30.41") is False
    finally:
        st.close()


def test_udp_rate_window_is_shared_between_mapped_and_plain_spellings(tmp_path):
    """A client must not get a fresh window by switching address spelling."""
    st = _open_storage(tmp_path)
    try:
        net = _udp_gate(st)
        for _ in range(P2PNetwork._CONN_RATE_LIMIT):
            assert net._udp_admit_inbound(("::ffff:10.0.0.9", 1)) is True
        assert net._udp_admit_inbound(("10.0.0.9", 1)) is False
        assert net._udp_admit_inbound(("::ffff:10.0.0.9", 1)) is False
    finally:
        st.close()


# ── VSA-28: the header timestamp is fixed once the state root is computed ──

import threading as _threading  # noqa: E402
import time as _time  # noqa: E402

from visold.ledger import block as block_mod  # noqa: E402
from visold.ledger.block import Block  # noqa: E402
from visold.mining import engine as engine_mod  # noqa: E402
from visold.mining import workers as workers_mod  # noqa: E402

_CANDIDATE_TS = 1_700_000_000
_FMT = '{"nonce":%d,"timestamp":%d}'


class _FakeClock:
    """Replaces the ``time`` module inside one module under test."""

    def __init__(self, value: int):
        self.value = value

    def time(self) -> float:
        return float(self.value)


class _StopAfter:
    """Stop event that trips after ``n`` checks, so a non-terminating search ends."""

    def __init__(self, n: int):
        self.n = n
        self.calls = 0

    def is_set(self) -> bool:
        self.calls += 1
        return self.calls > self.n


def _candidate(ts: int = _CANDIDATE_TS, difficulty: float = 1.0) -> Block:
    return Block(index=1, prev_hash="0" * 64, transactions=[],
                 miner_address="vsd_test_miner", difficulty=difficulty,
                 timestamp=ts, state_root="ab" * 32)


def test_block_mine_never_moves_the_timestamp_after_the_clock_has_moved_on(monkeypatch):
    # A target of 1 makes a solution practically impossible, so the search runs
    # past its 50 000-nonce refresh point with the wall clock ahead of the candidate.
    monkeypatch.setattr(block_mod.DifficultyEngine, "difficulty_to_target",
                        lambda difficulty: 1)
    monkeypatch.setattr(block_mod, "time", _FakeClock(_CANDIDATE_TS + 5))
    blk = _candidate()
    assert blk.mine(stop_event=_StopAfter(60_000)) is False
    assert blk.timestamp == _CANDIDATE_TS, \
        "the header timestamp moved after the state root was computed"


def test_block_mine_solves_with_the_candidate_timestamp_after_the_clock_has_moved_on(monkeypatch):
    monkeypatch.setattr(block_mod, "time", _FakeClock(_CANDIDATE_TS + 5))
    blk = _candidate(difficulty=1.0)
    assert blk.mine() is True
    assert blk.timestamp == _CANDIDATE_TS


def test_cpu_worker_solution_keeps_the_candidate_timestamp_after_the_clock_moves_on(monkeypatch):
    # Every digest is below an all-ones target and min_iters sits just past the
    # 50 000-hash refresh point, so the refresh point is crossed before any solution.
    # The worker imports ``time`` inside its own body, so patch the module itself.
    monkeypatch.setattr(_time, "time", lambda: float(_CANDIDATE_TS + 5))
    result = []
    workers_mod._cy_mine_worker(_FMT, b"\xff" * 32, _CANDIDATE_TS, 0, 1, 60_000,
                                result, _threading.Lock(), _threading.Event(), 0.0, 0)
    assert len(result) == 1, "worker produced no solution"
    _nonce, _digest, ts = result[0]
    assert ts == _CANDIDATE_TS, f"worker advanced the timestamp to {ts}"


class _Tip:
    def __init__(self, block_hash: str, index: int):
        self.block_hash = block_hash
        self.index = index


class _Chain:
    def __init__(self, tip):
        self._tip = tip

    def latest_block(self):
        return self._tip


def _engine_with_prewarm(candidate: Block):
    eng = object.__new__(engine_mod.MiningEngine)
    eng._prewarm_lock = _threading.Lock()
    eng._prewarm_block = candidate
    eng.blockchain = _Chain(_Tip("0" * 64, candidate.index - 1))
    return eng


def test_prewarm_candidate_keeps_its_timestamp_after_the_clock_moves_on(monkeypatch):
    monkeypatch.setattr(engine_mod, "time", _FakeClock(_CANDIDATE_TS + 5))
    candidate = _candidate()
    eng = _engine_with_prewarm(candidate)
    got = eng._consume_prewarm()
    assert got is candidate
    assert got.timestamp == _CANDIDATE_TS


# ── VSA-08: the outbound UDP handshake opens before it waits ──────────────

from types import SimpleNamespace  # noqa: E402

from visold.kernel.config import Config  # noqa: E402
from visold.network import p2p as p2p_mod  # noqa: E402


def test_udp_initiator_opens_the_handshake_before_waiting_for_the_challenge(monkeypatch):
    events = []
    recvs = []

    class FakeSession:
        def send_heartbeat(self):
            events.append("HB")

    class FakeTransport:
        def get_session(self, addr):
            return FakeSession()

        def remove_session(self, addr, expected_session=None):
            events.append("remove")

    class FakePeer:
        def __init__(self, role, ip, port, sess):
            self.connected = True

        def recv_line(self, timeout):
            recvs.append(timeout)
            events.append(("recv", timeout))
            # The responder replies with POW_CHALLENGE only once it has seen the opener.
            if len(recvs) == 1 and "HB" in events:
                return {"type": p2p_mod.MSG_POW_CHALLENGE, "challenge": "c", "difficulty": 0}
            return None

        def send(self, msg):
            events.append(("send", msg.get("type")))

        def close(self):
            events.append("close")

    monkeypatch.setattr(p2p_mod, "UDPPeerConnection", FakePeer)
    monkeypatch.setattr(Config, "ICE_ENABLED", False)
    net = object.__new__(P2PNetwork)
    net._udp_peers_lock = threading.Lock()
    net._udp_peers = {}
    net._udp = FakeTransport()
    net.node_id = "initiator-under-test"
    net.port = 19701
    net.wallet = SimpleNamespace(pub_hex="00", user_id="", priv=None)
    # Keep this fixture focused on handshake ordering: the path builds HELLO
    # using storage metadata and a local chain height before it calls peer.send.
    net.storage = SimpleNamespace(get_meta=lambda _key: "")
    net.blockchain = SimpleNamespace(height=lambda: 0)
    net._local_chain_tip_hash = lambda: ""

    assert net._udp_connect_to("203.0.113.9", 19701) is False  # the fake peer never sends VERIFY
    assert events[0] == "HB", f"the handshake was not opened first: {events}"
    challenge_wait = ("recv", net._UDP_CHALLENGE_WAIT_SECS)
    assert events.index(challenge_wait) < events.index(("send", p2p_mod.MSG_HELLO)), \
        f"HELLO went out before the challenge was read: {events}"
    assert recvs[0] == net._UDP_CHALLENGE_WAIT_SECS < 8


# ── VSA-13 / VSA-14: one listen port for TCP and UDP, or a clear startup failure ──

import socket as _socket  # noqa: E402


def _free_tcp_port() -> int:
    probe = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _occupy(port: int):
    busy = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    busy.bind(("0.0.0.0", port))
    busy.listen(1)
    return busy


def test_listen_plan_binds_tcp_and_udp_to_one_port_when_the_configured_port_is_busy():
    base = _free_tcp_port()
    busy = _occupy(base)
    net = object.__new__(P2PNetwork)
    net.port = base
    srv = udp = None
    try:
        srv, udp = net._open_listen_sockets(base)
        assert net.port != base, "a busy configured port was chosen"
        assert net.port != base + Config.RPC_PORT_OFFSET, "the RPC port was taken"
        assert srv.getsockname()[1] == net.port, "TCP is not on the advertised port"
        assert udp._port == net.port, "UDP is not on the advertised port"
    finally:
        busy.close()
        if srv is not None:
            srv.close()
        if udp is not None:
            udp._sock.close()


def test_listen_plan_fails_clearly_instead_of_advertising_an_unbound_port():
    base = _free_tcp_port()
    busy = _occupy(base)
    net = object.__new__(P2PNetwork)
    net.port = base
    net._LISTEN_PORT_SEARCH = 0  # only the configured port is a candidate, and it is busy
    raised = False
    try:
        net._open_listen_sockets(base)
    except RuntimeError:
        raised = True
    finally:
        busy.close()
    assert raised, "startup did not fail when no listen port was free"
    assert net.port == base, "the port was changed without a bound socket"


# ── VSA-10: one budget bounds the UDP stage and the CGNAT retry ───────────

def _fallback_net():
    net = object.__new__(P2PNetwork)
    net._outbound_fail_lock = threading.Lock()
    net._outbound_fail = {}
    net._pending_lock = threading.Lock()
    net._pending_connections = set()
    return net


def test_outbound_fallback_skips_the_cgnat_retry_once_the_attempt_budget_is_spent(monkeypatch):
    monkeypatch.setattr(Config, "P2P_CONNECT_BUDGET_SECS", 0.0)
    ip = "203.0.113.20"
    port = Config.DEFAULT_PORT + 7
    calls = []
    net = _fallback_net()
    net._udp_connect_to = lambda ip_, port_, deadline=None: False
    net.connect_to = lambda ip_, port_: (calls.append(port_), False)[1]
    net._pending_connections.add((ip, port))
    net._connect_with_fallback(ip, port)
    assert calls == [port], f"the CGNAT retry ran after the budget was spent: {calls}"


def test_udp_handshake_waits_are_capped_by_the_attempt_deadline(monkeypatch):
    recorded = []

    class FakeSession:
        def send_heartbeat(self):
            pass

    class FakeTransport:
        def get_session(self, addr):
            return FakeSession()

        def remove_session(self, addr, expected_session=None):
            pass

    class FakePeer:
        def __init__(self, role, ip, port, sess):
            self.connected = True

        def recv_line(self, timeout):
            recorded.append(timeout)
            return None

        def send(self, msg):
            pass

        def close(self):
            pass

    monkeypatch.setattr(p2p_mod, "UDPPeerConnection", FakePeer)
    monkeypatch.setattr(Config, "ICE_ENABLED", False)
    net = object.__new__(P2PNetwork)
    net._udp_peers_lock = threading.Lock()
    net._udp_peers = {}
    net._udp = FakeTransport()
    net.node_id = "initiator-under-test"
    net.port = 19701
    net.wallet = SimpleNamespace(pub_hex="00", user_id="", priv=None)
    assert net._udp_connect_to("203.0.113.9", 19701, deadline=time.monotonic() + 1.0) is False
    assert recorded and all(t <= 1.05 for t in recorded), f"waits exceeded the budget: {recorded}"


# ── VSA-29: no GPU backend is initialised while the kernels are unverified ──

from visold.mining import parallel_miner as pm_mod  # noqa: E402


def test_gpu_backend_is_not_initialised_while_the_kernels_are_unverified(monkeypatch):
    assert pm_mod.GPU_KERNELS_VERIFIED is False
    monkeypatch.setattr(Config, "MINING_GPU_ENABLED", True)
    monkeypatch.setattr(pm_mod, "_CUDA_AVAILABLE", True)
    monkeypatch.setattr(pm_mod, "_OPENCL_AVAILABLE", True)
    attempts = []
    miner = object.__new__(pm_mod.ParallelMiner)
    miner._initialized = False
    miner._lock = _threading.Lock()
    miner._backend = "cpu"
    miner._n_threads = 1
    miner._try_init_cuda = lambda: attempts.append("cuda") or True
    miner._try_init_opencl = lambda: attempts.append("opencl") or True
    assert miner.initialize() == "cpu"
    assert attempts == [], f"a GPU backend was initialised: {attempts}"


# ── VSA-27: pending outflow reserves the gas budget of a VVM transaction ──

from visold.kernel.units import gas_fee_to_sat, to_satoshi  # noqa: E402
from visold.ledger.transaction import Transaction  # noqa: E402
from visold.mempool import pool as pool_mod  # noqa: E402


def test_pending_outflow_reserves_the_gas_budget_of_a_vvm_transaction():
    tx = Transaction(sender="vsd_sender_under_test", receiver="", amount=0.5, fee=0.0,
                     memo="VVM:deploy", nonce=0, tx_type=Transaction.TYPE_DEPLOY,
                     data="00", gas_limit=100, gas_price=0.01)

    class FakeStorage:
        def mempool_all(self):
            return [tx]

    mp = object.__new__(pool_mod.Mempool)
    mp.storage = FakeStorage()
    _reg, xfer, fee = mp.pending_outflow_sat("vsd_sender_under_test")
    assert xfer == to_satoshi(0.5), f"amount not reserved: {xfer}"
    assert fee == gas_fee_to_sat(100, 0.01), f"gas budget not reserved: {fee}"
