"""Regression tests for clean Visold exit from menu option 0 / Termux."""
import socket
import threading
from types import SimpleNamespace

from visold.api.rpc_server import RPCServer
from visold.cli.interactive import CLI
from visold.crypto import parallel_verify
from visold.network.nat.ice import ICEManager
from visold.network.p2p import P2PNetwork
from visold.node.visold_node import VisoldNode


class _Stopper:
    def __init__(self, fail=False):
        self.calls = 0
        self.fail = fail

    def stop(self):
        self.calls += 1
        if self.fail:
            raise RuntimeError("simulated stop failure")

    def close(self):
        self.calls += 1
        if self.fail:
            raise RuntimeError("simulated close failure")


class _Storage:
    def __init__(self):
        self._block_db = _Stopper()
        self.calls = 0

    def close(self):
        self.calls += 1


def test_node_shutdown_attempts_all_components_and_is_idempotent(monkeypatch):
    node = VisoldNode.__new__(VisoldNode)
    node._shutdown_lock = threading.Lock()
    node._shutdown_started = False
    node._shutdown_complete = False
    timer = threading.Timer(60.0, lambda: None)
    timer.daemon = True
    timer.start()
    node._startup_timers = [timer]
    node.mining = _Stopper(fail=True)  # one failure must not short-circuit cleanup
    node.sequencer = _Stopper()
    node.network = _Stopper()
    node.rpc = _Stopper()
    node.sentinel = _Stopper()
    node.shbs = _Stopper()
    node.circuit_breaker = _Stopper()
    node.state_engine = _Stopper()
    node.storage = _Storage()
    pool_calls = []
    monkeypatch.setattr(parallel_verify, "shutdown_signature_pool", lambda: pool_calls.append(True))

    node.stop()
    node.stop()  # safe to call from both CLI Exit and main() finalizer

    for component in (node.mining, node.sequencer, node.network, node.rpc,
                      node.sentinel, node.shbs, node.circuit_breaker, node.state_engine):
        assert component.calls == 1
    assert node.storage._block_db.calls == 1
    assert node.storage.calls == 1
    assert pool_calls == [True]
    assert node._shutdown_complete is True
    assert not timer.is_alive()
    assert node._startup_timers == []


def test_menu_zero_stops_node_and_returns_without_leaving_ui_running(monkeypatch):
    cli = CLI()
    cli._stop_refresh_thread = lambda: None
    node_stops = []
    cli.node = SimpleNamespace(stop=lambda: node_stops.append(True))

    cli._exit()

    assert cli._running is False
    assert node_stops == [True]
    assert cli._node_shutdown_done is True


def test_p2p_stop_releases_listener_and_stops_services_once():
    net = P2PNetwork.__new__(P2PNetwork)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    net._listen_sock = listener
    net._server_thread = None
    net._shutdown_lock = threading.Lock()
    net._stopped = False
    net._running = True
    net._upnp = _Stopper()
    net._dns_seeder = _Stopper()
    net._ice = _Stopper()
    net._udp = _Stopper()
    net._udp_peers_lock = threading.Lock()
    net._udp_peers = {}
    net._lock = threading.Lock()
    net.peers = {}

    net.stop()
    net.stop()

    assert listener.fileno() == -1
    for service in (net._upnp, net._dns_seeder, net._ice, net._udp):
        assert service.calls == 1
    assert net._running is False


def test_rpc_stop_closes_listener_even_after_loop_stops():
    calls = []
    server = SimpleNamespace(server_close=lambda: calls.append("close"))
    rpc = RPCServer.__new__(RPCServer)
    rpc._server = server
    rpc._thread = None

    rpc.stop()

    assert calls == ["close"]
    assert rpc._server is None
    assert rpc._thread is None


def test_ice_stop_reaps_relay_process():
    class Proc:
        def __init__(self):
            self.terminated = False
            self.waited = False

        def poll(self):
            return 0 if self.terminated else None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            self.waited = True
            return 0

    class Puncher:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    ice = ICEManager.__new__(ICEManager)
    ice._stop_evt = threading.Event()
    ice._relay_proc_lock = threading.Lock()
    ice._relay_proc = Proc()
    ice._thread = None
    ice._puncher = Puncher()
    proc = ice._relay_proc

    ice.stop()

    assert proc.terminated is True
    assert proc.waited is True
    assert ice._relay_proc is None
    assert ice._puncher.closed is True


def test_signature_worker_pool_is_shut_down_and_cleared(monkeypatch):
    class Pool:
        def __init__(self):
            self.kwargs = None

        def shutdown(self, **kwargs):
            self.kwargs = kwargs

    pool = Pool()
    monkeypatch.setattr(parallel_verify, "_SIG_POOL", pool)

    parallel_verify.shutdown_signature_pool()

    assert pool.kwargs == {"wait": True, "cancel_futures": True}
    assert parallel_verify._SIG_POOL is None
