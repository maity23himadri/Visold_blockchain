"""Regression tests: never retry a possibly partial TCP frame on the same stream."""
import socket
import threading

from visold.network.peer_connection import PeerConnection


class _SendFailSocket:
    def __init__(self, *, failure=BrokenPipeError("simulated broken pipe"), partial=True):
        self.failure = failure
        self.partial = partial
        self.sendall_calls = 0
        self.partial_bytes = []
        self.shutdown_calls = []
        self.closed = False

    def sendall(self, data):
        self.sendall_calls += 1
        if self.partial:
            self.partial_bytes.append(bytes(data[:max(1, min(7, len(data)))]))
        raise self.failure

    def shutdown(self, how):
        self.shutdown_calls.append(how)

    def close(self):
        self.closed = True

    def fileno(self):
        return 41 if not self.closed else -1

    def getsockname(self):
        return ("127.0.0.1", 31001)

    def getpeername(self):
        return ("127.0.0.1", 31002)

    def gettimeout(self):
        return 30.0


class _SuccessfulSocket(_SendFailSocket):
    def __init__(self):
        super().__init__(partial=False)
        self.sent = []

    def sendall(self, data):
        self.sendall_calls += 1
        self.sent.append(bytes(data))

    def shutdown(self, how):
        self.shutdown_calls.append(how)



class _StateObservingLock:
    """Record peer state at unlock to exercise the concurrent-writer race."""
    def __init__(self, peer):
        self._lock = threading.Lock()
        self.peer = peer
        self.states_at_release = []

    def __enter__(self):
        self._lock.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.states_at_release.append((
            self.peer.connected, self.peer._local_transport_failure_reason))
        self._lock.release()
        return False

def _peer(sock):
    peer = PeerConnection("peer-writer-regression", "127.0.0.1", 31002, sock=None)
    peer.sock = sock
    peer.connected = True
    # Constructor cannot start the writer because sock=None was supplied.
    assert peer._writer_thread is None
    return peer


def test_writer_does_not_retry_frame_after_partial_sendall_failure():
    sock = _SendFailSocket(partial=True)
    peer = _peer(sock)
    first = {"type": "BLOCK", "hash": "abc"}
    second = {"type": "PING", "nonce": "next"}
    peer._out_queue.put((0, 1, first))
    peer._out_queue.put((1, 2, second))
    peer._out_bytes = len(__import__("json").dumps(first)) + len(__import__("json").dumps(second))

    peer._writer_loop()

    assert sock.sendall_calls == 1, "same stream must never be retried after ambiguous partial write"
    assert len(sock.partial_bytes) == 1
    assert peer.connected is False
    assert peer._writer_stop.is_set()
    assert sock.shutdown_calls == [socket.SHUT_RDWR]
    assert peer._out_queue.empty(), "queued frames must not be sent on a broken stream"
    assert peer._out_bytes == 0


def test_unserializable_message_is_dropped_without_poisoning_socket():
    sock = _SuccessfulSocket()
    peer = _peer(sock)
    bad = {"type": "INVALID", "value": object()}
    good = {"type": "PING", "nonce": "ok"}
    peer._out_queue.put((0, 1, bad))
    peer._out_queue.put((1, 2, good))
    peer._out_queue.put((2, 3, None))
    peer._out_bytes = 0

    peer._writer_loop()

    assert sock.sendall_calls == 1
    assert len(sock.sent) == 1
    assert b'"PING"' in sock.sent[0]
    assert peer.connected is True
    assert not peer._writer_stop.is_set()
    assert sock.shutdown_calls == []


def test_sync_send_failure_aborts_stream_and_does_not_keep_writer_alive():
    sock = _SendFailSocket(partial=True)
    peer = _peer(sock)

    result = peer.send({"type": "BLOCK", "body": "private"})

    assert result is False
    assert sock.sendall_calls == 1
    assert peer.connected is False
    assert peer._writer_stop.is_set()
    assert sock.shutdown_calls == [socket.SHUT_RDWR]


def test_failed_writer_rejects_new_queue_items():
    sock = _SendFailSocket(partial=True)
    peer = _peer(sock)
    peer._out_queue.put((0, 1, {"type": "PING"}))
    peer._writer_loop()

    assert peer.send_priority({"type": "PING", "nonce": "later"}) is False
    assert peer._out_queue.empty()
    assert peer._writer_stop.is_set()


def test_sync_encoding_failure_does_not_close_healthy_transport(caplog):
    sock = _SuccessfulSocket()
    peer = _peer(sock)

    result = peer.send({"type": "INVALID", "value": object()})

    assert result is False
    assert peer.connected is True
    assert not peer._writer_stop.is_set()
    assert sock.sendall_calls == 0
    assert sock.shutdown_calls == []
    assert any("[PeerEncodeFailure]" in record.message for record in caplog.records)


def test_sync_send_refuses_after_session_writer_is_stopped():
    sock = _SuccessfulSocket()
    peer = _peer(sock)
    peer.close_writer()

    assert peer.send({"type": "PING"}) is False
    assert sock.sendall_calls == 0


def test_async_send_failure_marks_stream_unusable_before_unlock():
    sock = _SendFailSocket(partial=True)
    peer = _peer(sock)
    state_lock = _StateObservingLock(peer)
    peer._lock = state_lock

    assert peer._raw_send({"type": "PING", "nonce": "race"}) is False

    assert state_lock.states_at_release[0] == (
        False, "async_writer_sendall_failed")
    assert sock.sendall_calls == 1


def test_sync_send_failure_marks_stream_unusable_before_unlock():
    sock = _SendFailSocket(partial=True)
    peer = _peer(sock)
    state_lock = _StateObservingLock(peer)
    peer._lock = state_lock

    assert peer.send({"type": "PING", "nonce": "race"}) is False

    assert state_lock.states_at_release[0] == (
        False, "sync_sendall_failed")
    assert sock.sendall_calls == 1
