#!/usr/bin/env python3
"""Stress one real Visold TLS peer session pair: concurrent reader + writers on a single socket.

Uses the real PeerConnection, the real TLS contexts and the real reader helper
(visold.network.p2p._recv_with_blockingio_retry), with the same thread layout as the node:
  reader thread  -> reads the socket
  async writer   -> PeerConnection._writer_loop (via send_priority)
  sync writer    -> PeerConnection.send
Before the 2026-10-25 serialization fix this loses sessions (EOF / BAD_RECORD_MAC) within
seconds to minutes; with the fix it must report sessions_lost=0.

Usage (from the project root):
    python3 tools/tls_io_stress_repro.py --duration 60 --pairs 4 --interval 0.01   # heavy
    python3 tools/tls_io_stress_repro.py --duration 150 --pairs 6 --interval 1.0   # light
Exit code 0 = no session lost, 1 = at least one session lost.
"""
import argparse, collections, json, os, random, socket, sys, tempfile, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, default=60)
    ap.add_argument("--pairs", type=int, default=4)
    ap.add_argument("--interval", type=float, default=0.01, help="max random sleep between sends (seconds)")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="visold_tls_stress_")
    os.environ["VISOLD_DATA_DIR"] = tmp
    from visold.kernel.config import Config
    Config.DATA_DIR = tmp
    Config.TLS_CERT_FILE = os.path.join(tmp, "c.pem")
    Config.TLS_KEY_FILE = os.path.join(tmp, "k.pem")
    from visold.network.tls import TLSManager
    if not TLSManager.ensure_cert():
        print("could not create a TLS certificate"); return 2
    from visold.network.compression import CompressionEngine
    from visold.network.peer_connection import PeerConnection
    from visold.network import p2p

    sctx, cctx = TLSManager.server_context(), TLSManager.client_context()
    stats = collections.Counter(); sl = threading.Lock(); stop = threading.Event()

    def bump(k):
        with sl:
            stats[k] += 1

    def reader(peer):
        buf = b""
        # The node's _peer_message_loop puts the peer socket into timeout mode before
        # reading; reproduce that so the socket state matches production.
        peer.sock.settimeout(30)
        while not stop.is_set() and peer.connected:
            try:
                chunk = p2p._recv_with_blockingio_retry(peer.sock, 65536, timeout=30.0)
            except socket.timeout:
                continue
            except Exception as exc:
                if not stop.is_set():
                    bump(f"reader exception {type(exc).__name__}: {getattr(exc, 'reason', None) or exc}")
                peer.connected = False
                return
            if not chunk:
                if not stop.is_set():
                    bump("reader got EOF (node would log remote_eof and drop the session)")
                peer.connected = False
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    json.loads(CompressionEngine.decompress(line).decode()); bump("messages_ok")
                except Exception:
                    bump("garbled_frame")

    def sender(peer, sync):
        n = 0
        while not stop.is_set() and peer.connected:
            n += 1
            msg = {"type": "PING", "n": n, "pad": "x" * random.randint(0, 3000)}
            (peer.send(msg) if sync else peer.send_priority(msg, 1))
            time.sleep(random.random() * args.interval)

    peers = []
    for i in range(args.pairs):
        ls = socket.socket(); ls.bind(("127.0.0.1", 0)); ls.listen(1); port = ls.getsockname()[1]
        out = {}

        def accept():
            c, _ = ls.accept(); c.settimeout(10)
            out["s"] = sctx.wrap_socket(c, server_side=True); out["s"].settimeout(None)

        t = threading.Thread(target=accept); t.start()
        cs = cctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname=None)
        t.join(); ls.close()
        for sock, name in ((out["s"], "srv"), (cs, "cli")):
            peers.append(PeerConnection(f"{name}{i}".ljust(16, "0"), "127.0.0.1", port, sock=sock))
    for p in peers:
        threading.Thread(target=reader, args=(p,), daemon=True).start()
        threading.Thread(target=sender, args=(p, True), daemon=True).start()
        threading.Thread(target=sender, args=(p, False), daemon=True).start()
    t0 = time.time()
    while time.time() - t0 < args.duration and any(p.connected for p in peers):
        time.sleep(0.5)
    stop.set(); time.sleep(0.5)
    lost = sum(not p.connected for p in peers)
    print(f"ran {time.time() - t0:.0f}s | sessions_lost={lost}/{len(peers)}")
    for k, v in sorted(stats.items()):
        print(f"   {k}: {v}")
    return 1 if lost else 0


if __name__ == "__main__":
    sys.exit(main())
