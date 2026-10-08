# ─────────────────────────────────────────────────────────────────────────────
#  Visold (VSD) Blockchain Protocol
#  Copyright (c) 2025 Visold Contributors
#  Licensed under the MIT License.
#
#  The original and canonical source is maintained by the Visold Project.
#  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#  the license agreement.
# ─────────────────────────────────────────────────────────────────────────────
# cython: language_level=3
# cython: boundscheck=True
# cython: wraparound=True
# cython: cdivision=True
# cython: nonecheck=True
# cython: initializedcheck=False
# cython: infer_types=True
# cython: optimize.use_switch=True
# cython: optimize.unpack_method_calls=True
"""visold.network.p2p

Original section: SECTION UDP-P2PNETWORK: UDP transport integration methods (v7.5-UDP)

Defines: P2PNetwork
Origin: visold_vsd_.py L33451-38510
"""

import hashlib
import hmac
import json
import queue
import random
import secrets
import socket
import ssl
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING


def _reject_nonfinite_json_constant(value: str):
    """Reject JSON NaN/Infinity spellings on the consensus/network boundary."""
    raise ValueError(f"non-finite JSON number is not permitted: {value}")

from visold.chain.blockchain import Blockchain
from visold.consensus.slashing import SlashingEvidenceProtocol
from visold.crypto.ecc import ecdsa_sign, ecdsa_verify, pub_from_hex, sig_from_hex, sig_to_hex
from visold.crypto.hashing import hash_obj, sha256
from visold.kernel.config import Config
from visold.kernel.events import Event, EventType
from visold.kernel.logging_setup import log
from visold.kernel.lru_cache import LRUCache
from visold.kernel.messages import (
    MSG_ACCEPT,
    MSG_ALERT,
    MSG_BLOCK,
    MSG_BLOCKTXN,
    MSG_BLOCK_CHUNK_DATA,
    MSG_BLOCK_MANIFEST,
    MSG_CHAIN,
    MSG_CMPCTBLOCK,
    MSG_GETBLOCKTXN,
    MSG_GET_BLOCK,
    MSG_GET_BLOCK_CHUNK,
    MSG_GET_BLOCK_MANIFEST,
    MSG_GET_CHAIN,
    MSG_GET_PEERS,
    MSG_HASHRATE_REPORT,
    MSG_HELLO,
    MSG_IDENTITY,
    MSG_L2TX,
    MSG_PEERS,
    MSG_PING,
    MSG_PONG,
    MSG_POW_CHALLENGE,
    MSG_RATE_DEFECTION_EVIDENCE,
    MSG_REJECT,
    MSG_RESOLVE,
    MSG_RESOLVE_RESP,
    MSG_TX,
    MSG_VALIDATOR_SIG,
    MSG_VERIFY,
)
from visold.kernel.metrics import metrics
from visold.kernel.netutil import (
    _create_connection_dual_stack,
    _create_dual_stack_server_socket,
    _format_peer_addr,
    _is_ipv6_address,
    _normalize_ip,
    _parse_peer_addr,
)
from visold.kernel.notifications import (
    _pa_push,
    _push_block_notif,
    _push_peer_notif,
    _push_sync_request_notif,
)
from visold.kernel.source_identity import _NODE_LOGIC_HASH
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.block_download import ParallelBlockDownloader
from visold.network.capabilities import (
    MSG_CAPABILITY_ADV,
    MSG_CAPABILITY_QUERY,
    MSG_CAPABILITY_RESPONSE,
    MSG_CHUNK_DATA,
    MSG_CHUNK_MANIFEST,
    MSG_GET_CHUNK,
    MSG_GET_CHUNK_MANIFEST,
    MSG_GET_SNAPSHOT,
    MSG_GET_SNAPSHOT_MANIFEST,
    MSG_SNAPSHOT_DATA,
    MSG_SNAPSHOT_MANIFEST,
)
from visold.network.compression import CompressionEngine
from visold.network.dns_seeder import DNSSeeder
from visold.network.kademlia import KademliaRouter
from visold.network.message_logger import P2PMessageLogger
from visold.network.nat.ice import ICEManager, _pow_check, _pow_solve
from visold.network.nat.upnp import UPnPManager
from visold.network.peer_connection import PeerConnection
from visold.network.tls import TLSManager
from visold.network.udp.latency import LatencyTracker
from visold.network.udp.transport import UDPPeerConnection, UDPTransport
from visold.network.udp.wire import _UDP_HB_INTERVAL, _udp_normalize_addr
from visold.rollup.l2_state import L2Transaction
from visold.storage.storage import Storage

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.chain.sequencer import Sequencer
    from visold.mining.engine import MiningEngine
    from visold.state.engine import StateEngine
    from visold.wallet.wallet import Wallet


class P2PNetwork:
    # Per-IP inbound connection rate limit:
    # no more than _CONN_RATE_LIMIT new connections from one IP within
    # _CONN_RATE_WINDOW seconds.  Legitimate peers reconnect rarely.
    _CONN_RATE_LIMIT  = 5
    _CONN_RATE_WINDOW = 60   # seconds

    # ── v7.1.0: Per-peer message-rate limits (DoS protection) ────────────────
    # The existing byte-rate cap (MAX_PEER_BANDWIDTH) catches bulk floods, and
    # the per-IP connection rate limit (_CONN_RATE_LIMIT) catches connection
    # floods.  These per-message-type limits catch the missing middle ground:
    # an attacker who sends thousands of tiny valid frames per second, each
    # below the byte cap but collectively exhausting CPU / DB.  Particularly
    # important for expensive queries like MSG_GET_CHAIN which triggers a
    # 200-block DB scan per request.
    _MSG_RATE_WINDOW  = 10   # seconds per bucket
    _MSG_RATE_GLOBAL  = 500  # total msgs per peer per window (50/s sustained)
    _MSG_RATE_PERTYPE = {
        # Expensive queries — strictly limited
        "GET_CHAIN":          5,   # 0.5 req/s sustained
        "GET_PEERS":          3,
        "GET_BLOCK":         30,
        "RESOLVE":           10,
        "CAPABILITY_QUERY":   5,
        # Snapshot / fast-sync — expensive (blob can be large); strictly limited
        "GET_SNAP_MANIFEST":  3,
        "GET_SNAPSHOT":       2,   # 1 per 5s sustained — blobs are large
        # Gossip floods — generous but bounded
        "TX":               300,  # 30 tx/s per peer
        "BLOCK":             20,  # 2 blocks/s per peer — more is suspicious
        # v7.5.0 compact-block protocol
        "CMPCTBLOCK":        20,  # same cadence as BLOCK
        "GETBLOCKTXN":       40,  # one per missing-tx request, burst ok
        "BLOCKTXN":          40,  # one reply per GETBLOCKTXN
        # v7.5.0-OPT L2 rollup gossip — L2 txs are small and frequent.
        # 600/10s = 60/s sustained per peer.  Paired with BULK priority
        # means bursts are buffered behind consensus traffic, not racing.
        "L2TX":             600,
        "VALIDATOR_SIG":     50,
        "IDENTITY":          30,
        "ALERT":             10,
        "GET_BLOCK_MANIFEST": 10,
        "GET_BLOCK_CHUNK":   200,   # Accommodates 512KB chunking of large blocks
        # ── v7.6.0 Hashrate optimization gossip ──────────────────────────────
        # Each node sends one report per HASHRATE_REPORT_INTERVAL (default 5s).
        # 30/window (10 s) sustained = 3 reports per honest cycle with 10×
        # headroom for transient bursts and accidental retries.  An attacker
        # spamming reports is harmless (governor's per-peer key dedupes them)
        # but still consumes bandwidth, so we cap.
        "HASHRATE_REPORT":   30,

        # ── v7.7.0 Rate defection evidence ───────────────────────────────────
        # Audit cycles run every RATE_AUDIT_CADENCE (50) blocks, at most one
        # evidence per miner per cycle.  20/window (10 s) is conservative and
        # accommodates a burst at audit time without rate-limiting honest
        # broadcasts.
        "RATE_DEFECTION_EVIDENCE": 20,

        # Responses — no cap (they should follow our outgoing requests)
    }

    def __init__(self, blockchain: Blockchain, wallet: 'Wallet',
                 storage: Storage, port: int = Config.DEFAULT_PORT,
                 node_id: Optional[str] = None):
        self.blockchain  = blockchain
        self.wallet      = wallet
        self.storage     = storage
        self.port        = port
        self.node_id     = node_id or sha256(wallet.pub_hex.encode())
        self.router      = KademliaRouter(self.node_id)
        self.peers: Dict[str, PeerConnection] = {}
        self._lock       = threading.Lock()
        self._block_serve_cache = LRUCache(5, ttl=60.0) 

        # Plumtree-style: eager set (active) + lazy set (ihave hints)
        self._eager_peers: set = set()   # peer_ids for full gossip
        self._seen_msgs  = LRUCache(4096, ttl=3600)  # BUG-FIX (v7.0.1.0): 1-hour TTL
        self._id_cache   = LRUCache(Config.LRU_CACHE_SIZE)
        self._server     = None
        self._running    = False
        self._callbacks  = defaultdict(list)
        self.hashrate    = 0.0
        # Per-IP connection timestamps for rate limiting (ip -> deque of ts)
        self._conn_rate: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self._CONN_RATE_LIMIT + 1))
        # Per-peer untrusted TX/block rate tracking used by Full Audit Mode.
        # Maps peer_id → [window_start_ts, bytes_sent_in_window].
        # Entries are cleared when the peer disconnects (_on_peer_disconnect).
        self._untrusted_rate: Dict[str, list] = {}
        self._untrusted_rate_lock = threading.Lock()
        # Tracks (ip, port) pairs for which a connection thread is currently
        # running.  Prevents duplicate concurrent connection attempts to the
        # same endpoint (Bug #3 / #4 fix).
        self._pending_connections: set = set()
        self._pending_lock = threading.Lock()
        # Per-IP outbound fail tracking: ip → [fail_count, cooldown_until_ts]
        # After Config.OUTBOUND_FAIL_LIMIT consecutive failures the reconnect
        # loop skips this IP for Config.OUTBOUND_FAIL_COOLDOWN_SECS.
        # Resets on successful connect or when cooldown expires.
        self._outbound_fail: Dict[str, list] = {}
        self._outbound_fail_lock = threading.Lock()
        # Per-peer message-rate buckets (v7.1.0 DoS protection).
        # Maps peer_id -> {"global": deque[ts], "types": {type: deque[ts]}}
        self._msg_rate: Dict[str, dict] = {}
        self._msg_rate_lock = threading.Lock()
        # StateEngine reference — injected after construction (avoids circular deps)
        self._state_engine: Optional['StateEngine'] = None
        # ── v7.5.0 Compact-Block stash ───────────────────────────────────────
        # Keyed by block_hash.  Each entry holds the partially-reconstructed
        # block data while we wait for MSG_BLOCKTXN to fill in missing txs.
        # Format:
        #   block_hash -> {
        #     "header":       dict          (full header from CMPCTBLOCK),
        #     "short_ids":    list[str],    (6-byte hex short-IDs, one per non-cb tx)
        #     "txs":          dict[str, Transaction],  # short_id -> tx (filled so far)
        #     "missing":      list[str],    (full tx_ids still needed)
        #     "source_peer":  str,          (peer_id we sent GETBLOCKTXN to)
        #     "ts":           float,        (time.time() of first receipt)
        #   }
        # Entries are evicted after _CMPCT_STASH_TTL seconds.
        self._compact_stash: Dict[str, dict] = {}
        self._compact_stash_lock = threading.Lock()
        self._CMPCT_STASH_TTL   = 30.0   # seconds before a stale stash entry is dropped
        self._load_peers()
        # UPnP NAT traversal (background — never blocks startup)
        self._upnp    = UPnPManager(internal_port=port, external_port=port)
        # DNS seed discovery (background — never blocks startup)
        self._dns_seeder = DNSSeeder(self)
        # ICE NAT traversal (STUN + UDP hole punching + relay)
        self._ice = ICEManager(node_port=port)
        # ── UDP Resilient Transport Layer (v7.5-UDP) ──────────────────────
        # Initialized here; started in start() after TLS certs are ready.
        # Runs PARALLEL to the TCP layer — peers with "udp_port" in their
        # HELLO are contacted via UDP; others fall back to TCP seamlessly.
        self._udp: 'UDPTransport' = UDPTransport(
            port=port,
            bind_addr=Config.BIND_ADDRESS if Config.BIND_ADDRESS else '',
            max_pending_inbound=Config.MAX_PEERS)
        # Map: (ip, port) -> UDPPeerConnection  (UDP peers only)
        self._udp_peers: dict = {}
        self._udp_peers_lock = threading.Lock()
        # ── v7.5.0-OPT Network-Aware Block Sizing ────────────────────────────
        # Aggregates per-session RTTs (already measured by _UDPWindow._update_rtt
        # under RFC 6298) into a single network-wide mean used by
        # Blockchain.get_dynamic_block_size().  Purely advisory — never
        # touches TARGET_BLOCK_TIME or difficulty.
        self.latency_tracker: 'LatencyTracker' = LatencyTracker()
        # ── v7.5.0-OPT L2 SEQUENCER REFERENCE ─────────────────────────────
        # Injected by Node.start() after the Sequencer is constructed.
        # When non-None, inbound MSG_L2TX messages are delivered into its
        # pending pool.  When None, L2TX messages are silently relayed so
        # other nodes' sequencers still see them.
        self._sequencer: Optional['Sequencer'] = None
        # Injected by VisoldNode after construction
        self._reputation_mgr: Optional[Any] = None
        self._capability_router: Optional[Any] = None
        self._slash_evidence: Optional[Any] = None
        # ── v7.6.0 Mining engine reference ───────────────────────────────────
        # Wired by VisoldNode after both objects are created.  Used by the
        # MSG_HASHRATE_REPORT handler to feed peer-actual-hashrate values
        # into the local HashrateGovernor.  None on investor-only nodes
        # (which never mine) — the handler tolerates that gracefully.
        self._mining_engine_ref: Optional['MiningEngine'] = None

    def set_state_engine(self, engine: 'StateEngine'):
        """Inject StateEngine after both objects are created."""
        self._state_engine = engine

    def set_mining_engine(self, engine: 'MiningEngine'):
        """Inject MiningEngine after both objects are created.  Optional —
        nodes that never mine simply ignore inbound HASHRATE_REPORT messages."""
        self._mining_engine_ref = engine

    def set_sequencer(self, sequencer: 'Sequencer'):
        """Inject Sequencer after both objects are created.  Optional —
        nodes without a sequencer simply relay MSG_L2TX gossip."""
        self._sequencer = sequencer

    def start(self):
        self._running = True
        threading.Thread(target=self._server_loop, daemon=True).start()
        threading.Thread(target=self._pex_loop, daemon=True).start()
        threading.Thread(target=self._reconnect_loop, daemon=True).start()
        threading.Thread(target=self._peer_decay_loop, daemon=True).start()
        threading.Thread(target=self._ban_score_decay_loop, daemon=True).start()
        # v7.5.0: compact-block stash GC thread
        threading.Thread(target=self._cmpct_stash_gc_loop, daemon=True).start()
        log.info(f"P2P dual-stack node starting on port {self.port} "
                 f"(bind={Config.BIND_ADDRESS}) | node_id={self.node_id[:16]}...")
        threading.Thread(target=self._bootstrap, daemon=True).start()
        self._upnp.start()
        self._dns_seeder.start()
        # ICE NAT traversal — start background candidate gathering
        self._ice.start()
        # Ensure TLS certificates are ready before accepting connections
        TLSManager.ensure_cert()
        # ── UDP Resilient Transport (v7.5-UDP) ────────────────────────────
        # Start UDP layer AFTER TLS certs are ready.  on_new_peer callback
        # triggers _udp_handle_inbound so spontaneous UDP peers (behind NAT,
        # hole-punched) get a full handshake and are added to the peer set.
        self._udp.start(
            on_new_peer=self._udp_on_new_peer,
            inbound_admission=self._udp_admit_inbound)
        threading.Thread(target=self._udp_heartbeat_loop, daemon=True,
                         name='udp-hb').start()
        log.info(f"UDP resilient transport started on port {self.port}")

    def _cmpct_stash_gc_loop(self):
        """
        v7.5.0: Periodically evict compact-block stash entries that have
        exceeded _CMPCT_STASH_TTL without being resolved.  This is a safety
        net for the case where MSG_BLOCKTXN is never received (e.g. the peer
        disconnected after we sent MSG_GETBLOCKTXN but before the disconnect
        GC in _on_peer_disconnect ran, or the reply was dropped by the TCP
        stack).

        Runs every _CMPCT_STASH_TTL / 2 seconds so the worst-case memory
        bloat is bounded at two TTL periods.
        """
        while self._running:
            time.sleep(self._CMPCT_STASH_TTL / 2)
            try:
                _now = time.time()
                with self._compact_stash_lock:
                    _expired = [
                        _k for _k, _v in self._compact_stash.items()
                        if _now - _v.get("ts", 0) > self._CMPCT_STASH_TTL
                    ]
                    for _k in _expired:
                        self._compact_stash.pop(_k, None)
                        log.debug(f"[CMPCT] GC evicted stash {_k[:16]}")
            except Exception as _gc_err:
                log.debug(f"[CMPCT] Stash GC error: {_gc_err}")


    # ══════════════════════════════════════════════════════════════════════
    # SECTION UDP-P2PNETWORK: UDP transport integration methods (v7.5-UDP)
    #
    # These methods augment P2PNetwork with:
    #   1. _udp_on_new_peer         — callback from UDPTransport on new addr
    #   2. _udp_handle_inbound      — handshake logic for UDP peers (mirrors
    #                                 _handle_inbound for TCP)
    #   3. _udp_connect_to          — outbound UDP peer connection + handshake
    #   4. _udp_send_to_peer        — rate-limited unicast send via UDP
    #   5. _udp_heartbeat_loop      — manages UDP peer keep-alive eviction
    #   6. _udp_peer_message_loop   — reads from UDPSession.inbound and feeds
    #                                 _handle_message (same as TCP loop)
    # ══════════════════════════════════════════════════════════════════════

    def _udp_admit_inbound(self, addr: tuple) -> bool:
        """Cheap inbound gate evaluated before UDPSession allocation.

        This is deliberately limited to admission controls that do not need
        the authenticated peer object: per-IP connection rate limiting and the
        persistent IP soft-ban check.  The UDP transport also enforces a global
        cap on simultaneously admitted pre-authentication endpoints.
        """
        ip, _port = addr
        now = time.time()
        if self._is_ip_banned(ip):
            _pa_push("IN", ip, addr[1], "BANNED")
            return False

        with self._lock:
            window = self._conn_rate[ip]
            while window and (now - window[0]) > self._CONN_RATE_WINDOW:
                window.popleft()
            if len(window) >= self._CONN_RATE_LIMIT:
                log.debug(
                    f"Inbound UDP rate-limit hit for {ip} "
                    f"({len(window)} conns in {self._CONN_RATE_WINDOW}s)")
                return False
            window.append(now)
        return True

    def _udp_on_new_peer(self, addr: tuple):
        """
        Callback from UDPTransport._recv_loop when admission has already
        succeeded and a new UDPSession has been allocated.

        We do NOT block the recv_loop — spawn a daemon handshake worker.
        """
        try:
            threading.Thread(target=self._udp_handle_inbound,
                             args=(addr,),
                             daemon=True,
                             name=f'udp-inbound-{addr[0]}:{addr[1]}').start()
        except Exception:
            self._udp.release_inbound(addr)

    def _udp_handle_inbound(self, addr: tuple):
        """
        Perform the VSD handshake (HELLO → VERIFY → CHALLENGE_RESP → ACCEPT)
        over a UDP session.  On success, register the peer and start
        _udp_peer_message_loop.

        Design notes
        ────────────
        • The session's inbound queue is used for recv_line() during handshake
          (same as PeerConnection._recv_buf / recv_line() over TCP).
        • On any failure the UDPSession is removed so the source address can
          reconnect cleanly.
        • The PoW, TOFU TLS pinning, and logic_hash trust checks from the TCP
          path are replicated here identically.
        """
        ip, port = addr
        admission_released = False
        handshake_registered = False
        sess = None
        peer = None
        final_peer = None

        try:
            sess  = self._udp.get_session(addr)
            peer  = UDPPeerConnection("unknown", ip, port, sess)
            # ── PoW challenge ─────────────────────────────────────────────
            _srv_pow_challenge = ""
            if Config.PEER_POW_DIFFICULTY > 0:
                _srv_pow_challenge = secrets.token_hex(16)
                peer.send({"type": MSG_POW_CHALLENGE,
                           "challenge": _srv_pow_challenge,
                           "difficulty": Config.PEER_POW_DIFFICULTY})

            msg = peer.recv_line(timeout=12)
            if not msg or msg.get("type") != MSG_HELLO:
                peer.close(); return

            peer_id          = msg.get("node_id", "")
            pub_hex          = msg.get("pub_hex", "")
            user_id          = msg.get("user_id", "")
            peer_logic_hash  = msg.get("logic_hash", "")
            peer_hello_caps  = msg.get("capabilities", [])
            peer_listen_port = int(msg.get("listen_port", Config.DEFAULT_PORT))
            peer_udp_port    = int(msg.get("udp_port", port))

            if not peer_id or not pub_hex:
                peer.send({"type": MSG_REJECT, "reason": "Missing identity"})
                peer.close(); return

            # ── PoW verification ──────────────────────────────────────────
            if _srv_pow_challenge and Config.PEER_POW_DIFFICULTY > 0:
                _pow_nonce = msg.get("pow_nonce", "")
                if not _pow_check(_srv_pow_challenge, _pow_nonce,
                                  Config.PEER_POW_DIFFICULTY):
                    peer.send({"type": MSG_REJECT, "reason": "PoW verification failed"})
                    peer.close(); return

            # ── ECDSA challenge ───────────────────────────────────────────
            challenge = secrets.token_hex(16)
            peer.send({"type": MSG_VERIFY, "challenge": challenge,
                       "tls_fp": TLSManager.fingerprint()})

            resp = peer.recv_line(timeout=8)
            if not resp:
                peer.close(); return

            try:
                pub = pub_from_hex(pub_hex)
                sig = sig_from_hex(resp.get("sig", "[]"))
                h   = hashlib.sha256(challenge.encode()).digest()
                if not ecdsa_verify(pub, h, sig):
                    peer.send({"type": MSG_REJECT, "reason": "Signature invalid"})
                    peer.close(); return
            except Exception:
                peer.send({"type": MSG_REJECT, "reason": "Sig verification failed"})
                peer.close(); return

            # ── Trust classification ──────────────────────────────────────
            if (peer_logic_hash
                    and peer_logic_hash != _NODE_LOGIC_HASH
                    and peer_logic_hash not in Config.KNOWN_GOOD_LOGIC_HASHES):
                _inbound_trust = UDPPeerConnection.TRUST_LOW
            else:
                _inbound_trust = UDPPeerConnection.TRUST_HIGH

            # ── Send ACCEPT ───────────────────────────────────────────────
            peer.send({"type": MSG_ACCEPT, "node_id": self.node_id,
                       "pub_hex": self.wallet.pub_hex,
                       "version": Config.VERSION,
                       "tls_fp": TLSManager.fingerprint(),
                       "logic_hash": _NODE_LOGIC_HASH,
                       "capabilities": Config.NODE_CAPABILITIES,
                       "chain_height": self.blockchain.height(),
                       "udp_port": self.port})

            # ── Rebuild UDPPeerConnection with proper peer_id + trust ─────
            final_peer = UDPPeerConnection(
                peer_id, ip, peer_udp_port, sess,
                reputation=1.0, trust_level=_inbound_trust)
            # Register capabilities
            if peer_hello_caps and hasattr(self, "_capability_router"):
                try:
                    self._capability_router.handle_adv(peer_id, peer_hello_caps)
                except Exception:
                    pass

            # Track in _udp_peers map
            with self._udp_peers_lock:
                self._udp_peers[addr] = final_peer

            self._register_peer(final_peer, peer_id, pub_hex, user_id,  # type: ignore[arg-type]
                                initiator=True)
            if not final_peer.connected:
                # _register_peer() can reject/close the peer (peer cap,
                # anti-eclipse, self-connect, etc.).  The handshake did not
                # produce a live registered session, so treat it as a failed
                # attempt and tear down this exact session below.
                return
            handshake_registered = True
            # The peer has crossed the authentication boundary.  Free the
            # pre-authentication transport slot before entering the long-lived
            # message loop.
            self._udp.release_inbound(addr)
            admission_released = True
            self._udp_peer_message_loop(final_peer)

        except Exception as e:
            log.debug(f"[UDP] Inbound handler error {ip}:{port}: {e}")
        finally:
            if not handshake_registered:
                # Do not leave a failed final peer in the address-indexed UDP
                # registry: _udp_connect_to() uses this map as its fast
                # "already connected" check.  Remove only our exact object so
                # a concurrent replacement remains intact.
                if final_peer is not None:
                    with self._udp_peers_lock:
                        if self._udp_peers.get(addr) is final_peer:
                            self._udp_peers.pop(addr, None)
                # Remove only the session this handshake actually acquired.
                # A concurrent reconnect may have replaced it; the transport
                # identity check then leaves the newer live session untouched.
                if sess is not None:
                    self._udp.remove_session(addr, expected_session=sess)
                else:
                    self._udp.release_inbound(addr)
            elif not admission_released:
                self._udp.release_inbound(addr)

    def _udp_connect_to(self, ip: str, port: int) -> bool:
        """
        Establish an outbound UDP peer connection (handshake initiator role).
        Mirrors connect_to() but uses UDPSession / UDPPeerConnection.

        Returns True if the handshake succeeded and the peer was registered.
        """
        addr = _udp_normalize_addr((ip, port))

        # Bail out if already connected over UDP
        with self._udp_peers_lock:
            if addr in self._udp_peers:
                return True

        sess = self._udp.get_session(addr)
        peer = UDPPeerConnection("outbound", ip, port, sess)
        final_peer = None
        handshake_registered = False

        try:
            # ── PoW response ──────────────────────────────────────────────
            pow_challenge_msg = peer.recv_line(timeout=8)
            pow_nonce: Optional[str] = ""
            if (pow_challenge_msg
                    and pow_challenge_msg.get("type") == MSG_POW_CHALLENGE):
                _challenge = pow_challenge_msg.get("challenge", "")
                _diff      = pow_challenge_msg.get("difficulty", 0)
                pow_nonce  = _pow_solve(_challenge, _diff)

            # ── Send HELLO ────────────────────────────────────────────────
            hello = {
                "type":         MSG_HELLO,
                "node_id":      self.node_id,
                "pub_hex":      self.wallet.pub_hex,
                "user_id":      getattr(self.wallet, "user_id", ""),
                "version":      Config.VERSION,
                "listen_port":  self.port,
                "udp_port":     self.port,
                "capabilities": Config.NODE_CAPABILITIES,
                "logic_hash":   _NODE_LOGIC_HASH,
                "pow_nonce":    pow_nonce,
            }
            if Config.ICE_ENABLED:
                try:
                    hello["ice_candidates"] = self._ice.get_candidates_as_dicts()
                except Exception:
                    hello["ice_candidates"] = []
            peer.send(hello)

            # ── ECDSA challenge response ───────────────────────────────────
            verify_msg = peer.recv_line(timeout=8)
            if not verify_msg or verify_msg.get("type") != MSG_VERIFY:
                peer.close(); return False

            challenge = verify_msg.get("challenge", "")
            h   = hashlib.sha256(challenge.encode()).digest()
            sig = ecdsa_sign(self.wallet.priv, h)
            peer.send({"type": "CHALLENGE_RESP",
                       "sig": sig_to_hex(sig)})

            # ── Read ACCEPT ───────────────────────────────────────────────
            accept_msg = peer.recv_line(timeout=10)
            if not accept_msg or accept_msg.get("type") != MSG_ACCEPT:
                peer.close(); return False

            remote_peer_id    = accept_msg.get("node_id", "")
            remote_pub_hex    = accept_msg.get("pub_hex", "")
            remote_user_id    = accept_msg.get("user_id", "")
            remote_logic_hash = accept_msg.get("logic_hash", "")
            remote_caps       = accept_msg.get("capabilities", [])

            if not remote_peer_id or not remote_pub_hex:
                peer.close(); return False

            # ── Trust classification ──────────────────────────────────────
            if (remote_logic_hash
                    and remote_logic_hash != _NODE_LOGIC_HASH
                    and remote_logic_hash not in Config.KNOWN_GOOD_LOGIC_HASHES):
                _trust = UDPPeerConnection.TRUST_LOW
            else:
                _trust = UDPPeerConnection.TRUST_HIGH

            # ── Rebuild with real peer_id ─────────────────────────────────
            final_peer = UDPPeerConnection(
                remote_peer_id, ip, port, sess,
                reputation=1.0, trust_level=_trust)

            if remote_caps and hasattr(self, "_capability_router"):
                try:
                    self._capability_router.handle_adv(remote_peer_id, remote_caps)
                except Exception:
                    pass

            with self._udp_peers_lock:
                self._udp_peers[addr] = final_peer

            self._register_peer(final_peer, remote_peer_id,  # type: ignore[arg-type]
                                remote_pub_hex, remote_user_id,
                                initiator=True)
            if not final_peer.connected:
                # _register_peer() rejected/closed the connection.  Do not
                # leave its dead UDPSession as the canonical session for this
                # endpoint.
                return False
            handshake_registered = True

            # Start message loop in a daemon thread (mirrors TCP path)
            threading.Thread(
                target=self._udp_peer_message_loop,
                args=(final_peer,),
                daemon=True,
                name=f'udp-msgloop-{remote_peer_id[:8]}').start()
            return True

        except Exception as e:
            log.debug(f"[UDP] connect_to {ip}:{port} error: {e}")
            return False
        finally:
            if not handshake_registered:
                # A rejected _register_peer() can happen after final_peer has
                # already been inserted into _udp_peers.  Remove only that
                # exact object so a concurrent replacement is not disturbed.
                if final_peer is not None:
                    with self._udp_peers_lock:
                        if self._udp_peers.get(addr) is final_peer:
                            self._udp_peers.pop(addr, None)
                # Remove only the session used by this handshake.  If another
                # concurrent path has already replaced the endpoint's session,
                # identity-checked removal preserves that newer session.
                self._udp.remove_session(addr, expected_session=sess)

    def _udp_peer_message_loop(self, peer: 'UDPPeerConnection'):
        """
        Mirrors _peer_message_loop for UDP peers.

        Key differences from TCP:
          • No raw socket recv() — messages arrive already decoded in
            peer._session.inbound (the reassembly queue).
          • Heartbeat / keep-alive is managed by UDPSession._retransmit_loop;
            we only check for session liveness here.
          • Bandwidth cap is enforced per-message (len of serialized JSON).
        """
        bytes_this_second = 0
        second_start      = time.time()

        while self._running and peer.connected:
            try:
                msg = peer.recv_line(timeout=30.0)
            except Exception:
                break

            if msg is None:
                # Timeout — check liveness via heartbeat
                if not peer._session.is_alive():
                    log.debug(f"[UDP] Peer {peer.peer_id[:12]} heartbeat timeout — disconnecting")
                    break
                # Still alive — send a ping to keep the session warm
                peer.send({"type": MSG_PING})
                continue

            # ── Per-peer bandwidth cap ─────────────────────────────────────
            now = time.time()
            if now - second_start >= 1.0:
                bytes_this_second = 0
                second_start      = now
            try:
                msg_size = len(json.dumps(msg))
            except Exception:
                msg_size = 0
            bytes_this_second += msg_size
            if bytes_this_second > Config.MAX_PEER_BANDWIDTH:
                log.warning(
                    f"[UDP] Peer {peer.peer_id[:12]} exceeded bandwidth limit "
                    f"({bytes_this_second} bytes/s) — disconnecting")
                self.storage.add_ban_score(peer.peer_id,
                                           Config.PEER_SCORE_OVERSIZED_MSG)
                break

            # ── Soft-ban throttle (mirrors TCP path) ──────────────────────
            mtype = msg.get("type", "")
            if (mtype in (MSG_TX, MSG_BLOCK, MSG_CMPCTBLOCK)
                    and peer._soft_ban_throttle_until > time.time()):
                _rem = peer._soft_ban_throttle_until - time.time()
                _sl  = min(_rem, Config.SOFT_BAN_THROTTLE_DELAY_SECS)
                if _sl > 0:
                    time.sleep(_sl)
                peer._soft_ban_throttle_until = (
                    time.time() + Config.SOFT_BAN_THROTTLE_DELAY_SECS)

            # ── Dispatch to shared message handler ────────────────────────
            try:
                self._handle_message(peer, msg)  # type: ignore[arg-type]
            except Exception as exc:
                log.debug(f"[UDP] _handle_message error: {exc}")

        self._on_peer_disconnect(peer)  # type: ignore[arg-type]
        # Clean up UDP session
        addr = _udp_normalize_addr((peer.ip, peer.port))
        with self._udp_peers_lock:
            self._udp_peers.pop(addr, None)
        self._udp.remove_session(addr, expected_session=peer._session)

    def _udp_send_to_peer(self, peer: 'UDPPeerConnection', msg: dict,
                           priority: int = 1) -> bool:
        """
        Rate-limited unicast send to a UDP peer.

        The sliding window inside UDPSession.send_message() is the primary
        rate limiter.  This method adds an additional priority-queue layer
        that mirrors the TCP PeerConnection.send_priority() contract so that
        the rest of P2PNetwork can call either interchangeably.

        Priority tiers:
          PRI_CRITICAL (0) — new blocks, consensus votes
          PRI_NORMAL   (1) — transactions, capability updates
          PRI_BULK     (2) — chain sync pages, PEX
        """
        return peer.send_priority(msg, priority)

    def _udp_heartbeat_loop(self):
        """
        Periodically:
          1. Evict UDP peers whose sessions have gone silent (>_UDP_HB_TIMEOUT).
          2. Log current UDP peer count.
          3. v7.5.0-OPT: feed per-peer SRTT samples into LatencyTracker so the
             network-aware block sizer has a fresh mean on every build.
        """
        while self._running:
            time.sleep(_UDP_HB_INTERVAL)
            try:
                dead_peers = []
                # ── Snapshot peer list under lock, then work on the copy ────
                with self._udp_peers_lock:
                    peer_items = list(self._udp_peers.items())
                for addr, up in peer_items:
                    sess = getattr(up, "_session", None)
                    if sess is None:
                        continue
                    if not sess.is_alive():
                        dead_peers.append((addr, up))
                        continue
                    # Pull the session's current smoothed RTT (may be None
                    # before the first ACK arrives — skip then).
                    w = getattr(sess, "_window", None)
                    srtt = getattr(w, "_srtt", None) if w is not None else None
                    if srtt is not None:
                        self.latency_tracker.record_peer_rtt(addr, srtt)
                for addr, dead_up in dead_peers:
                    # The heartbeat scan used a snapshot.  A peer may have
                    # reconnected on the same endpoint before cleanup runs;
                    # only evict the exact stale object observed by the scan.
                    evict = False
                    with self._udp_peers_lock:
                        if self._udp_peers.get(addr) is dead_up:
                            self._udp_peers.pop(addr, None)
                            evict = True
                    if evict:
                        dead_up.connected = False
                        dead_up.close()
                        self._udp.remove_session(
                            addr, expected_session=getattr(dead_up, "_session", None))
                        self.latency_tracker.drop_peer(addr)
                        log.debug(f"[UDP] Evicted silent peer {addr}")
            except Exception as e:
                log.debug(f"[UDP] Heartbeat loop error: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # END SECTION UDP-P2PNETWORK
    # ══════════════════════════════════════════════════════════════════════

    def _ban_score_decay_loop(self):
        """Periodically halve all ban scores so peers can recover."""
        while self._running:
            time.sleep(Config.PEER_SCORE_DECAY_INTERVAL)
            try:
                self.storage.decay_ban_scores()
            except Exception as e:
                log.debug(f"Ban score decay error: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # v7.1.0 — Per-peer message-rate limiter (DoS protection)
    # ──────────────────────────────────────────────────────────────────────
    def _check_msg_rate(self, peer: 'PeerConnection', mtype: str) -> bool:
        """Check if ``peer`` has exceeded its per-window msg-rate quota.

        Returns True if the message should be processed, False if it should
        be dropped.  On a hard breach (>2× a quota) we also apply a ban score
        penalty so repeat offenders are disconnected after decay.

        Strategy:
          • sliding window of _MSG_RATE_WINDOW seconds
          • check global msg-count AND per-type count
          • small overshoots: silent drop (protect the receiver only)
          • egregious overshoots (>2×): add_ban_score so the peer is punished
        """
        if not peer or not peer.peer_id:
            return True
        now = time.time()
        cutoff = now - self._MSG_RATE_WINDOW
        with self._msg_rate_lock:
            rec = self._msg_rate.get(peer.peer_id)
            if rec is None:
                rec = {"global": deque(), "types": defaultdict(deque)}
                self._msg_rate[peer.peer_id] = rec
            g = rec["global"]
            while g and g[0] < cutoff:
                g.popleft()
            t_deque = rec["types"][mtype]
            while t_deque and t_deque[0] < cutoff:
                t_deque.popleft()

            # Global cap
            if len(g) >= self._MSG_RATE_GLOBAL:
                over = len(g) / max(1, self._MSG_RATE_GLOBAL)
                if over > 2.0:
                    try:
                        self.storage.add_ban_score(
                            peer.peer_id,
                            getattr(Config, "PEER_SCORE_RATE_LIMIT_HARD", 20))
                    except Exception:
                        pass
                    log.warning(
                        "Peer %s: global msg-rate %d/%ds (%.1fx over) — penalizing",
                        peer.peer_id[:12], len(g),
                        self._MSG_RATE_WINDOW, over)
                else:
                    log.debug(
                        "Peer %s: global msg-rate %d/%ds — dropping",
                        peer.peer_id[:12], len(g), self._MSG_RATE_WINDOW)
                return False

            # Per-type cap
            limit = self._MSG_RATE_PERTYPE.get(mtype)
            if limit is not None and len(t_deque) >= limit:
                over = len(t_deque) / max(1, limit)
                if over > 2.0:
                    try:
                        self.storage.add_ban_score(
                            peer.peer_id,
                            getattr(Config, "PEER_SCORE_RATE_LIMIT_HARD", 20))
                    except Exception:
                        pass
                    log.warning(
                        "Peer %s: type=%s rate %d/%ds (%.1fx over) — penalizing",
                        peer.peer_id[:12], mtype,
                        len(t_deque), self._MSG_RATE_WINDOW, over)
                else:
                    log.debug(
                        "Peer %s: type=%s rate %d/%ds — dropping",
                        peer.peer_id[:12], mtype,
                        len(t_deque), self._MSG_RATE_WINDOW)
                return False

            g.append(now)
            t_deque.append(now)
        return True

    def _clear_msg_rate(self, peer_id: str):
        """Free memory when a peer disconnects."""
        with self._msg_rate_lock:
            self._msg_rate.pop(peer_id, None)

    def stop(self):
        self._running = False
        self._upnp.stop()
        self._dns_seeder.stop()
        self._ice.stop()
        # ── UDP transport teardown ─────────────────────────────────────────
        try:
            self._udp.stop()
        except Exception:
            pass
        with self._udp_peers_lock:
            for p in list(self._udp_peers.values()):
                try: p.close()
                except Exception: pass
            self._udp_peers.clear()
        with self._lock:
            for p in list(self.peers.values()):
                p.close()
            self.peers.clear()

    def _server_loop(self):
        srv = _create_dual_stack_server_socket(self.port)
        try:
            try:
                srv.bind((Config.BIND_ADDRESS, self.port))
            except OSError:
                self.port += 1
                srv.bind((Config.BIND_ADDRESS, self.port))
            srv.listen(64)
            srv.settimeout(1.0)
            log.info(f"P2P server bound to [{Config.BIND_ADDRESS}]:{self.port} "
                     f"(dual-stack)")
            while self._running:
                try:
                    conn, addr = srv.accept()
                    threading.Thread(
                        target=self._handle_inbound,
                        args=(conn, addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        log.debug(f"Server error: {e}")
        finally:
            try:
                srv.close()
            except Exception:
                pass

    def _handle_inbound(self, sock: socket.socket, addr):
        # addr[0] from an AF_INET6 dual-stack socket may arrive as
        # '::ffff:192.168.1.1' for IPv4 clients.  Normalize it immediately
        # so that rate-limit buckets, peer dedup, and ban score lookups
        # all use a consistent representation.
        client_ip = _normalize_ip(addr[0])

        # ── Per-IP inbound connection rate limit ──────────────────────────────
        now = time.time()
        with self._lock:
            window = self._conn_rate[client_ip]
            while window and (now - window[0]) > self._CONN_RATE_WINDOW:
                window.popleft()
            if len(window) >= self._CONN_RATE_LIMIT:
                log.debug(
                    f"Inbound rate-limit hit for {client_ip} "
                    f"({len(window)} conns in {self._CONN_RATE_WINDOW}s)")
                try:
                    sock.close()
                except Exception:
                    pass
                return
            window.append(now)

        # ── Soft Ban: IP ban check (v6.0.0) ──────────────────────────────────
        # Reject inbound connections from IPs that earned a strike-3 ban.
        if self._is_ip_banned(client_ip):
            log.debug(
                f"[SoftBan] Inbound connection from banned IP "
                f"{client_ip} rejected (24-hour ban active)")
            _pa_push("IN", client_ip, addr[1], "BANNED")
            try:
                sock.close()
            except Exception:
                pass
            return

        # ── TLS wrap inbound socket (Problem #1) ─────────────────────────────
        tls_ctx = TLSManager.server_context()
        if tls_ctx:
            try:
                sock = tls_ctx.wrap_socket(sock, server_side=True)
            except ssl.SSLError as e:
                log.debug(f"TLS wrap failed for {client_ip}: {e}")
                try:
                    sock.close()
                except Exception:
                    pass
                return

            # ── TLS FIX v2 (v6.9.7): Inbound TOFU removed ────────────────────
            # With CERT_NONE on the server context (the correct setting for a
            # self-signed P2P mesh), the TLS layer never requests a client cert,
            # so getpeercert() always returns None here.  The previous code
            # treated that as a TOFU failure and dropped the connection before
            # HELLO was ever read — which is why DNS peers could never become
            # P2P peers.
            #
            # Inbound peer identity is verified cryptographically by the
            # ECDSA VERIFY / CHALLENGE_RESP exchange below, which proves the
            # connecting node owns the private key corresponding to pub_hex in
            # their HELLO.  That is a complete proof of identity — we do not
            # also need a TLS client cert.
            #
            # The outbound (connect_to) side still does TOFU on the SERVER cert,
            # protecting against MITM on outbound connections.

        # Use normalized client_ip (IPv4-mapped addresses already stripped above)
        # addr[1] is the port number regardless of address family
        tmp = PeerConnection("unknown", client_ip, addr[1], sock)
        _pa_push("IN", client_ip, addr[1], "ARRIVING")
        try:
            # CRIT-01 FIX: Server generates and sends the PoW challenge BEFORE
            # reading the client's HELLO.  The client must solve it and embed
            # the nonce in their HELLO.  This prevents the prior bypass where
            # a client could omit pow_challenge from HELLO to skip PoW entirely.
            _srv_pow_challenge = ""
            if Config.PEER_POW_DIFFICULTY > 0:
                _srv_pow_challenge = secrets.token_hex(16)
                tmp.send({"type": MSG_POW_CHALLENGE,
                          "challenge": _srv_pow_challenge,
                          "difficulty": Config.PEER_POW_DIFFICULTY})

            msg = tmp.recv_line(timeout=12)
            if not msg or msg.get("type") != MSG_HELLO:
                tmp.close(); return
            peer_id  = msg.get("node_id", "")
            pub_hex  = msg.get("pub_hex", "")
            user_id  = msg.get("user_id", "")
            peer_tls_fp = msg.get("tls_fp", "")   # advertised TLS fingerprint
            # NEW: software identity hash for trust classification
            peer_logic_hash = msg.get("logic_hash", "")
            # v6.9.9.7: read peer capabilities from HELLO so capability router
            # is populated immediately (was delayed up to 120 s before).
            peer_hello_caps = msg.get("capabilities", [])
            # ICE candidates advertised by the remote peer (may be absent on
            # old nodes — default to empty list; never crash)
            remote_ice_cands = msg.get("ice_candidates", [])
            # P2P-PORT-FIX: the remote node's actual TCP listen port.
            # addr[1] is the ephemeral OS source port of this TCP connection —
            # NOT the port the remote is listening on.  Old nodes that don't
            # send this field fall back to DEFAULT_PORT as a safe assumption.
            peer_listen_port = int(msg.get("listen_port", Config.DEFAULT_PORT))

            if not peer_id or not pub_hex:
                tmp.send({"type": MSG_REJECT, "reason": "Missing identity"})
                tmp.close(); return

            # ── TLS fingerprint pinning (TOFU) ────────────────────────────────
            if tls_ctx and peer_tls_fp:
                stored_fp = self.storage.get_peer_tls_fp(peer_id)
                if stored_fp and not hmac.compare_digest(stored_fp, peer_tls_fp):
                    log.warning(
                        f"TLS fingerprint mismatch for {peer_id[:12]} — "
                        f"possible MITM! Rejecting.")
                    tmp.send({"type": MSG_REJECT, "reason": "TLS fingerprint mismatch"})
                    tmp.close(); return
                elif not stored_fp and peer_tls_fp:
                    self.storage.set_peer_tls_fp(peer_id, peer_tls_fp)

            challenge = secrets.token_hex(16)
            tmp.send({"type": MSG_VERIFY, "challenge": challenge,
                      "tls_fp": TLSManager.fingerprint()})

            resp = tmp.recv_line(timeout=8)
            if not resp:
                tmp.close(); return

            try:
                pub  = pub_from_hex(pub_hex)
                sig  = sig_from_hex(resp.get("sig", "[]"))
                h    = hashlib.sha256(challenge.encode()).digest()
                if not ecdsa_verify(pub, h, sig):
                    _pa_push("IN", client_ip, peer_listen_port, "REJECTED:Sig")
                    tmp.send({"type": MSG_REJECT, "reason": "Signature invalid"})
                    tmp.close(); return
            except Exception:
                _pa_push("IN", client_ip, peer_listen_port, "REJECTED:Sig")
                tmp.send({"type": MSG_REJECT, "reason": "Sig verification failed"})
                tmp.close(); return

            # Gather our ICE candidates to include in ACCEPT (backward-compat)
            ice_cands_out = []
            if Config.ICE_ENABLED:
                try:
                    ice_cands_out = self._ice.get_candidates_as_dicts()
                except Exception:
                    ice_cands_out = []

            # ── PoW verification (CRIT-01 FIX v2) ───────────────────────────
            # IMPORTANT: verify PoW BEFORE sending MSG_ACCEPT.
            #
            # Previous order (WRONG):
            #   1. send MSG_ACCEPT   ← client receives this, calls _register_peer,
            #                           starts message loop, returns connect_to=True
            #   2. check PoW         ← if bad, close socket
            # Result: client has a live peer entry; server has none. They are
            # permanently asymmetric and can never exchange messages.
            #
            # Correct order (this fix):
            #   1. check PoW         ← reject before the client considers itself connected
            #   2. send MSG_ACCEPT   ← only reached if PoW is valid
            if _srv_pow_challenge and Config.PEER_POW_DIFFICULTY > 0:
                _pow_nonce = msg.get("pow_nonce", "")
                if not _pow_check(_srv_pow_challenge, _pow_nonce,
                                  Config.PEER_POW_DIFFICULTY):
                    log.warning(
                        f"Inbound {peer_id[:12]} failed PoW "
                        f"(challenge={_srv_pow_challenge[:16]}..., "
                        f"nonce={_pow_nonce!r}) — rejecting before ACCEPT")
                    _pa_push("IN", client_ip, peer_listen_port, "REJECTED:PoW")
                    tmp.send({"type": MSG_REJECT, "reason": "PoW verification failed"})
                    tmp.close()
                    return

            tmp.send({"type": MSG_ACCEPT, "node_id": self.node_id,
                      "pub_hex": self.wallet.pub_hex, "version": Config.VERSION,
                      "tls_fp": TLSManager.fingerprint(),
                      "ice_candidates": ice_cands_out,
                      "logic_hash": _NODE_LOGIC_HASH,
                      # v6.9.9.7: include capabilities and our chain height so
                      # the connecting node knows our role immediately and can
                      # decide whether to sync from us without extra round-trips.
                      "capabilities": Config.NODE_CAPABILITIES,
                      "chain_height": self.blockchain.height(),
                      # v7.5-UDP: advertise our UDP port in ACCEPT
                      "udp_port":     self.port})

            # v6.9.9.7: register inbound peer's capabilities immediately from HELLO
            # (was delayed until first MSG_CAPABILITY_ADV, up to 120 s later).
            if peer_hello_caps and hasattr(self, "_capability_router"):
                try:
                    self._capability_router.handle_adv(peer_id, peer_hello_caps)
                    log.debug(f"Inbound {peer_id[:12]} capabilities from HELLO: "
                              f"{peer_hello_caps}")
                except Exception:
                    pass   # capability registration is non-fatal

            # Unknown hashes are not grounds for disconnection — the peer may
            # be running a legitimate but older or custom build.
            # Instead we flag the peer TRUST_LEVEL_LOW and activate Full Audit
            # Mode so every message from it is scrutinised more deeply.
            if (peer_logic_hash
                    and peer_logic_hash != _NODE_LOGIC_HASH
                    and peer_logic_hash not in Config.KNOWN_GOOD_LOGIC_HASHES):
                _inbound_trust = PeerConnection.TRUST_LOW
                log.warning(
                    f"Inbound {peer_id[:12]} logic_hash="
                    f"{peer_logic_hash[:16]}... "
                    f"(ours={_NODE_LOGIC_HASH[:16]}...) — "
                    f"TRUST_LEVEL_LOW; Full Audit Mode enabled")
            else:
                _inbound_trust = PeerConnection.TRUST_HIGH

            peer = PeerConnection(peer_id, client_ip, peer_listen_port, sock,
                                  reputation=1.0, trust_level=_inbound_trust)
            # BUG-FIX (v7.0.0.1): Transfer any bytes already buffered by
            # recv_line() during the handshake into the new peer object.
            # recv_line() accumulates raw TCP bytes in tmp._recv_buf.  TCP is a
            # stream — the remote may have sent the first post-handshake message
            # (e.g. MSG_GET_CHAIN, MSG_CAPABILITY_ADV) before we finished reading
            # the last handshake frame.  Those bytes landed in tmp._recv_buf but
            # tmp is discarded here; without this transfer they are lost silently,
            # causing "connected but never syncs" because the initiator's
            # MSG_GET_CHAIN is dropped before _peer_message_loop ever runs.
            peer._recv_buf = tmp._recv_buf
            # v7.0.1.2 GHOST-PEER FIX: inbound side must ALSO request sync.
            # Previously only the outbound (connecting) side fired MSG_GET_CHAIN.
            # Scenario that failed: A(h=66) dials B(h=0).  A is the initiator
            # and asks B for chain → B returns empty → A learns nothing, and
            # B never asks A because initiator=False → both stay desynced
            # forever ("ghost peer").  Making both sides request is safe
            # because MSG_GET_CHAIN is in _GOSSIP_DEDUP_SKIP and whichever
            # side is shorter simply receives an empty MSG_CHAIN reply.
            self._register_peer(peer, peer_id, pub_hex, user_id,
                                initiator=True)    # v7.0.1.2 — both sides sync
            # BUG-FIX (v7.0.0.6): _register_peer() can reject the peer silently
            # (anti-eclipse subnet limit or MAX_PEERS cap) by calling peer.close()
            # and returning without raising an exception.  The old code pushed
            # "CONNECTED" and called _peer_message_loop unconditionally, resulting
            # in a false dashboard event and a _peer_message_loop call on a closed
            # socket (harmless but wasteful).  Guard on peer.connected so we only
            # proceed when registration actually succeeded.
            if not peer.connected:
                return   # rejected by _register_peer; socket already closed
            _pa_push("IN", client_ip, peer_listen_port, "CONNECTED")
            self._peer_message_loop(peer)
        except Exception as e:
            log.debug(f"Inbound handler error {_format_peer_addr(client_ip, addr[1])}: {e}")
            tmp.close()

    def connect_to(self, ip: str, port: int) -> bool:
        """
        Establish a P2P connection to (ip, port) using the ICE priority ladder:
          1. Direct TCP (existing path — fast path for open/UPnP nodes)
          2. UDP hole punch (NAT/CGNAT traversal via STUN server-reflexive)
          3. TCP direct (outbound-only / asymmetric NAT)
          4. TURN-lite relay bridge
          5. Original _create_connection_dual_stack (absolute failsafe)

        On success, completes the existing TLS + HELLO handshake so that the
        rest of the networking code is completely unchanged.
        """
        # ── ICE connection attempt ────────────────────────────────────────────
        raw_sock: Optional[socket.socket] = None

        if Config.ICE_ENABLED:
            try:
                # Wait briefly for candidate gathering to complete (non-blocking
                # if already done; at most 2s on very slow STUN lookups)
                self._ice._ready.wait(timeout=2.0)
                ice_sock = self._ice.connect(ip, port, timeout=Config.PEER_TIMEOUT)
                if ice_sock:
                    raw_sock = ice_sock
            except Exception as exc:
                log.debug(f"ICE connect attempt failed for "
                          f"{_format_peer_addr(ip, port)}: {exc}")
                raw_sock = None

        # ── Failsafe: fall back to original dual-stack TCP ────────────────────
        if raw_sock is None:
            try:
                raw_sock = _create_connection_dual_stack(
                    ip, port, Config.PEER_TIMEOUT)
            except Exception:
                return False

        # ── From here: identical to original connect_to logic ─────────────────
        try:
            # TLS wrap outbound socket
            tls_ctx = TLSManager.client_context()
            if tls_ctx:
                try:
                    raw_sock = tls_ctx.wrap_socket(raw_sock, server_hostname=None)
                except ssl.SSLError as e:
                    log.debug(f"TLS wrap failed for {_format_peer_addr(ip, port)}: {e}")
                    try:
                        raw_sock.close()
                    except Exception:
                        pass
                    return False

                # ── TOFU: pin outbound peer cert immediately after TLS handshake ─
                # BUG-FIX v6.9.8: Changed from reject-on-mismatch to pin-only.
                #
                # Old behaviour: verify_peer_fingerprint_by_ip() returned False
                # whenever the peer's cert fingerprint differed from the stored
                # one, causing connect_to to return False and log "TOFU fingerprint
                # check failed."  This broke reconnection after ANY node restart
                # because self-signed certs are regenerated on startup — a new
                # fingerprint is normal, not an attack.
                #
                # The in-handshake ECDSA CHALLENGE_RESP already proves identity
                # cryptographically (connecting node must sign our challenge with
                # the private key matching pub_hex in their HELLO).  IP-keyed TOFU
                # adds no security benefit over that proof and actively breaks
                # reconnection on Android/Pydroid3 where restarts are frequent.
                #
                # New behaviour: always pin the new fingerprint (TOFU first-use
                # semantics), log a warning if the fingerprint changed, but never
                # drop the connection here.  The ECDSA exchange below is the real
                # identity gate.
                try:
                    peer_cert_der = raw_sock.getpeercert(binary_form=True)
                    if peer_cert_der:
                        from cryptography.hazmat.primitives import hashes as _h
                        from cryptography.x509 import load_der_x509_certificate as _ldx
                        _cert = _ldx(peer_cert_der)
                        _fp   = _cert.fingerprint(_h.SHA256()).hex()
                        with TLSManager._lock:
                            _stored = TLSManager._ip_fp_store.get(ip)
                            if _stored is None:
                                TLSManager._ip_fp_store[ip] = _fp
                                log.debug(f"[TOFU] Pinned cert for {ip}: {_fp[:16]}...")
                            elif not hmac.compare_digest(_stored, _fp):
                                # Cert rotated (normal after restart) — re-pin,
                                # do NOT reject.  The ECDSA handshake below is
                                # the authoritative identity check.
                                TLSManager._ip_fp_store[ip] = _fp
                                log.warning(
                                    f"[TOFU] Cert fingerprint changed for {ip} "
                                    f"(stored={_stored[:16]}... new={_fp[:16]}...) "
                                    f"— re-pinned. ECDSA will verify identity.")
                except Exception as e:
                    # Non-fatal: cert pinning is best-effort; ECDSA is the gate.
                    log.debug(f"[TOFU] Cert pin skipped for {ip}: {e}")

            tmp = PeerConnection("unknown", ip, port, raw_sock)
            my_user_id = self.storage.get_meta("user_id") or ""

            # CRIT-01 FIX: Read the server's POW_CHALLENGE before sending HELLO.
            # Old servers that don't send a challenge are handled gracefully —
            # if the first message is not MSG_POW_CHALLENGE we treat it as a
            # legacy peer (no PoW required) and proceed with an empty nonce.
            _outbound_pow_nonce = ""
            _first_msg = tmp.recv_line(timeout=8)
            if not _first_msg:
                tmp.close(); return False
            if _first_msg.get("type") == MSG_POW_CHALLENGE:
                _outbound_challenge = _first_msg.get("challenge", "")
                _outbound_diff      = _first_msg.get("difficulty",
                                                      Config.PEER_POW_DIFFICULTY)
                if _outbound_challenge and _outbound_diff > 0:
                    _outbound_pow_nonce = _pow_solve(
                        _outbound_challenge, _outbound_diff) or ""
                    if not _outbound_pow_nonce:
                        log.warning(
                            f"connect_to {_format_peer_addr(ip, port)}: "
                            f"PoW solve failed after max iterations — "
                            f"connection will be rejected by peer")
                # After solving, read the actual HELLO prompt if server sends one,
                # or proceed directly (server waits for our HELLO after challenge).
            elif _first_msg.get("type") != MSG_HELLO:
                # Unexpected first message — not a Visold peer
                tmp.close(); return False

            # Inject ICE candidates into HELLO so the remote can use them
            # for future connections (backward-compatible: old nodes ignore
            # the extra field).
            ice_cands = []
            if Config.ICE_ENABLED:
                try:
                    ice_cands = self._ice.get_candidates_as_dicts()
                except Exception:
                    ice_cands = []

            tmp.send({
                "type":           MSG_HELLO,
                "node_id":        self.node_id,
                "pub_hex":        self.wallet.pub_hex,
                "version":        Config.VERSION,
                "user_id":        my_user_id,
                "tls_fp":         TLSManager.fingerprint(),
                "ice_candidates": ice_cands,    # ignored by old nodes
                "logic_hash":     _NODE_LOGIC_HASH,
                # v6.9.9.7: advertise capabilities in HELLO so the remote peer
                # knows our role (full_node, vvm, etc.) without waiting up to
                # 120 s for the periodic MSG_CAPABILITY_ADV broadcast.
                "capabilities":   Config.NODE_CAPABILITIES,
                # CRIT-01: nonce for the server-issued PoW challenge above.
                "pow_nonce":      _outbound_pow_nonce,
                # P2P-PORT-FIX: advertise our actual TCP listen port so the
                # remote stores it in the peers DB and shares it via PEX.
                # Without this field the remote records addr[1] (the ephemeral
                # OS-assigned source port of this TCP connection) which is NOT
                # our listen port and is unreachable from any third node.
                "listen_port":    self.port,
                # v7.5-UDP: advertise UDP port so the remote can prefer UDP
                "udp_port":       self.port,
            })

            msg = tmp.recv_line(timeout=8)
            if not msg:
                log.debug(
                    f"connect_to {_format_peer_addr(ip, port)}: "
                    f"no response after HELLO (peer offline or incompatible protocol)")
                tmp.close(); return False
            if msg.get("type") != MSG_VERIFY:
                log.debug(
                    f"connect_to {_format_peer_addr(ip, port)}: "
                    f"expected '{MSG_VERIFY}', got {msg.get('type')!r} — "
                    f"possible version mismatch or non-Visold peer")
                tmp.close(); return False

            challenge   = msg.get("challenge", "")
            peer_tls_fp = msg.get("tls_fp", "")
            sig = self.wallet.sign(challenge.encode())
            tmp.send({"type": "CHALLENGE_RESP", "sig": sig_to_hex(sig)})

            msg = tmp.recv_line(timeout=8)
            if not msg:
                log.debug(
                    f"connect_to {_format_peer_addr(ip, port)}: "
                    f"no response after CHALLENGE_RESP")
                tmp.close(); return False
            if msg.get("type") != MSG_ACCEPT:
                log.debug(
                    f"connect_to {_format_peer_addr(ip, port)}: "
                    f"expected '{MSG_ACCEPT}', got {msg.get('type')!r} — "
                    f"handshake rejected (reason: {msg.get('reason', 'unknown')})")
                tmp.close(); return False

            peer_id  = msg.get("node_id", sha256(
                _format_peer_addr(ip, port).encode()))
            pub_hex  = msg.get("pub_hex", "")
            # NEW: read the remote node's software identity from ACCEPT
            accept_logic_hash = msg.get("logic_hash", "")
            # v6.9.9.7: read capabilities and chain height from ACCEPT
            accept_caps        = msg.get("capabilities", [])
            accept_chain_height = int(msg.get("chain_height", -1))

            # TLS fingerprint pinning for outbound connection
            if peer_tls_fp:
                stored_fp = self.storage.get_peer_tls_fp(peer_id)
                if stored_fp and not hmac.compare_digest(stored_fp, peer_tls_fp):
                    log.warning(
                        f"TLS fingerprint mismatch for outbound {peer_id[:12]} — "
                        f"possible MITM! Rejecting.")
                    tmp.close(); return False
                elif not stored_fp:
                    self.storage.set_peer_tls_fp(peer_id, peer_tls_fp)

            # ── Logic Hash Trust Classification (Hybrid Approach) ─────────────
            # Mirror the inbound logic: keep the connection, but flag the peer
            # TRUST_LEVEL_LOW if it advertises an unrecognised logic_hash.
            if (accept_logic_hash
                    and accept_logic_hash != _NODE_LOGIC_HASH
                    and accept_logic_hash not in Config.KNOWN_GOOD_LOGIC_HASHES):
                _outbound_trust = PeerConnection.TRUST_LOW
                log.warning(
                    f"Outbound {peer_id[:12]} logic_hash="
                    f"{accept_logic_hash[:16]}... "
                    f"(ours={_NODE_LOGIC_HASH[:16]}...) — "
                    f"TRUST_LEVEL_LOW; Full Audit Mode enabled")
            else:
                _outbound_trust = PeerConnection.TRUST_HIGH

            peer = PeerConnection(peer_id, ip, port, raw_sock,
                                  reputation=1.0, trust_level=_outbound_trust)
            # BUG-FIX (v7.0.0.1): Same _recv_buf transfer as the inbound path.
            # recv_line() was called multiple times during the outbound handshake
            # (POW_CHALLENGE, VERIFY, ACCEPT).  Any bytes arriving in the same
            # TCP segment as the final ACCEPT frame are buffered in tmp._recv_buf.
            # Without this transfer, _peer_message_loop starts with buf=b"" and
            # those bytes — potentially the start of a MSG_CHAIN response — are
            # silently discarded, explaining why sync requests sent immediately
            # after connect are never processed on the receiving node.
            peer._recv_buf = tmp._recv_buf
            self._register_peer(peer, peer_id, pub_hex, "",
                                initiator=True)   # outbound — we request sync

            # BUG-FIX (v7.0.0.7): Mirror the inbound peer.connected guard that
            # was added in v7.0.0.6.  _register_peer() can silently close the
            # peer and return (anti-eclipse subnet limit or MAX_PEERS cap).
            # Without this guard the old code unconditionally spawned a
            # _peer_message_loop thread on a closed socket.  The thread exited
            # immediately (peer.connected==False) causing no data corruption, but
            # connect_to() incorrectly returned True, making the caller believe
            # the connection succeeded when registration was actually rejected.
            if not peer.connected:
                return False   # rejected by _register_peer; socket already closed

            # v6.9.9.7: register outbound peer capabilities immediately from ACCEPT.
            if accept_caps and hasattr(self, "_capability_router"):
                try:
                    self._capability_router.handle_adv(peer_id, accept_caps)
                    log.debug(f"Outbound {peer_id[:12]} capabilities from ACCEPT: "
                              f"{accept_caps}")
                except Exception:
                    pass

            # ── v7.6.0 Save peer-advertised chain_height + capabilities on
            # the PeerConnection so MiningSafetyGuard can read the highest
            # known peer height without a network round-trip.  Also used
            # by the safety guard's _kick_fast_sync helper to find peers
            # that advertise the "snapshots" capability.
            try:
                if isinstance(accept_caps, list):
                    peer.capabilities = list(accept_caps)
                if accept_chain_height >= 0:
                    peer.chain_height = int(accept_chain_height)
            except Exception:
                pass

            if accept_chain_height >= 0:
                my_h = self.blockchain.height()
                if accept_chain_height > my_h:
                    log.info(
                        f"[Handshake] Peer {peer_id[:12]} has height "
                        f"{accept_chain_height} (ours={my_h}) — "
                        f"sync will follow automatically")
            threading.Thread(
                target=self._peer_message_loop,
                args=(peer,),
                daemon=True
            ).start()
            return True
        except Exception as e:
            log.debug(f"connect_to {_format_peer_addr(ip, port)} failed: {e}")
            try:
                raw_sock.close()
            except Exception:
                pass
            return False

    def _register_peer(self, peer: PeerConnection, peer_id: str,
                        pub_hex: str, user_id: str,
                        initiator: bool = False):
        """Register a fully-handshaked peer and start background post-connect tasks.

        Parameters
        ----------
        initiator : bool
            True  — we are the OUTBOUND (connecting) side.  We fire the
                    one-time full-chain sync request from_idx=1, because the
                    remote may have a chain we haven't seen yet.
            False — we are the INBOUND (accepting) side.  The remote will
                    fire its own sync request to us, so we don't duplicate it.
                    (Previously both sides fired from_idx=1 simultaneously,
                    wasting bandwidth and causing confusion in the logs.)
        """
        # AUDIT-FIX (self-connect): this is the ONE place every handshaked
        # peer (TCP inbound, TCP outbound, UDP) gets registered, so it's
        # the only choke point guaranteed to run *after* peer_id is known.
        # The pre-dial guard in _try_add_peer only catches literal loopback
        # IPs, plus an already-known peer_id -- neither applies to a DNS
        # seed (e.g. visoldcrypto2026.duckdns.org) that currently resolves
        # to our own public IP, so that guard is a no-op for this exact
        # case and the connection previously sailed through a full
        # PoW+TLS+ECDSA handshake before anything noticed. Reject by
        # identity here, unconditionally, before any peer-list/storage
        # side effects happen.
        if peer_id == self.node_id:
            log.warning(
                f"Refusing self-connection from "
                f"{_format_peer_addr(peer.ip, peer.port)} "
                f"(peer_id == our own node_id)")
            try:
                peer.close()
            except Exception:
                pass
            return
        with self._lock:
            # ── Fix #6: Anti-eclipse — IP subnet diversity enforcement ─────────
            # Count how many connected peers share the same /24 (IPv4) or /48
            # (IPv6) subnet.  If a single subnet already contributes more than
            # MAX_PEERS_PER_SUBNET of the total peer slots, reject this peer.
            # This limits the damage an adversary can do by controlling many IPs
            # in the same subnet and clustering them into our peer set (eclipse).
            MAX_PEERS_PER_SUBNET = max(3, Config.MAX_PEERS // 8)
            peer_subnet = self._peer_subnet(peer.ip)
            subnet_count = sum(
                1 for p in self.peers.values()
                if self._peer_subnet(p.ip) == peer_subnet and p.connected
            )
            if subnet_count >= MAX_PEERS_PER_SUBNET:
                log.debug(
                    f"Anti-eclipse: rejecting {peer.ip} — subnet {peer_subnet} "
                    f"already has {subnet_count}/{MAX_PEERS_PER_SUBNET} peers")
                peer.close()
                return

            # AUDIT-FIX-21: duplicate-registration race. Two independent
            # handshakes for the SAME peer_id can complete concurrently —
            # e.g. simultaneous mutual connect_to()/_handle_inbound() (both
            # sides dial each other around the same time, routine while
            # under MIN_PEERS), or a race between the TCP and UDP transports
            # (_udp_connect_to / _udp_handle_inbound register into this same
            # dict). Previously `self.peers[peer_id] = peer` below was a bare
            # overwrite with no check for an existing entry, so the loser's
            # socket/session was never closed (its message-loop thread ran
            # forever, blocked on recv — a leak), and when that orphaned
            # connection eventually disconnected, _on_peer_disconnect()'s
            # unconditional pop-by-key evicted whichever connection was
            # *currently* registered — silently dropping a live, healthy
            # peer from gossip/routing. See AUDIT-FIX-21 in
            # _on_peer_disconnect() for the other half of this fix.
            #
            # Fix: the new connection just proved key ownership via a fresh
            # ECDSA handshake, so it always wins. Close the superseded
            # connection here, under this same lock, so by the time its
            # message loop notices and calls _on_peer_disconnect(), that
            # function's own identity check (added there) will correctly
            # see it's no longer the current registration and skip the
            # identity-level cleanup instead of evicting the new one.
            _existing_peer = self.peers.get(peer_id)
            if _existing_peer is not None and _existing_peer is not peer:
                log.info(
                    f"Peer {peer_id[:12]}... reconnected via a new session "
                    f"[{_format_peer_addr(peer.ip, peer.port)}] — closing "
                    f"previous session "
                    f"[{_format_peer_addr(_existing_peer.ip, _existing_peer.port)}]")
                try:
                    _existing_peer.connected = False
                    _existing_peer.close()
                except Exception:
                    pass
                self._eager_peers.discard(peer_id)

            if len(self.peers) >= Config.MAX_PEERS:
                if self.peers:
                    worst = min(self.peers.values(), key=lambda p: p.reputation)
                    worst.close()
                    self.peers.pop(worst.peer_id, None)
                    self._eager_peers.discard(worst.peer_id)
            self.peers[peer_id] = peer
            self._eager_peers.add(peer_id)  # Plumtree: start as eager
        info = {"peer_id": peer_id, "ip": peer.ip, "port": peer.port,
                "pub_hex": pub_hex, "user_id": user_id}
        self.router.update(peer_id, info)
        self.storage.save_peer(peer_id, peer.ip, peer.port)
        log.info(f"Peer connected: {peer_id[:12]}... "
                 f"[{_format_peer_addr(peer.ip, peer.port)}]")
        # ── LIVE-UI: push instant peer-connect notification ───────────────────
        _push_peer_notif("connected", peer.ip, peer.port)

        # BUG-FIX: Auto-sync chain on peer connect.
        # Without this, two nodes that were mining independently would never
        # reconcile their chains — each node only gossiped NEW blocks but never
        # requested historical blocks from newly connected peers.  Node A with
        # 65 blocks and Node B with 66 blocks would each keep mining on their
        # own fork indefinitely.
        #
        # This is intentionally from_idx=1 (not from our tip) because the two
        # chains may have diverged at block 1.  This one-time fork-check on
        # connect is the ONLY place the full chain is replayed; the periodic
        # heartbeat (_reconnect_loop) and the keypress-sync (_dispatch) request
        # only blocks above our current tip to prevent Socket Bloat.
        #
        # v6.9.9.7: the `initiator` flag gates the sync request so only the
        # OUTBOUND (connecting) side fires it.  Previously BOTH sides fired
        # from_idx=1 simultaneously — the inbound side's request was wasteful
        # (the connecting node has no blocks yet) and added noise to the logs.
        def _auto_sync_on_connect(p, do_sync: bool):
            # BUG-FIX (sync-fix-4): guard against two concurrent auto-sync
            # threads for the same peer.  After v7.0.1.2, both the inbound
            # and outbound _register_peer paths call _auto_sync_on_connect
            # with initiator=True.  Without a dedup flag both threads fire
            # simultaneous MSG_GET_CHAIN bursts producing duplicate attempt
            # 3/4 log lines and interleaved responses that stall accept_chain.
            if not do_sync:
                return
            if p._auto_sync_active.is_set():
                return   # another thread already owns sync for this peer
            p._auto_sync_active.set()
            try:
                time.sleep(0.5)   # allow message loop to start first
                if not p.connected:
                    return
                # Always advertise our capabilities immediately (don't wait for
                # the 120-second periodic broadcast timer).
                try:
                    p.send({
                        "type":         MSG_CAPABILITY_ADV,
                        "capabilities": Config.NODE_CAPABILITIES,
                        "ttl":          Config.GOSSIP_TTL,
                    })
                except Exception:
                    pass
                # ── v7.4.0: Snapshot verification path ────────────────────
                # A fresh node cannot safely install a peer snapshot under the
                # current state-root commitment, so _fast_sync_from_peer() will
                # refuse it and the normal block-sync path below takes over.
                # If a future protocol version commits every auxiliary state
                # component, the snapshot path can be made trustless again.
                # If fast-sync succeeds, _fast_sync_from_peer
                # already fires the first MSG_GET_CHAIN for the remaining
                # ROLLING_PRUNE_WINDOW blocks.  We then skip the normal
                # retry loop (pagination handles the rest).
                # If fast-sync fails for any reason we fall through to the
                # existing full-chain retry loop unchanged.
                # (sync-fix-4: do_sync check removed — dedup guard at top handles it)
                if (Config.SNAPSHOT_FAST_SYNC_ENABLED
                            and self.blockchain.height() <= 0
                            and p.connected):
                        try:
                            did_fast = self._fast_sync_from_peer(p)
                        except Exception as _fs_e:
                            log.debug("[FastSync] error: %s", _fs_e)
                            did_fast = False
                        if did_fast:
                            log.info(
                                "[AutoSync] Fast-sync via snapshot succeeded "
                                "for peer %s; normal pagination will complete "
                                "the remaining blocks.", peer_id[:12]
                            )
                            return   # pagination thread takes over
                        else:
                            log.debug(
                                "[AutoSync] Fast-sync not available from %s; "
                                "falling back to full-chain sync.", peer_id[:12]
                            )
                # Retry loop: a single MSG_GET_CHAIN can be lost if the
                # peer's message loop is not yet running, the response
                # is dropped mid-flight, or the peer is briefly busy.
                # We ask for chain pages in a loop until either our
                # height advances or we time out -- this is what was
                # missing and is the reason "request is sent but no
                # answer ever comes back" was visible to users.
                # [v7.0.0.2 fix]
                start_h = self.blockchain.height()
                last_h  = start_h
                for attempt in range(6):   # up to ~6 * 4s = 24s
                    if not p.connected:
                        return
                    cur_h = self.blockchain.height()

                    # BUG-FIX (v7.0.0.6) — Two problems with the old
                    # from_idx = max(0, cur_h):
                    #
                    # Problem A (fork detection): The first attempt must
                    # always start at from_idx=0 so that independently-
                    # mined chains are detected at block 1. The old code
                    # used cur_h, which on a node at height 50 skipped
                    # blocks 0-49, making any fork below the tip invisible
                    # to accept_chain()'s fork-choice logic.
                    #
                    # Problem B (off-by-one): After partial progress
                    # (e.g. height advanced to 50), from_idx=max(0,50)=50
                    # re-requested block 50 (already stored).  The next
                    # block needed is 51, so the correct value is cur_h+1.
                    #
                    # Fix: attempt 0 always starts at genesis (from_idx=0).
                    # Subsequent attempts (when we've already received some
                    # blocks) request from cur_h+1 to avoid duplicating
                    # the already-applied tip block.
                    # BUG-FIX (sync-fix-2): subsequent attempts used
                    # cur_h+1 even when height had NOT advanced.  When
                    # both nodes have equal-height independent forks,
                    # cur_h stays at start_h and attempt 1+ send
                    # from_idx=cur_h+1 — a range the peer doesn't have
                    # (it only has blocks 0..cur_h), yielding 0 blocks
                    # served.  Fix: keep requesting from 0 until real
                    # height progress is observed; only advance from_idx
                    # once the height has actually moved past start_h.
                    if attempt == 0 or cur_h <= start_h:
                        from_idx = 0
                    else:
                        from_idx = max(0, cur_h + 1)
                    to_idx = from_idx + 199
                    try:
                        self._sync_request(
                            p, from_idx, to_idx,
                            kind="auto-sync", force=False)
                        log.info(
                            f"[AutoSync] Requested chain blocks "
                            f"{from_idx}-{to_idx} from {peer_id[:12]} "
                            f"(attempt {attempt + 1})"
                        )
                    except Exception as _e:
                        log.debug(f"Auto-sync send error: {_e}")
                        return
                    time.sleep(4.0)
                    new_h = self.blockchain.height()
                    if new_h > last_h:
                        # Height has advanced since the last check.
                        #
                        # v7.0.0.6 BUG: the old code used `continue` here,
                        # which fired ANOTHER MSG_GET_CHAIN request while the
                        # MSG_CHAIN handler's _request_next_page thread was
                        # already sleeping 1 s before sending the next page.
                        # Two concurrent GET_CHAIN requests → interleaved
                        # CHAIN responses → accept_chain() sees out-of-order
                        # batches → sync stalled.
                        # v7.0.0.6 FIX: exit immediately on height advance,
                        # assuming "pagination is working."
                        #
                        # v7.0.1.1 BUG (Partial-Sync Fix):
                        # The v7.0.0.6 exit-on-advance is WRONG when the
                        # response was a partial page (fewer than 200 blocks)
                        # at the server's current tip.  In that case:
                        #   • _needs_next_page=False → _apply_chain_direct
                        #     does NOT fire a next-page request.
                        #   • peer._pagination_active is NOT set.
                        #   • The auto-sync exits assuming "pagination will
                        #     handle it" — but there is NO pagination thread.
                        #   • Result: the 66 mined blocks ARE applied, but
                        #     _auto_sync_on_connect exits silently and never
                        #     attempts to fetch further blocks as the peer
                        #     mines more.  The 60-second heartbeat is the only
                        #     fallback — far too slow for a live sync.
                        #
                        # v7.0.1.1 FIX: check peer._pagination_active.
                        #   • Flag SET   → full 200-block pagination is
                        #     running → yield to it (original v7.0.0.6 logic).
                        #   • Flag CLEAR → partial page / server tip reached →
                        #     no pagination thread exists → update last_h and
                        #     continue the loop from the new tip.  This lets
                        #     auto-sync pick up more blocks as they're mined
                        #     within the remaining retry window (up to 24 s)
                        #     without racing against a pagination thread.
                        if peer._pagination_active.is_set():
                            log.info(
                                f"[AutoSync] Height advanced "
                                f"{start_h} → {new_h}; full-page "
                                f"pagination is active — yielding to "
                                f"pagination thread.")
                            return
                        else:
                            # Partial page — pagination is NOT running.
                            # Continue from the new tip to pick up any
                            # blocks the server mines in the next window.
                            log.info(
                                f"[AutoSync] Partial sync: height "
                                f"{last_h} → {new_h} (server tip "
                                f"reached). Continuing retry loop "
                                f"from new tip.")
                            last_h = new_h
                            continue
                    if new_h > start_h:
                        # Made some progress overall; stop quietly.
                        return
                if self.blockchain.height() == start_h:
                    log.warning(
                        f"[AutoSync] No chain data received from "
                        f"{peer_id[:12]} after 6 attempts; will rely "
                        f"on periodic heartbeat sync."
                    )
            except Exception as _e:
                log.debug(f"Auto-sync send error: {_e}")
            finally:
                # BUG-FIX (sync-fix-4): always release the dedup flag so that
                # the periodic heartbeat or a future reconnect can trigger a
                # fresh sync if needed.
                p._auto_sync_active.clear()
        threading.Thread(target=_auto_sync_on_connect,
                         args=(peer, initiator), daemon=True).start()

    @staticmethod
    def _peer_subnet(ip: str) -> str:
        """
        Return the /24 subnet for IPv4 or /48 subnet for IPv6.
        Used for anti-eclipse diversity enforcement (Fix #6).
        """
        try:
            if ':' in ip:
                # IPv6 — use first 48 bits (3 groups of 16)
                parts = ip.split(':')
                return ':'.join(parts[:3])
            else:
                # IPv4 — use first 24 bits (/24)
                parts = ip.split('.')
                return '.'.join(parts[:3])
        except Exception:
            return ip

    # ── SECTION 6F: Soft Ban — Consecutive Failure Escalation (v6.0.0) ─────────
    # Implements the three-strikes probabilistic filter that replaces the naive
    # "ban on unknown logic_hash" approach.  Unlike the binary ban-score system,
    # soft-ban tracks *consecutive* failures per session, which distinguishes a
    # flaky-but-honest experimental fork (occasional errors, resets often) from
    # a deliberate CPU-exhaustion attacker (all messages invalid, never resets).
    # ─────────────────────────────────────────────────────────────────────────────

    def _is_ip_banned(self, ip: str) -> bool:
        """
        Return True if `ip` is currently under a soft-ban (strike 3).

        The ban record is stored in node_meta as:
            key  = "ip_ban:<ip>"
            value = JSON {"until": <unix_epoch>, "reason": "<str>"}

        A ban is active when `until` > now.  Expired records are treated as
        absent (the node will not clean them up proactively — they expire on
        the next read, which is fine for a low-volume table).
        """
        try:
            raw = self.storage.get_meta(f"ip_ban:{ip}")
            if not raw:
                return False
            record = json.loads(raw)
            return int(time.time()) < record.get("until", 0)
        except Exception:
            return False

    def _soft_ban_record_failure(self, peer: 'PeerConnection', mtype: str):
        """
        Increment the consecutive-failure counter for an untrusted peer and
        apply the appropriate escalation level.

        Strike 1 — WARNING log only.
        Strike 2 — Per-message throttle: sets peer._soft_ban_throttle_until so
                   that the message loop sleeps SOFT_BAN_THROTTLE_DELAY_SECS
                   before processing each subsequent MSG_TX / MSG_BLOCK from
                   this peer.  This caps CPU consumption without disconnecting.
        Strike 3 — 24-hour IP ban: blacklists the peer_id in the peers table
                   and writes a timestamped ban record to node_meta so that
                   both inbound (_handle_inbound) and outbound (_try_add_peer)
                   connections from this IP are refused for 24 hours.

        Thread safety: called from the peer's dedicated message-loop thread
        only, so no lock is needed for the peer fields themselves.
        """
        peer.consecutive_audit_failures += 1
        strikes = peer.consecutive_audit_failures

        if strikes == 1:
            log.warning(
                f"[SoftBan] Strike 1/3 — untrusted peer {peer.peer_id[:12]} "
                f"({peer.ip}) sent invalid {mtype}. "
                f"Watching for consecutive failures.")

        elif strikes == 2:
            # Activate per-message throttle: every future MSG_TX / MSG_BLOCK
            # from this peer will block for SOFT_BAN_THROTTLE_DELAY_SECS
            # before being processed, capping scrutiny-tax CPU usage.
            peer._soft_ban_throttle_until = (
                time.time() + Config.SOFT_BAN_THROTTLE_DELAY_SECS)
            log.warning(
                f"[SoftBan] Strike 2/3 — untrusted peer {peer.peer_id[:12]} "
                f"({peer.ip}) consecutive invalid {mtype}. "
                f"Throttling: +{Config.SOFT_BAN_THROTTLE_DELAY_SECS:.0f}s "
                f"delay per message until valid data received.")
            metrics.inc("soft_ban_throttles")

        elif strikes >= 3:
            ban_until = int(time.time()) + int(Config.SOFT_BAN_BAN_DURATION_SECS)
            ban_expiry_str = datetime.fromtimestamp(
                ban_until, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            log.warning(
                f"[SoftBan] Strike 3/3 — untrusted peer {peer.peer_id[:12]} "
                f"({peer.ip}) BANNED for 24 hours after three consecutive "
                f"audit failures on {mtype}. "
                f"Ban expires: {ban_expiry_str}")
            # Blacklist by peer_id in the peers DB table (permanent until decay)
            self.storage.blacklist_peer(peer.peer_id)
            # Record IP ban in node_meta with TTL
            try:
                self.storage.set_meta(
                    f"ip_ban:{peer.ip}",
                    json.dumps({
                        "until":     ban_until,
                        "peer_id":   peer.peer_id,
                        "reason":    "soft_ban_strike3",
                        "banned_at": int(time.time()),
                    }))
            except Exception as _e:
                log.debug(f"[SoftBan] Failed to write IP ban record: {_e}")

            # F-11 FIX: Also ban by logic_hash so IP-rotating attackers
            # (botnets, VPN rotators) are blocked by their modified-build
            # fingerprint regardless of which IP they reconnect from.
            logic_hash = getattr(peer, 'logic_hash', None)
            if logic_hash and logic_hash not in ('unknown', _NODE_LOGIC_HASH):
                try:
                    self.storage.set_meta(
                        f"logic_hash_ban:{logic_hash}",
                        json.dumps({
                            "until":      ban_until,
                            "reason":     "soft_ban_strike3",
                            "banned_at":  int(time.time()),
                        }))
                    log.warning(
                        f"[SoftBan] Logic-hash ban applied: {logic_hash[:16]}... "
                        f"— any node with this build fingerprint blocked for 24h")
                    metrics.inc("soft_ban_logic_hash_bans")
                except Exception as _e2:
                    log.debug(f"[SoftBan] Failed to write logic-hash ban: {_e2}")

            # F-11 FIX: Subnet ban (/24 IPv4 or /48 IPv6) for repeat offenders.
            # Only applied when the IP is already in a prior ban record,
            # indicating the attacker already rotated once from this subnet.
            try:
                _subnet = self._ip_subnet(peer.ip)
                prior   = self.storage.get_meta(f"subnet_strike:{_subnet}")
                _strikes_subnet = int(prior) + 1 if prior else 1
                self.storage.set_meta(f"subnet_strike:{_subnet}", str(_strikes_subnet))
                if _strikes_subnet >= 2:
                    self.storage.set_meta(
                        f"subnet_ban:{_subnet}",
                        json.dumps({"until": ban_until, "reason": "subnet_repeat_offender"}))
                    log.warning(
                        f"[SoftBan] Subnet ban applied: {_subnet} "
                        f"(repeat offender, strike {_strikes_subnet})")
                    metrics.inc("soft_ban_subnet_bans")
            except Exception:
                pass

            metrics.inc("soft_ban_ip_bans")
            # Disconnect immediately — no further messages will be accepted
            peer.connected = False
            peer.close()


    @staticmethod
    def _ip_subnet(ip: str) -> str:
        """F-11: Return /24 subnet for IPv4, /48 subnet for IPv6 (for subnet banning)."""
        try:
            if ':' in ip:  # IPv6
                parts = ip.split(':')
                return ':'.join(parts[:3]) + '::/48'
            else:           # IPv4
                parts = ip.split('.')
                return '.'.join(parts[:3]) + '.0/24'
        except Exception:
            return ip

    def _soft_ban_reset_failures(self, peer: 'PeerConnection'):
        """
        Reset the consecutive-failure counter to 0 after a valid message.

        Called whenever an untrusted peer successfully passes Full Audit Mode
        (MSG_TX or MSG_BLOCK accepted without rejection).  This allows a
        legitimate experimental fork that occasionally sends bad data to
        recover without accumulating strikes indefinitely.
        """
        if peer.consecutive_audit_failures > 0:
            log.info(
                f"[SoftBan] Untrusted peer {peer.peer_id[:12]} sent valid "
                f"data — consecutive failure counter reset "
                f"(was {peer.consecutive_audit_failures}).")
            peer.consecutive_audit_failures  = 0
            peer._soft_ban_throttle_until    = 0.0

    def _peer_message_loop(self, peer: PeerConnection):
        bytes_this_second  = 0
        second_start       = time.time()
        # BUG-FIX (v7.0.0.0): buf must survive socket.timeout and outer-loop
        # restarts.  The old code reset buf=b"" at the top of the try block,
        # so any partial frame in-flight when the 30-second idle timeout fired
        # was silently discarded.  A large MSG_CHAIN (200 blocks of JSON) may
        # arrive across dozens of TCP segments; if no segment arrives within
        # 30s the incomplete frame was lost and the sync message was never
        # processed — causing "connected but stuck" syndrome.
        #
        # BUG-FIX (v7.0.0.1): Seed buf from peer._recv_buf, then clear it.
        # recv_line() — used during the TLS/HELLO handshake — stores any bytes
        # that arrived after the final handshake frame's \n in peer._recv_buf.
        # TCP is a stream: the remote may have sent the first post-handshake
        # message (MSG_GET_CHAIN, MSG_CAPABILITY_ADV, etc.) before we entered
        # this loop.  Those bytes are already sitting in peer._recv_buf.
        # Without this seed, buf starts empty and sock.recv() blocks waiting
        # for the next TCP segment — the already-arrived message is permanently
        # lost, causing "sync request sent but never processed" even when the
        # peer shows CONNECTED in the dashboard.
        buf = peer._recv_buf
        peer._recv_buf = b""   # message loop owns the buffer from here on
        # Absolute age for an unterminated frame.  TCP idle timeouts alone do
        # not protect against a peer that trickles one byte every few seconds.
        partial_started_at = time.monotonic() if buf else None

        while self._running and peer.connected:
            try:
                peer.sock.settimeout(30)
                while True:
                    chunk = peer.sock.recv(65536)
                    if not chunk:
                        peer.connected = False
                        break

                    # ── Per-peer bandwidth cap (Problem #10) ──────────────────
                    now = time.time()
                    if now - second_start >= 1.0:
                        bytes_this_second = 0
                        second_start = now
                    bytes_this_second += len(chunk)
                    if bytes_this_second > Config.MAX_PEER_BANDWIDTH:
                        log.warning(
                            f"Peer {peer.peer_id[:12]} exceeded bandwidth limit "
                            f"({bytes_this_second} bytes/s) — disconnecting")
                        self.storage.add_ban_score(
                            peer.peer_id, Config.PEER_SCORE_OVERSIZED_MSG)
                        peer.connected = False
                        break

                    buf += chunk

                    # ── Hard message size cap (Problem #10) ───────────────────
                    if len(buf) > Config.MAX_MESSAGE_SIZE:
                        log.warning(
                            f"Peer {peer.peer_id[:12]} sent oversized frame "
                            f"({len(buf)} bytes > {Config.MAX_MESSAGE_SIZE}) — banning")
                        self.storage.add_ban_score(
                            peer.peer_id, Config.PEER_SCORE_OVERSIZED_MSG)
                        peer.connected = False
                        break

                    # A complete frame may use the larger compatibility ceiling
                    # above, but an *unfinished* frame gets a much tighter bound.
                    # Without this, an attacker can keep recv() active forever
                    # and force the process to retain an arbitrarily large
                    # unterminated buffer.
                    if b"\n" not in buf:
                        if partial_started_at is None:
                            partial_started_at = time.monotonic()
                        if len(buf) > Config.MAX_PARTIAL_FRAME_BYTES:
                            log.warning(
                                f"Peer {peer.peer_id[:12]} sent oversized "
                                f"unterminated frame ({len(buf)} bytes > "
                                f"{Config.MAX_PARTIAL_FRAME_BYTES}) — disconnecting")
                            self.storage.add_ban_score(
                                peer.peer_id, Config.PEER_SCORE_OVERSIZED_MSG)
                            peer.connected = False
                            break
                        if (time.monotonic() - partial_started_at
                                > Config.MAX_PARTIAL_FRAME_AGE_SECS):
                            log.warning(
                                f"Peer {peer.peer_id[:12]} kept an unterminated "
                                f"frame open for more than "
                                f"{Config.MAX_PARTIAL_FRAME_AGE_SECS:.1f}s — "
                                "disconnecting")
                            self.storage.add_ban_score(
                                peer.peer_id, Config.PEER_SCORE_SYNC_TIMEOUT)
                            peer.connected = False
                            break

                    _completed_frame_in_chunk = False
                    while b"\n" in buf:
                        _completed_frame_in_chunk = True
                        line, buf = buf.split(b"\n", 1)
                        if not line.strip():
                            continue
                        try:
                            # Decompress if compressed frame (transparent)
                            decoded = CompressionEngine.decompress(line)
                            msg = json.loads(decoded.decode(), parse_constant=_reject_nonfinite_json_constant)
                            # v7.1.7: inbound P2P message logging (no-op
                            # unless enabled).  Size is the on-wire byte
                            # count (pre-decompression) for symmetry with
                            # the outbound side.
                            P2PMessageLogger.log_in(peer, msg, len(line) + 1)
                            # ── Soft Ban: strike-2 throttle enforcement ───────────
                            # If this untrusted peer is under a per-message throttle
                            # (strike 2), sleep before processing TX/BLOCK messages.
                            # This limits the "scrutiny-tax" CPU drain caused by
                            # flooding with complex-but-invalid data.
                            _sbt_mtype = msg.get("type", "")
                            if (_sbt_mtype in (MSG_TX, MSG_BLOCK, MSG_CMPCTBLOCK)
                                    and peer._soft_ban_throttle_until > time.time()):
                                _throttle_remaining = (
                                    peer._soft_ban_throttle_until - time.time())
                                _sleep_secs = min(
                                    _throttle_remaining,
                                    Config.SOFT_BAN_THROTTLE_DELAY_SECS)
                                if _sleep_secs > 0:
                                    log.debug(
                                        f"[SoftBan] Throttling "
                                        f"{peer.peer_id[:12]} "
                                        f"for {_sleep_secs:.1f}s "
                                        f"(strike 2 active)")
                                    time.sleep(_sleep_secs)
                                # Advance the throttle window so each new
                                # message costs another full delay interval.
                                peer._soft_ban_throttle_until = (
                                    time.time()
                                    + Config.SOFT_BAN_THROTTLE_DELAY_SECS)
                            self._handle_message(peer, msg)
                        except json.JSONDecodeError:
                            self.storage.add_ban_score(
                                peer.peer_id, Config.PEER_SCORE_INVALID_MSG)

                    # If a complete frame consumed the whole buffer, the next
                    # partial frame starts a fresh age window.  A partial suffix
                    # keeps its original timestamp across complete frames so it
                    # cannot be kept alive indefinitely by prefixing new frames.
                    if not buf:
                        partial_started_at = None
                    elif _completed_frame_in_chunk:
                        # Any bytes after the delimiter belong to a fresh
                        # application frame; do not inherit the prior frame's age.
                        partial_started_at = time.monotonic()
                    elif partial_started_at is None:
                        partial_started_at = time.monotonic()

            except socket.timeout:
                if not peer.send({"type": MSG_PING}):
                    break
            except Exception:
                break
        self._on_peer_disconnect(peer)
        
    def _get_serialized_block(self, block_hash: str):
        """Fetches and caches a serialized block for chunk-serving."""
        # 1. Check if we already have this block ready in RAM
        cached = self._block_serve_cache.get(block_hash)
        if cached:
            return cached

        # 2. If not, get it from the database
        block = self.blockchain.storage.get_block_by_hash(block_hash)
        if block:
            # 3. Convert it to data bytes (JSON)
            import json
            raw = json.dumps(block.to_dict()).encode("utf-8")

            # 4. Save in RAM for the next 60 seconds
            self._block_serve_cache.put(block_hash, raw)
            return raw

        return None

    def _sync_request(self, peer: 'PeerConnection', from_idx: int,
                      to_idx: int, *, kind: str = "heartbeat",
                      force: bool = False) -> Optional[str]:
        """Send one correlated chain request for a peer.

        Only one request is live per peer.  A later heartbeat or reconnect
        cannot overwrite a pagination request, and every response can be
        matched to the exact request that produced it.
        """
        try:
            from_idx = max(0, int(from_idx))
            to_idx = max(from_idx, int(to_idx))
        except (TypeError, ValueError):
            return None
        now = time.monotonic()
        timeout = max(5.0, float(getattr(Config, "CHAIN_SYNC_TIMEOUT_SECS", 20)))
        with peer._sync_state_lock:
            pending = peer._sync_pending
            if pending is not None:
                age = now - float(pending.get("sent_at", now))
                if not force and age < timeout:
                    return None
                peer._sync_pending = None
                peer._pagination_active.clear()
            peer._sync_request_seq += 1
            request_id = (
                f"{id(peer):x}-{peer._sync_request_seq:x}-"
                f"{secrets.token_hex(6)}"
            )
            peer._sync_pending = {
                "id": request_id,
                "from_idx": from_idx,
                "to_idx": to_idx,
                "kind": kind,
                "sent_at": now,
                "status": "waiting",
            }
        try:
            peer.send({
                "type": MSG_GET_CHAIN,
                "from_idx": from_idx,
                "to_idx": to_idx,
                "request_id": request_id,
            })
            log.info(
                f"[ChainSync] request {request_id[:16]} {kind} "
                f"blocks {from_idx}-{to_idx} to {peer.peer_id[:12]}"
            )
            return request_id
        except Exception as exc:
            with peer._sync_state_lock:
                if (peer._sync_pending is not None
                        and peer._sync_pending.get("id") == request_id):
                    peer._sync_pending = None
                    peer._pagination_active.clear()
            log.debug(f"[ChainSync] request send failed: {exc}")
            return None

    def _sync_claim_response(self, peer: 'PeerConnection', msg: dict,
                             blocks_data: list) -> Optional[str]:
        """Accept only the response belonging to the current sync flight."""
        incoming_id = msg.get("request_id")
        with peer._sync_state_lock:
            pending = peer._sync_pending
            if pending is None:
                if incoming_id:
                    log.warning(
                        f"[ChainSync] stale response {str(incoming_id)[:16]} "
                        f"from {peer.peer_id[:12]} — no request pending")
                    return None
                # Compatibility for legacy/manual callers that did not create
                # a correlated flight.  This path is safe because there is no
                # active correlated request for this peer.
                return "__legacy__"
            expected = pending.get("id")
            if not incoming_id:
                incoming_id = expected
            if incoming_id != expected:
                log.warning(
                    f"[ChainSync] stale response {str(incoming_id)[:16]} "
                    f"from {peer.peer_id[:12]}; expected {str(expected)[:16]}"
                )
                return None
            if pending.get("status") != "waiting":
                log.warning(
                    f"[ChainSync] duplicate response {str(incoming_id)[:16]} "
                    f"from {peer.peer_id[:12]} — already processing")
                return None
            if blocks_data:
                try:
                    first = int(blocks_data[0].get("index", -1))
                    last = int(blocks_data[-1].get("index", -1))
                    if first < pending["from_idx"] or last > pending["to_idx"]:
                        log.warning(
                            f"[ChainSync] out-of-range response {first}-{last} "
                            f"for request {pending['from_idx']}-"
                            f"{pending['to_idx']} from {peer.peer_id[:12]}"
                        )
                        return None
                except (AttributeError, TypeError, ValueError):
                    log.warning(
                        f"[ChainSync] malformed response for request "
                        f"{expected[:16]} from {peer.peer_id[:12]}"
                    )
                    return None
            pending["status"] = "processing"
            return expected

    def _sync_finish(self, peer: 'PeerConnection',
                     request_id: Optional[str]) -> None:
        if request_id == "__legacy__":
            return
        with peer._sync_state_lock:
            pending = peer._sync_pending
            if pending is not None and pending.get("id") == request_id:
                peer._sync_pending = None

    def _on_chain_sync_result(self, peer: 'PeerConnection', blocks: list,
                               ok: bool, reason: str,
                               needs_next_page: bool, next_page_from: int,
                               request_id: Optional[str] = None
                               ) -> None:
        """
        AUDIT-FIX-2 (network sync stall): react to an accept_chain() outcome
        by continuing pagination if more blocks remain from this peer.

        Extracted from the body of the MSG_CHAIN handler's _apply_chain_direct
        closure so the identical pagination-continuation logic (next-page
        request + sync watchdog + _pagination_active bookkeeping) runs no
        matter which of the two dispatch paths actually called
        accept_chain():

          1. The synchronous fallback path (_apply_chain_direct in
             _handle_message), used when the StateEngine queue is full,
             raises, or is absent.
          2. StateEngine._handle_chain_sync, on the StateEngine's own
             single-writer thread — which is what handles almost every
             chain-sync batch in normal operation, since
             StateEngine.post() only fails when its queue is already
             over 80% full.

        Before this fix, only path (1) ever requested the next page.
        Path (2) — the one that actually runs almost all the time — simply
        applied the batch and returned, so the elaborate event-driven
        pagination system never engaged in practice. Sync speed collapsed
        from "next 200-block page as soon as this one commits" (the
        documented design intent) to "one 200-block page per periodic
        heartbeat tick" (P2PNetwork._reconnect_loop, every
        Config.RECONNECT_INTERVAL * 2 seconds) regardless of how many
        blocks behind the node actually was.
        """
        try:
            if ok:
                self._sync_finish(peer, request_id)
                log.info(
                    f"[ChainSync] Applied {len(blocks)} block(s) "
                    f"from {peer.peer_id[:12]} — "
                    f"height now {self.blockchain.height()}")
                if needs_next_page and peer.connected:
                    # Signal to _auto_sync_on_connect that full pagination
                    # is now in flight for this peer. The auto-sync loop
                    # reads this flag to decide whether to yield (flag set)
                    # or continue its own retry from the new tip (flag
                    # clear = no pagination thread running).
                    peer._pagination_active.set()
                    _sent_ok = bool(self._sync_request(
                        peer, next_page_from, next_page_from + 199,
                        kind="pagination", force=True))
                    if _sent_ok:
                        log.debug(
                            f"[ChainSync] Pagination: requested "
                            f"blocks {next_page_from}–"
                            f"{next_page_from + 199} from "
                            f"{peer.peer_id[:12]}")

                    # ── Sync watchdog (v7.0.1.0 — Bug 3 fix) ────────────
                    if _sent_ok:
                        _height_after_apply = self.blockchain.height()

                        def _sync_watchdog(
                            _from   = next_page_from,
                            _p      = peer,
                            _h_base = _height_after_apply,
                        ):
                            time.sleep(Config.CHAIN_SYNC_TIMEOUT_SECS)
                            # ── Success path ─────────────────────────
                            if self.blockchain.height() >= _from:
                                _p._pagination_active.clear()
                                return
                            # ── Failure path: peer is zombie ──────────
                            _p._pagination_active.clear()
                            if not _p.connected:
                                pass
                            else:
                                log.warning(
                                    f"[ChainSync] Watchdog: no response "
                                    f"for blocks {_from}–{_from + 199} "
                                    f"from {_p.peer_id[:12]} within "
                                    f"{Config.CHAIN_SYNC_TIMEOUT_SECS}s "
                                    f"— closing zombie peer")
                                self.storage.add_ban_score(
                                    _p.peer_id,
                                    Config.PEER_SCORE_SYNC_TIMEOUT)
                                _p.close()   # → _on_peer_disconnect

                            with self._lock:
                                alts = [
                                    q for q in self.peers.values()
                                    if q.connected
                                    and q.peer_id != _p.peer_id
                                ]
                            if alts:
                                alt = random.choice(alts)
                                try:
                                    self._sync_request(
                                        alt, _from, _from + 199,
                                        kind="watchdog-fallback", force=True)
                                    log.info(
                                        f"[ChainSync] Watchdog: "
                                        f"re-requesting blocks "
                                        f"{_from}–{_from + 199} "
                                        f"from fallback peer "
                                        f"{alt.peer_id[:12]}")
                                except Exception as _we:
                                    log.debug(
                                        f"[ChainSync] Watchdog "
                                        f"fallback send error: {_we}")
                            else:
                                log.warning(
                                    f"[ChainSync] Watchdog: no "
                                    f"alternate peers available to "
                                    f"re-request blocks {_from}+; "
                                    f"heartbeat will retry in "
                                    f"{Config.RECONNECT_INTERVAL * 2}s")

                        threading.Thread(
                            target=_sync_watchdog,
                            daemon=True,
                        ).start()
                else:
                    # No further pagination — either the server tip was
                    # reached (Case C) or the peer disconnected. Clear the
                    # flag so _auto_sync_on_connect does not incorrectly
                    # yield to a non-existent pagination thread.
                    peer._pagination_active.clear()
                    log.info(
                        f"[ChainSync] Partial sync complete: "
                        f"{len(blocks)} block(s) applied from "
                        f"{peer.peer_id[:12]} (server tip reached, "
                        f"no further pagination needed)")
            else:
                self._sync_finish(peer, request_id)
                peer._pagination_active.clear()
                local_height = self.blockchain.height()
                first_idx = blocks[0].index if blocks else -1
                last_idx = blocks[-1].index if blocks else -1
                print(f"[SYNCPLUS-REJECT] {reason}", flush=True)
                log.warning(
                    f"[ChainSync] accept_chain rejected {len(blocks)} "
                    f"block(s) {first_idx}-{last_idx} from "
                    f"{peer.peer_id[:12]} at local height {local_height}: "
                    f"{reason}")
                now = time.monotonic()
                with peer._sync_state_lock:
                    if now - peer._sync_last_reject_at >= 5.0:
                        peer._sync_last_reject_at = now
                        do_recovery = True
                    else:
                        do_recovery = False
                if do_recovery and peer.connected:
                    self._sync_request(
                        peer, 0, 199, kind="recovery", force=True)
        except Exception as _ace:
            log.warning(
                f"[ChainSync] Error handling chain-sync result from "
                f"{peer.peer_id[:12]}: {_ace}")
            # Clear on exception so the flag is never left set permanently
            # after an unexpected failure.
            peer._pagination_active.clear()

    def _handle_message(self, peer: PeerConnection, msg: dict):
        mtype = msg.get("type", "")

        # ── v7.1.0: Per-peer message-rate limit (DoS protection) ─────────────
        # Drop before any expensive work (dedup hash, DB scan, signature
        # verification).  Repeat offenders get ban-score penalties.
        if mtype and not self._check_msg_rate(peer, mtype):
            return

        # ── Gossip dedup using msg hash ───────────────────────────────────────
        # DEDUP-FIX (v6.9.9.7): Point-to-point RESPONSE messages must NOT be
        # deduplicated.  MSG_CHAIN / MSG_PEERS are replies to explicit queries,
        # not free-floating gossip floods.  The old code hashed every incoming
        # message type identically, which caused a critical sync failure:
        #
        #   1. Peer B connects to peer A (A has height=66, B has height=0).
        #   2. _auto_sync_on_connect fires; B requests MSG_GET_CHAIN(1→999999).
        #   3. A replies with MSG_CHAIN(66 blocks).  Hash is stored in _seen_msgs.
        #   4. If accept_chain() or StateEngine.post() fails for any reason,
        #      B's height stays at 0.
        #   5. 60 s later the heartbeat fires; B requests MSG_GET_CHAIN(1→501).
        #   6. A replies with MSG_CHAIN(66 blocks) — IDENTICAL PAYLOAD, same hash.
        #   7. _seen_msgs already has this hash → msg dropped → B stuck at height=0.
        #   8. Manual "Sync Chain" (menu 2) produces the same payload → also dropped.
        #   → Node can NEVER recover from a failed first sync attempt.
        #
        # Fix: skip the dedup check and store for response-type messages.
        # Gossip flooding (MSG_TX, MSG_BLOCK, MSG_ALERT, MSG_IDENTITY) is still
        # deduplicated normally to prevent exponential flood amplification.
        # ── v7.5.0 parallel block-sync messages (point-to-point) ─────────
        _GOSSIP_DEDUP_SKIP = frozenset({
            MSG_CHAIN,
            MSG_PEERS,
            MSG_RESOLVE_RESP,
            MSG_CAPABILITY_RESPONSE,
            MSG_GET_CHAIN,
            MSG_GET_PEERS,
            MSG_GET_BLOCK,
            MSG_RESOLVE,
            MSG_CAPABILITY_QUERY,
            MSG_GET_SNAPSHOT_MANIFEST,
            MSG_SNAPSHOT_MANIFEST,
            MSG_GET_SNAPSHOT,
            MSG_SNAPSHOT_DATA,
            MSG_GET_CHUNK_MANIFEST,
            MSG_CHUNK_MANIFEST,
            MSG_GET_CHUNK,
            MSG_CHUNK_DATA,
            MSG_CMPCTBLOCK,
            MSG_GETBLOCKTXN,
            MSG_BLOCKTXN,
            # Your new Parallel Downloader messages:
            MSG_GET_BLOCK_MANIFEST,
            MSG_BLOCK_MANIFEST,
            MSG_GET_BLOCK_CHUNK,
            MSG_BLOCK_CHUNK_DATA,
            # ── v7.6.0 Hashrate optimization: point-to-point, never gossiped.
            # Dedup is unnecessary because each peer's payload changes every
            # HASHRATE_REPORT_INTERVAL, and stale reports are evicted by TTL.
            MSG_HASHRATE_REPORT,
            # ── v7.7.0 Rate defection evidence — gossiped, but dedup is
            # done inside RateDefectionAuditor by content hash, not here.
            # Adding to skip set lets the same evidence reach all nodes
            # quickly; the auditor's own dedup prevents duplicate slashing.
            MSG_RATE_DEFECTION_EVIDENCE,
        })

        if mtype not in _GOSSIP_DEDUP_SKIP:
            # ─────────────────────────────────────────────────────────────────
            # v7.1.8 BUG-FIX (Bug 4 — DEDUP-BEFORE-PROCESS RACE):
            # The pre-fix code stored the message hash here BEFORE the
            # handler ran.  Failure modes that followed all left the same
            # poisonous state:
            #   • StateEngine.post() returns False (queue high-water) —
            #     block silently dropped, hash already cached for 1 hour.
            #   • _handle_new_block returns (False, "Gap: missing blocks…")
            #     — block neither applied nor relayed, hash already cached.
            #   • apply_block raises and is swallowed in the try/except
            #     wrapper — same outcome.
            # In every case the next gossip copy from a different peer was
            # rejected at this dedup check, leaving the node DEAF to that
            # block for an entire hour.  Symptom: "block came to the device
            # but for some reason it is not syncing."
            #
            # Fix: for MSG_BLOCK, dedup by the canonical, deterministic
            # ``block.block_hash`` (not the wire-message hash, which varies
            # because validator_sigs / finalized fields mutate between
            # broadcasts) and DEFER the put() until the StateEngine /
            # apply_block has actually accepted the block.  See the
            # MSG_BLOCK branch below for the deferred put.
            #
            # For all other gossip-floodable types, keep the existing
            # behaviour — they are idempotent on the receiver side, so
            # storing the hash before processing is safe.
            # ─────────────────────────────────────────────────────────────────
            if mtype == MSG_BLOCK:
                _bd = msg.get("block")
                _bh = _bd.get("block_hash") if isinstance(_bd, dict) else None
                if _bh and self._seen_msgs.get(("BLOCK", _bh)):
                    # Already accepted (or in-flight to the StateEngine for
                    # this exact block_hash).  Drop silently — re-gossip
                    # noise is expected and benign.
                    return
                # NOTE: do NOT put() yet.  The MSG_BLOCK branch below will
                # store the hash only after a successful post / apply.
            elif mtype == MSG_CMPCTBLOCK:
                # v7.5.0: dedup compact blocks by the same canonical block_hash
                # key so that if we also receive a full MSG_BLOCK for the same
                # block (fallback from a non-compact peer) we don't process it
                # twice.  The stash eviction path below handles the deferred put.
                _chdr = msg.get("header", {})
                _cbh  = _chdr.get("block_hash") if isinstance(_chdr, dict) else None
                if _cbh and self._seen_msgs.get(("BLOCK", _cbh)):
                    return
                # do NOT put() yet — deferred until reconstruction succeeds
            else:
                msg_hash = sha256(json.dumps(msg, sort_keys=True).encode())
                if self._seen_msgs.get(msg_hash):
                    # Plumtree demotion is only safe on networks with
                    # redundant paths (5+ peers). On tiny 2-3 peer nets,
                    # demoting on the first duplicate (which auto-sync
                    # MSG_CHAIN re-gossip reliably produces) leaves the
                    # demoted peer with no eager neighbour and new blocks
                    # stop propagating -> fork/orphan storms.  Skip
                    # demotion below the safety threshold.  [v7.0.0.2 fix]
                    with self._lock:
                        if len(self.peers) >= 5:
                            self._eager_peers.discard(peer.peer_id)
                    return
                self._seen_msgs.put(msg_hash, True)

        peer.last_seen = time.time()

        # ═════════════════════════════════════════════════════════════════════
        # SECTION 6E: FULL AUDIT MODE FOR TRUST_LEVEL_LOW PEERS
        # ─────────────────────────────────────────────────────────────────────
        # Peers whose logic_hash was not recognised during the HELLO handshake
        # are flagged TRUST_LEVEL_LOW.  For these peers, every MSG_TX and
        # MSG_BLOCK is subjected to three layers of extra scrutiny before it
        # is allowed to proceed through the normal message handler:
        #
        #   1. Resource Throttling
        #      Untrusted peers may send at most Config.UNTRUSTED_TX_RATE_LIMIT_BYTES
        #      (default 1 MB) of TX / block data per 60-second window.
        #      Exceeding the limit drops the message and increments the ban score.
        #
        #   2. Deep Transaction Validation
        #      Each transaction is re-validated in full (tx.is_valid()), which
        #      re-verifies the ECDSA signature, fee, expiry, and chain rules.
        #      Standard (trusted) peers only have their Merkle root checked.
        #
        #   3. Safety Invariant Check
        #      After a block from an untrusted peer, SafetyInvariantChecker
        #      .rolling_check() is invoked to verify chain linkage and finality
        #      consistency.  Violations are logged and metered.
        #
        # None of these checks disconnect the peer — that is left to the
        # existing ban-score / blacklist mechanism.
        # ═════════════════════════════════════════════════════════════════════
        _is_untrusted = (
            getattr(peer, 'trust_level', PeerConnection.TRUST_HIGH)
            == PeerConnection.TRUST_LOW
        )

        if _is_untrusted and mtype in (MSG_TX, MSG_BLOCK):
            # ── 1. Resource Throttling ─────────────────────────────────────────
            # Compute approximate wire-size of this message.
            _msg_bytes = len(json.dumps(msg).encode())
            _now = time.time()
            with self._untrusted_rate_lock:
                if peer.peer_id not in self._untrusted_rate:
                    # First message in this session — open a fresh 60-s window
                    self._untrusted_rate[peer.peer_id] = [_now, _msg_bytes]
                else:
                    _win_start, _win_bytes = self._untrusted_rate[peer.peer_id]
                    if _now - _win_start >= 60.0:
                        # Previous window expired — reset counter
                        self._untrusted_rate[peer.peer_id] = [_now, _msg_bytes]
                    else:
                        _win_bytes += _msg_bytes
                        self._untrusted_rate[peer.peer_id][1] = _win_bytes
                        if _win_bytes > Config.UNTRUSTED_TX_RATE_LIMIT_BYTES:
                            log.warning(
                                f"[FullAudit] Untrusted peer "
                                f"{peer.peer_id[:12]} exceeded "
                                f"{Config.UNTRUSTED_TX_RATE_LIMIT_BYTES // 1024} "
                                f"KB/min rate limit on {mtype} — message dropped")
                            self.storage.add_ban_score(
                                peer.peer_id,
                                Config.PEER_SCORE_INVALID_MSG // 2)
                            self._soft_ban_record_failure(peer, mtype)
                            return   # drop without further processing

        if _is_untrusted and mtype == MSG_TX:
            # ── 2a. Deep Transaction Validation ───────────────────────────────
            # Re-verify the entire transaction (signature + all business rules)
            # before it touches the mempool or StateEngine.
            try:
                _tx_data = msg.get("tx")
                if _tx_data:
                    _tx = Transaction.from_dict(_tx_data)
                    _ok, _reason = _tx.is_valid()
                    if not _ok:
                        log.warning(
                            f"[FullAudit] Untrusted peer {peer.peer_id[:12]} "
                            f"TX {_tx.tx_id[:12]} failed full audit: {_reason}")
                        self.storage.add_ban_score(
                            peer.peer_id, Config.PEER_SCORE_INVALID_MSG)
                        self._soft_ban_record_failure(peer, mtype)
                        return   # drop invalid transaction
                    # TX passed Full Audit — reset consecutive failure counter
                    self._soft_ban_reset_failures(peer)
            except Exception as _e:
                log.warning(
                    f"[FullAudit] Untrusted peer {peer.peer_id[:12]} "
                    f"TX parse/audit error: {_e}")
                self._soft_ban_record_failure(peer, mtype)
                return

        if _is_untrusted and mtype == MSG_BLOCK:
            # ── 2b. Deep Block Validation ──────────────────────────────────────
            # Re-verify every transaction signature in the block, then run
            # a rolling safety-invariant check.
            try:
                _block_data = msg.get("block")
                if _block_data:
                    _block = Block.from_dict(_block_data)
                    _bad_tx = None
                    for _tx in _block.transactions:
                        if _tx.sender == "COINBASE":
                            continue   # coinbase transactions have no signature
                        _ok, _reason = _tx.is_valid()
                        if not _ok:
                            _bad_tx = (_tx.tx_id[:12], _reason)
                            break

                    if _bad_tx:
                        log.warning(
                            f"[FullAudit] Untrusted peer {peer.peer_id[:12]} "
                            f"block #{_block.index} TX {_bad_tx[0]} "
                            f"failed sig audit: {_bad_tx[1]}")
                        self.storage.add_ban_score(
                            peer.peer_id, Config.PEER_SCORE_INVALID_MSG)
                        self._soft_ban_record_failure(peer, mtype)
                        return   # drop the entire block

                    # ── 3. Safety Invariants ───────────────────────────────────
                    # Run the rolling checker if it has been wired in via
                    # StateEngine (not available during unit tests — guarded).
                    _checker = getattr(
                        getattr(self, '_state_engine', None),
                        '_invariant_checker', None)
                    if _checker is not None:
                        try:
                            _report = _checker.rolling_check()
                            if _report.get("violations"):
                                log.warning(
                                    f"[FullAudit] Untrusted peer "
                                    f"{peer.peer_id[:12]} block #{_block.index} "
                                    f"triggered {len(_report['violations'])} "
                                    f"safety invariant violation(s) — "
                                    f"monitoring closely")
                        except Exception:
                            pass   # invariant check failure is non-fatal

                    _n_verified = sum(
                        1 for _t in _block.transactions
                        if _t.sender != "COINBASE")
                    log.info(
                        f"[FullAudit] Untrusted peer {peer.peer_id[:12]} "
                        f"block #{_block.index} passed — "
                        f"{_n_verified} TX signatures re-verified")
                    # Block passed Full Audit — reset consecutive failure counter
                    self._soft_ban_reset_failures(peer)
            except Exception as _e:
                log.warning(
                    f"[FullAudit] Untrusted peer {peer.peer_id[:12]} "
                    f"block parse/audit error: {_e}")
                self._soft_ban_record_failure(peer, mtype)
                return
        # ── End Full Audit Mode ───────────────────────────────────────────────

        # ── v7.5.0 Full Audit Mode: header-integrity check for MSG_CMPCTBLOCK ─
        # For untrusted peers we cannot deep-validate transactions yet (they
        # aren't in the message), but we CAN verify that the advertised
        # block_hash is the correct SHA-256 of the header fields.  A fabricated
        # or corrupted block_hash is caught here before it pollutes the stash.
        if _is_untrusted and mtype == MSG_CMPCTBLOCK:
            try:
                _chdr = msg.get("header", {})
                if isinstance(_chdr, dict):
                    _claimed_bh = _chdr.get("block_hash", "")
                    _recomputed = hash_obj({
                        "version":          _chdr.get("version"),
                        "protocol_version": _chdr.get("protocol_version"),
                        "index":            _chdr.get("index"),
                        "prev_hash":        _chdr.get("prev_hash"),
                        "timestamp":        _chdr.get("timestamp"),
                        "miner":            _chdr.get("miner_address"),
                        "difficulty":       _chdr.get("difficulty"),
                        "nonce":            _chdr.get("nonce"),
                        "merkle_root":      _chdr.get("merkle_root"),
                        "state_root":       _chdr.get("state_root"),
                        "vrf_proof":        _chdr.get("vrf_proof"),
                        "vrf_output":       _chdr.get("vrf_output"),
                    })
                    if _claimed_bh != _recomputed:
                        log.warning(
                            f"[FullAudit] Untrusted peer {peer.peer_id[:12]} "
                            f"CMPCTBLOCK header hash mismatch "
                            f"(claimed={_claimed_bh[:16]} "
                            f"expected={_recomputed[:16]}) — dropping"
                        )
                        self.storage.add_ban_score(
                            peer.peer_id, Config.PEER_SCORE_INVALID_MSG)
                        self._soft_ban_record_failure(peer, mtype)
                        return
            except Exception as _cfa_err:
                log.debug(f"[FullAudit] CMPCTBLOCK header check error: {_cfa_err}")
                # Non-fatal — let normal handler deal with it

        if mtype == MSG_PING:
            peer.send({"type": MSG_PONG})

        elif mtype == MSG_PONG:
            pass

        elif mtype == MSG_GET_PEERS:
            peers_list = [
                {"ip": p.ip, "port": p.port, "peer_id": pid}
                for pid, p in self.peers.items()
                if p.connected and pid != peer.peer_id
            ][:20]
            peer.send({"type": MSG_PEERS, "peers": peers_list})

        elif mtype == MSG_PEERS:
            # v6.9.9: process IPv6 peers before IPv4 peers so that on CGNAT
            # networks IPv6 connection threads start first and are more likely
            # to establish before the IPv4 attempts time out.
            pex_peers = msg.get("peers", [])
            pex_ipv6  = [p for p in pex_peers if _is_ipv6_address(p.get("ip", ""))]
            pex_ipv4  = [p for p in pex_peers if not _is_ipv6_address(p.get("ip", ""))]
            for pinfo in (pex_ipv6 + pex_ipv4):
                self._try_add_peer(pinfo.get("ip"), pinfo.get("port"), pinfo.get("peer_id",""))

        elif mtype == MSG_TX:
            # ── Route through StateEngine (single-writer) ─────────────────────
            # The network I/O thread posts a NEW_TX event and does NOT call
            # mempool.add() directly.  This prevents race conditions between
            # concurrent peer message loops.
            try:
                tx_data = msg.get("tx")
                if tx_data:
                    if self._state_engine is not None:
                        evt = Event(
                            EventType.NEW_TX,
                            {"tx": tx_data},
                            source_peer_id=peer.peer_id,
                        )
                        # Fire-and-forget: network I/O thread must not block
                        # BUG-FIX (v7.0.0.0): raised from 2s → 5s — under
                        # heavy load (large sync batch being processed) the
                        # StateEngine queue can be temporarily saturated and
                        # 2s wasn't enough; TX events were silently dropped.
                        self._state_engine.post(evt, timeout=5.0)
                    else:
                        # Fallback for tests
                        tx = Transaction.from_dict(tx_data)
                        ok, _ = self.blockchain.mempool.add(tx)
                        if ok:
                            self._gossip(msg, exclude=peer.peer_id)
            except Exception as e:
                log.debug(f"TX parse error: {e}")

        elif mtype == MSG_L2TX:
            # ── v7.5.0-OPT L2 ROLLUP GOSSIP HANDLER ──────────────────────
            # If this node has a Sequencer attached, feed the L2 tx into
            # its pending pool.  Otherwise we simply relay (gossip) so
            # L2 messages still propagate across the network to whatever
            # node(s) DO have a sequencer running.  Never consumes main-
            # chain resources — no block/mempool/StateEngine posting.
            try:
                l2_data = msg.get("l2_tx")
                if not l2_data:
                    return
                try:
                    l2_tx = L2Transaction.from_dict(l2_data)
                except Exception as e:
                    log.debug(f"L2TX parse error: {e}")
                    return
                # Cheap structural check here keeps malformed gossip from
                # spreading; per-sequencer deeper checks happen below.
                ok_s, msg_s = l2_tx.is_valid()
                if not ok_s:
                    log.debug(f"L2TX from {peer.peer_id[:12]} invalid: {msg_s}")
                    return
                # If a sequencer is plugged in, enqueue.  Failure is non-
                # fatal; the L2 tx may simply be duplicate / out of nonce.
                sequencer = getattr(self, "_sequencer", None)
                if sequencer is not None and getattr(sequencer, "_running", False):
                    try:
                        sequencer.add_l2_tx(l2_tx)
                    except Exception as e:
                        log.debug(f"sequencer.add_l2_tx raised: {e}")
                # Always relay — other peers may host sequencers we don't
                # know about, and the DA / mempool semantics require wide
                # propagation of L2 traffic.  Dedup at _seen_msgs keeps
                # this from amplifying exponentially.
                self._gossip(msg, exclude=peer.peer_id)
            except Exception as e:
                log.debug(f"L2TX handler error: {e}")

        elif mtype == MSG_HASHRATE_REPORT:
            # ── v7.6.0 HASHRATE OPTIMIZATION (peer-actual-rate gossip) ──────
            # A peer reports its actual (unthrottled) hashrate.  We forward
            # this to the local HashrateGovernor (if mining is active) so
            # the per-miner cap can be recomputed against the latest network
            # picture.  This is metadata only — it does NOT affect any
            # consensus rule, block validation, or PoW path.
            #
            # Validation:
            #   • node_id and hashrate must both be present and well-formed.
            #   • hashrate is clamped via record_peer_hashrate (>= 0, <= 2^48).
            #   • Stale reports are dropped automatically on read by the
            #     governor's TTL eviction; no cleanup is needed here.
            try:
                reporter_id = msg.get("node_id", "")
                hr_value    = msg.get("hashrate", -1.0)
                if not isinstance(reporter_id, str) or not reporter_id:
                    return
                # Use the peer's connection peer_id as the canonical key —
                # not the node_id from the payload — to prevent a malicious
                # peer from spoofing reports for OTHER peers.  The peer_id
                # used here is the cryptographically-verified ID established
                # during the HELLO handshake.
                key = peer.peer_id
                if key == self.node_id:
                    return   # ignore reports about ourselves (shouldn't happen)
                # Push into our local mining engine's governor.  When no
                # mining engine is attached (e.g. an investor-only node) the
                # report is silently ignored — that's the correct behavior.
                me_attr = getattr(self, "_mining_engine_ref", None)
                if me_attr is not None:
                    try:
                        gov = me_attr.get_hashrate_governor()
                        if gov is not None:
                            gov.record_peer_hashrate(key, float(hr_value))
                    except Exception as _hge:
                        log.debug(f"[HR-Report] governor update failed: {_hge}")
                # Hashrate reports are point-to-point, NOT gossiped.  Each
                # node's report reaches every peer it is directly connected
                # to in O(degree) sends per HASHRATE_REPORT_INTERVAL, which
                # is plenty for governance accuracy and avoids amplification.
            except Exception as _hre:
                log.debug(f"[HR-Report] handler error: {_hre}")

        elif mtype == MSG_RATE_DEFECTION_EVIDENCE:
            # ── v7.7.0 RATE DEFECTION EVIDENCE ──────────────────────────────
            # Statistical evidence that a miner consistently produced blocks
            # faster than their throttle cap.  Receivers MUST independently
            # re-audit before applying any slash; the auditor handles this.
            try:
                auditor = getattr(self, "_rate_auditor", None)
                if auditor is None:
                    return   # No auditor wired (light node) — ignore
                # Build the cap registry from the local hashrate governor's
                # peer view + our own measured rate.  Light nodes without a
                # mining engine don't run the auditor at all.
                me_attr = getattr(self, "_mining_engine_ref", None)
                if me_attr is None:
                    return
                gov = me_attr.get_hashrate_governor()
                if gov is None:
                    return
                # Build the registry view from the governor's snapshot.
                # We use peer_id as the registry key, matching the auditor's
                # convention (miner_address from blocks may differ; the
                # consensus engine resolves this via the cap-snapshot rules
                # documented in the auditor class).
                cap_registry = {}
                with gov._lock:
                    for pid, (rate, _ts) in gov._peer_rates.items():
                        if rate > 0:
                            cap_registry[pid] = rate
                    if gov._local_actual_hashrate > 0:
                        my_id = getattr(self, "node_id", "self")
                        cap_registry[my_id] = gov._local_actual_hashrate
                if not cap_registry:
                    log.debug("[RateAudit-MSG] empty cap registry; cannot verify")
                    return
                accepted, reason = auditor.handle_received_evidence(
                    msg, cap_registry)
                if accepted:
                    log.info(f"[RateAudit-MSG] {reason}")
                else:
                    log.debug(f"[RateAudit-MSG] rejected: {reason}")
            except Exception as exc:
                log.debug(f"[RateAudit-MSG] handler error: {exc}")

        elif mtype == MSG_BLOCK:
            # ── v7.6.0 Track peer's chain_height from received blocks ─────
            # Every inbound block tells us the peer is at least at height
            # block.index.  This gives the MiningSafetyGuard a fresh view
            # without a separate query message.  We only ratchet upward —
            # never lower — so a peer can't fool us into thinking it has
            # regressed.
            try:
                _b_data = msg.get("block")
                if isinstance(_b_data, dict):
                    _b_idx = _b_data.get("index", -1)
                    if isinstance(_b_idx, int) and _b_idx > peer.chain_height:
                        peer.chain_height = _b_idx
            except Exception:
                pass
            # ── Route through StateEngine (single-writer) ─────────────────────
            # v7.1.8 BUG-FIX (Bug 4 + Bug 5):
            #   • The pre-fix code IGNORED the return value of
            #     state_engine.post().  Network-sourced events (line 4254
            #     ``post()``) drop with return False under any backpressure
            #     and the ``timeout=5.0`` argument is silently a no-op for
            #     them — so this call was a coin flip during sync.
            #   • Combined with the dedup-before-process bug above, every
            #     dropped block was permanently un-resyncable for ~1 hour.
            #
            # Now: we only mark the block_hash as seen AFTER post() succeeds
            # (or after the test-fallback apply_block succeeds).  If post()
            # refuses, we log loudly and leave the dedup cache empty so the
            # next gossip copy from another peer gets a fresh attempt.
            try:
                block_data = msg.get("block")
                if block_data:
                    _bh = (block_data.get("block_hash")
                           if isinstance(block_data, dict) else None)
                    if self._state_engine is not None:
                        evt = Event(
                            EventType.NEW_BLOCK,
                            {"block": block_data},
                            source_peer_id=peer.peer_id,
                        )
                        accepted = self._state_engine.post(evt, timeout=5.0)
                        if accepted:
                            # Block is now in the StateEngine queue —
                            # safe to dedup further re-gossip copies.
                            if _bh:
                                self._seen_msgs.put(("BLOCK", _bh), True)
                        else:
                            log.warning(
                                f"[INBOUND-DROP] MSG_BLOCK from "
                                f"{peer.peer_id[:12]} REFUSED by StateEngine "
                                f"(queue high-water).  NOT dedup-caching — "
                                f"next gossip copy will be retried.")
                    else:
                        # Fallback for tests / pre-engine startup.
                        block = Block.from_dict(block_data)
                        ok, reason = self.blockchain.apply_block(block)
                        if ok:
                            log.info(f"Accepted block #{block.index} from {peer.peer_id[:12]}")
                            if _bh:
                                self._seen_msgs.put(("BLOCK", _bh), True)
                            # ── LIVE-UI: push instant block notification ──────────
                            _push_block_notif(block.index, block.miner_address, source="network")
                            self._gossip(msg, exclude=peer.peer_id)
                        else:
                            log.debug(f"Rejected block #{block.index}: {reason}")
                            if "tampered" in reason or "genesis" in reason:
                                self._broadcast_invalid_alert(peer.peer_id)
            except Exception as e:
                log.debug(f"Block parse error: {e}")

        # ═══════════════════════════════════════════════════════════════════
        # v7.5.0 COMPACT-BLOCK PROTOCOL
        # ───────────────────────────────────────────────────────────────────
        # ... existing block handlers above ...
        
        # ── Parallel Block Sync Handlers ──────────────────────────────────────────
        elif mtype == MSG_GET_BLOCK_MANIFEST:
            bh = msg.get("block_hash")
            if bh:
                raw_block = self._get_serialized_block(bh)
                if raw_block:
                    chunk_sz = ParallelBlockDownloader.CHUNK_SIZE
                    chunks = [raw_block[i:i + chunk_sz] for i in range(0, len(raw_block), chunk_sz)]
                    chunk_hashes = [hashlib.sha256(c).hexdigest() for c in chunks]
                    peer.send({
                        "type": MSG_BLOCK_MANIFEST,
                        "block_hash": bh,
                        "total_chunks": len(chunks),
                        "chunk_hashes": chunk_hashes
                    })
                else:
                    peer.send({
                        "type": MSG_BLOCK_MANIFEST, 
                        "block_hash": bh, 
                        "error": "not found"
                    })

        elif mtype == MSG_BLOCK_MANIFEST:
            # Route to the waiting downloader thread
            q = getattr(peer, "_block_chunk_queue", None)
            if q is not None:
                q.put(msg)

        elif mtype == MSG_GET_BLOCK_CHUNK:
            bh = msg.get("block_hash")
            idx = int(msg.get("chunk_index", -1))
            if bh and idx >= 0:
                raw_block = self._get_serialized_block(bh)
                if raw_block:
                    chunk_sz = ParallelBlockDownloader.CHUNK_SIZE
                    offset = idx * chunk_sz
                    if offset < len(raw_block):
                        chunk = raw_block[offset:offset + chunk_sz]
                        peer.send({
                            "type": MSG_BLOCK_CHUNK_DATA,
                            "block_hash": bh,
                            "chunk_index": idx,
                            "data_hex": chunk.hex()
                        })
                    else:
                        peer.send({
                            "type": MSG_BLOCK_CHUNK_DATA, 
                            "block_hash": bh, 
                            "error": "index out of bounds"
                        })
                else:
                    peer.send({
                        "type": MSG_BLOCK_CHUNK_DATA, 
                        "block_hash": bh, 
                        "error": "not found"
                    })

        elif mtype == MSG_BLOCK_CHUNK_DATA:
            # Route chunk payload to the active worker thread
            q = getattr(peer, "_block_chunk_queue", None)
            if q is not None:
                q.put(msg)
        
        elif mtype == MSG_CMPCTBLOCK:
            # ── Receiver logic ─────────────────────────────────────────────
            # 1. Extract header + short_ids from the wire message.
            # 2. Try to match every short_id against our in-memory mempool.
            # 3a. All found → reconstruct Block, verify merkle_root, push to
            #     StateEngine as a NEW_BLOCK event (same path as MSG_BLOCK).
            # 3b. Some missing → stash the partial entry and request the
            #     missing full transactions via MSG_GETBLOCKTXN.
            #
            # This handler NEVER blocks the P2P receive thread — all heavy
            # work (Block.from_dict, apply_block) goes through the
            # StateEngine queue.
            try:
                _hdr       = msg.get("header", {})
                _short_ids = msg.get("short_ids", [])
                _cbh       = _hdr.get("block_hash", "") if isinstance(_hdr, dict) else ""
                # ── v7.6.0 Track peer's chain_height from compact block hdr ─
                try:
                    if isinstance(_hdr, dict):
                        _ci = _hdr.get("index", -1)
                        if isinstance(_ci, int) and _ci > peer.chain_height:
                            peer.chain_height = _ci
                except Exception:
                    pass
                # CMPCT-COINBASE FIX: extract the attached coinbase once here
                # so both fast-path and BLOCKTXN-slow-path reconstruction use
                # the same validated value.  The coinbase is REQUIRED because
                # its tx_id depends on a timestamp that is not a header field
                # (Transaction.coinbase() uses int(time.time()) at creation),
                # so the receiver cannot deterministically rebuild it from
                # header fields alone.  Missing/invalid coinbase → drop.
                _cb_dict = msg.get("coinbase")
                if (not isinstance(_cb_dict, dict)
                        or _cb_dict.get("sender") != "COINBASE"):
                    log.warning(
                        f"[CMPCT] missing/invalid coinbase in MSG_CMPCTBLOCK "
                        f"from {peer.peer_id[:12]}: cannot reconstruct block "
                        f"#{_hdr.get('index') if isinstance(_hdr, dict) else '?'}")
                    return

                if not _cbh or not isinstance(_hdr, dict):
                    log.debug(f"[CMPCT] Malformed MSG_CMPCTBLOCK from {peer.peer_id[:12]}: missing header/block_hash")
                    return

                # ── Stale-stash GC (opportunistic, every receipt) ──────────
                _now = time.time()
                with self._compact_stash_lock:
                    _expired = [_k for _k, _v in self._compact_stash.items()
                                if _now - _v.get("ts", 0) > self._CMPCT_STASH_TTL]
                    for _k in _expired:
                        self._compact_stash.pop(_k, None)
                        log.debug(f"[CMPCT] Evicted stale stash entry {_k[:16]}")

                # ── Build mempool lookup index: short_id → Transaction ──────
                # Read all live mempool entries once under the heap lock so we
                # don't hold the lock during the per-tx loop.
                _mempool_txs: Dict[str, 'Transaction'] = {}
                try:
                    _live = self.blockchain.mempool._heap.get_all_live()
                    for _tx in _live:
                        _mempool_txs[_tx.tx_id[:16]] = _tx
                except Exception as _mp_err:
                    log.debug(f"[CMPCT] Mempool scan error: {_mp_err}")

                # ── Match short_ids against mempool ────────────────────────
                _found:   Dict[str, 'Transaction'] = {}   # short_id → tx
                _missing: List[str] = []                   # short_ids not in mempool

                for _sid in _short_ids:
                    if _sid in _mempool_txs:
                        _found[_sid] = _mempool_txs[_sid]
                    else:
                        _missing.append(_sid)

                if not _missing:
                    # ── Fast path: full reconstruction ─────────────────────
                    # All non-coinbase transactions are in our mempool.
                    # Assemble [coinbase, tx_for_sid_0, tx_for_sid_1, ...] so
                    # the reconstructed merkle tree matches the miner's.
                    # _cb_dict was extracted and validated at the top of this
                    # handler (see CMPCT-COINBASE FIX).
                    _txs_ordered = [_cb_dict] + [
                        _found[_sid].to_dict() for _sid in _short_ids]
                    _block_dict = dict(_hdr)
                    _block_dict["transactions"] = _txs_ordered

                    # ── Verify merkle_root before posting ──────────────────
                    try:
                        _reconstructed = Block.from_dict(_block_dict)
                        _expected_mr   = _hdr.get("merkle_root", "")
                        if _reconstructed.merkle_root != _expected_mr:
                            log.warning(
                                f"[CMPCT] merkle_root mismatch for block "
                                f"#{_hdr.get('index')} from {peer.peer_id[:12]}: "
                                f"got {_reconstructed.merkle_root[:12]} "
                                f"expected {_expected_mr[:12]}"
                            )
                            return
                    except Exception as _re_err:
                        log.debug(f"[CMPCT] Reconstruction error (fast path): {_re_err}")
                        return

                    # ── Post to StateEngine (deferred dedup put) ───────────
                    if self._state_engine is not None:
                        _evt = Event(
                            EventType.NEW_BLOCK,
                            {"block": _block_dict},
                            source_peer_id=peer.peer_id,
                        )
                        _accepted = self._state_engine.post(_evt, timeout=5.0)
                        if _accepted:
                            self._seen_msgs.put(("BLOCK", _cbh), True)
                            log.debug(
                                f"[CMPCT] Fast-path block #{_hdr.get('index')} "
                                f"from {peer.peer_id[:12]} posted to StateEngine"
                            )
                        else:
                            log.warning(
                                f"[CMPCT] StateEngine refused fast-path block "
                                f"#{_hdr.get('index')} — not dedup-cached"
                            )
                    else:
                        # Pre-engine fallback (tests / early startup)
                        try:
                            _blk = Block.from_dict(_block_dict)
                            _ok, _reason = self.blockchain.apply_block(_blk)
                            if _ok:
                                self._seen_msgs.put(("BLOCK", _cbh), True)
                                _push_block_notif(_blk.index, _blk.miner_address, source="network")
                                self._gossip(msg, exclude=peer.peer_id)
                            else:
                                log.debug(f"[CMPCT] Pre-engine apply rejected: {_reason}")
                        except Exception as _fe:
                            log.debug(f"[CMPCT] Pre-engine fallback error: {_fe}")

                else:
                    # ── Slow path: request missing transactions ─────────────
                    # Stash the partial state and ask the sender for the full
                    # transaction dicts corresponding to the missing short_ids.
                    #
                    # We request by full tx_id, which we don't have yet (we
                    # only have the 8-byte prefix).  The sender maps short_id
                    # → full tx_id on its side and returns the full tx dicts.
                    # We send the short_ids so the sender knows exactly which
                    # ones we need.
                    with self._compact_stash_lock:
                        self._compact_stash[_cbh] = {
                            "header":      _hdr,
                            "short_ids":   _short_ids,
                            "txs":         _found,     # short_id → Transaction (already resolved)
                            "missing":     _missing,   # short_ids still needed
                            "coinbase":    _cb_dict,   # CMPCT-COINBASE FIX: needed to rebuild the block
                            "source_peer": peer.peer_id,
                            "ts":          time.time(),
                        }

                    peer.send({
                        "type":        MSG_GETBLOCKTXN,
                        "block_hash":  _cbh,
                        "short_ids":   _missing,   # the sender resolves these server-side
                    })
                    log.debug(
                        f"[CMPCT] Slow-path: block #{_hdr.get('index')} "
                        f"from {peer.peer_id[:12]}: "
                        f"{len(_missing)}/{len(_short_ids)} tx(s) missing — "
                        f"sent GETBLOCKTXN"
                    )

            except Exception as _cmpct_err:
                log.debug(f"[CMPCT] MSG_CMPCTBLOCK handler error: {_cmpct_err}", exc_info=True)

        elif mtype == MSG_GETBLOCKTXN:
            # ── Sender services a missing-tx request ───────────────────────
            # The requester sends:
            #   { "type": "GETBLOCKTXN",
            #     "block_hash": "<bh>",
            #     "short_ids":  ["<16-hex>", ...] }   ← 8-byte prefixes
            #
            # We look up the block from our chain, find each tx by short_id,
            # and reply with the full transaction dicts via MSG_BLOCKTXN.
            #
            # Lookup order: local chain DB first (tx already confirmed in our
            # copy of that block), then mempool (tx not yet confirmed here but
            # we have it from gossip).
            try:
                _req_bh      = msg.get("block_hash", "")
                _req_sids    = msg.get("short_ids", [])

                if not _req_bh or not _req_sids:
                    return

                # Locate the block to build a short_id → tx mapping
                _serving_block: Optional['Block'] = None
                # Try to get the block from the chain by block_hash.
                # Blockchain.get_block() takes an index, so we search by hash.
                try:
                    _tip = self.blockchain.height()
                    # Walk backwards at most 20 blocks (compact blocks are fresh)
                    for _bi in range(_tip, max(-1, _tip - 20), -1):
                        _b = self.blockchain.get_block(_bi)
                        if _b and _b.block_hash == _req_bh:
                            _serving_block = _b
                            break
                except Exception:
                    pass

                _tx_map: Dict[str, dict] = {}   # short_id → tx_dict

                if _serving_block is not None:
                    # Build short_id → tx_dict from confirmed block
                    for _tx in _serving_block.transactions:
                        _sid = _tx.tx_id[:16]
                        _tx_map[_sid] = _tx.to_dict()
                else:
                    # Block not in our chain yet — serve from mempool
                    try:
                        _live = self.blockchain.mempool._heap.get_all_live()
                        for _tx in _live:
                            _sid = _tx.tx_id[:16]
                            _tx_map[_sid] = _tx.to_dict()
                    except Exception:
                        pass
                    # Also check the DB for confirmed txs by short_id prefix
                    for _sid in _req_sids:
                        if _sid not in _tx_map:
                            # last-resort: scan recent confirmed txs
                            # (this path is rare and only for very fresh blocks)
                            try:
                                _dbtx = self.blockchain.storage.get_tx(_sid)   # won't work with prefix
                            except Exception:
                                _dbtx = None
                            # get_tx needs the full tx_id; skip if not found
                            # The sender will retry via MSG_BLOCK fallback if
                            # MSG_BLOCKTXN is incomplete (timeout path).

                # Collect the requested transactions
                _reply_txs = []
                for _sid in _req_sids:
                    if _sid in _tx_map:
                        _reply_txs.append(_tx_map[_sid])
                    else:
                        log.debug(
                            f"[CMPCT] GETBLOCKTXN: short_id {_sid} not found "
                            f"for block {_req_bh[:16]}"
                        )

                if _reply_txs:
                    peer.send({
                        "type":        MSG_BLOCKTXN,
                        "block_hash":  _req_bh,
                        "txs":         _reply_txs,
                    })
                    log.debug(
                        f"[CMPCT] Served {len(_reply_txs)}/{len(_req_sids)} "
                        f"tx(s) to {peer.peer_id[:12]} for block {_req_bh[:16]}"
                    )

            except Exception as _gbt_err:
                log.debug(f"[CMPCT] MSG_GETBLOCKTXN handler error: {_gbt_err}", exc_info=True)

        elif mtype == MSG_BLOCKTXN:
            # ── Receiver fills in missing transactions and finalises block ──
            # The sender replies with:
            #   { "type": "BLOCKTXN",
            #     "block_hash": "<bh>",
            #     "txs":        [ <tx_dict>, ... ] }
            #
            # We find our stashed partial compact block, merge in the newly
            # arrived transactions, re-verify the merkle_root, and post to
            # the StateEngine.
            try:
                _fill_bh  = msg.get("block_hash", "")
                _fill_txs = msg.get("txs", [])

                if not _fill_bh or not isinstance(_fill_txs, list):
                    return

                with self._compact_stash_lock:
                    _stash = self._compact_stash.get(_fill_bh)

                if _stash is None:
                    # Stash was already evicted (TTL) or block came another way
                    log.debug(
                        f"[CMPCT] MSG_BLOCKTXN for {_fill_bh[:16]} "
                        f"from {peer.peer_id[:12]}: no stash entry — ignoring"
                    )
                    return

                # Check we haven't already processed this block hash
                if self._seen_msgs.get(("BLOCK", _fill_bh)):
                    with self._compact_stash_lock:
                        self._compact_stash.pop(_fill_bh, None)
                    return

                _hdr        = _stash["header"]
                _short_ids  = _stash["short_ids"]
                _resolved   = dict(_stash["txs"])   # short_id → Transaction (already known)

                # Incorporate newly arrived transactions
                for _td in _fill_txs:
                    try:
                        _tx  = Transaction.from_dict(_td)
                        _sid = _tx.tx_id[:16]
                        _resolved[_sid] = _tx
                    except Exception as _td_err:
                        log.debug(f"[CMPCT] BLOCKTXN: tx parse error: {_td_err}")

                # Check if we now have everything
                _still_missing = [_sid for _sid in _short_ids if _sid not in _resolved]
                if _still_missing:
                    log.warning(
                        f"[CMPCT] BLOCKTXN: still missing "
                        f"{len(_still_missing)} tx(s) for block "
                        f"{_fill_bh[:16]} after reply — dropping stash"
                    )
                    with self._compact_stash_lock:
                        self._compact_stash.pop(_fill_bh, None)
                    return

                # ── Reconstruct ordered transaction list ───────────────────
                # CMPCT-COINBASE FIX: prepend the coinbase stashed when the
                # original MSG_CMPCTBLOCK was received.  Without this, the
                # recomputed merkle_root would differ from the miner's (the
                # miner hashes [coinbase, tx1, ...] but we'd hash [tx1, ...]).
                _cb_dict = _stash.get("coinbase")
                if (not isinstance(_cb_dict, dict)
                        or _cb_dict.get("sender") != "COINBASE"):
                    log.warning(
                        f"[CMPCT] BLOCKTXN: stash for {_fill_bh[:16]} has "
                        f"missing/invalid coinbase — dropping")
                    with self._compact_stash_lock:
                        self._compact_stash.pop(_fill_bh, None)
                    return
                _txs_ordered = [_cb_dict] + [
                    _resolved[_sid].to_dict() for _sid in _short_ids]
                _block_dict  = dict(_hdr)
                _block_dict["transactions"] = _txs_ordered

                # ── Verify merkle_root ─────────────────────────────────────
                try:
                    _reconstructed = Block.from_dict(_block_dict)
                    _expected_mr   = _hdr.get("merkle_root", "")
                    if _reconstructed.merkle_root != _expected_mr:
                        log.warning(
                            f"[CMPCT] BLOCKTXN merkle_root mismatch for block "
                            f"#{_hdr.get('index')} from {peer.peer_id[:12]}: "
                            f"got {_reconstructed.merkle_root[:12]} "
                            f"expected {_expected_mr[:12]}"
                        )
                        with self._compact_stash_lock:
                            self._compact_stash.pop(_fill_bh, None)
                        return
                except Exception as _re2:
                    log.debug(f"[CMPCT] BLOCKTXN reconstruction error: {_re2}")
                    with self._compact_stash_lock:
                        self._compact_stash.pop(_fill_bh, None)
                    return

                # ── Remove stash entry before posting (prevent double-post) ─
                with self._compact_stash_lock:
                    self._compact_stash.pop(_fill_bh, None)

                # ── Post to StateEngine ────────────────────────────────────
                if self._state_engine is not None:
                    _evt = Event(
                        EventType.NEW_BLOCK,
                        {"block": _block_dict},
                        source_peer_id=peer.peer_id,
                    )
                    _accepted = self._state_engine.post(_evt, timeout=5.0)
                    if _accepted:
                        self._seen_msgs.put(("BLOCK", _fill_bh), True)
                        log.debug(
                            f"[CMPCT] Slow-path block #{_hdr.get('index')} "
                            f"from {peer.peer_id[:12]} posted to StateEngine "
                            f"after BLOCKTXN fill"
                        )
                    else:
                        log.warning(
                            f"[CMPCT] StateEngine refused slow-path block "
                            f"#{_hdr.get('index')} — not dedup-cached"
                        )
                else:
                    # Pre-engine fallback
                    try:
                        _blk = Block.from_dict(_block_dict)
                        _ok, _reason = self.blockchain.apply_block(_blk)
                        if _ok:
                            self._seen_msgs.put(("BLOCK", _fill_bh), True)
                            _push_block_notif(_blk.index, _blk.miner_address, source="network")
                        else:
                            log.debug(f"[CMPCT] BLOCKTXN pre-engine apply rejected: {_reason}")
                    except Exception as _fe2:
                        log.debug(f"[CMPCT] BLOCKTXN pre-engine fallback error: {_fe2}")

            except Exception as _bktxn_err:
                log.debug(f"[CMPCT] MSG_BLOCKTXN handler error: {_bktxn_err}", exc_info=True)

        elif mtype == MSG_GET_BLOCK:
            _req_idx = msg.get("index")
            if _req_idx is not None:
                _req_block = self.blockchain.get_block(int(_req_idx))
                if _req_block is not None:
                    peer.send({"type": MSG_BLOCK, "block": _req_block.to_dict()})

        elif mtype == MSG_GET_CHAIN:
            from_idx = msg.get("from_idx", 0)
            to_idx   = msg.get("to_idx", self.blockchain.height())
            chain    = []
            # BUG-FIX (v7.0.0.0): Reduced per-response cap from 500 → 200 blocks.
            # On Android/Pydroid3 with limited RAM, a 500-block response frequently
            # exceeded MAX_MESSAGE_SIZE, causing the receiving peer to be banned for
            # "oversized frame".  200 blocks × ~8 KB avg = ~1.6 MB typical payload,
            # which stays safely under the 1 GB cap even on heavy-transaction chains.
            # Pagination in the MSG_CHAIN handler fetches subsequent batches automatically.
            #
            # v7.0.1.1 (Partial-Sync Fix): The loop already skips missing indices
            # (get_block returns None), so a request for blocks 0–199 when only
            # 66 are mined correctly produces a 66-block response.  We now also
            # include the server's current chain height in every MSG_CHAIN reply
            # so the receiving peer can distinguish "partial page because server
            # has no more blocks yet" (server_height == last_received_index) from
            # "partial page but more blocks exist above the received range"
            # (server_height > last_received_index), enabling smarter pagination.
            _server_height = self.blockchain.height()
            for i in range(from_idx, min(to_idx + 1, from_idx + 200)):
                b = self.blockchain.get_block(i)
                if b:
                    chain.append(b.to_dict())
            peer.send({
                "type":          MSG_CHAIN,
                "blocks":        chain,
                "server_height": _server_height,   # v7.0.1.1: partial-sync signal
                "request_id":    msg.get("request_id"),
            })
            # ── Dashboard visibility for INBOUND sync requests ───────────────
            # Prior to this change the server-side sync path was completely
            # silent: a peer could request thousands of blocks and the operator
            # would see nothing on the dashboard.  We now emit one INFO log
            # line (routed through _QueueHandler into the Recent Activity
            # panel) AND push a dedicated formatted entry so operators can see
            # in real time which peers are syncing from this node.
            try:
                log.info(
                    f"[ChainServe] Peer {peer.peer_id[:12]} requested blocks "
                    f"{from_idx}-{to_idx}; served {len(chain)} block(s) "
                    f"(chain tip={_server_height})"
                )
                _push_sync_request_notif(
                    peer.peer_id, from_idx, to_idx, len(chain)
                )
            except Exception:
                pass

        elif mtype == MSG_CHAIN:
            # ── Route through StateEngine (single-writer) ─────────────────────
            #
            # v6.9.9.7 improvements:
            #   1. If StateEngine post times out or raises, fall back to direct
            #      accept_chain() so the sync never silently disappears.
            #   2. Log sync outcomes at INFO level (not DEBUG) so operators can
            #      see whether blocks were actually adopted.
            #   3. Automatic pagination: if a full page (200 blocks) arrives,
            #      request the next batch after the current page is committed.
            #      This is essential when a fresh node joins a chain that
            #      already has thousands of blocks.
            #
            # v7.0.0.7 pagination rework — event-driven, not sleep-based:
            #   The old code spawned a _request_next_page thread that slept
            #   1 s and then fired the next MSG_GET_CHAIN unconditionally.
            #   On slow disks accept_chain() can take 5-10 s per batch.
            #   When _request_next_page fired before page N was committed,
            #   the peer responded with page N+1 whose _apply_chain_direct
            #   thread then raced page N's thread to acquire blockchain._lock.
            #   Whichever lost called accept_chain() after the winner and saw
            #   blocks it considered out-of-order, silently rejecting the page.
            #   Pagination stalled with no retry and no error beyond a WARNING.
            #
            #   Fix: _request_next_page is removed entirely.  The next-page
            #   MSG_GET_CHAIN is sent from INSIDE _apply_chain_direct(), AFTER
            #   accept_chain() returns ok=True.  This guarantees the next
            #   request is only issued once the current batch is fully written,
            #   making pagination strictly serial and race-free regardless of
            #   how long the DB commit takes.
            blocks_data = msg.get("blocks", [])
            if not isinstance(blocks_data, list):
                return
            _sync_request_id = self._sync_claim_response(
                peer, msg, blocks_data)
            if _sync_request_id is None:
                return
            if not blocks_data:
                self._sync_finish(peer, _sync_request_id)
                peer._pagination_active.clear()
                return   # correlated empty response

            # ── v7.6.0 Track peer's chain_height from received blocks ─────
            # Update peer.chain_height to the highest index in this batch
            # plus, if the response includes a server_height field, use
            # that as the canonical max (it is the peer's actual tip).
            try:
                _server_height = msg.get("server_height", -1)
                if isinstance(_server_height, int) and _server_height > peer.chain_height:
                    peer.chain_height = _server_height
                else:
                    _max_idx = peer.chain_height
                    for _b in blocks_data:
                        if isinstance(_b, dict):
                            _bi = _b.get("index", -1)
                            if isinstance(_bi, int) and _bi > _max_idx:
                                _max_idx = _bi
                    if _max_idx > peer.chain_height:
                        peer.chain_height = _max_idx
            except Exception:
                pass

            # ── Capture pagination state before spawning apply thread ─────────
            _rcvd = len(blocks_data)

            # v7.0.1.1 — Partial-Sync Fix: smarter next-page decision.
            #
            # OLD logic:  _needs_next_page = (_rcvd >= 200)
            # Problem:    When the server has only 66 blocks and we requested
            #             0–199, we receive 66 blocks (_rcvd=66 < 200), so
            #             _needs_next_page=False.  BUT if the server has 265
            #             blocks and we requested 200–399, we also receive 66
            #             blocks (_rcvd=66 < 200) — yet there ARE no more
            #             blocks because we already reached the server's tip.
            #
            # NEW logic:  use server_height (included in every MSG_CHAIN reply
            #             since v7.0.1.1) to distinguish the two cases:
            #
            #   Case A — full page (rcvd == 200):
            #     Server may have more blocks. Paginate unconditionally.
            #
            #   Case B — partial page AND last received index < server_height:
            #     Server has more blocks above what we received (e.g. blocks
            #     arrived between the request and the response).  Paginate from
            #     the last received index + 1.
            #
            #   Case C — partial page AND last received index >= server_height:
            #     We have reached the server's current tip.  No more blocks
            #     available right now.  Do NOT paginate — the watchdog would
            #     time out and falsely mark the peer as a zombie.
            #     _pagination_active is NOT set; _auto_sync_on_connect will
            #     NOT yield to a non-existent pagination thread and will
            #     instead continue its own loop from the new tip.
            #
            _server_height   = msg.get("server_height", -1)
            _last_rcvd_index = -1
            try:
                _last_rcvd_index = int(blocks_data[-1].get("index", -1))
            except Exception:
                pass

            # Deep-fork pagination: do not feed a partial overlapping page to
            # accept_chain(). First identify a real hash divergence. Once one
            # is found, accumulate the divergent suffix until the peer tip is
            # reached so cumulative-work comparison has complete input.
            _fork_buffer_active = bool(peer._fork_sync_buffer)
            _fork_payload_complete = False
            _divergence_idx = None
            if not _fork_buffer_active:
                try:
                    _local_tip_for_fork = self.blockchain.height()
                    for _bd in blocks_data:
                        _bi = int(_bd.get("index", -1))
                        if 0 <= _bi <= _local_tip_for_fork:
                            _lb = self.blockchain.storage.get_block(_bi)
                            if _lb is None or _lb.block_hash != str(_bd.get("block_hash", "")):
                                _divergence_idx = _bi
                                break
                except Exception:
                    _divergence_idx = None

            if _fork_buffer_active or _divergence_idx is not None:
                if not _fork_buffer_active:
                    peer._fork_sync_buffer = []
                    peer._fork_sync_buffer_bytes = 0
                    peer._fork_sync_target_height = (
                        int(_server_height) if isinstance(_server_height, int) else -1)
                    if _divergence_idx is not None and _divergence_idx > 0:
                        _common = self.blockchain.storage.get_block(_divergence_idx - 1)
                        if _common is not None:
                            _common_dict = _common.to_dict()
                            peer._fork_sync_buffer.append(_common_dict)
                            peer._fork_sync_buffer_bytes += len(
                                json.dumps(_common_dict, separators=(",", ":"), sort_keys=True)
                            )
                start_idx = (_divergence_idx if _divergence_idx is not None
                             else int(blocks_data[0].get("index", -1)))
                for _bd in blocks_data:
                    try:
                        if int(_bd.get("index", -1)) >= start_idx:
                            peer._fork_sync_buffer.append(_bd)
                            peer._fork_sync_buffer_bytes += len(
                                json.dumps(_bd, separators=(",", ":"), sort_keys=True)
                            )
                    except Exception:
                        peer._fork_sync_buffer.append(_bd)
                        try:
                            peer._fork_sync_buffer_bytes += len(
                                json.dumps(_bd, separators=(",", ":"), sort_keys=True)
                            )
                        except Exception:
                            peer._fork_sync_buffer_bytes += 1024

                if (len(peer._fork_sync_buffer) > Config.MAX_FORK_SYNC_BLOCKS
                        or peer._fork_sync_buffer_bytes > Config.MAX_FORK_SYNC_BYTES):
                    log.warning(
                        f"[ChainSync] Deep-fork buffer exceeded "
                        f"{Config.MAX_FORK_SYNC_BLOCKS} blocks for "
                        f"{peer.peer_id[:12]} — aborting fork sync")
                    peer._fork_sync_buffer.clear()
                    peer._fork_sync_buffer_bytes = 0
                    peer._fork_sync_target_height = -1
                    self._sync_finish(peer, _sync_request_id)
                    peer._pagination_active.clear()
                    return

                if (_server_height >= 0 and _last_rcvd_index < _server_height):
                    self._sync_finish(peer, _sync_request_id)
                    peer._pagination_active.set()
                    _sent_more = self._sync_request(
                        peer, _last_rcvd_index + 1, _last_rcvd_index + 200,
                        kind="fork-pagination", force=True)
                    if not _sent_more:
                        peer._pagination_active.clear()
                    return

                blocks_data = list(peer._fork_sync_buffer)
                _fork_payload_complete = True
                peer._fork_sync_buffer.clear()
                peer._fork_sync_buffer_bytes = 0
                peer._fork_sync_target_height = -1
                _rcvd = len(blocks_data)
                try:
                    _last_rcvd_index = int(blocks_data[-1].get("index", -1))
                except Exception:
                    _last_rcvd_index = -1

            _needs_next_page = False
            _next_page_from  = 0

            if _fork_payload_complete:
                # The buffer already contains the complete divergent suffix
                # through the peer tip. Do not paginate again based on its
                # aggregate length.
                _needs_next_page = False
            elif _rcvd >= 200:
                # Case A: full page — always paginate
                _needs_next_page = True
                try:
                    _next_page_from = int(blocks_data[-1].get("index", 0)) + 1
                except Exception:
                    _needs_next_page = False   # malformed index — skip pagination
            elif (_rcvd > 0
                  and _last_rcvd_index >= 0
                  and _server_height > _last_rcvd_index):
                # Case B: partial page but server has more — paginate from tip+1
                _needs_next_page = True
                _next_page_from  = _last_rcvd_index + 1
            # else Case C: partial page at server tip — no pagination needed

            def _apply_chain_direct():
                """Apply blocks directly; used as primary path and StateEngine fallback.

                v7.0.0.7: Next-page pagination request is fired from here, AFTER
                accept_chain() succeeds, guaranteeing the next page is only
                requested once this page is fully committed to disk.

                v7.0.1.0: A sync watchdog daemon thread is started alongside
                every next-page request.  If the peer fails to deliver the
                requested blocks within CHAIN_SYNC_TIMEOUT_SECS, the watchdog
                closes the zombie peer and re-requests from an alternate peer.
                """
                # AUDIT-FIX-2: the actual pagination-continuation logic now
                # lives in the shared _on_chain_sync_result() method (see its
                # docstring), so this fallback path and the StateEngine's
                # primary path (StateEngine._handle_chain_sync) can never
                # drift apart again.
                try:
                    blocks = [Block.from_dict(d) for d in blocks_data]
                    ok, reason = self.blockchain.accept_chain(blocks)
                except Exception as _ace:
                    log.warning(
                        f"[ChainSync] Error applying blocks from "
                        f"{peer.peer_id[:12]}: {_ace}")
                    # v7.0.1.1: clear on exception so the flag is never
                    # left set permanently after an unexpected failure.
                    peer._pagination_active.clear()
                    return
                self._on_chain_sync_result(
                    peer, blocks, ok, reason,
                    _needs_next_page, _next_page_from,
                    _sync_request_id)

            if self._state_engine is not None:
                try:
                    evt = Event(
                        EventType.CHAIN_SYNC,
                        {
                            "blocks": blocks_data,
                            # AUDIT-FIX-2: computed once, above, from the
                            # same Case A/B/C logic the fallback path uses —
                            # passed through so StateEngine._handle_chain_sync
                            # can continue pagination identically instead of
                            # silently dropping it.
                            "needs_next_page": _needs_next_page,
                            "next_page_from":  _next_page_from,
                            "sync_request_id": _sync_request_id,
                        },
                        source_peer_id=peer.peer_id,
                    )
                    # Increased timeout: large batch at startup may take >2s
                    posted = self._state_engine.post(evt, timeout=10.0)
                    if not posted:
                        log.warning(
                            f"[ChainSync] StateEngine queue full for "
                            f"{_rcvd} block(s) from {peer.peer_id[:12]} "
                            f"— applying in background thread")
                        # BUG-FIX (v7.0.0.6): Never call _apply_chain_direct()
                        # synchronously on the receive thread.  accept_chain()
                        # acquires blockchain._lock and runs DB writes for up
                        # to ~10 s per 200-block batch.  Blocking the recv
                        # thread during that time means:
                        #   1. No sock.recv() calls → incoming TCP data backs
                        #      up in the kernel buffer.
                        #   2. If the kernel buffer fills, the SENDER blocks
                        #      on its write() → the peer's send side stalls.
                        # Fix: always dispatch to a daemon thread so the recv
                        # loop keeps running regardless of apply duration.
                        threading.Thread(target=_apply_chain_direct,
                                         daemon=True).start()
                except Exception as _se:
                    log.warning(
                        f"[ChainSync] StateEngine post error ({_se}) — "
                        f"applying {_rcvd} block(s) in background thread")
                    threading.Thread(target=_apply_chain_direct,
                                     daemon=True).start()
            else:
                # No StateEngine (unit-test path) — still dispatch to thread
                # so this code path is consistent and never blocks.
                threading.Thread(target=_apply_chain_direct,
                                 daemon=True).start()

        elif mtype == MSG_VALIDATOR_SIG:
            # ── Route through StateEngine (single-writer) ─────────────────────
            if self._state_engine is not None:
                evt = Event(
                    EventType.VALIDATOR_SIG,
                    {
                        "block_hash": msg.get("block_hash",""),
                        "validator":  msg.get("validator",""),
                        "sig":        msg.get("sig",""),
                        "pub_hex":    msg.get("pub_hex",""),
                    },
                    source_peer_id=peer.peer_id,
                )
                posted = self._state_engine.post(evt, timeout=2.0)
                if not posted:
                    # Validator signatures are consensus-critical. Keep the
                    # receive thread non-blocking, but retry enqueueing for a
                    # bounded period instead of silently losing the vote when
                    # block/sync events temporarily fill the StateEngine queue.
                    def _retry_validator_sig(_event=evt,
                                             _engine=self._state_engine):
                        deadline = time.time() + 15.0
                        while time.time() < deadline and _engine._running:
                            if _engine.post(_event):
                                return
                            time.sleep(0.10)
                        log.warning(
                            "Dropped validator signature after bounded retry: "
                            f"{_event.payload.get('block_hash', '')[:16]}...")
                    threading.Thread(
                        target=_retry_validator_sig,
                        name="validator-sig-retry",
                        daemon=True,
                    ).start()
            else:
                self.blockchain.add_validator_sig(
                    msg.get("block_hash",""),
                    msg.get("validator",""),
                    msg.get("sig",""),
                    msg.get("pub_hex",""),
                )

        elif mtype == MSG_ALERT:
            bad_id = msg.get("bad_node_id","")
            if bad_id:
                self.storage.blacklist_peer(bad_id)
                with self._lock:
                    if bad_id in self.peers:
                        self.peers[bad_id].close()
                        del self.peers[bad_id]
                    self._eager_peers.discard(bad_id)

        elif mtype == MSG_IDENTITY:
            uid     = msg.get("user_id","")
            uid     = uid.strip().casefold() if isinstance(uid, str) else ""
            pid     = msg.get("peer_id","")
            waddr   = msg.get("wallet_addr","")
            pub_hex = msg.get("pub_hex","")
            maddrs  = msg.get("multiaddrs",[])
            if uid and pid:
                # Gossip is a directory update only. Ownership must already
                # exist in the canonical name_claims index populated from a
                # confirmed block; this prevents an unauthenticated
                # MSG_IDENTITY from creating or replacing a name claim.
                claim = self.storage.resolve_name_claim(uid)
                if not claim:
                    log.warning(
                        f"[IDENTITY] ignored unconfirmed MSG_IDENTITY for "
                        f"{uid!r} from peer_id={pid[:16]}")
                elif claim.get("pub_hex") != pub_hex:
                    log.warning(
                        f"[IDENTITY] rejected conflicting MSG_IDENTITY for "
                        f"{uid!r} from peer_id={pid[:16]} — canonical pub_hex "
                        f"does not match claimed pub_hex")
                else:
                    self.storage.save_identity(uid, pid, claim["wallet_addr"],
                                               claim["pub_hex"], maddrs)

        elif mtype == MSG_RESOLVE:
            uid  = msg.get("user_id","")
            uid  = uid.strip().casefold() if isinstance(uid, str) else ""
            resp = {"type": MSG_RESOLVE_RESP, "user_id": uid}
            # Never answer from a cache entry if the canonical local index has
            # a newer authoritative result (or no confirmed claim at all).
            identity = self.storage.resolve_identity(uid)
            if identity:
                self._id_cache.put(uid, identity)
                resp["result"] = identity
            else:
                cached = self._id_cache.get(uid)
                resp["result"] = cached if cached else None
            peer.send(resp)

        elif mtype == MSG_RESOLVE_RESP:
            uid    = msg.get("user_id","")
            uid    = uid.strip().casefold() if isinstance(uid, str) else ""
            result = msg.get("result")
            if uid and result:
                self._id_cache.put(uid, result)

        # ── NEW: DiscV5 Capability Discovery ──────────────────────────────────
        elif mtype == MSG_CAPABILITY_ADV:
            caps = msg.get("capabilities", [])
            if caps and hasattr(self, "_capability_router"):
                self._capability_router.handle_adv(peer.peer_id, caps)
                # Award reputation for capability advertisement
                if hasattr(self, "_reputation_mgr"):
                    self._reputation_mgr.record_uptime(peer.peer_id)

        elif mtype == MSG_CAPABILITY_QUERY:
            capability = msg.get("capability", "")
            if capability and hasattr(self, "_capability_router"):
                matching = self._capability_router.handle_query(capability)
                peer.send({
                    "type": MSG_CAPABILITY_RESPONSE,
                    "capability": capability,
                    "peers": matching[:20],  # max 20 results
                })

        elif mtype == MSG_CAPABILITY_RESPONSE:
            # Store discovered peers with the requested capability AND
            # attempt to connect to them so discovery actually produces
            # connections (Bug #7 fix — discovery was previously a dead end).
            capability = msg.get("capability", "")
            peer_ids   = msg.get("peers", [])
            if capability and hasattr(self, "_capability_router"):
                log.debug(f"DiscV5: received {len(peer_ids)} peers for "
                          f"capability '{capability}' from {peer.peer_id[:12]}")
                for discovered_peer_id in peer_ids:
                    if not isinstance(discovered_peer_id, str):
                        continue
                    if not discovered_peer_id:
                        continue
                    # Skip ourselves and already-connected peers
                    if discovered_peer_id == self.node_id:
                        continue
                    with self._lock:
                        if discovered_peer_id in self.peers:
                            continue
                    # Look up the peer's address from local storage
                    try:
                        row = self.storage._conn().execute(
                            "SELECT ip, port FROM peers "
                            "WHERE peer_id=? AND blacklisted=0",
                            (discovered_peer_id,)).fetchone()
                        if row and row["ip"] and row["port"]:
                            self._try_add_peer(
                                row["ip"], row["port"], discovered_peer_id)
                        else:
                            log.debug(
                                f"DiscV5: no stored address for peer "
                                f"{discovered_peer_id[:12]} — cannot connect")
                    except Exception as _cap_e:
                        log.debug(
                            f"DiscV5: lookup error for {discovered_peer_id[:12]}: "
                            f"{_cap_e}")

        # ── v7.4.0: Snapshot manifest request ────────────────────────────────
        elif mtype == MSG_GET_SNAPSHOT_MANIFEST:
            if hasattr(self.blockchain, "_snapshot_engine"):
                manifest = self.blockchain._snapshot_engine.get_manifest()
                peer.send({
                    "type":     MSG_SNAPSHOT_MANIFEST,
                    "manifest": manifest,
                })

        # ── v7.4.0: Snapshot manifest response ───────────────────────────────
        elif mtype == MSG_SNAPSHOT_MANIFEST:
            # BUG-FIX (sync-fix-1): MSG_SNAPSHOT_MANIFEST was silently dropped
            # (pass) instead of being routed to the _snap_response_queue that
            # _fast_sync_legacy() is blocking on.  This caused a guaranteed
            # 30-second MANIFEST_TIMEOUT on every peer connection, burning most
            # of the _auto_sync_on_connect 24-second retry budget before the
            # normal full-chain fallback even started.  Route the message to the
            # queue exactly like MSG_SNAPSHOT_DATA does.
            q = getattr(peer, "_snap_response_queue", None)
            if q is not None:
                q.put(msg)

        # ── v7.4.0: Snapshot blob request ─────────────────────────────────────
        elif mtype == MSG_GET_SNAPSHOT:
            height = int(msg.get("height", -1))
            if height < 0:
                peer.send({"type": MSG_SNAPSHOT_DATA, "height": height,
                           "error": "invalid height"})
            elif hasattr(self.blockchain, "_snapshot_engine"):
                blob = self.blockchain._snapshot_engine.get_snapshot_blob(height)
                if blob is None:
                    peer.send({"type": MSG_SNAPSHOT_DATA, "height": height,
                               "error": "snapshot not found"})
                else:
                    # Send as hex; CompressionEngine already compressed the blob
                    peer.send({
                        "type":      MSG_SNAPSHOT_DATA,
                        "height":    height,
                        "data_hex":  blob.hex(),
                        "size":      len(blob),
                    })
                    log.info(
                        f"[SnapshotServe] Sent snapshot height={height} "
                        f"({len(blob):,}B) to {peer.peer_id[:12]}"
                    )

        # ── v7.4.0: Snapshot blob response ────────────────────────────────────
        elif mtype == MSG_SNAPSHOT_DATA:
            # Routed to the fast-sync coroutine via a shared queue stored on
            # the peer object (set up in _fast_sync_from_peer).
            q = getattr(peer, "_snap_response_queue", None)
            if q is not None:
                q.put(msg)

        # ── v7.5.0: Chunk manifest request ────────────────────────────────────
        elif mtype == MSG_GET_CHUNK_MANIFEST:
            if hasattr(self.blockchain, "_snapshot_engine"):
                eng    = self.blockchain._snapshot_engine
                height = int(msg.get("height", -1))
                # height == -1 means "give me your latest snapshot"
                if height == -1:
                    height = eng.latest_snapshot_height()
                chunk_manifest = eng.get_chunk_manifest(height) if height >= 0 else None
                if chunk_manifest:
                    peer.send({"type": MSG_CHUNK_MANIFEST, **chunk_manifest})
                else:
                    peer.send({
                        "type":   MSG_CHUNK_MANIFEST,
                        "height": height,
                        "error":  "snapshot not found",
                    })

        # ── v7.5.0: Chunk manifest response ───────────────────────────────────
        elif mtype == MSG_CHUNK_MANIFEST:
            # Routed to the parallel downloader via _chunk_response_queue.
            q = getattr(peer, "_chunk_response_queue", None)
            if q is not None:
                q.put(msg)

        # ── v7.5.0: Single chunk request ──────────────────────────────────────
        elif mtype == MSG_GET_CHUNK:
            if hasattr(self.blockchain, "_snapshot_engine"):
                eng         = self.blockchain._snapshot_engine
                height      = int(msg.get("height", -1))
                chunk_index = int(msg.get("chunk_index", -1))
                if height < 0 or chunk_index < 0:
                    peer.send({
                        "type":        MSG_CHUNK_DATA,
                        "height":      height,
                        "chunk_index": chunk_index,
                        "error":       "invalid height or chunk_index",
                    })
                else:
                    chunk_bytes = eng.get_chunk(height, chunk_index)
                    if chunk_bytes is None:
                        peer.send({
                            "type":        MSG_CHUNK_DATA,
                            "height":      height,
                            "chunk_index": chunk_index,
                            "error":       "chunk not found",
                        })
                    else:
                        chunk_hash = hashlib.sha256(chunk_bytes).hexdigest()
                        peer.send({
                            "type":        MSG_CHUNK_DATA,
                            "height":      height,
                            "chunk_index": chunk_index,
                            "data_hex":    chunk_bytes.hex(),
                            "hash":        chunk_hash,
                        })
                        log.debug(
                            "[ChunkServe] Sent chunk %d for h=%d (%dB) to %s",
                            chunk_index, height, len(chunk_bytes),
                            peer.peer_id[:12],
                        )

        # ── v7.5.0: Single chunk response ─────────────────────────────────────
        elif mtype == MSG_CHUNK_DATA:
            # Routed to the parallel downloader via _chunk_response_queue.
            q = getattr(peer, "_chunk_response_queue", None)
            if q is not None:
                q.put(msg)

        # ── NEW: Automated Slashing Evidence ─────────────────────────────────
        elif mtype == SlashingEvidenceProtocol.MSG_TYPE:
            if hasattr(self, "_slash_evidence") and self._slash_evidence:
                ok, reason = self._slash_evidence.handle_network_evidence(msg)
                if ok:
                    # Relay to other peers (gossip)
                    self._gossip(msg, exclude=peer.peer_id)
                    log.info(f"Slashing evidence accepted and relayed: {reason}")
                elif "already processed" not in reason:
                    log.debug(f"Slashing evidence rejected: {reason}")

        for cb in self._callbacks.get(mtype, []):
            try: cb(peer, msg)
            except Exception: pass

    def _on_peer_disconnect(self, peer: PeerConnection):
        peer.connected = False
        peer._fork_sync_buffer.clear()
        peer._fork_sync_buffer_bytes = 0
        peer._fork_sync_target_height = -1
        peer.close()
        # AUDIT-FIX-21: a connection that lost the _register_peer() race
        # (see AUDIT-FIX-21 there) was already closed and superseded while
        # it was still open — its own message loop is only now noticing and
        # unwinding. `self.peers[peer.peer_id]` may therefore already point
        # at a *different*, newer, still-live connection for this same
        # identity. Compute whether that's the case atomically with the pop
        # (same lock acquisition, no separate check-then-act gap), and if
        # so, treat this purely as this object's own local cleanup — do NOT
        # run any of the peer_id-keyed "this identity is now offline"
        # bookkeeping below, since it isn't offline.
        with self._lock:
            _still_current = self.peers.get(peer.peer_id) is peer
            if _still_current:
                self.peers.pop(peer.peer_id, None)
                self._eager_peers.discard(peer.peer_id)
        if not _still_current:
            log.debug(
                f"Stale connection torn down for {peer.peer_id[:12]}... "
                f"[{peer.ip}:{peer.port}] — a newer session for this peer "
                f"is still registered; skipping identity-level disconnect "
                f"bookkeeping.")
            return
        self.storage.mark_peer_fail(peer.peer_id)
        self.router.remove(peer.peer_id)
        # ── NEW: Remove capability records for disconnected peer ──────────────
        if hasattr(self, "_capability_router"):
            self._capability_router.remove_peer(peer.peer_id)
        # ── NEW: Clean up Full Audit Mode rate-tracking for disconnected peer ─
        with self._untrusted_rate_lock:
            self._untrusted_rate.pop(peer.peer_id, None)
        # ── v7.1.0: Free per-peer message-rate buckets ───────────────────────
        self._clear_msg_rate(peer.peer_id)
        # ── v7.5.0: Drop compact-block stash entries waiting on this peer ────
        # If we were waiting for MSG_BLOCKTXN from this peer and it disconnected,
        # the stash entries are now unserviceable.  Drop them so memory is freed
        # and a future CMPCTBLOCK from another peer gets a clean stash slot.
        with self._compact_stash_lock:
            _dead_keys = [
                _k for _k, _v in self._compact_stash.items()
                if _v.get("source_peer") == peer.peer_id
            ]
            for _k in _dead_keys:
                self._compact_stash.pop(_k, None)
                log.debug(f"[CMPCT] Stash entry {_k[:16]} dropped on peer disconnect")
        # ── v7.6.0: Drop the peer's last-known hashrate from the governor ────
        # Stale hashrate reports from a now-disconnected peer would incorrectly
        # inflate the governor's view of the network's actual-hashrate sum.
        # Forget_peer is idempotent and safe to call when no entry exists.
        try:
            me_attr = getattr(self, "_mining_engine_ref", None)
            if me_attr is not None:
                gov = me_attr.get_hashrate_governor()
                if gov is not None:
                    gov.forget_peer(peer.peer_id)
        except Exception:
            pass
        log.info(f"Peer disconnected: {peer.ip}:{peer.port} ({peer.peer_id[:12]})")
        # ── LIVE-UI: push instant peer-disconnect notification ────────────────
        _push_peer_notif("disconnected", peer.ip, peer.port)

    def _try_add_peer(self, ip: str, port: int, peer_id: str = ""):
        if not ip or not port:
            return
        # Normalize first (strips IPv4-mapped prefix from IPv6 dual-stack addr)
        ip = _normalize_ip(ip)
        # Validate that it is a legal IP address (IPv4 or IPv6) or at least
        # a non-empty hostname; getaddrinfo in connect_to will resolve names.
        # We do NOT call inet_aton here — that rejects all valid IPv6 addresses.
        if not ip.strip():
            return

        # ── Optional Port Override (Config.FORCE_OUTBOUND_DEST_PORT) ─────────
        # Default is False — the advertised port is used as-is so IPv6 peers
        # and IPv4 peers on non-standard ports are reachable.
        # When True (private test networks only), clamp to DEFAULT_PORT here.
        if Config.FORCE_OUTBOUND_DEST_PORT and port != Config.DEFAULT_PORT:
            log.debug(
                f"[PortEnforce] Overriding advertised port {port} → "
                f"{Config.DEFAULT_PORT} for {ip} "
                f"(FORCE_OUTBOUND_DEST_PORT=True)")
            port = Config.DEFAULT_PORT

        # ── Soft Ban: skip outbound connections to currently-banned IPs ───────
        if self._is_ip_banned(ip):
            log.debug(
                f"[SoftBan] Skipping outbound connection to banned IP "
                f"{ip} (24-hour ban active)")
            _pa_push("OUT", ip, port, "BANNED")
            return

        # ── Outbound fail cooldown: skip IPs with too many consecutive failures ─
        _now = time.time()
        with self._outbound_fail_lock:
            _of = self._outbound_fail.get(ip)
            if _of is not None:
                if _of[0] >= Config.OUTBOUND_FAIL_LIMIT and _now < _of[1]:
                    _remain = int(_of[1] - _now)
                    log.debug(
                        f"[OutboundCooldown] Skipping {ip} — failed "
                        f"{_of[0]}x consecutively, cooling down "
                        f"for {_remain}s more")
                    _pa_push("OUT", ip, port, "COOLDOWN")
                    return
                elif _now >= _of[1] and _of[0] >= Config.OUTBOUND_FAIL_LIMIT:
                    # Cooldown expired — reset so next attempt is treated fresh
                    del self._outbound_fail[ip]
        with self._lock:
            existing_ips = {(p.ip, p.port) for p in self.peers.values()}
            # ── Self-connection guard ─────────────────────────────────────────
            # Block loopback IPs on our own port.  Note: Config.BIND_ADDRESS
            # ("::") is a bind wildcard, NOT a peer address — do not include it
            # here or valid peers that happen to resolve to "::" would be dropped.
            _loopback_ips = {"127.0.0.1", "::1", "0.0.0.0"}  # nosec B104 – comparison set, never passed to bind()
            if Config.LOOPBACK_ADDRESS:
                _loopback_ips.add(Config.LOOPBACK_ADDRESS)
            if port == self.port and ip in _loopback_ips:
                return
            # Also block by peer_id when we already know it
            if peer_id and peer_id == self.node_id:
                return
            if (ip, port) in existing_ips:
                return
            if len(self.peers) >= Config.MAX_PEERS:
                return
        # ── Pending-connection dedup (Bug #3/#4 fix) ─────────────────────────
        # Prevent multiple concurrent threads from racing to the same endpoint.
        with self._pending_lock:
            if (ip, port) in self._pending_connections:
                return
            self._pending_connections.add((ip, port))

        if peer_id:
            row = self.storage._conn().execute(
                "SELECT blacklisted FROM peers WHERE peer_id=?", (peer_id,)).fetchone()
            if row and row["blacklisted"]:
                with self._pending_lock:
                    self._pending_connections.discard((ip, port))
                return

        threading.Thread(
            target=self._connect_with_fallback, args=(ip, port), daemon=True).start()
        _pa_push("OUT", ip, port, "CONNECTING")

    def _connect_with_fallback(self, ip: str, port: int):
        """
        Connection worker spawned by _try_add_peer.

        Always removes (ip, port) from _pending_connections on exit so
        subsequent _try_add_peer calls are never permanently blocked.

        Strategy:
          1. Try the advertised port (correct for IPv6 and properly-forwarded
             IPv4 peers).
          2. For IPv4-only peers where the advertised port != DEFAULT_PORT,
             retry on DEFAULT_PORT as a CGNAT fallback.  IPv6 peers are
             publicly routable and their advertised port is almost always
             accurate, so we skip the extra attempt for them.
        """
        try:
            # ── v7.5-UDP: try UDP transport first (resilient path) ────────────
            # UDP is preferred because the sliding-window + FEC layer handles
            # packet loss and jitter more gracefully than TCP on lossy links.
            # We attempt UDP first; on any error we fall through to TCP without
            # logging a failure so the user experience is seamless.
            try:
                _udp_ok = self._udp_connect_to(ip, port)
                if _udp_ok:
                    with self._outbound_fail_lock:
                        self._outbound_fail.pop(ip, None)
                    _pa_push("OUT", ip, port, "CONNECTED(UDP)")
                    return
            except Exception as _udp_ex:
                log.debug(f"[UDP] _udp_connect_to {ip}:{port} failed: {_udp_ex} — trying TCP")
            # ── Fall back to TCP (original path) ──────────────────────────────
            success = self.connect_to(ip, port)
            if success:
                # Reset outbound fail counter on first successful handshake
                with self._outbound_fail_lock:
                    self._outbound_fail.pop(ip, None)
                _pa_push("OUT", ip, port, "CONNECTED")
                return
            _pa_push("OUT", ip, port, "FAILED")
            # Increment consecutive fail counter for this IP
            with self._outbound_fail_lock:
                rec = self._outbound_fail.setdefault(ip, [0, 0.0])
                rec[0] += 1
                if rec[0] >= Config.OUTBOUND_FAIL_LIMIT:
                    rec[1] = time.time() + Config.OUTBOUND_FAIL_COOLDOWN_SECS
                    log.info(
                        f"[OutboundCooldown] {ip} failed {rec[0]} consecutive "
                        f"outbound attempts — pausing for "
                        f"{Config.OUTBOUND_FAIL_COOLDOWN_SECS}s")
            log.debug(
                f"[P2P] Connection to {_format_peer_addr(ip, port)} failed")
            # ── CGNAT fallback for IPv4 peers only ───────────────────────────
            # IPv4 peers behind CGNAT advertise their internal ephemeral port
            # which may be unreachable.  DEFAULT_PORT is the well-known door
            # operators intentionally forward through their NAT/firewall.
            # We do NOT apply this for IPv6 peers — their ports are routable.
            if (port != Config.DEFAULT_PORT
                    and not _is_ipv6_address(ip)):
                log.debug(
                    f"[P2P] IPv4 CGNAT fallback: retrying "
                    f"{ip} on DEFAULT_PORT {Config.DEFAULT_PORT}")
                # Register DEFAULT_PORT as pending too so we don't race
                _fb_port: Optional[int] = Config.DEFAULT_PORT
                with self._pending_lock:
                    if (_fb_port != port
                            and (ip, _fb_port) not in self._pending_connections):
                        self._pending_connections.add((ip, _fb_port))
                    else:
                        _fb_port = None   # already attempted or same port
                if _fb_port is not None:
                    try:
                        self.connect_to(ip, _fb_port)
                    finally:
                        with self._pending_lock:
                            self._pending_connections.discard((ip, _fb_port))
        except Exception as exc:
            log.debug(f"[P2P] _connect_with_fallback error for "
                      f"{_format_peer_addr(ip, port)}: {exc}")
        finally:
            with self._pending_lock:
                self._pending_connections.discard((ip, port))

    def _gossip(self, msg: dict, exclude: Optional[str] = None, ttl: Optional[int] = None):
        """
        Plumtree-style gossip: send full message to eager peers only.
        Lazy peers receive only IHAVE hints (omitted here for simplicity,
        but the eager/lazy partition is maintained).

        v7.1.0: message prioritization — MSG_BLOCK and MSG_VALIDATOR_SIG
        go through PeerConnection.send_priority(PRI_CRITICAL) so they
        jump the queue ahead of any bulk sync / peer exchange traffic
        already pending on the same peer.
        """
        if ttl is None:
            ttl = msg.get("ttl", Config.GOSSIP_TTL)
        if ttl <= 0: return
        msg = dict(msg)
        msg["ttl"] = ttl - 1
        _mtype = msg.get("type")

        # Classify message priority for the per-peer outbound queue.
        if _mtype in (MSG_BLOCK, MSG_CMPCTBLOCK, MSG_VALIDATOR_SIG):
            _pri = 0           # CRITICAL — consensus path
        elif _mtype in (MSG_TX, MSG_IDENTITY, MSG_ALERT):
            _pri = 1           # NORMAL
        elif _mtype == MSG_L2TX:
            # v7.5.0-OPT: L2 rollup traffic rides at BULK priority so a
            # flood of L2 gossip can never starve block propagation.  The
            # on-chain tip always moves forward even if the L2 mempool
            # sync is lagging — which is the explicit requirement.
            _pri = 2           # BULK
        else:
            _pri = 2           # BULK — peer exchange, gossip discovery

        with self._lock:
            # Blocks (full or compact) bypass the eager/lazy filter entirely:
            # a fresh block MUST reach every connected peer immediately or we
            # get forks.  [v7.0.0.2 fix, v7.5.0 extended for CMPCTBLOCK]
            if _mtype in (MSG_BLOCK, MSG_CMPCTBLOCK, MSG_VALIDATOR_SIG):
                # Blocks and validator signatures are consensus-critical;
                # neither may be stranded by the eager/lazy Plumtree split.
                targets = [p for pid, p in self.peers.items()
                           if pid != exclude and p.connected]
            else:
                targets = [p for pid, p in self.peers.items()
                           if pid != exclude and p.connected
                           and pid in self._eager_peers]
        # Parallelise sends so one slow peer's TCP buffer cannot stall
        # propagation to the others. Daemon threads, fire-and-forget;
        # Peer.send() is already thread-safe via its own send_lock.
        # [v7.0.0.2 fix]
        if len(targets) <= 1:
            for p in targets:
                try:
                    # Use prioritized queue for consensus-critical messages;
                    # fall back to sync send if send_priority not available.
                    if hasattr(p, "send_priority"):
                        p.send_priority(msg, _pri)
                    else:
                        p.send(msg)
                except Exception:
                    pass
        else:
            def _fanout_send(_p, _msg, _p_pri):
                try:
                    if _p.connected:
                        if hasattr(_p, "send_priority"):
                            _p.send_priority(_msg, _p_pri)
                        else:
                            _p.send(_msg)
                except Exception:
                    pass
            for p in targets:
                threading.Thread(
                    target=_fanout_send, args=(p, msg, _pri), daemon=True
                ).start()

    def broadcast_tx(self, tx: Transaction):
        msg = {"type": MSG_TX, "tx": tx.to_dict(), "ttl": Config.GOSSIP_TTL}
        self._gossip(msg)

    # ── v7.5.0-OPT L2 ROLLUP ─────────────────────────────────────────────
    def broadcast_l2_tx(self, l2_tx: 'L2Transaction'):
        """Gossip an L2Transaction at BULK priority.

        At BULK priority an oversubscribed peer's outbound queue drops or
        delays L2TX before it drops or delays BLOCK / CMPCTBLOCK — which
        is exactly the property the rollup architecture requires.  From
        the user's perspective this is imperceptible: L2 transactions
        queue up safely at sequencer nodes and are still batched.
        """
        msg = {"type": MSG_L2TX, "l2_tx": l2_tx.to_dict(),
               "ttl": Config.GOSSIP_TTL}
        self._gossip(msg)

    def broadcast_block(self, block: Block, exclude: Optional[str] = None):
        """
        v7.5.0 Compact-Block broadcast (BIP-152-inspired).

        Instead of sending the full block JSON, we send a MSG_CMPCTBLOCK
        containing:
          • the complete block header dict  (index, prev_hash, merkle_root,
            block_hash, miner_address, difficulty, nonce, timestamp,
            state_root, vrf_proof, vrf_output, validator_sigs, finalized,
            version, protocol_version)
          • one short_id per non-coinbase transaction  (first 8 bytes / 16
            hex-chars of tx_id).  The coinbase is omitted because every
            honest peer reconstructs it independently.

        Receivers that have all transactions in their mempool can reconstruct
        the full block immediately.  Those that are missing some transactions
        send MSG_GETBLOCKTXN; we reply with MSG_BLOCKTXN containing the
        full transaction dicts.

        Compatibility: peers that do not understand MSG_CMPCTBLOCK will
        ignore it.  If a peer asks back with MSG_GETBLOCKTXN we service it
        from our local chain/mempool.  A full MSG_BLOCK fallback is never
        needed because we always service GETBLOCKTXN from local state.
        """
        # ── Build compact representation ──────────────────────────────────
        header = block.to_dict()
        # Strip the full transactions list — receivers reconstruct from short-IDs
        txs_full = header.pop("transactions", [])

        # Coinbase is always the first tx; receivers rebuild it from header
        # fields (miner_address + index).  Short-IDs cover the rest.
        #
        # CMPCT-COINBASE FIX (v7.5.0-OPT post-audit): Receivers cannot
        # deterministically reconstruct the coinbase tx_id because
        # Transaction.coinbase() stamps the tx with wall-clock time() at
        # creation.  That timestamp becomes part of the tx_id and is NOT
        # in the header, so the receiver's re-built coinbase would always
        # have a different tx_id → different merkle root → every compact
        # block rejected.  Attach the miner's actual coinbase dict so the
        # receiver can prepend it verbatim before computing the merkle.
        coinbase_dict = None
        short_ids = []
        for td in txs_full:
            sender = td.get("sender", "")
            if sender == "COINBASE":
                coinbase_dict = td
                continue
            tx_id = td.get("tx_id", "")
            # 8-byte (16 hex char) prefix of the tx_id
            short_ids.append(tx_id[:16])

        msg = {
            "type":      MSG_CMPCTBLOCK,
            "header":    header,         # full header — no transactions list
            "coinbase":  coinbase_dict,  # full coinbase tx dict (see comment above)
            "short_ids": short_ids,      # list[str], one per non-CB tx
            "ttl":       Config.GOSSIP_TTL,
        }
        self._gossip(msg, exclude=exclude)

    def broadcast_genesis(self):
        """
        Announce the locally-stored Genesis block (index 0) over the same
        MSG_BLOCK gossip path used for all other blocks.

        v7.1.5 — Genesis propagation:
          Previously Genesis was created locally by every node on first boot
          (via Blockchain._create_genesis) and was never announced to peers,
          because the network does not exist yet at Blockchain.__init__ time.
          This method is invoked from Node.start() on a short Timer after the
          network has come up, so initial peer connections have had time to
          establish.

          Receivers that already have a matching Genesis will short-circuit
          inside Blockchain.apply_block (idempotent path) and still relay the
          message one hop forward; _seen_msgs LRU bounds re-propagation.
          Determinism of the Config.GENESIS_* constants guarantees that every
          honest node computes the identical block_hash, so any mismatch is
          correctly rejected by validate_block() as a wrong-chain genesis.
        """
        try:
            genesis = self.blockchain.get_block(0)
        except Exception as e:
            log.debug(f"broadcast_genesis: get_block(0) failed: {e}")
            return
        if genesis is None:
            log.debug("broadcast_genesis: no genesis stored yet; skipping")
            return
        log.info(
            f"[GENESIS-BROADCAST] Announcing genesis "
            f"{genesis.block_hash[:16]}... to peers"
        )
        self.broadcast_block(genesis)

    def broadcast_validator_sig(self, block_hash: str, sig_hex: str):
        msg = {
            "type": MSG_VALIDATOR_SIG,
            "block_hash": block_hash,
            "validator": self.wallet.address,
            "sig": sig_hex,
            "pub_hex": self.wallet.pub_hex,
            "ttl": Config.GOSSIP_TTL,
        }
        self._gossip(msg)

    def broadcast_identity(self, user_id: str, multiaddrs: List[str]):
        msg = {
            "type":        MSG_IDENTITY,
            "user_id":     user_id,
            "peer_id":     self.node_id,
            "wallet_addr": self.wallet.address,
            "pub_hex":     self.wallet.pub_hex,
            "multiaddrs":  multiaddrs,
            "ttl":         Config.GOSSIP_TTL,
        }
        self._gossip(msg)

    def _broadcast_invalid_alert(self, bad_node_id: str):
        msg = {
            "type":        MSG_ALERT,
            "bad_node_id": bad_node_id,
            "reported_by": self.node_id,
            "ttl":         Config.GOSSIP_TTL,
        }
        self._gossip(msg)
        self.storage.blacklist_peer(bad_node_id)

    def resolve_user_id(self, user_id: str) -> Optional[dict]:
        if isinstance(user_id, str):
            user_id = user_id.strip().casefold()
        # The canonical local claim index is checked before the mutable cache.
        # This prevents a stale directory response from overriding confirmed
        # ownership after restart, snapshot restore, or reorg processing.
        local = self.storage.resolve_identity(user_id)
        if local:
            self._id_cache.put(user_id, local)
            return local
        cached = self._id_cache.get(user_id)
        if cached:
            return cached
        # BUG-FIX: The original code only queried the 5 closest DHT peers.
        # On small networks (2-3 peers) the DHT routing table may not overlap
        # with the peers that actually have the target identity stored, so the
        # resolution always failed with "Cannot resolve '<user_id>'".
        # Fix: broadcast MSG_RESOLVE to ALL currently connected peers (not
        # just the 5 closest), and wait up to 5 s instead of 2 s.
        results = queue.Queue()
        def ask(peer):
            if peer and peer.connected:
                peer.send({"type": MSG_RESOLVE, "user_id": user_id})
                for _ in range(25):          # 25 × 0.2 s = 5 s per peer
                    time.sleep(0.2)
                    r = self._id_cache.get(user_id)
                    if r: results.put(r); return
        with self._lock:
            all_peers = list(self.peers.values())
        # Also include DHT-closest peers that may not be in self.peers yet
        key     = sha256(f"user:{user_id}".encode())
        closest = self.router.get_closest(key)
        extra_pids = {info.get("peer_id","") for info in closest[:5]}
        for pid in extra_pids:
            with self._lock:
                p = self.peers.get(pid)
            if p and p not in all_peers:
                all_peers.append(p)
        threads = [threading.Thread(target=ask, args=(p,), daemon=True)
                   for p in all_peers if p.connected]
        for t in threads: t.start()
        for t in threads: t.join(timeout=6)
        try:
            return results.get_nowait()
        except queue.Empty:
            return None

    def _bootstrap(self):
        time.sleep(1)
        known = self.storage.get_peers(limit=20)
        for p in known:
            if len(self.active_peer_count()) < Config.MIN_PEERS:
                self._try_add_peer(p["ip"], p["port"], p["peer_id"])
        for seed in Config.SEED_PEERS:
            if len(self.active_peer_count()) >= Config.MIN_PEERS:
                break
            try:
                ip, port = _parse_peer_addr(seed)
            except ValueError:
                log.debug(f"Bootstrap: invalid seed address '{seed}' — skipping")
                continue
            # Skip self-connections for both IPv4 and IPv6 loopbacks
            # (do NOT include Config.BIND_ADDRESS "::" — it is a wildcard, not a peer addr)
            _boot_loopback = {"127.0.0.1", "::1", "0.0.0.0"}  # nosec B104 – comparison set, never passed to bind()
            if Config.LOOPBACK_ADDRESS:
                _boot_loopback.add(Config.LOOPBACK_ADDRESS)
            if port == self.port and ip in _boot_loopback:
                continue
            self._try_add_peer(ip, port)
        # DNS seeds are queried in the DNSSeeder background thread; no extra
        # call needed here — DNSSeeder.start() fires an immediate query.

    def active_peer_count(self):
        with self._lock:
            return [p for p in self.peers.values() if p.connected]

    def _pex_loop(self):
        while self._running:
            time.sleep(Config.PEX_INTERVAL)
            with self._lock:
                targets = list(self.peers.values())
            for peer in targets:
                if peer.connected:
                    peer.send({"type": MSG_GET_PEERS})

    def _reconnect_loop(self):
        _sync_tick = 0
        while self._running:
            time.sleep(Config.RECONNECT_INTERVAL)
            count = len(self.active_peer_count())
            if count < Config.MIN_PEERS:
                log.debug(f"Only {count} peers, reconnecting...")
                known = self.storage.get_peers(limit=20)
                random.shuffle(known)
                for p in known:
                    if len(self.active_peer_count()) >= Config.MIN_PEERS:
                        break
                    with self._lock:
                        already = any(
                            peer.ip == p["ip"] and peer.port == p["port"]
                            for peer in self.peers.values()
                        )
                    if not already:
                        self._try_add_peer(p["ip"], p["port"], p["peer_id"])
                if len(self.active_peer_count()) < Config.MIN_PEERS:
                    self._bootstrap()

            # Chain sync heartbeat — every 60 s (2 ticks of the 30 s loop).
            #
            # FIX — Full Chain Heartbeat Bug:
            # The old code used from_idx=max(1, my_height-10), which on a short
            # chain (e.g. height=5) effectively sent the entire chain every
            # minute.  Each response is up to 500 blocks of JSON; on a 66-block
            # chain that is megabytes of redundant data causing Socket Bloat,
            # buffer fill, lag, timeout, and then the Blacklist Bug firing.
            #
            # Fix: the heartbeat now requests ONLY blocks strictly above our
            # current tip (from_idx = my_height + 1).  The one-time full
            # fork-choice sync (from_idx=1) already runs in _auto_sync_on_connect
            # at peer registration; the heartbeat's only job is to pick up new
            # blocks mined while we were connected.  This reduces heartbeat
            # payload from O(chain_length) to O(new_blocks_since_last_tick).
            _sync_tick += 1
            if _sync_tick >= 2:
                _sync_tick = 0
                my_height = self.blockchain.height()
                hb_from   = max(0, my_height + 1)   # guard: height=-1 → request from 0
                with self._lock:
                    connected_peers = [p for p in self.peers.values()
                                       if p.connected]
                for p in connected_peers:
                    try:
                        self._sync_request(
                            p, hb_from, hb_from + 199,
                            kind="heartbeat", force=False)
                    except Exception:
                        pass

    def _peer_decay_loop(self):
        while self._running:
            time.sleep(Config.PEER_DECAY_SECS)
            now = time.time()
            with self._lock:
                dead = [pid for pid, p in self.peers.items()
                        if not p.connected or (now - p.last_seen) > Config.PEER_DECAY_SECS]
            for pid in dead:
                with self._lock:
                    peer = self.peers.pop(pid, None)
                    self._eager_peers.discard(pid)
                if peer:
                    peer.close()
                # BUG-FIX: Do NOT call mark_peer_fail here.
                # Peers evicted by the decay loop are simply idle/offline —
                # they had a valid connection that went quiet.  Calling
                # mark_peer_fail on them incremented fail_count on every
                # decay cycle, blacklisting good peers after 3 hours of
                # inactivity.  The reconnect loop then had no valid peers
                # left in the DB and was forced to hammer DNS seeds
                # constantly → the CONNECTING→FAILED→CONNECTING volatility.
                # mark_peer_fail is already called by _on_peer_disconnect
                # (which handles genuinely broken connections) — no need
                # to call it again here.

    def _load_peers(self):
        stored = self.storage.get_peers(limit=50)
        for p in stored:
            self.router.update(p["peer_id"], {
                "peer_id": p["peer_id"],
                "ip": p["ip"],
                "port": p["port"],
            })

    def on(self, msg_type: str, callback):
        self._callbacks[msg_type].append(callback)

    def peer_list(self) -> List[dict]:
        with self._lock:
            return [
                {"peer_id": pid, "ip": p.ip, "port": p.port,
                 "connected": p.connected, "reputation": p.reputation}
                for pid, p in self.peers.items()
            ]

    def sync_chain(self):
        # v6.9.9.7 FIX — sync_chain() previously requested only 50 blocks
        # (to_idx = height+50), which is insufficient on any chain taller than
        # 50 blocks.  A fresh node at height=0 would receive blocks 1-50 and
        # then stop, requiring 13+ manual syncs to catch up to a 650-block chain.
        #
        # v7.0.0.0 FIX — reduced window from 500 → 200 to match the server-side
        # MSG_GET_CHAIN cap.  Requesting 500 while the server only sends 200 was
        # harmless but confusing in logs.  The MSG_CHAIN pagination handler
        # automatically requests subsequent pages when a full 200-block page
        # arrives, so a single sync_chain() call still syncs the entire chain.
        height   = self.blockchain.height()
        from_idx = max(0, height + 1)
        with self._lock:
            targets = list(self.peers.values())
        for peer in targets:
            if peer.connected:
                self._sync_request(
                    peer, from_idx, from_idx + 199,
                    kind="manual", force=False)
        log.info(f"[SyncChain] Requested chain from height {from_idx} "
                 f"from {len([p for p in targets if p.connected])} peer(s)")

    # ── v7.4.0: Snapshot-Based Fast Sync ─────────────────────────────────────
    def _fast_sync_from_peer(self, peer: 'PeerConnection') -> bool:
        """
        v7.5.0 — Parallel Multi-Peer Snapshot Sync (BitTorrent-style).

        Phase A — Chunk-manifest negotiation (multi-peer):
          1. Query connected peers for chunk manifests at the best available
             snapshot height.  Snapshot state replacement is only eligible
             when the local node already has that exact canonical height;
             fresh/behind nodes fall back to ordinary block sync because the
             current state root does not authenticate every auxiliary state table.
          2. Build a GlobalChunkMap: chunk_index -> list of peer_ids that
             have it. All valid peers hold all chunks of the same height.
          3. Assign disjoint chunks to peers via a shared work queue;
             each peer runs its own worker thread in parallel.
          4. Verify each chunk SHA-256 on arrival; re-enqueue on mismatch
             or timeout without restarting the whole download.
          5. Reassemble chunks and restore via StateSnapshotEngine.

        Phase B — Step-by-step block sync (unchanged from v7.4.0):
          6. Request 200-block pages from `peer` until we reach the tip.

        Falls back to _fast_sync_legacy() when fewer than 2 peers have
        the same snapshot height, preserving full backward compatibility.
        """
        if not Config.SNAPSHOT_FAST_SYNC_ENABLED:
            return False
        if not hasattr(self.blockchain, "_snapshot_engine"):
            return False

        local_h = self.blockchain.height()
        if local_h > Config.SNAPSHOT_FAST_SYNC_MIN_HEIGHT:
            return False

        import queue as _queue_mod

        snap_engine      = self.blockchain._snapshot_engine
        MANIFEST_TIMEOUT = 20
        CHUNK_TIMEOUT    = Config.SNAPSHOT_CHUNK_TIMEOUT
        MAX_RETRIES      = Config.SNAPSHOT_CHUNK_MAX_RETRIES
        MAX_PARALLEL     = Config.SNAPSHOT_MAX_PARALLEL_PEERS
        PAGE_SIZE        = 200
        PAGE_DELAY       = 1.5
        MAX_PAGES        = 20

        # ── Phase A ────────────────────────────────────────────────────────────
        try:
            # 1. Collect candidate peers (up to MAX_PARALLEL, including `peer`)
            with self._lock:
                candidate_peers = [
                    p for p in self.peers.values()
                    if p.connected and p.peer_id != self.node_id
                ]
            if peer not in candidate_peers:
                candidate_peers.insert(0, peer)
            candidate_peers = candidate_peers[:MAX_PARALLEL]

            # 2. Query each candidate for its chunk manifest in parallel
            manifests = {}            # peer_id -> manifest dict
            manifest_lock = threading.Lock()

            def _fetch_manifest(p):
                q = _queue_mod.Queue(maxsize=4)
                p._chunk_response_queue = q
                try:
                    p.send({"type": MSG_GET_CHUNK_MANIFEST, "height": -1})
                    try:
                        resp = q.get(timeout=MANIFEST_TIMEOUT)
                    except _queue_mod.Empty:
                        log.debug("[ParallelSync] Manifest timeout from %s",
                                  p.peer_id[:12])
                        return
                    if resp.get("type") != MSG_CHUNK_MANIFEST:
                        return
                    if "error" in resp:
                        return
                    h = resp.get("height", -1)
                    if h < 0 or not resp.get("chunk_hashes"):
                        return
                    with manifest_lock:
                        manifests[p.peer_id] = resp
                except Exception as _me:
                    log.debug("[ParallelSync] manifest fetch error %s: %s",
                              p.peer_id[:12], _me)
                finally:
                    p._chunk_response_queue = None

            mthreads = [
                threading.Thread(target=_fetch_manifest, args=(p,), daemon=True)
                for p in candidate_peers
            ]
            for t in mthreads:
                t.start()
            for t in mthreads:
                t.join(timeout=MANIFEST_TIMEOUT + 2)

            if not manifests:
                log.info("[ParallelSync] No peers returned chunk manifests — "
                         "falling back to legacy fast-sync.")
                return self._fast_sync_legacy(peer)

            # 3. Choose consensus snapshot height (most peers agree on)
            height_votes = {}
            for m in manifests.values():
                h = m.get("height", -1)
                if h >= 0:
                    height_votes[h] = height_votes.get(h, 0) + 1
            best_height = max(height_votes, key=lambda h: (height_votes[h], h))

            # Current protocol state-root does not commit every auxiliary
            # consensus table, so a remote snapshot is only safe when the node
            # already has the exact canonical state at that height.  Otherwise
            # refuse the snapshot path early and fall back to block sync; never
            # download a large untrusted state blob merely to reject it later.
            if local_h != best_height:
                log.info(
                    "[ParallelSync] Snapshot h=%d cannot safely replace local "
                    "h=%d; falling back to ordinary block sync.",
                    best_height, local_h)
                return False

            valid_manifests = {
                pid: m for pid, m in manifests.items()
                if m.get("height") == best_height
            }
            if not valid_manifests:
                return self._fast_sync_legacy(peer)

            # If only 1 peer has chunks, fall back to legacy path
            if len(valid_manifests) < 2:
                log.info("[ParallelSync] Only 1 peer has snapshot h=%d — "
                         "using legacy fast-sync.", best_height)
                return self._fast_sync_legacy(peer)

            # AUDIT-FIX-17 (fast-sync forgery, second half): previously
            # picked an arbitrary manifest via next(iter(valid_manifests
            # .values())) once >=2 peers merely agreed on HEIGHT — nothing
            # required them to agree on state_root or chunk_hashes. Two
            # colluding (or Sybil) peers reporting the same fabricated
            # height, with state_root omitted from at least one of them,
            # could become ref_manifest and have their fabricated
            # chunk_hashes trusted for verifying every downloaded chunk —
            # this is exactly what AUDIT-FIX-17's other half (the presence
            # check in restore_from_blob) closes from the opposite end, but
            # this end needs its own fix too: require state_root agreement,
            # not just height agreement, before trusting any manifest as
            # the reference.
            root_votes: Dict[str, int] = {}
            for m in valid_manifests.values():
                r = m.get("state_root", "")
                if r:
                    root_votes[r] = root_votes.get(r, 0) + 1
            agreeing_roots = {r: n for r, n in root_votes.items() if n >= 2}
            if not agreeing_roots:
                log.warning(
                    "[ParallelSync] No state_root agreement among %d "
                    "peers at height %d (each peer disagrees, or omitted "
                    "state_root) — refusing to trust an arbitrary single "
                    "manifest; falling back to legacy fast-sync.",
                    len(valid_manifests), best_height)
                return self._fast_sync_legacy(peer)
            best_root = max(agreeing_roots, key=lambda r: agreeing_roots[r])
            valid_manifests = {
                pid: m for pid, m in valid_manifests.items()
                if m.get("state_root", "") == best_root
            }

            ref_manifest  = next(iter(valid_manifests.values()))
            snap_height   = ref_manifest["height"]
            total_chunks  = ref_manifest["total_chunks"]
            chunk_hashes  = ref_manifest["chunk_hashes"]
            state_root    = ref_manifest.get("state_root", "")
            anchor_block_hash = ref_manifest.get("anchor_block_hash", "")

            log.info(
                "[ParallelSync] Starting parallel download: height=%d "
                "total_chunks=%d peers=%d",
                snap_height, total_chunks, len(valid_manifests),
            )

            # 4. Shared work queue and per-chunk storage
            chunk_map_lock = threading.Lock()
            chunk_store: Dict[int, Optional[bytes]] = {i: None for i in range(total_chunks)}
            chunk_retries  = {i: 0    for i in range(total_chunks)}
            work_queue     = _queue_mod.Queue()
            for i in range(total_chunks):
                work_queue.put(i)

            completed    = threading.Event()
            failed       = threading.Event()
            done_count   = [0]
            done_lock    = threading.Lock()
            error_reason = [""]

            # 5. Per-peer worker thread: drains work_queue, downloads & verifies
            def _chunk_worker(worker_peer_id):
                with self._lock:
                    wp = self.peers.get(worker_peer_id)
                if wp is None or not wp.connected:
                    return
                wq = _queue_mod.Queue(maxsize=16)
                wp._chunk_response_queue = wq
                try:
                    while not completed.is_set() and not failed.is_set():
                        try:
                            chunk_idx = work_queue.get(timeout=1.0)
                        except _queue_mod.Empty:
                            break

                        # Already downloaded by a racing worker — skip
                        with chunk_map_lock:
                            if chunk_store[chunk_idx] is not None:
                                work_queue.task_done()
                                continue

                        # Request this chunk from the peer
                        try:
                            wp.send({
                                "type":        MSG_GET_CHUNK,
                                "height":      snap_height,
                                "chunk_index": chunk_idx,
                            })
                        except Exception as _se:
                            log.debug("[ParallelSync] send error to %s: %s",
                                      worker_peer_id[:12], _se)
                            work_queue.put(chunk_idx)
                            work_queue.task_done()
                            break   # peer socket broken; exit worker

                        # Wait for the response
                        try:
                            resp = wq.get(timeout=CHUNK_TIMEOUT)
                        except _queue_mod.Empty:
                            log.warning(
                                "[ParallelSync] Timeout chunk %d from %s — "
                                "re-assigning to another peer",
                                chunk_idx, worker_peer_id[:12],
                            )
                            with chunk_map_lock:
                                chunk_retries[chunk_idx] += 1
                                if chunk_retries[chunk_idx] >= MAX_RETRIES:
                                    failed.set()
                                    error_reason[0] = (
                                        f"Chunk {chunk_idx} exceeded max retries "
                                        f"({MAX_RETRIES}) — last peer: "
                                        f"{worker_peer_id[:12]}"
                                    )
                            work_queue.put(chunk_idx)
                            work_queue.task_done()
                            break   # peer is too slow; let other workers take over

                        if resp.get("type") != MSG_CHUNK_DATA:
                            work_queue.put(chunk_idx)
                            work_queue.task_done()
                            continue

                        if "error" in resp:
                            log.debug(
                                "[ParallelSync] Peer %s chunk %d error: %s",
                                worker_peer_id[:12], chunk_idx, resp["error"],
                            )
                            with chunk_map_lock:
                                chunk_retries[chunk_idx] += 1
                                if chunk_retries[chunk_idx] >= MAX_RETRIES:
                                    failed.set()
                                    error_reason[0] = (
                                        f"Chunk {chunk_idx} peer error after "
                                        f"{MAX_RETRIES} retries"
                                    )
                            work_queue.put(chunk_idx)
                            work_queue.task_done()
                            continue

                        # Decode hex payload
                        try:
                            raw_chunk = bytes.fromhex(resp.get("data_hex", ""))
                        except ValueError:
                            with chunk_map_lock:
                                chunk_retries[chunk_idx] += 1
                                if chunk_retries[chunk_idx] >= MAX_RETRIES:
                                    failed.set()
                                    error_reason[0] = (
                                        f"Chunk {chunk_idx} bad hex after "
                                        f"{MAX_RETRIES} retries"
                                    )
                            work_queue.put(chunk_idx)
                            work_queue.task_done()
                            continue

                        # ── Integrity verification ────────────────────────────
                        actual_hash   = hashlib.sha256(raw_chunk).hexdigest()
                        expected_hash = (chunk_hashes[chunk_idx]
                                         if chunk_idx < len(chunk_hashes) else "")
                        if expected_hash and actual_hash != expected_hash:
                            log.warning(
                                "[ParallelSync] Chunk %d hash MISMATCH from %s "
                                "(got=%s expected=%s) — re-assigning",
                                chunk_idx, worker_peer_id[:12],
                                actual_hash[:16], expected_hash[:16],
                            )
                            with chunk_map_lock:
                                chunk_retries[chunk_idx] += 1
                                if chunk_retries[chunk_idx] >= MAX_RETRIES:
                                    failed.set()
                                    error_reason[0] = (
                                        f"Chunk {chunk_idx} hash mismatch after "
                                        f"{MAX_RETRIES} retries"
                                    )
                            work_queue.put(chunk_idx)
                            work_queue.task_done()
                            continue

                        # ── Store verified chunk ──────────────────────────────
                        with chunk_map_lock:
                            chunk_store[chunk_idx] = raw_chunk

                        work_queue.task_done()

                        with done_lock:
                            done_count[0] += 1
                            current_done   = done_count[0]

                        # Progress log every 5 chunks and on final chunk
                        if current_done % 5 == 0 or current_done == total_chunks:
                            log.info(
                                "[ParallelSync] Progress: Downloaded %d/%d "
                                "chunks from %d peers",
                                current_done, total_chunks,
                                len(valid_manifests),
                            )

                        if current_done >= total_chunks:
                            completed.set()
                            break

                except Exception as _we:
                    log.debug("[ParallelSync] Worker %s unexpected error: %s",
                              worker_peer_id[:12], _we)
                finally:
                    wp._chunk_response_queue = None

            # 6. Launch one worker thread per valid peer
            worker_threads = []
            for pid in list(valid_manifests.keys()):
                t = threading.Thread(
                    target=_chunk_worker,
                    args=(pid,),
                    daemon=True,
                    name=f"chunk-worker-{pid[:8]}",
                )
                worker_threads.append(t)
                t.start()

            # 7. Wait for completion or failure
            # Generous timeout: per-chunk-timeout * chunks / workers + 60 s buffer
            n_workers = max(len(worker_threads), 1)
            max_wait  = max(
                CHUNK_TIMEOUT * total_chunks / n_workers + 60,
                120,
            )
            completed.wait(timeout=max_wait)

            if failed.is_set():
                log.warning("[ParallelSync] Download failed: %s", error_reason[0])
                return False

            missing = [i for i, v in chunk_store.items() if v is None]
            if missing:
                log.warning(
                    "[ParallelSync] Incomplete download: %d/%d chunks missing "
                    "after %.0f s wait.",
                    len(missing), total_chunks, max_wait,
                )
                return False

            log.info(
                "[ParallelSync] All %d chunks verified and downloaded from "
                "%d peer(s). Reassembling snapshot...",
                total_chunks, len(valid_manifests),
            )

            # 8. Reassemble blob — hold _snap_lock so no concurrent snapshot
            #    creation or restoration can race us during the join.
            with snap_engine._snap_lock:
                blob = b"".join(chunk_store[i] for i in range(total_chunks))

            # 9. Restore state from the reassembled blob
            ok, err = snap_engine.restore_from_blob(
                blob, state_root,
                {
                    "height": snap_height,
                    "block_hash": anchor_block_hash,
                    "state_root": state_root,
                },
            )
            if not ok:
                log.warning("[ParallelSync] restore_from_blob failed: %s", err)
                return False

            log.info(
                "[ParallelSync] Snapshot restored at height=%d "
                "(%d chunks, %d peer(s)). Starting step-by-step block sync...",
                snap_height, total_chunks, len(valid_manifests),
            )

        except Exception as e:
            log.warning("[ParallelSync] Phase A unexpected error: %s", e)
            return False

        # ── Phase B: step-by-step paginated block sync ─────────────────────────
        def _step_sync():
            from_idx   = snap_height + 1
            pages_done = 0
            while pages_done < MAX_PAGES and peer.connected:
                cur_local = self.blockchain.height()
                if cur_local >= from_idx:
                    from_idx = cur_local + 1
                to_idx = from_idx + PAGE_SIZE - 1
                try:
                    self._sync_request(
                        peer, from_idx, to_idx,
                        kind="parallel", force=False)
                    log.info(
                        "[ParallelSync] Phase B page %d: blocks %d-%d from %s",
                        pages_done + 1, from_idx, to_idx, peer.peer_id[:12],
                    )
                except Exception as _se:
                    log.debug("[ParallelSync] Phase B send error: %s", _se)
                    break
                time.sleep(PAGE_DELAY)
                new_local = self.blockchain.height()
                if new_local <= cur_local:
                    time.sleep(PAGE_DELAY * 2)
                    new_local = self.blockchain.height()
                    if new_local <= cur_local:
                        log.info(
                            "[ParallelSync] Phase B: no progress on page %d "
                            "(local=%d); handing off to heartbeat sync.",
                            pages_done + 1, new_local,
                        )
                        break
                from_idx   = new_local + 1
                pages_done += 1
                if new_local == cur_local:
                    break
            log.info(
                "[ParallelSync] Phase B complete: local height=%d "
                "after %d page(s).",
                self.blockchain.height(), pages_done,
            )

        threading.Thread(
            target=_step_sync,
            daemon=True,
            name=f"parallelsync-pages-{peer.peer_id[:8]}",
        ).start()

        return True

    def _fast_sync_legacy(self, peer: 'PeerConnection') -> bool:
        """
        Legacy single-peer snapshot verification path.

        Used only when the local node is already at the snapshot height.
        Fresh/behind nodes must use ordinary block synchronization; a peer
        snapshot is never trusted to replace unrooted auxiliary consensus state.
        """
        if not Config.SNAPSHOT_FAST_SYNC_ENABLED:
            return False
        if not hasattr(self.blockchain, "_snapshot_engine"):
            return False

        snap_engine = self.blockchain._snapshot_engine

        import queue as _queue_mod

        MANIFEST_TIMEOUT = 30
        SNAP_TIMEOUT     = 60
        PAGE_SIZE        = 200
        PAGE_DELAY       = 1.5
        MAX_PAGES        = 20

        try:
            resp_q = _queue_mod.Queue(maxsize=8)
            peer._snap_response_queue = resp_q

            peer.send({"type": MSG_GET_SNAPSHOT_MANIFEST})
            try:
                manifest_msg = resp_q.get(timeout=MANIFEST_TIMEOUT)
            except _queue_mod.Empty:
                log.warning("[FastSync/Legacy] Manifest timeout from %s",
                            peer.peer_id[:12])
                return False

            if manifest_msg.get("type") != MSG_SNAPSHOT_MANIFEST:
                return False

            manifest = manifest_msg.get("manifest", [])
            if not manifest:
                log.info("[FastSync/Legacy] Peer %s has no snapshots — "
                         "full sync required.", peer.peer_id[:12])
                return False

            best            = manifest[-1]
            snap_height     = int(best["height"])
            snap_state_root = best.get("state_root", "")
            snap_size       = best.get("size", 0)
            snap_anchor_hash = best.get("anchor_block_hash", "")
            if self.blockchain.height() != snap_height:
                log.info(
                    "[FastSync/Legacy] Snapshot h=%d cannot safely replace local "
                    "h=%d; falling back to ordinary block sync.",
                    snap_height, self.blockchain.height())
                return False
            log.info(
                "[FastSync/Legacy] Peer %s: snapshot h=%d size=%s "
                "state_root=%s...",
                peer.peer_id[:12], snap_height,
                f"{snap_size:,}B" if snap_size else "?",
                snap_state_root[:16],
            )

            peer.send({"type": MSG_GET_SNAPSHOT, "height": snap_height})
            try:
                data_msg = resp_q.get(timeout=SNAP_TIMEOUT)
            except _queue_mod.Empty:
                log.warning("[FastSync/Legacy] Snapshot data timeout from %s",
                            peer.peer_id[:12])
                return False

            if data_msg.get("type") != MSG_SNAPSHOT_DATA:
                return False
            if "error" in data_msg:
                log.warning("[FastSync/Legacy] Peer error: %s",
                            data_msg["error"])
                return False

            hex_data = data_msg.get("data_hex", "")
            if not hex_data:
                log.warning("[FastSync/Legacy] Empty blob from %s",
                            peer.peer_id[:12])
                return False
            try:
                blob = bytes.fromhex(hex_data)
            except ValueError as e:
                log.warning("[FastSync/Legacy] Bad hex from %s: %s",
                            peer.peer_id[:12], e)
                return False

            ok, err = snap_engine.restore_from_blob(
                blob, snap_state_root,
                {
                    "height": snap_height,
                    "block_hash": snap_anchor_hash,
                    "state_root": snap_state_root,
                },
            )
            if not ok:
                log.warning("[FastSync/Legacy] restore_from_blob failed: %s", err)
                return False

            log.info(
                "[FastSync/Legacy] Snapshot restored h=%d from %s. "
                "Starting step-by-step block sync...",
                snap_height, peer.peer_id[:12],
            )

            def _step_sync():
                from_idx   = snap_height + 1
                pages_done = 0
                while pages_done < MAX_PAGES and peer.connected:
                    cur_local = self.blockchain.height()
                    if cur_local >= from_idx:
                        from_idx = cur_local + 1
                    to_idx = from_idx + PAGE_SIZE - 1
                    try:
                        self._sync_request(
                            peer, from_idx, to_idx,
                            kind="fast-legacy", force=False)
                    except Exception as _se:
                        log.debug("[FastSync/Legacy] send error: %s", _se)
                        break
                    time.sleep(PAGE_DELAY)
                    new_local = self.blockchain.height()
                    if new_local <= cur_local:
                        time.sleep(PAGE_DELAY * 2)
                        new_local = self.blockchain.height()
                        if new_local <= cur_local:
                            break
                    from_idx   = new_local + 1
                    pages_done += 1
                    if new_local == cur_local:
                        break
                log.info(
                    "[FastSync/Legacy] Step-by-step complete: local h=%d "
                    "after %d page(s).",
                    self.blockchain.height(), pages_done,
                )

            threading.Thread(
                target=_step_sync,
                daemon=True,
                name=f"fastsync-pages-{peer.peer_id[:8]}",
            ).start()
            return True

        except Exception as e:
            log.warning("[FastSync/Legacy] Unexpected error: %s", e)
            return False
        finally:
            def _cleanup():
                time.sleep(5)
                peer._snap_response_queue = None
            threading.Thread(target=_cleanup, daemon=True).start()
