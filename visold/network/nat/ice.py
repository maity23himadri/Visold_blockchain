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
"""visold.network.nat.ice


Defines: ICEManager
Origin: visold_vsd_.py L32837-32852, L32855-32878, L32882-33338
"""

import hashlib
import os
import socket
import threading
import time
from typing import List, Optional, Tuple

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.netutil import _create_connection_dual_stack, _is_ipv6_address, _normalize_ip
from visold.network.nat.hole_punch import UDPHolePuncher
from visold.network.nat.relay import RelayBridge
from visold.network.nat.stun import ICECandidate, STUNClient


# ─── MAJOR-09: Peer PoW (hashcash-style) helpers ─────────────────────────────

def _pow_check(challenge: str, nonce_hex: str, difficulty_bits: int) -> bool:
    """Return True if SHA-256(challenge + nonce_hex) has difficulty_bits leading zeros."""
    try:
        digest = hashlib.sha256((challenge + nonce_hex).encode()).digest()
        # Check leading zero bits
        required_zero_bytes, remaining_bits = divmod(difficulty_bits, 8)
        for i in range(required_zero_bytes):
            if digest[i] != 0:
                return False
        if remaining_bits:
            mask = 0xFF & (0xFF << (8 - remaining_bits))
            if digest[required_zero_bytes] & mask != 0:
                return False
        return True
    except Exception:
        return False


def _pow_solve(challenge: str, difficulty_bits: int,
               max_iters: int = 10_000_000) -> Optional[str]:
    """Find a nonce_hex satisfying _pow_check.  Returns None if not found.

    WARN-05 FIX:
      • Seed from os.urandom(4) for a uniformly distributed start nonce,
        avoiding any platform-dependent random.getrandbits behaviour.
      • Log a WARNING (not silent None) if max_iters is exhausted so operators
        know the node cannot complete handshakes — likely a config error
        (PEER_POW_DIFFICULTY set impossibly high).
      Expected iterations at difficulty_bits d: 2^d.
      difficulty_bits=16 → ~65 536 iters; max_iters=10M is ample headroom.
    """
    nonce = int.from_bytes(os.urandom(4), "big")
    for _ in range(max_iters):
        nonce_hex = format(nonce & 0xFFFFFFFF, '08x')
        if _pow_check(challenge, nonce_hex, difficulty_bits):
            return nonce_hex
        nonce += 1
    log.warning(
        f"_pow_solve: exhausted {max_iters:,} iterations for "
        f"difficulty_bits={difficulty_bits} — returning None. "
        f"Check PEER_POW_DIFFICULTY config (current={Config.PEER_POW_DIFFICULTY}).")
    return None


# ─────────────────────────────────────────────────────────────────────────────

class ICEManager:
    """
    Full ICE (Interactive Connectivity Establishment) manager for Visold VSD.

    Connection priority order (highest first):
    1. Direct LAN TCP (existing behaviour — unchanged)
    2. UDP hole punching through NAT/CGNAT
    3. Direct TCP as outbound (for asymmetric NATs)
    4. TURN-lite relay server (last resort)
    5. Original connection path (failsafe — never crashes)

    The ICEManager is instantiated once per P2PNetwork node and shared across
    all connection attempts.  It is fully thread-safe.

    Signaling extension:
    ────────────────────
    ice_candidates is added to the existing HELLO payload as an optional list
    of {type, ip, port, priority} dicts.  Old nodes that do not understand this
    field simply ignore it — fully backward-compatible.
    """

    def __init__(self, node_port: int):
        self._node_port    = node_port
        self._relay_port   = node_port + Config.RELAY_PORT_OFFSET
        self._lock         = threading.Lock()
        self._public_ip:   Optional[str] = None
        self._public_port: Optional[int] = None
        self._candidates:  List[ICECandidate] = []
        self._local_ip:    Optional[str] = None
        self._puncher      = UDPHolePuncher()   # AUDIT-FIX-23: genuinely shared — see stun_bind()/punch()
        self._relay_bridge: Optional[RelayBridge] = None
        self._relay_proc   = None
        self._stop_evt     = threading.Event()
        self._ready        = threading.Event()
        self._gather_lock  = threading.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        """Start background candidate gathering (non-blocking)."""
        if not Config.ICE_ENABLED:
            self._ready.set()
            return
        t = threading.Thread(target=self._gather_and_init,
                             daemon=True, name="ice-gather")
        t.start()

    def stop(self):
        """Shutdown ICE — terminate relay subprocess if running."""
        self._stop_evt.set()
        if self._relay_proc is not None:
            try:
                self._relay_proc.terminate()
            except Exception:
                pass
        # AUDIT-FIX-23: self._puncher's socket can now be long-lived (it's
        # reused across the STUN query and the actual punch instead of a
        # fresh throwaway one), so make sure it's actually released here.
        try:
            self._puncher.close()
        except Exception:
            pass

    # ── Candidate gathering ───────────────────────────────────────────────────

    def _gather_and_init(self):
        """Background: gather all ICE candidates then signal ready."""
        try:
            self.gather_candidates()
            self._init_relay()
        except Exception as exc:
            log.debug(f"ICE gather error: {exc}")
        finally:
            self._ready.set()

    def gather_candidates(self) -> List[ICECandidate]:
        """
        Collect host, server-reflexive, and relay ICE candidates.
        Safe to call multiple times; results are cached and refreshed.
        """
        with self._gather_lock:
            candidates: List[ICECandidate] = []

            # 1. Host candidates — all non-loopback local IP addresses
            local_ips = self._get_local_ips()
            for ip in local_ips:
                cand = ICECandidate(
                    ICECandidate.HOST, ip, self._node_port,
                    priority=Config.ICE_PRIORITY_HOST)
                candidates.append(cand)
                if self._local_ip is None:
                    self._local_ip = ip

            # 2. Server-reflexive candidate — STUN query
            pub = self.get_public_address()
            if pub:
                self._public_ip, self._public_port = pub
                srflx = ICECandidate(
                    ICECandidate.SRFLX,
                    self._public_ip, self._public_port,
                    priority=Config.ICE_PRIORITY_SRFLX)
                candidates.append(srflx)
                log.info(f"ICE: server-reflexive candidate "
                         f"{self._public_ip}:{self._public_port}")

            # 3. Relay candidate — always last resort
            if Config.TURN_ENABLED and self._local_ip:
                relay_cand = ICECandidate(
                    ICECandidate.RELAY,
                    self._local_ip, self._relay_port,
                    priority=Config.ICE_PRIORITY_RELAY)
                candidates.append(relay_cand)

            with self._lock:
                self._candidates = candidates
            return candidates

    def get_candidates_as_dicts(self) -> List[dict]:
        """Return current candidates serialised for HELLO payload injection."""
        with self._lock:
            return [c.to_dict() for c in self._candidates]

    # ── STUN ──────────────────────────────────────────────────────────────────

    def get_public_address(self) -> Optional[Tuple[str, int]]:
        """
        Query each configured STUN server in order and return the first
        successful (public_ip, public_port) pair, or None if all fail.
        """
        for host, port in Config.STUN_SERVERS:
            if self._stop_evt.is_set():
                break
            # AUDIT-FIX-23: bind (or reuse) self._puncher's socket for this
            # query so the mapping STUN discovers belongs to the exact
            # socket udp_hole_punch() will subsequently reuse. Previously
            # this always opened and immediately closed its own throwaway
            # socket, so the candidate we advertised to peers never
            # actually matched the socket we punched from. stun_bind()
            # returns None if the puncher's port is already claimed by an
            # earlier successful punch, in which case we fall back to the
            # old (unverified but harmless) throwaway-socket behaviour.
            local_sock = self._puncher.stun_bind(host)
            result = STUNClient.get_public_address(host, port, local_sock=local_sock, timeout=3.0)
            if result:
                log.debug(f"ICE STUN: {host}:{port} → {result[0]}:{result[1]}")
                return result
        log.debug("ICE STUN: all servers failed or unavailable")
        return None

    # ── Relay initialisation ──────────────────────────────────────────────────

    def _init_relay(self):
        if not Config.TURN_ENABLED:
            return
        if Config.AUTO_RELAY and self._local_ip:
            # ── Scan-to-Bind: find a free relay port ─────────────────────────
            # Start from node_port + 1 and try up to 10 consecutive ports.
            # socket.bind() is used to verify availability before committing.
            # The P2P port (node_port / 8338) is never touched.
            found_port = None
            for offset in range(1, 11):
                candidate = self._node_port + offset
                # Use AF_INET6 with IPV6_V6ONLY=0 to probe dual-stack port
                # availability — same family as the actual relay server socket.
                try:
                    probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    _probe_bind_any = "::"     # AF_INET6 dual-stack wildcard
                except (AttributeError, OSError):
                    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    _probe_bind_any = "0.0.0.0"  # nosec B104 – intentional probe bind-all
                try:
                    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    probe.bind((_probe_bind_any, candidate))  # nosec B104 – port availability probe only
                    found_port = candidate
                    break
                except OSError:
                    log.debug(
                        f"ICE: relay port {candidate} busy — trying next…")
                finally:
                    try:
                        probe.close()
                    except Exception:
                        pass

            if found_port is None:
                log.warning(
                    "ICE: no available relay port found after 10 attempts "
                    f"(tried {self._node_port + 1}–{self._node_port + 10}) "
                    "— relay disabled for this session")
                return

            # Commit the selected port
            self._relay_port = found_port
            log.info(f"ICE: relay server binding on port {self._relay_port}")

            # Keep the relay ICE candidate in sync with the actual port
            with self._lock:
                for i, cand in enumerate(self._candidates):
                    if cand.ctype == ICECandidate.RELAY:
                        self._candidates[i] = ICECandidate(
                            ICECandidate.RELAY,
                            self._local_ip,
                            self._relay_port,
                            priority=Config.ICE_PRIORITY_RELAY,
                        )
                        break

            # Launch the relay subprocess on the confirmed port, bound to the
            # node's local IP so remote peers can reach it without an SSH tunnel.
            try:
                self._relay_proc = RelayBridge.start_relay_server(
                    self._relay_port, bind_addr=self._local_ip)
            except Exception as exc:
                log.debug(f"ICE: relay server start error: {exc}")

        if self._local_ip:
            self._relay_bridge = RelayBridge(
                relay_host=self._local_ip,
                relay_port=self._relay_port,
            )

    # ── Connection entry point ────────────────────────────────────────────────

    def connect(self, ip: str, port: int,
                remote_candidates: Optional[List[dict]] = None,
                timeout: Optional[float] = None) -> Optional[socket.socket]:
        """
        Try to establish the best possible TCP/UDP socket to (ip, port).

        Priority:
          1. Direct TCP (existing LAN / open internet)
          2. UDP hole punch using server-reflexive candidate from remote
          3. TCP direct (asymmetric NAT — outbound-only)
          4. Relay bridge
          5. None (caller falls back to original connection path)

        Returns a connected socket on success, None to signal fallback.
        """
        if not Config.ICE_ENABLED:
            return None  # signal: use original path

        if timeout is None:
            timeout = Config.PEER_TIMEOUT

        # Parse remote ICE candidates if provided
        remote_cands: List[ICECandidate] = []
        if remote_candidates:
            for d in remote_candidates:
                try:
                    remote_cands.append(ICECandidate.from_dict(d))
                except Exception:
                    pass
            # Sort by priority descending
            remote_cands.sort(key=lambda c: c.priority, reverse=True)

        # ── Step 1: Direct TCP (fastest, works when no NAT or UPnP is active) ─
        #
        # v6.9.9 FIX — CGNAT direct-TCP timeout reduction:
        #
        # Problem: CGNAT silently drops packets rather than sending TCP RST.
        # A direct-TCP attempt to an IPv4 peer behind CGNAT blocks for the
        # full 3-second timeout before hole-punch is even tried.  On mobile
        # networks with many CGNAT peers this adds 3s × N wasted seconds per
        # connect cycle before the faster UDP hole-punch path runs.
        #
        # Fix: detect "IPv4 peer + we are behind NAT" condition:
        #   _is_ipv4_peer  → peer address contains no ':' (not IPv6)
        #   _behind_nat    → STUN gave us a public IP that differs from our
        #                    local IP (classic NAT / CGNAT indicator)
        #
        # If both true: cut direct-TCP timeout to 0.8s.  This is enough for
        # LAN peers (sub-millisecond RTT) and properly port-forwarded WAN peers
        # (RTT typically < 300ms), while failing fast for CGNAT dead-drops so
        # hole-punch runs ~2.2s sooner per peer.
        #
        # IPv6 peers are always publicly routable; their timeout is unchanged.
        _is_ipv4_peer = not _is_ipv6_address(ip)
        _behind_nat   = (
            self._public_ip is not None
            and self._local_ip is not None
            and self._public_ip != self._local_ip
        )
        _direct_timeout = 0.8 if (_is_ipv4_peer and _behind_nat) else min(timeout, 3.0)

        sock = self.try_direct_tcp(ip, port, timeout=_direct_timeout)
        if sock:
            log.debug(f"ICE: direct TCP succeeded → {ip}:{port}")
            return sock

        # ── Step 2: UDP hole punch ─────────────────────────────────────────────
        # Use remote's srflx candidate if available; otherwise fall back to
        # the announced (ip, port) which may be the public address.
        punch_targets = []
        for rc in remote_cands:
            if rc.ctype in (ICECandidate.SRFLX, ICECandidate.HOST):
                punch_targets.append((rc.ip, rc.port))
        if not punch_targets:
            punch_targets.append((ip, port))

        for punch_ip, punch_port in punch_targets:
            sock = self.udp_hole_punch(punch_ip, punch_port)
            if sock:
                log.info(f"ICE: UDP hole punch succeeded → {punch_ip}:{punch_port}")
                return sock

        # ── Step 3: Try relay ──────────────────────────────────────────────────
        # Find relay candidate from remote
        relay_cand = next(
            (rc for rc in remote_cands if rc.ctype == ICECandidate.RELAY), None)
        if relay_cand and Config.TURN_ENABLED:
            session_token = self._make_session_token(ip, port)
            bridge = RelayBridge(relay_cand.ip, relay_cand.port)
            sock   = bridge.connect_via_relay(session_token, timeout=timeout)
            if sock:
                return sock

        # ── Step 4: Own relay ──────────────────────────────────────────────────
        if Config.TURN_ENABLED and self._relay_bridge:
            session_token = self._make_session_token(ip, port)
            sock = self._relay_bridge.connect_via_relay(session_token,
                                                        timeout=timeout)
            if sock:
                return sock

        # All ICE paths failed — return None so caller uses original TCP path
        log.debug(f"ICE: all paths failed for {ip}:{port} — falling back")
        return None

    # ── Individual transport methods ─────────────────────────────────────────

    def try_direct_tcp(self, ip: str, port: int,
                       timeout: float = 3.0) -> Optional[socket.socket]:
        """Attempt a plain TCP connection (existing semantics)."""
        try:
            sock = _create_connection_dual_stack(ip, port, timeout=timeout)
            return sock
        except Exception:
            return None

    def udp_hole_punch(self, remote_ip: str,
                       remote_port: int) -> Optional[socket.socket]:
        """
        Launch simultaneous UDP hole punching toward (remote_ip, remote_port).
        Returns a working UDP socket or None.
        """
        try:
            # AUDIT-FIX-23: reuse the shared puncher whose socket
            # get_public_address() STUN-verified, instead of a fresh
            # throwaway instance with an unrelated, unadvertised port —
            # otherwise the candidate we told this peer about (and every
            # other peer) never matches what we actually punch from, and
            # hole punching cannot work against a non-full-cone NAT.
            puncher = self._puncher
            sock    = puncher.punch(remote_ip, remote_port)
            if sock is None and puncher.is_claimed:
                # This puncher's port is already owned by an earlier,
                # successfully-punched peer's live connection — do not
                # touch it. Fall back to an independent, freshly-assigned
                # port for this attempt (same as the old behaviour for
                # this one case: it just won't match a previously
                # -advertised candidate, but it can't disrupt that peer).
                puncher = UDPHolePuncher()
                sock    = puncher.punch(remote_ip, remote_port)
            if sock:
                # Start keepalive in background
                stop_evt = threading.Event()
                threading.Thread(
                    target=puncher.keepalive_loop,
                    args=(remote_ip, remote_port, stop_evt),
                    daemon=True,
                    name="ice-keepalive",
                ).start()
                # Attach the stop event to the socket so the peer loop can
                # shut down the keepalive when the connection ends
                sock._ice_ka_stop = stop_evt   # type: ignore[attr-defined]
            return sock
        except Exception as exc:
            log.debug(f"ICE UDP hole punch error: {exc}")
            return None

    def use_relay(self, relay_host: str, relay_port: int,
                  session_token: str,
                  timeout: float = 10.0) -> Optional[socket.socket]:
        """Connect through the relay server using a pre-agreed session token."""
        bridge = RelayBridge(relay_host, relay_port)
        return bridge.connect_via_relay(session_token, timeout=timeout)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    @staticmethod
    def _get_local_ips() -> List[str]:
        """
        Return a deduplicated list of non-loopback local IP addresses
        (both IPv4 and IPv6).  IPv6 link-local (fe80::) addresses are excluded
        because they are not routable beyond the local segment.
        """
        ips: List[str] = []
        seen: set = set()
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None,
                                           socket.AF_UNSPEC, socket.SOCK_STREAM):
                ip = info[4][0]
                ip = _normalize_ip(str(ip))
                if ip in seen:
                    continue
                seen.add(ip)
                if ip.startswith("127.") or ip == "::1":
                    continue
                if ip.startswith("169.254."):       # IPv4 link-local
                    continue
                if ip.lower().startswith("fe80:"):  # IPv6 link-local
                    continue
                ips.append(ip)
        except Exception:
            pass

        # Fallback A: UDP trick toward IPv4 internet to detect LAN IP
        if not any("." in ip for ip in ips):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                if ip and not ip.startswith("127.") and ip not in seen:
                    ips.append(ip)
                    seen.add(ip)
            except Exception:
                pass

        # Fallback B: UDP trick toward IPv6 internet to detect global IPv6
        if not any(":" in ip for ip in ips):
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                s.connect(("2001:4860:4860::8888", 80))  # Google DNS IPv6
                ip = s.getsockname()[0]
                s.close()
                ip = _normalize_ip(ip)
                if ip and ip != "::1" and not ip.lower().startswith("fe80:") and ip not in seen:
                    ips.append(ip)
                    seen.add(ip)
            except Exception:
                pass

        return ips

    @staticmethod
    def _make_session_token(ip: str, port: int) -> str:
        """
        Deterministic relay session token shared by both peers.
        Both sides call this with the *server* peer's (ip, port) so they
        derive the same token without extra signaling.
        """
        raw = f"vsd-relay:{ip}:{port}:{int(time.time()) // 30}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]
