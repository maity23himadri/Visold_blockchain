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
"""visold.network.dns_seeder

Original section: SECTION 12C: DNS SEED DISCOVERY

Defines: DNSSeeder
Origin: visold_vsd_.py L33348-33448
"""

import socket
import threading
from typing import Optional, TYPE_CHECKING

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.netutil import _format_peer_addr, _is_ipv6_address, _normalize_ip

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.network.p2p import P2PNetwork


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                          === ICE END ===                                  ║
# ╚═══════════════════════════════════════════════════════════════════════════╝


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 12C: DNS SEED DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────
class DNSSeeder:
    """
    Queries DNS seed hostnames to bootstrap the peer list.

    Operators of seed nodes publish A (IPv4) or AAAA (IPv6) records under a
    dedicated hostname (e.g. seed.visioncoin.org).  Each IP address returned
    by the DNS lookup is treated as a potential peer running on
    Config.DNS_SEED_PORT.

    The seeder runs in a background thread and re-queries every
    Config.DNS_SEED_INTERVAL seconds, feeding discovered addresses into the
    P2PNetwork._try_add_peer pipeline — exactly the same path used for
    manually added peers, so reputation tracking and blacklist checks apply
    automatically.

    Config.DNS_SEEDS is intentionally empty by default; populate it before
    mainnet launch.
    """

    def __init__(self, network: 'P2PNetwork'):
        self._network   = network
        self._thread: Optional[threading.Thread] = None
        self._stop_evt  = threading.Event()

    def start(self):
        if not Config.DNS_SEEDS:
            log.debug("DNSSeeder: no DNS seeds configured, skipping")
            return
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="dns-seeder")
        self._thread.start()

    def stop(self):
        self._stop_evt.set()

    def _run(self):
        # Query immediately on startup, then on the configured interval.
        self._query_all()
        while not self._stop_evt.wait(timeout=Config.DNS_SEED_INTERVAL):
            self._query_all()

    def _query_all(self):
        for hostname in Config.DNS_SEEDS:
            self._query_one(hostname)

    def _query_one(self, hostname: str):
        try:
            # getaddrinfo returns both IPv4 and IPv6 results transparently.
            results = socket.getaddrinfo(
                hostname, Config.DNS_SEED_PORT,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM)
            ips_seen: set = set()
            ipv4_ips: list = []
            ipv6_ips: list = []

            for _family, _type, _proto, _canon, sockaddr in results:
                ip   = _normalize_ip(str(sockaddr[0]))
                port = int(sockaddr[1])
                if ip in ips_seen:
                    continue
                ips_seen.add(ip)
                # Skip our own listening address (both IPv4 and IPv6 loopbacks)
                if ip in ("127.0.0.1", "::1", Config.LOOPBACK_ADDRESS)                         and port == self._network.port:
                    continue
                log.debug(f"DNSSeeder: discovered {_format_peer_addr(ip, port)} "
                          f"via {hostname}")
                if _is_ipv6_address(ip):
                    ipv6_ips.append((ip, port))
                else:
                    ipv4_ips.append((ip, port))

            # v6.9.9: IPv6-first peer registration.
            #
            # When a seed hostname resolves to both A and AAAA records,
            # register IPv6 addresses FIRST so that _try_add_peer spawns
            # IPv6 connection threads before IPv4 ones.  On CGNAT networks
            # IPv4 attempts will timeout / fail; having IPv6 threads already
            # running means a working connection is established sooner rather
            # than waiting for all IPv4 timeouts to expire.
            #
            # Each IP is still registered separately (existing behaviour) —
            # this is intentional because the peer DB stores IPs, not
            # hostnames, and each IP gets its own reconnect lifecycle.
            for ip, port in (ipv6_ips + ipv4_ips):
                _family_label = "AF_INET6" if _is_ipv6_address(ip) else "AF_INET"
                # This runs in the background seeder thread. Route diagnostics
                # through the queue-backed logger; direct stdout writes corrupt
                # the interactive TUI and can move a waiting input cursor.
                log.debug(
                    "[SEED-ATTEMPT] %s %s via %s",
                    _family_label, _format_peer_addr(ip, port), hostname,
                )
                self._network._try_add_peer(ip, port)

            if ips_seen:
                log.info(
                    f"DNSSeeder: {hostname} → "
                    f"{len(ipv6_ips)} IPv6 + {len(ipv4_ips)} IPv4 host(s) discovered")
        except socket.gaierror as e:
            log.debug(f"DNSSeeder: DNS lookup failed for {hostname}: {e}")
        except Exception as e:
            log.debug(f"DNSSeeder: unexpected error for {hostname}: {e}")
