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
import time
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

    Config.DNS_SEEDS contains the built-in bootstrap hostnames by default and
    can be overridden through configuration or the VISOLD_DNS_SEEDS variable.
    """

    def __init__(self, network: 'P2PNetwork'):
        self._network   = network
        self._thread: Optional[threading.Thread] = None
        self._stop_evt  = threading.Event()
        # Serialize background refreshes with recovery-triggered refreshes.
        # Without this guard, the reconnect loop and 600-second DNS timer can
        # launch duplicate batches for the same endpoint at once.
        self._query_lock = threading.Lock()
        self._last_query_monotonic = 0.0
        # Treat A/AAAA answers for one DNS name as alternative routes to that
        # seed, not as two independent peers. If the first family keeps failing,
        # rotate the preferred family on the next recovery refresh.
        self._candidate_cursor: dict[str, int] = {}

    def start(self):
        if not Config.DNS_SEEDS:
            log.debug("DNSSeeder: no DNS seeds configured, skipping")
            return
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="dns-seeder")
        self._thread.start()

    def stop(self):
        self._stop_evt.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread() and thread.is_alive():
            thread.join(timeout=2.0)

    def _run(self):
        # Query immediately on startup, then on the configured interval.
        self._query_all()
        while not self._stop_evt.wait(timeout=Config.DNS_SEED_INTERVAL):
            self._query_all()

    def _query_all_locked(self) -> int:
        scheduled = 0
        for hostname in Config.DNS_SEEDS:
            scheduled += self._query_one(hostname)
        return scheduled

    def _query_all(self) -> int:
        with self._query_lock:
            self._last_query_monotonic = time.monotonic()
            return self._query_all_locked()

    def refresh_now(self, min_interval_seconds: float = 15.0) -> int:
        """Re-resolve DNS seeds during peer recovery, with a bounded rate.

        The regular timer is intentionally slow (600 seconds by default).
        That is suitable for steady-state discovery but too slow after an IP
        migration: a one-shot dial may fail while the seed is restarting, and
        the reconnect loop used to retry only static/cached IP addresses.
        Recovery calls this method when below target. A non-blocking lock and
        minimum interval prevent a stuck DNS query or concurrent caller from
        stalling the reconnect loop or creating query storms.

        Returns the number of endpoint dial attempts successfully scheduled;
        that is not the same as authenticated connection success.
        """
        if not Config.DNS_SEEDS:
            return 0
        if not self._query_lock.acquire(blocking=False):
            log.debug("DNSSeeder: recovery refresh skipped; another lookup is active")
            return 0
        try:
            now = time.monotonic()
            minimum = max(5.0, float(min_interval_seconds))
            elapsed = now - float(self._last_query_monotonic or 0.0)
            if elapsed < minimum:
                log.debug(
                    "DNSSeeder: recovery refresh throttled for %.1fs",
                    minimum - elapsed)
                return 0
            self._last_query_monotonic = now
            log.info("DNSSeeder: recovery refresh started (peer target not met)")
            return self._query_all_locked()
        finally:
            self._query_lock.release()

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

            candidates = ipv6_ips + ipv4_ips
            if candidates:
                # Log the actual answer, not only family counts. This makes it
                # possible to distinguish a stale resolver answer from a later
                # failure to connect to the refreshed address.
                resolved = ", ".join(
                    ("IPv6 " if _is_ipv6_address(ip) else "IPv4 ")
                    + _format_peer_addr(ip, port)
                    for ip, port in candidates
                )
                log.info("DNSSeeder: %s resolved to %s", hostname, resolved)

                # Prefer IPv6 initially, but rotate through the alternatives on
                # each refresh. Only schedule one endpoint per hostname per
                # pass: A and AAAA are alternate routes to the same seed, and
                # parallel attempts could consume the soft peer-target budget
                # before the usable family gets a chance to run.
                start = int(self._candidate_cursor.get(hostname, 0) or 0) % len(candidates)
                ordered = candidates[start:] + candidates[:start]
                self._candidate_cursor[hostname] = (start + 1) % len(candidates)
                for ip, port in ordered:
                    family_label = "AF_INET6" if _is_ipv6_address(ip) else "AF_INET"
                    endpoint = _format_peer_addr(ip, port)
                    try:
                        started = bool(self._network._try_add_peer(
                            ip, port, auto_discovery=True, dial_source="dns-seeder"))
                    except Exception as exc:
                        started = False
                        log.debug("DNSSeeder: scheduling %s via %s raised %s",
                                  endpoint, hostname, exc)
                    log.info("DNSSeeder: dial %s %s via %s scheduled=%s",
                             family_label, endpoint, hostname, started)
                    if started:
                        return 1
            else:
                log.info("DNSSeeder: %s resolved to no usable endpoints", hostname)
            return 0
        except socket.gaierror as e:
            log.debug(f"DNSSeeder: DNS lookup failed for {hostname}: {e}")
            return 0
        except Exception as e:
            log.debug(f"DNSSeeder: unexpected error for {hostname}: {e}")
            return 0
