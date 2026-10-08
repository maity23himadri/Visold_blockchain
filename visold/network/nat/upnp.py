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
"""visold.network.nat.upnp

Original section: SECTION 12B: UPnP NAT TRAVERSAL

Defines: UPnPManager
Origin: visold_vsd_.py L31828-32141
"""

import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.netutil import _is_ipv6_address


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 12B: UPnP NAT TRAVERSAL
# ─────────────────────────────────────────────────────────────────────────────
class UPnPManager:
    """
    Automatic UPnP/IGD port-mapping so nodes behind home routers are reachable
    without manual port-forwarding.

    Discovery protocol (all in-process, no external deps):
      1. Send SSDP M-SEARCH multicast to find an Internet Gateway Device.
      2. Fetch the IGD's XML description to locate the WANIPConnection
         (or WANPPPConnection) SOAP control URL.
      3. Issue AddPortMapping SOAP call for TCP port `external_port`.
      4. Renew the lease every UPNP_RENEW_INTERVAL seconds.
      5. On shutdown, call DeletePortMapping to release the lease cleanly.

    Failures are logged at DEBUG level; they never crash or block the node.
    """

    SSDP_ADDR    = "239.255.255.250"
    SSDP_PORT    = 1900
    SSDP_TIMEOUT = 3          # seconds to wait for SSDP responses
    SOAP_TIMEOUT = 5

    def __init__(self, internal_port: int, external_port: Optional[int] = None):
        self.internal_port = internal_port
        self.external_port = external_port or internal_port
        self._control_url: Optional[str] = None
        self._service_type: Optional[str] = None
        self._gateway_host: Optional[str] = None
        self._mapped        = False
        self._thread: Optional[threading.Thread] = None
        self._stop_evt      = threading.Event()
        self._local_ip: Optional[str] = None

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self):
        """
        Discover gateway and set up mapping in a background thread.

        IPv6 note: UPnP/IGD NAT traversal is an IPv4-only mechanism.
        IPv6 hosts are globally routable without NAT, so we skip UPnP
        entirely when the node is bound to a pure-IPv6 address.
        We still run UPnP when bound to '::' (dual-stack) because the
        node may also be reachable on its IPv4 address.
        """
        if not Config.UPNP_ENABLED:
            return
        bind = Config.BIND_ADDRESS
        # Skip if explicitly bound to a non-loopback IPv6-only address
        # ('::' is dual-stack and still benefits from IPv4 NAT traversal)
        if bind not in ("::", "0.0.0.0", "") and _is_ipv6_address(bind):  # nosec B104 – comparison only, not a bind()
            log.debug("UPnP: skipped — node is bound to an IPv6-only address "
                      "(no NAT traversal needed for IPv6)")
            return
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="upnp-manager")
        self._thread.start()

    def stop(self):
        """Release the port mapping and stop the background thread."""
        self._stop_evt.set()
        if self._mapped:
            try:
                self._delete_mapping()
            except Exception as e:
                log.debug(f"UPnP: delete mapping error: {e}")

    def external_ip(self) -> Optional[str]:
        """Return the WAN IP reported by the gateway, if known."""
        if not self._control_url:
            return None
        try:
            return self._soap_action(
                "GetExternalIPAddress", {}, "NewExternalIPAddress")
        except Exception:
            return None

    # ── Background loop ───────────────────────────────────────────────────────

    def _run(self):
        # Initial discovery + mapping
        try:
            self._discover_and_map()
        except Exception as e:
            log.debug(f"UPnP: initial setup failed: {e}")
            return

        if not self._mapped:
            log.debug("UPnP: no IGD found or mapping rejected")
            return

        wan_ip = self.external_ip()
        log.info(
            f"UPnP: port {self.external_port}/TCP mapped "
            f"(WAN IP: {wan_ip or 'unknown'})")

        # Renewal loop
        while not self._stop_evt.wait(timeout=Config.UPNP_RENEW_INTERVAL):
            try:
                self._add_mapping()
                log.debug(f"UPnP: lease renewed for port {self.external_port}")
            except Exception as e:
                log.debug(f"UPnP: renewal failed: {e}")
                # Try full rediscovery on renewal failure
                try:
                    self._discover_and_map()
                except Exception:
                    pass

    # ── Discovery ─────────────────────────────────────────────────────────────

    def _discover_and_map(self):
        """SSDP discovery → XML description fetch → SOAP mapping."""
        locations = self._ssdp_search()
        for loc in locations:
            try:
                ctrl_url, svc_type, gw_host = self._parse_description(loc)
                self._control_url  = ctrl_url
                self._service_type = svc_type
                self._gateway_host = gw_host
                self._local_ip     = self._get_local_ip(gw_host)
                self._add_mapping()
                self._mapped = True
                return
            except Exception as e:
                log.debug(f"UPnP: IGD at {loc} unusable: {e}")
                continue

    def _ssdp_search(self) -> List[str]:
        """Broadcast SSDP M-SEARCH; return list of LOCATION header values."""
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {self.SSDP_ADDR}:{self.SSDP_PORT}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
            "\r\n"
        ).encode()

        locations = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                 socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(self.SSDP_TIMEOUT)
            sock.sendto(msg, (self.SSDP_ADDR, self.SSDP_PORT))
            deadline = time.time() + self.SSDP_TIMEOUT
            while time.time() < deadline:
                try:
                    data, _ = sock.recvfrom(4096)
                    text = data.decode(errors="ignore")
                    for line in text.splitlines():
                        if line.lower().startswith("location:"):
                            loc = line.split(":", 1)[1].strip()
                            if loc not in locations:
                                locations.append(loc)
                except socket.timeout:
                    break
                except Exception:
                    break
        except Exception as e:
            log.debug(f"UPnP SSDP error: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return locations

    def _parse_description(self, location: str) -> Tuple[str, str, str]:
        """
        Fetch the IGD XML description and extract:
          - SOAP control URL (absolute)
          - service type string
          - gateway hostname (for local IP detection)
        """
        from urllib.parse import urlparse, urljoin
        # ── Scheme whitelist ─────────────────────────────────────────────────────
        # `location` comes from a SSDP network response and must be validated
        # before opening.  Only plain HTTP to a LAN gateway is expected for UPnP.
        _parsed_loc = urlparse(location)
        if _parsed_loc.scheme not in ("http", "https"):
            log.warning("UPnP: rejecting description URL with unexpected scheme "
                        f"'{_parsed_loc.scheme}' — location={location!r}")
            raise ValueError(f"UPnP: disallowed URL scheme '{_parsed_loc.scheme}'")
        resp  = urllib.request.urlopen(location, timeout=self.SOAP_TIMEOUT)  # nosec B310
        xml   = resp.read().decode(errors="ignore")
        parsed = urlparse(location)
        base  = f"{parsed.scheme}://{parsed.netloc}"
        gw_host = parsed.hostname

        # Search for WANIPConnection or WANPPPConnection service
        svc_types = [
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANIPConnection:2",
            "urn:schemas-upnp-org:service:WANPPPConnection:1",
        ]

        # Very lightweight XML parsing — avoids importing xml.etree for portability
        # (the description is small, regular, and well-known in structure)
        def _between(text: str, tag: str) -> Optional[str]:
            open_t  = f"<{tag}>"
            close_t = f"</{tag}>"
            s = text.find(open_t)
            if s == -1:
                # try with namespace prefix stripped — some IGDs use ns1: etc.
                for line in text.splitlines():
                    if f":{tag}>" in line or f"<{tag}>" in line:
                        import re as _re
                        m = _re.search(r'>([^<]+)<', line)
                        if m:
                            return m.group(1).strip()
                return None
            e = text.find(close_t, s)
            if e == -1:
                return None
            return text[s + len(open_t):e].strip()

        # Split into <service> blocks
        blocks = xml.split("<service>")
        for block in blocks[1:]:
            svc_type_val = _between(block, "serviceType") or ""
            ctrl_url_rel = _between(block, "controlURL") or ""
            for svc in svc_types:
                if svc in svc_type_val and ctrl_url_rel:
                    ctrl_url = urljoin(base, ctrl_url_rel)
                    return ctrl_url, svc_type_val.strip(), gw_host
        raise RuntimeError("No WANIPConnection service found in IGD description")

    # ── SOAP helpers ──────────────────────────────────────────────────────────

    def _soap_action(self, action: str, args: dict,
                     response_field: Optional[str] = None) -> Optional[str]:
        """Execute a UPnP SOAP action; return the value of `response_field`.
        F-17 FIX: XML-escape all argument values to prevent XML injection.
        """
        import html as _html
        arg_xml = "".join(
            f"<{k}>{_html.escape(str(v))}</{k}>" for k, v in args.items())
        body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            "<s:Body>"
            f'<u:{action} xmlns:u="{self._service_type}">'
            f"{arg_xml}"
            f"</u:{action}>"
            "</s:Body>"
            "</s:Envelope>"
        ).encode()

        req = urllib.request.Request(
            self._control_url or "",
            data=body,
            headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction":   f'"{self._service_type}#{action}"',
                "Content-Length": str(len(body)),
            },
        )
        resp = urllib.request.urlopen(req, timeout=self.SOAP_TIMEOUT)  # nosec B310 – URL validated in _parse_description
        if response_field is None:
            return None
        text = resp.read().decode(errors="ignore")
        # Extract the first occurrence of <NewExternalIPAddress> etc.
        tag_open  = f"<{response_field}>"
        tag_close = f"</{response_field}>"
        s = text.find(tag_open)
        if s == -1:
            return None
        e = text.find(tag_close, s)
        if e == -1:
            return None
        return text[s + len(tag_open):e].strip()

    def _add_mapping(self):
        """Issue AddPortMapping SOAP call."""
        local_ip = self._local_ip or self._get_local_ip(self._gateway_host)
        self._soap_action("AddPortMapping", {
            "NewRemoteHost":             "",
            "NewExternalPort":           str(self.external_port),
            "NewProtocol":               "TCP",
            "NewInternalPort":           str(self.internal_port),
            "NewInternalClient":         local_ip,
            "NewEnabled":                "1",
            "NewPortMappingDescription": "Visold-VSD-P2P",
            "NewLeaseDuration":          str(Config.UPNP_LEASE_SECONDS),
        })

    def _delete_mapping(self):
        """Issue DeletePortMapping SOAP call."""
        self._soap_action("DeletePortMapping", {
            "NewRemoteHost":   "",
            "NewExternalPort": str(self.external_port),
            "NewProtocol":     "TCP",
        })
        log.debug(f"UPnP: mapping released for port {self.external_port}")

    @staticmethod
    def _get_local_ip(gateway_host: str) -> str:
        """
        Determine the local IP that routes toward the gateway.
        Uses a UDP trick (no actual packet is sent).
        Falls back to 127.0.0.1 on any error (including IPv6-only hosts
        where the gateway_host may not be reachable over IPv4).
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((gateway_host, 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
