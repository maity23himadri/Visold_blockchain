import os
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

_V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _V4_ROOT not in sys.path:
    sys.path.insert(0, _V4_ROOT)

from visold.kernel.config import Config
from visold.network.nat.hole_punch import UDPHolePuncher
from visold.network.nat.ice import ICEManager
from visold.network.nat.relay import RelayBridge
from visold.network.nat.stun import STUNClient
from visold.network.nat.upnp import UPnPManager


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_hole_punch_simultaneous_peers_succeed():
    """V4 Regression: Simultaneous UDPHolePuncher.punch() peers recognize each other's probes and succeed."""
    p1 = UDPHolePuncher()
    p2 = UDPHolePuncher()
    s1_bind = p1.stun_bind("127.0.0.1")
    s2_bind = p2.stun_bind("127.0.0.1")
    assert s1_bind is not None and s2_bind is not None
    port1 = p1.get_local_port()
    port2 = p2.get_local_port()

    results = {}

    def run1():
        results["p1"] = p1.punch("127.0.0.1", port2, timeout=1.5)

    def run2():
        results["p2"] = p2.punch("127.0.0.1", port1, timeout=1.5)

    t1 = threading.Thread(target=run1)
    t2 = threading.Thread(target=run2)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    try:
        assert results.get("p1") is not None and results.get("p2") is not None
    finally:
        if results.get("p1"):
            results["p1"].close()
        if results.get("p2"):
            results["p2"].close()
        p1.close()
        p2.close()


def test_hole_punch_rejects_unverified_ack_without_nonce_or_port_check():
    """V4 Regression: UDPHolePuncher.punch() rejects ACK packets with wrong nonce or source port."""
    p1 = UDPHolePuncher()
    p1.stun_bind("127.0.0.1")
    port1 = p1.get_local_port()

    result = {}

    def run_punch():
        result["sock"] = p1.punch("127.0.0.1", _free_udp_port(), timeout=0.6)

    t = threading.Thread(target=run_punch)
    t.start()
    time.sleep(0.1)

    attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        attacker.sendto(UDPHolePuncher.ACK_MAGIC + b"\x00" * 8, ("127.0.0.1", port1))
        t.join(timeout=3)
        assert result.get("sock") is None
    finally:
        attacker.close()
        if result.get("sock"):
            result["sock"].close()
        p1.close()


def test_relay_server_no_duplicate_ok_on_bridged_stream(tmp_path):
    """V4 Regression: Relay server sends only one {"status":"ok"} per peer and does not corrupt bridged stream."""
    relay_port = _free_tcp_port()
    with patch.object(Config, "DATA_DIR", str(tmp_path)):
        proc = RelayBridge.start_relay_server(relay_port, bind_addr="127.0.0.1")
    assert proc is not None

    try:
        token = "a" * 32
        b1 = RelayBridge("127.0.0.1", relay_port)
        b2 = RelayBridge("127.0.0.1", relay_port)

        socks = {}

        def c1():
            socks["s1"] = b1.connect_via_relay(token, timeout=5.0)

        def c2():
            time.sleep(0.15)
            socks["s2"] = b2.connect_via_relay(token, timeout=5.0)

        t1 = threading.Thread(target=c1)
        t2 = threading.Thread(target=c2)
        t1.start()
        t2.start()
        t1.join(timeout=8)
        t2.join(timeout=8)

        s1 = socks.get("s1")
        s2 = socks.get("s2")
        assert s1 is not None and s2 is not None

        try:
            time.sleep(0.25)
            s1.sendall(b"APP_PAYLOAD")
            s2.settimeout(2.0)
            received = b""
            deadline = time.time() + 1.5
            while time.time() < deadline and b"APP_PAYLOAD" not in received:
                try:
                    chunk = s2.recv(4096)
                    if not chunk:
                        break
                    received += chunk
                except socket.timeout:
                    break
            assert not received.startswith(b'{"status":"ok"}\n')
            assert received == b"APP_PAYLOAD"
        finally:
            s1.close()
            s2.close()
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_relay_server_enforces_per_ip_limit_for_active_spliced_sessions(tmp_path):
    """V4 Regression: Relay server enforces MAX_CONN_PER_IP (8) across active spliced sessions."""
    relay_port = _free_tcp_port()
    with patch.object(Config, "DATA_DIR", str(tmp_path)):
        proc = RelayBridge.start_relay_server(relay_port, bind_addr="127.0.0.1")
    assert proc is not None

    opened_sockets = []
    try:
        # First 4 pairs = 8 active connections should succeed
        for i in range(4):
            token = f"sess_{i:02d}_" + "b" * 24
            b1 = RelayBridge("127.0.0.1", relay_port)
            b2 = RelayBridge("127.0.0.1", relay_port)
            res = {}

            def _c1(b=b1, tok=token, r=res):
                r["s1"] = b.connect_via_relay(tok, timeout=5.0)

            def _c2(b=b2, tok=token, r=res):
                time.sleep(0.05)
                r["s2"] = b.connect_via_relay(tok, timeout=5.0)

            t1 = threading.Thread(target=_c1)
            t2 = threading.Thread(target=_c2)
            t1.start()
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)
            assert res.get("s1") is not None and res.get("s2") is not None
            opened_sockets.extend([res["s1"], res["s2"]])
            time.sleep(0.1)

        assert len(opened_sockets) == 8

        # 5th pair exceeds MAX_CONN_PER_IP (8) and must be rate-limited
        b_extra = RelayBridge("127.0.0.1", relay_port)
        extra_sock = b_extra.connect_via_relay("sess_04_" + "b" * 24, timeout=2.0)
        assert extra_sock is None
    finally:
        for s in opened_sockets:
            try:
                s.close()
            except Exception:
                pass
        proc.terminate()
        proc.wait(timeout=5)


def test_stun_parse_response_handles_truncated_attribute():
    """V4 Regression: STUNClient._parse_response() returns None on truncated attribute instead of crashing."""
    txn_id = b"\x01" * 12
    header = struct.pack("!HHI12s", STUNClient.MSG_BINDING_RESPONSE, 12,
                         STUNClient.MAGIC_COOKIE, txn_id)
    truncated_attr = struct.pack("!HH", STUNClient.ATTR_XOR_MAPPED_ADDRESS, 8) + b"\x00\x01"
    pkt = header + truncated_attr

    assert STUNClient._parse_response(pkt, txn_id) is None


def test_stun_get_public_address_ignores_malformed_packet_and_accepts_valid_response():
    """V4 Regression: STUNClient.get_public_address() ignores malformed packets and reads the valid response."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv_port = srv.getsockname()[1]

    def responder():
        try:
            data, addr = srv.recvfrom(2048)
            txn_id = data[8:20]
            bad_hdr = struct.pack("!HHI12s", STUNClient.MSG_BINDING_RESPONSE, 12,
                                  STUNClient.MAGIC_COOKIE, txn_id)
            bad_pkt = bad_hdr + struct.pack("!HH", STUNClient.ATTR_XOR_MAPPED_ADDRESS, 8) + b"\x00\x01"
            srv.sendto(bad_pkt, addr)
            time.sleep(0.05)
            xport = 5678 ^ (STUNClient.MAGIC_COOKIE >> 16)
            xip = int.from_bytes(socket.inet_aton("1.2.3.4"), "big") ^ STUNClient.MAGIC_COOKIE
            val = struct.pack("!BBHI", 0, 0x01, xport, xip)
            good_attr = struct.pack("!HH", STUNClient.ATTR_XOR_MAPPED_ADDRESS, len(val)) + val
            good_hdr = struct.pack("!HHI12s", STUNClient.MSG_BINDING_RESPONSE, len(good_attr),
                                   STUNClient.MAGIC_COOKIE, txn_id)
            srv.sendto(good_hdr + good_attr, addr)
        except OSError:
            pass

    t = threading.Thread(target=responder, daemon=True)
    t.start()
    try:
        res = STUNClient.get_public_address("127.0.0.1", srv_port, timeout=2.0)
        assert res == ("1.2.3.4", 5678)
    finally:
        t.join(timeout=1.0)
        srv.close()


def test_ice_stun_bind_handles_ipv6_to_ipv4_fallback():
    """V4 Regression: ICEManager.get_public_address() falls back cleanly from IPv6 to IPv4 STUN server."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv_port = srv.getsockname()[1]
    received_requests = []

    def responder():
        srv.settimeout(4.0)
        try:
            data, addr = srv.recvfrom(2048)
            received_requests.append(addr)
            txn_id = data[8:20]
            xport = 4321 ^ (STUNClient.MAGIC_COOKIE >> 16)
            xip = int.from_bytes(socket.inet_aton("9.8.7.6"), "big") ^ STUNClient.MAGIC_COOKIE
            val = struct.pack("!BBHI", 0, 0x01, xport, xip)
            attr = struct.pack("!HH", STUNClient.ATTR_XOR_MAPPED_ADDRESS, len(val)) + val
            hdr = struct.pack("!HHI12s", STUNClient.MSG_BINDING_RESPONSE, len(attr),
                              STUNClient.MAGIC_COOKIE, txn_id)
            srv.sendto(hdr + attr, addr)
        except Exception:
            pass

    t = threading.Thread(target=responder, daemon=True)
    t.start()

    ice = ICEManager(node_port=_free_tcp_port())
    try:
        with patch.object(Config, "STUN_SERVERS", [("::1", _free_udp_port()), ("127.0.0.1", srv_port)]):
            pub = ice.get_public_address()
        assert pub == ("9.8.7.6", 4321)
        assert len(received_requests) == 1
    finally:
        ice.stop()
        srv.close()


def test_upnp_control_url_rejects_cross_host_or_non_lan_redirect():
    """V4 Regression: UPnPManager rejects cross-host controlURL / non-LAN description URLs."""
    captured_soap = []

    class EvilSoapHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode(errors="ignore")
            captured_soap.append((self.path, body))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<s:Envelope/>")

        def log_message(self, format, *args):
            pass

    evil_srv = HTTPServer(("127.0.0.1", 0), EvilSoapHandler)
    evil_port = evil_srv.server_port

    class IGDHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            xml = f"""<?xml version="1.0"?>
<root><device><serviceList><service>
  <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
  <controlURL>http://127.0.0.1:{evil_port}/steal</controlURL>
</service></serviceList></device></root>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(xml.encode())

        def log_message(self, format, *args):
            pass

    igd_srv = HTTPServer(("127.0.0.1", 0), IGDHandler)
    igd_port = igd_srv.server_port

    t_evil = threading.Thread(target=evil_srv.serve_forever, daemon=True)
    t_igd = threading.Thread(target=igd_srv.serve_forever, daemon=True)
    t_evil.start()
    t_igd.start()

    try:
        mgr = UPnPManager(internal_port=8338, external_port=8338)
        with patch.object(mgr, "_ssdp_search", return_value=[f"http://127.0.0.1:{igd_port}/desc.xml"]):
            mgr._discover_and_map()
        assert len(captured_soap) == 0
    finally:
        igd_srv.shutdown()
        evil_srv.shutdown()
        igd_srv.server_close()
        evil_srv.server_close()


def test_relay_server_supports_ipv6_bind_addr(tmp_path):
    """V4 Regression: RelayBridge.start_relay_server() starts cleanly on IPv6 bind_addr '::1'."""
    relay_port = _free_tcp_port()
    with patch.object(Config, "DATA_DIR", str(tmp_path)):
        proc = RelayBridge.start_relay_server(relay_port, bind_addr="::1")
    assert proc is not None
    try:
        assert proc.poll() is None
    finally:
        proc.terminate()
        proc.wait(timeout=5)
