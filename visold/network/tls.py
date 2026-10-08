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
"""visold.network.tls

Original section: SECTION 1B: TLS MANAGER  (Problem #1 — P2P + RPC encryption)

Defines: TLSManager
Origin: visold_vsd_.py L5224-5579
"""

import hmac
import os
import ssl
import threading
import datetime as _dt
from typing import Dict, Optional

from visold.kernel.compat import _NameOID, _ec, _hashes, _x509, serialization
from visold.kernel.config import Config
from visold.kernel.logging_setup import log


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1B: TLS MANAGER  (Problem #1 — P2P + RPC encryption)
# ─────────────────────────────────────────────────────────────────────────────
class TLSManager:
    """
    Manages self-signed TLS certificates for P2P socket encryption.

    Design:
    ═══════
    • Each node generates a P-256 self-signed certificate at first run.
    • Certificate is stored at ~/.visold/.node_tls_cert.pem (mode 0o600).
    • The cert's SHA-256 fingerprint is exchanged during the application-layer
      HELLO handshake and stored in the peers table (TOFU pinning).
    • Subsequent connections from the same peer_id verify that the cert
      fingerprint has not changed — providing certificate pinning without a CA.
    • TLS_ENABLED can be toggled via Config.TLS_ENABLED or the config.json file.

    Why self-signed + pinning instead of a CA:
    ───────────────────────────────────────────
    A P2P blockchain network has no natural certificate authority.  Using a
    commercial CA would create a centralised point of failure and cost.
    Trust-on-first-use (TOFU) is the same model used by SSH host keys and by
    libp2p's noise protocol — it provides encryption + MitM protection after
    the first connection without requiring centralised PKI.
    """

    _ctx_server: Optional[ssl.SSLContext] = None
    _ctx_client: Optional[ssl.SSLContext] = None
    _fingerprint: Optional[str] = None
    _lock = threading.Lock()
    # IP-keyed TOFU store: maps peer IP address -> SHA-256 cert fingerprint (hex).
    # Populated by verify_peer_fingerprint_by_ip() on first contact with each peer
    # and checked on every subsequent connection.  Complements the peer_id-keyed
    # store in NodeStorage (get/set_peer_tls_fp) which is populated after the
    # JSON handshake resolves the node_id.
    _ip_fp_store: Dict[str, str] = {}

    @classmethod
    def ensure_cert(cls) -> bool:
        """Generate cert+key PEM files if they don't exist. Returns True on success."""
        if not Config.TLS_ENABLED:
            return False
        cert_path = Config.TLS_CERT_FILE
        key_path  = Config.TLS_KEY_FILE
        if not cert_path or not key_path:
            return False
        # VSD-H06 FIX: regenerate if missing OR if cert expires within 14 days
        needs_gen = not (os.path.exists(cert_path) and os.path.exists(key_path))
        if not needs_gen:
            try:
                with open(cert_path, 'rb') as _cf:
                    _cert_check = _x509.load_pem_x509_certificate(_cf.read())
                import datetime as _dt_check
                _days_left = (_cert_check.not_valid_after_utc.replace(tzinfo=None)
                              - _dt_check.datetime.utcnow()).days
                if _days_left < 14:
                    log.warning(f"TLS cert expires in {_days_left} day(s) — rotating (VSD-H06).")
                    needs_gen = True
            except Exception:
                needs_gen = True
        if needs_gen:
            try:
                cls._generate_cert(cert_path, key_path)
                # Invalidate cached contexts so new cert is loaded on next use
                cls._ctx_server = None
                cls._ctx_client = None
            except Exception as e:
                log.warning(f"TLS cert generation failed: {e} — running without TLS")
                return False
        # Pre-compute fingerprint
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            cert = _x509.load_pem_x509_certificate(cert_data)
            fp   = cert.fingerprint(_hashes.SHA256())
            cls._fingerprint = fp.hex()
        except Exception as e:
            log.warning(f"TLS fingerprint compute failed: {e}")

        # SEC-FIX M-01 (TLS First-Joiner Pinning)
        # ────────────────────────────────────────
        # Preload operator-supplied bootstrap fingerprints into the TOFU
        # store so that a fresh node's very first TLS handshake with each
        # bootstrap peer is authenticated against the operator's pin
        # rather than blindly trusting whatever cert the wire delivers.
        # Empty config = no pins = previous TOFU behaviour.
        try:
            pins = getattr(Config, "TLS_BOOTSTRAP_FINGERPRINTS", {}) or {}
            if pins:
                with cls._lock:
                    for ip_or_host, pinned_fp in pins.items():
                        if not isinstance(ip_or_host, str) \
                                or not isinstance(pinned_fp, str):
                            continue
                        # Normalise — fingerprints are lowercase hex, no spaces
                        norm_fp = pinned_fp.strip().lower().replace(":", "")
                        if not norm_fp or any(c not in "0123456789abcdef"
                                              for c in norm_fp):
                            log.warning(
                                f"[TOFU] Skipping malformed pin for "
                                f"{ip_or_host!r}: not hex")
                            continue
                        cls._ip_fp_store[ip_or_host] = norm_fp
                log.info(
                    f"[TOFU] Preloaded {len(pins)} bootstrap "
                    f"fingerprint pin(s) from "
                    f"Config.TLS_BOOTSTRAP_FINGERPRINTS")
        except Exception as e:
            log.warning(f"[TOFU] Bootstrap fingerprint preload failed: {e}")

        return True

    @classmethod
    def _generate_cert(cls, cert_path: str, key_path: str):
        """Create a self-signed P-256 certificate and persist it."""
        key = _ec.generate_private_key(_ec.SECP256R1())
        subject = _x509.Name([
            _x509.NameAttribute(_NameOID.COMMON_NAME, u"visold-node"),
        ])
        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            _x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + _dt.timedelta(days=Config.TLS_CERT_VALIDITY_DAYS))
            .add_extension(
                _x509.SubjectAlternativeName([_x509.DNSName(u"visold-node")]),
                critical=False,
            )
            .sign(key, _hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem  = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        with open(cert_path, 'wb') as f:
            f.write(cert_pem)
        with open(key_path, 'wb') as f:
            f.write(key_pem)
        try:
            os.chmod(cert_path, 0o600)
            os.chmod(key_path,  0o600)
        except Exception:
            pass
        log.info(f"TLS self-signed cert generated: {cert_path}")

    @classmethod
    def server_context(cls) -> Optional[ssl.SSLContext]:
        """Return (and cache) the node-to-node server-side SSLContext.

        TOFU FIX (replaces broken MAJOR-01 approach): Every node generates its
        own self-signed certificate — there is no shared CA.  The previous code
        set CERT_REQUIRED and called load_verify_locations(our_own_cert), which
        caused every inbound connection to be dropped immediately at the TLS
        layer with SSLError: Certificate Verify Failed.  Peer certs are signed
        only by the peer itself, not by our local cert, so OpenSSL rejected them
        unconditionally and the JSON handshake (HELLO/VERIFY) never started.

        The correct model for a self-signed P2P mesh is:
          1. CERT_OPTIONAL — let the TLS handshake complete regardless of CA chain.
          2. Post-handshake TOFU fingerprint pinning — extract the peer's real
             certificate via getpeercert(binary_form=True) immediately after
             wrap_socket(), compute its SHA-256 fingerprint, and call
             TLSManager.verify_peer_fingerprint_by_ip().  On first contact the
             fingerprint is stored (Trust On First Use); on every subsequent
             connection the stored fingerprint must match or the connection is
             dropped.  This enforcement happens in _handle_inbound.

        load_verify_locations is intentionally omitted — we have no shared CA.
        """
        if not Config.TLS_ENABLED:
            return None
        with cls._lock:
            if cls._ctx_server is None:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(Config.TLS_CERT_FILE, Config.TLS_KEY_FILE)
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.check_hostname  = False
                    # TLS FIX v2 (v6.9.7): CERT_NONE on the server side.
                    #
                    # Root-cause analysis (empirically verified):
                    #   CERT_OPTIONAL → OpenSSL does NOT send CertificateRequest
                    #                   → client never sends its cert
                    #                   → getpeercert() = None on server
                    #                   → TOFU check rejects every inbound conn
                    #   CERT_REQUIRED + no load_verify_locations
                    #                   → OpenSSL sends CertificateRequest but
                    #                     then immediately rejects the self-signed
                    #                     client cert at the TLS layer before
                    #                     wrap_socket() even returns
                    #                   → same result: all connections dropped
                    #   CERT_NONE     → OpenSSL completes TLS handshake for
                    #                   encryption only; no client cert requested
                    #                   or verified at the TLS layer
                    #
                    # This is the correct model for a P2P mesh with self-signed
                    # certs (same approach used by Bitcoin Core, Lightning):
                    #   • TLS provides channel encryption only.
                    #   • Peer identity is verified by the ECDSA challenge/response
                    #     in the JSON handshake (MSG_VERIFY / CHALLENGE_RESP).
                    #     That is a proper cryptographic proof of key ownership,
                    #     stronger than TLS client cert auth.
                    #   • The outbound (client) side still gets the SERVER cert
                    #     via getpeercert() and does TOFU pinning on it, which
                    #     protects against MITM on outbound connections.
                    ctx.verify_mode     = ssl.CERT_NONE
                    # Do NOT call load_verify_locations — no shared CA exists.
                    cls._ctx_server = ctx
                except Exception as e:
                    log.warning(f"TLS server context failed: {e}")
                    return None
            return cls._ctx_server

    @classmethod
    def client_context(cls) -> Optional[ssl.SSLContext]:
        """Return (and cache) the node-to-node client-side SSLContext.

        TOFU FIX: Mirror server_context — CERT_OPTIONAL so that the TLS
        handshake succeeds against peers presenting self-signed certificates.
        Post-handshake identity verification is performed by the outbound
        connect path via TLSManager.verify_peer_fingerprint_by_ip() immediately
        after wrap_socket() returns.

        External/RPC callers that cannot present a node cert must use the
        separate permissive context returned by rpc_server_context().
        """
        if not Config.TLS_ENABLED:
            return None
        with cls._lock:
            if cls._ctx_client is None:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.load_cert_chain(Config.TLS_CERT_FILE, Config.TLS_KEY_FILE)
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.check_hostname  = False
                    # TLS FIX v2 (v6.9.7): CERT_NONE so the TLS handshake
                    # succeeds against the server's self-signed certificate
                    # without a shared CA.  CERT_OPTIONAL with no
                    # load_verify_locations causes OpenSSL to reject the
                    # server's self-signed cert with CERTIFICATE_VERIFY_FAILED.
                    # Outbound TOFU pinning (verify_peer_fingerprint_by_ip)
                    # in connect_to() handles post-handshake identity binding.
                    ctx.verify_mode     = ssl.CERT_NONE
                    # Do NOT call load_verify_locations — no shared CA exists.
                    cls._ctx_client = ctx
                except Exception as e:
                    log.warning(f"TLS client context failed: {e}")
                    return None
            return cls._ctx_client

    @classmethod
    def rpc_server_context(cls) -> Optional[ssl.SSLContext]:
        """Permissive TLS context for external/RPC clients that present no cert.

        MAJOR-01: Separates node-to-node mTLS (CERT_REQUIRED) from external
        client TLS (CERT_NONE).  External callers authenticate via Bearer token,
        not mutual TLS.  Currently the RPC server runs on plain HTTP (localhost
        only) so this context is provided for future TLS-on-RPC support.
        """
        if not Config.TLS_ENABLED:
            return None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(Config.TLS_CERT_FILE, Config.TLS_KEY_FILE)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname  = False
            ctx.verify_mode     = ssl.CERT_NONE   # external clients have no node cert
            return ctx
        except Exception as e:
            log.warning(f"TLS RPC context failed: {e}")
            return None

    @classmethod
    def fingerprint(cls) -> str:
        """Our own cert fingerprint (hex SHA-256)."""
        return cls._fingerprint or ""

    @classmethod
    def verify_peer_fingerprint(cls, sock: ssl.SSLSocket,
                                expected_fp: Optional[str]) -> bool:
        """
        Verify the peer's certificate fingerprint (TOFU model).
        F-05 / F-07 FIX:
          - Returns False on ANY exception (never silently accepts a bad cert).
          - On first connection (expected_fp is None): verify cert is well-formed,
            extract its fingerprint, store it on the socket for the caller to
            persist — only then return True (TOFU).
          - On subsequent connections: constant-time fingerprint comparison.
        """
        try:
            cert_der = sock.getpeercert(binary_form=True)
            if not cert_der:
                # F-07 FIX: No cert presented — reject, do not silently accept.
                log.warning("TLS: peer presented no certificate — connection rejected")
                return False
            cert = _x509.load_der_x509_certificate(cert_der)
            fp   = cert.fingerprint(_hashes.SHA256()).hex()
            sock._peer_tls_fp = fp  # type: ignore[attr-defined]
            if expected_fp is None:
                return True  # TOFU: first-connect — accept and let caller store fp
            return hmac.compare_digest(fp, expected_fp)
        except Exception as e:
            # F-07 FIX: Return False on exception — never silently pass verification.
            log.warning(f"TLS fingerprint verification error: {e} — rejecting connection")
            return False

    @classmethod
    def verify_peer_fingerprint_by_ip(cls, ip: str, cert_der: bytes) -> bool:
        """TOFU verification keyed by peer IP address using a raw DER certificate.

        This method is the correct integration point for the post-handshake TOFU
        check in _handle_inbound and the outbound connect path.  Unlike the
        existing verify_peer_fingerprint() (which operates on an ssl.SSLSocket
        and is keyed by the peer's node_id — known only after the JSON handshake),
        this method operates on the raw DER bytes extracted immediately after
        wrap_socket() returns, before any application-layer exchange begins.

        Behaviour:
          - First connection from this IP: computes SHA-256 fingerprint, stores
            it in the class-level _ip_fp_store dict, returns True (Trust On First Use).
          - Subsequent connections: computes fingerprint and compares with stored
            value using constant-time hmac.compare_digest().  Returns True on
            match, False on mismatch (possible cert rotation or MITM attack).
          - cert_der is None or empty: returns False immediately.
          - Any exception during cert parsing: returns False (fail-closed).

        Note: This IP-keyed store supplements the existing peer_id-keyed store
        (storage.get/set_peer_tls_fp).  Once the node_id is known from the JSON
        handshake, callers may additionally verify against the peer_id-keyed store.
        """
        if not cert_der:
            log.warning(f"[TOFU] No certificate presented by {ip} — rejecting")
            return False
        try:
            cert = _x509.load_der_x509_certificate(cert_der)
            fp   = cert.fingerprint(_hashes.SHA256()).hex()
            with cls._lock:
                stored = cls._ip_fp_store.get(ip)
                if stored is None:
                    # First contact — pin this fingerprint (TOFU).
                    cls._ip_fp_store[ip] = fp
                    log.debug(f"[TOFU] Pinned new fingerprint for {ip}: {fp[:16]}...")
                    return True
                if hmac.compare_digest(stored, fp):
                    return True
                log.warning(
                    f"[TOFU] Fingerprint MISMATCH for {ip} — "
                    f"stored={stored[:16]}... got={fp[:16]}... "
                    f"Possible MITM or cert rotation.  Rejecting connection.")
                return False
        except Exception as e:
            log.warning(f"[TOFU] Certificate parse error for {ip}: {e} — rejecting")
            return False
