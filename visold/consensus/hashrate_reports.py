"""Authenticated, replay-resistant hashrate report payloads for P2P gossip.

These reports authenticate which wallet made a rate claim; they cannot prove
that the claimed hardware rate is honest. The governor therefore treats them
as advisory telemetry only, never as consensus data.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from typing import Any, Mapping, Optional

from visold.crypto.ecc import ecdsa_verify, pub_from_hex, sig_from_hex, sig_to_hex

MAX_REPORT_HPS = float(1 << 48)


def hashrate_report_payload(report: Mapping[str, Any]) -> dict:
    """Canonical signed fields; hop TTL is intentionally unsigned and mutable."""
    return {
        "version": int(report.get("version", 1)),
        "node_id": str(report.get("node_id", "")),
        "pub_hex": str(report.get("pub_hex", "")),
        "hashrate": float(report.get("hashrate", -1.0)),
        "ts": int(report.get("ts", 0)),
        "seq": int(report.get("seq", 0)),
    }


def hashrate_report_signing_bytes(report: Mapping[str, Any]) -> bytes:
    return json.dumps(hashrate_report_payload(report), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_hashrate_report(wallet: Any, node_id: str, hps: float,
                         issued_at: Optional[int] = None,
                         sequence: Optional[int] = None) -> dict:
    """Create a wallet-signed rate report, compatible with Visold ECDSA APIs."""
    now = int(time.time()) if issued_at is None else int(issued_at)
    seq = time.time_ns() if sequence is None else int(sequence)
    pub_hex = str(wallet.pub_hex)
    expected_node_id = hashlib.sha256(pub_hex.encode("ascii")).hexdigest()
    if str(node_id) != expected_node_id:
        raise ValueError("node_id does not match the signing wallet public key")
    report = {
        "type": "HASHRATE_REPORT",
        "version": 1,
        "node_id": str(node_id),
        "pub_hex": pub_hex,
        "hashrate": float(hps),
        "ts": now,
        "seq": seq,
    }
    if not math.isfinite(report["hashrate"]) or not (0.0 < report["hashrate"] <= MAX_REPORT_HPS):
        raise ValueError("hashrate report is outside the allowed range")
    if seq < 1 or now < 1:
        raise ValueError("hashrate report timestamp/sequence must be positive")
    signature = wallet.sign(hashrate_report_signing_bytes(report))
    report["sig"] = sig_to_hex(signature)
    return report


def verify_hashrate_report(report: Any, *, now: Optional[float] = None,
                           max_age_seconds: int = 300,
                           max_future_skew_seconds: int = 30) -> bool:
    """Verify structure, freshness, identity binding and signature."""
    if not isinstance(report, dict):
        return False
    try:
        raw_hps = report.get("hashrate")
        raw_ts = report.get("ts")
        raw_seq = report.get("seq")
        if isinstance(raw_hps, bool) or isinstance(raw_ts, bool) or isinstance(raw_seq, bool):
            return False
        hps = float(raw_hps)
        issued_at = int(raw_ts)
        sequence = int(raw_seq)
        version = int(report.get("version", 0))
        node_id = str(report.get("node_id", ""))
        pub_hex = str(report.get("pub_hex", ""))
        if (version != 1 or not math.isfinite(hps) or hps <= 0.0
                or hps > MAX_REPORT_HPS or sequence < 1 or issued_at <= 0):
            return False
        if str(issued_at) != str(raw_ts).strip() or str(sequence) != str(raw_seq).strip():
            return False
        if len(node_id) != 64 or len(pub_hex) != 66:
            return False
        if hashlib.sha256(pub_hex.encode("ascii")).hexdigest() != node_id:
            return False
        now_value = float(time.time() if now is None else now)
        if issued_at > now_value + max(0, int(max_future_skew_seconds)):
            return False
        if now_value - issued_at > max(1, int(max_age_seconds)):
            return False
        signature = sig_from_hex(str(report.get("sig", "")))
        digest = hashlib.sha256(hashrate_report_signing_bytes(report)).digest()
        return bool(ecdsa_verify(pub_from_hex(pub_hex), digest, signature))
    except Exception:
        return False
