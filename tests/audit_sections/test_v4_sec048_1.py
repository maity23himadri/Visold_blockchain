"""V4 regression tests for Section 48: Authenticated Hashrate Reports & Signature Verification."""
from __future__ import annotations

import hashlib
import math
import time
from types import SimpleNamespace

import pytest

from visold.consensus.hashrate_reports import (
    MAX_REPORT_HPS,
    hashrate_report_payload,
    sign_hashrate_report,
    verify_hashrate_report,
)
from visold.kernel.messages import MSG_HASHRATE_REPORT
from visold.network.p2p import P2PNetwork
from visold.wallet.wallet import Wallet


def _make_wallet_and_id():
    w = Wallet.generate()
    nid = hashlib.sha256(w.pub_hex.encode("ascii")).hexdigest()
    return w, nid


def test_section48_sign_and_verify_tamper_and_mutable_ttl():
    wallet, node_id = _make_wallet_and_id()
    now = int(time.time())
    report = sign_hashrate_report(wallet, node_id, 1234.5, issued_at=now, sequence=1)

    assert verify_hashrate_report(report, now=now) is True

    relayed = dict(report, ttl=3)
    assert verify_hashrate_report(relayed, now=now) is True

    for field, bad_val in [
        ("hashrate", 1234.6),
        ("ts", now + 1),
        ("seq", 2),
        ("version", 2),
    ]:
        tampered = dict(report)
        tampered[field] = bad_val
        assert verify_hashrate_report(tampered, now=now + 1) is False


def test_section48_identity_binding_and_key_mismatch():
    w1, nid1 = _make_wallet_and_id()
    w2, nid2 = _make_wallet_and_id()
    now = int(time.time())

    with pytest.raises(ValueError):
        sign_hashrate_report(w1, nid2, 500.0, issued_at=now, sequence=1)

    report = sign_hashrate_report(w1, nid1, 500.0, issued_at=now, sequence=1)

    bad_nid = dict(report, node_id=nid2)
    assert verify_hashrate_report(bad_nid, now=now) is False

    bad_pub = dict(report, pub_hex=w2.pub_hex)
    assert verify_hashrate_report(bad_pub, now=now) is False

    forged = dict(report, node_id=nid2, pub_hex=w2.pub_hex)
    assert verify_hashrate_report(forged, now=now) is False


def test_section48_freshness_skew_and_type_bounds():
    wallet, node_id = _make_wallet_and_id()
    now = int(time.time())
    report = sign_hashrate_report(wallet, node_id, 1000.0, issued_at=now, sequence=10)

    assert verify_hashrate_report(report, now=now + 300, max_age_seconds=300) is True
    assert verify_hashrate_report(report, now=now + 301, max_age_seconds=300) is False
    assert verify_hashrate_report(report, now=now - 30, max_future_skew_seconds=30) is True
    assert verify_hashrate_report(report, now=now - 31, max_future_skew_seconds=30) is False

    assert verify_hashrate_report(dict(report, hashrate=True), now=now) is False
    assert verify_hashrate_report(dict(report, ts=True), now=now) is False
    assert verify_hashrate_report(dict(report, seq=True), now=now) is False
    assert verify_hashrate_report(dict(report, ts=float(now)), now=now) is False
    assert verify_hashrate_report(dict(report, seq="10.0"), now=now) is False
    assert verify_hashrate_report(dict(report, hashrate=math.nan), now=now) is False
    assert verify_hashrate_report(dict(report, hashrate=MAX_REPORT_HPS + 1.0), now=now) is False
    assert verify_hashrate_report("not-a-dict", now=now) is False


def test_section48_p2p_handler_relay_replay_and_self_echo(monkeypatch):
    local_w, local_nid = _make_wallet_and_id()
    peer_w, peer_nid = _make_wallet_and_id()

    net = P2PNetwork.__new__(P2PNetwork)
    net.node_id = local_nid
    net.wallet = local_w
    net._hr_reports_lock = __import__("threading").Lock()
    net._hr_reports_seen = {}
    net._hr_reports_seen_max = 10000
    net._mining_engine_ref = None
    net._callbacks = {}
    net._check_msg_rate = lambda peer, mtype: True

    gossiped = []
    monkeypatch.setattr(net, "_gossip", lambda msg, exclude=None, ttl=None: gossiped.append((msg, exclude)))

    peer = SimpleNamespace(peer_id=peer_nid, connected=True)
    now = int(time.time())

    self_report = sign_hashrate_report(local_w, local_nid, 900.0, issued_at=now, sequence=1)
    net._handle_message(peer, self_report)
    assert len(gossiped) == 0

    r1 = sign_hashrate_report(peer_w, peer_nid, 1500.0, issued_at=now, sequence=10)
    net._handle_message(peer, r1)
    assert len(gossiped) == 1
    assert gossiped[0][1] == peer_nid

    net._handle_message(peer, r1)
    r_same_ts = sign_hashrate_report(peer_w, peer_nid, 1600.0, issued_at=now, sequence=11)
    net._handle_message(peer, r_same_ts)
    assert len(gossiped) == 1

    r2 = sign_hashrate_report(peer_w, peer_nid, 1600.0, issued_at=now + 5, sequence=12)
    net._handle_message(peer, r2)
    assert len(gossiped) == 2

    unsigned = {"type": MSG_HASHRATE_REPORT, "node_id": peer_nid, "hashrate": 2000.0}
    net._handle_message(peer, unsigned)
    assert len(gossiped) == 2
