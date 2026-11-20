"""V4 regression tests for Section 24 (Session 02): Signature Malleability, Binding, and Parallel Verification."""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.crypto.ecc import (
    ECPoint,
    _canonical_low_s,
    sig_from_hex,
    sig_to_hex,
)
from visold.crypto.parallel_verify import _par_verify_sig, _par_verify_sig_batch
from visold.kernel.config import Config
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.network.receipt_relay import _ACK_DOMAIN, ReceiptRelayManager
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def test_low_s_signing_and_txid_immunity_to_sig_malleability():
    w1 = Wallet.generate()
    w2 = Wallet.generate()
    ts = int(time.time())
    tx = Transaction(
        sender=w1.address,
        receiver=w2.address,
        amount=5.0,
        fee=0.05,
        timestamp=ts,
        nonce=0,
        expiry=ts + 3600,
    )
    tx.sign(w1)
    r, s = sig_from_hex(tx.sig_hex)
    assert 1 <= r < ECPoint.N
    assert 1 <= s <= ECPoint.N // 2
    assert tx.verify_signature()

    # High-S form (r, N - s) does not change tx_id
    high_s = ECPoint.N - s
    assert high_s > ECPoint.N // 2
    assert _canonical_low_s(high_s) == s
    tx_malleated = Transaction.from_dict({**tx.to_dict(), "sig_hex": sig_to_hex((r, high_s))})
    assert tx_malleated.tx_id == tx.tx_id
    assert tx_malleated._compute_id() == tx.tx_id
    assert tx_malleated.verify_signature()

    # JSON whitespace malleability in sig_hex does not change tx_id
    tx_ws = Transaction.from_dict({**tx.to_dict(), "sig_hex": f"[ {r} ,  {s} ]"})
    assert tx_ws.tx_id == tx.tx_id
    assert tx_ws.verify_signature()


def test_sender_pubkey_binding_and_parallel_parity():
    w1 = Wallet.generate()
    w2 = Wallet.generate()
    ts = int(time.time())
    tx = Transaction(
        sender=w1.address,
        receiver=w2.address,
        amount=1.0,
        fee=0.01,
        timestamp=ts,
        nonce=0,
        expiry=ts + 3600,
    )
    # Sign with w2's key while claiming sender=w1.address
    tx.sign(w2)
    assert not tx.verify_signature()
    ok, msg = tx.is_valid(reference_time=ts)
    assert not ok
    assert "Invalid signature" in msg
    assert not _par_verify_sig(tx.pub_hex, tx.sig_hex, tx.signing_bytes(), sender=tx.sender)

    # Valid signature passes both sequential and parallel batch verification
    tx_good = Transaction(
        sender=w1.address,
        receiver=w2.address,
        amount=1.0,
        fee=0.01,
        timestamp=ts,
        nonce=0,
        expiry=ts + 3600,
    )
    tx_good.sign(w1)
    assert tx_good.verify_signature()
    assert _par_verify_sig(tx_good.pub_hex, tx_good.sig_hex, tx_good.signing_bytes(), sender=tx_good.sender)
    batch_res = _par_verify_sig_batch([
        (tx_good.pub_hex, tx_good.sig_hex, tx_good.signing_bytes(), tx_good.sender, None),
        (tx.pub_hex, tx.sig_hex, tx.signing_bytes(), tx.sender, None),
    ])
    assert batch_res == 1


def test_mempool_signature_fingerprint_fail_closed(tmp_path):
    storage = Storage(str(tmp_path / "mp_sec24.db"))
    mp = Mempool(storage)
    w1 = Wallet.generate()
    w2 = Wallet.generate()
    ts = int(time.time())
    tx = Transaction(
        sender=w1.address,
        receiver=w2.address,
        amount=1.0,
        fee=0.01,
        timestamp=ts,
        nonce=0,
        expiry=ts + 3600,
    )
    tx.sign(w1)
    mp._record_signature_verified(tx)
    assert mp.is_verified(tx.tx_id, tx=tx, signing_payload=tx.signing_bytes())

    # Mutating sig_hex while keeping tx_id identical must miss cache (fail closed)
    r, s = sig_from_hex(tx.sig_hex)
    tx_bad_sig = Transaction.from_dict({**tx.to_dict(), "sig_hex": sig_to_hex((r, s + 1))})
    assert tx_bad_sig.tx_id == tx.tx_id
    assert not mp.is_verified(tx_bad_sig.tx_id, tx=tx_bad_sig, signing_payload=tx_bad_sig.signing_bytes())


def test_receipt_ack_signature_verification():
    w1 = Wallet.generate()
    w2 = Wallet.generate()
    rid = "a" * 64

    payload = f"{_ACK_DOMAIN}|{Config.CHAIN_ID}|{w1.address}|{rid}".encode()
    sig = sig_to_hex(w1.sign(payload))
    ack = {
        "domain": _ACK_DOMAIN,
        "version": 1,
        "chain_id": Config.CHAIN_ID,
        "receiver": w1.address,
        "receipt_id": rid,
        "pub_hex": w1.pub_hex,
        "sig_hex": sig,
    }
    ok, msg = ReceiptRelayManager.verify_ack(ack)
    assert ok, msg

    # Wrong receiver (sender-pubkey mismatch)
    bad_ack = dict(ack, receiver=w2.address)
    ok_bad, _ = ReceiptRelayManager.verify_ack(bad_ack)
    assert not ok_bad
