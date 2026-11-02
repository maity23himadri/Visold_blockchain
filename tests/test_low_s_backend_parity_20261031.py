"""Regression: the optional native backend must accept exactly the signatures
the OpenSSL fallback accepts.  A node with coincurve installed and a node
without it must never disagree about whether a signature is valid.

libsecp256k1 only accepts lower-S signatures.  coincurve is not available in
every environment, so the native side is emulated by a fake that enforces that
documented rule.  The fake is a test double, not proof of libsecp's behaviour.
"""
import hashlib
import random

import pytest

from visold.crypto import ecc
from visold.crypto.ecc import ECPoint, ecdsa_keygen, ecdsa_sign, ecdsa_verify


class _StrictLowSNative:
    """Emulates libsecp256k1 verify: rejects high-S, otherwise checks ECDSA."""

    def __init__(self, pub: ECPoint):
        self._key = ecc._cached_crypto_public_key(pub.x, pub.y)

    def verify(self, sig_der, digest, hasher=None):
        _r, s = ecc.decode_dss_signature(sig_der)
        if s > ECPoint.N // 2:
            return False
        try:
            self._key.verify(sig_der, digest, ecc._ec.ECDSA(ecc.Prehashed(ecc._hashes.SHA256())))
            return True
        except Exception:
            return False


@pytest.fixture
def native_backend(monkeypatch):
    """Route ecdsa_verify through the strict fake, as if coincurve were active."""
    fakes = {}

    def factory(pub_bytes):
        if pub_bytes not in fakes:
            pub = ecc.pub_from_bytes(pub_bytes)
            fakes[pub_bytes] = _StrictLowSNative(pub)
        return fakes[pub_bytes]

    monkeypatch.setattr(ecc, "_COINCURVE_SELFTEST_OK", True)
    monkeypatch.setattr(ecc, "_cached_coincurve_public_key", factory)
    return fakes


def _fallback_verdict(pub, h, sig):
    """Verdict from the mandatory cryptography path only."""
    saved = ecc._COINCURVE_SELFTEST_OK
    ecc._COINCURVE_SELFTEST_OK = False
    try:
        return ecdsa_verify(pub, h, sig)
    finally:
        ecc._COINCURVE_SELFTEST_OK = saved


def test_emulated_native_backend_really_rejects_high_s(native_backend):
    # Guard: the fake must enforce lower-S, or the parity tests prove nothing.
    priv, pub = ecdsa_keygen()
    h = hashlib.sha256(b"guard").digest()
    r, s = ecdsa_sign(priv, h)
    digest = ecc._effective_ecdsa_digest(h)
    native = ecc._cached_coincurve_public_key(ecc.pub_to_bytes(pub))
    assert native.verify(ecc.encode_dss_signature(r, s), digest, hasher=None) is True
    assert native.verify(ecc.encode_dss_signature(r, ECPoint.N - s), digest, hasher=None) is False


def test_both_signature_forms_accepted_on_native_path(native_backend):
    priv, pub = ecdsa_keygen()
    for i in range(60):
        h = hashlib.sha256(f"both-forms-{i}".encode()).digest()
        r, s = ecdsa_sign(priv, h)
        assert ecdsa_verify(pub, h, (r, s)) is True
        assert ecdsa_verify(pub, h, (r, ECPoint.N - s)) is True


def test_native_and_fallback_agree_on_valid_and_invalid_inputs(native_backend):
    rng = random.Random(20261031)
    for i in range(80):
        priv, pub = ecdsa_keygen()
        h = hashlib.sha256(f"parity-{i}".encode()).digest()
        r, s = ecdsa_sign(priv, h)
        candidates = [
            (r, s),
            (r, ECPoint.N - s),
            (r, (s + 1) % ECPoint.N or 1),
            (r, rng.randrange(1, ECPoint.N)),
            (r ^ 1 or 1, s),
        ]
        for sig in candidates:
            native_verdict = ecdsa_verify(pub, h, sig)
            fallback_verdict = _fallback_verdict(pub, h, sig)
            assert native_verdict == fallback_verdict, (i, sig)


def test_signers_emit_canonical_low_s_for_both_backends():
    for i in range(60):
        priv, pub = ecdsa_keygen()
        h = hashlib.sha256(f"canon-{i}".encode()).digest()
        r, s = ecdsa_sign(priv, h)
        assert s <= ECPoint.N // 2
        assert ecdsa_verify(pub, h, (r, s)) is True


def test_digest_signer_emits_canonical_low_s():
    for i in range(60):
        priv, pub = ecdsa_keygen()
        d = hashlib.sha256(f"digest-{i}".encode()).digest()
        r, s = ecc.ecdsa_sign_digest(priv, d)
        assert s <= ECPoint.N // 2
