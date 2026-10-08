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
"""visold.crypto.vrf


Defines: vrf_prove, vrf_verify
Origin: visold_vsd_.py L10514, L10517-10518, L10523-10559, L10564-10567, L10570-10586, L10589-10591, L10596-10617, L10622-10633, L10638-10691, L10696-10768
"""

import hashlib
import hmac

from visold.crypto.ecc import ECPoint, G, pub_from_hex


# ── 2E. EC-VRF  (ECVRF-secp256k1-SHA256-TAI) ─────────────────────────────────
# Upgraded from ECVRF-P256-SHA256-TAI to ECVRF-secp256k1-SHA256-TAI.
#
# What changed and why:
#   1. Hand-rolled P-256 arithmetic (_p256_mul, _p256_add) removed entirely.
#      All EC math now goes through ECPoint.__rmul__ / ECPoint.__add__ (already
#      used and validated by the ECDSA path) or the `cryptography` library for
#      generator-point multiplications.  This eliminates timing side-channels
#      and correctness bugs in the double-and-add implementation.
#
#   2. Curve mixing fixed.  The old vrf_prove() derived a P-256 point from a
#      secp256k1 private key and the old vrf_verify() fed secp256k1 (x, y)
#      coordinates into P-256 arithmetic — the two curves are unrelated.  VRF
#      is now entirely secp256k1, the same curve used by all VSD wallet keys.
#
#   3. Full RFC-6979 HMAC-SHA256 DRBG nonce (Section 2.4) replaces the single-
#      step HMAC shortcut.  The full algorithm guarantees k ∈ [1, N-1] and
#      provides proper domain separation between the private key and the message.
#
# Construction: ECVRF-secp256k1-SHA256-TAI (Try-And-Increment hash-to-curve)
# Proof format: compressed(Gamma)[33] || c[16] || s[32]  = 81 bytes  (unchanged)
# Beta  format: SHA256(SUITE || 0x03 || compressed(Gamma)) = 32 bytes (unchanged)
#
# References:
#   draft-irtf-cfrg-vrf-09  (ECVRF-secp256k1-SHA256-TAI)
#   RFC 6979  Section 2.4   (deterministic nonce k)

# Suite byte for ECVRF-secp256k1-SHA256-TAI (0xfe = custom, distinct from P-256 0x01)
_VRF_SUITE = b"\xfe"


# secp256k1 group order and field prime (same as ECPoint.N / ECPoint.P)
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


# ── A. RFC-6979 Full HMAC-SHA256 DRBG nonce ──────────────────────────────────

def _rfc6979_nonce(priv: int, msg: bytes) -> int:
    """
    Generate a deterministic nonce k per RFC 6979 Section 2.4.

    Uses the full HMAC-SHA256 DRBG with V/K initialisation, domain separation
    between the private key and message hash, and an iteration loop that
    guarantees k ∈ [1, N-1].
    """
    N  = _SECP256K1_N
    x  = priv.to_bytes(32, 'big')
    h1 = hashlib.sha256(msg).digest()   # h1 = H(msg)

    # Steps b-c: initialise V and K (RFC 6979 §2.4)
    V  = b'\x01' * 32
    K  = b'\x00' * 32

    # Step d
    K = hmac.new(K, V + b'\x00' + x + h1, hashlib.sha256).digest()
    # Step e
    V = hmac.new(K, V, hashlib.sha256).digest()
    # Step f
    K = hmac.new(K, V + b'\x01' + x + h1, hashlib.sha256).digest()
    # Step g
    V = hmac.new(K, V, hashlib.sha256).digest()

    # Step h: generate candidates until k ∈ [1, N-1]
    while True:
        T = b''
        while len(T) < 32:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T = T + V
        k = int.from_bytes(T[:32], 'big')
        if 1 <= k < N:
            return k
        # Reseed and retry
        K = hmac.new(K, V + b'\x00', hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


# ── B. secp256k1 point helpers ────────────────────────────────────────────────

def _vrf_point_to_bytes(pt: ECPoint) -> bytes:
    """Compressed SEC encoding of a secp256k1 point (02/03 prefix)."""
    prefix = b'\x02' if (pt.y & 1) == 0 else b'\x03'
    return prefix + pt.x.to_bytes(32, 'big')


def _vrf_scalar_mul_G(k: int) -> ECPoint:
    """
    Compute k * G on secp256k1 using the `cryptography` library.
    Falls back to ECPoint arithmetic only on library failure.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import (
            derive_private_key, SECP256K1 as _SK)
        from cryptography.hazmat.backends import default_backend as _db
        k_mod = k % _SECP256K1_N
        if k_mod == 0:
            return ECPoint.inf()
        priv_key = derive_private_key(k_mod, _SK(), _db())
        pn = priv_key.public_key().public_numbers()
        return ECPoint(pn.x, pn.y)
    except Exception:
        return k * G


def _vrf_scalar_mul_point(k: int, pt: ECPoint) -> ECPoint:
    """Compute k * pt on secp256k1 via ECPoint.__rmul__ (ECDSA-validated path)."""
    return k * pt


# ── C. Hash-to-curve: Try-And-Increment on secp256k1 ─────────────────────────

def _secp256k1_hash_to_curve(pub_bytes: bytes, alpha: bytes) -> ECPoint:
    """
    ECVRF_hash_to_try_and_increment for secp256k1.

    Deterministically maps (pub_bytes, alpha) to a point H on secp256k1.
    secp256k1 curve equation: y² ≡ x³ + 7  (mod P)
    """
    P = _SECP256K1_P
    for ctr in range(256):
        hash_input = _VRF_SUITE + b"\x01" + pub_bytes + alpha + bytes([ctr]) + b"\x00"
        h = hashlib.sha256(hash_input).digest()
        x = int.from_bytes(h, 'big') % P
        # secp256k1: y² = x³ + 7
        y2 = (pow(x, 3, P) + 7) % P
        y  = pow(y2, (P + 1) // 4, P)
        if pow(y, 2, P) == y2 % P:
            if (y & 1) != 0:
                y = P - y
            pt = ECPoint(x, y)
            if not pt.is_inf():
                return pt
    raise ValueError("VRF hash_to_curve: all 256 candidates failed (impossible)")


# ── D. Challenge generation ───────────────────────────────────────────────────

def _vrf_challenge(pub_bytes: bytes, H: ECPoint, Gamma: ECPoint,
                   U: ECPoint, V: ECPoint) -> int:
    """ECVRF_challenge_generation: hash five secp256k1 points to a 128-bit int."""
    def enc(pt: ECPoint) -> bytes:
        prefix = b'\x02' if (pt.y & 1) == 0 else b'\x03'
        return prefix + pt.x.to_bytes(32, 'big')

    data = (_VRF_SUITE + b"\x02"
            + pub_bytes
            + enc(H) + enc(Gamma) + enc(U) + enc(V))
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest[:16], 'big')   # 128-bit challenge


# ── E. VRF Prove ──────────────────────────────────────────────────────────────

def vrf_prove(priv: int, alpha: bytes) -> tuple:
    """
    ECVRF-secp256k1-SHA256-TAI prove.

    Returns (proof_bytes, beta_bytes).
    proof_bytes = compressed(Gamma)[33] || c[16] || s[32]  = 81 bytes
    beta        = SHA256(SUITE || 0x03 || compressed(Gamma)) = 32 bytes

    Algorithm:
      1. pub   = priv * G               (library-backed, no hand-rolled math)
      2. H     = hash_to_curve(pub, alpha)
      3. Gamma = priv * H
      4. k     = RFC-6979(priv, H_bytes) (full HMAC-DRBG)
      5. U     = k * G
      6. V     = k * H
      7. c     = challenge(pub, H, Gamma, U, V)
      8. s     = (k - c*priv) mod N
      9. proof = compress(Gamma) || c[16] || s[32]
     10. beta  = SHA256(SUITE || 0x03 || compress(Gamma))
    """
    N = _SECP256K1_N

    # Step 1: public key via cryptography library (no hand-rolled math)
    pub_pt    = _vrf_scalar_mul_G(priv)
    pub_bytes = _vrf_point_to_bytes(pub_pt)

    # Step 2: deterministic hash-to-curve
    H = _secp256k1_hash_to_curve(pub_bytes, alpha)

    # Step 3: Gamma = priv * H
    Gamma = _vrf_scalar_mul_point(priv, H)

    # Step 4: deterministic nonce k — full RFC-6979 HMAC-DRBG
    k_input = _vrf_point_to_bytes(H) + alpha    # domain-separated binding
    k = _rfc6979_nonce(priv, k_input)

    # Steps 5-6: commitments
    U = _vrf_scalar_mul_G(k)
    V = _vrf_scalar_mul_point(k, H)

    # Step 7: challenge
    c = _vrf_challenge(pub_bytes, H, Gamma, U, V)

    # Step 8: s = (k - c*priv) mod N
    s = (k - c * priv) % N

    # Step 9: proof
    gamma_bytes = _vrf_point_to_bytes(Gamma)
    proof       = gamma_bytes + c.to_bytes(16, 'big') + s.to_bytes(32, 'big')

    # Step 10: beta
    beta = hashlib.sha256(_VRF_SUITE + b"\x03" + gamma_bytes).digest()

    return proof, beta


# ── F. VRF Verify ─────────────────────────────────────────────────────────────

def vrf_verify(pub_hex: str, alpha: bytes, proof: bytes, beta: bytes) -> bool:
    """
    ECVRF-secp256k1-SHA256-TAI verify.

    pub_hex : secp256k1 compressed-SEC hex (same key format used by VSD wallets).
    proof   : 81-byte proof from vrf_prove.
    beta    : 32-byte output from vrf_prove.

    Returns True if proof is valid and beta matches; False otherwise.
    Never raises — all exceptions are caught and return False.
    """
    if not pub_hex:
        return False
    if not proof or len(proof) != 81:
        return False
    if not beta or len(beta) != 32:
        return False

    try:
        N = _SECP256K1_N

        # 1. Decode public key (secp256k1, consistent with wallet)
        pub_pt    = pub_from_hex(pub_hex)
        pub_bytes = _vrf_point_to_bytes(pub_pt)

        # 2. Decode proof
        gamma_bytes = proof[:33]
        c_int       = int.from_bytes(proof[33:49], 'big')
        s_int       = int.from_bytes(proof[49:81], 'big')

        if not (0 <= s_int < N):
            return False

        # 3. Decode Gamma from compressed secp256k1 point
        if gamma_bytes[0] not in (0x02, 0x03):
            return False
        P   = _SECP256K1_P
        gx  = int.from_bytes(gamma_bytes[1:], 'big')
        gy2 = (pow(gx, 3, P) + 7) % P              # secp256k1: y² = x³ + 7
        gy  = pow(gy2, (P + 1) // 4, P)
        if pow(gy, 2, P) != gy2 % P:
            return False
        if (gy & 1) != (gamma_bytes[0] & 1):
            gy = P - gy
        Gamma = ECPoint(gx, gy)
        if Gamma.is_inf():
            return False

        # 4. Recompute H
        H = _secp256k1_hash_to_curve(pub_bytes, alpha)

        # 5. Recompute commitments
        # U' = s*G + c*pub
        sG  = _vrf_scalar_mul_G(s_int)
        cP  = _vrf_scalar_mul_point(c_int, pub_pt)
        U_v = sG + cP

        # V' = s*H + c*Gamma
        sH  = _vrf_scalar_mul_point(s_int, H)
        cGm = _vrf_scalar_mul_point(c_int, Gamma)
        V_v = sH + cGm

        # 6. Recompute challenge
        c_check = _vrf_challenge(pub_bytes, H, Gamma, U_v, V_v)
        if c_check != c_int:
            return False

        # 7. Verify beta
        expected_beta = hashlib.sha256(_VRF_SUITE + b"\x03" + gamma_bytes).digest()
        return hmac.compare_digest(expected_beta, beta)

    except Exception:
        return False
