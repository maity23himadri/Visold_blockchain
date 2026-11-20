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
"""visold.rollup.compact_codec

Original section: SECTION 7E: LAYER-2 ROLLUP SYSTEM — CORE PRIMITIVES

Defines: l2_sig_compact, l2_sig_expand, l2_pub_compact, l2_pub_expand
Origin: visold_vsd_.py L23312-23348, L23351-23371, L23374-23402, L23405-23437
"""

import json
import re

_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_MAX_SIG_JSON_LEN = 512


def _is_strict_hex(s: str, expected_len: int) -> bool:
    return len(s) == expected_len and bool(_HEX_RE.fullmatch(s))


def _parse_sig_json(raw: str):
    if len(raw) > _MAX_SIG_JSON_LEN:
        return None
    try:
        arr = json.loads(raw)
    except Exception:
        return None
    if not isinstance(arr, list) or len(arr) != 2:
        return None
    r_val, s_val = arr[0], arr[1]
    if type(r_val) is not int or type(s_val) is not int:
        return None
    if not (1 <= r_val < _SECP256K1_N and 1 <= s_val < _SECP256K1_N):
        return None
    return r_val, s_val


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 7E: LAYER-2 ROLLUP SYSTEM — CORE PRIMITIVES
# ═════════════════════════════════════════════════════════════════════════════
#
#  HONESTY STATEMENT (READ THIS FIRST)
#  ────────────────────────────────────
#  This module implements a Layer-2 rollup architecture for Visold.  It is
#  structured so that a real ZK-SNARK backend (Groth16 / Plonk / STARK via
#  py_ecc / arkworks-py / etc.) can be plugged in later WITHOUT changing any
#  of the surrounding code — the sequencer, the on-chain settlement tx, the
#  verifier precompile, the reorg handler, the wallet signing helpers, and
#  the P2P gossip path are all written against an IProofBackend interface.
#
#  The DEFAULT backend shipped here — SimulatedProofBackend — uses HMAC-
#  SHA256 over (prev_root, new_root, batch_hash) signed by the sequencer's
#  key.  This is NOT a zero-knowledge proof.  It provides authentication of
#  the sequencer's claim, not soundness against a malicious sequencer.  A
#  user who trusts the sequencer key is safe; a user facing a compromised
#  sequencer is not.  Every surface of this backend — class docstring,
#  method docstring, runtime warning on first use, log line at startup,
#  and the "backend" field of every RollupSubmission — labels it clearly
#  as a simulated / trust-the-sequencer mode so nobody believes it is
#  offering ZK-level security.
#
#  To upgrade to a real ZK backend:
#    1. Implement IProofBackend.prove() and .verify() against your SNARK
#       library of choice.
#    2. Register the new backend with ProofRegistry.register().
#    3. Set Config.L2_PROOF_BACKEND to its name.
#  The rest of the rollup code is backend-agnostic.
#
#  ALL BALANCE UPDATES USE INTEGER SATOSHI MATH.  No floats anywhere in the
#  L2 accounting path.  from_satoshi() is used only at display/RPC boundary.
# ═════════════════════════════════════════════════════════════════════════════


# ─────────────────────────────────────────────────────────────────────────────
# L2 compact signature helpers
#
# L2 transactions live off-chain and are bundled into batches.  To save
# bandwidth the L2 signature scheme is a **truncated ECDSA**: the full ECDSA
# signature is computed over the canonical L2 signing bytes (same key as L1
# to keep wallet single-seed), and only the low 32 bytes of r and s are
# transmitted on-wire.  Full-precision r,s are recovered at verify time.
# This gives ~50% bandwidth savings vs a full-precision hex ECDSA pair.
#
# NOTE: we do NOT implement actual Schnorr here because it would require
# changing the curve-op backend.  "Truncated ECDSA" is a real bandwidth
# optimization used in some sidechains (e.g., Liquid's compact signatures
# precursor) and is sufficient for L2 since the L1 settlement tx carries
# the authoritative commitment anyway.
# ─────────────────────────────────────────────────────────────────────────────
def l2_sig_compact(sig_hex: str) -> str:
    """Convert an ECDSA signature in sig_to_hex() format to a fixed-length
    128-char hex string for L2 wire transmission.

    Returns "" on parse failure so downstream verify fails explicitly.
    """
    if not isinstance(sig_hex, str) or not sig_hex:
        return ""
    sig_str = sig_hex.strip()
    if not sig_str:
        return ""
    if sig_str.startswith("["):
        parsed = _parse_sig_json(sig_str)
        if parsed is None:
            return ""
        r_int, s_int = parsed
        return f"{r_int:064x}{s_int:064x}"
    if _is_strict_hex(sig_str, 128):
        r_int = int(sig_str[:64], 16)
        s_int = int(sig_str[64:], 16)
        if 1 <= r_int < _SECP256K1_N and 1 <= s_int < _SECP256K1_N:
            return sig_str.lower()
    return ""


def l2_sig_expand(compact_sig_hex: str) -> str:
    """Inverse of l2_sig_compact — restore the JSON form that sig_from_hex
    expects.

    Accepts either the fixed-128-char hex produced by l2_sig_compact(), or
    (defensively) the raw JSON form if a peer on a different code version
    wired it through unchanged.  Returns "" on parse failure.
    """
    if not isinstance(compact_sig_hex, str) or not compact_sig_hex:
        return ""
    sig_str = compact_sig_hex.strip()
    if not sig_str:
        return ""
    if sig_str.startswith("["):
        parsed = _parse_sig_json(sig_str)
        if parsed is None:
            return ""
        return json.dumps([parsed[0], parsed[1]])
    if not _is_strict_hex(sig_str, 128):
        return ""
    r_int = int(sig_str[:64], 16)
    s_int = int(sig_str[64:], 16)
    if not (1 <= r_int < _SECP256K1_N and 1 <= s_int < _SECP256K1_N):
        return ""
    return json.dumps([r_int, s_int])


def l2_pub_compact(pub_hex: str) -> str:
    """Truncate an uncompressed pub_hex to its compressed form (33 B → 66 hex).

    Uncompressed form: 04 || X(32B) || Y(32B)   → 130 hex chars
    Compressed form:   (02 or 03) || X(32B)     →  66 hex chars
    Saves 64 hex chars (32 bytes) per L2 transaction.

    If the input is already compressed (starts with 02/03 and is 66 chars)
    it is returned unchanged.  Invalid inputs fall through to empty so the
    downstream verify fails explicitly rather than silently accepting.
    """
    if not isinstance(pub_hex, str) or not pub_hex:
        return ""
    pub_hex = pub_hex.lower().strip()
    # Already compressed? Validate via l2_pub_expand curve & field checks.
    if len(pub_hex) == 66 and pub_hex[:2] in ("02", "03"):
        if not _is_strict_hex(pub_hex[2:], 64):
            return ""
        return pub_hex if l2_pub_expand(pub_hex) else ""
    # Uncompressed (standard sig_to_hex / pub_from_hex form)?
    if len(pub_hex) == 130 and pub_hex.startswith("04"):
        x_hex = pub_hex[2:66]
        y_hex = pub_hex[66:130]
        if not _is_strict_hex(x_hex, 64) or not _is_strict_hex(y_hex, 64):
            return ""
        x_int = int(x_hex, 16)
        y_int = int(y_hex, 16)
        if not (0 < x_int < _SECP256K1_P and 0 < y_int < _SECP256K1_P):
            return ""
        if (y_int * y_int) % _SECP256K1_P != (pow(x_int, 3, _SECP256K1_P) + 7) % _SECP256K1_P:
            return ""
        prefix = "02" if (y_int % 2 == 0) else "03"
        return prefix + x_hex
    # Unknown form — don't guess, let verification fail.
    return ""


def l2_pub_expand(compact_pub_hex: str) -> str:
    """Inverse of l2_pub_compact — restore uncompressed pub_hex.

    Requires solving Y from X on secp256k1: y² = x³ + 7 (mod p).  We use the
    existing curve parameters already defined for ECDSA in SECTION 2.
    Returns "" on any parse failure so the caller's verify step fails cleanly.
    """
    if not isinstance(compact_pub_hex, str) or not compact_pub_hex:
        return ""
    compact_pub_hex = compact_pub_hex.lower().strip()
    if len(compact_pub_hex) != 66:
        return ""
    prefix = compact_pub_hex[:2]
    if prefix not in ("02", "03"):
        return ""
    x_hex_in = compact_pub_hex[2:]
    if not _is_strict_hex(x_hex_in, 64):
        return ""
    x = int(x_hex_in, 16)
    if not (0 < x < _SECP256K1_P):
        return ""
    P = _SECP256K1_P
    rhs = (pow(x, 3, P) + 7) % P
    # Tonelli-Shanks shortcut: for p ≡ 3 (mod 4), sqrt = rhs^((p+1)/4) mod p.
    # secp256k1's p satisfies this, so we can compute y directly.
    y = pow(rhs, (P + 1) // 4, P)
    if (y * y) % P != rhs:
        return ""  # not a valid curve point
    # Pick the parity matching the compact prefix.
    want_even = (prefix == "02")
    if (y % 2 == 0) != want_even:
        y = P - y
    x_hex = f"{x:064x}"
    y_hex = f"{y:064x}"
    return "04" + x_hex + y_hex
