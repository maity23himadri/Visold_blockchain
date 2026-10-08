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
"""visold.kernel.source_identity

Original section: SECTION 0A: NODE LOGIC HASH — Software Identity for Handshake Verification

Origin: visold_vsd_.py L3579-3583
"""

import hashlib
import os


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 0A: NODE LOGIC HASH — Software Identity for Handshake Verification
# ─────────────────────────────────────────────────────────────────────────────
# Computed once at import from this source file.  Included in every HELLO
# handshake so peers can verify they are running compatible software.
# MAJOR-02 FIX: _NODE_LOGIC_HASH is a PERFORMANCE HINT only, not a security gate.
#
# The hash fingerprints the Python *source* file.  A malicious peer can keep
# the unmodified .py while loading a compiled Cython/C extension that overrides
# consensus methods — the source hash still matches and the peer is promoted to
# TRUST_LEVEL_HIGH.  Granting TRUST_HIGH on a matching hash is therefore NOT a
# security boundary.
#
# Security contract (unchanged by this fix):
#   • Every block from EVERY peer — regardless of trust level — is validated by
#     Blockchain.apply_block() which checks: PoW target, Merkle root, ECDSA
#     signatures on all transactions, nonce ordering, and BFT finality.
#   • Every transaction from EVERY peer passes mempool.add() which enforces
#     ECDSA validity, nonce, fee, expiry, and dust rules.
#   • TRUST_LOW peers additionally receive Full Audit Mode (extra deep re-
#     verification + bandwidth throttling) as a defence-in-depth measure.
#   • TRUST_HIGH peers skip Full Audit Mode as a *performance optimisation*
#     only — they still receive full primary cryptographic validation.
#
# To harden this further, replace source-hash comparison with a signed build
# manifest (Ed25519 signature over the binary + version) verified against a
# hardcoded Anthropic/Visold public key.
# ─────────────────────────────────────────────────────────────────────────────
def package_source_blob() -> bytes:
    """Deterministic byte blob of the whole ``visold`` package source.

    The monolith fingerprinted its own single source file.  After
    modularization the equivalent software identity is the ordered
    concatenation of every ``.py`` file of the package (relative POSIX path,
    NUL, file bytes, NUL).  Two nodes running identical package sources
    therefore compute identical hashes regardless of install location.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                full = os.path.join(dirpath, fn)
                entries.append((os.path.relpath(full, root).replace(os.sep, "/"), full))
    entries.sort()
    blob = bytearray()
    for rel, full in entries:
        with open(full, "rb") as fh:
            blob += rel.encode("utf-8") + b"\0" + fh.read() + b"\0"
    return bytes(blob)


try:
    _NODE_LOGIC_HASH: str = hashlib.sha256(package_source_blob()).hexdigest()[:32]
except Exception:
    _NODE_LOGIC_HASH = "unknown"
