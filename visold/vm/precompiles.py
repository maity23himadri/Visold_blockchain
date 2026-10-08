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
"""visold.vm.precompiles

Original section: SECTION 7C: VVM PRECOMPILED CONTRACTS

Defines: VVMPrecompiles
Origin: visold_vsd_.py L22603-22896
"""

import hashlib
import json
from typing import Tuple

from visold.crypto.ecc import ECPoint, pub_to_address
from visold.crypto.hashing import sha256
from visold.vm.frame import _VMFrame
from visold.kernel.logging_setup import log
from visold.rollup.proofs import ProofRegistry


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7C: VVM PRECOMPILED CONTRACTS
# Native Python functions mapped to specific addresses, executing at native
# speed without the VVM interpreter overhead.  Required for ZK-proofs,
# elliptic curve operations, and cryptographic primitives that would be
# prohibitively slow in the stack-based VVM interpreter.
# ─────────────────────────────────────────────────────────────────────────────
class VVMPrecompiles:
    """
    Precompiled contracts for the Visold Virtual Machine.

    Precompiles are special contract addresses that dispatch to native Python
    (or C-extension) implementations rather than the VVM bytecode interpreter.
    They are identical in interface to regular contracts — they accept calldata
    and return data — but run at native speed.

    Address scheme:  VSDcPRECOMPILE[24-char-zero-padded-index]
    These addresses are reserved and can never be used for user-deployed
    contracts (deploy_contract rejects addresses with the PRECOMPILE prefix).

    Supported precompiles (EVM-compatible where possible):
      01 — SHA-256       (60 + 12×⌈len/32⌉ gas)
      02 — RIPEMD-160    (600 + 120×⌈len/32⌉ gas)
      03 — Identity      (15 + 3×⌈len/32⌉ gas)   copy calldata to return
      04 — Modexp        (EIP-198 formula)         RSA / ZK exponentiation
      05 — ECRecover     (3000 gas)                ECDSA signer recovery
      06 — BLAKE2b-256   (60 + 12×⌈len/32⌉ gas)
    """

    # Address prefix for all precompiles
    ADDR_PREFIX = "VSDcPRECOMPILE"

    # Canonical precompile addresses
    SHA256    = "VSDcPRECOMPILE000000000000001"
    RIPEMD160 = "VSDcPRECOMPILE000000000000002"
    IDENTITY  = "VSDcPRECOMPILE000000000000003"
    MODEXP    = "VSDcPRECOMPILE000000000000004"
    ECRECOVER = "VSDcPRECOMPILE000000000000005"
    BLAKE2B   = "VSDcPRECOMPILE000000000000006"
    # ── v7.5.0-OPT L2 ROLLUP VERIFIER ─────────────────────────────────────
    # Note: the spec references "VSDcPRECOMPILE000000000000005" for the ZK
    # verifier but that slot is already ECRECOVER in this chain (occupied
    # long before the L2 work).  To keep backward compatibility we assign
    # the verifier to slot 07 and document the divergence here.  Address
    # strings are part of consensus; renaming ECRECOVER would be a hard
    # fork for every existing contract that calls it.
    L2_VERIFIER = "VSDcPRECOMPILE000000000000007"

    @classmethod
    def is_precompile(cls, address: str) -> bool:
        """Return True if address is a reserved precompile address."""
        return address.startswith(cls.ADDR_PREFIX)

    @classmethod
    def execute(cls, address: str, calldata: bytes,
                gas_limit: int) -> Tuple[bool, bytes, int]:
        """
        Execute the precompile at `address` with `calldata`.
        Returns (success, return_data, gas_used).
        Gas is charged before execution; returns (False, b"", gas_limit)
        if gas is insufficient.
        """
        try:
            if address == cls.SHA256:
                return cls._sha256(calldata, gas_limit)
            elif address == cls.RIPEMD160:
                return cls._ripemd160(calldata, gas_limit)
            elif address == cls.IDENTITY:
                return cls._identity(calldata, gas_limit)
            elif address == cls.MODEXP:
                return cls._modexp(calldata, gas_limit)
            elif address == cls.ECRECOVER:
                return cls._ecrecover(calldata, gas_limit)
            elif address == cls.BLAKE2B:
                return cls._blake2b(calldata, gas_limit)
            elif address == cls.L2_VERIFIER:
                return cls._l2_verifier(calldata, gas_limit)
            else:
                # Unknown precompile address — fail gracefully
                return False, b"unknown precompile", 21000
        except Exception as e:
            log.debug(f"Precompile {address}: execution error: {e}")
            return False, str(e).encode()[:256], gas_limit

    # ── Individual precompile implementations ─────────────────────────────────

    @staticmethod
    def _sha256(calldata: bytes, gas_limit: int) -> Tuple[bool, bytes, int]:
        gas = 60 + 12 * ((len(calldata) + 31) // 32)
        if gas > gas_limit:
            return False, b"", gas_limit
        return True, hashlib.sha256(calldata).digest(), gas

    @staticmethod
    def _ripemd160(calldata: bytes, gas_limit: int) -> Tuple[bool, bytes, int]:
        gas = 600 + 120 * ((len(calldata) + 31) // 32)
        if gas > gas_limit:
            return False, b"", gas_limit
        try:
            h = hashlib.new("ripemd160", calldata).digest()
        except ValueError:
            # RIPEMD-160 not available on all OpenSSL builds (FIPS mode)
            h = hashlib.sha256(calldata).digest()[:20]
        return True, b"\x00" * 12 + h, gas  # padded to 32 bytes

    @staticmethod
    def _identity(calldata: bytes, gas_limit: int) -> Tuple[bool, bytes, int]:
        gas = 15 + 3 * ((len(calldata) + 31) // 32)
        if gas > gas_limit:
            return False, b"", gas_limit
        return True, calldata, gas

    @staticmethod
    def _modexp(calldata: bytes, gas_limit: int) -> Tuple[bool, bytes, int]:
        """EIP-198 modular exponentiation: base^exp mod modulus."""
        if len(calldata) < 96:
            return True, b"\x00", 200  # empty inputs → zero
        b_len = int.from_bytes(calldata[0:32],  "big")
        e_len = int.from_bytes(calldata[32:64], "big")
        m_len = int.from_bytes(calldata[64:96], "big")
        # Safety: cap at 1 KB each to prevent DoS
        if b_len > 1024 or e_len > 1024 or m_len > 1024:
            return False, b"", gas_limit
        data = calldata[96:]
        base = int.from_bytes(data[:b_len],                  "big") if b_len else 0
        exp  = int.from_bytes(data[b_len:b_len+e_len],       "big") if e_len else 0
        mod  = int.from_bytes(data[b_len+e_len:b_len+e_len+m_len], "big") if m_len else 0
        if mod == 0:
            return True, b"\x00" * max(m_len, 1), 200
        # EIP-2565 gas formula (simplified)
        multiplication_complexity = ((max(b_len, m_len) + 7) // 8) ** 2
        iteration_count = max(e_len * 8, 1)
        gas = max(200, (multiplication_complexity * iteration_count) // 3)
        if gas > gas_limit:
            return False, b"", gas_limit
        result = pow(base, exp, mod)
        return True, result.to_bytes(m_len, "big"), gas

    @staticmethod
    def _ecrecover(calldata: bytes, gas_limit: int) -> Tuple[bool, bytes, int]:
        """
        Recover ECDSA signer from (hash, v, r, s).
        Input: 128 bytes — [32:hash][32:v][32:r][32:s]
        Output: 32 bytes — zero-padded recovered address (right-aligned 20 bytes)
        """
        gas = 3000
        if gas > gas_limit:
            return False, b"", gas_limit
        if len(calldata) < 128:
            return True, b"\x00" * 32, gas
        try:
            msg_hash = calldata[:32]
            v = int.from_bytes(calldata[32:64], "big")
            r = int.from_bytes(calldata[64:96], "big")
            s = int.from_bytes(calldata[96:128], "big")
            # Validate v is 27 or 28 (Ethereum convention)
            if v not in (27, 28):
                return True, b"\x00" * 32, gas
            N = ECPoint.N
            if not (1 <= r < N and 1 <= s < N):
                return True, b"\x00" * 32, gas
            # Attempt point recovery (secp256k1)
            # Using our ECPoint math for deterministic recovery
            recovery_id = v - 27
            P = ECPoint.P
            x = r + recovery_id * N
            if x >= P:
                return True, b"\x00" * 32, gas
            # y^2 = x^3 + 7 (mod P)
            y_sq = (pow(x, 3, P) + 7) % P
            y = pow(y_sq, (P + 1) // 4, P)
            if (y % 2) != (recovery_id % 2):
                y = P - y
            # AUDIT-FIX (Batch C secondary observation): confirm the
            # reconstructed point is genuinely on the curve before using it
            # in further EC arithmetic. pow(y_sq, (P+1)//4, P) only returns a
            # correct modular square root when y_sq is actually a quadratic
            # residue mod P; for a non-residue input it silently returns a
            # value that does NOT satisfy y^2 == y_sq, and R would not be a
            # real curve point. _secp256k1_hash_to_curve and vrf_verify's own
            # Gamma-decoding already perform this same check elsewhere.
            if pow(y, 2, P) != y_sq:
                return True, b"\x00" * 32, gas
            R = ECPoint(x, y)
            # pub = r^{-1} (s*R - hash*G)
            r_inv = pow(r, N - 2, N)
            hash_int = int.from_bytes(msg_hash, "big")
            u1 = (-hash_int * r_inv) % N
            u2 = (s * r_inv) % N
            G_pt = ECPoint(ECPoint.Gx, ECPoint.Gy)
            recovered_pub = (u1 * G_pt) + (u2 * R)
            if recovered_pub.is_inf():
                return True, b"\x00" * 32, gas
            recovered_addr = pub_to_address(recovered_pub)
            # AUDIT-FIX: use the canonical VM address encoding shared with
            # ADDRESS/CALLER/ORIGIN.  The recovered signer is an EOA, so its
            # address word is the raw 20-byte wallet payload (uint160), then
            # left-padded to the 32-byte VM return convention.  Do not hash the
            # address string here: doing so would make ECRecover incomparable
            # with CALLER/ORIGIN and break permit/meta-tx style contracts.
            frame = _VMFrame.__new__(_VMFrame)
            addr_int = frame._addr_to_int(recovered_addr)
            result = addr_int.to_bytes(32, "big")
            return True, result, gas
        except Exception:
            return True, b"\x00" * 32, gas

    @staticmethod
    def _blake2b(calldata: bytes, gas_limit: int) -> Tuple[bool, bytes, int]:
        """BLAKE2b-256 hash precompile."""
        gas = 60 + 12 * ((len(calldata) + 31) // 32)
        if gas > gas_limit:
            return False, b"", gas_limit
        try:
            result = hashlib.blake2b(calldata, digest_size=32).digest()
        except (AttributeError, ValueError):
            result = hashlib.sha256(calldata).digest()
        return True, result, gas

    @staticmethod
    def _l2_verifier(calldata: bytes, gas_limit: int) -> Tuple[bool, bytes, int]:
        """L2 rollup proof verifier precompile.

        Scope
        ─────
        This precompile is deliberately STATELESS.  It verifies that the
        proof bytes are internally consistent with the claimed
        (prev_root, new_root, batch_hash) triple under the currently
        configured IProofBackend.  It does NOT check that prev_root
        equals Layer2State's current on-chain root — that is the
        responsibility of apply_block's TYPE_ROLLUP branch, which has
        access to the live Layer2State.

        This separation mirrors how EVM precompiles work (e.g., ECRECOVER
        recovers a signer but does not check that the signer matches a
        particular account — the contract's logic does that).

        Calldata format (JSON, UTF-8):
          {
            "previous_l2_root": <hex64>,
            "new_l2_root":      <hex64>,
            "batch_hash":       <hex64>,
            "zk_proof":         <hex>,
            "backend":          <str>      (optional; informational)
          }

        Return data:
          On success: b"\\x01" + batch_hash_bytes  (33 bytes)
          On failure: b"\\x00" + 4-byte ASCII error tag (5 bytes)

        Gas cost
        ────────
        A real SNARK verifier costs ~200k–500k gas on Ethereum for a
        pairing-heavy check.  We charge a base of 150,000 gas plus 20
        gas per byte of proof — reflecting that the simulated backend
        is cheap but a real backend will not be, and we want gas
        accounting that scales with proof size so an oversized proof
        costs its bandwidth.
        """
        base_gas = 150_000
        per_byte = 20
        # First cost — even before parsing — covers the minimum work
        # irrespective of outcome, so a malformed calldata cannot be a
        # free DoS vector.
        if base_gas > gas_limit:
            return False, b"\x00" + b"NGAS", gas_limit
        try:
            payload = json.loads(calldata.decode("utf-8"))
        except Exception:
            return False, b"\x00" + b"JSON", base_gas
        try:
            prev_root  = str(payload["previous_l2_root"])
            new_root   = str(payload["new_l2_root"])
            batch_hash = str(payload["batch_hash"])
            zk_proof   = bytes.fromhex(payload.get("zk_proof", ""))
        except Exception:
            return False, b"\x00" + b"FLDS", base_gas
        if len(prev_root) != 64 or len(new_root) != 64 or len(batch_hash) != 64:
            return False, b"\x00" + b"ROOT", base_gas
        # Size-scaled portion of gas.
        gas = base_gas + per_byte * len(zk_proof)
        if gas > gas_limit:
            return False, b"\x00" + b"NGAS", gas_limit
        try:
            backend = ProofRegistry.get_configured()
            ok = backend.verify(prev_root, new_root, batch_hash, zk_proof)
        except Exception as e:
            # Backend raised — treat as verification failure.  Do NOT
            # propagate because a bad backend must not crash apply_block.
            log.debug(f"[L2-VERIFIER] backend raised: {e}")
            return False, b"\x00" + b"VERR", gas
        if not ok:
            return False, b"\x00" + b"FAIL", gas
        # Success: return a 1-byte tag plus the batch_hash so the caller
        # can cross-check.  Total 33 bytes.
        try:
            bh_bytes = bytes.fromhex(batch_hash)
        except Exception:
            bh_bytes = b"\x00" * 32
        return True, b"\x01" + bh_bytes, gas
