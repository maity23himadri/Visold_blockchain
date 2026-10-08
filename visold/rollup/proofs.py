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
"""visold.rollup.proofs

Original section: END SECTION 7E — Pass 2 (Layer2State).  Next passes add the proof backend,

Defines: ProofBackendError, UnsafeBackendOnMainnetError, IProofBackend, LocalDevBackend, SimulatedProofBackend, SubprocessSNARKBackend, ProofRegistry
Origin: visold_vsd_.py L24166-24172, L24175-24176, L24184-24186, L24189-24217, L24221-24224, L24227-24229, L24233-24293, L24297-24441, L24449-24459, L24463-24692, L24696-24806, L24812-24823
"""

import hashlib
import hmac
import json
import os
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

from visold.kernel.config import Config
from visold.kernel.logging_setup import log


# ═════════════════════════════════════════════════════════════════════════════
# END SECTION 7E — Pass 2 (Layer2State).  Next passes add the proof backend,
# sequencer, settlement tx, verifier precompile, and wallet/P2P integration.
# ═════════════════════════════════════════════════════════════════════════════


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 7E-3: PROOF BACKEND INTERFACE + DEV BACKEND + SUBPROCESS STUB +
#               PRODUCTION-GUARDED REGISTRY
#
# READ THIS BEFORE USING IN PRODUCTION:
#
# IProofBackend defines what a real zk-SNARK prover/verifier must expose
# to participate in Visold's rollup layer.  Real SNARK libraries
# (arkworks, gnark, halo2, circom+snarkjs, noir+barretenberg, etc.) live
# OUTSIDE this Python file — they are written in Rust/Go/C++ and invoked
# either via FFI or, more portably, via subprocess.  This file ships:
#
#   1. IProofBackend                — the abstract contract.
#   2. LocalDevBackend              — an HMAC-SHA256 dev/test backend.
#                                     Self-labelled UNSAFE.  Refuses to
#                                     run when VISOLD_NETWORK=mainnet.
#   3. SubprocessSNARKBackend       — a STUB that defines the prover-
#                                     binary contract.  Will not function
#                                     until an operator points it at a
#                                     real prover binary AND has performed
#                                     a trusted setup (or transparent
#                                     setup) for their circuits.
#   4. ProofRegistry                — name-keyed lookup with a hard
#                                     production guard.
#
# WHAT THE DEV BACKEND IS:
#   HMAC-SHA256 over (prev_root, new_root, batch_hash).  This authenticates
#   that SOMEONE who held the sequencer's HMAC key produced this claim.
#   It does NOT prove the state transition is valid.  A malicious sequencer
#   can sign any (A, B, X) and verification will pass.  This is exactly
#   the same property as a signature, NOT a SNARK.
#
# WHAT THE DEV BACKEND IS USEFUL FOR:
#   • Local development and CI.
#   • Testnets where every sequencer is trusted by every verifier.
#   • Validating the surrounding plumbing (sequencer thread, batching,
#     settlement tx, verifier precompile gas, P2P fan-out, reorg
#     handling) ahead of integrating a real prover.
#
# WHAT IT IS NOT USEFUL FOR:
#   • Anything called "mainnet".
#   • Anywhere "trustless" appears in marketing.
#   • Any deployment where users hold value on the rollup and the
#     sequencer is not unconditionally trusted.
#
# WHAT YOU NEED TO REACH PRODUCTION:
#   1. Choose a proving system (Groth16, Plonk, Halo2, STARK, …).
#   2. Author circuits for your L2 state-transition function in a DSL
#      (Circom, Noir, halo2-lib, gnark frontend, …).
#   3. Run a trusted setup ceremony (Groth16/Plonk) or use a transparent
#      setup (STARK/Halo2).  Publish the verifying key.
#   4. Build a prover binary and a verifier binary that speak the JSON
#      protocol documented on SubprocessSNARKBackend.
#   5. Implement IProofBackend in a subclass that calls those binaries,
#      register it, and set Config.L2_PROOF_BACKEND to its name.
#   6. Have all of the above audited by independent cryptographers
#      before exposing real value.
#
# Every RollupSubmission records the backend name+security in its
# zk_proof field so an explorer / auditor can see which backend signed
# any historical batch.
# ═════════════════════════════════════════════════════════════════════════════

# Module-level helper: which network are we on?  Used to decide whether to
# allow unsafe (development) backends.  Default is "dev" so existing
# unattended test scripts keep working; operators MUST set this to
# "mainnet" via env var on real deployments.
def _visold_network() -> str:
    n = (os.environ.get("VISOLD_NETWORK", "") or "").strip().lower()
    if not n:
        # Allow Config.NETWORK to override the default if set elsewhere
        # in the codebase, but env var wins.
        n = (getattr(Config, "NETWORK", "") or "").strip().lower()
    return n or "dev"


def _is_mainnet() -> bool:
    return _visold_network() == "mainnet"


# Backends with these security strings are considered UNSAFE for mainnet.
# This list is used as a hard filter inside ProofRegistry.get_configured()
# and Sequencer.start().  Adding "test", "dev", or "trust" tokens to the
# security string of a custom backend is the documented way for an
# implementer to opt OUT of mainnet eligibility.
_UNSAFE_SECURITY_TOKENS = (
    "simulated", "trust-sequencer", "hmac", "dev", "test", "stub", "mock",
)


def _is_unsafe_backend(backend: 'IProofBackend') -> bool:
    """Return True if `backend` self-identifies as not production-safe.

    A backend is considered unsafe if any of these are true:
      • It is a LocalDevBackend (or subclass).
      • It is a SubprocessSNARKBackend in unconfigured (stub) state.
      • Its security() string contains any token from _UNSAFE_SECURITY_TOKENS.

    This check is INTENTIONALLY loose — false positives (a real backend
    flagged as unsafe) cost a startup error message; false negatives
    (an unsafe backend flagged as safe) cost the entire chain.  We
    pick the safer side.
    """
    try:
        sec = (backend.security() or "").lower()
    except Exception:
        return True
    for tok in _UNSAFE_SECURITY_TOKENS:
        if tok in sec:
            return True
    # Class-based check for the two stubs we ship — covers the case where
    # a future subclass forgets to update security().
    if isinstance(backend, (LocalDevBackend, SubprocessSNARKBackend)):
        # SubprocessSNARKBackend can be marked production-ready by an
        # operator only if it passes its own readiness check.
        if isinstance(backend, SubprocessSNARKBackend):
            return not backend.is_production_ready()
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
class ProofBackendError(Exception):
    """Raised when a proof backend cannot be used (misconfigured, missing
    binary, stub not implemented, etc.).  Distinct from verification
    failure — verify() must NEVER raise on bad input, only return False."""


class UnsafeBackendOnMainnetError(RuntimeError):
    """Raised when a node tries to start the sequencer or verify proofs
    on mainnet using a backend that has self-identified as unsafe."""


# ─────────────────────────────────────────────────────────────────────────────
class IProofBackend:
    """Abstract interface for proof backends.  Real SNARK backends and
    development-only authentication backends both implement this.

    Contract
    ────────
    name() -> str
        Short stable identifier used in RollupSubmission.zk_proof.backend
        and Config.L2_PROOF_BACKEND.  MUST be non-empty and stable across
        restarts.

    security() -> str
        Honest, machine-greppable description of the security guarantee.
        Examples (real):     "zk-groth16-bn254", "zk-plonk-bls12-381",
                             "stark-fri-128bit"
        Examples (unsafe):   "simulated-hmac-trust-sequencer", "dev-only",
                             "stub-not-configured"
        Implementations MUST be honest — falsely advertising "zk-groth16"
        when the backend is HMAC is a deliberate consensus attack and is
        treated as such.

    prove(prev_root, new_root, batch_hash, witness) -> bytes
        Produce proof bytes for the claim "applying batch_hash to
        prev_root yields new_root".  `witness` is opaque — its layout is
        defined by the specific backend (the dev backend ignores it; a
        Groth16 backend expects the full execution trace).  MAY raise
        ProofBackendError if the backend cannot currently prove (e.g.,
        prover binary missing).

    verify(prev_root, new_root, batch_hash, proof_bytes) -> bool
        MUST be deterministic and stateless.  MUST NOT raise on malformed
        proof_bytes — return False.  This is a hard requirement: the
        verifier precompile assumes verify() never raises and treats
        exceptions as a bug, not a verification failure.

    is_production_ready() -> bool
        Default False.  A backend that returns True is asserting under
        operator responsibility that it can be safely used on mainnet.
        ProofRegistry consults this in addition to the security-string
        filter when running on mainnet.
    """

    def name(self) -> str:
        raise NotImplementedError

    def security(self) -> str:
        raise NotImplementedError

    def prove(self, prev_root: str, new_root: str,
              batch_hash: str, witness: bytes = b"") -> bytes:
        raise NotImplementedError

    def verify(self, prev_root: str, new_root: str,
               batch_hash: str, proof_bytes: bytes) -> bool:
        raise NotImplementedError

    def is_production_ready(self) -> bool:
        """Override and return True only after the backend has passed an
        independent cryptographic audit and been approved by the
        operator for mainnet use."""
        return False


# ─────────────────────────────────────────────────────────────────────────────
class LocalDevBackend(IProofBackend):
    """HMAC-SHA256 development-only backend.

    ⚠  THIS IS NOT A ZERO-KNOWLEDGE PROOF.  IT IS NOT EVEN A PROOF.  ⚠
    It is a MAC.  Anyone with the HMAC key can sign any state transition.

    This backend exists for local development, CI, and trusted-sequencer
    testnets.  It is REFUSED at startup when VISOLD_NETWORK=mainnet.

    Properties:
      • Constant-time verification (hmac.compare_digest).
      • Domain-separated HMAC ("VSD-L2-DEV-PROOF-v1") so the dev key
        cannot be re-used to forge other domain messages.
      • Loud, repeating warnings on every prove() and verify() call.
        Yes, every call.  This is intentional and not a bug.

    Backwards compatibility:
      The legacy class name `SimulatedProofBackend` is provided as an
      alias below so existing call sites and saved configs that reference
      "simulated" by name continue to load.  Any new code SHOULD use
      LocalDevBackend.
    """

    _NAME     = "local-dev"
    _SECURITY = "dev-only-hmac-trust-sequencer-NOT-A-PROOF"
    _DOMAIN   = b"VSD-L2-DEV-PROOF-v1"

    _warn_lock = threading.Lock()
    _last_warned_at = 0.0
    _WARN_THROTTLE_SECS = 60  # repeat the stderr banner at most once per minute

    # AUDIT-FIX-G1 (L2 state divergence — no shared dev-backend secret):
    # Every process that constructs a bare LocalDevBackend() (as the
    # module-level default registration below does, on every node) used
    # to get its own os.urandom(32) secret. prove() (on the sequencer)
    # and verify() (on every other node) then used DIFFERENT keys, so
    # verify() always returned False anywhere except the exact process
    # that produced the proof: the sequencer's own node would commit
    # every rollup batch while every other node silently rejected it,
    # permanently diverging Layer2State roots across the network from
    # the first batch onward — a functional break of this class's own
    # documented "trusted-sequencer testnet" use case, which requires
    # multiple processes to agree using the SAME key.
    #
    # A fixed, non-random default does not weaken this backend's security
    # model: it was already "fully trust the sequencer" (see class
    # docstring — "a malicious sequencer can sign any (A, B, X) and
    # verification will pass"), never "attacker cannot forge." What was
    # missing was the ability for honest, cooperating nodes to agree at
    # all, which a shared default restores.
    _FIXED_DEFAULT_SECRET = hashlib.sha256(
        b"VSD-L2-DEV-BACKEND-PUBLIC-DEFAULT-SECRET-NOT-SECURE-"
        b"DO-NOT-USE-FOR-ANYTHING-THAT-NEEDS-REAL-SECURITY"
    ).digest()

    def __init__(self, sequencer_secret: Optional[bytes] = None):
        # Symmetric HMAC key.  In a real SNARK setting verification is
        # public — here both sides need the same secret.  This is one of
        # several reasons this backend is dev-only.
        #
        # Resolution order (AUDIT-FIX-G1):
        #   1. Explicit `sequencer_secret` argument — unchanged, for
        #      callers/tests that manage their own key material.
        #   2. VISOLD_L2_DEV_SECRET env var (hex-encoded) — the documented
        #      way for operators of a shared trusted testnet to give every
        #      node the same key, mirroring how SubprocessSNARKBackend
        #      reads its own configuration from the environment.
        #   3. _FIXED_DEFAULT_SECRET — a fixed, published, non-random
        #      constant, so that out-of-the-box multi-node testnets and
        #      CI actually agree with each other instead of each node
        #      silently minting its own unshareable key.
        if sequencer_secret:
            self._secret = sequencer_secret
        else:
            env_hex = (os.environ.get("VISOLD_L2_DEV_SECRET", "") or "").strip()
            if env_hex:
                try:
                    self._secret = bytes.fromhex(env_hex)
                except Exception:
                    log.error(
                        "[L2-PROOF] VISOLD_L2_DEV_SECRET is not valid hex — "
                        "falling back to the fixed default dev secret. "
                        "Nodes with a bad value here will NOT be able to "
                        "verify batches from nodes using the default.")
                    self._secret = self._FIXED_DEFAULT_SECRET
            else:
                self._secret = self._FIXED_DEFAULT_SECRET

    def name(self) -> str:
        return self._NAME

    def security(self) -> str:
        return self._SECURITY

    def is_production_ready(self) -> bool:
        return False  # always

    def _warn(self) -> None:
        # Throttled to once per _WARN_THROTTLE_SECS to avoid log flooding
        # while still keeping the banner visible across long runs.
        now = time.time() if 'time' in globals() else 0.0
        with LocalDevBackend._warn_lock:
            if now - LocalDevBackend._last_warned_at < self._WARN_THROTTLE_SECS:
                return
            LocalDevBackend._last_warned_at = now
        try:
            log.warning(
                "[L2-PROOF] LocalDevBackend active — HMAC, NOT a "
                "zero-knowledge proof.  Sequencer is fully trusted.  "
                "REFUSED on mainnet.  Set VISOLD_NETWORK=mainnet and "
                "register a real IProofBackend before production use.")
        except Exception:
            pass
        try:
            sys.stderr.write(
                "[L2-PROOF WARNING] LocalDevBackend active — NOT a SNARK.\n")
            sys.stderr.flush()
        except Exception:
            pass

    def _tag(self, prev_root: str, new_root: str, batch_hash: str) -> bytes:
        msg = (self._DOMAIN + b"|" +
               prev_root.encode() + b"|" +
               new_root.encode() + b"|" +
               batch_hash.encode())
        return hmac.new(self._secret, msg, hashlib.sha256).digest()

    def prove(self, prev_root: str, new_root: str,
              batch_hash: str, witness: bytes = b"") -> bytes:
        self._warn()
        return self._tag(prev_root, new_root, batch_hash)

    def verify(self, prev_root: str, new_root: str,
               batch_hash: str, proof_bytes: bytes) -> bool:
        self._warn()
        # Strict input validation — verify() MUST NOT raise.
        if not isinstance(proof_bytes, (bytes, bytearray)):
            return False
        if len(proof_bytes) != 32:
            return False
        try:
            expected = self._tag(prev_root, new_root, batch_hash)
            return hmac.compare_digest(expected, bytes(proof_bytes))
        except Exception:
            return False


# Backwards-compatibility alias.  Existing configs / saved state that
# reference "simulated" by name still resolve to this class.  The
# resolved backend's name() returns "local-dev"; the registry below
# additionally registers it under the legacy name "simulated" so a
# config string of "simulated" continues to find a backend.
class SimulatedProofBackend(LocalDevBackend):
    """Deprecated alias for LocalDevBackend.  Kept for compatibility
    with older configs that say `L2_PROOF_BACKEND = "simulated"`.

    New code should reference LocalDevBackend directly.
    """

    _NAME = "simulated"  # so RollupSubmissions made under the old name keep verifying

    def name(self) -> str:
        return self._NAME


# ─────────────────────────────────────────────────────────────────────────────
class SubprocessSNARKBackend(IProofBackend):
    """STUB: invokes an external prover/verifier binary via subprocess.

    This class is a CONTRACT, not a working backend.  It defines the
    JSON protocol a real prover/verifier binary must speak, and provides
    a `is_production_ready()` check that returns True only when the
    operator has supplied:

      1. Path to a verifier binary (env: VISOLD_SNARK_VERIFIER_BIN).
      2. Path to a prover binary   (env: VISOLD_SNARK_PROVER_BIN, optional
         for a verifier-only node).
      3. Path to the verifying key (env: VISOLD_SNARK_VK_PATH).
      4. Explicit acknowledgement that the operator has audited and
         performed a trusted setup (env: VISOLD_SNARK_AUDITED=1).

    All four are required; missing any one keeps the backend in stub
    mode and `is_production_ready()` returns False.  In stub mode,
    prove() and verify() raise ProofBackendError — the backend will not
    silently fall through to anything.

    Wire protocol (line-delimited JSON over stdin/stdout)
    ─────────────────────────────────────────────────────
    Verifier invocation:
        $ verifier_bin --vk <VK_PATH>
        STDIN  (single line of JSON):
          {"prev_root": "<hex64>",
           "new_root":  "<hex64>",
           "batch_hash":"<hex64>",
           "proof":     "<hex>"}
        STDOUT (single line of JSON):
          {"ok": true}    or    {"ok": false, "reason": "<short string>"}
        Exit code:
          0 on a clean verdict (regardless of true/false).
          Non-zero on internal error (treated as verify=False, logged).

    Prover invocation:
        $ prover_bin --pk <PK_PATH>
        STDIN  (single line of JSON):
          {"prev_root": "<hex64>",
           "new_root":  "<hex64>",
           "batch_hash":"<hex64>",
           "witness":   "<hex>"}
        STDOUT (single line of JSON):
          {"ok": true,  "proof": "<hex>"}
          or
          {"ok": false, "reason": "<short string>"}
        Exit code: 0 on success, non-zero on internal error.

    Timeouts
    ────────
    Verifier: 30s wall-clock.  A real Groth16 verify is sub-second; a
    STARK verify is at most a few seconds.  Anything taking 30s is broken.
    Prover:   600s wall-clock.  Real provers can take minutes for large
    batches; longer than 10 minutes indicates a sizing problem.

    Operators implementing a real backend SHOULD subclass this and
    override is_production_ready() to add additional checks (binary
    signature verification, version pinning, etc.).
    """

    _NAME     = "snark-subprocess"
    _SECURITY = "stub-not-configured"  # overridden once configured
    _VERIFY_TIMEOUT_SECS = 30
    _PROVE_TIMEOUT_SECS  = 600

    def __init__(self,
                 verifier_bin: Optional[str] = None,
                 prover_bin:   Optional[str] = None,
                 vk_path:      Optional[str] = None,
                 pk_path:      Optional[str] = None,
                 security_label: Optional[str] = None):
        # Constructor args win; otherwise read from env so an operator
        # can deploy without code changes.
        self._verifier_bin = verifier_bin or os.environ.get("VISOLD_SNARK_VERIFIER_BIN", "")
        self._prover_bin   = prover_bin   or os.environ.get("VISOLD_SNARK_PROVER_BIN",   "")
        self._vk_path      = vk_path      or os.environ.get("VISOLD_SNARK_VK_PATH",      "")
        self._pk_path      = pk_path      or os.environ.get("VISOLD_SNARK_PK_PATH",      "")
        self._audited      = (os.environ.get("VISOLD_SNARK_AUDITED", "") == "1")
        # Operator can override the security string after auditing — this
        # is what flips the backend from "stub-not-configured" to
        # something like "zk-groth16-bn254-audited-2026-Q1".
        self._security_label = security_label or os.environ.get(
            "VISOLD_SNARK_SECURITY_LABEL", self._SECURITY)

    def name(self) -> str:
        return self._NAME

    def security(self) -> str:
        return self._security_label

    def is_production_ready(self) -> bool:
        """All four conditions must hold:
          (1) verifier binary exists and is executable
          (2) prover binary exists and is executable (or is empty if this
              is a verifier-only node)
          (3) verifying key file exists
          (4) operator has set VISOLD_SNARK_AUDITED=1
        """
        if not self._audited:
            return False
        if not self._vk_path or not os.path.isfile(self._vk_path):
            return False
        if not self._verifier_bin:
            return False
        if not (os.path.isfile(self._verifier_bin) and
                os.access(self._verifier_bin, os.X_OK)):
            return False
        if self._prover_bin:
            if not (os.path.isfile(self._prover_bin) and
                    os.access(self._prover_bin, os.X_OK)):
                return False
        # Refuse to be marked safe if the operator hasn't relabelled
        # security() — the default "stub-not-configured" string contains
        # the "stub" token which _is_unsafe_backend() filters out.
        if "stub" in (self._security_label or "").lower():
            return False
        return True

    def _run(self, binary: str, payload: dict, timeout: float) -> dict:
        """Invoke `binary` with one line of JSON on stdin, parse one line
        of JSON from stdout.  Raises ProofBackendError on any failure
        whose meaning is "the backend is broken" rather than "the proof
        is invalid"."""
        if not binary:
            raise ProofBackendError("subprocess backend: no binary configured")
        # Imported lazily so environments without subprocess support
        # (some sandboxed runtimes) don't fail at module import.
        try:
            import subprocess as _subprocess
        except Exception as e:
            raise ProofBackendError(f"subprocess module unavailable: {e}")
        try:
            line = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
        except Exception as e:
            raise ProofBackendError(f"payload serialisation failed: {e}")
        try:
            proc = _subprocess.run(
                [binary, "--vk", self._vk_path] if "verif" in binary.lower()
                else [binary, "--pk", self._pk_path],
                input=line,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except _subprocess.TimeoutExpired:
            raise ProofBackendError(f"backend binary {binary} timed out")
        except FileNotFoundError:
            raise ProofBackendError(f"backend binary not found: {binary}")
        except Exception as e:
            raise ProofBackendError(f"subprocess invocation failed: {e}")
        if proc.returncode != 0:
            stderr_tail = (proc.stderr or b"")[-256:].decode("utf-8", "replace")
            raise ProofBackendError(
                f"backend binary {binary} exited {proc.returncode}: {stderr_tail}")
        out = (proc.stdout or b"").strip().splitlines()
        if not out:
            raise ProofBackendError("backend binary produced no output")
        try:
            return json.loads(out[-1].decode("utf-8"))
        except Exception as e:
            raise ProofBackendError(f"backend output not JSON: {e}")

    def prove(self, prev_root: str, new_root: str,
              batch_hash: str, witness: bytes = b"") -> bytes:
        if not self.is_production_ready():
            raise ProofBackendError(
                "SubprocessSNARKBackend.prove: backend not configured "
                "(see class docstring for required env vars)")
        if not self._prover_bin:
            raise ProofBackendError("prover binary not configured on this node")
        try:
            wit_hex = witness.hex() if witness else ""
        except Exception:
            wit_hex = ""
        payload = {
            "prev_root":  prev_root,
            "new_root":   new_root,
            "batch_hash": batch_hash,
            "witness":    wit_hex,
        }
        result = self._run(self._prover_bin, payload, self._PROVE_TIMEOUT_SECS)
        if not result.get("ok"):
            raise ProofBackendError(
                f"prover refused: {result.get('reason', 'unknown')}")
        proof_hex = result.get("proof", "")
        try:
            return bytes.fromhex(proof_hex)
        except Exception as e:
            raise ProofBackendError(f"prover returned bad proof hex: {e}")

    def verify(self, prev_root: str, new_root: str,
               batch_hash: str, proof_bytes: bytes) -> bool:
        # verify() MUST NOT raise.  Misconfiguration → False, logged.
        if not self.is_production_ready():
            try:
                log.error(
                    "[L2-PROOF] SubprocessSNARKBackend.verify called while "
                    "backend is not production-ready — returning False.  "
                    "Configure VISOLD_SNARK_VERIFIER_BIN, VISOLD_SNARK_VK_PATH, "
                    "VISOLD_SNARK_AUDITED=1, and override the security label.")
            except Exception:
                pass
            return False
        if not isinstance(proof_bytes, (bytes, bytearray)):
            return False
        try:
            payload = {
                "prev_root":  prev_root,
                "new_root":   new_root,
                "batch_hash": batch_hash,
                "proof":      bytes(proof_bytes).hex(),
            }
        except Exception:
            return False
        try:
            result = self._run(self._verifier_bin, payload,
                               self._VERIFY_TIMEOUT_SECS)
        except ProofBackendError as e:
            try:
                log.warning(f"[L2-PROOF] verifier subprocess error: {e}")
            except Exception:
                pass
            return False
        except Exception as e:
            try:
                log.error(f"[L2-PROOF] verifier unexpected error: {e}")
            except Exception:
                pass
            return False
        return bool(result.get("ok") is True)


# ─────────────────────────────────────────────────────────────────────────────
class ProofRegistry:
    """Global registry of IProofBackend implementations, keyed by name.

    Production guard
    ────────────────
    When VISOLD_NETWORK=mainnet, get_configured() will REFUSE to return
    a backend that self-identifies as unsafe (LocalDevBackend, an
    unconfigured SubprocessSNARKBackend, or any backend whose security()
    string contains a dev/test/stub/hmac token).  Instead it raises
    UnsafeBackendOnMainnetError, which causes node startup to fail loudly
    rather than silently run with no real cryptographic guarantees.

    On dev/testnet (the default when VISOLD_NETWORK is unset), the
    registry behaves like before: it returns the configured backend and
    falls back to LocalDevBackend on misconfiguration.

    Thread safety
    ─────────────
    register() takes a lock.  get() / get_configured() take the same
    lock.  The dict is normally populated once at import time but late
    plug-in registration is supported.
    """

    _backends: Dict[str, IProofBackend] = {}
    _lock = threading.Lock()

    @classmethod
    def register(cls, backend: IProofBackend) -> None:
        if not isinstance(backend, IProofBackend):
            raise TypeError("backend must implement IProofBackend")
        nm = backend.name()
        if not nm:
            raise ValueError("backend.name() must be non-empty")
        with cls._lock:
            cls._backends[nm] = backend
        try:
            log.info(f"[L2-PROOF] Registered backend '{nm}' "
                     f"(security={backend.security()}, "
                     f"production_ready={backend.is_production_ready()})")
        except Exception:
            pass

    @classmethod
    def get(cls, name: str) -> Optional[IProofBackend]:
        with cls._lock:
            return cls._backends.get(name)

    @classmethod
    def list_registered(cls) -> List[Tuple[str, str, bool]]:
        """Return a list of (name, security, production_ready) for all
        registered backends.  Useful for status banners."""
        with cls._lock:
            items = list(cls._backends.values())
        out = []
        for b in items:
            try:
                out.append((b.name(), b.security(), b.is_production_ready()))
            except Exception:
                out.append((getattr(b, "_NAME", "?"), "?", False))
        return out

    @classmethod
    def get_configured(cls) -> IProofBackend:
        """Return the backend named by Config.L2_PROOF_BACKEND.

        On dev/testnet: missing or unsafe backend → fall back to
        LocalDevBackend with a warning (existing behaviour).

        On mainnet: an unsafe backend (or no real backend registered)
        causes UnsafeBackendOnMainnetError.  This is intentional —
        a misconfigured mainnet node MUST fail to start, not silently
        run with HMAC.
        """
        nm = getattr(Config, "L2_PROOF_BACKEND", "local-dev")
        b = cls.get(nm)
        mainnet = _is_mainnet()

        if b is None:
            if mainnet:
                raise UnsafeBackendOnMainnetError(
                    f"VISOLD_NETWORK=mainnet but backend '{nm}' is not "
                    f"registered.  Refusing to fall back to a dev backend. "
                    f"Register a real IProofBackend implementation and set "
                    f"Config.L2_PROOF_BACKEND to its name before startup. "
                    f"Registered backends: {[x[0] for x in cls.list_registered()]}")
            try:
                log.warning(
                    f"[L2-PROOF] Configured backend '{nm}' not registered — "
                    f"falling back to LocalDevBackend.  This is OK on "
                    f"dev/testnet only.  Set VISOLD_NETWORK=mainnet to "
                    f"enforce a real backend.")
            except Exception:
                pass
            b = cls.get("local-dev") or cls.get("simulated")
            if b is None:
                # Last-resort: register and return a fresh dev backend so
                # tests don't crash before they get a chance to run.
                b = LocalDevBackend()
                cls.register(b)
            return b

        if mainnet and _is_unsafe_backend(b):
            raise UnsafeBackendOnMainnetError(
                f"VISOLD_NETWORK=mainnet but the configured backend '{nm}' "
                f"(security={b.security()!r}, "
                f"production_ready={b.is_production_ready()}) is not "
                f"production-safe.  Mainnet REQUIRES a backend that returns "
                f"is_production_ready()==True and whose security() string "
                f"does not contain dev/test/stub/hmac tokens.  Refusing to "
                f"start.")
        return b


# Register the default dev backend at import time so dev/test workflows
# work out of the box.  The legacy name "simulated" is also bound to the
# same instance so old configs continue to load.
try:
    _dev_backend = LocalDevBackend()
    ProofRegistry.register(_dev_backend)
    # Bind the legacy name too — saved configs that set
    # L2_PROOF_BACKEND="simulated" should still resolve.
    _legacy_alias = SimulatedProofBackend()
    ProofRegistry.register(_legacy_alias)
except Exception as _reg_e:
    try:
        log.error(f"[L2-PROOF] Default backend registration failed: {_reg_e}")
    except Exception:
        pass
