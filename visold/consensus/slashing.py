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
"""visold.consensus.slashing

Original section: SECTION 7A2: AUTOMATED SLASHING EVIDENCE PROTOCOL

Defines: SlashingEvidenceProtocol
Origin: visold_vsd_.py L19002-19195
"""

import hashlib
import json
import threading
import time
from typing import TYPE_CHECKING, Tuple

from visold.crypto.ecc import ecdsa_verify, pub_from_hex, pub_to_address, sig_from_hex
from visold.crypto.hashing import sha256, hash_obj
from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.chain.blockchain import Blockchain
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7A2: AUTOMATED SLASHING EVIDENCE PROTOCOL
# When a double-sign is detected, automatically builds and broadcasts an
# evidence packet that any network participant can submit to trigger slashing.
# ─────────────────────────────────────────────────────────────────────────────
class SlashingEvidenceProtocol:
    """
    Automated double-sign evidence submission.

    Problem addressed
    ─────────────────
    The existing code detects double-signs in add_validator_sig() and calls
    storage.slash() immediately on the detecting node.  However, other nodes
    that have not observed both conflicting signatures do not slash — leading
    to inconsistent slashing across the network.

    Solution
    ────────
    When a double-sign is detected, this class:
      1. Builds a signed evidence packet containing BOTH conflicting
         signatures, the block hashes they signed, and the validator's
         identity (pub_hex → address binding).
      2. Broadcasts the evidence to all peers via MSG_SLASH_EVIDENCE.
      3. Any receiving node independently verifies the evidence and applies
         the slash, ensuring network-wide consistency.

    Evidence format (JSON):
      {
        "type":          "SLASH_EVIDENCE",
        "validator":     "VSD...",
        "pub_hex":       "...",
        "block_hash_a":  "...",
        "sig_a":         "...",
        "block_hash_b":  "...",
        "sig_b":         "...",
        "height":        N,
        "submitted_by":  "VSD...",
        "timestamp":     int
      }

    Security: evidence is self-verifying — any node can independently verify
    both signatures against the validator's public key.  No trusted submitter
    is required.
    """

    MSG_TYPE = "SLASH_EVIDENCE"

    def __init__(self, storage: 'Storage', blockchain: 'Blockchain'):
        self._storage    = storage
        self._blockchain = blockchain
        self._lock       = threading.Lock()
        self._seen_evidences: set = set()   # evidence_id → already processed

    def build_evidence(self, validator_address: str, pub_hex: str,
                       block_hash_a: str, sig_a: str,
                       block_hash_b: str, sig_b: str,
                       height: int,
                       own_address: str,
                       block_header_a: dict = None,
                       block_header_b: dict = None) -> dict:
        """Build a slash evidence packet."""
        return {
            "type":         self.MSG_TYPE,
            "validator":    validator_address,
            "pub_hex":      pub_hex,
            "block_hash_a": block_hash_a,
            "sig_a":        sig_a,
            "block_hash_b": block_hash_b,
            "sig_b":        sig_b,
            "height":       int(height),
            "evidence_version": 2 if block_header_a and block_header_b else 1,
            "block_header_a": block_header_a,
            "block_header_b": block_header_b,
            "submitted_by": own_address,
            "timestamp":    int(time.time()),
            "ttl":          Config.GOSSIP_TTL,
        }

    def verify_evidence(self, evidence: dict) -> Tuple[bool, str]:
        """
        Verify a slash evidence packet.
        Returns (True, "OK") if valid, (False, reason) otherwise.
        """
        try:
            pub     = pub_from_hex(evidence["pub_hex"])
            val_addr = pub_to_address(pub)
            if val_addr != evidence["validator"]:
                return False, "pub_hex does not derive to validator address"

            # Verify sig_a
            sig_a   = sig_from_hex(evidence["sig_a"])
            h_a     = hashlib.sha256(evidence["block_hash_a"].encode()).digest()
            if not ecdsa_verify(pub, h_a, sig_a):
                return False, "sig_a cryptographic verification failed"

            # Verify sig_b
            sig_b   = sig_from_hex(evidence["sig_b"])
            h_b     = hashlib.sha256(evidence["block_hash_b"].encode()).digest()
            if not ecdsa_verify(pub, h_b, sig_b):
                return False, "sig_b cryptographic verification failed"

            # Ensure both sigs are for DIFFERENT blocks (actual double-sign)
            if evidence["block_hash_a"] == evidence["block_hash_b"]:
                return False, "Both signatures are for the same block — not a double-sign"

            # AUDIT-FIX (Batch E): a validator produces many legitimate
            # signatures over its lifetime, one per height it endorses.
            # Two individually-valid signatures on two DIFFERENT block
            # hashes are proof of equivocation ONLY if both were cast at
            # the SAME height/round — nothing above checks that. The
            # signed payload (sha256(block_hash)) does not bind a height,
            # so without this, anyone could take any two of a validator's
            # real, non-conflicting signatures from two different heights
            # and submit them as "evidence"; every check above would still
            # pass, and an honest validator would be slashed for
            # equivocation that never happened. This is exactly the
            # height + different-hash pairing add_validator_sig() already
            # requires for its own live detection
            # (get_validator_votes_at_height) — cross-check the claimed
            # height against that same source of truth so a receiving
            # node cannot be fooled by cross-height evidence it did not
            # independently witness. A node with no local record of these
            # votes at this height fails closed (rejects) rather than
            # trusting the claim, which is the safe direction for a check
            # that can slash real stake.
            height = int(evidence["height"])
            header_a = evidence.get("block_header_a")
            header_b = evidence.get("block_header_b")
            if (evidence.get("evidence_version", 1) >= 2 and
                    isinstance(header_a, dict) and isinstance(header_b, dict)):
                # New evidence is self-contained.  The header hash commits to
                # index, so matching both headers to their signed hashes and
                # requiring the same index cryptographically binds the two
                # signatures to one height.  No local vote history is needed.
                try:
                    if int(header_a.get("index")) != height or int(header_b.get("index")) != height:
                        return False, "Evidence block headers are not both at the claimed height"
                    if hash_obj(header_a) != evidence["block_hash_a"]:
                        return False, "block_header_a does not match block_hash_a"
                    if hash_obj(header_b) != evidence["block_hash_b"]:
                        return False, "block_header_b does not match block_hash_b"
                except Exception as e:
                    return False, f"Invalid evidence block headers: {e}"
                return True, "OK"

            # Legacy v1 evidence did not bind height into the signed payload
            # and therefore still requires local vote history to prevent a
            # cross-height false slash.  Keeping this fallback preserves
            # compatibility with already-produced evidence packets.
            votes_at_height = self._storage.get_validator_votes_at_height(height)
            recorded = {(v["validator_addr"], v["block_hash"])
                        for v in votes_at_height}
            if (evidence["validator"], evidence["block_hash_a"]) not in recorded:
                return False, (
                    f"No record of {evidence['validator'][:16]} voting for "
                    f"block_hash_a at height {height} — legacy evidence "
                    f"requires local vote history")
            if (evidence["validator"], evidence["block_hash_b"]) not in recorded:
                return False, (
                    f"No record of {evidence['validator'][:16]} voting for "
                    f"block_hash_b at height {height} — legacy evidence "
                    f"requires local vote history")

            return True, "OK"
        except Exception as e:
            return False, f"Evidence verification error: {e}"

    def apply_evidence(self, evidence: dict) -> Tuple[bool, str]:
        """
        Apply verified evidence: slash the validator and record the event.
        Returns (True, "OK") if slashed, (False, reason) if already slashed
        or evidence is invalid.
        """
        # AUDIT-FIX (Batch E): verify BEFORE marking evidence_id as seen —
        # not after. evidence_id is derived only from (validator,
        # block_hash_a, block_hash_b), never from the signatures, so it is
        # identical for every resubmission of "evidence" about the same
        # claimed violation, valid or not. The dedup guard used to be set
        # before verify_evidence() ran, so a single malformed/garbage
        # submission (bad sig, wrong height, transit corruption, or a
        # deliberately poisoned packet) would permanently occupy
        # evidence_id — every future, potentially genuinely valid,
        # evidence for that same violation would then be silently
        # discarded as "already processed" without ever reaching
        # verify_evidence again, permanently immunizing that validator
        # against this automated mechanism for that violation. Verifying
        # first means only evidence that actually holds up can ever claim
        # the dedup slot; a concurrent duplicate call is still handled
        # correctly by re-checking the guard under the lock right before
        # committing to it.
        ok, reason = self.verify_evidence(evidence)
        if not ok:
            return False, reason

        evidence_id = sha256(
            f"{evidence['validator']}:{evidence['block_hash_a']}:"
            f"{evidence['block_hash_b']}".encode())
        with self._lock:
            if evidence_id in self._seen_evidences:
                return False, "Evidence already processed"
            self._seen_evidences.add(evidence_id)

        validator = evidence["validator"]
        role = self._storage.get_role(validator)
        if not role:
            return False, f"Validator {validator[:16]} not registered"
        if role.get("slashed"):
            return False, f"Validator {validator[:16]} already slashed"

        self._storage.slash(validator)
        self._storage.set_meta(
            f"slash_evidence:{evidence_id[:32]}",
            json.dumps({"validator": validator,
                        "height": evidence.get("height", 0),
                        "timestamp": int(time.time())}))
        log.critical(
            f"SLASH EVIDENCE APPLIED: Validator {validator[:16]}... "
            f"double-signed at height {evidence.get('height', '?')}. "
            f"Submitted by {evidence.get('submitted_by','?')[:16]}.")
        metrics.inc("slash_evidence_applied")
        return True, f"Validator {validator[:16]} slashed via automated evidence"

    def handle_network_evidence(self, evidence: dict) -> Tuple[bool, str]:
        """Process incoming evidence from the network."""
        if evidence.get("type") != self.MSG_TYPE:
            return False, "Not a slash evidence message"
        return self.apply_evidence(evidence)
