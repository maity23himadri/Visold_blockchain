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
"""visold.vm.naming


Defines: normalize_contract_name, validate_contract_name, derive_contract_address
Origin: visold_vsd_.py L10786-10804, L10809, L10812-10840, L21761-21764
"""

import re

from visold.crypto.hashing import sha256


# ── SC-NAME-1: Contract name helpers ─────────────────────────────────────────

def normalize_contract_name(raw: str) -> str:
    """
    Canonical normalisation for a VVM contract name.

    Rules:
      • strip leading/trailing whitespace
      • casefold (locale-independent lowercase)
      • result is the authoritative key used in storage and consensus

    Called at:
      - Transaction.__init__() boundary (incoming user input)
      - _apply_vvm_tx() before uniqueness check (consensus path)
      - Storage.get_contract_by_name() lookup (always normalise before query)

    Returns the normalised string (possibly empty — caller validates length).
    """
    if not isinstance(raw, str):
        return ""
    return raw.strip().casefold()


# Compiled once at module level — no regex object allocation in hot paths.
# Hyphen is placed at the end of the character class to avoid ambiguity.
_CONTRACT_NAME_RE = re.compile(r'^[a-z0-9_.-]{1,64}$')


def validate_contract_name(name: str) -> tuple:
    """
    Validate a NORMALISED contract name (call normalize_contract_name first).

    Returns (True, "OK") or (False, "<reason>").

    Rules:
      • 1–64 characters (Config.VVM_CONTRACT_NAME_MAX_LEN)
      • Allowed charset: lowercase a-z, 0-9, underscore, hyphen, dot
      • No consecutive dots (..) or hyphens (--)
        (prevents homoglyph confusion and mirrors DNS/identity rules)
      • No leading/trailing dot or hyphen

    Consensus impact: any node that deems a name invalid will reject the
    transaction.  The rules must be identical on every node.
    """
    if not name:
        return False, "Contract name cannot be empty"
    if len(name) > 64:          # hard-coded; mirrors Config.VVM_CONTRACT_NAME_MAX_LEN
        return False, f"Contract name too long: {len(name)} chars (max 64)"
    if not _CONTRACT_NAME_RE.match(name):
        return False, (
            "Contract name must contain only lowercase letters, digits, "
            "underscores, hyphens, or dots (a-z 0-9 _ - .)")
    if name.startswith(('.', '-')) or name.endswith(('.', '-')):
        return False, "Contract name must not start or end with '.' or '-'"
    if '..' in name or '--' in name:
        return False, "Contract name must not contain '..' or '--'"
    return True, "OK"


# ── Contract address derivation helper ───────────────────────────────────────
def derive_contract_address(sender: str, nonce: int, tx_id: str) -> str:
    """Deterministic contract address derivation (same as VVMEngine.deploy)."""
    addr_input = f"{sender}:{nonce}:{tx_id}"
    return "VSDc" + sha256(addr_input.encode())[:36]
