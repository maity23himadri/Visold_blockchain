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
"""visold.node.security_gate

Original section: SECTION 15: EXECUTION SECURITY (INTEGRITY GATE)

Defines: SecurityGate
Origin: visold_vsd_.py L40216-40270
"""

import hashlib
import json
import os
from typing import Tuple

from visold.chain.blockchain import Blockchain
from visold.crypto.ecc import (
    ecdsa_keygen,
    ecdsa_sign,
    ecdsa_verify,
    pub_from_hex,
    pub_to_hex,
    sig_from_hex,
    sig_to_hex,
)
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.source_identity import package_source_blob
from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 15: EXECUTION SECURITY (INTEGRITY GATE)
# ─────────────────────────────────────────────────────────────────────────────
class SecurityGate:
    @staticmethod
    def verify_startup() -> Tuple[bool, str]:
        Config.ensure_dirs()
        sig_exists = os.path.exists(Config.SIG_FILE)
        key_exists = os.path.exists(Config.KEY_FILE)

        if not sig_exists or not key_exists:
            SecurityGate._create_node_signature()
            return True, "Node signature initialized"

        try:
            with open(Config.KEY_FILE) as f:
                pub_hex = f.read().strip()
            with open(Config.SIG_FILE) as f:
                sig_data = json.load(f)
            pub = pub_from_hex(pub_hex)
            sig = sig_from_hex(sig_data.get("sig","[]"))
            node_id = sig_data.get("node_id","").encode()
            h = hashlib.sha256(node_id).digest()
            if not ecdsa_verify(pub, h, sig):
                return False, "Node signature invalid — potential tampering"
        except Exception as e:
            return False, f"Security gate error: {e}"

        return True, "OK"

    @staticmethod
    def _create_node_signature():
        priv, pub = ecdsa_keygen()
        pub_hex   = pub_to_hex(pub)
        node_id   = sha256(pub_hex.encode())
        sig       = ecdsa_sign(priv, hashlib.sha256(node_id.encode()).digest())
        with open(Config.KEY_FILE, 'w') as f:
            f.write(pub_hex)
        with open(Config.SIG_FILE, 'w') as f:
            json.dump({"node_id": node_id, "sig": sig_to_hex(sig)}, f)

    @staticmethod
    def hash_self() -> str:
        try:
            return sha256(package_source_blob())
        except Exception:
            return "unknown"

    @staticmethod
    def verify_genesis_hash(storage: Storage, blockchain: Blockchain) -> Tuple[bool, str]:
        stored = storage.get_meta("genesis_hash")
        if not stored:
            return True, "No genesis hash stored yet"
        gen = blockchain.get_block(0)
        if gen and gen.block_hash != stored:
            return False, "CRITICAL: Genesis block tampered!"
        return True, "Genesis OK"
