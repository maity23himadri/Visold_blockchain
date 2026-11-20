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
import hmac
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


def _compute_canonical_genesis_hash() -> str:
    """Return the canonical genesis block hash from Config.GENESIS_* constants."""
    if hasattr(Blockchain, "build_canonical_genesis"):
        return Blockchain.build_canonical_genesis().block_hash
    from visold.ledger.block import Block
    from visold.ledger.transaction import Transaction

    genesis_tx = Transaction(
        sender    = "COINBASE",
        receiver  = Config.GENESIS_MINER,
        amount    = Config.GENESIS_TX_AMOUNT,
        fee       = 0.0,
        timestamp = Config.GENESIS_TIMESTAMP,
        memo      = Config.GENESIS_TX_MEMO,
        nonce     = Config.GENESIS_TX_NONCE,
        expiry    = Config.GENESIS_TX_EXPIRY,
    )
    genesis_tx.sender = Config.GENESIS_TX_SENDER
    genesis_tx.tx_id  = genesis_tx._compute_id()

    genesis = Block(
        index         = 0,
        prev_hash     = "0" * 64,
        transactions  = [genesis_tx],
        miner_address = Config.GENESIS_MINER,
        difficulty    = Config.INITIAL_DIFFICULTY,
        timestamp     = Config.GENESIS_TIMESTAMP,
        nonce         = Config.GENESIS_NONCE,
    )
    genesis.finalized = True
    genesis.seal()
    return genesis.block_hash


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 15: EXECUTION SECURITY (INTEGRITY GATE)
# ─────────────────────────────────────────────────────────────────────────────
class SecurityGate:
    @staticmethod
    def verify_startup() -> Tuple[bool, str]:
        Config.ensure_dirs()
        sig_exists = os.path.exists(Config.SIG_FILE)
        key_exists = os.path.exists(Config.KEY_FILE)

        if not sig_exists and not key_exists:
            SecurityGate._create_node_signature()
            return True, "Node signature initialized"

        if sig_exists != key_exists:
            missing = Config.SIG_FILE if not sig_exists else Config.KEY_FILE
            return False, (
                f"Security gate error: partial identity state (missing {missing}) "
                "— potential tampering"
            )

        try:
            with open(Config.KEY_FILE) as f:
                pub_hex = f.read().strip()
            with open(Config.SIG_FILE) as f:
                sig_data = json.load(f)
            if not isinstance(sig_data, dict):
                return False, "Security gate error: invalid signature payload"
            node_id_str = sig_data.get("node_id", "")
            if not isinstance(node_id_str, str) or not node_id_str:
                return False, "Node signature invalid — missing node_id"
            expected_node_id = sha256(pub_hex.encode())
            if not hmac.compare_digest(node_id_str, expected_node_id):
                return False, "Node ID does not match public key — potential tampering"
            pub = pub_from_hex(pub_hex)
            sig = sig_from_hex(sig_data.get("sig", "[]"))
            h = hashlib.sha256(node_id_str.encode()).digest()
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
        pinned = (Config.GENESIS_HASH_PIN or "").strip().lower()
        canonical_hash = _compute_canonical_genesis_hash()
        if pinned and canonical_hash.lower() != pinned:
            return False, "CRITICAL: Canonical genesis hash does not match Config.GENESIS_HASH_PIN!"

        stored = storage.get_meta("genesis_hash")
        gen = blockchain.get_block(0)

        if not stored:
            if storage.chain_height() >= 0:
                if gen is None:
                    return False, "CRITICAL: Genesis block (height 0) is missing!"
                if gen.block_hash != canonical_hash:
                    return False, "CRITICAL: Genesis block tampered!"
                if pinned and gen.block_hash.lower() != pinned:
                    return False, "CRITICAL: Genesis block does not match Config.GENESIS_HASH_PIN!"
                return True, "Genesis OK"
            return True, "No genesis hash stored yet"

        if pinned and stored.lower() != pinned:
            return False, "CRITICAL: Stored genesis_hash does not match Config.GENESIS_HASH_PIN!"
        if gen is None:
            return False, "CRITICAL: Genesis block (height 0) is missing!"
        if gen.block_hash != stored:
            return False, "CRITICAL: Genesis block tampered!"
        if pinned and gen.block_hash.lower() != pinned:
            return False, "CRITICAL: Genesis block does not match Config.GENESIS_HASH_PIN!"
        return True, "Genesis OK"
