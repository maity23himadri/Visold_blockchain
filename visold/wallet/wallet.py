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
"""visold.wallet.wallet

Original section: SECTION 3: WALLET

Defines: Wallet
Origin: visold_vsd_.py L11308-11418
"""

import hashlib
import json
import time
from typing import Tuple

from visold.crypto.ecc import (
    ECPoint,
    G,
    ecdsa_keygen,
    ecdsa_sign,
    pub_from_hex,
    pub_to_address,
    pub_to_hex,
    sig_to_hex,
    _COINCURVE_SELFTEST_OK,
    _CoincurvePrivateKey,
)
from visold.crypto.keystore import keystore_decrypt, keystore_encrypt
from visold.crypto.mnemonic import mnemonic_from_priv, priv_from_mnemonic
from visold.rollup.compact_codec import l2_pub_compact, l2_sig_compact
from visold.rollup.l2_state import L2Transaction


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3: WALLET
# ─────────────────────────────────────────────────────────────────────────────
class Wallet:
    def __init__(self, priv: int, pub: ECPoint):
        self.priv    = priv
        self.pub     = pub
        self.address = pub_to_address(pub)
        self.pub_hex = pub_to_hex(pub)
        self._rebuild_signing_cache()

    def _rebuild_signing_cache(self) -> None:
        """Build process-local native signing objects; never serialize them."""
        self._crypto_private_key = None
        try:
            from visold.kernel.compat import derive_private_key, SECP256K1, default_backend
            self._crypto_private_key = derive_private_key(
                int(self.priv), SECP256K1(), default_backend()
            )
        except Exception:
            # The mandatory path remains available through ecdsa_sign() if a
            # platform unexpectedly cannot retain the cached native object.
            self._crypto_private_key = None

        self._native_private_key = None
        if _COINCURVE_SELFTEST_OK and _CoincurvePrivateKey is not None:
            try:
                self._native_private_key = _CoincurvePrivateKey(
                    int(self.priv).to_bytes(32, "big")
                )
            except Exception:
                self._native_private_key = None

    def __getstate__(self):
        """Exclude native cryptographic objects from pickle serialization."""
        state = dict(self.__dict__)
        state.pop("_crypto_private_key", None)
        state.pop("_native_private_key", None)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._rebuild_signing_cache()

    @classmethod
    def generate(cls) -> 'Wallet':
        priv, pub = ecdsa_keygen()
        return cls(priv, pub)

    def sign(self, data: bytes) -> Tuple[int,int]:
        h = hashlib.sha256(data).digest()
        return ecdsa_sign(self.priv, h, self._native_private_key, self._crypto_private_key)

    # ── v7.5.0-OPT L2 TRANSACTION SIGNING ────────────────────────────────
    def sign_l2_tx(self, receiver: str, amount_sat: int, nonce: int,
                   timestamp: int = 0) -> 'L2Transaction':
        """Construct and sign an L2Transaction in one call.

        Uses the same private key as L1 (single-seed wallet) but produces
        a compact-signature/compressed-pub form that saves ~50% on-wire
        bytes vs. attaching a full L1 tx signature.

        All amount / nonce values are integers (satoshi / sequence).
        The timestamp defaults to the current wall-clock second; callers
        that want deterministic timestamps can pass one explicitly.

        Note on cross-layer replay: L2Transaction.signing_bytes() embeds
        the L2 domain tag "VSD-L2" and Config.CHAIN_ID, so an L1
        signature over L1 content cannot be replayed as a valid L2 tx
        and vice versa — the signatures commit to different preimages.
        """
        if not isinstance(amount_sat, int):
            raise TypeError("amount_sat must be an int (satoshi)")
        ts = int(timestamp) if timestamp else int(time.time())
        # Build a scratch tx first — its signing_bytes() gives us the
        # canonical preimage.
        scratch = L2Transaction(
            sender     = self.address,
            receiver   = receiver,
            amount_sat = int(amount_sat),
            nonce      = int(nonce),
            timestamp  = ts,
        )
        sig_pair   = self.sign(scratch.signing_bytes())
        full_sig   = sig_to_hex(sig_pair)
        compact_sig = l2_sig_compact(full_sig)
        compact_pub = l2_pub_compact(self.pub_hex)
        # Produce the final tx with sig/pub populated and tx_id recomputed.
        return L2Transaction(
            sender     = self.address,
            receiver   = receiver,
            amount_sat = int(amount_sat),
            nonce      = int(nonce),
            timestamp  = ts,
            sig        = compact_sig,
            pub        = compact_pub,
        )

    def to_dict(self) -> dict:
        return {
            "priv_hex": hex(self.priv),
            "pub_hex":  self.pub_hex,
            "address":  self.address,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'Wallet':
        priv = int(d["priv_hex"], 16)
        pub  = pub_from_hex(d["pub_hex"])
        return cls(priv, pub)

    def save(self, path: str):
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> 'Wallet':
        with open(path) as f:
            return cls.from_dict(json.load(f))

    def save_keystore(self, path: str, password: str):
        """Save AES-256-GCM encrypted keystore.
        BUG-FIX: docstring previously said "AES-256-CBC" but keystore_encrypt()
        uses AES-256-GCM (authenticated encryption) since the GCM migration."""
        ks = keystore_encrypt(hex(self.priv), password)
        ks["address"] = self.address
        ks["pub_hex"] = self.pub_hex
        with open(path, 'w') as f:
            json.dump(ks, f, indent=2)

    @classmethod
    def load_keystore(cls, path: str, password: str) -> 'Wallet':
        with open(path) as f:
            ks = json.load(f)
        priv_hex = keystore_decrypt(ks, password)
        priv = int(priv_hex, 16)
        pub  = pub_from_hex(ks["pub_hex"])
        return cls(priv, pub)

    @property
    def mnemonic(self) -> str:
        return mnemonic_from_priv(self.priv)

    @classmethod
    def from_mnemonic(cls, phrase: str) -> 'Wallet':
        priv = priv_from_mnemonic(phrase)
        pub  = priv * G
        return cls(priv, pub)
