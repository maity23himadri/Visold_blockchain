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
"""visold.identity.names

Original section: SECTION 16: IDENTITY SYSTEM (Decentralized Name Service)

Defines: IdentitySystem
Origin: visold_vsd_.py L40275-40407
"""

import re
from typing import Optional, TYPE_CHECKING, Tuple

from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.events import Event, EventType
from visold.kernel.logging_setup import log
from visold.kernel.units import from_satoshi
from visold.ledger.transaction import Transaction
from visold.network.p2p import P2PNetwork
from visold.storage.storage import Storage

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.chain.blockchain import Blockchain
    from visold.state.engine import StateEngine
    from visold.wallet.wallet import Wallet


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 16: IDENTITY SYSTEM (Decentralized Name Service)
# ─────────────────────────────────────────────────────────────────────────────
class IdentitySystem:
    def __init__(self, storage: Storage, network: Optional[P2PNetwork],
                 wallet: 'Wallet', blockchain: Optional['Blockchain'] = None,
                 state_engine: Optional['StateEngine'] = None):
        self.storage = storage
        self.network = network
        self.wallet  = wallet
        self.blockchain = blockchain
        self.state_engine = state_engine

    def register(self, user_id: str, host: str, port: int) -> Tuple[bool, str]:
        # ─────────────────────────────────────────────────────────────────
        # v7.1.13 BUG-3 FIX (Identity Shadowing / Impersonation):
        #   Pre-fix code allowed both "Admin" and "admin" to register, and
        #   "alice" / "alice." / "alice-" all looked identical in many UI
        #   fonts.  Combined with the Decentralized Name Service
        #   broadcasting the registration, this created an
        #   impersonation/phishing surface.
        #
        #   Fix:
        #     1. Trim whitespace.
        #     2. Case-fold (Unicode-correct lowercase) so Admin == admin.
        #     3. Reject leading/trailing '.' or '-' (visual-confusion).
        #     4. Reject consecutive '.' or '-' (e.g. "alice..bob",
        #        "alice--bob") — ditto.
        #     5. Then run the existing alphanumeric regex on the
        #        normalised form.
        #
        #   The normalised user_id is what's stored on-chain and
        #   broadcast.  Callers should also display the normalised form
        #   so what users SEE matches what they TYPED.
        # ─────────────────────────────────────────────────────────────────
        if not isinstance(user_id, str):
            return False, "user_id must be a string"
        normalised = user_id.strip().casefold()
        if normalised != user_id:
            log.info(
                f"[IDENTITY] normalising user_id "
                f"{user_id!r} -> {normalised!r}")
        # FIX: accept BOTH forms used elsewhere in the system —
        #   1. domain form        : "alice"               (3–32 of [a-z0-9_.\-])
        #   2. account-ID form    : "alice#1a2b3c4d5e"   (USERNAME#10hex)
        # Previously only form 1 was accepted, so the boot path stripped
        # "#hex" before registering. That made the full account ID
        # un-resolvable AND made the bare username collide across all users
        # who share it. Registering the full form keeps IDs globally unique.
        _domain_re  = re.compile(r'^[a-z0-9_.\-]{3,32}$')
        _account_re = re.compile(r'^[a-z0-9_]{3,32}#[0-9a-f]{10}$')
        if not (_domain_re.match(normalised) or _account_re.match(normalised)):
            return False, (
                "user_id must be 3–32 chars of [a-z 0-9 _ . -] "
                "OR account form USERNAME#<10 hex chars> (case-insensitive)")
        # Boundary-character rejection (domain form only — account form is
        # already strictly validated by the regex above)
        if '#' not in normalised:
            if normalised[0] in '.-' or normalised[-1] in '.-':
                return False, "user_id cannot start or end with '.' or '-'"
            if '..' in normalised or '--' in normalised:
                return False, "user_id cannot contain '..' or '--'"
        user_id = normalised   # use the canonical form everywhere below

        existing = self.storage.resolve_name_claim(user_id)
        if existing:
            if existing["pub_hex"] != self.wallet.pub_hex:
                return False, "user_id already claimed by another key"
            # The claim is already canonical. Refresh only the non-consensus
            # reachability directory and never create another ownership record.
            peer_id = sha256(self.wallet.pub_hex.encode())
            multiaddrs = [f"/ip4/{host}/tcp/{port}/p2p/{peer_id}"]
            self.storage.save_identity(
                user_id, peer_id, self.wallet.address,
                self.wallet.pub_hex, multiaddrs)
            self.storage.set_meta("user_id", user_id)
            if self.network:
                self.network.broadcast_identity(user_id, multiaddrs)
            return True, f"Identity already registered: {user_id}"

        if self.blockchain is None or self.state_engine is None:
            return False, "Identity registry is not connected to the blockchain"

        # Do not submit duplicate claims while the first claim is pending.
        try:
            for pending in self.blockchain.mempool.all_txs():
                if (Transaction.is_identity_claim(pending)
                        and Transaction.identity_name_from_memo(pending.memo)
                        == user_id):
                    if pending.pub_hex == self.wallet.pub_hex:
                        return False, f"Identity claim already pending: {user_id}"
                    return False, "user_id already claimed by another pending key"
        except Exception as exc:
            log.debug("Identity pending-claim scan failed: %s", exc)

        # Ownership is decided by canonical block order. The existing
        # TYPE_REGISTER envelope is used so mining, gossip, block encoding,
        # and synchronization remain unchanged.
        fee_vsd = from_satoshi(int(getattr(Config, "MIN_TX_FEE_SAT", 1000)))
        sender = self.wallet.address
        try:
            chain_nonce = self.storage.get_nonce(sender)
            pending_count = len(
                self.blockchain.mempool._pending_nonces.get(sender, set()))
            nonce = chain_nonce + pending_count
        except Exception:
            nonce = 0
        tx = Transaction(
            sender=sender,
            receiver="",
            amount=0.0,
            fee=fee_vsd,
            memo=f"{Transaction.IDENTITY_MEMO_PREFIX}{user_id}",
            nonce=nonce,
            tx_type=Transaction.TYPE_REGISTER,
        )
        tx.sign(self.wallet)
        ok, msg = self.state_engine.post_sync(
            Event(EventType.NEW_TX, {"tx": tx.to_dict()}))
        if not ok:
            return False, msg
        self.storage.set_meta("user_id", user_id)
        return True, f"Identity claim submitted: {user_id}"

    def resolve(self, user_id: str) -> Optional[dict]:
        # v7.1.13: normalise lookups identically to register() so
        # "Admin" resolves to whatever was stored under "admin".
        if isinstance(user_id, str):
            user_id = user_id.strip().casefold()
        if self.network:
            return self.network.resolve_user_id(user_id)
        return self.storage.resolve_identity(user_id)

    def get_wallet_address(self, user_id: str) -> Optional[str]:
        identity = self.resolve(user_id)
        return identity["wallet_addr"] if identity else None
