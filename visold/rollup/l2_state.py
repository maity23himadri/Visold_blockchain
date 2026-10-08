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
"""visold.rollup.l2_state


Defines: L2Transaction, L2Account, L2StateTree, Layer2State
Origin: visold_vsd_.py L23441-23576, L23580-23602, L23606-23707, L23725, L23735, L23738-24090
"""

import hashlib
import json
import threading
import time
from typing import Dict, List, Optional, TYPE_CHECKING, Tuple

from visold.crypto.ecc import ecdsa_verify, pub_from_hex, pub_to_address, sig_from_hex
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics
from visold.rollup.compact_codec import l2_sig_expand

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
class L2Transaction:
    """A single off-chain transfer inside a rollup batch.

    Minimal field set (vs an L1 Transaction): no fee field, no memo, no
    tx_type, no gas_limit / gas_price, no expiry, no vrf.  The batch-level
    fee is paid by the sequencer when it submits the L1 RollupSubmission.

    Balance math is integer satoshi throughout (amount_sat is int, never float).

    Wire format (dict):
      {
        "l2_tx_id": <sha256 hex of canonical signing bytes + sig>,
        "sender":   <L1-style address, same keypair as L1>,
        "receiver": <L1-style address>,
        "amount_sat": <int>,
        "nonce":    <int, per-sender, 0-based>,
        "timestamp":<int, seconds>,
        "sig":      <128 hex chars — compact ECDSA sig_hex>,
        "pub":      <66 hex chars — compressed pub>,
      }
    """

    __slots__ = ("sender", "receiver", "amount_sat", "nonce",
                 "timestamp", "sig", "pub", "l2_tx_id")

    # Fixed upper bound on serialized tx size — prevents a malicious batch
    # from containing absurdly-huge individual entries.  Real entries are
    # ~400 B; 2 KB gives plenty of headroom.
    MAX_WIRE_BYTES = 2048

    def __init__(self, sender: str, receiver: str, amount_sat: int,
                 nonce: int, timestamp: int = 0,
                 sig: str = "", pub: str = "", l2_tx_id: str = ""):
        if not isinstance(amount_sat, int) or amount_sat < 0:
            raise ValueError("L2Transaction amount_sat must be non-negative int")
        if not isinstance(nonce, int) or nonce < 0:
            raise ValueError("L2Transaction nonce must be non-negative int")
        self.sender     = sender
        self.receiver   = receiver
        self.amount_sat = int(amount_sat)
        self.nonce      = int(nonce)
        self.timestamp  = int(timestamp) if timestamp else int(time.time())
        self.sig        = sig
        self.pub        = pub
        self.l2_tx_id   = l2_tx_id or self._compute_id()

    def signing_bytes(self) -> bytes:
        """Canonical bytes signed by the sender.  Includes CHAIN_ID + a fixed
        L2 domain tag so an L1 ECDSA signature cannot be replayed as an L2 tx
        (cross-layer replay protection) and vice versa."""
        d = (f"VSD-L2|{Config.CHAIN_ID}|{self.sender}|{self.receiver}|"
             f"{self.amount_sat}|{self.nonce}|{self.timestamp}")
        return d.encode()

    def _compute_id(self) -> str:
        core = self.signing_bytes() + self.sig.encode() + self.pub.encode()
        return sha256(core)

    def is_valid(self) -> Tuple[bool, str]:
        """Structural + signature check.  Does NOT check balance — that's the
        job of Layer2State.apply()."""
        if not self.sender or not self.receiver:
            return False, "missing sender/receiver"
        if self.sender == self.receiver:
            return False, "self-send forbidden on L2"
        if self.amount_sat <= 0:
            return False, "amount must be positive"
        if not self.sig or not self.pub:
            return False, "missing sig/pub"
        # POST-AUDIT FIX (v7.5.0-OPT): pub_from_hex() in this codebase
        # accepts the 33-byte COMPRESSED form directly (line 7790's
        # pub_from_bytes recomputes Y from X using the compressed prefix
        # convention) but does NOT correctly handle the 130-char
        # uncompressed 0x04-prefixed form — it reads the prefix's low bit
        # as the Y parity, which for 0x04 is always even, silently
        # corrupting ~50% of wallets whose true Y is odd (0x03 prefix).
        # We therefore pass the compressed form straight through; it is
        # already the canonical wire form produced by pub_to_hex().
        try:
            pub_pt = pub_from_hex(self.pub)
            sig_pair = sig_from_hex(l2_sig_expand(self.sig))
            h = hashlib.sha256(self.signing_bytes()).digest()
            if not ecdsa_verify(pub_pt, h, sig_pair):
                return False, "bad signature"
        except Exception as e:
            return False, f"signature verify error: {e}"
        # Bind the signer's public key to the declared sender address.
        # This prevents anyone from signing on behalf of another account by
        # swapping pub fields.  We derive the address from the compressed
        # pub_hex using the same scheme Wallet uses (pub_to_address):
        # double-sha256(pub_bytes), base58-encode the first 20 bytes, prefix
        # "VSD".  If the wallet's address derivation changes, this check
        # must be updated to match — but so far the primary defense against
        # signer impersonation is the ECDSA verify above, which binds the
        # signed payload to the pub bytes.
        #
        # SECURITY-FIX (v7.7.1) — fail CLOSED, not open.
        # Previous code: try/except set derived_addr=None on failure, then
        # `if derived_addr and ...` skipped the check entirely, allowing a
        # malicious tx with a crafted pub field that makes pub_to_address
        # raise to bypass the sender-binding rule and drain another account.
        # New behaviour: any exception in derivation → reject the tx.
        try:
            derived_addr = pub_to_address(pub_pt)
        except Exception as exc:
            return False, f"pub key address derivation failed: {exc}"
        if not derived_addr or self.sender != derived_addr:
            # Hard fail: the signer is not the claimed sender.  A replay
            # attacker swapping the pub field would hit exactly this path.
            return False, "sender/pub mismatch"
        return True, "OK"

    def to_dict(self) -> dict:
        return {
            "l2_tx_id":   self.l2_tx_id,
            "sender":     self.sender,
            "receiver":   self.receiver,
            "amount_sat": self.amount_sat,
            "nonce":      self.nonce,
            "timestamp":  self.timestamp,
            "sig":        self.sig,
            "pub":        self.pub,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'L2Transaction':
        return cls(
            sender     = d["sender"],
            receiver   = d["receiver"],
            amount_sat = int(d["amount_sat"]),
            nonce      = int(d["nonce"]),
            timestamp  = int(d.get("timestamp", 0)),
            sig        = d.get("sig", ""),
            pub        = d.get("pub", ""),
            l2_tx_id   = d.get("l2_tx_id", ""),
        )


# ─────────────────────────────────────────────────────────────────────────────
class L2Account:
    """Per-address L2 balance + nonce record.  All ints, all satoshi."""

    __slots__ = ("address", "balance_sat", "nonce")

    def __init__(self, address: str, balance_sat: int = 0, nonce: int = 0):
        self.address     = address
        self.balance_sat = int(balance_sat)
        self.nonce       = int(nonce)

    def leaf_bytes(self) -> bytes:
        """Canonical serialization used as a Merkle tree leaf.  Stable
        across platforms (no json whitespace variation, no locale)."""
        return (f"{self.address}|{self.balance_sat}|{self.nonce}").encode()

    def to_dict(self) -> dict:
        return {"address": self.address,
                "balance_sat": self.balance_sat,
                "nonce": self.nonce}

    @classmethod
    def from_dict(cls, d: dict) -> 'L2Account':
        return cls(d["address"], int(d["balance_sat"]), int(d["nonce"]))


# ─────────────────────────────────────────────────────────────────────────────
class L2StateTree:
    """Simple sorted-address Merkle tree over the L2 account set.

    Design choice — simple Merkle tree vs sparse Merkle / MMR:
    For a first-pass honest implementation the primary correctness property
    we need is: the root deterministically commits to (address → (balance,
    nonce)) for every address.  A sorted-by-address Merkle tree over the
    live account set gives that, is trivially auditable, and is what most
    "first-generation" sidechains use (including early Plasma variants).
    When you later swap to a circuit-friendly tree (e.g. Poseidon-hashed
    sparse Merkle tree of depth 256), only this class changes — the rest
    of the rollup refers to L2StateTree.root() as an opaque hex string.

    All balance/nonce values are integer satoshi; the tree stores no floats.

    Thread safety: callers are expected to own the Layer2State lock;
    L2StateTree itself is NOT internally synchronized (so recomputations
    stay cheap).
    """

    def __init__(self):
        # Sorted dict semantics via sorted(keys()) at root() time — we keep
        # a plain dict for O(1) update and sort at hash time.
        self._accounts: Dict[str, L2Account] = {}

    # ── Account access / mutation ─────────────────────────────────────────
    def get(self, address: str) -> L2Account:
        """Return the account, creating a zero-balance entry if missing.

        This is intentionally a mutating primitive.  Read-only callers MUST
        use ``peek()`` so an address lookup cannot alter the consensus state
        or its Merkle root.
        """
        a = self._accounts.get(address)
        if a is None:
            a = L2Account(address, 0, 0)
            self._accounts[address] = a
        return a

    def peek(self, address: str) -> Optional[L2Account]:
        """Return an existing account without creating one.

        This is the non-mutating account lookup primitive used by all
        consensus/read paths that must leave the state tree unchanged when
        an address is absent.
        """
        return self._accounts.get(address)

    def set(self, account: L2Account) -> None:
        self._accounts[account.address] = account

    def has(self, address: str) -> bool:
        return address in self._accounts

    def credit(self, address: str, amount_sat: int) -> None:
        if amount_sat <= 0:
            return
        a = self.get(address)
        a.balance_sat += int(amount_sat)

    def debit(self, address: str, amount_sat: int) -> Tuple[bool, str]:
        if amount_sat <= 0:
            return False, "amount must be positive"
        # Do not create a ghost zero-balance account on a failed debit.
        a = self.peek(address)
        if a is None or a.balance_sat < amount_sat:
            return False, "insufficient L2 balance"
        a.balance_sat -= int(amount_sat)
        return True, "OK"

    def bump_nonce(self, address: str) -> int:
        a = self.get(address)
        a.nonce += 1
        return a.nonce

    # ── Read-only accounting ──────────────────────────────────────────────
    def total_supply_sat(self) -> int:
        """Sum of all L2 balances — MUST equal total L1-locked L2 supply
        at every state transition.  Callers use this as a conservation
        invariant check against the L1 bridge balance."""
        return sum(a.balance_sat for a in self._accounts.values())

    def account_count(self) -> int:
        return len(self._accounts)

    # ── Root computation ──────────────────────────────────────────────────
    def root(self) -> str:
        """Deterministic Merkle root over the sorted account list.

        Empty state root: sha256(b"L2-EMPTY") — a constant domain-tagged
        sentinel, not all-zeros, so an empty root cannot collide with any
        hash of real data.
        """
        if not self._accounts:
            return sha256(b"L2-EMPTY")
        # Sort by address — stable, platform-independent, no locale issues.
        leaves = [sha256(self._accounts[addr].leaf_bytes())
                  for addr in sorted(self._accounts.keys())]
        # Standard duplicate-last Merkle tree (same scheme as Block._merkle).
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            leaves = [sha256((leaves[i] + leaves[i + 1]).encode())
                      for i in range(0, len(leaves), 2)]
        return leaves[0]

    # ── Snapshot / restore for reorgs ─────────────────────────────────────
    def snapshot(self) -> dict:
        """Return a dict suitable for deep-restore.  Plain dict of dicts —
        JSON-serializable so Storage can persist it alongside block data."""
        return {addr: acc.to_dict()
                for addr, acc in self._accounts.items()}

    def restore(self, snap: dict) -> None:
        self._accounts.clear()
        for addr, d in snap.items():
            self._accounts[addr] = L2Account.from_dict(d)


# ═════════════════════════════════════════════════════════════════════════════
# END SECTION 7E — Pass 1 (core primitives).  Subsequent passes add
#   Layer2State (7E-2), IProofBackend + SimulatedProofBackend (7E-3),
#   Sequencer + RollupSubmission (7E-4), verifier precompile hookup (7E-5),
#   wallet/P2P integration (7E-6), and reorg handler (7E-7).
# ═════════════════════════════════════════════════════════════════════════════


# ─────────────────────────────────────────────────────────────────────────────
# Canonical L2 bridge address.  L1 transactions sent to this receiver are
# interpreted by StateEngine as deposits into Layer-2.  The address is a
# reserved sentinel — it has no private key, balances accumulated here
# represent the L1 escrow backing of the L2 supply and should equal
# Layer2State.total_supply_sat() at every settlement boundary.
# ─────────────────────────────────────────────────────────────────────────────
L2_BRIDGE_ADDRESS = "VSDcL2BRIDGE00000000000000000"


# Sentinel address for L2 → L1 withdrawals.  A user sends a normal L1
# transfer TO this address; apply_block detects it, debits their L2 tree
# balance, then credits their L1 wallet from the bridge escrow — all inside
# the block, atomically, and recorded on-chain.  This means the L2 state
# root only mutates within apply_block (same as deposits), so no state-root
# mismatch or reorg vulnerability can occur.
# The address is a fixed 29-char sentinel (same length as L2_BRIDGE_ADDRESS)
# that cannot be a real keypair (no one can produce a valid signature for it).
L2_WITHDRAW_ADDRESS = "VSDcL2WITHDRAW0000000000000000"


class Layer2State:
    """Layer-2 state manager — bridges L1 escrow ↔ L2 balance tree and
    exposes the root that the sequencer will commit to on-chain.

    Invariants (checked on every mutation):
      • Every satoshi value is a Python int.  No floats.
      • total_supply_sat() == L1 balance at L2_BRIDGE_ADDRESS at every
        settlement boundary.  A deviation indicates a bug and is reported.
      • All roots are lowercase hex strings of length 64.
      • Confirmed-roots history is kept up to Config.L2_ROOT_HISTORY_DEPTH
        entries for reorg rollback (trimmed FIFO).

    Thread safety: single RLock.  All mutating methods take the lock.  Read
    methods that return immutable values (root, account_count) do not.
    """

    # How many past confirmed L2 roots we retain for reorg rollback.
    # A value of 128 covers multi-block reorgs up to ~2 hours at the 60s
    # block target, which is far beyond anything a honest network should
    # ever need to walk back.
    _DEFAULT_ROOT_HISTORY = 128

    def __init__(self, storage: 'Storage'):
        self.storage = storage
        self._lock   = threading.RLock()
        self._tree   = L2StateTree()
        # Ordered list of (l1_height, l1_block_hash, l2_root, tree_snapshot).
        # The tree_snapshot is the FULL account state at that l1_height so
        # a reorg can restore it deterministically.  Bounded below.
        self._history: List[dict] = []
        self._history_max = getattr(
            Config, "L2_ROOT_HISTORY_DEPTH", self._DEFAULT_ROOT_HISTORY)
        # Track last confirmed batch id so sequencer replay-protection is
        # enforceable here without coupling to the Sequencer object.
        self._last_batch_id: int = -1
        # Attempt to restore from persisted state on boot so restarts do not
        # lose L2 balances.  A missing/corrupt persisted state degrades to
        # an empty tree — the bridge-balance invariant below will detect
        # any supply mismatch and log it loudly.
        self._try_restore_from_storage()

    # ── Persistence helpers ───────────────────────────────────────────────
    # Layer2State uses Storage.set_meta / get_meta with JSON-encoded blobs.
    # Two keys:
    #   "l2_tree"    → current tree snapshot (dict of {addr: {balance, nonce}})
    #   "l2_history" → recent confirmed roots with snapshots
    #   "l2_last_batch_id" → int
    _META_TREE    = "l2_tree"
    _META_HISTORY = "l2_history"
    _META_BATCHID = "l2_last_batch_id"

    def _try_restore_from_storage(self) -> None:
        try:
            raw = self.storage.get_meta(self._META_TREE)
            if raw:
                snap = json.loads(raw)
                self._tree.restore(snap)
            raw_h = self.storage.get_meta(self._META_HISTORY)
            if raw_h:
                self._history = json.loads(raw_h)
            raw_b = self.storage.get_meta(self._META_BATCHID)
            if raw_b is not None and raw_b != "":
                self._last_batch_id = int(raw_b)
        except Exception as e:
            log.warning(f"Layer2State: restore failed — starting empty: {e}")
            self._tree    = L2StateTree()
            self._history = []
            self._last_batch_id = -1

    def _persist(self) -> None:
        """Atomically persist the complete L2 state.

        A successful mutation must never be acknowledged while only part of
        its durable state has reached storage.  Storage.set_meta_batch()
        commits all three metadata records in one backend transaction.
        Exceptions deliberately propagate to the mutating caller so it can
        restore its in-memory pre-mutation snapshot.
        """
        # Bound history size before serialisation.
        if len(self._history) > self._history_max:
            self._history = self._history[-self._history_max:]
        values = {
            self._META_TREE: json.dumps(self._tree.snapshot()),
            self._META_HISTORY: json.dumps(self._history),
            self._META_BATCHID: str(self._last_batch_id),
        }
        try:
            self.storage.set_meta_batch(values)
        except Exception as e:
            log.error(f"Layer2State: atomic persist FAILED: {e}")
            raise

    def _checkpoint(self, l1_height: int, l1_block_hash: str) -> None:
        """Record a full L2 checkpoint after an L1 bridge mutation.

        Rollup snapshots alone are insufficient for reorgs because deposits
        and withdrawals can occur between two settlements.  These checkpoints
        make rollback_to_height() restore the latest complete L2 state at or
        before the requested L1 height instead of rewinding to an older batch.
        """
        self._history.append({
            "l1_height": int(l1_height),
            "l1_block_hash": str(l1_block_hash or ""),
            "batch_id": int(self._last_batch_id),
            "l2_root": self._tree.root(),
            "snapshot": self._tree.snapshot(),
        })

    # ── Public read API ───────────────────────────────────────────────────
    def root(self) -> str:
        with self._lock:
            return self._tree.root()

    # ── L2-4 FIX: full-state snapshot/restore for apply_block atomicity ──
    # apply_block can mutate Layer2State via three hooks:
    #   • L2 bridge DEPOSIT  → tree.credit + persist
    #   • L2 bridge WITHDRAW → tree.debit  + persist
    #   • TYPE_ROLLUP        → tree advance + history.append + last_batch_id
    # If a LATER tx in the same block fails and apply_block calls
    # restore_accounts(snap) on the L1 side, the L2 mutations from earlier
    # txs in the same (now-rejected) block remain in memory AND on disk.
    # This causes the local Layer2State to drift from the canonical chain
    # state and to disagree with peers — the next TYPE_ROLLUP submission
    # would fail the prev_root check and the chain would fork at this node.
    #
    # snapshot_full() captures EVERYTHING that apply_block hooks can mutate.
    # restore_full() puts it all back, including the on-disk persist, so
    # apply_block failure leaves the local L2 indistinguishable from
    # before the call.
    def snapshot_full(self) -> dict:
        """Return an opaque snapshot of the entire L2 state.  Cheap because
        the tree snapshot is just a dict of dicts; history is already a
        list of dicts.  Caller must treat the return value as opaque."""
        with self._lock:
            return {
                "tree":          self._tree.snapshot(),
                # _history is a list of dicts; copy the list so future
                # mutations (history.append) do not mutate the snapshot.
                # The inner snapshot dicts are immutable in practice — we
                # never mutate an entry after appending — so a shallow
                # copy is sufficient.
                "history":       list(self._history),
                "last_batch_id": int(self._last_batch_id),
            }

    def restore_full(self, snap: dict) -> None:
        """Restore from a snapshot returned by snapshot_full().  Persists
        the restored state to storage so a process restart sees the
        same world.  Idempotent — multiple calls with the same snap
        produce the same on-disk state."""
        if not snap:
            return
        with self._lock:
            try:
                self._tree.restore(snap.get("tree") or {})
            except Exception as e:
                log.error(f"Layer2State.restore_full: tree restore failed: {e}")
            self._history       = list(snap.get("history") or [])
            self._last_batch_id = int(snap.get("last_batch_id", -1))
            # Persist immediately so a crash between here and the next
            # mutating call cannot leave a divergent on-disk state.
            self._persist()

    def get_balance_sat(self, address: str) -> int:
        with self._lock:
            account = self._tree.peek(address)
            return account.balance_sat if account is not None else 0

    def get_nonce(self, address: str) -> int:
        with self._lock:
            account = self._tree.peek(address)
            return account.nonce if account is not None else 0

    def total_supply_sat(self) -> int:
        with self._lock:
            return self._tree.total_supply_sat()

    def account_count(self) -> int:
        with self._lock:
            return self._tree.account_count()

    def bridge_balance_sat(self) -> int:
        """The L1 escrow balance — the canonical L2 collateral."""
        try:
            return int(self.storage.get_balance_sat(L2_BRIDGE_ADDRESS))
        except Exception as e:
            log.debug(f"bridge_balance_sat: storage failed: {e}")
            return 0

    def supply_invariant_ok(self) -> Tuple[bool, int, int]:
        """Return (ok, l2_supply_sat, l1_bridge_sat).  Called at settlement
        boundaries.  ok is False iff L2 total differs from L1 escrow."""
        l2 = self.total_supply_sat()
        l1 = self.bridge_balance_sat()
        return (l2 == l1), l2, l1

    # ── Bridge: L1 → L2 (deposit) ─────────────────────────────────────────
    def L2_deposit(self, address: str, amount_sat: int,
                   l1_height: int = -1, l1_block_hash: str = "") -> Tuple[bool, str]:
        """Credit `amount_sat` to `address` on L2.

        This is called by StateEngine IMMEDIATELY AFTER an L1 transfer of
        `amount_sat` into L2_BRIDGE_ADDRESS has been applied (so the L1
        escrow balance has already gone up by amount_sat).  We only touch
        the L2 tree here — the L1 credit is already in storage.

        The L1 side is the TRUTH: if somehow we are called with an L1 that
        doesn't match (bug / reorg mid-apply), we still credit L2 here
        because StateEngine is the authoritative caller, and the supply
        invariant check at the next settlement will surface any drift.
        """
        if not isinstance(amount_sat, int):
            return False, "amount_sat must be int"
        if amount_sat <= 0:
            return False, "deposit must be positive"
        if not address:
            return False, "missing address"
        with self._lock:
            snap = self._tree.snapshot()
            old_history = list(self._history)
            try:
                self._tree.credit(address, amount_sat)
                if l1_height >= 0:
                    self._checkpoint(l1_height, l1_block_hash)
                self._persist()
            except Exception:
                self._tree.restore(snap)
                self._history = old_history
                raise
        metrics.inc("l2_deposits")
        try:
            metrics.set_gauge("l2_total_supply_sat",
                              self.total_supply_sat())
        except Exception:
            pass
        return True, "OK"

    def L2_withdraw(self, address: str, amount_sat: int,
                    l1_height: int = -1, l1_block_hash: str = "") -> Tuple[bool, str]:
        """Debit `amount_sat` from `address` on L2.

        This is called by StateEngine when a settlement batch contains an
        exit intent for this address (or by a direct forced-exit path).
        The matching L1 side (crediting the user's L1 wallet) happens in
        the StateEngine call that invoked us, NOT here — Layer2State is
        responsible only for the L2 ledger.

        Returns (False, reason) if the account cannot cover the amount,
        leaving state unchanged — caller must not credit L1 on failure.
        """
        if not isinstance(amount_sat, int):
            return False, "amount_sat must be int"
        if amount_sat <= 0:
            return False, "withdraw must be positive"
        if not address:
            return False, "missing address"
        with self._lock:
            snap = self._tree.snapshot()
            old_history = list(self._history)
            try:
                ok, msg = self._tree.debit(address, amount_sat)
                if not ok:
                    return False, msg
                if l1_height >= 0:
                    self._checkpoint(l1_height, l1_block_hash)
                self._persist()
            except Exception:
                self._tree.restore(snap)
                self._history = old_history
                raise
        metrics.inc("l2_withdrawals")
        try:
            metrics.set_gauge("l2_total_supply_sat",
                              self.total_supply_sat())
        except Exception:
            pass
        return True, "OK"

    # ── Applying an L2 transaction (in-batch) ─────────────────────────────
    def apply_l2_tx(self, tx: 'L2Transaction') -> Tuple[bool, str]:
        """Apply one L2Transaction to the tree.  Used by the Sequencer during
        batch construction AND by the verifier during re-execution.

        Checks: structural, signature, nonce equality, sufficient balance.
        All balance math is integer satoshi; no float involvement.
        """
        ok, msg = tx.is_valid()
        if not ok:
            return False, msg
        with self._lock:
            # Read-only validation must not create a consensus-state entry.
            # An absent sender has no balance and therefore cannot satisfy the
            # transfer; keeping the tree untouched is essential for deterministic
            # rollup state-root computation when failed txs are encountered.
            sender = self._tree.peek(tx.sender)
            if sender is None:
                return False, "insufficient L2 balance"
            if tx.nonce != sender.nonce:
                return False, (f"nonce mismatch: got {tx.nonce}, "
                               f"expected {sender.nonce}")
            if sender.balance_sat < tx.amount_sat:
                return False, "insufficient L2 balance"
            # Apply.
            ok_d, dmsg = self._tree.debit(tx.sender, tx.amount_sat)
            if not ok_d:
                # Shouldn't happen — we just checked — but defensive.
                return False, dmsg
            self._tree.credit(tx.receiver, tx.amount_sat)
            self._tree.bump_nonce(tx.sender)
        return True, "OK"

    # ── Settlement: commit a batch's new root ─────────────────────────────
    def commit_batch(self, batch_id: int, new_root_expected: str,
                     l1_height: int, l1_block_hash: str) -> Tuple[bool, str]:
        """Record that an on-chain RollupSubmission for `batch_id` has been
        accepted at `l1_height`.  Snapshots the current tree so a future
        reorg past this point can restore it.

        Layer2State is expected to ALREADY be at the post-batch state (i.e.
        the Sequencer applied every tx in the batch via apply_l2_tx before
        calling this).  We sanity-check that the current root matches what
        the on-chain submission claimed.
        """
        with self._lock:
            cur = self._tree.root()
            if cur != new_root_expected:
                return False, (f"post-batch root mismatch: tree={cur[:16]}, "
                               f"submitted={new_root_expected[:16]}")
            if batch_id <= self._last_batch_id:
                return False, (f"batch_id {batch_id} not strictly greater "
                               f"than last {self._last_batch_id}")
            old_history = list(self._history)
            old_batch_id = self._last_batch_id
            self._last_batch_id = batch_id
            self._history.append({
                "l1_height":     int(l1_height),
                "l1_block_hash": l1_block_hash,
                "batch_id":      int(batch_id),
                "l2_root":       cur,
                "snapshot":      self._tree.snapshot(),
            })
            try:
                self._persist()
            except Exception:
                self._history = old_history
                self._last_batch_id = old_batch_id
                raise
        metrics.inc("l2_batches_committed")
        return True, "OK"

    # ── Reorg: roll L2 back to the most recent confirmed point whose L1
    # height is still canonical ───────────────────────────────────────────
    def rollback_to_height(self, safe_l1_height: int) -> Tuple[bool, str]:
        """Restore the latest complete L2 checkpoint at/before an L1 height.

        Every bridge mutation and every committed rollup now creates a
        checkpoint, so this no longer rewinds a post-batch deposit/withdrawal
        to an older batch snapshot.
        """
        with self._lock:
            target = None
            for entry in reversed(self._history):
                if int(entry.get("l1_height", -1)) <= int(safe_l1_height):
                    target = entry
                    break
            if target is None:
                log.warning(
                    f"Layer2State.rollback_to_height({safe_l1_height}): "
                    f"no checkpoint at or before that height — resetting L2 tree")
                self._tree = L2StateTree()
                self._history = []
                self._last_batch_id = -1
                self._persist()
                return True, "reset-to-empty"

            old_tree = self._tree.snapshot()
            old_history = list(self._history)
            old_batch_id = self._last_batch_id
            try:
                self._tree.restore(target["snapshot"])
                self._last_batch_id = int(target.get("batch_id", -1))
                # Retain the target checkpoint and only checkpoints that are
                # definitely at/before the canonical height.
                self._history = [e for e in self._history
                                 if int(e.get("l1_height", -1)) <= int(safe_l1_height)]
                self._persist()
            except Exception:
                self._tree.restore(old_tree)
                self._history = old_history
                self._last_batch_id = old_batch_id
                raise
            log.info(
                f"Layer2State: rolled back to L1 height "
                f"{target['l1_height']} (batch_id={target.get('batch_id', -1)}, "
                f"root={target['l2_root'][:16]})")
        return True, "OK"

    # ── Introspection for diagnostics / RPC ───────────────────────────────
    def status(self) -> dict:
        with self._lock:
            inv_ok, l2_sup, l1_sup = self.supply_invariant_ok()
            return {
                "root":              self._tree.root(),
                "account_count":     self._tree.account_count(),
                "l2_supply_sat":     l2_sup,
                "l1_bridge_sat":     l1_sup,
                "invariant_ok":      inv_ok,
                "last_batch_id":     self._last_batch_id,
                "history_depth":     len(self._history),
            }
