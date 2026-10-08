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
"""visold.state.batch_proxy


Origin: visold_vsd_.py L6821-7052
"""

from typing import Dict, TYPE_CHECKING

from visold.kernel.logging_setup import log
from visold.kernel.units import from_satoshi, to_satoshi
from visold.resilience.hardened_core import InvariantViolation, _hc_inv, _hc_panic_cb

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# TPS-OPT-2 — STORAGE BATCH PROXY
# ─────────────────────────────────────────────────────────────────────────────
# During apply_block, every credit_sat / debit_sat / set_nonce / update_ht_volume
# is an individual database round-trip.  For a 200-tx block that means ~800
# separate PG transactions + Redis writes.
#
# _StorageBatchProxy intercepts these calls, buffers all mutations in memory,
# and exposes a flush() that writes the ENTIRE block's state delta in ONE
# PG transaction and ONE RocksDB WriteBatch.  I/O drops from O(n) round-trips
# to O(1).
#
# Read-through: reads check the in-memory buffer first (so intra-block balance
# checks remain correct), then fall through to the real Storage.
#
# Security: IDENTICAL validation logic — only the write path changes.
# ─────────────────────────────────────────────────────────────────────────────
class _StorageBatchProxy:
    """Drop-in proxy for Storage that buffers writes for atomic batch commit."""

    __slots__ = ("_real", "_balances", "_nonces", "_vol_deltas",
                 "_dirty_bal", "_dirty_non", "_dirty_vol",
                 "_bal_preloaded", "_bal_original")

    def __init__(self, real_storage: 'Storage'):
        self._real = real_storage
        # addr → current balance_sat (may include this-block mutations)
        self._balances: Dict[str, int] = {}
        # addr → latest nonce
        self._nonces: Dict[str, int] = {}
        # addr → accumulated volume DELTA in this block (satoshi)
        self._vol_deltas: Dict[str, int] = {}
        # Track which addresses were actually mutated
        self._dirty_bal: set = set()
        self._dirty_non: set = set()
        self._dirty_vol: set = set()
        self._bal_preloaded: set = set()
        # AUDIT-FIX (Batch D): addr → balance_sat as of the FIRST time this
        # proxy touched it (before any credit_sat/debit_sat mutation). This
        # is a strict superset of whatever the caller's pre-loop `touched`/
        # `snap` set could know in advance, since it also covers addresses
        # only discovered mid-execution (a freshly deployed contract's
        # address, a SELFDESTRUCT beneficiary) that snapshot_accounts()
        # could never have included. See restore_all_touched().
        self._bal_original: Dict[str, int] = {}

    # ── Transparent delegation for any method not overridden below ─────
    def __getattr__(self, name):
        """Fall through to the real Storage for VVM, contract, and other
        methods not explicitly intercepted by this proxy."""
        return getattr(self._real, name)

    # ── Balance operations ────────────────────────────────────────────────

    def _ensure_bal(self, address: str) -> int:
        if address not in self._balances:
            bal = self._real._get_balance_satoshi(address)
            self._balances[address] = bal
            self._bal_preloaded.add(address)
            self._bal_original[address] = bal
        return self._balances[address]

    def _get_balance_satoshi(self, address: str) -> int:
        return self._ensure_bal(address)

    def get_balance(self, address: str) -> float:
        return from_satoshi(self._ensure_bal(address))

    def get_balance_sat(self, address: str) -> int:
        return self._ensure_bal(address)

    def credit_sat(self, address: str, amount_sat: int):
        # AUDIT-FIX-K1 (hardened invariant checks bypassed during real block
        # application): apply_hardened_overlay() monkey-patches
        # Storage.credit_sat/debit_sat on the real Storage instance, but
        # apply_block swaps self.storage to a fresh _StorageBatchProxy for
        # the whole call (this class), which has its own separate
        # credit_sat/debit_sat that never delegated to the real (possibly
        # patched) methods -- so none of the hardened write-gate /
        # invariant checks ever ran for normal transaction processing.
        # _hc_panic_cb and _hc_inv are module-level singletons, not
        # something that exists only via monkey-patching, so call them
        # directly here -- same checks hardened_credit_sat applies.
        _hc_panic_cb.assert_writable(f"credit_sat({address[:16]}, {amount_sat})")
        _hc_inv.assert_credit_safe(address, amount_sat, context="pre-credit (batch proxy)")
        # AUDIT-FIX-10 (unauthorized minting, defense in depth): a negative
        # "credit" is an unguarded debit. This should never be reachable now
        # that Transaction.is_valid() rejects amount < 0 for DEPLOY and CALL,
        # but this base primitive should not depend solely on callers
        # upstream getting that right -- raise loudly rather than silently
        # corrupting a balance. Caught safely by apply_block's existing
        # exception handler (AUDIT-FIX-3), which undoes any partial VVM
        # effects and rejects the whole block.
        if int(amount_sat) < 0:
            raise ValueError(
                f"credit_sat({address[:16]}, {amount_sat}): negative amount "
                f"rejected -- a negative credit is an unguarded debit")
        cur = self._ensure_bal(address)
        self._balances[address] = cur + int(amount_sat)
        self._dirty_bal.add(address)

    def credit(self, address: str, amount: float):
        self.credit_sat(address, to_satoshi(amount))

    def debit_sat(self, address: str, amount_sat: int) -> bool:
        # AUDIT-FIX-K1: mirror hardened_debit_sat's checks -- see credit_sat
        # above for why this proxy needs its own copy of them.
        _hc_panic_cb.assert_writable(f"debit_sat({address[:16]}, {amount_sat})")
        _pre_bal = self._ensure_bal(address)
        _hc_inv.assert_balance_non_negative(
            address, _pre_bal, context="pre-debit (batch proxy)")
        # AUDIT-FIX-10 (unauthorized minting, defense in depth): a negative
        # "debit" is an unguarded credit -- cur - amount_sat with a negative
        # amount_sat INCREASES the balance, and the balance-sufficiency check
        # below (cur < amount_sat) is trivially satisfied for any negative
        # amount_sat regardless of cur, including a zero starting balance.
        # Treat it the same as any other invalid debit: refuse it. Returning
        # False (not raising) reuses the caller's existing "debit failed"
        # handling (refund/reject), matching how insufficient balance is
        # already handled.
        if int(amount_sat) < 0:
            return False
        cur = self._ensure_bal(address)
        if cur < int(amount_sat):
            return False
        self._balances[address] = cur - int(amount_sat)
        self._dirty_bal.add(address)
        # AUDIT-FIX-K1: post-debit corruption check, mirroring
        # hardened_debit_sat's post-check -- catches an invariant break
        # (e.g. a logic bug) rather than trusting the pre-check alone.
        _post_bal = self._balances[address]
        if _post_bal < 0:
            _hc_panic_cb.record_failure(
                "post_debit_negative",
                InvariantViolation(
                    f"Post-debit balance negative (batch proxy): "
                    f"{address[:16]}={_post_bal}"),
                corruption_level=True)
            raise InvariantViolation(
                f"[INV] CORRUPTION: debit left negative balance "
                f"for {address[:16]}: {_post_bal} (batch proxy)")
        return True

    def debit(self, address: str, amount: float) -> bool:
        return self.debit_sat(address, to_satoshi(amount))

    # ── Nonce operations ──────────────────────────────────────────────────

    def get_nonce(self, address: str) -> int:
        if address not in self._nonces:
            self._nonces[address] = self._real.get_nonce(address)
        return self._nonces[address]

    def set_nonce(self, address: str, nonce: int):
        self._nonces[address] = int(nonce)
        self._dirty_non.add(address)

    # ── Volume operations ─────────────────────────────────────────────────

    def update_ht_volume(self, address: str, volume: float):
        vol_sat = to_satoshi(volume)
        self._vol_deltas[address] = self._vol_deltas.get(address, 0) + vol_sat
        self._dirty_vol.add(address)

    # ── Pass-through for read-only methods ────────────────────────────────

    def get_all_by_role(self, role):
        return self._real.get_all_by_role(role)

    def get_role(self, address):
        return self._real.get_role(address)

    def set_role(self, address, role, stake):
        # Roles are low-volume; write-through immediately (no batch needed)
        self._real.set_role(address, role, stake)

    def compute_state_root(self) -> str:
        # Must flush buffered state BEFORE computing root so the root
        # reflects all mutations from this block.
        self.flush()
        return self._real.compute_state_root()

    def save_block(self, block):
        return self._real.save_block(block)

    def record_block_apply_result(self, idx, ok):
        return self._real.record_block_apply_result(idx, ok)

    # Snapshot / restore delegate to real storage — the proxy is only
    # alive during a single apply_block call and snapshots are taken
    # BEFORE the proxy is created.
    def snapshot_accounts(self, addresses):
        return self._real.snapshot_accounts(addresses)

    def restore_accounts(self, snap):
        return self._real.restore_accounts(snap)

    def _record_state_channel_balance_before(self, address: str) -> None:
        """Journal the current in-block account view, not persistent pre-block state.

        During ``apply_block`` balance writes are buffered here.  Delegating this
        hook blindly to Storage would snapshot the database value before the whole
        block, losing earlier transaction effects when a later VVM frame reverts.
        """
        if not address:
            return
        current_balance = self._ensure_bal(address)
        base = self._real.snapshot_accounts([address]).get(address)
        if base is None:
            base = (0, 0, 0, False)
        current_nonce = self.get_nonce(address)
        current_volume = int(base[2]) + int(self._vol_deltas.get(address, 0))
        proxy_snapshot = (int(current_balance), int(current_nonce),
                          current_volume, bool(base[3]))
        self._real._record_state_channel_balance_before(
            address, snapshot=proxy_snapshot)

    def restore_state_channel_journal(self, journal: dict,
                                      restore_accounts: bool = True) -> None:
        """Restore channel rows and, when requested, the proxy-visible balances.

        Channel rows are write-through in VVM, so those must be restored in the
        real Storage.  Balances are buffered by this proxy, so restoring them via
        real Storage would be wrong and could erase earlier in-block mutations.
        """
        if not journal:
            return
        channels = journal.get("channels", journal if "channels" not in journal else {})
        accounts = journal.get("accounts", {})

        if channels:
            self._real.restore_state_channel_journal(
                {"channels": channels, "accounts": {}}, restore_accounts=False)

        if not restore_accounts:
            return

        for addr, snapshot in accounts.items():
            try:
                if not isinstance(snapshot, (list, tuple)) or len(snapshot) != 4:
                    continue
                target_balance = int(snapshot[0])
                self._ensure_bal(addr)
                self._balances[addr] = target_balance
                # Preserve whether this address was already dirty earlier in the
                # block.  Dirty is determined from the original pre-block value.
                original = self._bal_original.get(addr, target_balance)
                if target_balance != original:
                    self._dirty_bal.add(addr)
                else:
                    self._dirty_bal.discard(addr)
            except Exception as exc:
                log.error(
                    "CRITICAL: batch proxy channel-balance restore failed for %s: %s",
                    addr[:16], exc)
                raise

    def snapshot_roles(self, addresses):
        return self._real.snapshot_roles(addresses)

    def restore_roles(self, snap):
        return self._real.restore_roles(snap)

    def restore_all_touched(self):
        """AUDIT-FIX (Batch D): restore every address this proxy has ever
        touched back to its pre-touch balance, written directly to real
        storage. Call this on ANY apply_block failure path -- in addition to,
        not instead of, restore_accounts(snap) -- since the caller's
        pre-computed touched/snap set is built before the tx loop runs and
        can never include an address that only came into existence during
        VM execution (a freshly deployed contract's address, a SELFDESTRUCT
        beneficiary). Both credit that address via this proxy's credit_sat,
        which accepts any address, not just ones in the caller's snap; only
        this method's own _bal_original record can reverse that credit if
        the block is later rejected. Idempotent with restore_accounts(snap)
        for addresses in both sets, since both read the same pre-block value.
        """
        for addr, orig_val in self._bal_original.items():
            try:
                self._real.set_balance(addr, orig_val)
            except Exception as exc:
                log.error(
                    "CRITICAL: restore_all_touched failed for %s: %s — "
                    "state may be corrupted; node should be restarted.",
                    addr[:16], exc)

    # ── Atomic flush ──────────────────────────────────────────────────────

    def flush(self):
        """Write all accumulated mutations in a SINGLE I/O operation.

        PG path:   one asyncpg transaction with executemany for each table.
        SQLite:    one commit at the end of all INSERT OR REPLACE statements.
        Redis:     pipeline all cache updates.
        """
        if not self._dirty_bal and not self._dirty_non and not self._dirty_vol:
            return

        bal_updates = {a: self._balances[a] for a in self._dirty_bal}
        non_updates = {a: self._nonces[a]   for a in self._dirty_non}
        vol_updates = {a: self._vol_deltas[a] for a in self._dirty_vol}

        self._real._flush_block_batch(bal_updates, non_updates, vol_updates)

        # Clear dirty flags (but keep cached values for compute_state_root)
        self._dirty_bal.clear()
        self._dirty_non.clear()
        self._dirty_vol.clear()
        self._vol_deltas.clear()
