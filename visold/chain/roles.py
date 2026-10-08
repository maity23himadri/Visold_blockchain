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
"""visold.chain.roles

Original section: SECTION 9: ROLES (MINER / INVESTOR / HIGH TRANSACTOR)

Defines: RoleManager
Origin: visold_vsd_.py L30475-30663
"""

from typing import Any, Optional, TYPE_CHECKING, Tuple

from visold.kernel.config import Config
from visold.kernel.events import Event, EventType
from visold.kernel.units import from_satoshi, to_satoshi
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.chain.blockchain import Blockchain
    from visold.wallet.wallet import Wallet


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9: ROLES (MINER / INVESTOR / HIGH TRANSACTOR)
# ─────────────────────────────────────────────────────────────────────────────
class RoleManager:
    def __init__(self, storage: Storage, wallet: 'Wallet',
                 blockchain: Optional['Blockchain'] = None,
                 state_engine: Optional[Any] = None):
        self.storage      = storage
        self.wallet       = wallet
        self.blockchain   = blockchain
        self.state_engine = state_engine

    def _submit_register_tx(self, role: str, stake_vsd: float) -> Tuple[bool, str]:
        """
        Build, sign, and submit an on-chain REGISTER transaction for the
        wallet's address.  The role change only takes effect once the tx
        is mined into a block (at block height N+1 relative to mining).

        v7.2.0: this is the ONLY consensus-safe way to change roles.
        Direct storage mutation has been removed entirely — see the
        v7.1.10 hotfix series for the full failure analysis.
        """
        if self.blockchain is None or self.state_engine is None:
            return False, ("RoleManager not wired to blockchain/state_engine — "
                           "node still initializing, try again in a moment.")

        sender = self.wallet.address
        # REGISTER txs carry the stake in ``amount`` and the role in ``memo``.
        # A very small fee is required (same rate as transfers) to deter
        # spam; fee is debited at apply time.
        fee = (round(float(stake_vsd) * Config.TX_FEE_RATE, 8)
               if stake_vsd > 0 else
               float(getattr(Config, "MIN_TX_FEE_SAT", 1000)) / 100_000_000)
        # Auto-derive nonce the same way send_transaction does.
        try:
            chain_nonce = self.storage.get_nonce(sender)
            pending_count = len(
                self.blockchain.mempool._pending_nonces.get(sender, set()))
            nonce = chain_nonce + pending_count
        except Exception:
            nonce = 0

        tx = Transaction(
            sender   = sender,
            receiver = "",
            amount   = float(stake_vsd),
            fee      = fee,
            memo     = role,
            nonce    = nonce,
            tx_type  = Transaction.TYPE_REGISTER,
        )
        tx.sign(self.wallet)

        evt = Event(EventType.NEW_TX, {"tx": tx.to_dict()})
        return self.state_engine.post_sync(evt)

    def register_miner(self, stake: float) -> Tuple[bool, str]:
        """
        Broadcast a REGISTER(role=miner) transaction.  The role change
        takes effect at the NEXT block after this tx is mined — i.e. if
        the tx lands in block N, the address becomes a miner starting
        at block N+1's reward distribution.

        v7.2.0: on-chain REGISTER tx.  See Transaction.TYPE_REGISTER.
        """
        addr = self.wallet.address
        stake_sat = to_satoshi(stake)
        if stake_sat <= 0:
            return False, "Stake must be positive."
        # BUG-FIX: MIN_MINER_STAKE was previously only displayed, never
        # enforced.  Honest users could register with sub-minimum stake
        # then wonder why they receive no rewards / inconsistent treatment.
        # Enforce parity with register_investor here, but ONLY on initial
        # registration — top-ups (additive stake on an existing miner role)
        # may be any positive amount.
        _existing_for_min_check = self.storage.get_role(addr)
        _is_initial = not (_existing_for_min_check
                           and _existing_for_min_check.get("role") == "miner")
        if _is_initial and stake_sat < Config.MIN_MINER_STAKE:
            return False, (f"Minimum miner stake: "
                           f"{from_satoshi(Config.MIN_MINER_STAKE):.8f} VSD")

        # Spendable-balance preflight so the user gets a clear error
        # before broadcasting a tx that would be rejected at apply time.
        existing = self.storage.get_role(addr)
        current_stake_sat = 0
        if existing and existing.get("role") == "miner":
            current_stake_sat = to_satoshi(float(existing.get("stake", 0.0)))
        balance_sat = self.storage.get_balance_sat(addr)
        # v7.2.x FIX: also subtract any REGISTER stake already pending in the
        # mempool from this address, plus all pending fees from this address.
        # Without this, a user could submit the same stake twice back-to-back
        # because the first tx hasn't been mined yet and the preflight still
        # sees the full balance as free.
        pending_reg_sat, _pending_xfer_sat, pending_fee_sat = \
            self.blockchain.mempool.pending_outflow_sat(addr)
        spendable_sat = (balance_sat - current_stake_sat
                         - pending_reg_sat - pending_fee_sat)
        if spendable_sat < stake_sat:
            if pending_reg_sat > 0:
                return False, (
                    f"Insufficient spendable balance: "
                    f"have {from_satoshi(max(0, spendable_sat)):.8f} VSD free, "
                    f"need {from_satoshi(stake_sat):.8f} VSD "
                    f"(you already have "
                    f"{from_satoshi(pending_reg_sat):.8f} VSD pending "
                    f"in a REGISTER tx — wait for it to be mined).")
            return False, (
                f"Insufficient spendable balance: "
                f"have {from_satoshi(max(0, spendable_sat)):.8f} VSD free, "
                f"need {from_satoshi(stake_sat):.8f} VSD.")
        if existing and existing.get("role") == "investor":
            return False, "Already registered as investor — unstake first."

        ok, msg = self._submit_register_tx("miner", stake)
        if not ok:
            return False, f"REGISTER tx rejected: {msg}"
        return True, (
            f"REGISTER(miner, {stake:.8f} VSD) submitted. "
            f"Role will activate in the block AFTER this tx is mined "
            f"(i.e. at block N+1 if mined at height N).")

    def register_investor(self, stake: float) -> Tuple[bool, str]:
        """
        Broadcast a REGISTER(role=investor) transaction.  Same N+1
        activation semantics as register_miner.
        """
        addr = self.wallet.address
        stake_sat = to_satoshi(stake)
        if stake_sat <= 0:
            return False, "Stake must be positive."
        # BUG-FIX: only enforce minimum on INITIAL registration.  Top-ups
        # (additive stake on an existing investor role) may be any
        # positive amount, mirroring register_miner's behaviour.
        _existing_for_min_check = self.storage.get_role(addr)
        _is_initial = not (_existing_for_min_check
                           and _existing_for_min_check.get("role") == "investor")
        if _is_initial and stake_sat < Config.MIN_INVESTOR_STAKE:
            return False, (f"Minimum investor stake: "
                           f"{from_satoshi(Config.MIN_INVESTOR_STAKE):.8f} VSD")

        existing = self.storage.get_role(addr)
        if existing and existing.get("role") == "miner":
            return False, "Miners cannot be investors — unstake first."
        current_stake_sat = 0
        if existing and existing.get("role") == "investor":
            current_stake_sat = to_satoshi(float(existing.get("stake", 0.0)))
        balance_sat = self.storage.get_balance_sat(addr)
        # v7.2.x FIX: see register_miner — subtract pending mempool stake
        # and pending fees so a second stake can't race past the preflight
        # while the first one is still in the pool.
        pending_reg_sat, _pending_xfer_sat, pending_fee_sat = \
            self.blockchain.mempool.pending_outflow_sat(addr)
        spendable_sat = (balance_sat - current_stake_sat
                         - pending_reg_sat - pending_fee_sat)
        if spendable_sat < stake_sat:
            if pending_reg_sat > 0:
                return False, (
                    f"Insufficient spendable balance: "
                    f"have {from_satoshi(max(0, spendable_sat)):.8f} VSD free, "
                    f"need {from_satoshi(stake_sat):.8f} VSD "
                    f"(you already have "
                    f"{from_satoshi(pending_reg_sat):.8f} VSD pending "
                    f"in a REGISTER tx — wait for it to be mined).")
            return False, (
                f"Insufficient spendable balance: "
                f"have {from_satoshi(max(0, spendable_sat)):.8f} VSD free, "
                f"need {from_satoshi(stake_sat):.8f} VSD.")

        ok, msg = self._submit_register_tx("investor", stake)
        if not ok:
            return False, f"REGISTER tx rejected: {msg}"
        return True, (
            f"REGISTER(investor, {stake:.8f} VSD) submitted. "
            f"Role will activate at block N+1.")

    def get_my_role(self) -> Optional[dict]:
        return self.storage.get_role(self.wallet.address)

    def unstake(self) -> Tuple[bool, str]:
        """
        Broadcast a REGISTER(role=none) transaction to clear the role
        on-chain.  Effective at block N+1.
        """
        addr = self.wallet.address
        role = self.storage.get_role(addr)
        if not role or role.get("role") in (None, "", "none"):
            return False, "No active role to unstake."
        ok, msg = self._submit_register_tx("none", 0.0)
        if not ok:
            return False, f"UNREGISTER tx rejected: {msg}"
        return True, "UNREGISTER submitted. Role will clear at block N+1."
