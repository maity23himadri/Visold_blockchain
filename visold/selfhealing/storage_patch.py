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
"""visold.selfhealing.storage_patch


Defines: patch_storage
Origin: visold_vsd_.py L52873-52875, L52884-52914, L52917-52938, L52941-52953, L52956-52976, L53344-53346
"""

import json
from typing import List

from visold.kernel.logging_setup import log


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_time(ts: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# STORAGE EXTENSION STUBS
# These methods must be added to the Storage class (or monkey-patched in)
# if they don't already exist. They do NOT modify consensus logic.
# ─────────────────────────────────────────────────────────────────────────────

def _storage_get_vvm_receipts_for_block(self, height: int) -> List[dict]:
    """
    Fetch all VVM receipts for a given block height.
    Add to Storage class or patch in via SHBS._patch_storage().
    """
    try:
        c = self._conn()
        rows = c.execute(
            """SELECT tx_id, contract_addr, gas_used, gas_limit,
                      success, return_data, revert_reason, logs,
                      storage_delta
               FROM vvm_receipts WHERE block_idx=?""",
            (height,)
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["logs"] = json.loads(d.get("logs", "[]") or "[]")
            except Exception:
                d["logs"] = []
            try:
                d["storage_delta"] = json.loads(
                    d.get("storage_delta", "{}") or "{}")
            except Exception:
                d["storage_delta"] = {}
            result.append(d)
        return result
    except Exception as exc:
        log.debug(f"get_vvm_receipts_for_block({height}): {exc}")
        return []


def _storage_get_total_supply_sat(self) -> int:
    """
    Return total supply in satoshi by summing all non-zero balances.
    Expensive — only called every SAMPLE_INTERVAL blocks.

    AUDIT-FIX-16 (dead conservation check, wrong-table variant): previously
    hardcoded `self._conn().execute("... FROM accounts")` regardless of
    backend — "accounts" only exists in the PostgreSQL schema, so on
    SQLite this always raised (caught silently) and returned 0 every
    single call, meaning SupplyConservationMonitor.check()'s delta-based
    L1 anomaly detection compared 0 against 0 on every sample and could
    never fire on SQLite deployments. Delegate to
    Storage.sum_all_balances_satoshi() instead, which is properly
    backend-aware and already fixed for the same underlying bug, rather
    than maintaining a second, separately-broken implementation of the
    same computation.
    """
    try:
        return self.sum_all_balances_satoshi()
    except Exception as exc:
        log.debug(f"get_total_supply_sat: {exc}")
        return 0


def _storage_slash_validator(self, address: str) -> bool:
    """Mark a validator as slashed. Wraps existing storage layer."""
    try:
        c = self._conn()
        c.execute(
            "UPDATE validators SET slashed=1 WHERE address=?",
            (address,)
        )
        c.commit()
        return True
    except Exception as exc:
        log.error(f"slash_validator({address}): {exc}")
        return False


def patch_storage(storage_instance) -> None:
    """
    Monkey-patch storage methods needed by SHBS onto an existing Storage instance.
    Call this BEFORE creating SelfHealingSystem if these methods are not
    already present in the Storage class.
    """
    import types

    if not hasattr(storage_instance, "get_vvm_receipts_for_block"):
        storage_instance.get_vvm_receipts_for_block = types.MethodType(
            _storage_get_vvm_receipts_for_block, storage_instance)

    if not hasattr(storage_instance, "get_total_supply_sat"):
        storage_instance.get_total_supply_sat = types.MethodType(
            _storage_get_total_supply_sat, storage_instance)

    if not hasattr(storage_instance, "slash_validator"):
        storage_instance.slash_validator = types.MethodType(
            _storage_slash_validator, storage_instance)

    log.info("[SHBS] Storage extensions patched.")


# ─────────────────────────────────────────────────────────────────────────────

# Alias for use inside VisoldNode.__init__
def _patch_storage_for_shbs(storage_instance):
    """Alias for patch_storage — called from VisoldNode.__init__."""
    patch_storage(storage_instance)
