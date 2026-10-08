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
"""visold.kernel.units


Defines: to_satoshi, from_satoshi, gas_fee_to_sat, bft_threshold_met, conservation_check
Origin: visold_vsd_.py L4900, L4907-4973
"""

from typing import TYPE_CHECKING

from visold.kernel.config import Config

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# Special broadcast address for open market orders (no specific recipient)
VSD_GLOBAL_MARKET = "VSD_GLOBAL_MARKET"


# ─────────────────────────────────────────────────────────────────────────────
# F-01 FIX: SATOSHI CONVERSION HELPERS
# All internal financial arithmetic uses integer satoshi units.
# These helpers convert at the human-readable boundary (CLI / RPC display).
# ─────────────────────────────────────────────────────────────────────────────
def to_satoshi(vsd_amount) -> int:
    """Convert a VSD float or string to integer satoshi units (round half-even)."""
    return int(round(float(vsd_amount) * Config.SATOSHI_PER_VSD))


def from_satoshi(satoshi: int) -> float:
    """Convert integer satoshi to a human-readable VSD float for display only."""
    return satoshi / Config.SATOSHI_PER_VSD


def gas_fee_to_sat(gas_units: int, gas_price: float) -> int:
    """Deterministic gas fee in satoshi: gas_units × gas_price × SATOSHI_PER_VSD.

    F-01 COMPLETION: Computing gas_fee as round(gas * price, 8) in float, then
    converting to satoshi, introduces two rounding steps that can diverge across
    platforms.  Instead, convert gas_price to satoshi-per-gas *first* (a single
    float→int conversion), then multiply in pure integer arithmetic.

    gas_price is VSD-per-gas (e.g. 0.00000001 = 1 sat/gas).
    Result: gas_units × round(gas_price × SATOSHI_PER_VSD) — one rounding, rest int.
    """
    price_sat_per_gas = int(round(gas_price * Config.SATOSHI_PER_VSD))
    return gas_units * price_sat_per_gas


def bft_threshold_met(approved_stake: int, total_stake: int) -> bool:
    """
    Integer BFT threshold check — avoids float comparison.
    Returns True iff approved_stake / total_stake >= 666700/1000000 (≈66.67%).
    Uses cross-multiplication to stay in integer arithmetic:
        approved * 1_000_000 >= BFT_THRESHOLD_MILLIONTHS * total
    """
    if total_stake <= 0:
        return False
    return approved_stake * 1_000_000 >= Config.BFT_THRESHOLD_MILLIONTHS * total_stake


def conservation_check(storage: 'Storage') -> bool:
    """
    Verify that sum(all_balances) == cumulative_issuance.
    Raises ValueError on violation; returns True on pass.
    All values are in satoshi (integers).

    AUDIT-FIX-16 (dead conservation check): this previously computed
    `total_balances + total_burned != total_issued` — but this chain
    tracks burns by crediting Config.BURN_ADDRESS rather than destroying
    funds, so BURN_ADDRESS's balance is already included within
    total_balances (sum_all_balances_satoshi sums every address's
    balance, burn address included). Adding total_burned again double-
    counted it. On top of that, all three underlying storage methods
    previously queried tables (`accounts` on SQLite, `burns`, `issuance`)
    that were never created on either backend, silently returning 0 for
    all three inputs via their own exception handlers — making this
    check pass vacuously (0+0==0) on every deployment regardless of the
    real state of the ledger, even before considering the double-count.
    Both problems are fixed now: total_balances is correctly computed
    (Storage.sum_all_balances_satoshi, backend-consistent), and
    total_issued is a real, incrementally-tracked counter
    (Storage.get_cumulative_issued_sat, updated once per block from
    Blockchain._distribute_rewards at the point new supply is actually
    created) — so this comparison is no longer trivially true by
    construction.
    """
    total_balances = storage.sum_all_balances_satoshi()
    total_issued   = storage.get_total_issued_satoshi()
    if total_balances != total_issued:
        raise ValueError(
            f"CONSERVATION VIOLATION: balances={total_balances} "
            f"!= issued={total_issued} "
            f"(diff={total_balances - total_issued} satoshi)")
    return True
