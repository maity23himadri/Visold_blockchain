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

from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
import math
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
    """Convert a VSD int, float, Decimal, or numeric string to integer satoshi (round half-even)."""
    if isinstance(vsd_amount, bool):
        raise TypeError("vsd_amount must not be bool")
    if isinstance(vsd_amount, Decimal):
        dec = vsd_amount
    elif isinstance(vsd_amount, int):
        dec = Decimal(vsd_amount)
    elif isinstance(vsd_amount, float):
        if not math.isfinite(vsd_amount):
            raise ValueError(f"vsd_amount must be finite, got {vsd_amount!r}")
        dec = Decimal(str(vsd_amount))
    elif isinstance(vsd_amount, str):
        raw = vsd_amount.strip()
        if not raw:
            raise ValueError("vsd_amount string must not be empty")
        try:
            dec = Decimal(raw)
        except InvalidOperation as exc:
            raise ValueError(f"invalid vsd_amount string: {vsd_amount!r}") from exc
    else:
        raise TypeError(
            f"vsd_amount must be int, float, Decimal, or str, got {type(vsd_amount).__name__}"
        )

    if not dec.is_finite():
        raise ValueError(f"vsd_amount must be finite, got {vsd_amount!r}")

    scaled = dec * Decimal(Config.SATOSHI_PER_VSD)
    return int(scaled.to_integral_value(rounding=ROUND_HALF_EVEN))


def from_satoshi(satoshi: int) -> float:
    """Convert integer satoshi to a human-readable VSD float for display only.

    Note: IEEE-754 float64 loses 1-satoshi precision at >= 2^53 satoshi.
    Use from_satoshi_decimal() or from_satoshi_str() for lossless round-tripping.
    """
    if isinstance(satoshi, bool) or not isinstance(satoshi, int):
        raise TypeError(f"satoshi must be an int, got {type(satoshi).__name__}")
    return satoshi / Config.SATOSHI_PER_VSD


def from_satoshi_decimal(satoshi: int) -> Decimal:
    """Losslessly convert integer satoshi to an exact Decimal VSD amount."""
    if isinstance(satoshi, bool) or not isinstance(satoshi, int):
        raise TypeError(f"satoshi must be an int, got {type(satoshi).__name__}")
    return Decimal(satoshi) / Decimal(Config.SATOSHI_PER_VSD)


def from_satoshi_str(satoshi: int) -> str:
    """Losslessly format integer satoshi as an exact 8-decimal VSD string."""
    return f"{from_satoshi_decimal(satoshi):.8f}"


def gas_fee_to_sat(gas_units: int, gas_price) -> int:
    """Deterministic gas fee in satoshi: gas_units × to_satoshi(gas_price).

    Validates that gas_units is a non-negative int (not bool) and gas_price
    converts to a non-negative integer satoshi-per-gas value. Positive
    gas_price values below 0.5 sat/gas (<= 5e-9 VSD/gas) are clamped up to
    1 sat/gas so a positive gas price with positive gas_units never silently
    truncates to zero fee.
    """
    if isinstance(gas_units, bool) or not isinstance(gas_units, int):
        raise TypeError(f"gas_units must be an int, got {type(gas_units).__name__}")
    if gas_units < 0:
        raise ValueError(f"gas_units must be non-negative, got {gas_units}")
    if isinstance(gas_price, bool):
        raise TypeError("gas_price must not be bool")

    if isinstance(gas_price, Decimal):
        dec_price = gas_price
    elif isinstance(gas_price, int):
        dec_price = Decimal(gas_price)
    elif isinstance(gas_price, float):
        if not math.isfinite(gas_price):
            raise ValueError(f"gas_price must be finite, got {gas_price!r}")
        dec_price = Decimal(str(gas_price))
    elif isinstance(gas_price, str):
        raw = gas_price.strip()
        if not raw:
            raise ValueError("gas_price string must not be empty")
        try:
            dec_price = Decimal(raw)
        except InvalidOperation as exc:
            raise ValueError(f"invalid gas_price string: {gas_price!r}") from exc
    else:
        raise TypeError(
            f"gas_price must be int, float, Decimal, or str, got {type(gas_price).__name__}"
        )

    if not dec_price.is_finite():
        raise ValueError(f"gas_price must be finite, got {gas_price!r}")
    if dec_price < 0:
        raise ValueError(f"gas_price must be non-negative, got {gas_price!r}")
    if gas_units == 0 or dec_price == 0:
        return 0

    price_sat_per_gas = to_satoshi(dec_price)
    if price_sat_per_gas <= 0:
        price_sat_per_gas = 1
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
