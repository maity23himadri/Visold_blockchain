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
"""visold.economics.monitor

Original section: SECTION 1F: ECONOMIC MONITOR  (Problem #15 — Economic Security)

Defines: EconomicMonitor
Origin: visold_vsd_.py L7993-8287
"""

import math
import threading
from collections import Counter, deque
from typing import Dict, Iterable, List, TYPE_CHECKING

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1F: ECONOMIC MONITOR  (Problem #15 — Economic Security)
# ─────────────────────────────────────────────────────────────────────────────
class EconomicMonitor:
    """Monitor measured reward allocations without inferring attacks from streaks.

    A streak of public blocks does not, by itself, prove selfish mining.  This
    monitor only raises a reward-concentration signal when the recent canonical
    producer window contains repeated production by at least two addresses.
    Such a signal is a risk indicator, not proof of malicious behavior.
    """

    WINDOW = 100
    COMPETITION_WINDOW = 10
    COMPETITION_RECENCY_WINDOW = 6
    MIN_COMPETING_BLOCKS = 2

    CONCENTRATION_WARNING_FRAC = 0.40
    CONCENTRATION_CRITICAL_FRAC = 0.60
    REWARD_VS_STAKE_RATIO_MAX = 2.5
    FEE_SPIKE_MULTIPLIER = 10.0

    # Kept as compatibility constants for callers and dashboards. A consecutive
    # public-block streak is deliberately not treated as a selfish-mining alert.
    SELFISH_MINING_NOTICE = 3
    SELFISH_MINING_WARNING = 6
    SELFISH_MINING_CRITICAL = 10
    UNIQUE_MINERS_WINDOW = COMPETITION_WINDOW

    def __init__(self, storage: 'Storage'):
        self.storage = storage
        # One entry per block: (producer address, actual payouts in satoshi).
        # None means old canonical history whose historical role/payout state is
        # not safely reconstructable from the current role table.
        self._reward_log: deque = deque(maxlen=self.WINDOW)
        self._fee_log: deque = deque(maxlen=10)
        self._miner_sequence: deque = deque(maxlen=self.WINDOW)
        self._lock = threading.RLock()
        self._alert_latches = set()

    def record_block_rewards(self, producer_address: str, allocations: Dict[str, int]):
        """Record one canonical block and actual credited reward allocations."""
        producer = str(producer_address or "").strip()
        normalized: Dict[str, int] = {}
        for address, amount in (allocations or {}).items():
            addr = str(address or "").strip()
            try:
                value = int(amount)
            except (TypeError, ValueError, OverflowError):
                continue
            if addr and value > 0:
                normalized[addr] = normalized.get(addr, 0) + value
        with self._lock:
            self._reward_log.append((producer, normalized))
            self._miner_sequence.append(producer)
        self._check_concentration()

    def record_reward(self, address: str, amount: float):
        """Backward-compatible adapter for legacy single-recipient callers.

        New chain code must use record_block_rewards() so the monitor receives
        all actual allocations rather than assuming the proposer receives all.
        """
        try:
            amount_sat = int(round(float(amount) * 100_000_000))
        except (TypeError, ValueError, OverflowError):
            amount_sat = 0
        payouts = {str(address): amount_sat} if address and amount_sat > 0 else {}
        self.record_block_rewards(address, payouts)

    def replace_canonical_history(self, producers: Iterable[str]):
        """Rebase transient history after rollback/reorg to stored canonical blocks.

        Historical payouts are not fabricated using today's role table.  The
        producer addresses are restored, payout history is marked unknown, and
        fee samples are cleared because they may include an orphaned branch.
        """
        clean = [str(address or "").strip() for address in producers]
        clean = [address for address in clean if address]
        with self._lock:
            self._reward_log.clear()
            self._miner_sequence.clear()
            for address in clean[-self.WINDOW:]:
                self._reward_log.append((address, None))
                self._miner_sequence.append(address)
            self._fee_log.clear()
            self._alert_latches.clear()

    def record_block_fees(self, total_fees: float):
        try:
            fees = float(total_fees)
            if not math.isfinite(fees) or fees < 0:
                return
        except (TypeError, ValueError, OverflowError):
            return
        with self._lock:
            self._fee_log.append(fees)
        self._check_fee_spike()

    def record_validator_sigs(self, sig_addresses: List[str]):
        if len(sig_addresses) < 3:
            return
        self._check_collusion(sig_addresses)
        self._check_validator_reward_manipulation(sig_addresses)

    def _activate_latches(self, group: str, active_keys: set):
        """Keep latches for current conditions and return newly active ones."""
        with self._lock:
            previous = {
                key for key in self._alert_latches
                if isinstance(key, tuple) and key and key[0] == group
            }
            new_keys = active_keys - previous
            self._alert_latches = {
                key for key in self._alert_latches
                if not (isinstance(key, tuple) and key and key[0] == group)
            } | active_keys
            return new_keys

    def _check_concentration(self):
        """Check real payouts, gated by repeated evidence from multiple producers."""
        with self._lock:
            recent = list(self._reward_log)[-self.COMPETITION_WINDOW:]

        # Evidence of competition must be interleaved near the tip, not merely
        # somewhere in the ten-block payout window. This prevents one or two old
        # producer entries from making a later solo streak look suspicious.
        recent_producers = recent[-self.COMPETITION_RECENCY_WINDOW:]
        producer_counts = Counter(address for address, _ in recent_producers if address)
        competing_producers = sum(
            1 for count in producer_counts.values()
            if count >= self.MIN_COMPETING_BLOCKS
        ) >= 2
        active_keys = set()
        candidates = []
        if not Config.SOLO_MINING_MODE and competing_producers:
            candidates = [
                allocations for _, allocations in recent
                if isinstance(allocations, dict) and allocations
            ]

        # Do not infer a reward share until enough trustworthy post-rebase payout
        # records exist. The threshold avoids alerts from one or two samples.
        if (len(recent) >= self.COMPETITION_WINDOW
                and len(candidates) >= self.COMPETITION_WINDOW):
            paid: Counter = Counter()
            for allocations in candidates:
                paid.update(allocations)
            total = sum(paid.values())
            if total > 0 and paid:
                top_address, top_amount = paid.most_common(1)[0]
                share = top_amount / total
                if share > self.CONCENTRATION_CRITICAL_FRAC:
                    active_keys.add(("concentration", top_address, "critical"))
                elif share > self.CONCENTRATION_WARNING_FRAC:
                    active_keys.add(("concentration", top_address, "warning"))

        newly_active = self._activate_latches("concentration", active_keys)
        for key in sorted(newly_active, key=str):
            _, address, severity = key
            with self._lock:
                recent = list(self._reward_log)[-self.COMPETITION_WINDOW:]
            payout_rows = [
                allocations for _, allocations in recent
                if isinstance(allocations, dict) and allocations
            ]
            paid = Counter()
            for allocations in payout_rows:
                paid.update(allocations)
            total = sum(paid.values())
            share = paid.get(address, 0) / total if total else 0.0
            if severity == "critical":
                log.warning(
                    f"ECONOMIC ALERT: Actual reward concentration — {address[:16]}... "
                    f"received {share*100:.1f}% of measured payouts in a recent "
                    "window with repeated production by multiple miners. This is a "
                    "risk indicator, not proof of selfish mining.")
                metrics.inc("economic_concentration_critical")
            else:
                log.warning(
                    f"ECONOMIC NOTICE: Actual reward concentration — {address[:16]}... "
                    f"received {share*100:.1f}% of measured payouts in a recent "
                    "window with repeated production by multiple miners. This metric "
                    "alone does not establish an attack.")
            metrics.inc("economic_concentration_alerts")

    def _check_selfish_mining(self):
        """Compatibility hook: public consecutive-block streaks are not attack proof."""
        return

    def _check_fee_spike(self):
        with self._lock:
            fees = list(self._fee_log)
        active_keys = set()
        if len(fees) >= 10:
            avg_old = sum(fees[:5]) / 5
            avg_new = sum(fees[5:10]) / 5
            baseline = avg_old if avg_old > 0 else 0.0001
            if avg_new > baseline * self.FEE_SPIKE_MULTIPLIER:
                active_keys.add(("fee_spike",))
        newly_active = self._activate_latches("fee_spike", active_keys)
        if newly_active:
            avg_old = sum(fees[:5]) / 5
            avg_new = sum(fees[5:10]) / 5
            baseline = avg_old if avg_old > 0 else 0.0001
            log.warning(
                f"ECONOMIC ALERT: Fee spike — avg fee jumped from "
                f"{avg_old:.4f} to {avg_new:.4f} VSD "
                f"({avg_new/baseline:.1f}× increase, "
                f"threshold={self.FEE_SPIKE_MULTIPLIER:.0f}×). "
                "Possible fee-market stress; verify before attributing intent.")
            metrics.inc("economic_fee_spike_alerts")

    def _check_collusion(self, sig_addresses: List[str]):
        if not sig_addresses:
            return
        counts = Counter(sig_addresses)
        total_sigs = len(sig_addresses)
        unique = len(counts)
        if unique == 0:
            return
        top_n = max(1, unique // 5)
        top_n_count = sum(count for _, count in counts.most_common(top_n))
        share = top_n_count / total_sigs
        active_keys = set()
        if share > Config.COLLUSION_SIG_OVERLAP:
            key_addresses = tuple(sorted(address for address, _ in counts.most_common(top_n)))
            active_keys.add(("collusion", key_addresses))
        for _key in self._activate_latches("collusion", active_keys):
            log.warning(
                f"ECONOMIC ALERT: Validator-signature concentration — "
                f"{share*100:.0f}% of signatures came from the top {top_n} "
                "validator(s). Concentration warrants review but does not alone "
                "prove collusion.")
            metrics.inc("economic_collusion_alerts")

    def _check_validator_reward_manipulation(self, sig_addresses: List[str]):
        """Compare actual recorded payouts with stake shares, not proposer subsidy."""
        if not sig_addresses or self.storage is None:
            return
        with self._lock:
            reward_copy = list(self._reward_log)
        valid = [
            allocations for _, allocations in reward_copy
            if isinstance(allocations, dict) and allocations
        ]
        if len(valid) < 10:
            self._activate_latches("validator_reward", set())
            return

        reward_counts: Counter = Counter()
        for allocations in valid:
            reward_counts.update(allocations)
        total_reward = sum(reward_counts.values())
        if total_reward <= 0:
            self._activate_latches("validator_reward", set())
            return

        active_keys = set()
        details = {}
        try:
            validators = self.storage.get_all_by_role("investor")
            if validators:
                total_stake = sum(
                    max(float(item.get("stake", 0)), 0.0) for item in validators
                )
                if total_stake > 0:
                    for validator in validators:
                        address = str(validator.get("address") or "")
                        stake = max(float(validator.get("stake", 0)), 0.0)
                        stake_share = stake / total_stake
                        reward_share = reward_counts.get(address, 0) / total_reward
                        if (stake_share > 0 and
                                reward_share > stake_share * self.REWARD_VS_STAKE_RATIO_MAX):
                            key = ("validator_reward", address)
                            active_keys.add(key)
                            details[key] = (reward_share, stake_share)
        except Exception as exc:
            log.debug("Economic reward/stake check unavailable: %s", exc)
            return

        for key in self._activate_latches("validator_reward", active_keys):
            address = key[1]
            reward_share, stake_share = details[key]
            log.warning(
                f"ECONOMIC ALERT: Reward/stake share divergence — {address[:16]}... "
                f"received {reward_share*100:.1f}% of measured payouts with "
                f"{stake_share*100:.1f}% of stake "
                f"(ratio={reward_share/stake_share:.1f}×). Review role eligibility "
                "and payout records.")
            metrics.inc("economic_reward_manipulation_alerts")
