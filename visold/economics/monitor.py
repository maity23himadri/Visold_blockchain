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

import threading
from collections import Counter, deque
from typing import List, TYPE_CHECKING

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1F: ECONOMIC MONITOR  (Problem #15 — Economic Security)
# ─────────────────────────────────────────────────────────────────────────────
class EconomicMonitor:
    """
    Watches reward distribution and validator behaviour for collusion / farming.

    Fix #11 — Economic Attack Surface Definition:
    The monitor now has formal, documented attack boundary definitions for each
    detection class.  Each boundary is expressed as a quantitative threshold
    with a documented rationale so that alerts map to specific attack types:

    Attack class 1 — Reward Concentration / Selfish Mining
    ────────────────────────────────────────────────────────
    Threshold: single address > REWARD_CONCENTRATION_ALERT (default 40%) of
    last WINDOW block rewards.
    Attack model: a miner or pool controls >40% of hashrate and pools rewards,
    approaching the 51% threshold needed for selfish mining.  >40% is the
    practical attack boundary because at that concentration the attacker can
    occasionally win two consecutive blocks before honest miners, letting them
    orphan competitor blocks for profit.
    Severity: WARNING at 40%, CRITICAL at 60%.

    Attack class 2 — Validator Collusion / Cartel
    ───────────────────────────────────────────────
    Threshold: top-20% of validators produce > COLLUSION_SIG_OVERLAP (80%) of
    all BFT signatures.
    Attack model: a cartel of validators controlling >2/3 stake can censor
    transactions, manipulate finality timing, and (if also controlling PoW)
    orchestrate double-spend via selective finality.  80% signature dominance
    indicates the cartel is already at or near the 2/3 BFT threshold.
    Severity: WARNING at 80%.

    Attack class 3 — Fee Market Manipulation
    ──────────────────────────────────────────
    Threshold: 10× fee spike within 10 consecutive blocks.
    Attack model: an attacker floods the mempool with high-fee transactions
    to crowd out legitimate txs (grief attack) or to extract MEV by controlling
    which transactions are included.
    Severity: WARNING at 10×.

    Attack class 4 — Selfish Mining Detection (new, Fix #11)
    ──────────────────────────────────────────────────────────
    Threshold: a single miner mines more than SELFISH_MINING_CONSECUTIVE_BLOCKS
    consecutive blocks.
    Attack model: running more than N consecutive blocks indicates the miner
    may be withholding blocks (selfish mining strategy) — mining a private
    chain and releasing it when it overtakes the honest chain.
    Severity: WARNING when consecutive_blocks >= SELFISH_MINING_CONSECUTIVE_BLOCKS.

    Attack class 5 — Validator Reward Manipulation (new, Fix #11)
    ──────────────────────────────────────────────────────────────
    Threshold: a validator participates in finalization of blocks that
    disproportionately reward them.  Detected when a validator's reward share
    across the last WINDOW blocks exceeds their staking share by
    REWARD_VS_STAKE_RATIO_THRESHOLD.
    Severity: WARNING.
    """
    WINDOW = 100  # blocks

    # ── Formal attack boundary definitions (Fix #11) ─────────────────────────
    # All thresholds are formal protocol-level constants, not ad-hoc magic numbers.
    CONCENTRATION_WARNING_FRAC    = 0.40   # >40% reward share → warning
    CONCENTRATION_CRITICAL_FRAC   = 0.60   # >60% reward share → critical
    REWARD_VS_STAKE_RATIO_MAX     = 2.5    # validator reward > 2.5× stake share → warning
    FEE_SPIKE_MULTIPLIER          = 10.0   # fee spike threshold

    # ── Tiered Selfish Mining Detection (v5.6.0) ──────────────────────────────
    # Three-level severity ladder replaces the single hard threshold.
    # Rationale:
    #   3 blocks  — high variance; on a new low-difficulty chain this can happen
    #               by chance.  Log only as NOTICE so operators see it without
    #               alarm fatigue.
    #   6 blocks  — statistically unlikely (<1.6% chance at 50/50 hashrate split);
    #               meaningful WARNING.  Bitcoin uses 6-block confirmation depth
    #               precisely because the probability of accidental 6-streaks is
    #               negligible on a mature network.
    #   10 blocks — near-impossible at any honest hashrate split; CRITICAL.
    #               Indicates either >90% hashrate monopoly or active private
    #               chain withholding.
    SELFISH_MINING_NOTICE    =  3   # ≥3 consecutive → NOTICE  (high variance)
    SELFISH_MINING_WARNING   =  6   # ≥6 consecutive → WARNING (likely attack)
    SELFISH_MINING_CRITICAL  = 10   # ≥10 consecutive → CRITICAL (network at risk)

    # ── Bootstrap guard refinement (v5.6.0) ──────────────────────────────────
    # The old guard checked unique_miners in the short _miner_sequence deque
    # (maxlen=20).  Problem: a non-mining watcher peer increments peer_count
    # to ≥2 but contributes zero mining addresses, so 100% of blocks still come
    # from one miner — not an attack but still triggered the alert.
    # Fix: guard checks unique miners in the last UNIQUE_MINERS_WINDOW=100 blocks
    # of the reward log (same deque used for concentration checks).  Alerts only
    # fire when ≥2 distinct addresses have actually mined in that window.
    UNIQUE_MINERS_WINDOW = 100  # look at last N reward-log entries for guard

    def __init__(self, storage: 'Storage'):
        self.storage = storage
        self._reward_log: deque = deque(maxlen=self.WINDOW)  # (address, amount)
        self._fee_log:    deque = deque(maxlen=10)           # block total fees
        self._miner_sequence: deque = deque(maxlen=100)      # recent miner addresses (100-block window for guard)
        self._lock               = threading.Lock()

    def record_reward(self, address: str, amount: float):
        with self._lock:
            self._reward_log.append((address, amount))
            self._miner_sequence.append(address)
        self._check_concentration()
        self._check_selfish_mining()

    def record_block_fees(self, total_fees: float):
        with self._lock:
            self._fee_log.append(total_fees)
        self._check_fee_spike()

    def record_validator_sigs(self, sig_addresses: List[str]):
        if len(sig_addresses) < 3:
            return
        self._check_collusion(sig_addresses)
        self._check_validator_reward_manipulation(sig_addresses)

    def _check_concentration(self):
        with self._lock:
            log_copy = list(self._reward_log)
        if len(log_copy) < 10:
            return

        # ── Solo mode fast-exit ───────────────────────────────────────────────
        if Config.SOLO_MINING_MODE:
            return  # operator has explicitly declared solo intent — no alerts

        # ── Refined bootstrap guard (v5.6.0) ─────────────────────────────────
        # Original guard: unique_miners in short sequence < 2.
        # Problem: a non-mining watcher peer does not add its address to the
        # reward log, so "peer joined" does not equal "competition exists".
        # Fix: count unique mining addresses in the last UNIQUE_MINERS_WINDOW
        # entries of the reward log.  Alerts only fire when ≥2 distinct
        # addresses have actually mined recent blocks — not just connected.
        unique_miners = len(set(addr for addr, _ in log_copy))
        if unique_miners < 2:
            return   # solo / bootstrap — not an attack, skip alert

        total = sum(a for _, a in log_copy) or 1.0
        counts = Counter()
        for addr, amt in log_copy:
            counts[addr] += amt
        top_addr, top_amt = counts.most_common(1)[0]
        frac = top_amt / total
        if frac > self.CONCENTRATION_CRITICAL_FRAC:
            log.critical(
                f"ECONOMIC CRITICAL: Reward concentration — {top_addr[:16]}... "
                f"received {frac*100:.1f}% of last {len(log_copy)} block rewards. "
                f"Exceeds critical threshold ({self.CONCENTRATION_CRITICAL_FRAC*100:.0f}%). "
                f"Possible majority hashrate control / selfish mining.")
            metrics.inc("economic_concentration_critical")
            metrics.inc("economic_concentration_alerts")
        elif frac > self.CONCENTRATION_WARNING_FRAC:
            log.warning(
                f"ECONOMIC ALERT: Reward concentration — {top_addr[:16]}... "
                f"received {frac*100:.1f}% of last {len(log_copy)} block rewards. "
                f"Approaching selfish-mining attack boundary "
                f"({self.CONCENTRATION_WARNING_FRAC*100:.0f}% threshold).")
            metrics.inc("economic_concentration_alerts")

    def _check_selfish_mining(self):
        """
        v5.6.0 — Tiered selfish mining detection with refined bootstrap guard.

        Three-level severity ladder:
          NOTICE   (≥3 consecutive) — high variance; informational only.
          WARNING  (≥6 consecutive) — statistically unlikely at honest hashrates.
          CRITICAL (≥10 consecutive) — near-impossible without hashrate monopoly
                                        or active block withholding.

        Bootstrap guard: refined from "unique_miners in short sequence < 2" to
        "unique_miners in 100-block reward log < 2".  This correctly handles the
        case where a non-mining watcher peer joins (peer_count ≥ 2 but still only
        one miner) — the old guard would have wrongly fired in that scenario.

        Solo mode: if Config.SOLO_MINING_MODE is True, all alerts are suppressed
        unconditionally regardless of miner diversity.
        """
        with self._lock:
            seq = list(self._miner_sequence)
        if len(seq) < self.SELFISH_MINING_NOTICE:
            return

        # ── Solo mode fast-exit ───────────────────────────────────────────────
        if Config.SOLO_MINING_MODE:
            return

        # ── Refined bootstrap guard (v5.6.0) ─────────────────────────────────
        # Use the full 100-block miner sequence (not short 20-block window) so
        # that a non-mining watcher peer does not trigger the guard incorrectly.
        unique_miners = len(set(seq))
        if unique_miners < 2:
            return   # solo / bootstrap — no competition to analyze

        # Count trailing consecutive blocks by the same miner
        last_miner  = seq[-1]
        consecutive = 1
        for miner in reversed(seq[:-1]):
            if miner == last_miner:
                consecutive += 1
            else:
                break

        if consecutive >= self.SELFISH_MINING_CRITICAL:
            log.critical(
                f"ECONOMIC CRITICAL: Selfish mining — {last_miner[:16]}... "
                f"mined {consecutive} consecutive blocks. "
                f"≥{self.SELFISH_MINING_CRITICAL} consecutive blocks indicates "
                f"near-certain private chain withholding or hashrate monopoly. "
                f"Network integrity at risk.")
            metrics.inc("economic_selfish_mining_alerts")
            metrics.inc("economic_selfish_mining_critical")
        elif consecutive >= self.SELFISH_MINING_WARNING:
            log.warning(
                f"ECONOMIC WARNING: Selfish mining pattern — {last_miner[:16]}... "
                f"mined {consecutive} consecutive blocks. "
                f"≥{self.SELFISH_MINING_WARNING} consecutive blocks is statistically "
                f"unlikely at honest hashrate split. Possible block withholding.")
            metrics.inc("economic_selfish_mining_alerts")
        elif consecutive >= self.SELFISH_MINING_NOTICE:
            log.info(
                f"ECONOMIC NOTICE: High variance — {last_miner[:16]}... "
                f"mined {consecutive} consecutive blocks. "
                f"May be natural luck; watch for further streaks.")

    def _check_fee_spike(self):
        with self._lock:
            fees = list(self._fee_log)
        if len(fees) < 5:
            return
        avg_old = sum(fees[:5]) / 5 or 0.0001
        avg_new = sum(fees[5:]) / max(len(fees) - 5, 1) or 0.0
        if avg_new > avg_old * self.FEE_SPIKE_MULTIPLIER:
            log.warning(
                f"ECONOMIC ALERT: Fee spike — avg fee jumped from "
                f"{avg_old:.4f} to {avg_new:.4f} VSD "
                f"({avg_new/avg_old:.1f}× increase, threshold={self.FEE_SPIKE_MULTIPLIER:.0f}×). "
                f"Possible mempool manipulation or MEV extraction.")
            metrics.inc("economic_fee_spike_alerts")

    def _check_collusion(self, sig_addresses: List[str]):
        if not sig_addresses:
            return
        c = Counter(sig_addresses)
        total_sigs  = len(sig_addresses)
        # If >80% of total sigs come from <20% of validators, flag it
        unique = len(c)
        if unique == 0:
            return
        top_n_count = sum(cnt for _, cnt in c.most_common(max(1, unique // 5)))
        frac = top_n_count / total_sigs
        if frac > Config.COLLUSION_SIG_OVERLAP:
            log.warning(
                f"ECONOMIC ALERT: Possible validator collusion — "
                f"{frac*100:.0f}% of validator sigs from top-{max(1,unique//5)} validators. "
                f"Attack boundary: >{Config.COLLUSION_SIG_OVERLAP*100:.0f}% sig dominance "
                f"indicates cartel approaching 2/3 BFT threshold.")
            metrics.inc("economic_collusion_alerts")

    def _check_validator_reward_manipulation(self, sig_addresses: List[str]):
        """
        Fix #11 — Validator reward manipulation detection:
        Check if validators who sign blocks disproportionately reward themselves
        relative to their stake share.
        """
        if not sig_addresses:
            return
        with self._lock:
            reward_copy = list(self._reward_log)
        if len(reward_copy) < 10:
            return
        # Build validator reward shares from recent history
        total_reward = sum(a for _, a in reward_copy) or 1.0
        reward_counts: Counter = Counter()
        for addr, amt in reward_copy:
            reward_counts[addr] += amt
        # Get validator stakes for comparison
        try:
            validators = self.storage.get_all_by_role("investor")
            if not validators:
                return
            total_stake = sum(v["stake"] for v in validators) or 1.0
            for v in validators:
                stake_share  = v["stake"] / total_stake
                reward_share = reward_counts.get(v["address"], 0.0) / total_reward
                if stake_share > 0 and reward_share > stake_share * self.REWARD_VS_STAKE_RATIO_MAX:
                    log.warning(
                        f"ECONOMIC ALERT: Validator reward manipulation — "
                        f"{v['address'][:16]}... earns {reward_share*100:.1f}% "
                        f"of rewards but holds only {stake_share*100:.1f}% of stake "
                        f"(ratio={reward_share/stake_share:.1f}×, boundary="
                        f"{self.REWARD_VS_STAKE_RATIO_MAX}×). "
                        f"Possible preferential block construction.")
                    metrics.inc("economic_reward_manipulation_alerts")
        except Exception:
            pass
