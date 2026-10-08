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
"""visold.selfhealing.hardening.operator_api


Origin: visold_vsd_.py L54967-55096
"""

import time

from visold.kernel.logging_setup import log
from visold.selfhealing.hardening.risk import HardenedDecision, RiskScore


def _attach_operator_apis(shbs, safe_validator, abuse_guard, signal_window) -> None:
    """
    Attach new operator-facing methods to the SelfHealingSystem instance.
    Accessible via existing RPC dispatch table (shbs_* prefix).

    NEW OPERATOR COMMANDS:
        shbs_submit_rollback_proposal(depth, reason)
            → Manually initiate a governance rollback vote.
            → Requires operator auth token.

        shbs_manual_unfreeze(address)
            → Unfreeze an address and record cooldown.

        shbs_risk_status()
            → Return current signal window state and active risk scores.

        shbs_rollback_dry_run(depth)
            → Run dry-run preview without executing rollback.
    """

    def submit_rollback_proposal(depth: int, reason: str,
                                  risk_score: float = 85.0) -> dict:
        """
        Operator-initiated rollback proposal. Goes through governance vote.
        This is the ONLY path to rollback in v2 (no automatic rollback).
        """
        # Rate limit even operator proposals
        limited, msg = abuse_guard.is_rate_limited()
        if limited:
            return {"ok": False, "error": msg}

        current_tip = shbs._blockchain.height()
        target_height = max(0, current_tip - depth)

        # Dry run first
        preview = shbs.rollback_exec.dry_run_preview(target_height, set())
        if not preview.preview_ok:
            return {"ok": False, "error": f"Preview failed: {preview.reason}"}

        # Initiate governance vote via existing HAL mechanism
        # We create a mock HardenedDecision to reuse the vote infrastructure
        from types import SimpleNamespace
        mock_report = SimpleNamespace(
            kind=SimpleNamespace(value="operator_rollback"),
            evidence={"reason": reason, "depth": depth},
            affected_addr=None,
            block_height=current_tip,
        )
        mock_decision = HardenedDecision(
            report=mock_report,
            risk_score=RiskScore(
                value=risk_score,
                confidence_contrib=0,
                zscore_contrib=0,
                ev_contrib=0,
                freq_contrib=0,
            ),
            action_stage="CRITICAL",
            action_tags=["log"],
            attacker_ev=0.0,
            validator_ev=0.0,
            rationale=f"Operator rollback: {reason}",
            # AUDIT-FIX-M4: carry the operator's actual requested depth
            # through as an explicit target height, so
            # _initiate_governance_rollback executes against what this
            # function previewed and returned to the caller, instead of
            # silently substituting ROLLBACK_DEPTH[CRITICAL] (10 blocks).
            explicit_rollback_target_height=target_height,
        )

        log.critical(
            f"[OPR] submit_rollback_proposal: depth={depth} "
            f"target={target_height} reason={reason}")

        # Initiate the existing governance vote mechanism
        shbs.hal._initiate_governance_rollback(mock_decision, current_tip)

        return {
            "ok": True,
            "target_height": target_height,
            "depth": depth,
            "preview": {
                "affected_addresses": len(preview.affected_addresses),
                "flagged_txs": preview.flagged_tx_count,
                "safe_txs": preview.safe_tx_count,
            },
        }

    def manual_unfreeze(address: str) -> dict:
        """Unfreeze address and register cooldown to prevent rapid re-freeze."""
        shbs.hal._freeze.unfreeze(address)
        safe_validator.record_manual_unfreeze(address)
        log.warning(
            f"[OPR] Manual unfreeze: {address[:28]} "
            f"(re-freeze cooldown={safe_validator.REFREEZE_COOLDOWN}s)")
        return {"ok": True, "address": address}

    def risk_status() -> dict:
        """Return current v2 system state for monitoring dashboards."""
        return {
            "signal_window_keys": [
                str(k) for k in signal_window._windows.keys()
            ][:20],
            "rollback_proposals_last_hour": len([
                ts for ts in abuse_guard._proposals
                if time.time() - ts < 3600
            ]),
            "rollback_rate_limited": abuse_guard.is_rate_limited()[0],
        }

    def rollback_dry_run(depth: int) -> dict:
        """Run rollback preview without executing."""
        current_tip = shbs._blockchain.height()
        target = max(0, current_tip - depth)
        preview = shbs.rollback_exec.dry_run_preview(target, set())
        return {
            "preview_ok": preview.preview_ok,
            "depth": preview.rollback_depth,
            "affected_addresses": len(preview.affected_addresses),
            "flagged_txs": preview.flagged_tx_count,
            "safe_txs": preview.safe_tx_count,
            "balance_changes": dict(
                list(preview.estimated_balance_changes.items())[:10]),
            "reason": preview.reason,
        }

    shbs.submit_rollback_proposal = submit_rollback_proposal
    shbs.manual_unfreeze           = manual_unfreeze
    shbs.v2_risk_status            = risk_status
    shbs.rollback_dry_run          = rollback_dry_run
