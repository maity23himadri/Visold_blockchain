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
"""visold.selfhealing.state_hook

Original section: SECTION 9: STATEENGINE HOOK (non-invasive integration)

Defines: StateEngineHook
Origin: visold_vsd_.py L52506-52585
"""

from visold.kernel.logging_setup import log
from visold.selfhealing.healing import FreezeRegistry, RateLimiter


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9: STATEENGINE HOOK (non-invasive integration)
# ─────────────────────────────────────────────────────────────────────────────

class StateEngineHook:
    """
    Non-invasive hooks into StateEngine to enforce SHBS decisions.

    Integration strategy: monkey-patch StateEngine._handle_new_tx and
    StateEngine._handle_new_block BEFORE start() is called. The patches
    wrap the originals and delegate to SHBS checks first.

    WHY MONKEY-PATCH (not subclass):
      VisoldNode constructs StateEngine directly. Subclassing would require
      changing VisoldNode.__init__, which modifies the core codebase.
      Monkey-patching at the instance level (not class level) is isolated
      to this node instance and does not affect other tests or instances.

    NO STATE ROOT IMPACT:
      The hook only REJECTS transactions before they reach the state machine.
      It never modifies transactions, block contents, or apply paths.
      Rejected transactions are not applied → state_root is unchanged.
    """

    def __init__(
        self,
        state_engine,
        rate_limiter: RateLimiter,
        freeze_registry: FreezeRegistry,
    ):
        self._se = state_engine
        self._rl = rate_limiter
        self._fr = freeze_registry
        self._installed = False

    def install(self) -> None:
        """Wrap StateEngine methods at the instance level."""
        if self._installed:
            return

        original_handle_tx = self._se._handle_new_tx

        rl = self._rl
        fr = self._fr

        def _hooked_handle_new_tx(payload: dict, source_peer: str):
            # Extract sender from payload
            tx_data = payload.get("tx") if isinstance(payload, dict) else None
            sender = ""
            receiver = ""
            if isinstance(tx_data, dict):
                sender   = tx_data.get("sender", "")
                receiver = tx_data.get("receiver", "")

            # Check freeze registry
            if sender and fr.is_frozen(sender):
                log.warning(
                    f"[SHBS-HOOK] TX rejected: sender {sender[:24]} is FROZEN")
                return False, "SHBS: sender account frozen during anomaly response"

            if receiver and fr.is_frozen(receiver):
                log.warning(
                    f"[SHBS-HOOK] TX rejected: receiver {receiver[:24]} is FROZEN")
                return False, "SHBS: receiver account frozen during anomaly response"

            # Check rate limiter
            if sender:
                allow, msg = rl.check(sender)
                if not allow:
                    log.debug(f"[SHBS-HOOK] TX rate-limited: {sender[:24]}")
                    return False, f"SHBS: {msg}"

            # Delegate to original handler
            return original_handle_tx(payload, source_peer)

        # Patch instance method (not class method)
        import types
        self._se._handle_new_tx = types.MethodType(
            lambda se, payload, source_peer: _hooked_handle_new_tx(payload, source_peer),
            self._se
        )

        self._installed = True
        log.info("[SHBS] StateEngine hook installed (TX freeze + rate-limit enforcement)")
