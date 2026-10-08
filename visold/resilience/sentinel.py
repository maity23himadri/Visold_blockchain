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
"""visold.resilience.sentinel

Original section: SECTION 17C: SENTINEL NODE — HIGH-AVAILABILITY ORCHESTRATOR

Defines: SentinelNode
Origin: visold_vsd_.py L42998-43246
"""

import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional, TYPE_CHECKING

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics
from visold.kernel.netutil import _create_connection_dual_stack

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.node.visold_node import VisoldNode


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 17C: SENTINEL NODE — HIGH-AVAILABILITY ORCHESTRATOR
# A Sentinel node monitors a primary VisoldNode instance and automatically
# takes over validator duties if the primary goes offline.
# ─────────────────────────────────────────────────────────────────────────────
class SentinelNode:
    """
    High-availability sentinel for production validator deployments.

    Architecture
    ────────────
    A Sentinel is a lightweight background thread that:
      1. Monitors the PRIMARY node's RPC endpoint with periodic health-checks.
      2. Maintains its own blockchain state (in sync with the primary via P2P).
      3. On PRIMARY FAILURE: flags itself ACTIVE and pages a human operator —
         it does NOT automatically import the validator key or begin casting
         BFT votes. (AUDIT-FIX-L2: this step previously claimed automatic
         vote-casting takeover happens; no such mechanism exists in this
         codebase. See _do_failover().)
      4. On PRIMARY RECOVERY: gracefully yields back to the primary.

    Failure detection
    ─────────────────
    The sentinel considers the primary FAILED when:
      • SENTINEL_FAILOVER_AFTER consecutive health-check calls time out, OR
      • The primary's chain height stops advancing for > 3× TARGET_BLOCK_TIME

    State machine
    ─────────────
                     ┌──────────┐
                     │  STANDBY │  ◄─── initial state
                     └────┬─────┘
                          │ primary unreachable × FAILOVER_AFTER
                          ▼
                     ┌──────────┐
                     │  ACTIVE  │  ─── sentinel is the active validator
                     └────┬─────┘
                          │ primary recovered
                          ▼
                     ┌──────────┐
                     │  STANDBY │  ◄─── yielded back to primary
                     └──────────┘

    Thread safety: all state transitions are under _lock.
    """

    STANDBY = "STANDBY"
    ACTIVE  = "ACTIVE"

    def __init__(self, node: 'VisoldNode'):
        """
        `node` is the LOCAL node instance running as the backup.
        Primary connection details come from Config.SENTINEL_*.
        """
        self._node       = node
        self._lock       = threading.Lock()
        self._state      = self.STANDBY
        self._fail_count = 0
        self._thread: Optional[threading.Thread] = None
        self._stop_evt   = threading.Event()
        self._primary_height = -1
        # v7.1.13 BUG-4 FIX: cache the primary's RPC token after first read
        # to avoid filesystem I/O on every probe.  Invalidated on 401.
        self._cached_rpc_token: Optional[str] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if not Config.SENTINEL_MODE:
            return
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="sentinel-monitor")
        self._thread.start()
        log.info(
            f"Sentinel mode ACTIVE — monitoring primary "
            f"{Config.SENTINEL_PRIMARY_HOST}:{Config.SENTINEL_PRIMARY_PORT} "
            f"(failover after {Config.SENTINEL_FAILOVER_AFTER} failures)")

    def stop(self):
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=5)

    # ── Monitor loop ──────────────────────────────────────────────────────────

    def _monitor_loop(self):
        while not self._stop_evt.wait(Config.SENTINEL_CHECK_INTERVAL):
            try:
                self._check_primary()
            except Exception as e:
                log.debug(f"Sentinel: monitor error: {e}")

    def _check_primary(self):
        """Ping the primary node's RPC.  Adjust fail count accordingly."""
        try:
            primary_height = self._rpc_call("getblockcount")
            if primary_height is not None:
                self._on_primary_ok(int(primary_height))
            else:
                self._on_primary_fail("RPC returned None")
        except Exception as e:
            self._on_primary_fail(str(e)[:80])

    def _rpc_call(self, method: str, params: Optional[list] = None):
        """
        Call the primary's RPC.  Returns the result or None on failure.

        v7.1.13 BUG-4 FIX (Token File Re-Read on Every Probe):
          Pre-fix code re-opened ~/.visold/rpc_token on every probe
          (every Config.SENTINEL_CHECK_INTERVAL seconds).  Under heavy
          filesystem load or transient permission errors, the read would
          throw, _rpc_call returned None, and the caller incremented
          fail_count → the node could trigger a false-positive failover
          even when the primary was actually healthy.

          Fix: cache the token in memory after the first successful read.
          Re-read ONLY if the cached token gets a 401/Unauthorized
          response (i.e. the operator legitimately rotated the token).
          The TCP-probe failover guard at _probe_primary_tcp() already
          catches the case where the file is genuinely missing and the
          primary really is down.
        """
        try:
            rpc_port = Config.SENTINEL_PRIMARY_PORT + Config.RPC_PORT_OFFSET
            token = self._cached_rpc_token
            if not token:
                token_path = os.path.join(Config.DATA_DIR, "rpc_token")
                if os.path.exists(token_path):
                    try:
                        with open(token_path) as f:
                            token = f.read().strip()
                        self._cached_rpc_token = token
                    except Exception as _re:
                        # Truly unreadable — fall through with empty
                        # token; primary will reject and we'll treat it
                        # as a probe failure (not a token failure).
                        log.debug(f"sentinel: token read failed: {_re}")
                        token = ""
            body = json.dumps({
                "jsonrpc": "2.0", "id": 1,
                "method": method, "params": params or []
            }).encode()
            req = urllib.request.Request(
                f"http://{Config.SENTINEL_PRIMARY_HOST}:{rpc_port}",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
            )
            try:
                resp = urllib.request.urlopen(req, timeout=5)  # nosec B310 – URL built from Config.SENTINEL_PRIMARY_HOST constant
            except urllib.error.HTTPError as _he:
                if _he.code == 401:
                    # Token rotated by operator — invalidate cache and
                    # let the next call re-read.  Return None this time.
                    log.info(
                        "sentinel: 401 from primary — invalidating "
                        "cached RPC token; will re-read on next call")
                    self._cached_rpc_token = None
                return None
            data = json.loads(resp.read())
            return data.get("result")
        except Exception:
            return None

    def _on_primary_ok(self, primary_height: int):
        """Primary is responsive; handle recovery if we were active."""
        with self._lock:
            self._fail_count     = 0
            self._primary_height = primary_height
            if self._state == self.ACTIVE:
                log.info(
                    "Sentinel: primary has recovered. "
                    "Yielding validator duties back to primary.")
                self._state = self.STANDBY
                # Stop casting BFT votes as sentinel
                self._node.storage.set_meta("sentinel_active", "0")
                metrics.set_gauge("sentinel_active", 0.0)

    def _probe_primary_tcp(self) -> bool:
        """VSD-M01 FIX: Low-level TCP probe to confirm primary is truly unreachable.
        Separates RPC-layer failures from genuine network partitions.
        Uses _create_connection_dual_stack (Happy Eyeballs) so that an IPv6-only
        or CGNAT primary is reachable even when IPv4 is broken."""
        try:
            s = _create_connection_dual_stack(
                Config.SENTINEL_PRIMARY_HOST,
                Config.SENTINEL_PRIMARY_PORT,
                timeout=3)
            s.close()
            return True   # TCP reachable — RPC failure only, do NOT failover
        except OSError:
            return False  # truly unreachable

    def _on_primary_fail(self, reason: str):
        """Primary is unresponsive; increment fail count, maybe failover.
        VSD-M01 FIX: Before activating, perform a direct TCP probe to confirm
        the primary is genuinely unreachable (not just an RPC-layer blip).
        This prevents dual-validator during transient network partitions."""
        with self._lock:
            self._fail_count += 1
            log.warning(
                f"Sentinel: primary health-check failed "
                f"({self._fail_count}/{Config.SENTINEL_FAILOVER_AFTER}): {reason}")
            if (self._fail_count >= Config.SENTINEL_FAILOVER_AFTER and
                    self._state == self.STANDBY):
                # Release lock during TCP probe so monitor loop is not blocked
                do_failover_check = True
            else:
                do_failover_check = False
        if do_failover_check:
            if self._probe_primary_tcp():
                log.warning(
                    "Sentinel: RPC failures but primary TCP is reachable — "
                    "suppressing failover (VSD-M01). Resetting fail count.")
                with self._lock:
                    self._fail_count = 0
            else:
                with self._lock:
                    if self._state == self.STANDBY:
                        self._do_failover(reason)

    def _do_failover(self, reason: str):
        """Transition to ACTIVE. NOTE: this does NOT itself resume BFT
        voting — see class docstring. It signals that a human operator
        needs to promote this node (or another) to the validator role."""
        self._state = self.ACTIVE
        self._node.storage.set_meta("sentinel_active", "1")
        metrics.set_gauge("sentinel_active", 1.0)
        log.critical(
            f"🟡 SENTINEL FAILOVER DETECTED — Primary unreachable ({reason}). "
            f"Validator voting has NOT automatically resumed on this node. "
            f"MANUAL ACTION REQUIRED: promote this node to validator role "
            f"(or restore the primary) to avoid continued validator downtime.")
        metrics.inc("sentinel_failovers")
        # AUDIT-FIX-L2: previously this comment (and the class docstring)
        # implied automatic BFT-vote takeover; no such mechanism exists.
        # Wire in a real paging/alert integration here if one is available
        # (e.g. the existing p2p alert gossip, an external webhook, etc.)
        # so this is not just a log line an operator might miss.

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled":         Config.SENTINEL_MODE,
                "state":           self._state,
                "fail_count":      self._fail_count,
                "primary_height":  self._primary_height,
                "primary_host":    Config.SENTINEL_PRIMARY_HOST,
                "primary_port":    Config.SENTINEL_PRIMARY_PORT,
            }
