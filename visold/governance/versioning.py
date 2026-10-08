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
"""visold.governance.versioning

Original section: SECTION 1D: STRUCTURED LOGGING  (Problem #11)

Defines: ProtocolVersionManager
Origin: visold_vsd_.py L5900-5975
"""

import threading
from typing import TYPE_CHECKING, Tuple

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1D: STRUCTURED LOGGING  (Problem #11)
# _StructuredFormatter is defined early (before Section 1) to fix the
# forward-reference issue when VISOLD_LOG_FORMAT=json is set at startup.
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1E: PROTOCOL VERSION MANAGER  (Problem #13 — Upgrade Mechanism)
# ─────────────────────────────────────────────────────────────────────────────
class ProtocolVersionManager:
    """
    Tracks miner upgrade signaling for soft-fork activation.

    Mechanism:
    ══════════
    1. Miners embed `protocol_version` in their blocks.
    2. Every Config.FORK_SIGNAL_WINDOW blocks, we count what fraction signal
       a version ≥ next version.
    3. Once ≥ Config.FORK_SIGNAL_THRESHOLD fraction signal, we log an alert
       and set the active version, enabling new validation rules.

    Hard forks are handled by version numbers that nodes reject blocks below.
    """
    def __init__(self, storage: 'Storage'):
        self.storage       = storage
        self._current_ver  = Config.PROTOCOL_VERSION
        self._lock         = threading.Lock()

    def record_block_version(self, proto_ver: int, block_height: int):
        """Called whenever a new block is applied."""
        with self._lock:
            key = f"proto_sig:{block_height}"
            self.storage.set_meta(key, str(proto_ver))

        # Check signaling window every FORK_SIGNAL_WINDOW blocks
        # (GovernanceEngine also checks on every block via on_block_applied;
        # this path is kept for backward-compat logging only)
        if block_height % Config.FORK_SIGNAL_WINDOW == 0 and block_height > 0:
            self._check_upgrade_signal(block_height)

    def _check_upgrade_signal(self, tip_height: int):
        window = Config.FORK_SIGNAL_WINDOW
        start  = max(0, tip_height - window)
        versions = []
        for h in range(start, tip_height + 1):
            raw = self.storage.get_meta(f"proto_sig:{h}")
            if raw:
                try:
                    versions.append(int(raw))
                except ValueError:
                    pass
        if not versions:
            return
        next_ver = self._current_ver + 1
        fraction = sum(1 for v in versions if v >= next_ver) / len(versions)
        if fraction >= Config.FORK_SIGNAL_THRESHOLD:
            log.info(
                f"PROTOCOL UPGRADE: {fraction*100:.0f}% of last {len(versions)} blocks "
                f"signal version ≥ {next_ver}. Consider upgrading your node.")
            metrics.inc("protocol_upgrade_signals")

    def validate_block_version(self, proto_ver: int) -> Tuple[bool, str]:
        """Reject blocks from incompatible future hard forks."""
        # Hard fork: refuse blocks with version > current + 1
        if proto_ver > self._current_ver + 1:
            return False, (f"Block protocol_version {proto_ver} too far ahead "
                           f"(current {self._current_ver}) — hard fork?")
        return True, "OK"

    def current_version(self) -> int:
        return self._current_ver

    def advance_version(self, new_version: int) -> None:
        """AUDIT-FIX-K3: called by GovernanceEngine._check_activation() when
        a proposal transitions to ACTIVE. Previously nothing ever updated
        _current_ver after __init__, so current_version() (and therefore
        propose_upgrade's "version != current + 1" check) kept comparing
        against the chain's original version forever -- permanently
        blocking any upgrade proposal after the first one activated. Only
        moves the counter forward; a lower/equal new_version is ignored so
        an out-of-order or duplicate activation call can't move it backward.
        """
        with self._lock:
            if new_version > self._current_ver:
                self._current_ver = new_version
