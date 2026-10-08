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
"""visold.network.capabilities

Original section: SECTION 6D: DISCV5-STYLE CAPABILITY TOPIC DISCOVERY

Defines: CapabilityRouter
Origin: visold_vsd_.py L16602-16604, L16607-16610, L16613-16616, L16619-16624, L17761-17894
"""

import threading
import time
from collections import defaultdict
from typing import Dict, List, TYPE_CHECKING

from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6D: DISCV5-STYLE CAPABILITY TOPIC DISCOVERY
# Allows nodes to find peers with specific capabilities (full archive,
# VVM execution nodes, light relay, etc.) rather than random peers.
# ─────────────────────────────────────────────────────────────────────────────

MSG_CAPABILITY_ADV     = "CAPABILITY_ADV"      # advertise own capabilities


MSG_CAPABILITY_QUERY   = "CAPABILITY_QUERY"    # ask for peers with capability X


MSG_CAPABILITY_RESPONSE= "CAPABILITY_RESP"     # list of peers with that capability


# ── Snapshot / Fast-Sync messages (v7.4.0) ───────────────────────────────────
MSG_GET_SNAPSHOT_MANIFEST = "GET_SNAP_MANIFEST"  # request list of available snapshots


MSG_SNAPSHOT_MANIFEST     = "SNAP_MANIFEST"      # response: list of {height, state_root, size}


MSG_GET_SNAPSHOT          = "GET_SNAPSHOT"       # request snapshot blob at height H


MSG_SNAPSHOT_DATA         = "SNAPSHOT_DATA"      # response: compressed state blob


# ── Parallel Multi-Peer Snapshot Sync messages (v7.5.0) ──────────────────────
MSG_GET_CHUNK_MANIFEST = "GET_CHUNK_MANIFEST"  # request chunk manifest for height H


MSG_CHUNK_MANIFEST     = "CHUNK_MANIFEST"      # response: {height, total_chunks, chunk_hashes[]}


MSG_GET_CHUNK          = "GET_CHUNK"           # request chunk {height, chunk_index}


MSG_CHUNK_DATA         = "CHUNK_DATA"          # response: {height, chunk_index, data_hex, hash}


# Well-known capability strings
CAP_FULL_NODE     = "full_node"    # stores full block history


CAP_ARCHIVE       = "archive"      # stores full historical state (no pruning)


CAP_VVM_EXEC      = "vvm"          # executes VVM smart contracts


CAP_LIGHT_RELAY   = "relay"        # serves light client SPV proofs


CAP_VALIDATOR     = "validator"    # active PoS validator


CAP_BOOTSTRAP     = "bootstrap"    # stable bootstrap/seed node


class CapabilityRouter:
    """
    DiscV5-style topic-based peer discovery.

    Nodes advertise their capabilities in HELLO and in periodic CAP_ADV
    broadcasts.  The router maintains a local map of peer_id → capabilities
    and can answer queries for peers with a specific capability.

    Usage pattern
    ─────────────
    1. At startup, the node broadcasts its own CAP_ADV to all peers.
    2. Any node can send CAP_QUERY to find peers with capability X.
    3. Recipients with that capability reply with CAP_RESP listing known
       peers that also have it.
    4. The querying node can then connect to those specialized peers.

    This enables efficient routing of specific request types:
      • SPV proof requests → peers with CAP_LIGHT_RELAY
      • VVM simulation    → peers with CAP_VVM_EXEC
      • Archive queries   → peers with CAP_ARCHIVE
    """

    def __init__(self, storage: 'Storage'):
        self._storage = storage
        self._lock    = threading.Lock()
        # peer_id → set of capability strings
        self._peer_caps: Dict[str, set] = {}
        # capability → set of peer_ids known to have it
        self._cap_index: Dict[str, set] = defaultdict(set)
        self._own_caps: set = set(Config.NODE_CAPABILITIES)
        self._ensure_table()

    def _ensure_table(self):
        try:
            c = self._storage._conn()
            c.execute("""
                CREATE TABLE IF NOT EXISTS peer_capabilities (
                    peer_id    TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    updated_at INTEGER DEFAULT 0,
                    PRIMARY KEY (peer_id, capability)
                )
            """)
            c.commit()
            # Load persisted capabilities
            rows = c.execute(
                "SELECT peer_id, capability FROM peer_capabilities").fetchall()
            for r in rows:
                pid, cap = r["peer_id"], r["capability"]
                self._peer_caps.setdefault(pid, set()).add(cap)
                self._cap_index[cap].add(pid)
        except Exception as e:
            log.debug(f"CapabilityRouter: init error: {e}")

    def record_peer_capabilities(self, peer_id: str, caps: List[str]):
        """Record capabilities advertised by a peer."""
        with self._lock:
            cap_set = set(caps)
            self._peer_caps[peer_id] = cap_set
            for cap in cap_set:
                self._cap_index[cap].add(peer_id)
        try:
            c = self._storage._conn()
            now = int(time.time())
            for cap in caps:
                c.execute("""
                    INSERT OR REPLACE INTO peer_capabilities
                    (peer_id, capability, updated_at) VALUES (?,?,?)
                """, (peer_id, cap, now))
            c.commit()
        except Exception as e:
            log.debug(f"CapabilityRouter: record error: {e}")

    def find_peers_with(self, capability: str) -> List[str]:
        """Return list of known peer_ids that have the given capability."""
        with self._lock:
            return list(self._cap_index.get(capability, set()))

    def own_capabilities(self) -> List[str]:
        """Return this node's own capability list."""
        # Auto-detect validator status
        caps = set(self._own_caps)
        return list(caps)

    def build_adv_message(self) -> dict:
        """Build a CAPABILITY_ADV broadcast message."""
        return {
            "type": MSG_CAPABILITY_ADV,
            "capabilities": self.own_capabilities(),
            "ttl": Config.GOSSIP_TTL,
        }

    def build_query_message(self, capability: str) -> dict:
        """Build a CAPABILITY_QUERY message."""
        return {
            "type": MSG_CAPABILITY_QUERY,
            "capability": capability,
            "ttl": Config.GOSSIP_TTL,
        }

    def handle_adv(self, peer_id: str, caps: List[str]):
        """Handle an incoming CAPABILITY_ADV."""
        self.record_peer_capabilities(peer_id, caps)
        metrics.inc("capability_adverts_received")

    def handle_query(self, capability: str) -> List[str]:
        """Handle a CAPABILITY_QUERY; return matching peer_ids."""
        return self.find_peers_with(capability)

    def remove_peer(self, peer_id: str):
        """Remove all capability records for a disconnected peer."""
        with self._lock:
            caps = self._peer_caps.pop(peer_id, set())
            for cap in caps:
                self._cap_index[cap].discard(peer_id)
        try:
            self._storage._conn().execute(
                "DELETE FROM peer_capabilities WHERE peer_id=?", (peer_id,))
            self._storage._conn().commit()
        except Exception:
            pass

    def update_own_capabilities(self, storage: 'Storage'):
        """Dynamically add CAP_VALIDATOR if this node has active stake."""
        try:
            addr = storage.get_meta("own_address")
            if addr:
                role = storage.get_role(addr)
                if role and role["role"] == "investor":
                    self._own_caps.add(CAP_VALIDATOR)
                else:
                    self._own_caps.discard(CAP_VALIDATOR)
        except Exception:
            pass
