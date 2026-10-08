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
"""visold.network.kademlia

Original section: SECTION 11: KADEMLIA DHT

Defines: KBucket, KademliaRouter
Origin: visold_vsd_.py L31001-31138
"""

import hashlib
import threading
from collections import OrderedDict
from typing import List

from visold.kernel.config import Config


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 11: KADEMLIA DHT
# ─────────────────────────────────────────────────────────────────────────────
class KBucket:
    def __init__(self, k=Config.KAD_K):
        self.k = k
        self.nodes: OrderedDict = OrderedDict()
        # Fix #6: Track IP subnets within this bucket to prevent adversarial
        # clustering.  Each /24 (IPv4) or /48 (IPv6) subnet may contribute
        # at most MAX_NODES_PER_SUBNET nodes to any single k-bucket.
        self.MAX_NODES_PER_SUBNET = max(2, k // 5)

    def _subnet(self, ip: str) -> str:
        """Extract /24 (IPv4) or /48 (IPv6) subnet prefix."""
        try:
            if ':' in ip:
                return ':'.join(ip.split(':')[:3])
            return '.'.join(ip.split('.')[:3])
        except Exception:
            return ip

    def add(self, peer_id: str, info: dict):
        if peer_id in self.nodes:
            self.nodes.move_to_end(peer_id)
            self.nodes[peer_id] = info
            return

        # Fix #6: subnet diversity check before adding new node
        ip = info.get("ip", "")
        if ip:
            subnet = self._subnet(ip)
            subnet_count = sum(
                1 for existing in self.nodes.values()
                if self._subnet(existing.get("ip", "")) == subnet
            )
            if subnet_count >= self.MAX_NODES_PER_SUBNET:
                # Bucket already has enough nodes from this subnet — skip
                return

        if len(self.nodes) < self.k:
            self.nodes[peer_id] = info

    def remove(self, peer_id: str):
        self.nodes.pop(peer_id, None)

    def get_all(self) -> List[dict]:
        return list(self.nodes.values())


class KademliaRouter:
    """
    Kademlia routing table.

    Dual-stack note:
    ────────────────
    Node IDs are always 160-bit SHA-1 hashes of the peer's public key hex
    string — completely independent of the peer's IP address family.  This
    means the same routing table stores IPv4 and IPv6 peers without any
    special-casing; the XOR metric operates on the hashed IDs.

    The `info` dict stored per peer carries the raw IP string (which may be
    an IPv4 literal, an IPv6 literal, or an IPv4-mapped IPv6 string that has
    been normalised to plain IPv4 by _normalize_ip).  Callers that need to
    open a socket to a peer should use _create_connection_dual_stack(ip, port)
    so that both address families are handled transparently.
    """
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.buckets = [KBucket() for _ in range(Config.KAD_BITS)]
        # AUDIT-FIX-25: every other stateful class in this batch
        # (_UDPWindow, UDPSession, LatencyTracker, LRUCache,
        # PeerReputationManager, CapabilityRouter, ...) locks its shared
        # dict/state before mutating or iterating it. This router was the
        # one exception: P2PNetwork calls update() from each peer
        # connection's own handshake thread, so concurrent handshakes
        # (routine at startup against several bootstrap peers) could
        # mutate/iterate a bucket's OrderedDict at the same time, raising
        # RuntimeError: OrderedDict mutated during iteration or leaving
        # bucket/LRU bookkeeping inconsistent. One coarse router-level
        # lock is sufficient since each bucket is small and operations
        # here are not a hot path.
        self._lock = threading.Lock()

    def _to_160bit_int(self, node_id: str) -> int:
        """
        Convert any node_id string to a 160-bit integer for XOR distance.
        If the string is a short hex value (≤40 chars) it is used directly;
        otherwise a SHA-1 hash is taken.  This is stable for both IPv4-derived
        (32-bit source) and IPv6-derived (128-bit source) peer identifiers
        because the final ID is always a 160-bit SHA-1 of the pub_hex.
        """
        try:
            val = int(node_id, 16) if len(node_id) <= 40 else \
                  int(hashlib.sha1(node_id.encode(), usedforsecurity=False).hexdigest(), 16)  # nosec B324
        except (ValueError, OverflowError):
            val = int(hashlib.sha1(node_id.encode(), usedforsecurity=False).hexdigest(), 16)  # nosec B324
        # Clamp to 160 bits so bucket index is always in [0, KAD_BITS)
        return val & ((1 << Config.KAD_BITS) - 1)

    def _bucket_idx(self, target_id: str) -> int:
        a   = self._to_160bit_int(self.node_id)
        b   = self._to_160bit_int(target_id)
        xor = a ^ b
        if xor == 0:
            return 0
        return min(xor.bit_length() - 1, Config.KAD_BITS - 1)

    def update(self, peer_id: str, info: dict):
        with self._lock:
            idx = self._bucket_idx(peer_id)
            self.buckets[idx].add(peer_id, info)

    def remove(self, peer_id: str):
        with self._lock:
            for b in self.buckets:
                b.remove(peer_id)

    def get_closest(self, target_id: str, k: int = Config.KAD_K) -> List[dict]:
        with self._lock:
            idx = self._bucket_idx(target_id)
            results = []
            for offset in range(Config.KAD_BITS):
                for delta in [offset, -offset]:
                    i = idx + delta
                    if 0 <= i < Config.KAD_BITS:
                        results.extend(self.buckets[i].get_all())
        target_int = self._to_160bit_int(target_id)
        def xor_dist(info):
            pid = info.get("peer_id", "")
            try:
                return target_int ^ self._to_160bit_int(pid)
            except Exception:
                return (1 << Config.KAD_BITS)
        results.sort(key=xor_dist)
        return results[:k]

    def all_peers(self) -> List[dict]:
        with self._lock:
            out = []
            for b in self.buckets:
                out.extend(b.get_all())
            return out
