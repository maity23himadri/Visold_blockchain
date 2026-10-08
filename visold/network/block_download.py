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
"""visold.network.block_download

Original section: SECTION 6F: STATE SNAPSHOT ENGINE  (v7.4.0)

Defines: ParallelBlockDownloader
Origin: visold_vsd_.py L17043-17266
"""

import hashlib
import json
import threading
from typing import Any, Dict, Optional, TYPE_CHECKING

from visold.kernel.logging_setup import log
from visold.kernel.messages import (
    MSG_BLOCK_CHUNK_DATA,
    MSG_BLOCK_MANIFEST,
    MSG_GET_BLOCK_CHUNK,
    MSG_GET_BLOCK_MANIFEST,
)
from visold.ledger.block import Block

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.network.p2p import P2PNetwork
    from visold.network.peer_connection import PeerConnection


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6F: STATE SNAPSHOT ENGINE  (v7.4.0)
# Generates compressed binary state snapshots at every SNAPSHOT_INTERVAL
# blocks so new nodes can fast-sync without replaying history from genesis.
#
# Snapshot format (stored in node_meta as "snap:<height>"):
#   zlib-compressed JSON object:
#   {
#     "height":    <int>,
#     "state_root": "<hex>",
#     "balances":  { "<addr>": <balance_sat_int>, ... },
#     "nonces":    { "<addr>": <nonce_int>, ... },
#     "contracts": { "<addr>": { "code_hash": "..", "storage_root": "..",
#                                "nonce": .., "creator": "..",
#                                "created_at": .., "name": ".." } },
#     "roles":     { "<addr>": { "role": "..", "stake_sat": ..,
#                                "score": .., "slashed": 0/1 } },
#   }
#
# The state_root field lets any recipient verify integrity against the
# block header already in their DB / received over the wire.
# ─────────────────────────────────────────────────────────────────────────────

class ParallelBlockDownloader:
    """
    Downloads a single large block in chunks from multiple peers in parallel.
    Optimized for slow links and mobile nodes (CGNAT/Termux). 
    
    Features:
      - 512KB deterministic chunking.
      - Parallel multi-peer fetching (up to MAX_PARALLEL_PEERS).
      - Strict SHA-256 verification per chunk.
      - Auto-reassigns chunks from slow/dead peers to active workers.
    """
    CHUNK_SIZE         = 512 * 1024  # 512 KB chunks to keep memory footprint low
    MAX_PARALLEL_PEERS = 8           # Fits within typical active peer bounds
    CHUNK_TIMEOUT      = 15.0        # Seconds before re-assigning a chunk
    MAX_RETRIES        = 3           # Max retries per chunk before failing the block

    def __init__(self, network: 'P2PNetwork', block_hash: str):
        self._network    = network
        self._block_hash = block_hash
        self._lock       = threading.Lock()

    def download(self) -> Optional['Block']:
        import queue as _queue_mod

        # 1. Collect candidate peers
        with self._network._lock:
            candidate_peers = [p for p in self._network.peers.values() if p.connected]

        if not candidate_peers:
            log.debug(f"[ParallelBlock] No connected peers for {self._block_hash[:16]}")
            return None

        # 2. Fetch Manifest from the first responsive peer
        manifest      = None
        manifest_peer = None
        
        for p in candidate_peers:
            q: Any = _queue_mod.Queue(maxsize=4)
            p._block_chunk_queue = q  # Route MSG_BLOCK_MANIFEST here
            try:
                p.send({
                    "type": MSG_GET_BLOCK_MANIFEST, 
                    "block_hash": self._block_hash
                })
                try:
                    resp = q.get(timeout=5.0)
                    if (resp.get("type") == MSG_BLOCK_MANIFEST and 
                        resp.get("block_hash") == self._block_hash):
                        if "error" not in resp:
                            manifest = resp
                            manifest_peer = p
                            break
                except _queue_mod.Empty:
                    continue
            finally:
                p._block_chunk_queue = None

        if manifest is None:
            log.debug(f"[ParallelBlock] Manifest unavailable for {self._block_hash[:16]}")
            return None

        total_chunks = manifest.get("total_chunks", 0)
        chunk_hashes = manifest.get("chunk_hashes", [])
        if total_chunks == 0 or len(chunk_hashes) != total_chunks:
            return None

        log.info(f"[ParallelBlock] Downloading {self._block_hash[:16]} "
                 f"({total_chunks} chunks, up to {self.MAX_PARALLEL_PEERS} peers)")

        # 3. Work Queue & Thread Coordination
        chunk_map_lock = threading.Lock()
        chunk_store: Dict[int, Optional[bytes]] = {i: None for i in range(total_chunks)}
        chunk_retries  = {i: 0 for i in range(total_chunks)}
        work_queue: Any = _queue_mod.Queue()
        
        for i in range(total_chunks):
            work_queue.put(i)

        completed  = threading.Event()
        failed     = threading.Event()
        done_count = [0]

        # 4. Worker Thread Definition
        def _worker(wp: 'PeerConnection'):
            wq: Any = _queue_mod.Queue(maxsize=16)
            wp._block_chunk_queue = wq  # Route MSG_BLOCK_CHUNK_DATA here
            try:
                while not completed.is_set() and not failed.is_set():
                    try:
                        chunk_idx = work_queue.get(timeout=1.0)
                    except _queue_mod.Empty:
                        break

                    # Check if already fulfilled by a racing worker
                    with chunk_map_lock:
                        if chunk_store[chunk_idx] is not None:
                            work_queue.task_done()
                            continue

                    # Request chunk
                    try:
                        wp.send({
                            "type":        MSG_GET_BLOCK_CHUNK,
                            "block_hash":  self._block_hash,
                            "chunk_index": chunk_idx
                        })
                    except Exception as e:
                        log.debug(f"[ParallelBlock] Send error to {wp.peer_id[:8]}: {e}")
                        work_queue.put(chunk_idx)
                        work_queue.task_done()
                        break  # Peer broken; exit this worker

                    # Await chunk data
                    try:
                        resp = wq.get(timeout=self.CHUNK_TIMEOUT)
                    except _queue_mod.Empty:
                        log.warning(f"[ParallelBlock] Timeout chunk {chunk_idx} from {wp.peer_id[:8]}")
                        with chunk_map_lock:
                            chunk_retries[chunk_idx] += 1
                            if chunk_retries[chunk_idx] >= self.MAX_RETRIES:
                                failed.set()
                        work_queue.put(chunk_idx)
                        work_queue.task_done()
                        # AUDIT-FIX-26: this used to `continue`, silently
                        # contradicting the comment below — a slow peer
                        # stayed in rotation and kept drawing OTHER chunks
                        # from the shared queue, timing out on those too
                        # and burning their MAX_RETRIES budget for a
                        # problem that was actually about this peer, not
                        # those chunks. `break` retires this worker so a
                        # healthier peer can take over the rest.
                        break  # Peer is too slow; exit this worker so others take over

                    # AUDIT-FIX-26: verify the response actually answers
                    # THIS request, not a late/stale response to a PRIOR
                    # chunk request on this same peer — wq is one shared
                    # queue for this worker's whole lifetime, so replies
                    # can arrive out of order relative to what was most
                    # recently requested. The hash check further below
                    # already stops wrong bytes from being accepted, but
                    # without this a stale reply still burned a retry on
                    # whatever chunk was actually being awaited, for a
                    # problem that was really cross-talk, not a fetch
                    # failure.
                    if (resp.get("type") != MSG_BLOCK_CHUNK_DATA or 
                        resp.get("block_hash") != self._block_hash or 
                        resp.get("chunk_index") != chunk_idx or
                        "error" in resp):
                        work_queue.put(chunk_idx)
                        work_queue.task_done()
                        continue

                    # Decode and verify
                    try:
                        raw_chunk   = bytes.fromhex(resp.get("data_hex", ""))
                        actual_hash = hashlib.sha256(raw_chunk).hexdigest()
                    except ValueError:
                        actual_hash = ""

                    if actual_hash != chunk_hashes[chunk_idx]:
                        log.warning(f"[ParallelBlock] Hash mismatch chunk {chunk_idx} from {wp.peer_id[:8]}")
                        with chunk_map_lock:
                            chunk_retries[chunk_idx] += 1
                            if chunk_retries[chunk_idx] >= self.MAX_RETRIES:
                                failed.set()
                        work_queue.put(chunk_idx)
                        work_queue.task_done()
                        continue

                    # Commit chunk to store
                    with chunk_map_lock:
                        chunk_store[chunk_idx] = raw_chunk
                        done_count[0] += 1
                        if done_count[0] == total_chunks:
                            completed.set()

                    work_queue.task_done()
            except Exception as e:
                log.debug(f"[ParallelBlock] Worker {wp.peer_id[:8]} error: {e}")
            finally:
                wp._block_chunk_queue = None

        # 5. Spawn parallel workers
        active_peers = candidate_peers[:self.MAX_PARALLEL_PEERS]
        threads = []
        for p in active_peers:
            t = threading.Thread(
                target=_worker, 
                args=(p,), 
                daemon=True, 
                name=f"blk-chunk-{p.peer_id[:8]}"
            )
            threads.append(t)
            t.start()

        # 6. Await completion with fallback timeout
        max_wait = (self.CHUNK_TIMEOUT * total_chunks / max(1, len(active_peers))) + 30
        completed.wait(timeout=max_wait)

        if failed.is_set() or not completed.is_set():
            log.warning(f"[ParallelBlock] Download failed or timed out for {self._block_hash[:16]}")
            return None

        # 7. Reassemble & Deserialize
        with chunk_map_lock:
            blob = b"".join(v for v in (chunk_store[i] for i in range(total_chunks)) if v is not None)

        try:
            block_dict = json.loads(blob.decode("utf-8"))
            
            # Block lives in visold.ledger.block (was: sys.modules[__name__].Block)
            block = Block.from_dict(block_dict)
            
            if block.block_hash != self._block_hash:
                log.warning(f"[ParallelBlock] Reassembled block hash mismatch!")
                return None
                
            log.info(f"[ParallelBlock] Successfully rebuilt {self._block_hash[:16]}")
            return block
        except Exception as e:
            log.warning(f"[ParallelBlock] Reassembly JSON error: {e}")
            return None
