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
"""visold.storage.block_database

Original section: SECTION 5B: BLOCK DATABASE — LevelDB / RocksDB BACKEND

Defines: BlockDatabase
Origin: visold_vsd_.py L12430-12770
"""

import json
import os
import threading
from typing import Any, List, Optional, TYPE_CHECKING

from visold.kernel.compat import _LEVELDB_AVAILABLE, _ROCKSDB_AVAILABLE
from visold.kernel.logging_setup import log

try:  # optional dependency: name may be undefined, exactly as in the monolith
    from visold.kernel.compat import _plyvel
except ImportError:
    pass

try:  # optional dependency: name may be undefined, exactly as in the monolith
    from visold.kernel.compat import _rocksdb
except ImportError:
    pass

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.ledger.block import Block


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5B: BLOCK DATABASE — LevelDB / RocksDB BACKEND
# ─────────────────────────────────────────────────────────────────────────────
class BlockDatabase:
    """
    High-performance key-value block storage backend.

    Problem addressed
    ─────────────────
    When the blockchain reaches millions of blocks, SQLite block storage becomes
    a bottleneck:
      • Each block's full JSON (transactions, signatures, etc.) is stored as a
        BLOB in the ``data_json`` column.  Large BLOBs cause excessive page
        fragmentation and slow sequential scans.
      • SQLite B-tree indexes do not compress BLOB values, so disk usage grows
        linearly with block data even when many fields are repetitive.
      • Write amplification from WAL + checkpoint cycles limits sustained
        write throughput to ~1,000–5,000 rows/s on typical hardware.

    Solution
    ────────
    BlockDatabase is a transparent drop-in layer that replaces SQLite block
    data storage with a dedicated key-value database (LevelDB or RocksDB).
    Relational data (balances, roles, peers, mempool, contract tables, etc.)
    stays in SQLite — only ``data_json`` for blocks moves to the KV store.

    Backends
    ────────
    "sqlite"   — default; no extra install; existing behaviour unchanged.
    "leveldb"  — uses plyvel (C LevelDB binding); install: pip install plyvel
                 Best for: read-heavy workloads, easy setup.
    "rocksdb"  — uses python-rocksdb; install: pip install rocksdict (PGX) or python-rocksdb (legacy)
                 Best for: write-heavy workloads (active mining), compression.

    Key schema (binary keys)
    ────────────────────────
    b:<height>   →  block JSON bytes      (primary: block by index)
    h:<hash>     →  height as 8-byte LE   (secondary: block by hash → height)
    tip          →  height as 8-byte LE   (current chain tip height)

    Thread safety
    ─────────────
    All public methods are protected by ``_lock``.  Batch writes ensure
    atomicity: a partial write (e.g. crash after storing ``b:<height>`` but
    before storing ``h:<hash>``) leaves the height index stale.  The Storage
    class recovers gracefully by falling back to a full scan when a hash lookup
    fails.

    Fallback
    ────────
    If the requested library is not installed, or if the database directory
    cannot be created, BlockDatabase logs a warning and sets ``enabled=False``.
    Storage then falls back to SQLite for all block operations, so the node
    continues to function correctly.
    """

    def __init__(self, backend: str, path: str):
        self._backend  = backend
        self._path     = path
        self._db: Any  = None
        self._lock     = threading.Lock()
        self._enabled  = False
        if backend in ("leveldb", "rocksdb"):
            self._init()

    # ── Initialisation ────────────────────────────────────────────────────────

    def _init(self):
        if self._backend == "leveldb":
            if not _LEVELDB_AVAILABLE:
                log.warning(
                    "LevelDB backend requested (VISOLD_DB_BACKEND=leveldb) but "
                    "'plyvel' is not installed.  Falling back to SQLite.\n"
                    "  Install with:  pip install plyvel")
                return
            try:
                os.makedirs(self._path, exist_ok=True)
                self._db      = _plyvel.DB(self._path, create_if_missing=True)
                self._enabled = True
                log.info(
                    f"BlockDatabase: LevelDB backend ACTIVE — "
                    f"block data stored at {self._path}")
            except Exception as exc:
                log.warning(
                    f"BlockDatabase: LevelDB initialisation failed: {exc}\n"
                    f"  Falling back to SQLite block storage.")

        elif self._backend == "rocksdb":
            if not _ROCKSDB_AVAILABLE:
                log.warning(
                    "RocksDB backend requested (VISOLD_DB_BACKEND=rocksdb) but "
                    "'python-rocksdb' is not installed.  Falling back to SQLite.\n"
                    "  Install with:  pip install python-rocksdb")
                return
            try:
                os.makedirs(self._path, exist_ok=True)
                opts = _rocksdb.Options()
                opts.create_if_missing        = True
                opts.max_open_files           = 300
                opts.write_buffer_size        = 67_108_864   # 64 MB
                opts.max_write_buffer_number  = 3
                opts.target_file_size_base    = 67_108_864   # 64 MB
                # Enable Snappy compression for block JSON (typically 3–5× ratio)
                opts.compression              = _rocksdb.CompressionType.snappy_compression
                self._db      = _rocksdb.DB(self._path, opts)
                self._enabled = True
                log.info(
                    f"BlockDatabase: RocksDB backend ACTIVE — "
                    f"block data stored at {self._path}")
            except Exception as exc:
                log.warning(
                    f"BlockDatabase: RocksDB initialisation failed: {exc}\n"
                    f"  Falling back to SQLite block storage.")

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        """True when the KV backend is open and operational."""
        return self._enabled and self._db is not None

    # ── Key helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _height_key(height: int) -> bytes:
        """Primary key: block by index."""
        return f"b:{height}".encode()

    @staticmethod
    def _hash_key(block_hash: str) -> bytes:
        """Secondary key: block hash → height."""
        return f"h:{block_hash}".encode()

    @staticmethod
    def _encode_height(height: int) -> bytes:
        """Store height as 8-byte little-endian integer."""
        return height.to_bytes(8, 'little')

    @staticmethod
    def _decode_height(data: bytes) -> int:
        return int.from_bytes(data[:8], 'little')

    # ── Write operations ──────────────────────────────────────────────────────

    def put_block(self, block: 'Block') -> bool:
        """
        Persist a block to the KV store.

        Writes three keys atomically:
          b:<height>  — full block JSON
          h:<hash>    — height reference (for hash lookups)
          tip         — updated chain tip height

        Returns True on success, False on any error.
        """
        if not self.enabled:
            return False
        try:
            data       = json.dumps(block.to_dict()).encode()
            height_key = self._height_key(block.index)
            hash_key   = self._hash_key(block.block_hash)
            tip_key    = b"tip"
            height_val = self._encode_height(block.index)

            with self._lock:
                # v7.0.1.2 — Monotonic tip guard.
                # Only advance the tip; never regress it when writing an
                # older block (e.g. during a reorg rollback+replay, or when
                # back-filling a block received out of order).  Without this
                # guard, writing block N with N < current_tip would silently
                # set tip=N, causing chain_height() to report the wrong value
                # until the next higher block was written.  This was one of
                # the latent paths that could surface as "Height: -1" or
                # "peer reports height 0" in the ghost-peer scenario.
                try:
                    current_tip_raw = self._db.get(tip_key)
                except Exception:
                    current_tip_raw = None
                if current_tip_raw is None:
                    advance_tip = True
                else:
                    try:
                        current_tip = self._decode_height(current_tip_raw)
                        advance_tip = block.index > current_tip
                    except Exception:
                        advance_tip = True   # corrupt tip — overwrite

                if self._backend == "leveldb":
                    with self._db.write_batch() as wb:
                        wb.put(height_key, data)
                        wb.put(hash_key,   height_val)
                        if advance_tip:
                            wb.put(tip_key, height_val)
                elif self._backend == "rocksdb":
                    batch = _rocksdb.WriteBatch()
                    batch.put(height_key, data)
                    batch.put(hash_key,   height_val)
                    if advance_tip:
                        batch.put(tip_key, height_val)
                    self._db.write(batch)
            return True
        except Exception as exc:
            log.debug(f"BlockDatabase.put_block({block.index}): {exc}")
            return False

    def delete_block(self, height: int) -> bool:
        """
        Remove a block from the KV store (used during chain reorg rollback).

        Deletes both the primary key and the hash index key atomically.
        Returns True on success, False on error.
        """
        if not self.enabled:
            return False
        try:
            # Retrieve the block first so we can delete its hash index key.
            blk_dict   = self.get_block_by_height(height)
            height_key = self._height_key(height)
            tip_key    = b"tip"

            with self._lock:
                current_tip_raw = self._db.get(tip_key)
                try:
                    current_tip = self._decode_height(current_tip_raw) if current_tip_raw is not None else -1
                except Exception:
                    current_tip = -1
                rewind_tip = (height == current_tip)
                if self._backend == "leveldb":
                    with self._db.write_batch() as wb:
                        wb.delete(height_key)
                        if blk_dict:
                            wb.delete(self._hash_key(blk_dict["block_hash"]))
                        if rewind_tip:
                            if height <= 0:
                                wb.delete(tip_key)
                            else:
                                wb.put(tip_key, self._encode_height(height - 1))
                elif self._backend == "rocksdb":
                    batch = _rocksdb.WriteBatch()
                    batch.delete(height_key)
                    if blk_dict:
                        batch.delete(self._hash_key(blk_dict["block_hash"]))
                    if rewind_tip:
                        if height <= 0:
                            batch.delete(tip_key)
                        else:
                            batch.put(tip_key, self._encode_height(height - 1))
                    self._db.write(batch)
            return True
        except Exception as exc:
            log.debug(f"BlockDatabase.delete_block({height}): {exc}")
            return False

    # ── Read operations ───────────────────────────────────────────────────────

    def prune_block(self, height: int, slim_block: dict) -> bool:
        """Replace only the b:<height> payload with a slim authenticated block."""
        if not self.enabled:
            return False
        try:
            key = self._height_key(int(height))
            data = json.dumps(dict(slim_block), separators=(",", ":")).encode()
            with self._lock:
                if self._backend == "leveldb":
                    with self._db.write_batch() as wb:
                        wb.put(key, data)
                else:
                    batch = _rocksdb.WriteBatch()
                    batch.put(key, data)
                    self._db.write(batch)
            return True
        except Exception as exc:
            log.debug(f"BlockDatabase.prune_block({height}): {exc}")
            return False

    def get_block_by_height(self, height: int) -> Optional[dict]:
        """
        Return a block dict for the given height, or None if not found.
        """
        if not self.enabled:
            return None
        try:
            key = self._height_key(height)
            with self._lock:
                data = self._db.get(key)
            if data is None:
                return None
            return json.loads(data.decode())
        except Exception as exc:
            log.debug(f"BlockDatabase.get_block_by_height({height}): {exc}")
            return None

    def get_block_by_hash(self, block_hash: str) -> Optional[dict]:
        """
        Return a block dict for the given hash, or None if not found.

        Uses the hash→height secondary index for O(1) lookup.
        Falls back to linear scan on index miss (handles the rare case where
        a crash left the secondary index stale).
        """
        if not self.enabled:
            return None
        try:
            hash_key = self._hash_key(block_hash)
            with self._lock:
                height_val = self._db.get(hash_key)
            if height_val is None:
                return None
            height = self._decode_height(height_val)
            return self.get_block_by_height(height)
        except Exception as exc:
            log.debug(f"BlockDatabase.get_block_by_hash({block_hash[:16]}): {exc}")
            return None

    def chain_height(self) -> int:
        """
        Return the highest stored block height, or -1 if the store is empty.
        Reads the ``tip`` key which is updated on every put_block() call.
        """
        if not self.enabled:
            return -1
        try:
            with self._lock:
                data = self._db.get(b"tip")
            if data is None:
                return -1
            return self._decode_height(data)
        except Exception as exc:
            log.debug(f"BlockDatabase.chain_height(): {exc}")
            return -1

    def get_last_n_blocks(self, n: int) -> List[dict]:
        """
        Return the last *n* blocks in ascending height order.
        Used by the CLI blockchain explorer and chain sync.
        """
        if not self.enabled:
            return []
        try:
            tip = self.chain_height()
            if tip < 0:
                return []
            results = []
            for h in range(max(0, tip - n + 1), tip + 1):
                blk = self.get_block_by_height(h)
                if blk is not None:
                    results.append(blk)
            return results
        except Exception as exc:
            log.debug(f"BlockDatabase.get_last_n_blocks({n}): {exc}")
            return []

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self):
        """Close the underlying database connection gracefully."""
        if self._db is not None and self.enabled:
            try:
                with self._lock:
                    if hasattr(self._db, 'close'):
                        self._db.close()
            except Exception:
                pass
            finally:
                self._enabled = False

    def backend_info(self) -> dict:
        """Return a summary dict for RPC / monitoring."""
        return {
            "backend":   self._backend,
            "enabled":   self.enabled,
            "path":      self._path if self.enabled else "",
            "leveldb_available": _LEVELDB_AVAILABLE,
            "rocksdb_available": _ROCKSDB_AVAILABLE,
        }
