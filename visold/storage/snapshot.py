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
"""visold.storage.snapshot


Defines: StateSnapshotEngine
Origin: visold_vsd_.py L17268-17758
"""

import hashlib
import json
import threading
import zlib
from typing import Optional, TYPE_CHECKING, Tuple

from visold.kernel.config import Config
from visold.kernel.compression_utils import bounded_zlib_decompress
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


class StateSnapshotEngine:
    """
    Generates, stores, and serves full compressed state snapshots.

    Snapshot creation  — called from apply_block via maybe_snapshot().
    Snapshot serving   — called from P2PNetwork._handle_message() for
                         MSG_GET_SNAPSHOT_MANIFEST and MSG_GET_SNAPSHOT.
    Snapshot restoring — called during fast-sync to apply a downloaded blob.

    All heavy work (serialisation + zlib) is off the main chain thread;
    maybe_snapshot() always dispatches to a daemon thread.
    """

    # node_meta key prefix and manifest key
    _KEY_PREFIX  = "snap:"
    _MANIFEST    = "snap_manifest"   # JSON list of {height, state_root, size}

    def __init__(self, storage: 'Storage'):
        self._storage       = storage
        self._last_snap_h   = -1
        self._snap_lock     = threading.Lock()

    # ── Public: trigger point ─────────────────────────────────────────────────
    def maybe_snapshot(self, height: int, state_root: str, state_lock=None):
        """
        Called after every apply_block.  Spawns a snapshot daemon thread when
        height is a multiple of SNAPSHOT_INTERVAL.
        """
        if not Config.SNAPSHOT_ENABLED:
            return
        if height <= 0 or (height % Config.SNAPSHOT_INTERVAL) != 0:
            return
        if height == self._last_snap_h:
            return
        threading.Thread(
            target=self._create_snapshot,
            args=(height, state_root, state_lock),
            daemon=True,
            name=f"snap-{height}",
        ).start()

    # ── Snapshot creation ─────────────────────────────────────────────────────
    def _create_snapshot(self, height: int, state_root: str, state_lock=None):
        """Background thread: capture state at `height` atomically, then compress/store it."""
        with self._snap_lock:
            if height == self._last_snap_h:
                return   # raced with another thread for the same height
            try:
                # apply_block mutates state before committing the block/header.
                # Capture while Blockchain's writer lock is held so a snapshot
                # can never combine the state of height H+1 with H's header.
                if state_lock is not None:
                    with state_lock:
                        if self._storage.chain_height() != height:
                            log.info(
                                "StateSnapshotEngine: skipping height=%d; "
                                "canonical height is %d", height, self._storage.chain_height())
                            return
                        raw = self._serialise_state(height, state_root, compress=False)
                else:
                    if self._storage.chain_height() != height:
                        log.info(
                            "StateSnapshotEngine: skipping height=%d; canonical height is %d",
                            height, self._storage.chain_height())
                        return
                    raw = self._serialise_state(height, state_root, compress=False)
                if raw is None:
                    return
                blob = zlib.compress(raw, level=9)
                if blob is None:
                    return
                key = f"{self._KEY_PREFIX}{height}"
                # Store as hex string so set_meta (text column) can hold it
                self._storage.set_meta(key, blob.hex())
                self._last_snap_h = height
                header = self._storage.get_block_header(height) or {}
                self._update_manifest(
                    height, state_root, len(blob), str(header.get("block_hash", ""))
                )
                self._evict_old_snapshots(height)
                log.info(
                    f"StateSnapshotEngine: snapshot created at height={height} "
                    f"size={len(blob):,}B state_root={state_root[:16]}..."
                )
                metrics.inc("snapshots_created")
                metrics.set_gauge("last_snapshot_height", float(height))
            except Exception as e:
                log.warning("StateSnapshotEngine: create error at %d: %s", height, e)

    def _serialise_state(self, height: int, state_root: str,
                         compress: bool = True) -> Optional[bytes]:
        """Dump an authenticated complete state snapshot.

        A snapshot is only created for a locally persisted canonical block whose
        header commits the same ``state_root``.  The payload also carries the
        anchor block hash and every state component needed for a local restore.
        """
        try:
            if not isinstance(height, int) or height <= 0 or not state_root:
                raise ValueError("invalid snapshot height/state_root")

            header = self._storage.get_block_header(height)
            if not header:
                raise ValueError(f"canonical block header {height} is unavailable")
            anchor_hash = str(header.get("block_hash", ""))
            anchor_root = str(header.get("state_root", ""))
            if not anchor_hash or not anchor_root or anchor_root != state_root:
                raise ValueError(
                    f"snapshot anchor mismatch at {height}: "
                    f"header_root={anchor_root[:16]}... supplied_root={state_root[:16]}..."
                )

            pgx = self._storage._pgx_enabled

            # Balances + nonces
            if pgx:
                rows = self._storage._pg_fetch(
                    "SELECT address, balance_sat, nonce FROM accounts ORDER BY convert_to(address, 'UTF8') ASC", [])
                balances = {r["address"]: int(r["balance_sat"]) for r in rows if r["address"]}
                nonces = {r["address"]: int(r["nonce"]) for r in rows if r["address"]}
            else:
                c = self._storage._conn()
                bal_rows = c.execute(
                    "SELECT address, balance FROM balances ORDER BY CAST(address AS BLOB) ASC"
                ).fetchall()
                balances = {r["address"]: int(round(float(r["balance"]))) for r in bal_rows if r["address"]}
                try:
                    nonce_rows = c.execute(
                        "SELECT address, nonce FROM account_nonces ORDER BY CAST(address AS BLOB) ASC"
                    ).fetchall()
                    nonces = {r["address"]: int(r["nonce"]) for r in nonce_rows if r["address"]}
                except Exception:
                    nonces = {}

            # Contract accounts
            if pgx:
                con_rows = self._storage._pg_fetch(
                    """SELECT address, code_hash, storage_root, nonce,
                              creator, created_at, contract_name
                         FROM contract_accounts
                        WHERE destroyed = FALSE
                        ORDER BY convert_to(address, 'UTF8') ASC""", [])
            else:
                con_rows = self._storage._conn().execute(
                    """SELECT address, code_hash, storage_root, nonce,
                              creator, created_at, contract_name
                         FROM contract_accounts
                        WHERE destroyed=0
                        ORDER BY CAST(address AS BLOB) ASC"""
                ).fetchall()
            contracts = {
                r["address"]: {
                    "code_hash": r["code_hash"] or "",
                    "storage_root": r["storage_root"] or "",
                    "nonce": int(r["nonce"] or 0),
                    "creator": r["creator"] or "",
                    "created_at": int(r["created_at"] or 0),
                    "name": r["contract_name"] or "",
                }
                for r in con_rows if r["address"]
            }

            # Contract bytecode + storage are canonical state and are required
            # to make a trusted local snapshot complete.
            contract_code = {}
            contract_storage = {}
            contract_storage_tags = {}
            for addr, ct in contracts.items():
                code_hash = ct.get("code_hash", "")
                if code_hash:
                    code = self._storage.get_contract_code(code_hash)
                    if code is None:
                        raise ValueError(
                            f"missing bytecode for live contract {addr[:16]} ({code_hash[:16]})"
                        )
                    if hashlib.sha256(code).hexdigest() != code_hash:
                        raise ValueError(
                            f"contract bytecode hash mismatch for {addr[:16]}"
                        )
                    contract_code[code_hash] = code.hex()
                slots = self._storage.get_all_contract_slots(addr)
                contract_storage[addr] = {
                    str(k): str(v) for k, v in sorted(slots.items(), key=lambda kv: kv[0].encode("utf-8"))
                }
                tags = self._storage.get_all_contract_storage_tags(addr)
                contract_storage_tags[addr] = {
                    str(k): int(v) for k, v in sorted(tags.items(), key=lambda kv: kv[0].encode("utf-8"))
                    if 1 <= int(v) <= 7
                }

            # Roles / validators, including registration timestamp.
            if pgx:
                role_rows = self._storage._pg_fetch(
                    """SELECT address, role, stake_sat, score, slashed, registered_at
                         FROM validators ORDER BY convert_to(address, 'UTF8') ASC""", [])
                roles = {
                    r["address"]: {
                        "role": r["role"] or "",
                        "stake_sat": int(r["stake_sat"] or 0),
                        "score": float(r["score"] or 0),
                        "slashed": 1 if r["slashed"] else 0,
                        "registered_at": int(r["registered_at"] or 0),
                    }
                    for r in role_rows if r["address"]
                }
            else:
                role_rows = self._storage._conn().execute(
                    """SELECT address, role, stake, score, slashed, registered_at
                         FROM roles ORDER BY CAST(address AS BLOB) ASC"""
                ).fetchall()
                roles = {
                    r["address"]: {
                        "role": r["role"] or "",
                        "stake_sat": int(round(float(r["stake"] or 0) * Config.SATOSHI_PER_VSD)),
                        "score": float(r["score"] or 0),
                        "slashed": int(r["slashed"] or 0),
                        "registered_at": int(r["registered_at"] or 0),
                    }
                    for r in role_rows if r["address"]
                }

            # Name ownership
            if pgx:
                claim_rows = self._storage._pg_fetch(
                    """SELECT user_id, wallet_addr, pub_hex, registered_height, tx_id
                         FROM name_claims ORDER BY convert_to(user_id, 'UTF8') ASC""", [])
            else:
                claim_rows = self._storage._conn().execute(
                    """SELECT user_id, wallet_addr, pub_hex, registered_height, tx_id
                         FROM name_claims ORDER BY CAST(user_id AS BLOB) ASC"""
                ).fetchall()
            name_claims = {
                r["user_id"]: {
                    "wallet_addr": r["wallet_addr"],
                    "pub_hex": r["pub_hex"],
                    "registered_height": int(r["registered_height"]),
                    "tx_id": r["tx_id"],
                }
                for r in claim_rows if r["user_id"]
            }

            # Native state channels are canonical lifecycle state.
            if pgx:
                channel_rows = self._storage._pg_fetch(
                    "SELECT * FROM state_channels ORDER BY channel_id", [])
            else:
                channel_rows = self._storage._conn().execute(
                    "SELECT * FROM state_channels ORDER BY CAST(channel_id AS BLOB) ASC"
                ).fetchall()
            state_channels = {
                r["channel_id"]: {
                    "contract_addr": r["contract_addr"] or "",
                    "opener": r["opener"] or "",
                    "counterparty": r["counterparty"] or "",
                    "total_deposit_sat": int(r["total_deposit_sat"] or 0),
                    "opener_deposit_sat": int(r["opener_deposit_sat"] or 0),
                    "timeout_blocks": int(r["timeout_blocks"] or 0),
                    "open_height": int(r["open_height"] or 0),
                    "status": r["status"] or "OPEN",
                    "dispute_seq": int(r["dispute_seq"] or 0),
                    "dispute_bal_opener": int(r["dispute_bal_opener"] or 0),
                    "dispute_bal_counter": int(r["dispute_bal_counter"] or 0),
                    "dispute_height": int(r["dispute_height"] or 0),
                    "closed_height": int(r["closed_height"] or 0),
                }
                for r in channel_rows if r["channel_id"]
            }

            payload = {
                "version": 3,
                "height": height,
                "anchor_block_hash": anchor_hash,
                "state_root": state_root,
                "balances": balances,
                "nonces": nonces,
                "contracts": contracts,
                "contract_code": contract_code,
                "contract_storage": contract_storage,
                "contract_storage_tags": contract_storage_tags,
                "roles": roles,
                "name_claims": name_claims,
                "state_channels": state_channels,
            }
            raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            if len(raw) > Config.SNAPSHOT_MAX_UNCOMPRESSED_BYTES:
                raise ValueError(
                    f"snapshot payload too large: {len(raw)} > {Config.SNAPSHOT_MAX_UNCOMPRESSED_BYTES}"
                )
            return zlib.compress(raw, level=9) if compress else raw
        except Exception as e:
            log.warning("StateSnapshotEngine: serialise error: %s", e)
            return None

    # ── Manifest helpers ──────────────────────────────────────────────────────
    def _update_manifest(self, height: int, state_root: str, size: int,
                         anchor_block_hash: str = ""):
        """Maintain a JSON list of available snapshots in node_meta."""
        try:
            raw = self._storage.get_meta(self._MANIFEST)
            manifest = json.loads(raw) if raw else []
        except Exception:
            manifest = []
        # Remove any existing entry for this height
        manifest = [e for e in manifest if e.get("height") != height]
        manifest.append({
            "height": height, "state_root": state_root, "size": size,
            "anchor_block_hash": anchor_block_hash,
        })
        manifest.sort(key=lambda e: e["height"])
        self._storage.set_meta(self._MANIFEST, json.dumps(manifest))

    def _evict_old_snapshots(self, current_height: int):
        """Keep only the most recent SNAPSHOT_KEEP snapshots."""
        try:
            raw = self._storage.get_meta(self._MANIFEST)
            if not raw:
                return
            manifest = json.loads(raw)
        except Exception:
            return
        if len(manifest) <= Config.SNAPSHOT_KEEP:
            return
        to_evict = manifest[: len(manifest) - Config.SNAPSHOT_KEEP]
        for entry in to_evict:
            h = entry.get("height", -1)
            if h >= 0:
                try:
                    c = self._storage._conn()
                    c.execute("DELETE FROM node_meta WHERE key=?",
                              (f"{self._KEY_PREFIX}{h}",))
                    c.commit()
                except Exception:
                    pass
        # Update manifest
        manifest = manifest[len(to_evict):]
        self._storage.set_meta(self._MANIFEST, json.dumps(manifest))

    # ── Retrieval for P2P serving ─────────────────────────────────────────────
    def get_manifest(self) -> list:
        """Return list of available snapshot entries."""
        try:
            raw = self._storage.get_meta(self._MANIFEST)
            return json.loads(raw) if raw else []
        except Exception:
            return []

    def get_snapshot_blob(self, height: int) -> Optional[bytes]:
        """Return raw compressed bytes for snapshot at `height`, or None."""
        try:
            hex_val = self._storage.get_meta(f"{self._KEY_PREFIX}{height}")
            if hex_val:
                return bytes.fromhex(hex_val)
        except Exception:
            pass
        return None

    def latest_snapshot_height(self) -> int:
        """Return height of the most recent available snapshot, or -1."""
        manifest = self.get_manifest()
        if not manifest:
            return -1
        return manifest[-1]["height"]

    # ── Restoration (fast-sync receiver side) ─────────────────────────────────
    def restore_from_blob(self, blob: bytes, expected_state_root: str,
                          trusted_anchor: Optional[dict] = None) -> Tuple[bool, str]:
        """Safely inspect a snapshot without trusting an unverified peer.

        A peer snapshot is never allowed to replace canonical consensus state.
        For the current protocol, the only safe restore point is a node that
        already possesses the exact canonical block at the snapshot height. In
        that case we compare the complete snapshot payload with a locally
        serialised snapshot and accept only an exact match; no remote bytes are
        written into consensus storage. Nodes behind the anchor simply fall
        back to ordinary block sync.
        """
        try:
            if not blob:
                return False, "empty snapshot blob"
            raw = bounded_zlib_decompress(blob, Config.SNAPSHOT_MAX_UNCOMPRESSED_BYTES)
            payload = json.loads(raw.decode("utf-8"))
        except Exception as e:
            return False, f"Snapshot decompression/parse failed: {e}"

        if not isinstance(payload, dict):
            return False, "snapshot payload is not an object"
        if int(payload.get("version", 0)) < 2:
            return False, "unsupported/legacy snapshot format"

        if not expected_state_root:
            return False, "snapshot restore requires a non-empty expected_state_root"
        snap_root = str(payload.get("state_root", ""))
        if snap_root != expected_state_root:
            return False, (
                f"state_root mismatch: expected={expected_state_root[:16]}... "
                f"got={snap_root[:16]}..."
            )

        snap_height = int(payload.get("height", -1))
        anchor_hash = str(payload.get("anchor_block_hash", ""))
        if snap_height < 0 or not anchor_hash:
            return False, "snapshot has no authenticated canonical anchor"
        if not isinstance(trusted_anchor, dict):
            return False, "untrusted snapshot: local canonical anchor is required"
        try:
            ta_height = int(trusted_anchor.get("height", -1))
        except Exception:
            ta_height = -1
        ta_hash = str(trusted_anchor.get("block_hash", ""))
        ta_root = str(trusted_anchor.get("state_root", ""))
        if ta_height != snap_height or ta_hash != anchor_hash or ta_root != snap_root:
            return False, "snapshot anchor does not match supplied local anchor"

        local_height = self._storage.chain_height()
        if local_height != snap_height:
            return False, (
                f"snapshot at height {snap_height} cannot be restored on local "
                f"height {local_height}; full block sync is required"
            )
        local_header = self._storage.get_block_header(snap_height)
        if not local_header:
            return False, "local canonical anchor header is unavailable"
        if (str(local_header.get("block_hash", "")) != anchor_hash
                or str(local_header.get("state_root", "")) != snap_root):
            return False, "local canonical anchor does not match snapshot"

        # The full state root currently commits balances/contracts/name mapping,
        # not every auxiliary consensus table.  Therefore root equality alone
        # is insufficient to authenticate a remote snapshot.  Compare the whole
        # payload to a locally reconstructed canonical snapshot before accepting.
        local_blob = self._serialise_state(snap_height, snap_root)
        if local_blob is None:
            return False, "unable to reconstruct local canonical snapshot"
        try:
            local_payload = json.loads(
                bounded_zlib_decompress(
                    local_blob, Config.SNAPSHOT_MAX_UNCOMPRESSED_BYTES
                ).decode("utf-8")
            )
        except Exception as e:
            return False, f"local snapshot reconstruction failed: {e}"

        if local_payload != payload:
            return False, "remote snapshot state does not exactly match local canonical state"

        with self._snap_lock:
            self._storage.set_meta("snap_restored_height", str(snap_height))
            self._storage.set_meta("snap_restored_root", snap_root)
            metrics.inc("snapshots_restored")
        log.info(
            "StateSnapshotEngine: verified canonical snapshot at height=%d; "
            "no remote state write was necessary", snap_height
        )
        return True, "OK (canonical state already present)"

    # ── v7.5.0: Chunk-based serving ───────────────────────────────────────────

    def _chunk_size(self) -> int:
        """Return the configured chunk size in bytes."""
        return Config.SNAPSHOT_CHUNK_SIZE

    def get_chunk_manifest(self, height: int) -> Optional[dict]:
        """
        Return a chunk manifest dict for an available snapshot at ``height``.

        Manifest format::

            {
                "height":       <int>,
                "total_chunks": <int>,
                "chunk_hashes": ["<sha256_hex>", ...],
                "state_root":   "<str>",
                "total_size":   <int>,
            }

        Returns None if the snapshot is not available.
        """
        blob = self.get_snapshot_blob(height)
        if blob is None:
            return None
        chunk_sz     = self._chunk_size()
        chunks       = [blob[i:i + chunk_sz] for i in range(0, len(blob), chunk_sz)]
        chunk_hashes = [hashlib.sha256(c).hexdigest() for c in chunks]
        state_root = ""
        anchor_block_hash = ""
        for entry in self.get_manifest():
            if entry.get("height") == height:
                state_root = entry.get("state_root", "")
                anchor_block_hash = entry.get("anchor_block_hash", "")
                break
        return {
            "height":       height,
            "total_chunks": len(chunks),
            "chunk_hashes": chunk_hashes,
            "state_root":   state_root,
            "anchor_block_hash": anchor_block_hash,
            "total_size":   len(blob),
        }

    def get_chunk(self, height: int, chunk_index: int) -> Optional[bytes]:
        """Return raw bytes for a single chunk of the snapshot at ``height``."""
        blob = self.get_snapshot_blob(height)
        if blob is None:
            return None
        chunk_sz = self._chunk_size()
        offset   = chunk_index * chunk_sz
        if offset >= len(blob):
            return None
        return blob[offset: offset + chunk_sz]
