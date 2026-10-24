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

    def __init__(self, storage: 'Storage', rolling_pruner=None):
        self._storage       = storage
        self._rolling_pruner = rolling_pruner
        self._last_snap_h   = -1
        self._snap_lock     = threading.Lock()

    # ── Public: trigger point ─────────────────────────────────────────────────
    def maybe_snapshot(self, height: int, state_root: str, state_lock=None):
        """
        Called after every apply_block.  Spawns a snapshot daemon thread when
        height is a multiple of SNAPSHOT_INTERVAL.
        """
        bootstrap_anchor = (
            int(height) > 0
            and int(height) % int(Config.BOOTSTRAP_SNAPSHOT_INTERVAL) == 0
        )
        regular_anchor = (
            bool(Config.SNAPSHOT_ENABLED)
            and int(height) > 0
            and int(height) % int(Config.SNAPSHOT_INTERVAL) == 0
        )
        # When rolling pruning is enabled, consensus bootstrap anchors must be
        # generated even if the optional general-purpose snapshot feature was
        # disabled by an operator.  Otherwise that node could prune history it
        # can no longer help newcomers replace.
        if not regular_anchor and not (Config.ROLLING_PRUNE_ENABLED and bootstrap_anchor):
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
                    height, state_root, len(blob), str(header.get("block_hash", "")),
                    bootstrap_digest=hashlib.sha256(raw).hexdigest(),
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

            # Permanent replay protection is consensus-relevant after a
            # snapshot jump.  Without it, a fresh node could accept and apply a
            # transaction that was already confirmed before the snapshot.
            if pgx:
                replay_rows = self._storage._pg_fetch(
                    "SELECT tx_id FROM tx_replay_guard ORDER BY convert_to(tx_id, 'UTF8') ASC", [])
                replay_guard = [str(r["tx_id"]) for r in replay_rows if r.get("tx_id")]
            else:
                replay_rows = self._storage._conn().execute(
                    "SELECT tx_id FROM tx_replay_guard ORDER BY CAST(tx_id AS BLOB) ASC"
                ).fetchall()
                replay_guard = [str(r["tx_id"]) for r in replay_rows if r["tx_id"]]

            # Layer-2 current state is future-consensus-relevant but is stored
            # in node_meta rather than the L1 state-root.  Commit the current
            # tree and last accepted batch id, not the rollback history (which
            # is local recovery metadata and can legitimately differ).
            try:
                l2_tree = json.loads(self._storage.get_meta("l2_tree") or "{}")
            except Exception:
                l2_tree = {}
            try:
                l2_last_batch_id = int(self._storage.get_meta("l2_last_batch_id") or -1)
            except Exception:
                l2_last_batch_id = -1

            # Governance proposal state can change future block-version
            # validity.  Commit only deterministic lifecycle fields; wall-clock
            # created_at/updated_at values are intentionally excluded.
            governance_proposals = []
            for _row in self._storage.get_all_upgrade_proposals():
                governance_proposals.append({
                    "version": int(_row.get("version", 0)),
                    "phase": str(_row.get("phase", "DORMANT")),
                    "signal_start_height": int(_row.get("signal_start_height", 0)),
                    "signal_end_height": int(_row.get("signal_end_height", 0)),
                    "lock_in_height": int(_row.get("lock_in_height", 0)),
                    "activation_height": int(_row.get("activation_height", 0)),
                    # Decimal string avoids backend/JSON float formatting being
                    # part of the consensus commitment. Restore converts it back.
                    "threshold": format(float(_row.get("threshold", 0.75)), ".17g"),
                    "rollback_window": int(_row.get("rollback_window", 0)),
                    "disabled": 1 if bool(_row.get("disabled", 0)) else 0,
                })
            governance_proposals.sort(key=lambda x: x["version"])

            # Cumulative new issuance is used by the monetary-supply rules and
            # must survive a history-skipping bootstrap exactly.
            cumulative_issued_sat = int(self._storage.get_cumulative_issued_sat())

            payload = {
                "version": 4,
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
                "tx_replay_guard": replay_guard,
                "l2_tree": l2_tree,
                "l2_last_batch_id": l2_last_batch_id,
                "cumulative_issued_sat": cumulative_issued_sat,
                "governance_proposals": governance_proposals,
            }
            # Canonical JSON bytes are the object committed by the next
            # bootstrap-commitment block.  sort_keys + compact separators make
            # the digest independent of database row iteration order.
            raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            if len(raw) > Config.SNAPSHOT_MAX_UNCOMPRESSED_BYTES:
                raise ValueError(
                    f"snapshot payload too large: {len(raw)} > {Config.SNAPSHOT_MAX_UNCOMPRESSED_BYTES}"
                )
            return zlib.compress(raw, level=9) if compress else raw
        except Exception as e:
            log.warning("StateSnapshotEngine: serialise error: %s", e)
            return None

    def compute_bootstrap_digest(self, height: int, state_root: str) -> Tuple[Optional[str], Optional[bytes], str]:
        """Return the deterministic complete-state digest for ``height``.

        The digest is SHA-256 over the *uncompressed canonical JSON bytes* so
        it is independent of zlib implementation/version.  This function has
        no persistent side effects and is therefore safe to call from block
        validation: every honest validator recomputes the same value from its
        canonical pre-block state.
        """
        raw = self._serialise_state(int(height), str(state_root), compress=False)
        if raw is None:
            return None, None, "unable to serialise deterministic bootstrap state"
        return hashlib.sha256(raw).hexdigest(), raw, "OK"

    def ensure_bootstrap_snapshot(self, height: int, state_root: str) -> Tuple[Optional[str], str]:
        """Synchronously ensure an authenticated bootstrap snapshot is stored.

        Candidate construction calls this at consensus snapshot boundaries.
        The snapshot is persisted before the following block commits to its
        digest, preventing a node from mining an otherwise-valid commitment
        and then being unable to serve the corresponding state to newcomers.
        """
        digest, raw, err = self.compute_bootstrap_digest(height, state_root)
        if digest is None or raw is None:
            return None, err
        try:
            blob = zlib.compress(raw, level=9)
            with self._snap_lock:
                self._storage.set_meta(f"{self._KEY_PREFIX}{int(height)}", blob.hex())
                header = self._storage.get_block_header(int(height)) or {}
                self._update_manifest(
                    int(height), str(state_root), len(blob),
                    str(header.get("block_hash", "")),
                    bootstrap_digest=digest,
                )
                self._last_snap_h = int(height)
                self._evict_old_snapshots(int(height))
            return digest, "OK"
        except Exception as exc:
            return None, f"failed to persist bootstrap snapshot: {exc}"

    # ── Manifest helpers ──────────────────────────────────────────────────────
    def _update_manifest(self, height: int, state_root: str, size: int,
                         anchor_block_hash: str = "",
                         bootstrap_digest: str = ""):
        """Maintain a JSON list of available snapshots in node_meta."""
        try:
            raw = self._storage.get_meta(self._MANIFEST)
            manifest = json.loads(raw) if raw else []
        except Exception:
            manifest = []
        # Remove any existing entry for this height
        manifest = [e for e in manifest if e.get("height") != height]
        entry = {
            "height": height, "state_root": state_root, "size": size,
            "anchor_block_hash": anchor_block_hash,
        }
        if bootstrap_digest:
            entry["bootstrap_digest"] = bootstrap_digest
        manifest.append(entry)
        manifest.sort(key=lambda e: e["height"])
        self._storage.set_meta(self._MANIFEST, json.dumps(manifest))

    def _evict_old_snapshots(self, current_height: int):
        """Evict snapshots without breaking pruning/rollback recoverability.

        A fixed ``SNAPSHOT_KEEP`` count is insufficient when the rolling-prune
        window spans more snapshot intervals: an anchor that will be needed as
        the prune boundary advances can be deleted before it becomes the active
        floor.  Keep:
          * the configured newest ``SNAPSHOT_KEEP`` entries;
          * every snapshot inside the current rolling rollback horizon; and
          * the newest snapshot immediately before that horizon.

        This remains bounded by roughly ``window / interval + keep + 1`` and
        guarantees the pruner always has the authenticated anchor ladder needed
        to advance safely.
        """
        try:
            raw = self._storage.get_meta(self._MANIFEST)
            if not raw:
                return
            manifest = json.loads(raw)
        except Exception:
            return
        if not isinstance(manifest, list) or not manifest:
            return
        manifest = [e for e in manifest if isinstance(e, dict) and "height" in e]
        manifest.sort(key=lambda e: int(e.get("height", -1)))
        keep_count = max(1, int(Config.SNAPSHOT_KEEP))
        keep_heights = {int(e["height"]) for e in manifest[-keep_count:]}

        if Config.ROLLING_PRUNE_ENABLED:
            threshold = max(0, int(current_height) - int(Config.ROLLING_PRUNE_WINDOW))
            below = []
            for e in manifest:
                h = int(e.get("height", -1))
                if h >= threshold:
                    keep_heights.add(h)
                elif h >= 0:
                    below.append(h)
            if below:
                keep_heights.add(max(below))

        kept = []
        for entry in manifest:
            h = int(entry.get("height", -1))
            if h in keep_heights:
                kept.append(entry)
                continue
            try:
                key = f"{self._KEY_PREFIX}{h}"
                if self._storage._pgx_enabled:
                    self._storage._pg_exec("DELETE FROM node_meta WHERE key=$1", key)
                else:
                    c = self._storage._conn()
                    c.execute("DELETE FROM node_meta WHERE key=?", (key,))
                    c.commit()
            except Exception as exc:
                # Fail closed: if blob deletion is uncertain, retain the manifest
                # entry so maintenance can retry instead of silently orphaning it.
                log.warning(
                    "StateSnapshotEngine: snapshot eviction failed h=%d: %s", h, exc)
                kept.append(entry)
        kept.sort(key=lambda e: int(e.get("height", -1)))
        self._storage.set_meta(self._MANIFEST, json.dumps(kept))

    # ── Retrieval for P2P serving ─────────────────────────────────────────────
    def get_manifest(self) -> list:
        """Return the locally persisted snapshot manifest."""
        try:
            raw = self._storage.get_meta(self._MANIFEST)
            return json.loads(raw) if raw else []
        except Exception:
            return []

    def get_servable_manifest(self) -> list:
        """Return only snapshots that this *current* canonical tip can serve.

        A snapshot at H is bootstrap-authenticated by the commitment in H+1,
        so a rolled-back node whose tip is <= H must never advertise it even if
        stale metadata or a cached blob remains on disk.  Requiring the blob and
        both canonical headers also makes serving fail closed after partial
        metadata corruption.
        """
        try:
            tip = int(self._storage.chain_height())
        except Exception:
            return []
        out = []
        for entry in self.get_manifest():
            if not isinstance(entry, dict) or not entry.get("bootstrap_digest"):
                continue
            try:
                h = int(entry.get("height", -1))
            except (TypeError, ValueError):
                continue
            if h <= 0 or h + 1 > tip:
                continue
            if self.get_snapshot_blob(h) is None:
                continue
            try:
                if not self._storage.get_block_header(h) or not self._storage.get_block_header(h + 1):
                    continue
            except Exception:
                continue
            out.append(entry)
        out.sort(key=lambda e: int(e.get("height", -1)))
        return out

    def invalidate_snapshots_above(self, height: int) -> None:
        """Remove cached/created snapshots that are no longer on the local tip.

        Rollback changes canonical history availability.  Keeping a snapshot
        above the new tip would make this node advertise state it can no longer
        authenticate with a local H+1 commitment.
        """
        cutoff = int(height)
        with self._snap_lock:
            manifest = self.get_manifest()
            kept = []
            for entry in manifest:
                try:
                    h = int(entry.get("height", -1))
                except Exception:
                    continue
                if h > cutoff:
                    key = f"{self._KEY_PREFIX}{h}"
                    try:
                        if self._storage._pgx_enabled:
                            self._storage._pg_exec("DELETE FROM node_meta WHERE key=$1", key)
                        else:
                            c = self._storage._conn()
                            c.execute("DELETE FROM node_meta WHERE key=?", (key,))
                            c.commit()
                    except Exception as exc:
                        log.warning("StateSnapshotEngine: failed deleting stale snapshot %d: %s", h, exc)
                else:
                    kept.append(entry)
            kept.sort(key=lambda e: int(e.get("height", -1)))
            self._storage.set_meta(self._MANIFEST, json.dumps(kept))
            self._last_snap_h = int(kept[-1]["height"]) if kept else -1

            for h_key, r_key in (("snap_restored_height", "snap_restored_root"),
                                 ("bootstrap_checkpoint_height", "bootstrap_checkpoint_hash")):
                try:
                    raw = self._storage.get_meta(h_key)
                    if raw not in (None, "") and int(raw) > cutoff:
                        self._storage.set_meta(h_key, "")
                        self._storage.set_meta(r_key, "")
                except Exception:
                    pass

    def get_snapshot_blob(self, height: int) -> Optional[bytes]:
        """Return raw compressed bytes for snapshot at `height`, or None."""
        try:
            hex_val = self._storage.get_meta(f"{self._KEY_PREFIX}{height}")
            if hex_val:
                return bytes.fromhex(hex_val)
        except Exception:
            pass
        return None

    def is_snapshot_servable(self, height: int) -> bool:
        """Return True only when ``height`` is authenticated by this tip.

        A cached blob alone is not enough: the current canonical chain must
        still contain both H and H+1, and the manifest entry must carry the
        committed bootstrap digest.  Direct snapshot/chunk requests use this
        guard too, so callers cannot bypass manifest filtering by guessing a
        stale rollback height.
        """
        try:
            want = int(height)
        except Exception:
            return False
        return any(
            isinstance(e, dict) and int(e.get("height", -1)) == want
            for e in self.get_servable_manifest()
        )

    def latest_servable_snapshot_height(self) -> int:
        manifest = self.get_servable_manifest()
        return int(manifest[-1]["height"]) if manifest else -1

    def latest_snapshot_height(self) -> int:
        """Return height of the most recent cached snapshot, or -1.

        Network serving must use ``latest_servable_snapshot_height`` instead.
        This raw helper remains for local maintenance/diagnostics.
        """
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

    def restore_authenticated_bootstrap(self, blob: bytes, expected_digest: str,
                                        verified_headers: list, *,
                                        allow_same_height_repair: bool = False
                                        ) -> Tuple[bool, str]:
        """Install a fresh-node snapshot authenticated by a verified PoW chain.

        ``verified_headers`` must contain the already-verified transport records
        for heights 0..snapshot_height+1.  Height H+1 is the commitment block;
        only 0..H are installed because the snapshot itself represents state at
        H.  The caller must independently verify the H+1 coinbase Merkle proof
        and pass its exact committed digest as ``expected_digest``.

        This operation may also fast-forward a stale/behind node whose next
        required full block body has already been pruned. It can repair state
        at the same height only when the caller explicitly enables that mode
        after a bootstrap-commitment validation failure. In every mode, every
        local block hash through the current local height must exactly match
        the independently verified PoW header chain. A same-height repair does
        not replace canonical headers or reorg the chain; it replaces only the
        state represented by the authenticated snapshot.
        """
        if not blob or not expected_digest:
            return False, "authenticated bootstrap requires snapshot bytes and digest"
        try:
            raw = bounded_zlib_decompress(blob, Config.SNAPSHOT_MAX_UNCOMPRESSED_BYTES)
        except Exception as exc:
            return False, f"bootstrap snapshot decompression failed: {exc}"
        actual_digest = hashlib.sha256(raw).hexdigest()
        if actual_digest != str(expected_digest):
            return False, (
                f"bootstrap snapshot digest mismatch: committed={str(expected_digest)[:16]}... "
                f"received={actual_digest[:16]}...")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            return False, f"bootstrap snapshot parse failed: {exc}"
        if not isinstance(payload, dict) or int(payload.get("version", 0)) < 4:
            return False, "bootstrap snapshot is not complete format v4+"
        try:
            snap_h = int(payload.get("height", -1))
        except Exception:
            return False, "bootstrap snapshot height is invalid"
        if snap_h <= 0:
            return False, "bootstrap snapshot height must be positive"
        local_h = int(self._storage.chain_height())
        same_height_repair = bool(allow_same_height_repair and local_h == snap_h)
        if local_h > snap_h or (local_h == snap_h and not same_height_repair):
            return False, (
                f"authenticated bootstrap snapshot must be ahead of local tip "
                f"unless explicit same-height repair is enabled; "
                f"local height={local_h}, snapshot height={snap_h}")
        if not isinstance(verified_headers, list) or len(verified_headers) <= snap_h + 1:
            return False, "verified bootstrap header chain is incomplete"

        # A non-fresh node may use an authenticated snapshot only as a strict
        # fast-forward of its existing canonical chain.  Bind every locally
        # applied height to the verified PoW chain before any state/header
        # mutation.  This prevents a peer snapshot from becoming an implicit
        # reorg or chain replacement mechanism.
        try:
            for _h in range(0, local_h + 1):
                _local = self._storage.get_block(_h)
                if _local is None:
                    return False, f"local canonical chain has a gap at height {_h}"
                _remote = verified_headers[_h]
                if int(_remote.get("index", -1)) != _h:
                    return False, f"verified bootstrap header index mismatch at height {_h}"
                if str(getattr(_local, "block_hash", "")) != str(_remote.get("block_hash", "")):
                    return False, (
                        f"authenticated bootstrap is not a fast-forward: "
                        f"local/verified hash mismatch at height {_h}")
        except Exception as exc:
            return False, f"failed to verify local canonical prefix: {exc}"
        try:
            anchor = verified_headers[snap_h]
            commit_block = verified_headers[snap_h + 1]
            if int(anchor.get("index", -1)) != snap_h:
                return False, "verified snapshot anchor height mismatch"
            if int(commit_block.get("index", -1)) != snap_h + 1:
                return False, "verified snapshot commitment block missing"
            if str(payload.get("anchor_block_hash", "")) != str(anchor.get("block_hash", "")):
                return False, "snapshot anchor block hash does not match verified chain"
            if str(payload.get("state_root", "")) != str(anchor.get("state_root", "")):
                return False, "snapshot state_root does not match verified chain"
        except Exception as exc:
            return False, f"invalid verified bootstrap headers: {exc}"

        replay = payload.get("tx_replay_guard", [])
        if not isinstance(replay, list) or any(not isinstance(x, str) or not x for x in replay):
            return False, "snapshot replay guard is malformed"
        if len(replay) != len(set(replay)):
            return False, "snapshot replay guard contains duplicates"
        l2_tree = payload.get("l2_tree", {})
        if not isinstance(l2_tree, dict):
            return False, "snapshot L2 tree is malformed"
        governance = payload.get("governance_proposals", [])
        if not isinstance(governance, list):
            return False, "snapshot governance state is malformed"
        try:
            _seen_gov = set()
            for _g in governance:
                if not isinstance(_g, dict):
                    raise ValueError("proposal is not an object")
                _v = int(_g.get("version", -1))
                if _v < 0 or _v in _seen_gov:
                    raise ValueError("invalid/duplicate proposal version")
                _seen_gov.add(_v)
                float(str(_g.get("threshold", "0.75")))
                int(_g.get("rollback_window", 0))
        except Exception as exc:
            return False, f"snapshot governance metadata invalid: {exc}"
        try:
            l2_last_batch = int(payload.get("l2_last_batch_id", -1))
            cumulative = int(payload.get("cumulative_issued_sat", -1))
            if cumulative < 0:
                raise ValueError("negative issuance")
        except Exception as exc:
            return False, f"snapshot monetary/L2 metadata invalid: {exc}"

        # Write a durable marker before the multi-store installation.  A crash
        # can therefore never be mistaken for a completed bootstrap.  The
        # operation is idempotent for a fresh node and can be retried.
        self._storage.set_meta("bootstrap_restore_in_progress", str(snap_h))
        installed = []
        try:
            from visold.ledger.block import Block

            # Install only authenticated header-only history through H.  Never
            # trust peer finality signatures: the header verifier strips them.
            for h in range(local_h + 1, snap_h + 1):
                d = dict(verified_headers[h])
                d["transactions"] = []
                d["pruned"] = True
                d["finalized"] = False
                d["validator_sigs"] = []
                blk = Block.from_dict(d)
                self._storage.save_block(blk)
                installed.append(h)

            # Replace all canonical execution state from the digest-authenticated
            # payload, then restore state components intentionally kept outside
            # the legacy L1 state_root.
            self._storage.restore_snapshot_state(payload)

            if self._storage._pgx_enabled:
                self._storage._pg_exec("DELETE FROM tx_replay_guard")
                if replay:
                    async def _fill_replay():
                        async with self._storage._pg._pool.acquire() as c:
                            await c.executemany(
                                "INSERT INTO tx_replay_guard (tx_id) VALUES ($1) ON CONFLICT DO NOTHING",
                                [(x,) for x in replay])
                    self._storage._pg.run(_fill_replay())
            else:
                c = self._storage._conn()
                with self._storage._sqlite_api_lock:
                    c.execute("CREATE TABLE IF NOT EXISTS tx_replay_guard (tx_id TEXT PRIMARY KEY)")
                    c.execute("DELETE FROM tx_replay_guard")
                    c.executemany(
                        "INSERT INTO tx_replay_guard (tx_id) VALUES (?)",
                        [(x,) for x in replay])
                    c.commit()

            # Restore deterministic governance lifecycle state.  Timestamps
            # are local diagnostics only; save_upgrade_proposal supplies them.
            if self._storage._pgx_enabled:
                self._storage._pg_exec("DELETE FROM upgrade_proposals")
            else:
                _gc = self._storage._conn()
                _gc.execute("DELETE FROM upgrade_proposals")
                _gc.commit()
            for _g in governance:
                self._storage.save_upgrade_proposal(
                    version=int(_g["version"]), phase=str(_g["phase"]),
                    signal_start=int(_g["signal_start_height"]),
                    signal_end=int(_g["signal_end_height"]),
                    lock_in_height=int(_g["lock_in_height"]),
                    activation_height=int(_g["activation_height"]),
                    threshold=float(str(_g["threshold"])),
                    rollback_window=int(_g["rollback_window"]),
                    disabled=bool(int(_g.get("disabled", 0))),
                )

            # Reconstruct the signaling window from authenticated header fields
            # rather than trusting peer metadata.
            _sig_start = max(0, snap_h - int(Config.FORK_SIGNAL_WINDOW) - 1)
            for _h in range(_sig_start, snap_h + 1):
                _hd = verified_headers[_h]
                self._storage.set_meta(
                    f"proto_sig:{_h}", str(int(_hd.get("protocol_version", Config.PROTOCOL_VERSION))))

            self._storage.set_meta(
                "l2_tree", json.dumps(l2_tree, separators=(",", ":"), sort_keys=True))
            self._storage.set_meta("l2_last_batch_id", str(l2_last_batch))
            # Keep one authenticated rollback checkpoint rather than importing
            # peer-local L2 history.  It must use Layer2State's own entry
            # format (l1_height / l1_block_hash / batch_id / l2_root /
            # snapshot).  The earlier {"height", "tree", "last_batch_id"}
            # shape was never read by Layer2State, so any later rollback
            # onto this checkpoint raised KeyError.
            try:
                from visold.rollup.l2_state import L2StateTree
                _l2_t = L2StateTree()
                _l2_t.restore(l2_tree)
                _l2_root = _l2_t.root()
            except Exception as _l2_root_exc:
                log.warning(
                    f"bootstrap: could not compute L2 root for the "
                    f"checkpoint: {_l2_root_exc}")
                _l2_root = ""
            self._storage.set_meta(
                "l2_history",
                json.dumps([{"l1_height": snap_h,
                             "l1_block_hash": str(anchor.get("block_hash", "")),
                             "batch_id": l2_last_batch,
                             "l2_root": _l2_root,
                             "snapshot": l2_tree}],
                           separators=(",", ":"), sort_keys=True))
            # L2 state before the snapshot height is not retained, so a
            # rollback below it must be refused rather than reset to empty.
            self._storage.set_meta("l2_history_first_height", "0")
            self._storage.set_meta("cumulative_issued_sat", str(cumulative))
            # Do not set rolling_pruned_until=snap_h.  The local prefix can
            # still contain full bodies even though the imported suffix is
            # header-only.  Reconcile from persisted block markers and run the
            # normal rolling pruner before declaring the restore complete.
            if self._rolling_pruner is not None:
                try:
                    self._rolling_pruner.reconcile_after_bootstrap(snap_h)
                except Exception as _prune_exc:
                    # Snapshot state is authenticated and already installed.  A
                    # pruning failure must not undo that state transition, but
                    # leave a conservative watermark and log so pruning retries.
                    log.warning(
                        "StateSnapshotEngine: post-bootstrap pruning reconciliation "
                        "failed at height=%d: %s", snap_h, _prune_exc)
                    try:
                        self._storage.set_meta("rolling_pruned_until", "0")
                    except Exception:
                        pass
            else:
                # Conservative fallback for direct engine construction.  Never
                # assert that the snapshot height itself proves old bodies gone.
                self._storage.set_meta("rolling_pruned_until", "0")
            self._storage.set_meta("bootstrap_checkpoint_height", str(snap_h))
            self._storage.set_meta("bootstrap_checkpoint_hash", str(anchor.get("block_hash", "")))
            self._storage.set_meta("snap_restored_height", str(snap_h))
            self._storage.set_meta("snap_restored_root", str(payload.get("state_root", "")))
            self._storage.set_meta("bootstrap_restore_in_progress", "")
            self._storage.record_block_apply_result(snap_h, True)

            # A successfully authenticated bootstrap snapshot is safe to relay.
            # Persist the exact verified compressed bytes plus the digest that
            # was independently recovered from the H+1 PoW commitment.  This
            # makes bootstrap availability transitive: a node that joined via
            # snapshot can later bootstrap other nodes once it has H+1/tip.
            # Cache failure is non-consensus-critical because state/header
            # installation is already complete; fail closed for serving via the
            # manifest filter and surface the problem in logs.
            try:
                with self._snap_lock:
                    self._storage.set_meta(f"{self._KEY_PREFIX}{snap_h}", blob.hex())
                    self._update_manifest(
                        snap_h, str(payload.get("state_root", "")), len(blob),
                        str(anchor.get("block_hash", "")),
                        bootstrap_digest=str(expected_digest),
                    )
                    self._last_snap_h = max(int(self._last_snap_h), snap_h)
                    self._evict_old_snapshots(snap_h)
            except Exception as _cache_exc:
                log.error(
                    "StateSnapshotEngine: authenticated snapshot h=%d installed "
                    "but relay-cache persistence failed: %s", snap_h, _cache_exc)

            metrics.inc("snapshots_restored")
            log.info(
                "StateSnapshotEngine: authenticated pruning bootstrap installed at height=%d",
                snap_h)
            return True, "OK"
        except Exception as exc:
            # Best-effort rewind of imported headers.  The in-progress marker is
            # deliberately retained if any part of state installation failed,
            # so startup/operations cannot treat this as a clean checkpoint.
            for h in reversed(installed):
                try:
                    self._storage.delete_block(h)
                except Exception:
                    pass
            return False, f"authenticated bootstrap installation failed: {exc}"

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
