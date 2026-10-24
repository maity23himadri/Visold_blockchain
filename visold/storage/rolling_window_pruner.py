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
"""visold.storage.rolling_window_pruner

Original section: SECTION 6E: ROLLING WINDOW PRUNER  (v7.4.0)

Defines: RollingWindowPruner
Origin: visold_vsd_.py L16635-17017
"""

import json
import threading
from typing import Optional, TYPE_CHECKING

from visold.kernel.config import Config
from visold.crypto.hashing import sha256
from visold.ledger.transaction import Transaction
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6E: ROLLING WINDOW PRUNER  (v7.4.0)
# Keeps the last ROLLING_PRUNE_WINDOW blocks as full records; strips
# transaction bodies from older blocks to bound disk growth.  Only slim
# header rows (hash, prev_hash, merkle_root, state_root, timestamp,
# difficulty, nonce) survive beyond the window, preserving chain integrity.
# Runs entirely in a background daemon thread; never touches blockchain._lock.
# ─────────────────────────────────────────────────────────────────────────────
class RollingWindowPruner:
    """
    Prunes full block body + transaction data for blocks older than the
    rolling window (Config.ROLLING_PRUNE_WINDOW blocks from the current tip).

    What is KEPT for pruned blocks
    ──────────────────────────────
      • blocks row: preserved, but data_json is replaced with a slim header-
        only JSON with ``transactions=[]`` and ``pruned=true`` so the row
        still anchors the hash chain and can answer header-only SPV queries.
      • block_headers table: a dedicated slim row is upserted before pruning
        so header data is never lost even if the caller later drops the full
        blocks row.
      • transactions rows: deleted entirely for blocks beyond the window.
      • node_meta 'snap:<H>' entries: kept (those are state snapshots, not tx).

    Safety invariant
    ────────────────
    Transaction projections are deleted only after the authoritative canonical
    block body has been compacted successfully.  SQLite canonical storage uses
    one local transaction; KV/RocksDB and PGX modes compact their authoritative
    block store first and treat the SQLite database as an auxiliary shadow/archive.
    No global reconciliation DELETE is used, because cross-store backends may
    legitimately retain different transaction projections until canonical
    compaction has succeeded.

    Thread safety
    ─────────────
    All writes go through Storage helpers which hold their own per-backend
    locks (_commit_lock, _aux_lock).  maybe_prune() is re-entrant; a second
    call while a prune pass is running is a no-op.
    """

    @staticmethod
    def _merkle_proof_for_index(tx_ids, target_index: int, block_height: int):
        """Return a V1/V2-compatible Merkle proof for one retained tx id."""
        hashes = [str(x) for x in tx_ids]
        if not hashes or target_index < 0 or target_index >= len(hashes):
            return None
        idx = int(target_index)
        proof = []
        v2 = int(block_height) >= int(Config.MERKLE_V2_ACTIVATION_HEIGHT)
        if v2:
            odd_tag = "|odd|"
            while len(hashes) > 1:
                pairs = len(hashes) // 2
                paired = pairs * 2
                if idx < paired:
                    sib = idx ^ 1
                    proof.append({"hash": hashes[sib],
                                  "side": "R" if idx % 2 == 0 else "L"})
                else:
                    proof.append({"hash": "", "side": "ODD"})
                nxt = [sha256((hashes[2*i] + hashes[2*i+1]).encode())
                       for i in range(pairs)]
                if len(hashes) % 2:
                    nxt.append(sha256((odd_tag + hashes[-1]).encode()))
                idx = idx // 2 if idx < paired else len(nxt) - 1
                hashes = nxt
            return proof
        while len(hashes) > 1:
            if len(hashes) % 2:
                hashes.append(hashes[-1])
            sib = idx ^ 1
            proof.append({"hash": hashes[sib],
                          "side": "R" if idx % 2 == 0 else "L"})
            hashes = [sha256((hashes[i] + hashes[i+1]).encode())
                      for i in range(0, len(hashes), 2)]
            idx //= 2
        return proof

    def __init__(self, storage: 'Storage'):
        self._storage       = storage
        self._last_height   = -1
        self._running_lock  = threading.Lock()
        # Wired by Blockchain immediately after StateSnapshotEngine creation.
        # Pruning fails closed (no new body deletion) until this is available,
        # because recoverability must be anchored by a committed snapshot.
        self._snapshot_engine = None
        self._ensure_header_table()

    def set_snapshot_engine(self, snapshot_engine) -> None:
        """Attach the snapshot engine used to enforce bootstrap recoverability."""
        self._snapshot_engine = snapshot_engine

    def _recoverability_aligned_cutoff(self, current_height: int) -> int:
        """Return the exclusive prune boundary that preserves rollback/bootstrap liveness.

        The raw rolling-window cutoff alone is unsafe: if it lands between two
        committed snapshot anchors, pruning to that arbitrary height can delete
        the replay suffix needed after a later rollback.  We therefore prune
        only through ``S`` (exclusive boundary ``S+1``), where ``S`` is the
        newest *servable/committed* bootstrap snapshot strictly below the raw
        cutoff.  This guarantees every target at or above the persisted
        watermark can still be reconstructed from a surviving authenticated
        snapshot plus contiguous full bodies.

        With the default 600-block window and 600-block bootstrap interval this
        intentionally retains between ~600 and ~1199 full bodies.  The extra
        bounded retention is the price of making pruning and rollback mutually
        safe without weakening snapshot authentication.
        """
        raw_cutoff = max(0, int(current_height) - int(Config.ROLLING_PRUNE_WINDOW))
        if raw_cutoff <= 0:
            return 0
        eng = self._snapshot_engine
        if eng is None:
            # RollingWindowPruner is also used directly by storage-level tools
            # and unit tests. Blockchain production construction always wires
            # StateSnapshotEngine immediately; preserve legacy raw-window
            # compaction only for this standalone mode.
            return raw_cutoff
        try:
            manifest = eng.get_servable_manifest()
        except Exception as exc:
            log.warning(
                "RollingWindowPruner: cannot inspect servable snapshots; "
                "skipping prune for recoverability safety: %s", exc)
            return 0
        anchors = []
        for entry in manifest:
            try:
                h = int(entry.get("height", -1))
            except Exception:
                continue
            if 0 < h < raw_cutoff:
                anchors.append(h)
        if not anchors:
            return 0
        return min(raw_cutoff, max(anchors) + 1)

    # ── Schema bootstrap ──────────────────────────────────────────────────────
    def _ensure_header_table(self):
        """Create block_headers slim table and permanent_history archive table."""
        try:
            c = self._storage._conn()
            c.execute("""
                CREATE TABLE IF NOT EXISTS block_headers (
                    idx         INTEGER PRIMARY KEY,
                    block_hash  TEXT NOT NULL,
                    prev_hash   TEXT NOT NULL,
                    merkle_root TEXT NOT NULL DEFAULT '',
                    state_root  TEXT NOT NULL DEFAULT '',
                    timestamp   INTEGER NOT NULL DEFAULT 0,
                    difficulty  REAL    NOT NULL DEFAULT 0,
                    nonce       INTEGER NOT NULL DEFAULT 0
                )
            """)
            # ── Selective Archive table (never pruned) ────────────────────
            # Critical transactions are INSERT OR IGNOREd here before their
            # parent block is stripped.  The table grows monotonically and
            # is never touched by the pruning logic after insertion.
            c.execute("""
                CREATE TABLE IF NOT EXISTS permanent_history (
                    tx_hash       TEXT    PRIMARY KEY,
                    block_idx     INTEGER NOT NULL,
                    sender        TEXT    NOT NULL DEFAULT '',
                    receiver      TEXT    NOT NULL DEFAULT '',
                    amount        REAL    NOT NULL DEFAULT 0,
                    tx_type       TEXT    NOT NULL DEFAULT 'transfer',
                    timestamp     INTEGER NOT NULL DEFAULT 0,
                    metadata_json TEXT    NOT NULL DEFAULT '{}'
                )
            """)
            # Index so callers can query by block range efficiently.
            c.execute(
                "CREATE INDEX IF NOT EXISTS idx_permhist_block_idx "
                "ON permanent_history (block_idx)"
            )
            c.commit()
        except Exception as e:
            log.debug("RollingWindowPruner: schema init: %s", e)

    # ── Public API ────────────────────────────────────────────────────────────
    def maybe_prune(self, current_height: int) -> int:
        """Trigger a pruning pass if the height has advanced enough.
        Returns the number of blocks processed by the pass/reconciliation.
        Non-blocking: skipped if another pass is in flight.
        """
        if not Config.ROLLING_PRUNE_ENABLED:
            return 0
        if current_height < Config.ROLLING_PRUNE_WINDOW + Config.ROLLING_PRUNE_INTERVAL:
            return 0
        if not self._running_lock.acquire(blocking=False):
            return 0   # another pass is in flight
        try:
            # Check the marker only after owning the pruner lock.  Otherwise two
            # background triggers could both decide to reconcile and run with
            # different heights out of order, moving the watermark backwards.
            try:
                _reconcile_version = self._storage.get_meta(
                    "rolling_prune_reconcile_version")
            except Exception:
                _reconcile_version = None
            if _reconcile_version != "1":
                return self.reconcile_after_bootstrap(
                    current_height, _lock_already_held=True)
            if (current_height - self._last_height) < Config.ROLLING_PRUNE_INTERVAL:
                return 0
            self._last_height = current_height
            return self._run_prune_pass(current_height)
        finally:
            self._running_lock.release()

    def prune_async(self, current_height: int):
        """Fire maybe_prune in a daemon thread so apply_block is never blocked."""
        threading.Thread(
            target=self.maybe_prune,
            args=(current_height,),
            daemon=True,
            name="rolling-pruner",
        ).start()

    # ── Schema guard ──────────────────────────────────────────────────────────
    def _ensure_reconcile_index(self, c) -> None:
        """
        Guarantee idx_tx_block_idx exists before the reconciliation DELETE so
        the range scan on block_idx < cutoff is always an index seek rather
        than a full-table scan.  CREATE INDEX IF NOT EXISTS is a no-op when
        the index is already present, so this is safe to call every pass.
        """
        try:
            c.execute(
                "CREATE INDEX IF NOT EXISTS idx_tx_block_idx "
                "ON transactions (block_idx)"
            )
        except Exception as e:
            log.debug("RollingWindowPruner: index guard: %s", e)

    # ── Core pruning pass ─────────────────────────────────────────────────────
    def _run_prune_pass(self, current_height: int) -> int:
        """
        Prune old canonical block bodies without ever deleting a transaction
        projection before its authoritative block body has been compacted.

        SQLite mode keeps the entire operation in one local transaction.
        LevelDB/RocksDB and PGX modes use their canonical KV/RocksDB block store
        directly; the auxiliary SQLite database is only a shadow/archive store.
        Cross-store paths deliberately fail closed if canonical compaction or
        projection cleanup cannot be completed.
        """
        cutoff = self._recoverability_aligned_cutoff(current_height)
        if cutoff <= 0:
            return 0
        archived = 0
        pruned = 0
        _ARCHIVE_THRESHOLD = Config.ROLLING_PRUNE_ARCHIVE_THRESHOLD
        _CONTRACT_TYPES = {"deploy", "call"}
        _SYSTEM_PREFIXES = ("SYS:", "GOVERNANCE:", "EMERGENCY:")
        try:
            _own_addr = self._storage.get_meta("own_address") or ""
        except Exception:
            _own_addr = ""

        # The watermark marks the first height whose canonical full body is not
        # guaranteed to be available.  Start there so a failed/partial pass can
        # resume exactly where it stopped instead of repeatedly rescanning the
        # entire old chain.
        try:
            watermark = max(0, int(self._storage.get_meta("rolling_pruned_until") or 0))
        except Exception:
            watermark = 0

        # Repair the specific stale-watermark shape emitted by older snapshot
        # bootstrap code: it could set the watermark beyond the rolling cutoff
        # while block 0 (or another prefix block) still had a full body.  This
        # cheap sentinel check avoids rescanning the entire chain on every block.
        # The full contiguous-prefix reconciliation runs once after bootstrap.
        if watermark > 0:
            try:
                first_block = self._storage.get_block(0)
                if first_block is not None:
                    first_data = first_block.to_dict()
                    if not bool(first_data.get("pruned", False)):
                        # Authenticated bootstrap deliberately retains genesis as
                        # a full trust anchor while installing 1..H header-only.
                        # That valid shape must keep its positive watermark. Only
                        # reset the legacy stale marker when block 1 is full too.
                        second = self._storage.get_block(1)
                        second_pruned = bool(
                            second is not None and second.to_dict().get("pruned", False))
                        if not second_pruned:
                            watermark = 0
                            self._storage.set_meta("rolling_pruned_until", "0")
            except Exception:
                # On an uncertain read, do not move the watermark forward.
                watermark = min(watermark, cutoff)
        start = watermark

        # A watermark beyond the rolling cutoff is valid after authenticated
        # bootstrap when the imported history is already header-only.  Never
        # clamp it back to cutoff: doing so would move the retention boundary
        # backwards and could weaken rollback protection.

        # SQLite's canonical body lives in the same connection that also stores
        # transaction metadata.  Keep those changes ACID in one transaction.
        is_sqlite_canonical = bool(
            not getattr(self._storage, "_pgx_enabled", False)
            and not getattr(getattr(self._storage, "_block_db", None), "enabled", False)
        )
        c = None

        try:
            c = self._storage._conn()
            if is_sqlite_canonical:
                self._ensure_reconcile_index(c)

            # Limit one pass to the configured batch.  For KV/PGX this is a
            # deterministic height range; for SQLite it is the same range but
            # skips already-slimmed rows without a full-table query.
            end = min(cutoff, start + Config.ROLLING_PRUNE_BATCH)
            if end <= start:
                return 0

            contiguous = start
            for idx in range(start, end):
                try:
                    block_obj = self._storage.get_block(idx)
                except Exception as exc:
                    log.warning(
                        "RollingWindowPruner: cannot load canonical block=%d: %s",
                        idx, exc)
                    break
                if block_obj is None:
                    # A canonical height gap is not safe to skip: do not advance
                    # the pruning watermark beyond it.
                    log.warning(
                        "RollingWindowPruner: canonical block=%d is unavailable; "
                        "stopping this pass", idx)
                    break

                try:
                    full = block_obj.to_dict()
                except Exception:
                    full = dict(block_obj) if isinstance(block_obj, dict) else None
                if not isinstance(full, dict):
                    log.warning(
                        "RollingWindowPruner: canonical block=%d has invalid data; "
                        "stopping this pass", idx)
                    break

                # A body already marked pruned is safe to pass through.  For
                # cross-store modes, however, transaction projections can remain
                # after a crash between canonical compaction and projection delete,
                # so the cleanup below still runs for this height.
                already_pruned = bool(full.get("pruned", False))

                # PGX keeps a canonical RocksDB tx_id -> location index in addition
                # to the PostgreSQL transaction projection.  Capture all tx IDs
                # BEFORE deleting the PG rows so pruning can remove those RocksDB
                # locations atomically with canonical body compaction.
                pgx_tx_ids = []
                if getattr(self._storage, "_pgx_enabled", False):
                    pgx_tx_ids.extend(
                        str(tx.get("tx_id"))
                        for tx in (full.get("transactions", []) or [])
                        if isinstance(tx, dict) and tx.get("tx_id")
                    )
                    pg_fetch = getattr(self._storage, "_pg_fetch", None)
                    if callable(pg_fetch):
                        try:
                            rows = pg_fetch(
                                "SELECT tx_id FROM transactions WHERE block_idx=$1",
                                idx)
                            for row in rows:
                                try:
                                    txid = row["tx_id"]
                                except (KeyError, TypeError, IndexError):
                                    txid = None
                                if txid:
                                    pgx_tx_ids.append(str(txid))
                        except Exception as exc:
                            log.error(
                                "RollingWindowPruner: PG tx-id lookup failed "
                                "for block=%d; retaining transaction data: %s",
                                idx, exc)
                            break
                    # De-duplicate while preserving deterministic order.
                    pgx_tx_ids = list(dict.fromkeys(pgx_tx_ids))

                # Preserve an authenticated bootstrap commitment even after
                # the containing block body is pruned.  We retain only the
                # coinbase transaction plus its Merkle co-path; a newcomer can
                # verify inclusion against the permanent block-header
                # merkle_root without retaining any other transaction body.
                _bootstrap_meta = None
                _full_txs = list(full.get("transactions", []) or [])
                if _full_txs and isinstance(_full_txs[0], dict):
                    _cb = _full_txs[0]
                    _commit = Transaction.parse_bootstrap_commitment(
                        str(_cb.get("memo", "")))
                    if _commit is not None and _cb.get("tx_id"):
                        _txids = [str(t.get("tx_id", ""))
                                  for t in _full_txs if isinstance(t, dict)]
                        if len(_txids) == len(_full_txs) and all(_txids):
                            _proof = self._merkle_proof_for_index(_txids, 0, idx)
                            if _proof is not None:
                                _bootstrap_meta = {
                                    "snapshot_height": int(_commit[0]),
                                    "digest": str(_commit[1]),
                                    "coinbase": dict(_cb),
                                    "merkle_proof": _proof,
                                }

                header = {
                    "version": full.get("version", 1),
                    "protocol_version": full.get(
                        "protocol_version", Config.PROTOCOL_VERSION),
                    "idx": idx,
                    "index": idx,
                    "block_hash": full.get("block_hash", ""),
                    "prev_hash": full.get("prev_hash", ""),
                    "miner_address": full.get("miner_address", ""),
                    "merkle_root": full.get("merkle_root", ""),
                    "state_root": full.get("state_root", ""),
                    "timestamp": full.get("timestamp", 0),
                    "difficulty": full.get("difficulty", 0),
                    "nonce": full.get("nonce", 0),
                    "vrf_proof": full.get("vrf_proof", ""),
                    "vrf_output": full.get("vrf_output", ""),
                    "finalized": bool(full.get("finalized", False)),
                    "validator_sigs": list(full.get("validator_sigs", []) or []),
                    "pruned": True,
                    "transactions": [],
                }
                # A previously-pruned body can still carry an authenticated
                # bootstrap commitment needed by reconnecting peers.  Preserve
                # it when rebuilding/repairing the slim header; freshly derived
                # metadata from the full coinbase takes precedence.
                _stored_bootstrap_meta = full.get("bootstrap_commitment")
                if isinstance(_stored_bootstrap_meta, dict):
                    header["bootstrap_commitment"] = dict(_stored_bootstrap_meta)
                if _bootstrap_meta is not None:
                    header["bootstrap_commitment"] = _bootstrap_meta

                # ── Archive before any irreversible transaction deletion ────
                # For PGX/KV the archive lives in auxiliary SQLite, while the
                # transaction projection may live elsewhere.  Commit the archive
                # first so a later PG/KV cleanup failure can never lose the only
                # preserved copy of a critical transaction.
                if not already_pruned:
                    block_ts = int(full.get("timestamp", 0) or 0)
                    for tx in full.get("transactions", []) or []:
                        if not isinstance(tx, dict):
                            continue
                        try:
                            tx_type = tx.get("tx_type") or "transfer"
                            amount = float(tx.get("amount") or 0.0)
                            memo = tx.get("memo") or ""
                            is_contract = tx_type in _CONTRACT_TYPES
                            is_large = amount >= _ARCHIVE_THRESHOLD
                            is_system = isinstance(memo, str) and memo.startswith(_SYSTEM_PREFIXES)
                            is_self = bool(_own_addr and (
                                tx.get("sender") == _own_addr or
                                tx.get("receiver") == _own_addr
                            ))
                            if not (is_contract or is_large or is_system or is_self):
                                continue
                            tx_hash = tx.get("tx_id") or ""
                            if not tx_hash:
                                continue
                            sender = tx.get("sender") or ""
                            receiver = tx.get("receiver") or ""
                            tx_ts = int(tx.get("timestamp") or block_ts)
                            meta_keys = (
                                "fee", "nonce", "gas_limit", "gas_price",
                                "data", "contract_name", "memo",
                            )
                            meta = {
                                k: tx[k] for k in meta_keys
                                if k in tx and tx[k] not in (None, "", 0, 0.0)
                            }
                            c.execute(
                                """INSERT OR IGNORE INTO permanent_history
                                   (tx_hash, block_idx, sender, receiver,
                                    amount, tx_type, timestamp, metadata_json)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                (tx_hash, idx, sender, receiver, amount,
                                 str(tx_type), tx_ts,
                                 json.dumps(meta, separators=(",", ":"))),
                            )
                            archived += c.execute("SELECT changes()").fetchone()[0]
                        except Exception as arc_exc:
                            log.debug(
                                "RollingWindowPruner: archive error block=%d tx=%s: %s",
                                idx, tx.get("tx_id", "?"), arc_exc)

                if not is_sqlite_canonical and not already_pruned:
                    # Commit archive rows before touching the canonical KV body.
                    c.commit()

                # ── Canonical compaction ──────────────────────────────────
                if is_sqlite_canonical:
                    # Header-only blocks imported by snapshot bootstrap may not
                    # have a corresponding block_headers row yet.  Always repair
                    # that index, even when the body was already pruned.
                    c.execute(
                        """INSERT OR REPLACE INTO block_headers
                           (idx, block_hash, prev_hash, merkle_root, state_root,
                            timestamp, difficulty, nonce)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (idx, header["block_hash"], header["prev_hash"],
                         header["merkle_root"], header["state_root"],
                         int(header["timestamp"]), float(header["difficulty"]),
                         int(header["nonce"])),
                    )
                    if not already_pruned:
                        slim_json = json.dumps(header, separators=(",", ":"))
                        result = c.execute(
                            "UPDATE blocks SET data_json=? WHERE idx=?",
                            (slim_json, idx),
                        )
                        if result.rowcount != 1:
                            c.rollback()
                            log.warning(
                                "RollingWindowPruner: SQLite canonical block=%d "
                                "missing; retaining transaction data", idx)
                            break
                elif (not already_pruned or pgx_tx_ids):
                    if not self._storage.prune_block_body(
                            idx, header, tx_ids=pgx_tx_ids):
                        log.warning(
                            "RollingWindowPruner: canonical block compaction "
                            "failed for block=%d; retaining transaction data",
                            idx,
                        )
                        break

                    # Auxiliary block row is non-authoritative in KV/PGX mode.
                    slim_json = json.dumps(header, separators=(",", ":"))
                    c.execute(
                        "UPDATE blocks SET data_json=? WHERE idx=?",
                        (slim_json, idx),
                    )

                # ── Remove transaction projections only after compaction ───
                if getattr(self._storage, "_pgx_enabled", False):
                    try:
                        self._storage._pg_exec(
                            "DELETE FROM transactions WHERE block_idx=$1", idx)
                    except Exception as exc:
                        log.error(
                            "RollingWindowPruner: PG transaction cleanup failed "
                            "for block=%d: %s", idx, exc)
                        # Keep aux metadata so the operation is retried.  The
                        # canonical body is already safely compacted.
                        if not already_pruned:
                            c.rollback()
                        break
                    try:
                        c.execute("DELETE FROM transactions WHERE block_idx=?", (idx,))
                    except Exception:
                        pass
                else:
                    c.execute("DELETE FROM transactions WHERE block_idx=?", (idx,))

                if not is_sqlite_canonical:
                    # Commit aux shadow state after the canonical block and the
                    # transaction projection agree.  A crash before this commit
                    # leaves only stale auxiliary data; canonical state remains safe.
                    c.execute(
                        """INSERT OR REPLACE INTO block_headers
                           (idx, block_hash, prev_hash, merkle_root, state_root,
                            timestamp, difficulty, nonce)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (idx, header["block_hash"], header["prev_hash"],
                         header["merkle_root"], header["state_root"],
                         int(header["timestamp"]), float(header["difficulty"]),
                         int(header["nonce"])),
                    )
                    slim_json = json.dumps(header, separators=(",", ":"))
                    c.execute(
                        "UPDATE blocks SET data_json=? WHERE idx=?",
                        (slim_json, idx),
                    )
                    c.commit()

                pruned += 1
                contiguous = idx + 1

            # SQLite mode has not committed the batch yet; commit only the work
            # that made it through the canonical + transaction-delete sequence.
            if is_sqlite_canonical and pruned:
                c.commit()

            # Advance the watermark only through successfully compacted heights.
            # Do not jump to ``cutoff`` when the configured batch only handled a
            # prefix; doing so would falsely claim old blocks are unavailable.
            if pruned:
                new_watermark = contiguous
                self._storage.set_meta("rolling_pruned_until", str(new_watermark))
                metrics.set_gauge("rolling_pruned_until_height", float(new_watermark))
            return pruned

        except Exception as exc:
            try:
                if c is not None:
                    c.rollback()
            except Exception:
                pass
            log.warning("RollingWindowPruner: pass error: %s", exc)
            return pruned
    def reconcile_after_bootstrap(
            self, current_height: int, *, _lock_already_held: bool = False) -> int:
        """Reconcile pruning metadata and header indexes after snapshot bootstrap.

        Authenticated bootstrap installs header-only rows for the imported suffix,
        but the local canonical prefix can still contain full block bodies.  The
        persisted watermark must therefore be derived from the actual contiguous
        pruned prefix, never copied from the snapshot height.  When pruning is
        enabled, finish the ordinary rolling-prune range synchronously so a node
        does not resume syncing with stale full bodies below the cutoff.

        Returns the number of heights processed by rolling-prune passes.  A
        partial/no-progress pass leaves the watermark at the last verified safe
        boundary; the next normal pruning trigger can resume it.
        """
        height = max(0, int(current_height))
        if not _lock_already_held:
            if not self._running_lock.acquire(blocking=True):
                # A blocking acquire should normally succeed; retain a conservative
                # result rather than claiming the bootstrap range was compacted.
                return 0
        processed = 0
        try:
            raw_cutoff = max(0, height - int(Config.ROLLING_PRUNE_WINDOW))
            cutoff = raw_cutoff
            c = self._storage._conn()

            # Find the contiguous pruned prefix, while repairing any missing
            # block_headers rows for header-only blocks installed by an earlier
            # bootstrap.  Do not infer pruning from the old watermark: older
            # releases could set it to snapshot_height while leaving the local
            # prefix's transaction bodies untouched.
            contiguous = 0  # contiguous pruned prefix, bounded by rolling cutoff
            prefix_open = True
            all_prefix_boundary = 0  # actual contiguous pruned prefix through the tip
            all_prefix_open = True
            # Bootstrap keeps genesis full but can install 1..H as one
            # contiguous header-only range. Track that explicit genesis
            # exception so the watermark still records historical unavailability.
            genesis_exception_boundary = 0
            genesis_exception_open = True
            first_full_at_or_after_cutoff = None
            scan_complete = True
            batch = []
            for idx in range(height + 1):
                block = self._storage.get_block(idx)
                if block is None:
                    log.warning(
                        "RollingWindowPruner: bootstrap reconciliation found a "
                        "canonical gap at block=%d; stopping prefix scan", idx)
                    scan_complete = False
                    break
                try:
                    full = block.to_dict()
                except Exception:
                    full = dict(block) if isinstance(block, dict) else {}
                is_pruned = bool(full.get("pruned", False))

                if is_pruned:
                    batch.append((
                        idx, str(full.get("block_hash", "")),
                        str(full.get("prev_hash", "")),
                        str(full.get("merkle_root", "")),
                        str(full.get("state_root", "")),
                        int(full.get("timestamp", 0) or 0),
                        float(full.get("difficulty", 0) or 0),
                        int(full.get("nonce", 0) or 0),
                    ))
                    if len(batch) >= 1000:
                        c.executemany(
                            """INSERT OR REPLACE INTO block_headers
                               (idx, block_hash, prev_hash, merkle_root, state_root,
                                timestamp, difficulty, nonce)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", batch)
                        c.commit()
                        batch.clear()

                if all_prefix_open:
                    if is_pruned:
                        all_prefix_boundary = idx + 1
                    else:
                        all_prefix_open = False
                if idx == 0:
                    genesis_exception_open = not is_pruned
                elif genesis_exception_open:
                    if is_pruned:
                        genesis_exception_boundary = idx + 1
                    else:
                        genesis_exception_open = False
                if idx >= cutoff and not is_pruned and first_full_at_or_after_cutoff is None:
                    first_full_at_or_after_cutoff = idx

                if idx < cutoff and prefix_open:
                    if is_pruned:
                        contiguous = idx + 1
                    else:
                        prefix_open = False

            if batch:
                c.executemany(
                    """INSERT OR REPLACE INTO block_headers
                       (idx, block_hash, prev_hash, merkle_root, state_root,
                        timestamp, difficulty, nonce)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", batch)
                c.commit()

            if not scan_complete:
                # Keep only the verified contiguous prefix; a partial scan must
                # never advertise a larger watermark or mark reconciliation done.
                self._storage.set_meta("rolling_pruned_until", str(contiguous))
                metrics.set_gauge("rolling_pruned_until_height", float(contiguous))
                self._last_height = -1
                return 0

            if (not Config.ROLLING_PRUNE_ENABLED or
                    height < int(Config.ROLLING_PRUNE_WINDOW) +
                    int(Config.ROLLING_PRUNE_INTERVAL)):
                self._storage.set_meta(
                    "rolling_pruned_until", str(all_prefix_boundary))
                metrics.set_gauge(
                    "rolling_pruned_until_height", float(all_prefix_boundary))
                self._storage.set_meta("rolling_prune_reconcile_version", "1")
                self._last_height = height
                return 0

            # Initially trust only the contiguous prefix already marked pruned.
            # The regular compactor will convert any remaining bodies below the
            # cutoff, in bounded batches, before we advance the boundary further.
            self._storage.set_meta("rolling_pruned_until", str(contiguous))
            metrics.set_gauge("rolling_pruned_until_height", float(contiguous))

            target = self._recoverability_aligned_cutoff(height)
            # Run bounded batches to completion only to the recoverability-safe
            # boundary. Imported header-only history may already extend farther;
            # that factual prefix is preserved by the reconciliation scan above.
            # The guard guarantees progress
            # or exits, so a backend failure cannot cause an infinite loop.
            while self.get_pruned_watermark() < target:
                before = self.get_pruned_watermark()
                self._run_prune_pass(height)
                after = self.get_pruned_watermark()
                if after <= before:
                    break
                processed += after - before

            # If every height below the cutoff is now pruned, imported header-only
            # history above it may extend the contiguous pruned prefix further.
            # Preserve that fact for rollback guards and avoid reprocessing it as
            # though it were still a full-body range.
            if self.get_pruned_watermark() >= target:
                # Extend only through heights that are *actually* header-only
                # after the safe compaction. This can join a newly-pruned local
                # prefix to an imported bootstrap header-only suffix, but can
                # never leap across a retained full body merely because the old
                # raw rolling cutoff was farther ahead.
                final_boundary = int(target)
                scan = final_boundary
                if scan == 0:
                    try:
                        g0 = self._storage.get_block(0)
                        g1 = self._storage.get_block(1) if height >= 1 else None
                        if (g0 is not None and not bool(g0.to_dict().get("pruned", False))
                                and g1 is not None and bool(g1.to_dict().get("pruned", False))):
                            scan = 1
                            final_boundary = 1
                    except Exception:
                        pass
                while scan <= height:
                    try:
                        blk = self._storage.get_block(scan)
                        if blk is None or not bool(blk.to_dict().get("pruned", False)):
                            break
                    except Exception:
                        break
                    final_boundary = scan + 1
                    scan += 1
                final_boundary = max(
                    final_boundary, int(all_prefix_boundary),
                    int(genesis_exception_boundary))
                self._storage.set_meta("rolling_pruned_until", str(final_boundary))
                metrics.set_gauge(
                    "rolling_pruned_until_height", float(final_boundary))
            self._storage.set_meta("rolling_prune_reconcile_version", "1")
            self._last_height = height
            return processed
        except Exception as exc:
            log.warning("RollingWindowPruner: bootstrap reconciliation failed: %s", exc)
            try:
                # Reset only to a conservative value; never claim the snapshot
                # height itself was pruned merely because its state was restored.
                self._storage.set_meta("rolling_pruned_until", "0")
            except Exception:
                pass
            return processed
        finally:
            if not _lock_already_held:
                self._running_lock.release()

    # ── Header retrieval ──────────────────────────────────────────────────────
    def get_header(self, idx: int) -> Optional[dict]:
        """Return slim header dict for a pruned block, or None."""
        try:
            c = self._storage._conn()
            row = c.execute(
                "SELECT * FROM block_headers WHERE idx=?", (idx,)
            ).fetchone()
            if row:
                return dict(row)
        except Exception:
            pass
        return None

    def get_pruned_watermark(self) -> int:
        """Height below which full transaction data is unavailable."""
        try:
            val = self._storage.get_meta("rolling_pruned_until")
            return int(val) if val else 0
        except Exception:
            return 0
