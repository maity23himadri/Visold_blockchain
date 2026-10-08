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

    def __init__(self, storage: 'Storage'):
        self._storage       = storage
        self._last_height   = -1
        self._running_lock  = threading.Lock()
        self._ensure_header_table()

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
        """
        Trigger a pruning pass if the height has advanced enough.
        Returns the number of blocks whose tx data was pruned.
        Non-blocking: skipped if another pass is already running.
        """
        if not Config.ROLLING_PRUNE_ENABLED:
            return 0
        if current_height < Config.ROLLING_PRUNE_WINDOW + Config.ROLLING_PRUNE_INTERVAL:
            return 0
        if (current_height - self._last_height) < Config.ROLLING_PRUNE_INTERVAL:
            return 0
        if not self._running_lock.acquire(blocking=False):
            return 0   # another pass is in flight
        try:
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
        cutoff = max(0, int(current_height) - Config.ROLLING_PRUNE_WINDOW)
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
        start = min(watermark, cutoff)

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
                if not already_pruned or (
                        getattr(self._storage, "_pgx_enabled", False) and pgx_tx_ids):
                    if is_sqlite_canonical:
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
                    else:
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
