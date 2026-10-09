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
"""visold.storage.storage


Defines: Storage
Origin: visold_vsd_.py L12905-16212
"""

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Dict, Iterable, List, Optional

from visold.crypto.hashing import sha256
from visold.kernel.compat import (
    _PGX_AVAILABLE, _PGX_IMPORT_ERROR, _STORAGE_BACKEND,
    _STORAGE_BACKEND_REQUESTED,
)
from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics
from visold.kernel.units import VSD_GLOBAL_MARKET, from_satoshi, to_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.backends import (
    _META_CHAIN_TIP,
    _META_TIP_HASH,
    _PgStateDB,
    _RedisCache,
    _RocksBlockStore,
    _u64,
)
from visold.storage.block_database import BlockDatabase
from visold.storage.sqlite_serialized import (
    _SerializedSQLiteConnection,
    _SQLiteConnectionTransactionBusy,
)
from visold.vm.naming import normalize_contract_name


# PostgreSQL stores transaction type as SMALLINT to keep the hot metadata
# projection compact.  The Transaction object and wire format intentionally
# remain string-based (e.g. "transfer", "deploy", "call"); this mapping is
# strictly a persistence representation and MUST NOT be used when hashing,
# signing, or serialising consensus transactions.  Keep it explicit: silently
# mapping an unknown type to a known type would corrupt the PG projection.
_PG_TX_TYPE_CODES = {
    Transaction.TYPE_TRANSFER: 0,
    Transaction.TYPE_DEPLOY: 1,
    Transaction.TYPE_CALL: 2,
    Transaction.TYPE_REGISTER: 3,
    Transaction.TYPE_ROLLUP: 4,
    "reward": 5,
}


def _pg_tx_type_code(tx_type) -> int:
    """Return the canonical PostgreSQL SMALLINT code for a transaction type."""
    if isinstance(tx_type, bool):
        raise ValueError(f"Unsupported PostgreSQL tx_type boolean: {tx_type!r}")
    if isinstance(tx_type, int):
        # Backward compatibility for any already-normalised internal caller.
        if -32768 <= tx_type <= 32767:
            return int(tx_type)
        raise ValueError(f"PostgreSQL tx_type SMALLINT out of range: {tx_type}")
    key = str(tx_type or Transaction.TYPE_TRANSFER)
    try:
        return _PG_TX_TYPE_CODES[key]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported transaction type for PGX projection: {key!r}"
        ) from exc


class Storage:
    """Hybrid Storage layer (v7.1.0) — PostgreSQL + RocksDB + Redis.

    Public API is UNCHANGED from the v7.0 SQLite-based Storage so every call
    site in Blockchain/P2P/RPC/Mining/CLI keeps working verbatim.

    Backend selection (env ``VISOLD_STORAGE``):
        * ``pgx``    — PostgreSQL + RocksDB + Redis (default when libs present)
        * ``sqlite`` — legacy single-file WAL SQLite (rollback path)

    In ``pgx`` mode we also keep a tiny auxiliary SQLite file at
    ``{db_path}.aux`` for the handful of external modules (reputation_extended,
    peer_capabilities, ad-hoc RPC queries) that bypass Storage's public API
    and run raw SQL via ``._conn()``.  That file NEVER holds consensus state
    — just a few small index tables — so it produces zero lock contention
    on the hot path.

    All balance arithmetic is exact integer satoshi.  All block writes go
    through ``commit_block()`` (RocksDB fsync → PG txn → Redis), so the old
    ``save_block()`` no longer blocks peer write threads on a single SQLite
    writer slot.  This fixes v7.0.1.0 Bug 1 (``database is locked``).
    """

    # ── lifecycle ────────────────────────────────────────────────────────────
    def __init__(self, db_path: str):
        self.db_path      = db_path
        # AUDIT-FIX (self-connect / WAL-corruption pass, see _conn() below):
        # this was threading.local(), handing out one independent SQLite
        # connection per OS thread. This codebase spawns a fresh daemon
        # thread per peer connection, per outbound dial, and per applied
        # chain-sync batch -- each one became its own permanent, never-
        # closed WAL participant against the same file. Now a single
        # connection is created once (see _conn()) and shared across
        # threads; _conn_create_lock only guards the one-time creation race.
        self._shared_conn      = None
        self._conn_create_lock = threading.Lock()
        # All SQLite calls, including cursor fetches and commits, pass through
        # this one re-entrant lock.  check_same_thread=False permits access
        # from the node's worker threads; it does not serialize connection
        # state, so that responsibility belongs here.
        self._sqlite_api_lock  = threading.RLock()
        self._wal_lock    = threading.Lock()
        self._write_count = 0
        self._commit_lock = threading.RLock()      # serializes commit_block()
        self._aux_lock    = threading.Lock()       # aux-SQLite write guard
        # PGX block transactions hold one PostgreSQL connection for the whole
        # block application so every consensus-state write/read participates
        # in the same database transaction.  The connection is stored only in
        # this thread-local while the transaction is active; it is never
        # shared concurrently across consensus threads.
        self._pgx_block_local = threading.local()
        self._pgx_canonical_tip = -1
        self._pgx_canonical_tip_hash = ""

        self._backend = _STORAGE_BACKEND
        self._pgx_enabled = False

        # ── Try PG + Rocks + Redis first ────────────────────────────────────
        if self._backend == "pgx":
            if not _PGX_AVAILABLE:
                msg = (
                    "VISOLD_STORAGE=pgx requested but PGX dependencies are unavailable: "
                    f"{_PGX_IMPORT_ERROR}. Install rocksdict (preferred) or a compatible "
                    "python-rocksdb binding, plus asyncpg redis msgpack."
                )
                if _STORAGE_BACKEND_REQUESTED == "pgx":
                    raise RuntimeError(msg)
                log.warning("%s; using sqlite because no backend was explicitly selected", msg)
                self._backend = "sqlite"
            else:
                try:
                    rocks_path = os.environ.get(
                        "VISOLD_ROCKS_PATH",
                        os.path.join(os.path.dirname(os.path.abspath(db_path))
                                     or ".", "rocks"))
                    self._rocks = _RocksBlockStore(
                        rocks_path,
                        cache_mb=int(os.environ.get("VISOLD_ROCKS_CACHE_MB", "512")),
                        wbuf_mb=int(os.environ.get("VISOLD_ROCKS_WBUF_MB", "128")))
                    pg_dsn = os.environ.get(
                        "VISOLD_PG_DSN",
                        "postgresql://{u}:{p}@{h}:{P}/{d}".format(
                            u=os.environ.get("VISOLD_PG_USER", "visold"),
                            p=os.environ.get("VISOLD_PG_PASSWORD", "visold"),
                            h=os.environ.get("VISOLD_PG_HOST", "127.0.0.1"),
                            P=os.environ.get("VISOLD_PG_PORT", "5432"),
                            d=os.environ.get("VISOLD_PG_DB", "visold")))
                    self._pg = _PgStateDB(
                        pg_dsn,
                        min_size=int(os.environ.get("VISOLD_PG_POOL_MIN", "4")),
                        max_size=int(os.environ.get("VISOLD_PG_POOL_MAX", "32")))
                    self._pg.start()
                    self._cache = _RedisCache(
                        os.environ.get("VISOLD_REDIS_URL", "redis://127.0.0.1:6379/0"))
                    self._pgx_enabled = True
                    log.info(
                        "Storage: PostgreSQL + %s + Redis initialized",
                        getattr(self._rocks, "_impl", "RocksDB"),
                    )
                except Exception as e:
                    # Never silently turn an explicit PGX deployment into a
                    # SQLite deployment.  That makes test results and, more
                    # importantly, production backend selection trustworthy.
                    try:
                        rocks = getattr(self, "_rocks", None)
                        if rocks is not None:
                            rocks.close()
                    except Exception:
                        pass
                    try:
                        pg = getattr(self, "_pg", None)
                        if pg is not None:
                            pg.close()
                    except Exception:
                        pass
                    self._pgx_enabled = False
                    if _STORAGE_BACKEND_REQUESTED == "pgx":
                        raise RuntimeError(f"PGX storage initialization failed: {e}") from e
                    log.error(
                        "Storage: automatic PGX initialization failed (%s); "
                        "using sqlite because no backend was explicitly selected", e)
                    self._backend = "sqlite"

        # aux-SQLite (also used as primary in sqlite mode)
        self._aux_path = db_path if not self._pgx_enabled else (db_path + ".aux")
        self._init_aux_schema()

        if self._pgx_enabled:
            self._init_pgx_canonical_state()

        if not self._pgx_enabled:
            # Legacy: keep the same KV block-db side-store the old code used.
            try:
                _kv_path = (Config.LEVELDB_PATH if Config.DB_BACKEND == "leveldb"
                            else Config.ROCKSDB_PATH)
                self._block_db = BlockDatabase(backend=Config.DB_BACKEND, path=_kv_path)
            except Exception:
                class _Stub:
                    enabled = False
                    def chain_height(self):   return -1
                    def get_block_by_height(self, h): return None
                    def get_block_by_hash(self, h):   return None
                    def get_last_n_blocks(self, n):   return []
                self._block_db = _Stub()  # type: ignore[assignment]
        else:
            class _Stub2:
                enabled = False
                def chain_height(self):   return -1
                def get_block_by_height(self, h): return None
                def get_block_by_hash(self, h):   return None
                def get_last_n_blocks(self, n):   return []
            self._block_db = _Stub2()  # type: ignore[assignment]

        if self._block_db.enabled:
            self._reconcile_external_block_db()

        self._run_legacy_balance_migration_once()
        self._run_sc_name_1_migration_once()  # SC-NAME-1: add contract_name column


    # ── Conservation / accounting helpers (required by conservation_check) ───
    def sum_all_balances_satoshi(self) -> int:
        """Return the sum of all account balances in satoshi."""
        try:
            if self._pgx_enabled:
                rows = self._pg_fetch("SELECT COALESCE(SUM(balance_sat),0) AS s FROM accounts", [])
                return int(rows[0]["s"]) if rows else 0
            # AUDIT-FIX-16 (dead conservation check, wrong-table variant):
            # this queried "accounts" — a table that only exists in the
            # PostgreSQL schema (_PG_SCHEMA_SQL). On SQLite, the real
            # balance table is "balances" with column "balance", not
            # "balance_sat". The query below always raised
            # "no such table: accounts", silently caught by the except
            # clause, returning 0 unconditionally on every SQLite
            # deployment regardless of actual total balance.
            cur = self._conn().cursor()
            cur.execute("SELECT COALESCE(SUM(balance),0) FROM balances")
            row = cur.fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0

    # AUDIT-FIX-O1: added alongside sum_all_balances_satoshi. Postgres has no
    # "roles" table -- the equivalent is "validators" (stake_sat, already
    # satoshi); SQLite's "roles" table stores stake as a VSD REAL, so that
    # branch converts explicitly. Callers that previously read
    # self.storage._conn() directly for a stake/slash total (the startup
    # guards, SafetyInvariantChecker) were unconditionally hitting the
    # aux-SQLite shadow even in pgx mode -- see sum_all_balances_satoshi's
    # own AUDIT-FIX-16 for the balance-side version of this same bug.
    def sum_all_staked_satoshi(self) -> int:
        """Return the sum of all active (non-slashed) stake, in satoshi."""
        try:
            if self._pgx_enabled:
                rows = self._pg_fetch(
                    "SELECT COALESCE(SUM(stake_sat),0) AS s FROM validators "
                    "WHERE slashed = FALSE", [])
                return int(rows[0]["s"]) if rows else 0
            cur = self._conn().cursor()
            cur.execute(
                "SELECT COALESCE(SUM(CAST(stake * ? AS INTEGER)),0) "
                "FROM roles WHERE slashed=0", (Config.SATOSHI_PER_VSD,))
            row = cur.fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0

    def sum_all_slashed_satoshi(self) -> int:
        """Return the sum of stake belonging to slashed validators, in satoshi."""
        try:
            if self._pgx_enabled:
                rows = self._pg_fetch(
                    "SELECT COALESCE(SUM(stake_sat),0) AS s FROM validators "
                    "WHERE slashed = TRUE", [])
                return int(rows[0]["s"]) if rows else 0
            cur = self._conn().cursor()
            cur.execute(
                "SELECT COALESCE(SUM(CAST(stake * ? AS INTEGER)),0) "
                "FROM roles WHERE slashed=1", (Config.SATOSHI_PER_VSD,))
            row = cur.fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0

    def get_burned_satoshi(self) -> int:
        """
        Return the cumulative burned satoshi (sent to BURN_ADDRESS).

        AUDIT-FIX-16: previously summed a `burns` table that is never
        created on either backend (no CREATE TABLE for it exists anywhere
        in this codebase) — always silently returned 0. This chain tracks
        burns by crediting Config.BURN_ADDRESS rather than destroying funds
        outright (see Blockchain._distribute_rewards's dust-handling
        comment), so that address's own balance already *is* the
        cumulative burned total — no separate ledger needed.
        """
        try:
            return self.get_balance_sat(Config.BURN_ADDRESS)
        except Exception:
            return 0

    def get_total_issued_satoshi(self) -> int:
        """
        Return the total issuance in satoshi (sum of all coinbase rewards).

        AUDIT-FIX-16: previously summed an `issuance` table that is never
        created on either backend — always silently returned 0. Replaced
        with the real, incrementally-tracked counter (see
        get_cumulative_issued_sat / increment_cumulative_issued_sat),
        updated once per block from Blockchain._distribute_rewards at the
        point new coinbase supply is actually computed.
        """
        return self.get_cumulative_issued_sat()

    def close(self):
        try:
            if self._pgx_enabled:
                self._pg.close()
        except Exception:
            pass
        try:
            if self._pgx_enabled:
                rocks = getattr(self, "_rocks", None)
                if rocks is not None:
                    rocks.close()
        except Exception:
            pass
        # AUDIT-FIX: checkpoint + close the shared aux-SQLite connection
        # (see _conn()). No-op if it was never opened.
        # Serialize close against every execute/fetch/commit and prevent a
        # concurrent first-use path from creating a new connection while the
        # old one is being shut down.
        try:
            with self._conn_create_lock:
                conn = self._shared_conn
                if conn is not None:
                    try:
                        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    except Exception:
                        pass
                    try:
                        conn.close()
                    finally:
                        self._shared_conn = None
        except Exception:
            pass

    # ── aux SQLite (single shared connection — see AUDIT-FIX note below) ────
    def _conn(self) -> sqlite3.Connection:
        """Return the shared SQLite connection for this Storage instance.

        In ``pgx`` mode this connection points at ``{db_path}.aux`` and holds
        only small ad-hoc tables used by external modules that bypass the
        Storage public API (reputation_extended, peer_capabilities).  All
        consensus state is in Postgres + RocksDB.

        In ``sqlite`` mode this is the legacy primary DB, unchanged.

        AUDIT-FIX (self-connect / WAL-corruption pass): this used to open a
        *separate* connection per OS thread via threading.local(), and
        nothing ever closed them. Every peer-message-loop, outbound-connect,
        and chain-apply thread became its own permanent WAL participant.
        A single shared connection removes that N-participant exposure, but
        ``check_same_thread=False`` alone does NOT serialize the Python
        sqlite3 connection/cursor operation sequence. The connection is
        therefore wrapped by _SerializedSQLiteConnection, and every
        execute/execute-many/script/cursor/fetch/commit/rollback/close call
        is serialized by _sqlite_api_lock. The existing _commit_lock /
        _aux_lock critical sections remain unchanged for their original
        multi-statement purposes.
        """
        if self._shared_conn is not None:
            return self._shared_conn
        with self._conn_create_lock:
            if self._shared_conn is None:
                conn = sqlite3.connect(self._aux_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA wal_autocheckpoint=1000")
                conn.execute(f"PRAGMA busy_timeout={Config.SQLITE_BUSY_TIMEOUT_MS}")
                self._shared_conn = _SerializedSQLiteConnection(
                    conn, self._sqlite_api_lock)
        return self._shared_conn

    def _maybe_checkpoint(self):
        with self._wal_lock:
            self._write_count += 1
            if self._write_count % Config.WAL_CHECKPOINT_PAGES == 0:
                try:
                    self._conn().execute("PRAGMA wal_checkpoint(PASSIVE)")
                except Exception:
                    pass

    # ── block-application atomicity (SQLite) ────────────────────────────────
    # A complete block must become durable as one SQLite transaction.  Many
    # legacy Storage methods call commit() internally, so the serialized
    # connection suppresses those inner commits while this lock/transaction is
    # held.  Keeping the API here (rather than exposing the connection wrapper
    # to Blockchain) also makes the ownership and lock lifetime explicit.
    def begin_sqlite_atomic_block(self) -> None:
        if self._pgx_enabled:
            return

        # An ordinary Storage write may have executed its DML and released the
        # per-operation lock just before its separate commit() call. In that
        # narrow window, the shared SQLite connection is in a transaction, but
        # no block-level transaction owns it yet. Never commit/rollback that
        # work on the block thread: release the lock and let the writer finish.
        # Retry only this specific state; a genuinely active atomic block or
        # any unrelated error must still fail immediately.
        timeout = max(0.1, float(Config.SQLITE_BUSY_TIMEOUT_MS) / 1000.0)
        deadline = time.monotonic() + timeout
        while True:
            self._sqlite_api_lock.acquire()
            try:
                self._conn().begin_atomic()
            except _SQLiteConnectionTransactionBusy as exc:
                self._sqlite_api_lock.release()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(
                        "SQLite connection remained in an ordinary transaction "
                        f"for {timeout:.2f}s; refusing to interfere with the writer"
                    ) from exc
                time.sleep(min(0.01, remaining))
                continue
            except BaseException:
                self._sqlite_api_lock.release()
                raise
            return

    def commit_sqlite_atomic_block(self) -> None:
        if self._pgx_enabled:
            return
        try:
            self._conn().commit_atomic()
        finally:
            self._sqlite_api_lock.release()

    def rollback_sqlite_atomic_block(self) -> None:
        if self._pgx_enabled:
            return
        try:
            self._conn().rollback_atomic()
        finally:
            self._sqlite_api_lock.release()

    def _init_aux_schema(self):
        """Create the schema needed for aux-SQLite (and full schema in sqlite mode)."""
        c = self._conn()
        # In PGX mode we create only the tables that external raw-SQL callers
        # may touch. In sqlite mode we create everything (legacy full schema).
        if self._pgx_enabled:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS reputation_extended (
                peer_id      TEXT PRIMARY KEY,
                score        REAL DEFAULT 0.5,
                fast_blocks  INTEGER DEFAULT 0,
                valid_txs    INTEGER DEFAULT 0,
                uptime_ticks INTEGER DEFAULT 0,
                last_updated INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS peer_capabilities (
                peer_id    TEXT NOT NULL,
                capability TEXT NOT NULL,
                updated_at INTEGER DEFAULT 0,
                PRIMARY KEY (peer_id, capability)
            );
            CREATE TABLE IF NOT EXISTS schema_meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
            -- Shadow tables for raw-SQL callers that JOIN/read directly.
            -- Kept in sync by the corresponding public-API write methods.
            CREATE TABLE IF NOT EXISTS node_meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS peers (
                peer_id      TEXT PRIMARY KEY,
                ip           TEXT,
                port         INTEGER,
                last_seen    INTEGER,
                reputation   REAL DEFAULT 1.0,
                fail_count   INTEGER DEFAULT 0,
                blacklisted  INTEGER DEFAULT 0,
                ban_score    INTEGER DEFAULT 0,
                tls_fp       TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS balances (
                address   TEXT PRIMARY KEY,
                balance   REAL DEFAULT 0.0
            );
            CREATE TABLE IF NOT EXISTS blocks (
                idx         INTEGER PRIMARY KEY,
                block_hash  TEXT UNIQUE,
                prev_hash   TEXT,
                timestamp   INTEGER,
                miner       TEXT,
                difficulty  REAL,
                nonce       INTEGER,
                merkle_root TEXT,
                state_root  TEXT DEFAULT '',
                finalized   INTEGER DEFAULT 0,
                data_json   TEXT
            );
            CREATE TABLE IF NOT EXISTS transactions (
                tx_id     TEXT PRIMARY KEY,
                block_idx INTEGER,
                sender    TEXT,
                receiver  TEXT,
                amount    REAL,
                fee       REAL,
                timestamp INTEGER,
                data_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_tx_block_idx ON transactions(block_idx);
            CREATE TABLE IF NOT EXISTS contract_accounts (
                address       TEXT    PRIMARY KEY,
                code_hash     TEXT    NOT NULL DEFAULT '',
                storage_root  TEXT    NOT NULL DEFAULT '',
                nonce         INTEGER NOT NULL DEFAULT 0,
                creator       TEXT    NOT NULL DEFAULT '',
                created_at    INTEGER NOT NULL DEFAULT 0,
                destroyed     INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_contract_created_at
                ON contract_accounts(created_at DESC);
            -- v7.4.0: slim header table for rolling-window pruned blocks
            CREATE TABLE IF NOT EXISTS block_headers (
                idx         INTEGER PRIMARY KEY,
                block_hash  TEXT NOT NULL,
                prev_hash   TEXT NOT NULL,
                merkle_root TEXT NOT NULL DEFAULT '',
                state_root  TEXT NOT NULL DEFAULT '',
                timestamp   INTEGER NOT NULL DEFAULT 0,
                difficulty  REAL    NOT NULL DEFAULT 0,
                nonce       INTEGER NOT NULL DEFAULT 0
            );
            -- v11.0.0: Native State Channels table
            CREATE TABLE IF NOT EXISTS state_channels (
                channel_id      TEXT    PRIMARY KEY,
                contract_addr   TEXT    NOT NULL DEFAULT '',
                opener          TEXT    NOT NULL,
                counterparty    TEXT    NOT NULL,
                total_deposit_sat INTEGER NOT NULL DEFAULT 0,
                opener_deposit_sat INTEGER NOT NULL DEFAULT 0,
                timeout_blocks  INTEGER NOT NULL DEFAULT 100,
                open_height     INTEGER NOT NULL DEFAULT 0,
                status          TEXT    NOT NULL DEFAULT 'OPEN',
                dispute_seq     INTEGER NOT NULL DEFAULT 0,
                dispute_bal_opener INTEGER NOT NULL DEFAULT 0,
                dispute_bal_counter INTEGER NOT NULL DEFAULT 0,
                dispute_height  INTEGER NOT NULL DEFAULT 0,
                closed_height   INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_sc_opener
                ON state_channels(opener);
            CREATE INDEX IF NOT EXISTS idx_sc_counterparty
                ON state_channels(counterparty);
            CREATE INDEX IF NOT EXISTS idx_sc_status
                ON state_channels(status);
            """)
            c.commit()
            # SC-NAME-1 inline guard for PGX aux-sqlite shadow table.
            # The executescript above uses CREATE TABLE IF NOT EXISTS, so an
            # existing old-schema table (without contract_name) is left as-is.
            # We must add the column and index here, AFTER executescript, using
            # individual guarded execute() calls so errors don't abort startup.
            try:
                cols = {row[1] for row in c.execute(
                    "PRAGMA table_info(contract_accounts)")}
                if "contract_name" not in cols:
                    c.execute(
                        "ALTER TABLE contract_accounts "
                        "ADD COLUMN contract_name TEXT NOT NULL DEFAULT ''")
                    c.commit()
            except Exception:
                pass
            try:
                c.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_contract_name_unique "
                    "ON contract_accounts (contract_name) "
                    "WHERE destroyed = 0 AND contract_name != ''")
                c.commit()
            except Exception:
                pass  # index already exists — harmless
            # Validator votes are canonical in PostgreSQL in PGX mode.  The
            # auxiliary SQLite schema is only a shadow schema, so no vote
            # migration is required here.
            return
        # Legacy sqlite mode: original full schema
        c.executescript("""
        CREATE TABLE IF NOT EXISTS blocks (
            idx         INTEGER PRIMARY KEY,
            block_hash  TEXT UNIQUE,
            prev_hash   TEXT,
            timestamp   INTEGER,
            miner       TEXT,
            difficulty  REAL,
            nonce       INTEGER,
            merkle_root TEXT,
            state_root  TEXT DEFAULT '',
            finalized   INTEGER DEFAULT 0,
            data_json   TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_block_hash ON blocks(block_hash);
        CREATE TABLE IF NOT EXISTS transactions (
            tx_id     TEXT PRIMARY KEY,
            block_idx INTEGER,
            sender    TEXT,
            receiver  TEXT,
            amount    REAL,
            fee       REAL,
            timestamp INTEGER,
            data_json TEXT
        );
        -- Replay protection is independent of the prunable transactions table.
        -- Rollback/reorg code deliberately removes entries for orphaned blocks,
        -- while canonical/pruned history keeps them indefinitely.
        CREATE TABLE IF NOT EXISTS tx_replay_guard (
            tx_id TEXT PRIMARY KEY
        );
        CREATE INDEX IF NOT EXISTS idx_tx_sender   ON transactions(sender);
        CREATE INDEX IF NOT EXISTS idx_tx_receiver ON transactions(receiver);
        CREATE TABLE IF NOT EXISTS balances (
            address   TEXT PRIMARY KEY,
            balance   REAL DEFAULT 0.0
        );
        CREATE TABLE IF NOT EXISTS roles (
            address       TEXT PRIMARY KEY,
            role          TEXT,
            stake         REAL DEFAULT 0.0,
            score         REAL DEFAULT 1.0,
            slashed       INTEGER DEFAULT 0,
            registered_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS identities (
            user_id    TEXT PRIMARY KEY,
            peer_id     TEXT, wallet_addr TEXT, pub_hex TEXT,
            multiaddrs TEXT, last_seen INTEGER
        );
        CREATE TABLE IF NOT EXISTS name_claims (
            user_id           TEXT PRIMARY KEY,
            wallet_addr       TEXT NOT NULL,
            pub_hex           TEXT NOT NULL,
            registered_height INTEGER NOT NULL,
            tx_id             TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS peers (
            peer_id      TEXT PRIMARY KEY,
            ip TEXT, port INTEGER, last_seen INTEGER,
            reputation REAL DEFAULT 1.0,
            fail_count INTEGER DEFAULT 0,
            blacklisted INTEGER DEFAULT 0,
            ban_score INTEGER DEFAULT 0,
            tls_fp TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS mempool (
            tx_id TEXT PRIMARY KEY, fee REAL, timestamp INTEGER, data_json TEXT
        );
        CREATE TABLE IF NOT EXISTS ht_volume (
            address TEXT PRIMARY KEY, volume REAL DEFAULT 0.0, updated INTEGER
        );
        CREATE TABLE IF NOT EXISTS node_meta (
            key TEXT PRIMARY KEY, value TEXT
        );
        CREATE TABLE IF NOT EXISTS validator_votes (
            block_hash TEXT, validator_addr TEXT,
            block_idx  INTEGER NOT NULL DEFAULT -1,
            sig_hex TEXT, pub_hex TEXT,
            PRIMARY KEY (block_hash, validator_addr)
        );
        CREATE TABLE IF NOT EXISTS account_nonces (
            address TEXT PRIMARY KEY, nonce INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS upgrade_proposals (
            version INTEGER PRIMARY KEY,
            phase TEXT DEFAULT 'DORMANT',
            signal_start_height INTEGER DEFAULT 0,
            signal_end_height INTEGER DEFAULT 0,
            lock_in_height INTEGER DEFAULT 0,
            activation_height INTEGER DEFAULT 0,
            threshold REAL DEFAULT 0.75,
            rollback_window INTEGER DEFAULT 100,
            created_at INTEGER DEFAULT 0,
            updated_at INTEGER DEFAULT 0,
            disabled INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS contract_accounts (
            address       TEXT    PRIMARY KEY,
            code_hash     TEXT    NOT NULL DEFAULT '',
            storage_root  TEXT    NOT NULL DEFAULT '',
            nonce         INTEGER NOT NULL DEFAULT 0,
            creator       TEXT    NOT NULL DEFAULT '',
            created_at    INTEGER NOT NULL DEFAULT 0,
            destroyed     INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS contract_code (
            code_hash TEXT PRIMARY KEY, bytecode TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS contract_storage (
            contract_addr TEXT NOT NULL,
            slot_key TEXT NOT NULL,
            slot_value TEXT NOT NULL DEFAULT '0',
            PRIMARY KEY (contract_addr, slot_key)
        );
        CREATE TABLE IF NOT EXISTS contract_storage_tags (
            contract_addr TEXT NOT NULL,
            slot_key TEXT NOT NULL,
            type_tag INTEGER NOT NULL,
            PRIMARY KEY (contract_addr, slot_key),
            CHECK (type_tag BETWEEN 1 AND 7)
        );
        CREATE TABLE IF NOT EXISTS vvm_receipts (
            tx_id TEXT PRIMARY KEY,
            block_idx INTEGER NOT NULL,
            contract_addr TEXT NOT NULL DEFAULT '',
            gas_used INTEGER NOT NULL DEFAULT 0,
            gas_limit INTEGER NOT NULL DEFAULT 0,
            success INTEGER NOT NULL DEFAULT 1,
            return_data TEXT NOT NULL DEFAULT '',
            revert_reason TEXT NOT NULL DEFAULT '',
            logs TEXT NOT NULL DEFAULT '[]',
            storage_delta TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS state_channels (
            channel_id        TEXT    PRIMARY KEY,
            contract_addr     TEXT    NOT NULL DEFAULT '',
            opener            TEXT    NOT NULL,
            counterparty      TEXT    NOT NULL,
            total_deposit_sat INTEGER NOT NULL DEFAULT 0,
            opener_deposit_sat INTEGER NOT NULL DEFAULT 0,
            timeout_blocks    INTEGER NOT NULL DEFAULT 100,
            open_height       INTEGER NOT NULL DEFAULT 0,
            status            TEXT    NOT NULL DEFAULT 'OPEN',
            dispute_seq       INTEGER NOT NULL DEFAULT 0,
            dispute_bal_opener INTEGER NOT NULL DEFAULT 0,
            dispute_bal_counter INTEGER NOT NULL DEFAULT 0,
            dispute_height    INTEGER NOT NULL DEFAULT 0,
            closed_height     INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_sc_opener
            ON state_channels(opener);
        CREATE INDEX IF NOT EXISTS idx_sc_counterparty
            ON state_channels(counterparty);
        CREATE INDEX IF NOT EXISTS idx_sc_status
            ON state_channels(status);
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY, value TEXT
        );
        CREATE TABLE IF NOT EXISTS reputation_extended (
            peer_id TEXT PRIMARY KEY, score REAL DEFAULT 0.5,
            fast_blocks INTEGER DEFAULT 0, valid_txs INTEGER DEFAULT 0,
            uptime_ticks INTEGER DEFAULT 0, last_updated INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS peer_capabilities (
            peer_id TEXT NOT NULL, capability TEXT NOT NULL,
            updated_at INTEGER DEFAULT 0,
            PRIMARY KEY (peer_id, capability)
        );
        """)
        c.commit()
        # Existing SQLite databases were created before validator_votes gained
        # an explicit block height.  Backfill the new column from the canonical
        # block table so orphaned votes remain independently queryable by
        # height after a reorg.
        try:
            cols = {row[1] for row in c.execute("PRAGMA table_info(validator_votes)")}
            if "block_idx" not in cols:
                c.execute(
                    "ALTER TABLE validator_votes "
                    "ADD COLUMN block_idx INTEGER NOT NULL DEFAULT -1")
                c.execute(
                    """UPDATE validator_votes
                       SET block_idx = COALESCE(
                           (SELECT b.idx FROM blocks b
                            WHERE b.block_hash = validator_votes.block_hash),
                           -1)
                       WHERE block_idx = -1""")
                c.commit()
        except Exception as exc:
            log.error("validator_votes schema migration failed: %s", exc)
            raise

        # ── v7.4.0: block_headers slim table for pruned blocks ───────────────
        # Created AFTER the main executescript so it is always present
        # regardless of which schema path ran above.
        try:
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
            c.commit()
        except Exception:
            pass

        # ── SC-NAME-1 inline guard ───────────────────────────────────────────
        # On existing databases the contract_accounts table was created before
        # the contract_name column was added in v7.3.0.  The executescript
        # above uses CREATE TABLE IF NOT EXISTS, so an existing table is left
        # as-is — meaning contract_name may be absent.
        # Use PRAGMA table_info to verify presence before attempting ALTER TABLE
        # so a silent exception can never leave the column missing.
        try:
            cols = {row[1] for row in c.execute(
                "PRAGMA table_info(contract_accounts)")}
            if "contract_name" not in cols:
                c.execute(
                    "ALTER TABLE contract_accounts "
                    "ADD COLUMN contract_name TEXT NOT NULL DEFAULT ''")
                c.commit()
        except Exception:
            pass   # column already present or table not yet created — harmless

        try:
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_contract_name_unique "
                "ON contract_accounts (contract_name) "
                "WHERE destroyed = 0 AND contract_name != ''")
            c.commit()
        except Exception:
            pass

    # ── backward-compat aliases for the external raw-SQL callers ────────────
    def _init_db(self):
        # Retained for any subclass / test still calling it.
        self._init_aux_schema()

    def _run_legacy_balance_migration_once(self):
        """One-shot migration guard — no-op when already marked."""
        try:
            c = self._conn()
            row = c.execute(
                "SELECT value FROM schema_meta WHERE key=?",
                ("balances_satoshi_migrated_v2",)).fetchone()
            if row:
                return
            c.execute(
                "INSERT OR REPLACE INTO schema_meta (key,value) VALUES (?,?)",
                ("balances_satoshi_migrated_v2", "1"))
            c.commit()
        except Exception:
            pass

    def _run_sc_name_1_migration_once(self):
        """
        SC-NAME-1: Idempotent migration — add contract_name column and unique
        index to contract_accounts on first start after upgrading to v7.3.0.

        Safe to call multiple times.  Uses schema_meta to skip the ALTER TABLE
        attempt on nodes that are already on the new schema, avoiding the
        sqlite3.OperationalError that SQLite raises when the column already
        exists (SQLite does not support ALTER TABLE … ADD COLUMN IF NOT EXISTS).
        """
        try:
            c = self._conn()
            # Check if migration has already been recorded
            try:
                row = c.execute(
                    "SELECT value FROM schema_meta WHERE key=?",
                    ("sc_name_1_migrated",)).fetchone()
                if row:
                    return
            except Exception:
                pass  # schema_meta may not exist in very old DBs; proceed

            # Add contract_name column (may already exist on new chains)
            try:
                cols = {row[1] for row in c.execute(
                    "PRAGMA table_info(contract_accounts)")}
                if "contract_name" not in cols:
                    c.execute(
                        "ALTER TABLE contract_accounts "
                        "ADD COLUMN contract_name TEXT NOT NULL DEFAULT ''")
                    c.commit()
            except Exception:
                pass  # column already exists — harmless

            # Add unique partial index (idempotent via IF NOT EXISTS)
            try:
                c.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_contract_name_unique "
                    "ON contract_accounts (contract_name) "
                    "WHERE destroyed = 0 AND contract_name != ''")
                c.commit()
            except Exception:
                pass  # index already exists — harmless

            # Mark migration as complete
            try:
                c.execute(
                    "INSERT OR REPLACE INTO schema_meta (key,value) VALUES (?,?)",
                    ("sc_name_1_migrated", "1"))
                c.commit()
            except Exception:
                pass
        except Exception as exc:
            log.warning("SC-NAME-1 migration warning (non-fatal): %s", exc)

    # ── helpers for PG sync-invocation from this sync class ────────────────
    def _pgx_active_conn(self):
        if not self._pgx_enabled:
            return None
        return getattr(self._pgx_block_local, "conn", None)

    def _pgx_active_state(self):
        if not self._pgx_enabled:
            return None
        return getattr(self._pgx_block_local, "state", None)

    def _pgx_after_commit(self, fn, *args, **kwargs):
        """Run a non-authoritative side effect now or after PG commit.

        Redis and aux-SQLite are caches/shadows, not consensus storage.  They
        must never be updated from inside an active block transaction because
        a later consensus failure could roll PostgreSQL back while leaving a
        cache/shadow that falsely reflects the rejected block.
        """
        state = self._pgx_active_state()
        if state is not None:
            state.setdefault("after_commit", []).append((fn, args, kwargs))
            return
        fn(*args, **kwargs)

    def _pgx_restore_rocks_changes(self, changes):
        """Restore every RocksDB mutation made by an aborted PGX transaction."""
        if not changes:
            return
        with self._commit_lock:
            for change in reversed(list(changes)):
                try:
                    height = int(change["height"])
                    previous = change.get("previous")
                    prev_tip = change.get("previous_tip")
                    prev_tip_hash = change.get("previous_tip_hash")
                    old_hash = str(previous.get("block_hash", "")) if previous else ""
                    batch = self._rocks.new_batch()
                    if previous is None:
                        self._rocks.delete_block(
                            batch, height, str(change.get("new_hash", "")))
                        for tx_id in change.get("new_tx_ids", ()):
                            if tx_id:
                                self._rocks.delete_tx_loc(batch, str(tx_id))
                    else:
                        hdr = {
                            "idx": height,
                            "block_hash": old_hash,
                            "prev_hash": previous.get("prev_hash", ""),
                            "timestamp": previous.get("timestamp", 0),
                            "merkle_root": previous.get("merkle_root", ""),
                            "state_root": previous.get("state_root", ""),
                            "difficulty": previous.get("difficulty", 0),
                            "nonce": previous.get("nonce", 0),
                        }
                        self._rocks.put_block(
                            batch, height, previous, hdr, old_hash)
                        for tx_index, tx in enumerate(previous.get("transactions") or []):
                            tx_id = tx.get("tx_id") if isinstance(tx, dict) else None
                            if tx_id:
                                self._rocks.put_tx_loc(
                                    batch, tx_id, height, tx_index)
                    if prev_tip is None:
                        self._rocks.delete_meta(batch, _META_CHAIN_TIP)
                        self._rocks.delete_meta(batch, _META_TIP_HASH)
                    else:
                        self._rocks.put_meta(batch, _META_CHAIN_TIP, prev_tip)
                        self._rocks.put_meta(
                            batch, _META_TIP_HASH, prev_tip_hash or b"")
                    self._rocks.commit(batch, sync=True)
                except Exception as exc:
                    log.error(
                        "PGX rollback restore failed for RocksDB block #%s: %s",
                        change.get("height"), exc)

    def _pgx_resolve_commit_outcome(self, expected_height: int,
                                    expected_hash: str) -> bool:
        """Resolve an ambiguous PostgreSQL COMMIT result without data loss."""
        try:
            row = self._pg_fetchrow(
                "SELECT value FROM node_meta WHERE key=$1",
                "canonical_tip_height")
            h = int(row["value"]) if row else -1
            row2 = self._pg_fetchrow(
                "SELECT value FROM node_meta WHERE key=$1",
                "canonical_tip_hash")
            bh = str(row2["value"]) if row2 else ""
            return h == int(expected_height) and bh == str(expected_hash)
        except Exception:
            # Unknown commit outcome: fail closed and leave RocksDB intact.
            # The next startup's reconciliation can safely determine whether
            # the PostgreSQL transaction committed.
            return False

    def _init_pgx_canonical_state(self) -> None:
        """Load and reconcile the durable PGX canonical-tip commit marker.

        State mutations and this marker are committed in one PostgreSQL
        transaction.  RocksDB is written first, but readers consider a RocksDB
        block canonical only up to this committed PG marker.  Therefore a
        process death between the RocksDB fsync and PostgreSQL COMMIT leaves
        only an orphaned RocksDB block, which is hidden and removed here.

        Existing PGX databases created before this marker existed are migrated
        conservatively by taking their current RocksDB tip as the initial
        canonical tip.  There is no historical crash marker to infer beyond
        that point, so this one-time bootstrap does not rewrite state.
        """
        row_h = self._pg_fetchrow(
            "SELECT value FROM node_meta WHERE key=$1",
            "canonical_tip_height")
        row_hash = self._pg_fetchrow(
            "SELECT value FROM node_meta WHERE key=$1",
            "canonical_tip_hash")

        rocks_tip = int(self._rocks.tip_height())
        rocks_hash = ""
        if rocks_tip >= 0:
            rb = self._rocks.get_block(rocks_tip)
            if rb is not None:
                rocks_hash = str(rb.get("block_hash", ""))
            else:
                rh = self._rocks.get_header(rocks_tip)
                if rh is not None:
                    rocks_hash = str(rh.get("block_hash", ""))

        if row_h is None:
            # Pre-marker migration. Persist both halves of the marker in one
            # PostgreSQL transaction so a crash cannot leave a height marker
            # without its corresponding hash.
            async def _migrate_marker():
                async with self._pg._pool.acquire() as c:
                    async with c.transaction():
                        await c.execute(
                            """INSERT INTO node_meta (key, value) VALUES ($1, $2)
                               ON CONFLICT (key) DO NOTHING""",
                            "canonical_tip_height", str(rocks_tip))
                        await c.execute(
                            """INSERT INTO node_meta (key, value) VALUES ($1, $2)
                               ON CONFLICT (key) DO NOTHING""",
                            "canonical_tip_hash", rocks_hash)
            self._pg.run(_migrate_marker())
            self._pgx_canonical_tip = rocks_tip
            self._pgx_canonical_tip_hash = rocks_hash
            return

        try:
            canonical_tip = int(row_h["value"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "PGX canonical_tip_height is corrupt; refusing to start") from exc
        canonical_hash = str(row_hash["value"]) if row_hash else ""
        if canonical_tip >= 0 and not canonical_hash:
            raise RuntimeError(
                "PGX canonical_tip_hash is missing; refusing to start")

        if rocks_tip > canonical_tip:
            # These blocks were written to RocksDB before a PG commit and are
            # therefore uncommitted according to the authoritative marker.
            for height in range(rocks_tip, canonical_tip, -1):
                try:
                    blk = self._rocks.get_block(height)
                    if blk is not None:
                        bhash = str(blk.get("block_hash", ""))
                    else:
                        hdr = self._rocks.get_header(height)
                        bhash = str(hdr.get("block_hash", "")) if hdr else ""
                    batch = self._rocks.new_batch()
                    self._rocks.delete_block(batch, height, bhash)
                    if blk is not None:
                        for tx in blk.get("transactions") or []:
                            tx_id = tx.get("tx_id") if isinstance(tx, dict) else None
                            if tx_id:
                                self._rocks.delete_tx_loc(batch, tx_id)
                    self._rocks.commit(batch, sync=True)
                except Exception as exc:
                    raise RuntimeError(
                        f"PGX recovery could not remove uncommitted RocksDB block #{height}") from exc
            rocks_tip = int(self._rocks.tip_height())
            rb = self._rocks.get_block(canonical_tip) if canonical_tip >= 0 else None
            rocks_hash = str(rb.get("block_hash", "")) if rb else ""

        if rocks_tip < canonical_tip:
            raise RuntimeError(
                "PGX canonical PostgreSQL tip is ahead of RocksDB; refusing "
                f"to start (postgres={canonical_tip}, rocks={rocks_tip})")
        if canonical_tip >= 0 and canonical_hash and rocks_hash != canonical_hash:
            raise RuntimeError(
                "PGX canonical tip hash does not match RocksDB; refusing to start "
                f"at height {canonical_tip}")

        self._pgx_canonical_tip = canonical_tip
        self._pgx_canonical_tip_hash = canonical_hash

    @contextmanager
    def pgx_atomic_block(self):
        """Transaction spanning the complete PGX consensus block application."""
        if not self._pgx_enabled:
            yield None
            return

        if self._pgx_active_conn() is not None:
            yield self._pgx_active_state()
            return

        self._commit_lock.acquire()

        async def _start():
            conn = await self._pg._pool.acquire()
            tx = conn.transaction()
            await tx.start()
            return conn, tx

        conn, tx = self._pg.run(_start())
        state = {
            "conn": conn,
            "tx": tx,
            "commit": False,
            "rocks_changes": [],
            "after_commit": [],
            "pending_tip": None,
        }
        self._pgx_block_local.conn = conn
        self._pgx_block_local.state = state
        committed = False
        try:
            yield state
            if not state.get("commit"):
                self._pg.run(tx.rollback())
                self._pg.run(self._pg._pool.release(conn))
                self._pgx_restore_rocks_changes(state.get("rocks_changes", []))
                return

            expected = state.get("pending_tip")
            try:
                self._pg.run(tx.commit())
                committed = True
            except BaseException as commit_exc:
                # asyncpg cannot always distinguish "server committed, client
                # lost response" from "server rolled back". Resolve using the
                # durable canonical marker before deciding whether RocksDB may
                # be deleted. Never delete on an unknown outcome.
                try:
                    self._pg.run(self._pg._pool.release(conn))
                except Exception:
                    pass
                self._pgx_block_local.conn = None
                self._pgx_block_local.state = None
                if expected is not None and self._pgx_resolve_commit_outcome(
                        expected[0], expected[1]):
                    committed = True
                else:
                    state["commit_exception_is_ambiguous"] = True
                    log.error(
                        "PGX transaction COMMIT outcome is ambiguous at #%s; "
                        "leaving RocksDB intact for startup reconciliation: %s",
                        expected[0] if expected else "?", commit_exc)
                    raise
            else:
                try:
                    self._pg.run(self._pg._pool.release(conn))
                except Exception:
                    pass
        except BaseException:
            if not committed:
                try:
                    # If control reached here after a normal-body exception,
                    # the transaction is still open.  A failed rollback is
                    # harmless because RocksDB cleanup below is conditional.
                    self._pg.run(tx.rollback())
                except Exception:
                    pass
                try:
                    self._pg.run(self._pg._pool.release(conn))
                except Exception:
                    pass
                # Do not perform cleanup after an ambiguous COMMIT outcome.
                if state.get("commit_exception_is_ambiguous") is not True:
                    self._pgx_restore_rocks_changes(state.get("rocks_changes", []))
            raise
        finally:
            self._pgx_block_local.conn = None
            self._pgx_block_local.state = None
            if committed:
                pending = state.get("pending_tip")
                if pending is not None:
                    self._pgx_canonical_tip = int(pending[0])
                    self._pgx_canonical_tip_hash = str(pending[1])
                for fn, args, kwargs in state.get("after_commit", []):
                    try:
                        fn(*args, **kwargs)
                    except Exception as exc:
                        log.warning("PGX post-commit side effect failed: %s", exc)
            self._commit_lock.release()

    def _pg_exec(self, sql, *args):
        active = self._pgx_active_conn()
        if active is not None:
            async def _e_active():
                return await active.execute(sql, *args)
            return self._pg.run(_e_active())
        async def _e():
            async with self._pg._pool.acquire() as c:
                return await c.execute(sql, *args)
        return self._pg.run(_e())

    def _pg_fetch(self, sql, *args):
        active = self._pgx_active_conn()
        if active is not None:
            async def _f_active():
                return await active.fetch(sql, *args)
            return self._pg.run(_f_active())
        async def _f():
            async with self._pg._pool.acquire() as c:
                return await c.fetch(sql, *args)
        return self._pg.run(_f())

    def _pg_fetchrow(self, sql, *args):
        active = self._pgx_active_conn()
        if active is not None:
            async def _fr_active():
                return await active.fetchrow(sql, *args)
            return self._pg.run(_fr_active())
        async def _fr():
            async with self._pg._pool.acquire() as c:
                return await c.fetchrow(sql, *args)
        return self._pg.run(_fr())

    # ── VVM state-channel transaction journal ────────────────────────────────
    def _state_channel_journal_stack(self):
        """Return the per-thread stack of active VVM state-channel journals."""
        local = getattr(self, "_state_channel_journal_local", None)
        if local is None:
            self._state_channel_journal_local = threading.local()
            local = self._state_channel_journal_local
        if not hasattr(local, "stack"):
            local.stack = []
        return local.stack

    def begin_state_channel_journal(self) -> dict:
        """Begin an execution-scoped journal for channel/account side effects."""
        journal = {"channels": {}, "accounts": {}}
        self._state_channel_journal_stack().append(journal)
        return journal

    def end_state_channel_journal(self, journal: dict) -> dict:
        """Finish a journal while retaining its captured pre-state."""
        stack = self._state_channel_journal_stack()
        if not stack or stack[-1] is not journal:
            raise RuntimeError("state-channel journal nesting mismatch")
        stack.pop()
        return journal

    def _record_state_channel_before(self, channel_id: str,
                                     previous: Optional[dict]) -> None:
        """Capture first pre-mutation channel row in every active journal."""
        if not channel_id:
            return
        for journal in self._state_channel_journal_stack():
            channels = journal.setdefault("channels", {})
            if channel_id not in channels:
                channels[channel_id] = (
                    dict(previous) if previous is not None else None)

    def _record_state_channel_balance_before(
            self, address: str, snapshot: Optional[tuple] = None) -> None:
        """Capture the first pre-mutation account state in every active journal.

        ``snapshot`` is optional for the normal Storage path.  The block batch
        proxy supplies a proxy-visible snapshot so nested VVM channel mutations
        do not accidentally capture the persistent pre-block balance instead of
        the current in-block balance.
        """
        if not address:
            return
        if snapshot is None:
            snapshot = self.snapshot_accounts([address]).get(address)
        if snapshot is None:
            return
        snapshot = tuple(snapshot)
        for journal in self._state_channel_journal_stack():
            accounts = journal.setdefault("accounts", {})
            if address not in accounts:
                accounts[address] = snapshot

    def restore_state_channel_journal(
            self, journal: dict, restore_accounts: bool = True) -> None:
        """Restore exactly the channel rows and direct balance mutations captured.

        ``restore_accounts=False`` is used by block-scoped VVM undo after the
        normal whole-block account snapshot has already restored balances.  In
        that path the journal must restore only the auxiliary state-channel rows;
        restoring its account snapshot again could resurrect effects from an
        earlier transaction in the same block.
        """
        if not journal:
            return
        channels = journal.get("channels", journal if "channels" not in journal else {})
        accounts = journal.get("accounts", {})

        # Restore database state first.  Account restoration intentionally uses
        # Storage.restore_accounts(), which keeps the PG/SQLite/cache projections
        # synchronized exactly like the normal block snapshot path.
        if restore_accounts and accounts:
            self.restore_accounts(accounts)

        if not channels:
            return

        if self._pgx_enabled:
            async def _restore_pg(c):
                for channel_id, previous in channels.items():
                    await c.execute(
                        "DELETE FROM state_channels WHERE channel_id=$1",
                        str(channel_id))
                    if previous is not None:
                        await c.execute(
                            """INSERT INTO state_channels
                               (channel_id, contract_addr, opener, counterparty,
                                total_deposit_sat, opener_deposit_sat, timeout_blocks,
                                open_height, status, dispute_seq, dispute_bal_opener,
                                dispute_bal_counter, dispute_height, closed_height)
                               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)""",
                            str(previous.get("channel_id", channel_id)),
                            str(previous.get("contract_addr", "")),
                            str(previous.get("opener", "")),
                            str(previous.get("counterparty", "")),
                            int(previous.get("total_deposit_sat", 0)),
                            int(previous.get("opener_deposit_sat", 0)),
                            int(previous.get("timeout_blocks", 100)),
                            int(previous.get("open_height", 0)),
                            str(previous.get("status", "OPEN")),
                            int(previous.get("dispute_seq", 0)),
                            int(previous.get("dispute_bal_opener", 0)),
                            int(previous.get("dispute_bal_counter", 0)),
                            int(previous.get("dispute_height", 0)),
                            int(previous.get("closed_height", 0)),
                        )

            active = self._pgx_active_conn()
            if active is not None:
                self._pg.run(_restore_pg(active))
            else:
                async def _restore_pg_independent():
                    async with self._pg._pool.acquire() as c:
                        async with c.transaction():
                            await _restore_pg(c)
                self._pg.run(_restore_pg_independent())
            # Aux-SQLite is a shadow only; never make a rollback visible there
            # before the authoritative PG transaction commits.
            def _mirror_channels(chs=dict(channels)):
                try:
                    with self._aux_lock:
                        c = self._conn()
                        for channel_id, previous in chs.items():
                            c.execute(
                                "DELETE FROM state_channels WHERE channel_id=?",
                                (str(channel_id),))
                            if previous is not None:
                                c.execute(
                                    """INSERT INTO state_channels
                                       (channel_id, contract_addr, opener, counterparty,
                                        total_deposit_sat, opener_deposit_sat, timeout_blocks,
                                        open_height, status, dispute_seq, dispute_bal_opener,
                                        dispute_bal_counter, dispute_height, closed_height)
                                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                                    (str(previous.get("channel_id", channel_id)),
                                     str(previous.get("contract_addr", "")),
                                     str(previous.get("opener", "")),
                                     str(previous.get("counterparty", "")),
                                     int(previous.get("total_deposit_sat", 0)),
                                     int(previous.get("opener_deposit_sat", 0)),
                                     int(previous.get("timeout_blocks", 100)),
                                     int(previous.get("open_height", 0)),
                                     str(previous.get("status", "OPEN")),
                                     int(previous.get("dispute_seq", 0)),
                                     int(previous.get("dispute_bal_opener", 0)),
                                     int(previous.get("dispute_bal_counter", 0)),
                                     int(previous.get("dispute_height", 0)),
                                     int(previous.get("closed_height", 0))))
                        c.commit()
                except Exception as exc:
                    log.warning("state-channel aux restore failed: %s", exc)
            self._pgx_after_commit(_mirror_channels)
            return
            return

        c = self._conn()
        try:
            for channel_id, previous in channels.items():
                c.execute("DELETE FROM state_channels WHERE channel_id=?",
                          (str(channel_id),))
                if previous is not None:
                    c.execute(
                        """INSERT INTO state_channels
                           (channel_id, contract_addr, opener, counterparty,
                            total_deposit_sat, opener_deposit_sat, timeout_blocks,
                            open_height, status, dispute_seq, dispute_bal_opener,
                            dispute_bal_counter, dispute_height, closed_height)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (str(previous.get("channel_id", channel_id)),
                         str(previous.get("contract_addr", "")),
                         str(previous.get("opener", "")),
                         str(previous.get("counterparty", "")),
                         int(previous.get("total_deposit_sat", 0)),
                         int(previous.get("opener_deposit_sat", 0)),
                         int(previous.get("timeout_blocks", 100)),
                         int(previous.get("open_height", 0)),
                         str(previous.get("status", "OPEN")),
                         int(previous.get("dispute_seq", 0)),
                         int(previous.get("dispute_bal_opener", 0)),
                         int(previous.get("dispute_bal_counter", 0)),
                         int(previous.get("dispute_height", 0)),
                         int(previous.get("closed_height", 0))))
            c.commit()
            self._maybe_checkpoint()
        except Exception:
            c.rollback()
            raise

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  BALANCES / NONCES   (PostgreSQL accounts table + Redis cache)         ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def _get_balance_satoshi(self, address: str) -> int:
        if self._pgx_enabled:
            # Redis contains only the last committed value.  During a live
            # PGX block transaction it would hide earlier writes from the
            # same block, so read the transaction snapshot directly.
            if self._pgx_active_conn() is None:
                cached = self._cache.get_balance(address)
                if cached is not None:
                    return cached
            row = self._pg_fetchrow(
                "SELECT balance_sat FROM accounts WHERE address=$1", address)
            bal = int(row["balance_sat"]) if row else 0
            self._pgx_after_commit(self._cache.cache_balance, address, bal)
            return bal
        row = self._conn().execute(
            "SELECT balance FROM balances WHERE address=?", (address,)).fetchone()
        return int(row["balance"]) if row else 0

    def get_balances_sat(self, addresses: Iterable[str]) -> Dict[str, int]:
        """Read a set of balances in one query, defaulting missing rows to zero."""
        addrs = list(dict.fromkeys(str(a) for a in addresses if a))
        if not addrs:
            return {}
        result = {a: 0 for a in addrs}
        chunk_size = 500
        if self._pgx_enabled:
            for i in range(0, len(addrs), chunk_size):
                chunk = addrs[i:i + chunk_size]
                rows = self._pg_fetch(
                    "SELECT address, balance_sat FROM accounts "
                    "WHERE address = ANY($1::text[])", chunk)
                for row in rows:
                    result[str(row["address"])] = int(row["balance_sat"])
            return result
        c = self._conn()
        for i in range(0, len(addrs), chunk_size):
            chunk = addrs[i:i + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            rows = c.execute(
                f"SELECT address, balance FROM balances WHERE address IN ({placeholders})",
                tuple(chunk)).fetchall()
            for row in rows:
                result[str(row["address"])] = int(row["balance"])
        return result

    def get_balance(self, address: str) -> float:
        return from_satoshi(self._get_balance_satoshi(address))

    def get_balance_sat(self, address: str) -> int:
        return self._get_balance_satoshi(address)

    def set_balance(self, address: str, balance):
        sat = to_satoshi(balance) if not isinstance(balance, int) else balance
        if self._pgx_enabled:
            self._pg_exec(
                """INSERT INTO accounts (address, balance_sat, updated_at)
                   VALUES ($1, $2, now())
                   ON CONFLICT (address) DO UPDATE SET
                       balance_sat = EXCLUDED.balance_sat,
                       updated_at  = now()""",
                address, sat)
            self._pgx_after_commit(self._cache.cache_balance, address, sat)
            self._pgx_after_commit(self._mirror_balance_to_aux, address, sat)
            return
        self._conn().execute(
            "INSERT OR REPLACE INTO balances (address, balance) VALUES (?,?)",
            (address, sat))
        self._conn().commit()
        self._maybe_checkpoint()

    def credit(self, address: str, amount: float):
        self.credit_sat(address, to_satoshi(amount))

    def credit_sat(self, address: str, amount_sat: int):
        # AUDIT-FIX-10 (unauthorized minting, defense in depth): see the
        # matching guard in _StorageBatchProxy.credit_sat for the full
        # rationale. This is the authoritative implementation both the PG
        # and SQLite branches below share, so one guard covers both.
        if int(amount_sat) < 0:
            raise ValueError(
                f"credit_sat({address[:16]}, {amount_sat}): negative amount "
                f"rejected -- a negative credit is an unguarded debit")
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                """INSERT INTO accounts (address, balance_sat, updated_at)
                   VALUES ($1, $2, now())
                   ON CONFLICT (address) DO UPDATE SET
                       balance_sat = accounts.balance_sat + EXCLUDED.balance_sat,
                       updated_at  = now()
                   RETURNING balance_sat""",
                address, int(amount_sat))
            new_sat = int(row["balance_sat"]) if row else 0
            self._pgx_after_commit(self._cache.cache_balance, address, new_sat)
            self._pgx_after_commit(self._mirror_balance_to_aux, address, new_sat)
            return
        sat_bal = self._get_balance_satoshi(address)
        self._conn().execute(
            "INSERT OR REPLACE INTO balances (address, balance) VALUES (?,?)",
            (address, sat_bal + amount_sat))
        self._conn().commit()
        self._maybe_checkpoint()

    def debit(self, address: str, amount: float) -> bool:
        return self.debit_sat(address, to_satoshi(amount))

    def debit_sat(self, address: str, amount_sat: int) -> bool:
        # AUDIT-FIX-10 (unauthorized minting, defense in depth): see the
        # matching guard in _StorageBatchProxy.debit_sat for the full
        # rationale (a negative debit is an unguarded, unconditional
        # credit -- the WHERE balance_sat >= $2 / sat_bal < amount_sat
        # sufficiency checks below are trivially satisfied by any negative
        # amount_sat, regardless of the address's actual balance).
        if int(amount_sat) < 0:
            return False
        if self._pgx_enabled:
            # Conditional debit inside a single PG statement — atomic & race-free.
            row = self._pg_fetchrow(
                """UPDATE accounts SET
                       balance_sat = balance_sat - $2,
                       updated_at  = now()
                    WHERE address=$1 AND balance_sat >= $2
                   RETURNING balance_sat""",
                address, int(amount_sat))
            if row is None:
                return False
            new_sat = int(row["balance_sat"])
            self._pgx_after_commit(self._cache.cache_balance, address, new_sat)
            self._pgx_after_commit(self._mirror_balance_to_aux, address, new_sat)
            return True
        sat_bal = self._get_balance_satoshi(address)
        if sat_bal < amount_sat:
            return False
        self._conn().execute(
            "INSERT OR REPLACE INTO balances (address, balance) VALUES (?,?)",
            (address, sat_bal - amount_sat))
        self._conn().commit()
        self._maybe_checkpoint()
        return True

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  BLOCKS  (RocksDB bodies/headers/hash-index + PG tx metadata)          ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def save_block(self, block: 'Block'):
        if not self._pgx_enabled:
            return self._save_block_sqlite(block)

        active = self._pgx_active_state()
        if active is None:
            with self.pgx_atomic_block() as state:
                self._save_block_pgx(block, state)
                state["commit"] = True
            return
        return self._save_block_pgx(block, active)

    def _save_block_pgx(self, block: 'Block', state: dict):
        """Persist one PGX block with a durable PG canonical-tip barrier.

        RocksDB is written and fsynced first.  The block is not considered
        canonical until the surrounding PostgreSQL transaction commits its
        state changes plus ``canonical_tip_*`` together.  On rollback the
        Rocks write is restored/removed; after a process death, startup
        reconciliation removes any Rocks block above the committed PG tip.
        """
        block_dict = block.to_dict()
        bhash = str(block.block_hash)
        height = int(block.index)
        canonical_tip = int(
            state["pending_tip"][0] if state.get("pending_tip") is not None
            else self._pgx_canonical_tip)
        canonical_hash = str(
            state["pending_tip"][1] if state.get("pending_tip") is not None
            else self._pgx_canonical_tip_hash)

        # Storage-level ordering guard: normal consensus application is a
        # strict append.  Re-saving the exact current block is allowed for
        # finality-signature/finalized-field updates, but changing its hash at
        # the same height through this API is never silently accepted.
        if height == canonical_tip:
            current = self._rocks.get_block(height)
            current_hash = str(current.get("block_hash", "")) if current else ""
            if current_hash and current_hash != bhash:
                raise ValueError(
                    f"PGX save_block hash conflict at height {height}: "
                    f"canonical={current_hash}, incoming={bhash}")
        elif height != canonical_tip + 1:
            raise ValueError(
                f"PGX save_block requires canonical append at {canonical_tip + 1}, "
                f"received height {height}")
        elif canonical_tip >= 0 and canonical_hash and block.prev_hash != canonical_hash:
            raise ValueError(
                f"PGX save_block prev_hash mismatch at height {height}")

        previous = self._rocks.get_block(height)
        previous_tip_bytes = self._rocks.get_meta(_META_CHAIN_TIP)
        previous_tip_hash = self._rocks.get_meta(_META_TIP_HASH)

        batch = self._rocks.new_batch()
        self._rocks.put_block(batch, height, block_dict, {
            "idx": height,
            "block_hash": bhash,
            "prev_hash": block.prev_hash,
            "timestamp": block.timestamp,
            "merkle_root": block_dict.get("merkle_root", ""),
            "state_root": block_dict.get("state_root", ""),
            "difficulty": block_dict.get("difficulty", 0),
            "nonce": block_dict.get("nonce", 0),
        }, bhash)

        pg_tx_rows = []
        identity_rows = []
        for i, tx in enumerate(block.transactions):
            self._rocks.put_tx_loc(batch, tx.tx_id, height, i)
            pg_tx_rows.append((
                tx.tx_id, height, i,
                tx.sender or "", tx.receiver or "",
                int(to_satoshi(tx.amount)), int(to_satoshi(tx.fee)),
                int(getattr(tx, "nonce", 0) or 0),
                int(tx.timestamp or 0),
                _pg_tx_type_code(getattr(tx, "tx_type", None)),
                1, json.dumps(tx.to_dict()),
                (getattr(tx, "memo", "") or "")))
            claim_name = Transaction.identity_name_from_memo(
                getattr(tx, "memo", ""))
            if (tx.tx_type == Transaction.TYPE_REGISTER and claim_name
                    and tx.sender != "COINBASE" and tx.pub_hex):
                identity_rows.append((claim_name, tx.sender, tx.pub_hex,
                                       height, tx.tx_id))

        # Rocks tip metadata is intentionally part of the pre-commit Rocks
        # write.  If PostgreSQL rolls back, the transaction context restores
        # the prior tip metadata.  If PostgreSQL commits, the PG canonical tip
        # becomes the authoritative reader barrier.
        if height == canonical_tip + 1:
            self._rocks.put_meta(batch, _META_CHAIN_TIP, _u64(height))
            self._rocks.put_meta(batch, _META_TIP_HASH, bhash.encode("ascii"))

        self._rocks.commit(batch, sync=True)
        state.setdefault("rocks_changes", []).append({
            "height": height,
            "new_hash": bhash,
            "new_tx_ids": [t.tx_id for t in block.transactions if getattr(t, "tx_id", None)],
            "previous": previous,
            "previous_tip": previous_tip_bytes,
            "previous_tip_hash": previous_tip_hash,
        })

        if pg_tx_rows:
            active_conn = self._pgx_active_conn()
            async def _write(c):
                await c.executemany(
                    """INSERT INTO transactions
                       (tx_id, block_idx, tx_index, sender, receiver,
                        amount_sat, fee_sat, nonce, timestamp,
                        tx_type, status, data_json, memo)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                       ON CONFLICT (tx_id) DO NOTHING""", pg_tx_rows)
                await c.executemany(
                    """INSERT INTO tx_replay_guard (tx_id)
                       VALUES ($1) ON CONFLICT (tx_id) DO NOTHING""",
                    [(row[0],) for row in pg_tx_rows])
                if identity_rows:
                    await c.executemany(
                        """INSERT INTO name_claims
                           (user_id, wallet_addr, pub_hex,
                            registered_height, tx_id)
                           VALUES ($1,$2,$3,$4,$5)
                           ON CONFLICT (user_id) DO NOTHING""",
                        identity_rows)
                await c.execute(
                    """INSERT INTO node_meta (key, value) VALUES
                       ('last_projected_height', $1::text)
                       ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value""",
                    str(height))

            if active_conn is not None:
                self._pg.run(_write(active_conn))
            else:
                # Defensive fallback for direct/internal callers. Normally
                # save_block() has already created pgx_atomic_block().
                async def _independent():
                    async with self._pg._pool.acquire() as c:
                        async with c.transaction():
                            await _write(c)
                self._pg.run(_independent())

        # The canonical barrier is updated in the same PostgreSQL transaction
        # as all consensus-state mutations performed before this save_block().
        if height == canonical_tip + 1:
            self._pg_exec(
                """INSERT INTO node_meta (key, value) VALUES ($1,$2)
                   ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value""",
                "canonical_tip_height", str(height))
            self._pg_exec(
                """INSERT INTO node_meta (key, value) VALUES ($1,$2)
                   ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value""",
                "canonical_tip_hash", bhash)
            state["pending_tip"] = (height, bhash)

        # Non-authoritative cache/shadow updates happen only after the PG
        # transaction commits.  This is critical on block rejection/exception.
        self._pgx_after_commit(self._cache.set_tip, height, bhash)
        self._pgx_after_commit(
            self._cache.mempool_remove,
            [t.tx_id for t in block.transactions])
        self._pgx_after_commit(self._mirror_block_to_aux, block)

    def _reconcile_external_block_db(self) -> None:
        """Reconcile the non-transactional KV block store against SQLite.

        In the legacy SQLite+KV layout, SQLite is the authoritative commit
        barrier because all consensus projections commit there.  A crash can
        therefore leave a physically durable KV block that never reached the
        SQLite commit, or a committed SQLite row whose KV body is missing.
        Orphans are deleted; missing canonical bodies fail closed instead of
        allowing a node to operate on incomplete chain history.
        """
        row = self._conn().execute(
            "SELECT MAX(idx) AS h FROM blocks").fetchone()
        sqlite_tip = int(row["h"]) if row and row["h"] is not None else -1
        kv_tip = int(self._block_db.chain_height())

        if kv_tip > sqlite_tip:
            for height in range(kv_tip, sqlite_tip, -1):
                if not self._block_db.delete_block(height):
                    raise RuntimeError(
                        f"External block DB recovery failed to remove orphan block #{height}")
            kv_tip = int(self._block_db.chain_height())

        if kv_tip < sqlite_tip:
            raise RuntimeError(
                "SQLite canonical chain is ahead of external block DB; refusing "
                f"to start (sqlite={sqlite_tip}, kv={kv_tip})")

        if sqlite_tip >= 0:
            sql_tip = self._conn().execute(
                "SELECT block_hash FROM blocks WHERE idx=?",
                (sqlite_tip,)).fetchone()
            kv_block = self._block_db.get_block_by_height(sqlite_tip)
            if not sql_tip or kv_block is None or str(kv_block.get("block_hash", "")) != str(sql_tip["block_hash"] or ""):
                raise RuntimeError(
                    f"External block DB tip does not match SQLite canonical tip #{sqlite_tip}")

    def _save_block_sqlite(self, block):
        c = self._conn()
        if self._block_db.enabled:
            self._block_db.put_block(block)
            data_json_col = ""
        else:
            data_json_col = json.dumps(block.to_dict())
        c.execute("""INSERT OR REPLACE INTO blocks
            (idx,block_hash,prev_hash,timestamp,miner,difficulty,nonce,
             merkle_root,state_root,finalized,data_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (block.index, block.block_hash, block.prev_hash, block.timestamp,
             block.miner_address, block.difficulty, block.nonce,
             block.merkle_root, block.state_root,
             int(block.finalized), data_json_col))
        c.execute(
            "CREATE TABLE IF NOT EXISTS tx_replay_guard (tx_id TEXT PRIMARY KEY)")
        for tx in block.transactions:
            c.execute("""INSERT OR REPLACE INTO transactions
                (tx_id,block_idx,sender,receiver,amount,fee,timestamp,data_json)
                VALUES (?,?,?,?,?,?,?,?)""",
                (tx.tx_id, block.index, tx.sender, tx.receiver, tx.amount,
                 tx.fee, tx.timestamp, json.dumps(tx.to_dict())))
            # AUDIT-FIX-14b: permanent, never-pruned replay guard, committed
            # atomically with the transactions row above.
            c.execute(
                "INSERT OR IGNORE INTO tx_replay_guard (tx_id) VALUES (?)",
                (tx.tx_id,))
            claim_name = Transaction.identity_name_from_memo(
                getattr(tx, "memo", ""))
            if (tx.tx_type == Transaction.TYPE_REGISTER and claim_name
                    and tx.sender != "COINBASE" and tx.pub_hex):
                c.execute(
                    """INSERT OR IGNORE INTO name_claims
                       (user_id, wallet_addr, pub_hex, registered_height, tx_id)
                       VALUES (?,?,?,?,?)""",
                    (claim_name, tx.sender, tx.pub_hex,
                     int(block.index), tx.tx_id))
        c.commit()
        self._maybe_checkpoint()

    def prune_block_body(self, idx: int, header: dict, tx_ids=None) -> bool:
        """Compact a canonical block body while preserving authenticated headers.

        Rolling-window pruning must compact the authoritative block store before
        deleting any relational transaction projection.  The operation is
        deliberately fail-closed: if the canonical backend cannot be updated,
        return False so the caller retains the transaction rows and retries on
        a later pruning pass.
        """
        try:
            idx = int(idx)
        except (TypeError, ValueError):
            return False
        if idx < 0 or not isinstance(header, dict):
            return False

        slim = dict(header)
        slim.setdefault("index", idx)
        slim.setdefault("idx", idx)
        slim["transactions"] = []
        slim["pruned"] = True
        tx_ids = [str(txid) for txid in (tx_ids or ()) if txid]

        # PGX: RocksDB is canonical. Keep the existing hash index and rewrite
        # the height payload plus header atomically in one RocksDB batch.
        if self._pgx_enabled:
            try:
                current = self._rocks.get_block(idx)
                if current is None:
                    return False
                # Direct callers may omit tx_ids. Derive them from the canonical
                # pre-prune body so compaction remains self-contained and does
                # not leave stale tx-location indexes behind.
                if not tx_ids:
                    tx_ids = [
                        str(tx.get("tx_id"))
                        for tx in (current.get("transactions") or [])
                        if isinstance(tx, dict) and tx.get("tx_id")
                    ]
                current_hash = str(current.get("block_hash", ""))
                expected_hash = str(slim.get("block_hash", ""))
                if expected_hash and current_hash and current_hash != expected_hash:
                    log.error(
                        "prune_block_body(%d): canonical hash mismatch (%s != %s)",
                        idx, current_hash, expected_hash)
                    return False
                batch = self._rocks.new_batch()
                # The tx_id -> (height,index) location index is canonical too.
                # It must be deleted in the SAME RocksDB batch as body compaction;
                # otherwise pruned transactions remain discoverable forever and
                # tx_exists() can falsely reject future transactions.
                for txid in tx_ids:
                    self._rocks.delete_tx_loc(batch, txid)
                self._rocks.put_block(
                    batch, idx, slim, slim,
                    expected_hash or current_hash)
                self._rocks.commit(batch, sync=True)
                return True
            except Exception as exc:
                log.error("prune_block_body(%d): PGX canonical compaction failed: %s",
                          idx, exc)
                return False

        # Legacy LevelDB/RocksDB: BlockDatabase is canonical for block bodies.
        if self._block_db.enabled:
            try:
                current = self._block_db.get_block_by_height(idx)
                if current is None:
                    return False
                current_hash = str(current.get("block_hash", ""))
                expected_hash = str(slim.get("block_hash", ""))
                if expected_hash and current_hash and current_hash != expected_hash:
                    log.error(
                        "prune_block_body(%d): canonical KV hash mismatch (%s != %s)",
                        idx, current_hash, expected_hash)
                    return False
                return bool(self._block_db.prune_block(idx, slim))
            except Exception as exc:
                log.error("prune_block_body(%d): KV canonical compaction failed: %s",
                          idx, exc)
                return False

        # SQLite stores the full body itself.  The caller will clear the
        # transaction projection only after this point; preserving the slim
        # body in SQLite is therefore the canonical compaction step.
        try:
            c = self._conn()
            data_json = json.dumps(slim, separators=(",", ":"))
            result = c.execute(
                "UPDATE blocks SET data_json=? WHERE idx=?",
                (data_json, idx),
            )
            if result.rowcount != 1:
                c.rollback()
                return False
            c.commit()
            return True
        except Exception as exc:
            try:
                self._conn().rollback()
            except Exception:
                pass
            log.error("prune_block_body(%d): SQLite canonical compaction failed: %s",
                      idx, exc)
            return False

    def delete_block(self, idx: int, rollback_tx_ids: Optional[List[str]] = None) -> bool:
        """Delete one block and all canonical indexes derived from it.

        ``rollback_tx_ids`` is supplied ONLY when the block is being orphaned
        by a consensus rollback/reorg. In that case its tx ids are removed from
        the replay guard as well, because replay protection tracks the current
        canonical chain. Ordinary block deletion keeps the permanent replay
        guard intact.

        In pgx mode the RocksDB tx-location index is part of the canonical
        transaction index and must be deleted with the block; otherwise
        ``tx_exists()`` can keep reporting a rolled-back transaction forever.
        The RocksDB canonical tip metadata is also rewound when the deleted
        block is the current tip.
        """
        rollback_ids = [str(x) for x in (rollback_tx_ids or ()) if x]
        if self._pgx_enabled:
            blk = self._rocks.get_block(idx)
            if not blk:
                return False
            bhash = blk.get("block_hash", "")
            tx_ids = [
                str(t.get("tx_id", "")) for t in (blk.get("transactions") or [])
                if isinstance(t, dict) and t.get("tx_id")
            ]
            # Prefer the caller's exact tx list for replay-guard removal (the
            # caller has the consensus Block object); use stored tx ids for the
            # Rocks tx-location index so stale locations are never retained.
            replay_ids = rollback_ids
            with self._commit_lock:
                # Snapshot the tip while holding the same lock that serializes
                # block writes/deletes.  Taking this snapshot before the lock
                # would race a concurrent commit and could produce a stale Redis
                # tip after a legitimate rollback.
                current_tip = self._rocks.tip_height()
                prev = self._rocks.get_block(idx - 1) if idx > 0 else None
                batch = self._rocks.new_batch()
                self._rocks.delete_block(batch, idx, bhash)
                for tx_id in tx_ids:
                    self._rocks.delete_tx_loc(batch, tx_id)
                # Keep the canonical tip metadata consistent with the actual
                # highest stored block. Only rewind when the deleted block is
                # the current RocksDB tip; never disturb a different tip.
                if current_tip == idx:
                    if idx > 0:
                        prev = self._rocks.get_block(idx - 1)
                        if prev is not None:
                            self._rocks.put_meta(
                                batch, _META_CHAIN_TIP, _u64(idx - 1))
                            self._rocks.put_meta(
                                batch, _META_TIP_HASH,
                                str(prev.get("block_hash", "")).encode("ascii"))
                        else:
                            self._rocks.delete_meta(batch, _META_CHAIN_TIP)
                            self._rocks.delete_meta(batch, _META_TIP_HASH)
                    else:
                        # No genesis remains; let Blockchain.height() perform
                        # its existing deterministic genesis self-heal.
                        self._rocks.delete_meta(batch, _META_CHAIN_TIP)
                        self._rocks.delete_meta(batch, _META_TIP_HASH)
                self._rocks.commit(batch, sync=True)

            # PG metadata is canonical transaction projection in pgx mode.
            # Keep transaction rows and replay guards in one PG transaction.
            if replay_ids:
                try:
                    async def _cleanup_pgx():
                        async with self._pg._pool.acquire() as c:
                            async with c.transaction():
                                await c.execute(
                                    "DELETE FROM transactions WHERE block_idx=$1",
                                    idx)
                                await c.executemany(
                                    "DELETE FROM tx_replay_guard WHERE tx_id=$1",
                                    [(tx_id,) for tx_id in replay_ids])
                                if replay_ids:
                                    await c.execute(
                                        "DELETE FROM vvm_receipts WHERE block_idx=$1",
                                        idx)
                                await c.execute(
                                    "DELETE FROM node_meta WHERE key=$1",
                                    f"block_apply:{idx}")
                                await c.execute(
                                    "DELETE FROM node_meta WHERE key=$1",
                                    f"block_role_undo:{idx}")
                    self._pg.run(_cleanup_pgx())
                except Exception as exc:
                    # Do not silently claim rollback succeeded when the PG
                    # canonical projection could not be cleaned. The RocksDB
                    # block has already been removed; this is a hard consistency
                    # failure that must be surfaced to the caller.
                    log.error(
                        "delete_block(%d): PG canonical cleanup failed: %s",
                        idx, exc)
                    return False
            else:
                try:
                    self._pg_exec("DELETE FROM transactions WHERE block_idx=$1", idx)
                    self._pg_exec("DELETE FROM node_meta WHERE key=$1",
                                  f"block_apply:{idx}")
                    self._pg_exec("DELETE FROM node_meta WHERE key=$1",
                                  f"block_role_undo:{idx}")
                except Exception as exc:
                    log.error(
                        "delete_block(%d): PG transaction cleanup failed: %s",
                        idx, exc)
                    return False

            # The auxiliary SQLite DB is deliberately *not* the PGX VVM receipt
            # store.  vvm_receipts is canonical in PostgreSQL and is not mirrored
            # here, so never issue a receipt delete against the aux connection.
            # Aux cleanup is also non-authoritative: a shadow-cache failure must
            # never turn an otherwise successful canonical rollback into a false
            # failure after RocksDB has already been rewound.  External raw-SQL
            # readers may observe stale shadow rows until the next mirror/rebuild.
            c = None
            try:
                with self._aux_lock:
                    c = self._conn()
                    c.execute("DELETE FROM transactions WHERE block_idx=?", (idx,))
                    c.execute("DELETE FROM blocks WHERE idx=?", (idx,))
                    c.execute("DELETE FROM node_meta WHERE key=?",
                              (f"block_apply:{idx}",))
                    c.execute("DELETE FROM node_meta WHERE key=?",
                              (f"block_role_undo:{idx}",))
                    c.commit()
            except Exception as exc:
                if c is not None:
                    try:
                        c.rollback()
                    except Exception:
                        pass
                log.warning(
                    "delete_block(%d): auxiliary SQLite shadow cleanup skipped: %s",
                    idx, exc)
                metrics.inc("aux_mirror_write_failures")

            # The canonical stores now agree.  Refresh the non-authoritative Redis
            # tip without publishing a fake "new block" notification.
            try:
                if current_tip == idx:
                    if idx > 0 and prev is not None:
                        self._cache.set_tip(
                            idx - 1, str(prev.get("block_hash", "")), publish=False)
                    else:
                        self._cache.clear_tip()
            except Exception as exc:
                log.debug("delete_block(%d): Redis tip refresh failed: %s", idx, exc)

            self.rebuild_name_claims_from_transactions(idx)
            return True

        if self._block_db.enabled:
            if not self._block_db.delete_block(idx):
                return False
        c = self._conn()
        try:
            c.execute("DELETE FROM transactions WHERE block_idx=?", (idx,))
            c.execute("DELETE FROM vvm_receipts WHERE block_idx=?", (idx,)) if rollback_ids else None
            c.execute("DELETE FROM blocks WHERE idx=?", (idx,))
            c.execute("DELETE FROM node_meta WHERE key=?", (f"block_apply:{idx}",))
            c.execute("DELETE FROM node_meta WHERE key=?", (f"block_role_undo:{idx}",))
            if rollback_ids:
                c.executemany(
                    "DELETE FROM tx_replay_guard WHERE tx_id=?",
                    [(tx_id,) for tx_id in rollback_ids])
            c.commit()
        except Exception as exc:
            c.rollback()
            log.error("delete_block(%d) failed: %s", idx, exc)
            return False
        self.rebuild_name_claims_from_transactions(idx)
        return True

    @staticmethod
    def _normalize_persisted_block_dict(data: dict) -> dict:
        """Normalize legacy compact block JSON before Block.from_dict().

        Early rolling-pruner records used SQL-oriented ``idx`` and omitted
        ``miner_address``.  Keep this compatibility at the SQLite storage
        boundary; network and consensus block validation remain unchanged.
        New compact records contain both fields directly.
        """
        if not isinstance(data, dict):
            return data
        if "index" not in data and "idx" in data:
            data["index"] = data["idx"]
        if "miner_address" not in data:
            data["miner_address"] = ""
        return data

    def get_block(self, idx: int) -> Optional['Block']:
        if self._pgx_enabled:
            active = self._pgx_active_state()
            canonical_tip = (int(active["pending_tip"][0])
                              if active is not None and active.get("pending_tip")
                              else int(self._pgx_canonical_tip))
            if int(idx) > canonical_tip:
                return None
            d = self._rocks.get_block(idx)
            return Block.from_dict(d) if d else None
        if self._block_db.enabled:
            # SQLite is the transactionally-committed canonical marker.  The
            # external KV backend commits independently, so a crash during
            # save_block() may leave an orphan KV block after the SQLite
            # transaction rolled back. Never expose such a KV-only block.
            row = self._conn().execute(
                "SELECT block_hash FROM blocks WHERE idx=?", (int(idx),)
            ).fetchone()
            if not row:
                return None
            d = self._block_db.get_block_by_height(idx)
            if d is not None:
                if str(d.get("block_hash", "")) != str(row["block_hash"] or ""):
                    return None
                return Block.from_dict(d)
        row = self._conn().execute(
            "SELECT data_json FROM blocks WHERE idx=?", (idx,)).fetchone()
        if not row or not row["data_json"]:
            return None
        data = self._normalize_persisted_block_dict(json.loads(row["data_json"]))
        return Block.from_dict(data)

    def get_block_hash(self, idx: int) -> Optional[str]:
        """Return the canonical block hash without deserializing a Block object."""
        idx = int(idx)
        if idx < 0:
            return None
        if self._pgx_enabled:
            active = self._pgx_active_state()
            canonical_tip = (int(active["pending_tip"][0])
                              if active is not None and active.get("pending_tip")
                              else int(self._pgx_canonical_tip))
            if idx > canonical_tip:
                return None
            d = self._rocks.get_block(idx)
            if not d:
                return None
            return str(d.get("block_hash", "")) or None
        if self._block_db.enabled:
            row = self._conn().execute(
                "SELECT block_hash FROM blocks WHERE idx=?", (idx,)).fetchone()
            if not row:
                return None
            d = self._block_db.get_block_by_height(idx)
            if d is None:
                return None
            kv_hash = str(d.get("block_hash", ""))
            sql_hash = str(row["block_hash"] or "")
            if kv_hash != sql_hash:
                return None
            return kv_hash or None
        row = self._conn().execute(
            "SELECT block_hash FROM blocks WHERE idx=?", (idx,)).fetchone()
        return str(row["block_hash"]) if row and row["block_hash"] else None

    def get_block_consensus_window(self, start_idx: int, end_idx: int) -> List[tuple]:
        """Return ``(timestamp, difficulty)`` rows for an inclusive height range.

        This helper is intentionally header-only: the difficulty algorithm only
        needs these two consensus fields, so loading/deserializing complete block
        bodies during every historical difficulty calculation is unnecessary.
        Missing heights are omitted in the same way as the old per-height
        ``get_block()`` loop.
        """
        start_idx = int(start_idx)
        end_idx = int(end_idx)
        if end_idx < start_idx:
            return []
        if self._pgx_enabled:
            out = []
            for idx in range(start_idx, end_idx + 1):
                hdr = self._rocks.get_header(idx)
                if hdr:
                    out.append((int(hdr.get("timestamp", 0)),
                                float(hdr.get("difficulty", 0.0))))
            return out
        # The SQLite ``blocks`` row retains the canonical header fields even
        # after rolling-window pruning replaces ``data_json`` with a slim body.
        rows = self._conn().execute(
            "SELECT timestamp, difficulty FROM blocks "
            "WHERE idx >= ? AND idx <= ? ORDER BY idx",
            (start_idx, end_idx)).fetchall()
        return [(int(r["timestamp"]), float(r["difficulty"])) for r in rows]

    def get_block_timestamps(self, start_idx: int, end_idx: int) -> List[int]:
        """Return canonical block timestamps for an inclusive height range.

        This read-only helper avoids deserializing full block bodies for the
        MTP consensus check. Missing heights are omitted exactly as the old
        per-height get_block() loop did.
        """
        start_idx = int(start_idx)
        end_idx = int(end_idx)
        if end_idx < start_idx:
            return []
        if self._pgx_enabled:
            rows = self._pg_fetch(
                "SELECT idx, timestamp FROM blocks "
                "WHERE idx >= $1 AND idx <= $2 ORDER BY idx",
                start_idx, end_idx)
            return [int(r["timestamp"]) for r in rows]
        rows = self._conn().execute(
            "SELECT timestamp FROM blocks WHERE idx >= ? AND idx <= ? ORDER BY idx",
            (start_idx, end_idx)).fetchall()
        return [int(r["timestamp"]) for r in rows]

    def get_block_by_hash(self, h: str) -> Optional['Block']:
        if self._pgx_enabled:
            d = self._rocks.get_block_by_hash(h)
            if not d:
                return None
            active = self._pgx_active_state()
            canonical_tip = (int(active["pending_tip"][0])
                              if active is not None and active.get("pending_tip")
                              else int(self._pgx_canonical_tip))
            if int(d.get("index", d.get("idx", -1))) > canonical_tip:
                return None
            return Block.from_dict(d)
        if self._block_db.enabled:
            row = self._conn().execute(
                "SELECT idx FROM blocks WHERE block_hash=?", (h,)
            ).fetchone()
            if not row:
                return None
            d = self._block_db.get_block_by_hash(h)
            if d is not None:
                if int(d.get("index", d.get("idx", -1))) != int(row["idx"]):
                    return None
                return Block.from_dict(d)
        row = self._conn().execute(
            "SELECT data_json FROM blocks WHERE block_hash=?", (h,)).fetchone()
        if not row or not row["data_json"]:
            return None
        data = self._normalize_persisted_block_dict(json.loads(row["data_json"]))
        return Block.from_dict(data)

    def get_block_header(self, idx: int) -> Optional[dict]:
        """Return the locally stored canonical header for ``idx``.

        Full blocks are preferred.  When rolling-window pruning removed the
        body, the slim ``block_headers`` table (SQLite) or RocksDB header index
        remains available.  A header is considered a trust anchor only when it
        is at or below the node's current canonical tip; callers must enforce
        that height condition before using it for snapshot authentication.
        """
        try:
            idx = int(idx)
        except (TypeError, ValueError):
            return None
        if idx < 0 or idx > self.chain_height():
            return None
        if self._pgx_enabled:
            h = self._rocks.get_header(idx)
            return dict(h) if h else None
        try:
            row = self._conn().execute(
                "SELECT idx, block_hash, prev_hash, merkle_root, state_root, "
                "timestamp, difficulty, nonce FROM block_headers WHERE idx=?",
                (idx,)).fetchone()
            if row:
                return dict(row)
        except Exception:
            pass
        try:
            blk = self.get_block(idx)
            if blk is None:
                return None
            return {
                "idx": blk.index,
                "block_hash": blk.block_hash,
                "prev_hash": blk.prev_hash,
                "merkle_root": blk.merkle_root,
                "state_root": blk.state_root,
                "timestamp": blk.timestamp,
                "difficulty": blk.difficulty,
                "nonce": blk.nonce,
            }
        except Exception:
            return None

    def chain_height(self) -> int:
        if self._pgx_enabled:
            active = self._pgx_active_state()
            if active is not None and active.get("pending_tip") is not None:
                return int(active["pending_tip"][0])
            return int(self._pgx_canonical_tip)
        if self._block_db.enabled:
            # The SQLite transaction is the canonical durability barrier.
            # Do not use the independently committed KV tip as chain height;
            # it can temporarily be ahead after a crash between KV and SQLite
            # commits, in which case the extra KV block is an orphan.
            row = self._conn().execute(
                "SELECT MAX(idx) as h FROM blocks").fetchone()
            return int(row["h"]) if row and row["h"] is not None else -1
        row = self._conn().execute("SELECT MAX(idx) as h FROM blocks").fetchone()
        return row["h"] if row and row["h"] is not None else -1

    def get_last_n_blocks(self, n: int) -> List['Block']:
        if self._pgx_enabled:
            n = max(0, int(n))
            tip = self.chain_height()
            if n == 0 or tip < 0:
                return []
            out = []
            for h in range(tip, max(-1, tip - n), -1):
                d = self._rocks.get_block(h)
                if d is not None:
                    out.append(Block.from_dict(d))
            out.reverse()
            return out
        if self._block_db.enabled:
            ds = self._block_db.get_last_n_blocks(n)
            if ds:
                return [Block.from_dict(d) for d in ds]
        rows = self._conn().execute(
            "SELECT data_json FROM blocks ORDER BY idx DESC LIMIT ?", (n,)).fetchall()
        out = []
        for r in reversed(rows):
            if r["data_json"]:
                out.append(Block.from_dict(json.loads(r["data_json"])))
        return out

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  TRANSACTIONS                                                          ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def get_tx(self, tx_id: str) -> Optional['Transaction']:
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT data_json FROM transactions WHERE tx_id=$1", tx_id)
            if not row:
                return None
            try:
                return Transaction.from_dict(json.loads(row["data_json"]))
            except Exception:
                return None
        row = self._conn().execute(
            "SELECT data_json FROM transactions WHERE tx_id=?", (tx_id,)).fetchone()
        return Transaction.from_dict(json.loads(row["data_json"])) if row else None

    def existing_tx_ids(self, tx_ids: Iterable[str]) -> set[str]:
        """Return tx_ids present in either the canonical body table or replay guard."""
        ids = list(dict.fromkeys(str(x) for x in tx_ids if x))
        if not ids:
            return set()
        found: set[str] = set()
        chunk_size = 500
        if self._pgx_enabled:
            for i in range(0, len(ids), chunk_size):
                chunk = ids[i:i + chunk_size]
                rows = self._pg_fetch(
                    "SELECT tx_id FROM transactions WHERE tx_id = ANY($1::text[])", chunk)
                found.update(str(r["tx_id"]) for r in rows)
                rows = self._pg_fetch(
                    "SELECT tx_id FROM tx_replay_guard WHERE tx_id = ANY($1::text[])", chunk)
                found.update(str(r["tx_id"]) for r in rows)
            return found

        c = self._conn()
        # The replay guard is consensus-critical and may not exist on an older
        # database that has not yet applied its migration. Creating it here is
        # idempotent and preserves the existing replay_guard_exists semantics.
        c.execute(
            "CREATE TABLE IF NOT EXISTS tx_replay_guard (tx_id TEXT PRIMARY KEY)")
        for i in range(0, len(ids), chunk_size):
            chunk = ids[i:i + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            rows = c.execute(
                f"SELECT tx_id FROM transactions WHERE tx_id IN ({placeholders})",
                tuple(chunk)).fetchall()
            found.update(str(r["tx_id"]) for r in rows)
            rows = c.execute(
                f"SELECT tx_id FROM tx_replay_guard WHERE tx_id IN ({placeholders})",
                tuple(chunk)).fetchall()
            found.update(str(r["tx_id"]) for r in rows)
        return found

    def tx_exists(self, tx_id: str) -> bool:
        """Return whether a transaction body still exists in canonical storage.

        In PGX mode the RocksDB tx-location index is only a secondary index.
        A stale location must not make a transaction whose block body has already
        been pruned look like a live transaction.
        """
        tx_id = str(tx_id or "")
        if not tx_id:
            return False
        if self._pgx_enabled:
            try:
                loc = self._rocks.get_tx_loc(tx_id)
                if loc:
                    height, _tx_index = loc
                    block = self._rocks.get_block(int(height))
                    if block is not None:
                        for tx in (block.get("transactions") or []):
                            if isinstance(tx, dict) and str(tx.get("tx_id", "")) == tx_id:
                                return True
            except Exception:
                pass
            row = self._pg_fetchrow(
                "SELECT 1 FROM transactions WHERE tx_id=$1", tx_id)
            return row is not None
        row = self._conn().execute(
            "SELECT 1 FROM transactions WHERE tx_id=?", (tx_id,)).fetchone()
        return row is not None

    def record_applied_tx_id(self, tx_id: str) -> None:
        """
        AUDIT-FIX-14b: append tx_id to a durable, non-pruned replay-guard
        index — independent of the `transactions` table, which
        prune_old_data() and RollingWindowPruner both delete rows from
        (the latter at a default 600-block window). Once a transaction's
        `transactions` row is pruned, tx_exists() alone can no longer tell
        whether that exact tx_id was ever applied, which combined with
        expiry=0 transactions (see AUDIT-FIX-14a) made indefinite replay
        possible. This table is deliberately tiny (tx_id only) and is never
        touched by either pruner. Idempotent and best-effort: a failure here
        is logged but does not abort block persistence, since tx_exists()
        (checked first, wherever this is consulted) still provides the
        original, shorter-window protection even if this fails.
        """
        try:
            if self._pgx_enabled:
                self._pg_exec(
                    "INSERT INTO tx_replay_guard (tx_id) VALUES ($1) "
                    "ON CONFLICT (tx_id) DO NOTHING", tx_id)
            else:
                c = self._conn()
                c.execute(
                    "CREATE TABLE IF NOT EXISTS tx_replay_guard "
                    "(tx_id TEXT PRIMARY KEY)")
                c.execute(
                    "INSERT OR IGNORE INTO tx_replay_guard (tx_id) VALUES (?)",
                    (tx_id,))
                c.commit()
        except Exception as e:
            log.error(
                f"record_applied_tx_id failed for {tx_id[:16]}: {e} — "
                f"replay protection for this tx now depends solely on "
                f"tx_exists()'s prunable window")

    def decrement_cumulative_issued_sat(self, amount_sat: int) -> None:
        """Reverse one block's NEW coinbase issuance during rollback.

        Fees are not part of this counter because fees are redistribution, not
        new supply. The counter is never allowed to become negative; if an old
        database predates the counter or is already inconsistent, clamp at zero
        rather than creating a second, larger inconsistency.
        """
        amount = int(amount_sat)
        if amount <= 0:
            return
        current = self.get_cumulative_issued_sat()
        new_value = max(0, current - amount)
        if current < amount:
            log.warning(
                "cumulative_issued_sat underflow while rolling back issuance: "
                "current=%d amount=%d; clamping to zero", current, amount)
        self.set_meta("cumulative_issued_sat", str(new_value))

    def replay_guard_exists(self, tx_id: str) -> bool:
        """Check durable replay protection for the canonical/pruned history.

        Deliberate rollback/reorg removes entries belonging to blocks that are
        no longer canonical, so those transactions can be revalidated.
        """
        try:
            if self._pgx_enabled:
                row = self._pg_fetchrow(
                    "SELECT 1 FROM tx_replay_guard WHERE tx_id=$1", tx_id)
                return row is not None
            c = self._conn()
            c.execute(
                "CREATE TABLE IF NOT EXISTS tx_replay_guard "
                "(tx_id TEXT PRIMARY KEY)")
            row = c.execute(
                "SELECT 1 FROM tx_replay_guard WHERE tx_id=?",
                (tx_id,)).fetchone()
            return row is not None
        except Exception as e:
            log.error(f"replay_guard_exists failed for {tx_id[:16]}: {e}")
            return False

    def get_broadcast_orders(self) -> List[dict]:
        if self._pgx_enabled:
            rows = self._pg_fetch(
                """SELECT data_json FROM transactions
                    WHERE receiver=$1 AND memo LIKE 'ORDER:%'
                 ORDER BY timestamp DESC""",
                VSD_GLOBAL_MARKET)
            return [json.loads(r["data_json"]) for r in rows]
        rows = self._conn().execute("""
            SELECT data_json FROM transactions
             WHERE receiver=? ORDER BY timestamp DESC
        """, (VSD_GLOBAL_MARKET,)).fetchall()
        return [json.loads(r["data_json"]) for r in rows
                if json.loads(r["data_json"]).get("memo","").startswith("ORDER:")]

    def get_address_txs(self, address: str) -> List[dict]:
        """Return all transactions touching ``address``, NEWEST first.

        v7.5.x: also pulls archived rows from ``permanent_history`` (the
        rolling-window pruner archives transactions whose amount is at
        or above ROLLING_PRUNE_ARCHIVE_THRESHOLD, plus all VVM and system
        txs) so that the user's view of their own history is no longer
        silently truncated to the last ROLLING_PRUNE_WINDOW blocks.
        Smaller transfers below the archive threshold are still pruned
        from the live ``transactions`` table — the caller (CLI Balance
        History / All Transactions) is responsible for showing a
        "older small transactions may be summarised" footnote when
        ``rolling_pruned_until`` indicates the chain has been pruned.

        Live rows take precedence over archive rows of the same tx_id
        (a tx briefly exists in both during a prune pass — we de-dupe
        by tx_id so the user never sees duplicates).
        """
        live: List[dict] = []
        live_tx_ids: set = set()
        if self._pgx_enabled:
            rows = self._pg_fetch(
                """SELECT block_idx, data_json FROM transactions
                    WHERE sender=$1 OR receiver=$1
                 ORDER BY timestamp DESC""",
                address)
            for r in rows:
                d = json.loads(r["data_json"])
                if "block_idx" not in d:
                    d["block_idx"] = r["block_idx"]
                live.append(d)
                if d.get("tx_id"):
                    live_tx_ids.add(d["tx_id"])
        else:
            rows = self._conn().execute("""
                SELECT block_idx, data_json FROM transactions
                 WHERE sender=? OR receiver=? ORDER BY timestamp DESC
            """, (address, address)).fetchall()
            for r in rows:
                d = json.loads(r["data_json"])
                if "block_idx" not in d:
                    d["block_idx"] = r[0]  # block_idx is first column
                live.append(d)
                if d.get("tx_id"):
                    live_tx_ids.add(d["tx_id"])

        # ── Pull archived rows from permanent_history ─────────────────────
        # SQLite-only: PostgreSQL backend stores archived rows differently
        # via the rolling-pruner; if the table doesn't exist yet (pre-prune)
        # the SELECT just yields nothing.
        archived: List[dict] = []
        try:
            arc_rows = self._conn().execute(
                """SELECT tx_hash, block_idx, sender, receiver, amount,
                          tx_type, timestamp, metadata_json
                     FROM permanent_history
                    WHERE sender=? OR receiver=?
                 ORDER BY timestamp DESC""",
                (address, address)
            ).fetchall()
        except Exception:
            arc_rows = []
        for r in arc_rows:
            tx_hash = r["tx_hash"] if isinstance(r, dict) or hasattr(r, "keys") else r[0]
            # sqlite3.Row supports both index and key access
            try:
                tx_hash = r["tx_hash"]
            except (KeyError, IndexError, TypeError):
                pass
            if tx_hash in live_tx_ids:
                continue
            try:
                meta = json.loads(r["metadata_json"] or "{}")
            except Exception:
                meta = {}
            d = {
                "tx_id":       tx_hash,
                "sender":      r["sender"],
                "receiver":    r["receiver"],
                "amount":      float(r["amount"] or 0.0),
                "tx_type":     r["tx_type"] or "transfer",
                "timestamp":   int(r["timestamp"] or 0),
                "block_idx":   int(r["block_idx"] or 0),
                "fee":         float(meta.get("fee", 0.0) or 0.0),
                "nonce":       int(meta.get("nonce", 0) or 0),
                "memo":        meta.get("memo", "") or "",
                "gas_limit":   int(meta.get("gas_limit", 0) or 0),
                "gas_price":   float(meta.get("gas_price", 0.0) or 0.0),
                "data":        meta.get("data", "") or "",
                "contract_name": meta.get("contract_name", "") or "",
                "_archived":   True,   # tag so callers can show a hint
            }
            archived.append(d)

        # Combine and re-sort by timestamp descending (newest first).
        result = live + archived
        result.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return result

    def get_uid_by_wallet(self, wallet_addr: str) -> Optional[str]:
        """Reverse-lookup: wallet address → user_id (best-effort, returns None if unknown)."""
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT user_id FROM identities WHERE wallet_addr=$1 LIMIT 1",
                wallet_addr)
            return row["user_id"] if row else None
        row = self._conn().execute(
            "SELECT user_id FROM identities WHERE wallet_addr=? LIMIT 1",
            (wallet_addr,)).fetchone()
        return row[0] if row else None

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  ROLES / VALIDATORS                                                    ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def get_role(self, address: str) -> Optional[dict]:
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                """SELECT address, role, stake_sat AS stake, score,
                          (CASE WHEN slashed THEN 1 ELSE 0 END) AS slashed,
                          registered_at
                     FROM validators WHERE address=$1""", address)
            if not row:
                return None
            d = dict(row)
            # Callers expect 'stake' as a VSD float (legacy schema).
            d["stake"] = from_satoshi(int(d["stake"]))
            return d
        row = self._conn().execute(
            "SELECT * FROM roles WHERE address=?", (address,)).fetchone()
        return dict(row) if row else None

    def set_role(self, address: str, role: str, stake: float, score: float = 1.0):
        # A slash is a protocol-level disqualification marker. An ordinary
        # REGISTER("none") may clear the active role/stake, but it must never
        # clear an existing slash marker. Without this, a slashed validator
        # could self-unslash by unregistering and then registering again.
        preserve_slashed = False
        if role == "none":
            existing = self.get_role(address)
            preserve_slashed = bool(existing and existing.get("slashed"))

        stake_sat = to_satoshi(stake)
        now = int(time.time())
        if self._pgx_enabled:
            self._pg_exec(
                """INSERT INTO validators
                       (address, role, stake_sat, score, slashed, registered_at)
                   VALUES ($1,$2,$3,$4,$5,$6)
                   ON CONFLICT (address) DO UPDATE SET
                       role=EXCLUDED.role, stake_sat=EXCLUDED.stake_sat,
                       score=EXCLUDED.score, slashed=EXCLUDED.slashed,
                       registered_at=EXCLUDED.registered_at""",
                address, role, stake_sat, float(score), bool(preserve_slashed), now)
            return
        self._conn().execute(
            """INSERT OR REPLACE INTO roles
                   (address,role,stake,score,slashed,registered_at)
               VALUES (?,?,?,?,?,?)""",
            (address, role, stake, score, int(preserve_slashed), now))
        self._conn().commit()

    def get_all_by_role(self, role: str) -> List[dict]:
        if self._pgx_enabled:
            rows = self._pg_fetch(
                """SELECT address, role, stake_sat AS stake, score,
                          (CASE WHEN slashed THEN 1 ELSE 0 END) AS slashed,
                          registered_at
                     FROM validators
                    WHERE role=$1 AND slashed=FALSE""", role)
            out = []
            for r in rows:
                d = dict(r)
                d["stake"] = from_satoshi(int(d["stake"]))
                out.append(d)
            return out
        rows = self._conn().execute(
            "SELECT * FROM roles WHERE role=? AND slashed=0", (role,)).fetchall()
        return [dict(r) for r in rows]

    def slash(self, address: str):
        r = self.get_role(address)
        if not r: return
        new_stake = max(0.0, r["stake"] * (1 - Config.SLASH_RATE))
        if self._pgx_enabled:
            self._pg_exec(
                "UPDATE validators SET slashed=TRUE, stake_sat=$2 WHERE address=$1",
                address, to_satoshi(new_stake))
            return
        self._conn().execute(
            "UPDATE roles SET slashed=1, stake=? WHERE address=?",
            (new_stake, address))
        self._conn().commit()

    def update_stake(self, address: str, stake: float):
        if self._pgx_enabled:
            self._pg_exec(
                "UPDATE validators SET stake_sat=$2 WHERE address=$1",
                address, to_satoshi(stake))
            return
        self._conn().execute(
            "UPDATE roles SET stake=? WHERE address=?", (stake, address))
        self._conn().commit()

    def record_validator_vote(self, block_hash: str, validator_addr: str,
                              sig_hex: str, pub_hex: str,
                              block_idx: Optional[int] = None):
        """Persist one validator vote with its immutable target height.

        The height is part of the vote record rather than being inferred from
        the current canonical block table at read time.  This is essential for
        equivocation detection across reorgs: an orphaned block's vote remains
        evidence of a prior signature at that height.
        """
        if self._pgx_enabled:
            if block_idx is None:
                d = self._rocks.get_block_by_hash(block_hash) if hasattr(self._rocks, "get_block_by_hash") else None
                block_idx = int(d.get("idx", d.get("index", -1))) if d else -1
            self._pg_exec(
                """INSERT INTO validator_votes
                       (block_hash, validator_addr, block_idx, sig_hex, pub_hex)
                   VALUES ($1,$2,$3,$4,$5)
                   ON CONFLICT DO NOTHING""",
                block_hash, validator_addr, int(block_idx), sig_hex, pub_hex)
            return
        if block_idx is None:
            row = self._conn().execute(
                "SELECT idx FROM blocks WHERE block_hash=?", (block_hash,)
            ).fetchone()
            block_idx = int(row[0]) if row else -1
        self._conn().execute(
            """INSERT OR IGNORE INTO validator_votes
                   (block_hash, validator_addr, block_idx, sig_hex, pub_hex)
               VALUES (?,?,?,?,?)""",
            (block_hash, validator_addr, int(block_idx), sig_hex, pub_hex))
        self._conn().commit()

    def get_validator_votes_at_height(self, height: int) -> List[dict]:
        if self._pgx_enabled:
            rows = self._pg_fetch(
                "SELECT * FROM validator_votes WHERE block_idx=$1",
                int(height))
            return [dict(r) for r in rows]
        rows = self._conn().execute(
            "SELECT * FROM validator_votes WHERE block_idx=?",
            (int(height),)).fetchall()
        return [dict(r) for r in rows]

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  MEMPOOL   (Redis sorted set in pgx mode; PG unlogged as cold store)   ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def mempool_get_by_id(self, tx_id: str) -> Optional['Transaction']:
        if self._pgx_enabled:
            if self._cache.r is not None:
                raw = self._cache._safe(self._cache.r.get, f"vsd:mempool:tx:{tx_id}")
                if raw:
                    try:
                        return Transaction.from_dict(json.loads(raw))
                    except Exception:
                        pass
            row = self._pg_fetchrow(
                "SELECT data_json FROM mempool WHERE tx_id=$1", tx_id)
            if not row:
                return None
            try:
                return Transaction.from_dict(json.loads(row["data_json"]))
            except Exception:
                return None
        row = self._conn().execute(
            "SELECT data_json FROM mempool WHERE tx_id=?", (tx_id,)).fetchone()
        return Transaction.from_dict(json.loads(row["data_json"])) if row else None

    def mempool_add(self, tx: 'Transaction'):
        payload = json.dumps(tx.to_dict())
        fee_sat = int(to_satoshi(tx.compute_fee()))
        if self._pgx_enabled:
            self._cache.mempool_add(tx.tx_id, fee_sat, payload.encode())
            try:
                self._pg_exec(
                    """INSERT INTO mempool
                           (tx_id, sender, fee_sat, timestamp, data_json)
                       VALUES ($1,$2,$3,$4,$5)
                       ON CONFLICT (tx_id) DO NOTHING""",
                    tx.tx_id, tx.sender or "", fee_sat, int(tx.timestamp), payload)
            except Exception:
                pass
            return
        self._conn().execute(
            """INSERT OR IGNORE INTO mempool (tx_id,fee,timestamp,data_json)
               VALUES (?,?,?,?)""",
            (tx.tx_id, tx.compute_fee(), tx.timestamp, payload))
        self._conn().commit()

    def mempool_remove(self, tx_id: str):
        if self._pgx_enabled:
            self._cache.mempool_remove([tx_id])
            try:
                self._pg_exec("DELETE FROM mempool WHERE tx_id=$1", tx_id)
            except Exception:
                pass
            return
        self._conn().execute("DELETE FROM mempool WHERE tx_id=?", (tx_id,))
        self._conn().commit()

    def mempool_get_top(self, n: int) -> List['Transaction']:
        if self._pgx_enabled:
            rows = self._pg_fetch(
                """SELECT data_json FROM mempool
                ORDER BY fee_sat DESC, timestamp ASC LIMIT $1""",
                int(n))
            out = []
            for r in rows:
                try: out.append(Transaction.from_dict(json.loads(r["data_json"])))
                except Exception: pass
            return out
        rows = self._conn().execute(
            "SELECT data_json FROM mempool ORDER BY fee DESC, timestamp ASC LIMIT ?",
            (n,)).fetchall()
        return [Transaction.from_dict(json.loads(r["data_json"])) for r in rows]

    def mempool_size(self) -> int:
        if self._pgx_enabled:
            row = self._pg_fetchrow("SELECT COUNT(*) AS c FROM mempool")
            return int(row["c"]) if row else 0
        row = self._conn().execute("SELECT COUNT(*) as c FROM mempool").fetchone()
        return row["c"]

    def mempool_all(self) -> List['Transaction']:
        if self._pgx_enabled:
            rows = self._pg_fetch(
                "SELECT data_json FROM mempool ORDER BY fee_sat DESC")
            out = []
            for r in rows:
                try: out.append(Transaction.from_dict(json.loads(r["data_json"])))
                except Exception: pass
            return out
        rows = self._conn().execute(
            "SELECT data_json FROM mempool ORDER BY fee DESC").fetchall()
        return [Transaction.from_dict(json.loads(r["data_json"])) for r in rows]

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  HT VOLUME                                                             ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def update_ht_volume(self, address: str, volume: float):
        volume_sat = to_satoshi(volume)
        if self._pgx_enabled:
            self._pg_exec(
                """INSERT INTO accounts (address, ht_volume_sat, updated_at)
                   VALUES ($1, $2, now())
                   ON CONFLICT (address) DO UPDATE SET
                       ht_volume_sat = accounts.ht_volume_sat + EXCLUDED.ht_volume_sat,
                       updated_at    = now()""",
                address, int(volume_sat))
            return
        row = self._conn().execute(
            "SELECT volume FROM ht_volume WHERE address=?", (address,)).fetchone()
        cur = int(row["volume"]) if row else 0
        self._conn().execute(
            """INSERT OR REPLACE INTO ht_volume (address,volume,updated)
               VALUES (?,?,?)""",
            (address, cur + volume_sat, int(time.time())))
        self._conn().commit()

    def get_ht_qualifiers(self) -> List[dict]:
        if self._pgx_enabled:
            rows = self._pg_fetch(
                """SELECT address, ht_volume_sat AS volume, updated_at
                     FROM accounts WHERE ht_volume_sat >= $1""",
                int(Config.HT_VOLUME_THRESHOLD))
            return [dict(r) for r in rows]
        rows = self._conn().execute(
            "SELECT * FROM ht_volume WHERE volume>=?",
            (Config.HT_VOLUME_THRESHOLD,)).fetchall()
        return [dict(r) for r in rows]

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  IDENTITIES                                                            ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def save_name_claim(self, user_id: str, wallet_addr: str,
                        pub_hex: str, registered_height: int,
                        tx_id: str) -> None:
        """Persist a confirmed, immutable name-ownership claim.

        Claims are inserted only from Storage.save_block(), so the claim index
        follows canonical block order.  Conflicts are intentionally ignored:
        the first claim in canonical transaction order owns the name forever
        unless a future transfer/expiry protocol is added explicitly.
        """
        if self._pgx_enabled:
            self._pg_exec(
                """INSERT INTO name_claims
                       (user_id, wallet_addr, pub_hex, registered_height, tx_id)
                   VALUES ($1,$2,$3,$4,$5)
                   ON CONFLICT (user_id) DO NOTHING""",
                user_id, wallet_addr, pub_hex,
                int(registered_height), tx_id)
            return
        self._conn().execute(
            """INSERT OR IGNORE INTO name_claims
                   (user_id, wallet_addr, pub_hex, registered_height, tx_id)
               VALUES (?,?,?,?,?)""",
            (user_id, wallet_addr, pub_hex,
             int(registered_height), tx_id))
        self._conn().commit()

    def resolve_name_claim(self, user_id: str) -> Optional[dict]:
        """Return only the canonical ownership record for a name."""
        if isinstance(user_id, str):
            user_id = user_id.strip().casefold()
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT * FROM name_claims WHERE user_id=$1", user_id)
            return dict(row) if row else None
        row = self._conn().execute(
            "SELECT * FROM name_claims WHERE user_id=?", (user_id,)).fetchone()
        return dict(row) if row else None

    def rebuild_name_claims_from_transactions(self, min_height: int) -> None:
        """Rebuild claims affected by a recent reorg from retained tx rows."""
        try:
            if self._pgx_enabled:
                self._pg_exec(
                    "DELETE FROM name_claims WHERE registered_height >= $1",
                    int(min_height))
                rows = self._pg_fetch(
                    """SELECT block_idx, data_json FROM transactions
                       WHERE block_idx >= $1
                       ORDER BY block_idx ASC, tx_index ASC""",
                    int(min_height))
                insert_sql = """INSERT INTO name_claims
                    (user_id, wallet_addr, pub_hex, registered_height, tx_id)
                    VALUES ($1,$2,$3,$4,$5)
                    ON CONFLICT (user_id) DO NOTHING"""
                for row in rows:
                    try:
                        tx = Transaction.from_dict(json.loads(row["data_json"]))
                        name = Transaction.identity_name_from_memo(tx.memo)
                        if (tx.tx_type == Transaction.TYPE_REGISTER and name
                                and tx.sender != "COINBASE" and tx.pub_hex):
                            self._pg_exec(insert_sql, name, tx.sender,
                                          tx.pub_hex, int(row["block_idx"]),
                                          tx.tx_id)
                    except Exception:
                        continue
                return
            c = self._conn()
            c.execute("DELETE FROM name_claims WHERE registered_height >= ?",
                      (int(min_height),))
            rows = c.execute(
                """SELECT block_idx, data_json FROM transactions
                   WHERE block_idx >= ? ORDER BY block_idx ASC, rowid ASC""",
                (int(min_height),)).fetchall()
            for row in rows:
                try:
                    tx = Transaction.from_dict(json.loads(row["data_json"]))
                    name = Transaction.identity_name_from_memo(tx.memo)
                    if (tx.tx_type == Transaction.TYPE_REGISTER and name
                            and tx.sender != "COINBASE" and tx.pub_hex):
                        c.execute(
                            """INSERT OR IGNORE INTO name_claims
                               (user_id, wallet_addr, pub_hex,
                                registered_height, tx_id)
                               VALUES (?,?,?,?,?)""",
                            (name, tx.sender, tx.pub_hex,
                             int(row["block_idx"]), tx.tx_id))
                except Exception:
                    continue
            c.commit()
        except Exception as exc:
            log.error("Name-claim reorg rebuild failed from height %s: %s",
                      min_height, exc)

    def save_identity(self, user_id: str, peer_id: str, wallet_addr: str,
                      pub_hex: str, multiaddrs: List[str]):
        if self._pgx_enabled:
            self._pg_exec(
                """INSERT INTO identities
                       (user_id, peer_id, wallet_addr, pub_hex, multiaddrs, last_seen)
                   VALUES ($1,$2,$3,$4,$5,$6)
                   ON CONFLICT (user_id) DO UPDATE SET
                       peer_id=EXCLUDED.peer_id,
                       wallet_addr=EXCLUDED.wallet_addr,
                       pub_hex=EXCLUDED.pub_hex,
                       multiaddrs=EXCLUDED.multiaddrs,
                       last_seen=EXCLUDED.last_seen""",
                user_id, peer_id, wallet_addr, pub_hex,
                json.dumps(multiaddrs), int(time.time()))
            return
        self._conn().execute(
            """INSERT OR REPLACE INTO identities
                   (user_id,peer_id,wallet_addr,pub_hex,multiaddrs,last_seen)
               VALUES (?,?,?,?,?,?)""",
            (user_id, peer_id, wallet_addr, pub_hex,
             json.dumps(multiaddrs), int(time.time())))
        self._conn().commit()

    def resolve_identity(self, user_id: str) -> Optional[dict]:
        """Resolve only a blockchain-confirmed name claim.

        The legacy identities table is treated as a liveness/directory cache.
        It can never create ownership and cannot override name_claims.
        """
        claim = self.resolve_name_claim(user_id)
        if not claim:
            return None
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT * FROM identities WHERE user_id=$1", user_id)
        else:
            row = self._conn().execute(
                "SELECT * FROM identities WHERE user_id=?", (user_id,)).fetchone()
        if row:
            d = dict(row)
            try: d["multiaddrs"] = json.loads(d.get("multiaddrs") or "[]")
            except Exception: d["multiaddrs"] = []
        else:
            d = {
                "user_id": user_id,
                "peer_id": sha256(claim["pub_hex"].encode()),
                "wallet_addr": claim["wallet_addr"],
                "pub_hex": claim["pub_hex"],
                "multiaddrs": [],
                "last_seen": 0,
            }
        # Canonical fields always win over mutable directory metadata.
        d.update({
            "user_id": user_id,
            "wallet_addr": claim["wallet_addr"],
            "pub_hex": claim["pub_hex"],
            "registered_height": claim["registered_height"],
            "claim_tx_id": claim["tx_id"],
        })
        return d

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  PEERS   (PG — fixes the SQLite writer-contention bug)                 ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def _mirror_peer_to_aux(self, peer_id, ip, port, last_seen, reputation,
                            fail_count=0, blacklisted=0, ban_score=0, tls_fp=""):
        """Keep aux-SQLite's peers table in sync for external raw-SQL readers."""
        if not self._pgx_enabled:
            return
        if self._pgx_active_state() is not None:
            self._pgx_after_commit(
                self._mirror_peer_to_aux,
                peer_id, ip, port, last_seen, reputation,
                fail_count, blacklisted, ban_score, tls_fp)
            return
        try:
            with self._aux_lock:
                self._conn().execute(
                    """INSERT OR REPLACE INTO peers
                       (peer_id, ip, port, last_seen, reputation, fail_count,
                        blacklisted, ban_score, tls_fp)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (peer_id, ip, int(port), int(last_seen),
                     float(reputation), int(fail_count),
                     int(blacklisted), int(ban_score), tls_fp or ""))
                self._conn().commit()
        except Exception:
            pass

    def _mirror_balance_to_aux(self, address: str, balance_sat: int):
        """Shadow balance row for external SUM(balance) / SELECT queries."""
        if not self._pgx_enabled:
            return
        if self._pgx_active_state() is not None:
            self._pgx_after_commit(self._mirror_balance_to_aux, address, balance_sat)
            return
        try:
            with self._aux_lock:
                self._conn().execute(
                    "INSERT OR REPLACE INTO balances (address, balance) VALUES (?,?)",
                    (address, int(balance_sat)))
                self._conn().commit()
        except Exception as _mir_e:
            # AUDIT-FIX-O1d: was a bare `except: pass` -- a failed mirror write
            # here was completely invisible, which is how the aux shadow could
            # drift from Postgres with no operator signal at all. Still
            # non-blocking by design (an aux hiccup must never fail the real
            # balance mutation), but no longer silent.
            log.debug("aux mirror (balance) failed for %s: %s", address, _mir_e)
            metrics.inc("aux_mirror_write_failures")

    def _mirror_block_to_aux(self, block: 'Block'):
        """Shadow block row for external SELECT MAX(idx) / by-hash queries."""
        if not self._pgx_enabled:
            return
        if self._pgx_active_state() is not None:
            self._pgx_after_commit(self._mirror_block_to_aux, block)
            return
        try:
            with self._aux_lock:
                c = self._conn()
                c.execute(
                    """INSERT OR REPLACE INTO blocks
                         (idx, block_hash, prev_hash, timestamp, miner,
                          difficulty, nonce, merkle_root, state_root,
                          finalized, data_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (block.index, block.block_hash, block.prev_hash,
                     block.timestamp, block.miner_address, block.difficulty,
                     block.nonce, block.merkle_root, block.state_root,
                     int(block.finalized), ""))
                c.commit()
        except Exception as _mir_e:
            # AUDIT-FIX-O1d: see _mirror_balance_to_aux above.
            log.debug("aux mirror (block) failed for #%s: %s",
                      getattr(block, "index", "?"), _mir_e)
            metrics.inc("aux_mirror_write_failures")

    def _mirror_contract_to_aux(self, address: str, code_hash: str,
                                 creator: str, created_at: int,
                                 destroyed: int = 0,
                                 contract_name: str = ""):  # SC-NAME-1: new param
        if not self._pgx_enabled:
            return
        if self._pgx_active_state() is not None:
            self._pgx_after_commit(
                self._mirror_contract_to_aux, address, code_hash, creator,
                created_at, destroyed, contract_name)
            return
        try:
            with self._aux_lock:
                self._conn().execute(
                    """INSERT OR REPLACE INTO contract_accounts
                         (address, code_hash, storage_root, nonce,
                          creator, created_at, destroyed, contract_name)
                       VALUES (?,?,?,0,?,?,?,?)""",
                    (address, code_hash, sha256(b"empty_storage"),
                     creator, int(created_at), int(destroyed),
                     normalize_contract_name(contract_name)))
                self._conn().commit()
        except Exception as _mir_e:
            # AUDIT-FIX-O1d: see _mirror_balance_to_aux above.
            log.debug("aux mirror (contract) failed for %s: %s", address, _mir_e)
            metrics.inc("aux_mirror_write_failures")

    def save_peer(self, peer_id: str, ip: str, port: int,
                  reputation: float = 1.0, fail_count: int = 0):
        ts = int(time.time())
        if self._pgx_enabled:
            self._pg_exec(
                """INSERT INTO peers
                       (peer_id, ip, port, last_seen, reputation,
                        fail_count, blacklisted)
                   VALUES ($1,$2,$3,$4,$5,0,FALSE)
                   ON CONFLICT (peer_id) DO UPDATE SET
                       ip=EXCLUDED.ip, port=EXCLUDED.port,
                       last_seen=EXCLUDED.last_seen,
                       reputation=EXCLUDED.reputation,
                       fail_count=0, blacklisted=FALSE,
                       updated_at=now()""",
                peer_id, ip, int(port), ts, float(reputation))
            self._mirror_peer_to_aux(peer_id, ip, port, ts, reputation)
            return
        self._conn().execute(
            """INSERT OR REPLACE INTO peers
                   (peer_id,ip,port,last_seen,reputation,fail_count,blacklisted)
               VALUES (?,?,?,?,?,0,0)""",
            (peer_id, ip, port, ts, reputation))
        self._conn().commit()

    def get_peers(self, limit: int = 100, exclude_blacklisted: bool = True) -> List[dict]:
        if self._pgx_enabled:
            if exclude_blacklisted:
                rows = self._pg_fetch(
                    """SELECT peer_id, ip, port, last_seen, reputation, fail_count,
                              (CASE WHEN blacklisted THEN 1 ELSE 0 END) AS blacklisted,
                              ban_score, tls_fp
                         FROM peers
                        WHERE blacklisted = FALSE
                     ORDER BY reputation DESC, last_seen DESC LIMIT $1""",
                    int(limit))
            else:
                rows = self._pg_fetch(
                    """SELECT peer_id, ip, port, last_seen, reputation, fail_count,
                              (CASE WHEN blacklisted THEN 1 ELSE 0 END) AS blacklisted,
                              ban_score, tls_fp
                         FROM peers
                     ORDER BY reputation DESC, last_seen DESC LIMIT $1""",
                    int(limit))
            return [dict(r) for r in rows]
        q = "SELECT * FROM peers"
        if exclude_blacklisted: q += " WHERE blacklisted=0"
        q += " ORDER BY reputation DESC, last_seen DESC LIMIT ?"
        rows = self._conn().execute(q, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def mark_peer_fail(self, peer_id: str):
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT fail_count, reputation FROM peers WHERE peer_id=$1", peer_id)
            if not row:
                return
            if float(row["reputation"] or 0.0) > 0.5:
                self._pg_exec(
                    """UPDATE peers SET fail_count=0, blacklisted=FALSE,
                                        updated_at=now() WHERE peer_id=$1""",
                    peer_id)
                try:
                    with self._aux_lock:
                        self._conn().execute(
                            "UPDATE peers SET fail_count=0, blacklisted=0 WHERE peer_id=?",
                            (peer_id,))
                        self._conn().commit()
                except Exception:
                    pass
                return
            new_fail = int(row["fail_count"] or 0) + 1
            bl = new_fail >= Config.PEER_MAX_FAIL
            self._pg_exec(
                """UPDATE peers SET fail_count=$2, blacklisted=$3,
                                    updated_at=now() WHERE peer_id=$1""",
                peer_id, new_fail, bl)
            try:
                with self._aux_lock:
                    self._conn().execute(
                        "UPDATE peers SET fail_count=?, blacklisted=? WHERE peer_id=?",
                        (new_fail, 1 if bl else 0, peer_id))
                    self._conn().commit()
            except Exception:
                pass
            return
        row = self._conn().execute(
            "SELECT fail_count, reputation FROM peers WHERE peer_id=?",
            (peer_id,)).fetchone()
        if not row:
            return
        if row["reputation"] > 0.5:
            self._conn().execute(
                "UPDATE peers SET fail_count=0, blacklisted=0 WHERE peer_id=?",
                (peer_id,))
            self._conn().commit()
            return
        new_fail = row["fail_count"] + 1
        blacklisted = 1 if new_fail >= Config.PEER_MAX_FAIL else 0
        self._conn().execute(
            "UPDATE peers SET fail_count=?,blacklisted=? WHERE peer_id=?",
            (new_fail, blacklisted, peer_id))
        self._conn().commit()

    def blacklist_peer(self, peer_id: str):
        if self._pgx_enabled:
            self._pg_exec(
                "UPDATE peers SET blacklisted=TRUE WHERE peer_id=$1", peer_id)
            try:
                with self._aux_lock:
                    self._conn().execute(
                        "UPDATE peers SET blacklisted=1 WHERE peer_id=?", (peer_id,))
                    self._conn().commit()
            except Exception:
                pass
            return
        self._conn().execute(
            "UPDATE peers SET blacklisted=1 WHERE peer_id=?", (peer_id,))
        self._conn().commit()

    def peer_count(self) -> int:
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT COUNT(*) AS c FROM peers WHERE blacklisted=FALSE")
            return int(row["c"]) if row else 0
        row = self._conn().execute(
            "SELECT COUNT(*) as c FROM peers WHERE blacklisted=0").fetchone()
        return row["c"]

    def get_nonce(self, address: str) -> int:
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT nonce FROM accounts WHERE address=$1", address)
            return int(row["nonce"]) if row else 0
        row = self._conn().execute(
            "SELECT nonce FROM account_nonces WHERE address=?", (address,)).fetchone()
        return row["nonce"] if row else 0

    def set_nonce(self, address: str, nonce: int):
        if self._pgx_enabled:
            self._pg_exec(
                """INSERT INTO accounts (address, nonce, updated_at)
                   VALUES ($1, $2, now())
                   ON CONFLICT (address) DO UPDATE SET
                       nonce=EXCLUDED.nonce, updated_at=now()""",
                address, int(nonce))
            return
        self._conn().execute(
            "INSERT OR REPLACE INTO account_nonces (address, nonce) VALUES (?,?)",
            (address, nonce))
        self._conn().commit()

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  TPS-OPT-2 — ATOMIC BLOCK BATCH FLUSH                                 ║
    # ║  Writes ALL balance / nonce / volume mutations from one block in a     ║
    # ║  SINGLE I/O operation per backend, eliminating ~800 round-trips for    ║
    # ║  a 200-tx block.                                                       ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def _flush_block_batch(self,
                           bal_updates: Dict[str, int],
                           non_updates: Dict[str, int],
                           vol_deltas:  Dict[str, int]):
        """Atomically commit all state mutations from a single block.

        Parameters
        ----------
        bal_updates : addr → FINAL balance_sat (absolute, not delta)
        non_updates : addr → new nonce value
        vol_deltas  : addr → volume DELTA to add (satoshi)
        """
        if self._pgx_enabled:
            active = self._pgx_active_conn()

            async def _write(c):
                # ── balances ──────────────────────────────────────────
                if bal_updates:
                    bal_rows = [(a, b) for a, b in bal_updates.items()]
                    await c.executemany(
                        """INSERT INTO accounts
                               (address, balance_sat, updated_at)
                           VALUES ($1, $2, now())
                           ON CONFLICT (address) DO UPDATE SET
                               balance_sat = EXCLUDED.balance_sat,
                               updated_at  = now()""",
                        bal_rows)
                # ── nonces ────────────────────────────────────────────
                if non_updates:
                    non_rows = [(a, n) for a, n in non_updates.items()]
                    await c.executemany(
                        """INSERT INTO accounts
                               (address, nonce, updated_at)
                           VALUES ($1, $2, now())
                           ON CONFLICT (address) DO UPDATE SET
                               nonce      = EXCLUDED.nonce,
                               updated_at = now()""",
                        non_rows)
                # ── ht_volume deltas ─────────────────────────────────
                if vol_deltas:
                    vol_rows = [(a, v) for a, v in vol_deltas.items()]
                    await c.executemany(
                        """INSERT INTO accounts
                               (address, ht_volume_sat, updated_at)
                           VALUES ($1, $2, now())
                           ON CONFLICT (address) DO UPDATE SET
                               ht_volume_sat = accounts.ht_volume_sat
                                               + EXCLUDED.ht_volume_sat,
                               updated_at    = now()""",
                        vol_rows)

            if active is not None:
                # The surrounding pgx_atomic_block owns the transaction.
                self._pg.run(_write(active))
            else:
                async def _atomic():
                    async with self._pg._pool.acquire() as c:
                        async with c.transaction():
                            await _write(c)
                self._pg.run(_atomic())

            # Cache/shadow updates become visible only after the canonical
            # PostgreSQL transaction commits.
            for addr, bal in bal_updates.items():
                self._pgx_after_commit(self._cache.cache_balance, addr, bal)
                self._pgx_after_commit(self._mirror_balance_to_aux, addr, bal)
        else:
            # ── SQLite: single commit at the end ──────────────────────
            c = self._conn()
            for addr, bal in bal_updates.items():
                c.execute(
                    "INSERT OR REPLACE INTO balances (address, balance) "
                    "VALUES (?,?)", (addr, int(bal)))
            for addr, nonce in non_updates.items():
                c.execute(
                    "INSERT OR REPLACE INTO account_nonces (address, nonce) "
                    "VALUES (?,?)", (addr, int(nonce)))
            for addr, vol_d in vol_deltas.items():
                row = c.execute(
                    "SELECT volume FROM ht_volume WHERE address=?",
                    (addr,)).fetchone()
                cur_vol = int(row["volume"]) if row else 0
                c.execute(
                    "INSERT OR REPLACE INTO ht_volume "
                    "(address, volume, updated) VALUES (?,?,?)",
                    (addr, cur_vol + int(vol_d), int(time.time())))
            c.commit()
            self._maybe_checkpoint()

    def get_peer_tls_fp(self, peer_id: str) -> Optional[str]:
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT tls_fp FROM peers WHERE peer_id=$1", peer_id)
            fp = row["tls_fp"] if row else None
            return fp if fp else None
        row = self._conn().execute(
            "SELECT tls_fp FROM peers WHERE peer_id=?", (peer_id,)).fetchone()
        if not row: return None
        fp = row["tls_fp"]
        return fp if fp else None

    def set_peer_tls_fp(self, peer_id: str, fingerprint: str):
        if self._pgx_enabled:
            self._pg_exec(
                "UPDATE peers SET tls_fp=$2, updated_at=now() WHERE peer_id=$1",
                peer_id, fingerprint)
            return
        self._conn().execute(
            "UPDATE peers SET tls_fp=? WHERE peer_id=?", (fingerprint, peer_id))
        self._conn().commit()

    def get_ban_score(self, peer_id: str) -> int:
        """Return current ban score for a peer without modifying it."""
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT ban_score FROM peers WHERE peer_id=$1", peer_id)
            if row is None:
                return 0
            return int(row["ban_score"] or 0)
        row = self._conn().execute(
            "SELECT ban_score FROM peers WHERE peer_id=?", (peer_id,)).fetchone()
        if not row:
            return 0
        return int(row["ban_score"] or 0)

    def add_ban_score(self, peer_id: str, points: int) -> int:
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                """UPDATE peers SET
                       ban_score   = ban_score + $2,
                       blacklisted = (ban_score + $2) >= $3,
                       updated_at  = now()
                    WHERE peer_id=$1
                   RETURNING ban_score, blacklisted""",
                peer_id, int(points), int(Config.PEER_BAN_SCORE_THRESHOLD))
            if row is None:
                return 0
            new_score = int(row["ban_score"])
            bl = bool(row["blacklisted"])
            try:
                with self._aux_lock:
                    self._conn().execute(
                        "UPDATE peers SET ban_score=?, blacklisted=? WHERE peer_id=?",
                        (new_score, 1 if bl else 0, peer_id))
                    self._conn().commit()
            except Exception:
                pass
            if bl:
                log.warning(f"Peer {peer_id[:12]} auto-banned (ban_score={new_score})")
            return new_score
        row = self._conn().execute(
            "SELECT ban_score FROM peers WHERE peer_id=?", (peer_id,)).fetchone()
        if not row:
            return 0
        new_score = (row["ban_score"] or 0) + points
        blacklisted = 1 if new_score >= Config.PEER_BAN_SCORE_THRESHOLD else 0
        self._conn().execute(
            "UPDATE peers SET ban_score=?, blacklisted=? WHERE peer_id=?",
            (new_score, blacklisted, peer_id))
        self._conn().commit()
        if blacklisted:
            log.warning(f"Peer {peer_id[:12]} auto-banned (ban_score={new_score})")
        return new_score

    def decay_ban_scores(self):
        if self._pgx_enabled:
            self._pg_exec(
                "UPDATE peers SET ban_score = ban_score / 2 WHERE ban_score > 0")
            return
        self._conn().execute(
            "UPDATE peers SET ban_score = ban_score / 2 WHERE ban_score > 0")
        self._conn().commit()

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  STATE ROOT (deterministic SHA-256 over sorted state)                  ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def compute_state_root(self) -> str:
        # ── v7.1.10-hotfix: environment-independent state_root ─────────────
        # Previously this used ``ORDER BY address ASC`` (subject to locale /
        # ICU collation differences between Termux and Pydroid builds of
        # SQLite) and ``int(row['balance'])`` (subject to SQLite type-affinity
        # differences — a balance column could come back as float on one
        # platform and int on another).  Both divergences produced different
        # state_roots on different Android Python builds from the SAME data,
        # which is exactly the symptom in the "Prev block state_root mismatch"
        # rejection loop.
        #
        # Fix: sort by the raw bytes of the address (collation-free) and
        # coerce balance through ``round(float(...))`` so float-affinity and
        # int-affinity storage both hash identically.
        #
        # v7.2.0-FIX-3: Balance is now formatted as integer satoshi directly
        # (e.g. "1000000000") instead of a VSD float string (e.g. "10.00000000").
        # This eliminates two sources of non-determinism:
        #   a) float(large_int) loses precision for balances > 2^53 sat (~90k VSD).
        #   b) :.8f float formatting can differ at ULP boundaries across platforms.
        # NOTE: all nodes must upgrade together — this changes the hash format.
        if self._pgx_enabled:
            balance_rows = self._pg_fetch(
                """SELECT address, balance_sat FROM accounts
                    WHERE balance_sat > 0
                    ORDER BY convert_to(address, 'UTF8') ASC""")
            contract_rows = self._pg_fetch(
                """SELECT address, code_hash, storage_root
                     FROM contract_accounts
                    WHERE destroyed=FALSE
                    ORDER BY convert_to(address, 'UTF8') ASC""")
            if not balance_rows and not contract_rows:
                return sha256(b"empty_state")
            parts = []
            for r in balance_rows:
                # v7.2.0-FIX-3: use integer satoshi directly — no float conversion.
                bal_sat = int(r['balance_sat'])
                parts.append(f"B:{r['address']}:{bal_sat}")
            for r in contract_rows:
                parts.append(f"C:{r['address']}:{r['code_hash']}:{r['storage_root']}")
            # SC-NAME-1: commit name→address mapping to the state root so any
            # divergence in the name registry is caught by state_root mismatch.
            named_rows = self._pg_fetch(
                """SELECT address, contract_name FROM contract_accounts
                    WHERE destroyed=FALSE AND contract_name != ''
                    ORDER BY convert_to(contract_name, 'UTF8') ASC""")
            for r in named_rows:
                parts.append(f"cname:{r['contract_name']}:{r['address']}")
            return sha256("\n".join(parts).encode())
        c = self._conn()
        # AUDIT-FIX-13 (state root divergence): this previously had no WHERE
        # clause at all, unlike the PostgreSQL branch above it
        # ("WHERE balance_sat > 0"). Every credit_sat/debit_sat/set_balance
        # call uses INSERT OR REPLACE, so a row always exists after any
        # activity — including addresses that have spent their entire
        # balance down to exactly 0, which happens on any ordinary full-
        # balance send. Without this filter, a SQLite-backed node included
        # every such zero-balance row in the state-root hash while a
        # PostgreSQL-backed node excluded them — two backends computing
        # different roots from identical underlying account state, an
        # immediate cross-backend fork on the first full-balance send
        # anywhere on the network. Matching the PG filter here makes both
        # branches select the same row set for the same data.
        balance_rows = c.execute(
            "SELECT address, balance FROM balances WHERE balance > 0 "
            "ORDER BY CAST(address AS BLOB) ASC").fetchall()
        contract_rows = c.execute(
            "SELECT address, code_hash, storage_root FROM contract_accounts "
            "WHERE destroyed=0 "
            "ORDER BY CAST(address AS BLOB) ASC").fetchall()
        if not balance_rows and not contract_rows:
            return sha256(b"empty_state")
        parts = []
        for row in balance_rows:
            # v7.2.0-FIX-3: coerce to int without going through float.
            # balance column may be stored as int, float, or numeric string.
            raw = row['balance']
            if isinstance(raw, float):
                bal_sat = int(round(raw))   # float column (legacy schema)
            else:
                bal_sat = int(raw)          # int or string — exact
            parts.append(f"B:{row['address']}:{bal_sat}")
        for row in contract_rows:
            parts.append(f"C:{row['address']}:{row['code_hash']}:{row['storage_root']}")
        # SC-NAME-1: commit name→address mapping to the state root so any
        # divergence in the name registry is caught by state_root mismatch.
        named_rows = c.execute(
            "SELECT address, contract_name FROM contract_accounts "
            "WHERE destroyed=0 AND contract_name != '' "
            "ORDER BY CAST(contract_name AS BLOB) ASC").fetchall()
        for row in named_rows:
            parts.append(f"cname:{row['contract_name']}:{row['address']}")
        return sha256("\n".join(parts).encode())

    def _compute_contract_storage_root(self, contract_addr: str) -> str:
        """Compute the canonical per-contract storage commitment.

        Untyped storage keeps the historical value-only encoding for backward
        compatibility.  Once any explicit type tag exists, each participating
        slot commits to ``slot:value:tag`` so typed metadata is consensus state.
        """
        if self._pgx_enabled:
            slots = sorted(self._rocks.iter_cstorage(contract_addr),
                           key=lambda kv: kv[0])
            tags = {k: int(v) for k, v in self._rocks.iter_cstorage_tags(contract_addr)}
            if not slots and not tags:
                return sha256(b"empty_storage")
            values = {k: (v.decode('ascii') if v else '0') for k, v in slots}
            keys = sorted(set(values) | set(tags), key=lambda x: x.encode('utf-8'))
            if not tags:
                payload = "\n".join(f"{k}:{values.get(k, '0')}" for k in keys).encode()
            else:
                payload = "\n".join(
                    f"{k}:{values.get(k, '0')}:{int(tags.get(k, 0))}"
                    for k in keys
                ).encode()
            return sha256(payload)

        rows = self._conn().execute(
            "SELECT slot_key, slot_value FROM contract_storage "
            "WHERE contract_addr=? ORDER BY CAST(slot_key AS BLOB) ASC",
            (contract_addr,)).fetchall()
        tag_rows = self._conn().execute(
            "SELECT slot_key, type_tag FROM contract_storage_tags "
            "WHERE contract_addr=? ORDER BY CAST(slot_key AS BLOB) ASC",
            (contract_addr,)).fetchall()
        if not rows and not tag_rows:
            return sha256(b"empty_storage")
        values = {str(r['slot_key']): str(r['slot_value']) for r in rows}
        tags = {str(r['slot_key']): int(r['type_tag']) for r in tag_rows}
        keys = sorted(set(values) | set(tags), key=lambda x: x.encode('utf-8'))
        if not tags:
            payload = "\n".join(f"{k}:{values.get(k, '0')}" for k in keys).encode()
        else:
            payload = "\n".join(
                f"{k}:{values.get(k, '0')}:{int(tags.get(k, 0))}"
                for k in keys
            ).encode()
        return sha256(payload)

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  CONTRACT ACCOUNTS / CODE / STORAGE                                    ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def get_contract(self, address: str) -> Optional[dict]:
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                """SELECT address, code_hash, storage_root, nonce, creator,
                          created_at, contract_name,
                          (CASE WHEN destroyed THEN 1 ELSE 0 END) AS destroyed
                     FROM contract_accounts
                    WHERE address=$1 AND destroyed=FALSE""", address)
            return dict(row) if row else None
        row = self._conn().execute(
            "SELECT * FROM contract_accounts WHERE address=? AND destroyed=0",
            (address,)).fetchone()
        return dict(row) if row else None

    def get_contract_by_name(self, name: str) -> Optional[dict]:
        """
        SC-NAME-1: Look up an active contract record by its normalised name.

        Returns the same dict as get_contract() or None if not found.

        CONSENSUS NOTE: always pass the already-normalised name (call
        normalize_contract_name() before this method).  The DB stores only
        canonical names so case variants never match.
        """
        norm = normalize_contract_name(name)
        if not norm:
            return None
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                """SELECT address, code_hash, storage_root, nonce, creator,
                          created_at, contract_name,
                          (CASE WHEN destroyed THEN 1 ELSE 0 END) AS destroyed
                     FROM contract_accounts
                    WHERE contract_name = $1 AND destroyed = FALSE""", norm)
            return dict(row) if row else None
        row = self._conn().execute(
            "SELECT * FROM contract_accounts "
            "WHERE contract_name = ? AND destroyed = 0",
            (norm,)).fetchone()
        return dict(row) if row else None

    def contract_name_exists(self, name: str) -> bool:
        """
        SC-NAME-1: Return True if an ACTIVE contract with this normalised name
        already exists.

        This is the fast-path uniqueness check called by _apply_vvm_tx() before
        VM execution.  It is O(1) via the unique index.
        """
        return self.get_contract_by_name(name) is not None

    def save_contract(self, address: str, code_hash: str, creator: str,
                      created_at: int = 0,
                      contract_name: str = ""):      # SC-NAME-1: new param
        """
        SC-NAME-1 UPDATED: Persist a newly deployed contract record.

        contract_name must already be normalised (pass normalize_contract_name()
        output or leave as "" for unnamed legacy contracts).

        If contract_name is non-empty AND already taken, the INSERT will hit the
        unique index and raise IntegrityError — this should never happen because
        _apply_vvm_tx() checks uniqueness before calling save_contract(), but the
        DB constraint is a safety net.
        """
        now = created_at or int(time.time())
        norm_name = normalize_contract_name(contract_name)  # idempotent
        if self._pgx_enabled:
            self._pg_exec(
                """INSERT INTO contract_accounts
                       (address, code_hash, storage_root, nonce,
                        creator, created_at, destroyed, contract_name)
                   VALUES ($1,$2,$3,0,$4,$5,FALSE,$6)
                   ON CONFLICT (address) DO NOTHING""",
                address, code_hash, sha256(b"empty_storage"), creator, now,
                norm_name)
            self._mirror_contract_to_aux(address, code_hash, creator, now, 0,
                                         norm_name)
            return
        c = self._conn()
        c.execute(
            """INSERT OR IGNORE INTO contract_accounts
                   (address, code_hash, storage_root, nonce, creator,
                    created_at, destroyed, contract_name)
               VALUES (?,?,?,0,?,?,0,?)""",
            (address, code_hash, sha256(b"empty_storage"), creator, now,
             norm_name))
        c.commit()
        self._maybe_checkpoint()

    def update_contract_storage_root(self, contract_addr: str):
        root = self._compute_contract_storage_root(contract_addr)
        if self._pgx_enabled:
            self._pg_exec(
                "UPDATE contract_accounts SET storage_root=$2 WHERE address=$1",
                contract_addr, root)
            return
        self._conn().execute(
            "UPDATE contract_accounts SET storage_root=? WHERE address=?",
            (root, contract_addr))
        self._conn().commit()

    def destroy_contract(self, address: str):
        """Mark an existing contract as destroyed (runtime SELFDESTRUCT semantics).

        This is intentionally a *soft* delete.  Consensus rollback of a
        contract created by the rolled-back block must instead call
        ``remove_contract`` so the address can be deterministically re-created
        when the same canonical block is replayed.
        """
        if self._pgx_enabled:
            self._pg_exec(
                "UPDATE contract_accounts SET destroyed=TRUE WHERE address=$1",
                address)
            try:
                with self._aux_lock:
                    self._conn().execute(
                        "UPDATE contract_accounts SET destroyed=1 WHERE address=?",
                        (address,))
                    self._conn().commit()
            except Exception:
                pass
            return
        self._conn().execute(
            "UPDATE contract_accounts SET destroyed=1 WHERE address=?",
            (address,))
        self._conn().commit()

    def remove_contract(self, address: str) -> Optional[str]:
        """Physically remove a contract account and all of its storage.

        This operation is for *consensus rollback only*: a contract created by
        an orphaned DEPLOY/CREATE/CREATE2 has no representation in the new
        canonical state and must not remain as a ``destroyed=1`` tombstone.
        ``save_contract()`` intentionally uses INSERT-OR-IGNORE/ON-CONFLICT-DO
        NOTHING, so leaving the tombstone would make deterministic replay of
        the same block silently skip contract creation and change the state
        root.

        Returns the removed contract's code_hash (or None when absent).
        The method is idempotent.
        """
        code_hash: Optional[str] = None
        if self._pgx_enabled:
            try:
                row = self._pg_fetchrow(
                    "SELECT code_hash FROM contract_accounts WHERE address=$1",
                    address)
                if row:
                    code_hash = row["code_hash"]
            except Exception as exc:
                log.error("remove_contract(%s): read failed: %s",
                          address[:16], exc)
                return None

            # Contract storage is canonical in RocksDB in pgx mode.  Remove it
            # in one batch with no externally visible intermediate slot set.
            try:
                slots = self._rocks.iter_cstorage(address)
                batch = self._rocks.new_batch()
                for slot, _ in slots:
                    self._rocks.del_cstorage(batch, address, slot)
                for slot, _ in self._rocks.iter_cstorage_tags(address):
                    self._rocks.del_cstorage_tag(batch, address, slot)
                self._rocks.commit(batch, sync=True)
            except Exception as exc:
                log.error("remove_contract(%s): RocksDB storage cleanup failed: %s",
                          address[:16], exc)
                return None

            try:
                self._pg_exec(
                    "DELETE FROM contract_accounts WHERE address=$1",
                    address)
            except Exception as exc:
                log.error("remove_contract(%s): PostgreSQL account delete failed: %s",
                          address[:16], exc)
                return None

            # Keep the auxiliary SQLite projection in sync.
            try:
                with self._aux_lock:
                    self._conn().execute(
                        "DELETE FROM contract_storage WHERE contract_addr=?",
                        (address,))
                    self._conn().execute(
                        "DELETE FROM contract_storage_tags WHERE contract_addr=?",
                        (address,))
                    self._conn().execute(
                        "DELETE FROM contract_accounts WHERE address=?",
                        (address,))
                    self._conn().commit()
            except Exception:
                pass
            return code_hash

        c = self._conn()
        try:
            row = c.execute(
                "SELECT code_hash FROM contract_accounts WHERE address=?",
                (address,)).fetchone()
            if row:
                code_hash = row["code_hash"]
            c.execute(
                "DELETE FROM contract_storage WHERE contract_addr=?",
                (address,))
            c.execute(
                "DELETE FROM contract_storage_tags WHERE contract_addr=?",
                (address,))
            c.execute(
                "DELETE FROM contract_accounts WHERE address=?",
                (address,))
            c.commit()
            self._maybe_checkpoint()
            return code_hash
        except Exception as exc:
            c.rollback()
            log.error("remove_contract(%s) failed: %s", address[:16], exc)
            return None

    # ── AUDIT-FIX (Batch D): Native State Channel Storage API ─────────────────
    # Moved here from Blockchain, where every one of these six methods called
    # self._conn() -- which does not exist on Blockchain -- so every channel
    # operation failed with AttributeError, caught by the method's own
    # try/except and surfaced as an ordinary-looking "operation failed"
    # return value. Storage genuinely has _conn() (aux/legacy SQLite) and
    # _pg_exec()/_pg_fetchrow() (Postgres), so these are reimplemented here
    # following the same pg-primary + aux-sqlite-shadow pattern as
    # save_contract/destroy_contract above. VVMEngine's precompile handler
    # already calls self._storage.create_channel(...) etc., so it needed no
    # change -- only fixing where these methods actually live.
    def create_channel(self, channel_id: str, contract_addr: str,
                       opener: str, counterparty: str,
                       opener_deposit_sat: int, timeout_blocks: int,
                       open_height: int) -> bool:
        """Insert a new OPEN channel row.  Returns False if channel_id exists."""
        previous = self.get_channel(channel_id)
        if self._pgx_enabled:
            self._record_state_channel_before(channel_id, previous)
            try:
                row = self._pg_fetchrow(
                    """INSERT INTO state_channels
                           (channel_id, contract_addr, opener, counterparty,
                            total_deposit_sat, opener_deposit_sat,
                            timeout_blocks, open_height, status,
                            dispute_seq, dispute_bal_opener, dispute_bal_counter,
                            dispute_height, closed_height)
                       VALUES ($1,$2,$3,$4,$5,$5,$6,$7,'OPEN',0,0,0,0,0)
                       ON CONFLICT (channel_id) DO NOTHING
                       RETURNING channel_id""",
                    channel_id, contract_addr, opener, counterparty,
                    opener_deposit_sat, timeout_blocks, open_height)
            except Exception as exc:
                log.warning("create_channel (pgx) failed: %s", exc)
                return False
            created = row is not None
            if created:
                try:
                    with self._aux_lock:
                        self._conn().execute(
                            """INSERT OR IGNORE INTO state_channels
                                   (channel_id, contract_addr, opener, counterparty,
                                    total_deposit_sat, opener_deposit_sat,
                                    timeout_blocks, open_height, status,
                                    dispute_seq, dispute_bal_opener, dispute_bal_counter,
                                    dispute_height, closed_height)
                               VALUES (?,?,?,?,?,?,?,?,'OPEN',0,0,0,0,0)""",
                            (channel_id, contract_addr, opener, counterparty,
                             opener_deposit_sat, opener_deposit_sat,
                             timeout_blocks, open_height))
                        self._conn().commit()
                except Exception:
                    pass
            return created
        try:
            self._record_state_channel_before(channel_id, previous)
            c = self._conn()
            c.execute(
                """INSERT INTO state_channels
                   (channel_id, contract_addr, opener, counterparty,
                    total_deposit_sat, opener_deposit_sat,
                    timeout_blocks, open_height, status,
                    dispute_seq, dispute_bal_opener, dispute_bal_counter,
                    dispute_height, closed_height)
                   VALUES (?,?,?,?,?,?,?,?,'OPEN',0,0,0,0,0)""",
                (channel_id, contract_addr, opener, counterparty,
                 opener_deposit_sat, opener_deposit_sat,
                 timeout_blocks, open_height))
            c.commit()
            self._maybe_checkpoint()
            return True
        except sqlite3.IntegrityError:
            return False   # duplicate channel_id
        except Exception as exc:
            log.warning("create_channel failed: %s", exc)
            return False

    def get_channel(self, channel_id: str) -> Optional[dict]:
        """Return channel row as dict, or None if not found."""
        if self._pgx_enabled:
            try:
                row = self._pg_fetchrow(
                    "SELECT * FROM state_channels WHERE channel_id=$1",
                    channel_id)
                return dict(row) if row else None
            except Exception as exc:
                log.warning("get_channel (pgx) failed: %s", exc)
                return None
        try:
            c = self._conn()
            row = c.execute(
                "SELECT * FROM state_channels WHERE channel_id=?",
                (channel_id,)).fetchone()
            return dict(row) if row else None
        except Exception as exc:
            log.warning("get_channel failed: %s", exc)
            return None

    def close_channel(self, channel_id: str, closed_height: int) -> bool:
        """Mark a channel as CLOSED."""
        if self._pgx_enabled:
            previous = self.get_channel(channel_id)
            try:
                row = self._pg_fetchrow(
                    """UPDATE state_channels SET status='CLOSED', closed_height=$1
                       WHERE channel_id=$2 AND status='OPEN'
                       RETURNING channel_id""",
                    closed_height, channel_id)
            except Exception as exc:
                log.warning("close_channel (pgx) failed: %s", exc)
                return False
            updated = row is not None
            if updated:
                self._record_state_channel_before(channel_id, previous)
                try:
                    with self._aux_lock:
                        self._conn().execute(
                            "UPDATE state_channels SET status='CLOSED', closed_height=? "
                            "WHERE channel_id=? AND status='OPEN'",
                            (closed_height, channel_id))
                        self._conn().commit()
                except Exception:
                    pass
            return updated
        try:
            previous = self.get_channel(channel_id)
            c = self._conn()
            c.execute(
                "UPDATE state_channels SET status='CLOSED', closed_height=? "
                "WHERE channel_id=? AND status='OPEN'",
                (closed_height, channel_id))
            c.commit()
            self._maybe_checkpoint()
            if c.rowcount > 0:
                self._record_state_channel_before(channel_id, previous)
            return c.rowcount > 0
        except Exception as exc:
            log.warning("close_channel failed: %s", exc)
            return False

    def raise_dispute(self, channel_id: str, seq_no: int,
                      bal_opener: int, bal_counter: int,
                      dispute_height: int) -> bool:
        """Set channel to DISPUTED state with submitted state snapshot."""
        if self._pgx_enabled:
            previous = self.get_channel(channel_id)
            try:
                row = self._pg_fetchrow(
                    """UPDATE state_channels
                       SET status='DISPUTED',
                           dispute_seq=$1, dispute_bal_opener=$2,
                           dispute_bal_counter=$3, dispute_height=$4
                       WHERE channel_id=$5 AND status='OPEN'
                       RETURNING channel_id""",
                    seq_no, bal_opener, bal_counter,
                    dispute_height, channel_id)
            except Exception as exc:
                log.warning("raise_dispute (pgx) failed: %s", exc)
                return False
            updated = row is not None
            if updated:
                self._record_state_channel_before(channel_id, previous)
                try:
                    with self._aux_lock:
                        self._conn().execute(
                            """UPDATE state_channels
                               SET status='DISPUTED',
                                   dispute_seq=?, dispute_bal_opener=?,
                                   dispute_bal_counter=?, dispute_height=?
                               WHERE channel_id=? AND status='OPEN'""",
                            (seq_no, bal_opener, bal_counter,
                             dispute_height, channel_id))
                        self._conn().commit()
                except Exception:
                    pass
            return updated
        try:
            previous = self.get_channel(channel_id)
            c = self._conn()
            c.execute(
                """UPDATE state_channels
                   SET status='DISPUTED',
                       dispute_seq=?, dispute_bal_opener=?,
                       dispute_bal_counter=?, dispute_height=?
                   WHERE channel_id=? AND status='OPEN'""",
                (seq_no, bal_opener, bal_counter,
                 dispute_height, channel_id))
            c.commit()
            self._maybe_checkpoint()
            if c.rowcount > 0:
                self._record_state_channel_before(channel_id, previous)
            return c.rowcount > 0
        except Exception as exc:
            log.warning("raise_dispute failed: %s", exc)
            return False

    def force_close_channel(self, channel_id: str, closed_height: int) -> bool:
        """Force-close a DISPUTED channel after timeout."""
        if self._pgx_enabled:
            previous = self.get_channel(channel_id)
            try:
                row = self._pg_fetchrow(
                    """UPDATE state_channels SET status='FORCE_CLOSED',
                       closed_height=$1 WHERE channel_id=$2 AND status='DISPUTED'
                       RETURNING channel_id""",
                    closed_height, channel_id)
            except Exception as exc:
                log.warning("force_close_channel (pgx) failed: %s", exc)
                return False
            updated = row is not None
            if updated:
                self._record_state_channel_before(channel_id, previous)
                try:
                    with self._aux_lock:
                        self._conn().execute(
                            "UPDATE state_channels SET status='FORCE_CLOSED', "
                            "closed_height=? WHERE channel_id=? AND status='DISPUTED'",
                            (closed_height, channel_id))
                        self._conn().commit()
                except Exception:
                    pass
            return updated
        try:
            previous = self.get_channel(channel_id)
            c = self._conn()
            c.execute(
                "UPDATE state_channels SET status='FORCE_CLOSED', "
                "closed_height=? WHERE channel_id=? AND status='DISPUTED'",
                (closed_height, channel_id))
            c.commit()
            self._maybe_checkpoint()
            if c.rowcount > 0:
                self._record_state_channel_before(channel_id, previous)
            return c.rowcount > 0
        except Exception as exc:
            log.warning("force_close_channel failed: %s", exc)
            return False

    def get_open_channel_between(self, opener: str, counterparty: str,
                                 contract_addr: str) -> Optional[dict]:
        """Return any OPEN channel between these two parties in this contract."""
        if self._pgx_enabled:
            try:
                row = self._pg_fetchrow(
                    """SELECT * FROM state_channels
                       WHERE opener=$1 AND counterparty=$2
                         AND contract_addr=$3 AND status='OPEN'
                       LIMIT 1""",
                    opener, counterparty, contract_addr)
                return dict(row) if row else None
            except Exception as exc:
                log.warning("get_open_channel_between (pgx) failed: %s", exc)
                return None
        try:
            c = self._conn()
            row = c.execute(
                """SELECT * FROM state_channels
                   WHERE opener=? AND counterparty=?
                     AND contract_addr=? AND status='OPEN'
                   LIMIT 1""",
                (opener, counterparty, contract_addr)).fetchone()
            return dict(row) if row else None
        except Exception as exc:
            log.warning("get_open_channel_between failed: %s", exc)
            return None

    # FIX-2 HELPERS ──────────────────────────────────────────────────────────

    def count_contracts_by_code_hash(self, code_hash: str) -> int:
        """Return the number of LIVE (non-destroyed) contracts sharing code_hash.

        Used by _rollback_block to decide whether the code row can be safely
        deleted after destroying a rolled-back contract: if the count is 0,
        no other contract references the bytecode and it is safe to remove.
        """
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT COUNT(*) AS n FROM contract_accounts "
                "WHERE code_hash=$1 AND destroyed=FALSE",
                code_hash)
            return int(row["n"]) if row else 0
        row = self._conn().execute(
            "SELECT COUNT(*) AS n FROM contract_accounts "
            "WHERE code_hash=? AND destroyed=0",
            (code_hash,)).fetchone()
        return int(row["n"]) if row else 0

    def delete_contract_code(self, code_hash: str):
        """Permanently remove a bytecode row from contract_code.

        Only called from _rollback_block after confirming no live contracts
        still reference this code_hash.  Safe to call even if the row is
        already absent (idempotent).
        """
        if self._pgx_enabled:
            # RocksDB holds the code in pgx mode — no separate SQL table.
            try:
                batch = self._rocks.new_batch()
                self._rocks.del_contract_code(batch, code_hash)
                self._rocks.commit(batch, sync=True)
            except Exception as _e:
                log.debug("delete_contract_code (rocks) %s: %s", code_hash[:16], _e)
            return
        try:
            self._conn().execute(
                "DELETE FROM contract_code WHERE code_hash=?", (code_hash,))
            self._conn().commit()
        except Exception as _e:
            log.debug("delete_contract_code (sqlite) %s: %s", code_hash[:16], _e)

    def get_contract_code(self, code_hash: str) -> Optional[bytes]:
        if self._pgx_enabled:
            return self._rocks.get_contract_code(code_hash)
        row = self._conn().execute(
            "SELECT bytecode FROM contract_code WHERE code_hash=?",
            (code_hash,)).fetchone()
        if not row: return None
        try: return bytes.fromhex(row["bytecode"])
        except ValueError: return None

    def save_contract_code(self, code_hash: str, bytecode: bytes):
        if self._pgx_enabled:
            existing = self._rocks.get_contract_code(code_hash)
            if existing is None:
                batch = self._rocks.new_batch()
                self._rocks.put_contract_code(batch, code_hash, bytecode)
                self._rocks.commit(batch, sync=True)
            return
        self._conn().execute(
            "INSERT OR IGNORE INTO contract_code (code_hash, bytecode) VALUES (?,?)",
            (code_hash, bytecode.hex()))
        self._conn().commit()

    def sload(self, contract_addr: str, slot_key: str) -> int:
        if self._pgx_enabled:
            v = self._rocks.get_cstorage(contract_addr, slot_key)
            if not v:
                return 0
            try: return int(v.decode("ascii"), 16)
            except Exception: return 0
        row = self._conn().execute(
            "SELECT slot_value FROM contract_storage "
            "WHERE contract_addr=? AND slot_key=?",
            (contract_addr, slot_key)).fetchone()
        if not row: return 0
        try: return int(row["slot_value"], 16)
        except (ValueError, TypeError): return 0

    def get_storage_tag(self, contract_addr: str, slot_key: str) -> int:
        """Return the persisted type tag for a contract slot (0 = untyped)."""
        if self._pgx_enabled:
            try:
                return int(self._rocks.get_cstorage_tag(contract_addr, slot_key) or 0) & 0x07
            except Exception:
                return 0
        row = self._conn().execute(
            "SELECT type_tag FROM contract_storage_tags WHERE contract_addr=? AND slot_key=?",
            (contract_addr, slot_key)).fetchone()
        return int(row['type_tag']) & 0x07 if row else 0

    def set_storage_tag(self, contract_addr: str, slot_key: str, type_tag: int) -> None:
        """Persist a slot type tag; tag 0 removes the explicit metadata row."""
        tag = int(type_tag) & 0x07
        if tag == 0:
            return self.delete_storage_tag(contract_addr, slot_key)
        if self._pgx_enabled:
            batch = self._rocks.new_batch()
            self._rocks.put_cstorage_tag(batch, contract_addr, slot_key, tag)
            self._rocks.commit(batch, sync=False)
            return
        c = self._conn()
        c.execute(
            "INSERT OR REPLACE INTO contract_storage_tags (contract_addr,slot_key,type_tag) VALUES (?,?,?)",
            (contract_addr, slot_key, tag))
        c.commit()

    def delete_storage_tag(self, contract_addr: str, slot_key: str) -> None:
        if self._pgx_enabled:
            batch = self._rocks.new_batch()
            self._rocks.del_cstorage_tag(batch, contract_addr, slot_key)
            self._rocks.commit(batch, sync=False)
            return
        self._conn().execute(
            "DELETE FROM contract_storage_tags WHERE contract_addr=? AND slot_key=?",
            (contract_addr, slot_key))
        self._conn().commit()

    def get_all_contract_storage_tags(self, contract_addr: str) -> dict:
        if self._pgx_enabled:
            return {k: int(v) for k, v in self._rocks.iter_cstorage_tags(contract_addr)}
        rows = self._conn().execute(
            "SELECT slot_key, type_tag FROM contract_storage_tags WHERE contract_addr=?",
            (contract_addr,)).fetchall()
        return {str(r['slot_key']): int(r['type_tag']) for r in rows}

    def restore_contract_storage_tags(self, contract_addr: str, snapshot: dict) -> None:
        if self._pgx_enabled:
            batch = self._rocks.new_batch()
            for slot, _ in self._rocks.iter_cstorage_tags(contract_addr):
                self._rocks.del_cstorage_tag(batch, contract_addr, slot)
            for slot, tag in snapshot.items():
                tag_i = int(tag) & 0x07
                if 1 <= tag_i <= 7:
                    self._rocks.put_cstorage_tag(batch, contract_addr, str(slot), tag_i)
            self._rocks.commit(batch, sync=True)
            self.update_contract_storage_root(contract_addr)
            return
        c = self._conn()
        c.execute("DELETE FROM contract_storage_tags WHERE contract_addr=?", (contract_addr,))
        for slot, tag in snapshot.items():
            tag_i = int(tag) & 0x07
            if 1 <= tag_i <= 7:
                c.execute(
                    "INSERT INTO contract_storage_tags (contract_addr,slot_key,type_tag) VALUES (?,?,?)",
                    (contract_addr, str(slot), tag_i))
        c.commit()
        self.update_contract_storage_root(contract_addr)

    def sstore(self, contract_addr: str, slot_key: str, value: int):
        if self._pgx_enabled:
            batch = self._rocks.new_batch()
            if value == 0:
                self._rocks.del_cstorage(batch, contract_addr, slot_key)
            else:
                hex_val = hex(value & ((1 << 256) - 1))
                self._rocks.put_cstorage(batch, contract_addr, slot_key,
                                         hex_val.encode("ascii"))
            self._rocks.commit(batch, sync=False)
            return
        c = self._conn()
        if value == 0:
            c.execute(
                "DELETE FROM contract_storage "
                "WHERE contract_addr=? AND slot_key=?",
                (contract_addr, slot_key))
        else:
            hex_val = hex(value & ((1 << 256) - 1))
            c.execute(
                """INSERT OR REPLACE INTO contract_storage
                       (contract_addr, slot_key, slot_value)
                   VALUES (?,?,?)""",
                (contract_addr, slot_key, hex_val))
        c.commit()

    def sload_prev(self, contract_addr: str, slot_key: str) -> int:
        return self.sload(contract_addr, slot_key)

    def get_all_contract_slots(self, contract_addr: str) -> dict:
        if self._pgx_enabled:
            return {k: (v.decode("ascii") if v else "0")
                    for k, v in self._rocks.iter_cstorage(contract_addr)}
        rows = self._conn().execute(
            "SELECT slot_key, slot_value FROM contract_storage "
            "WHERE contract_addr=?", (contract_addr,)).fetchall()
        return {r["slot_key"]: r["slot_value"] for r in rows}

    def restore_contract_slots(self, contract_addr: str, snapshot: dict):
        if self._pgx_enabled:
            # Delete existing + restore snapshot in one batch.
            cur = self._rocks.iter_cstorage(contract_addr)
            batch = self._rocks.new_batch()
            for slot, _ in cur:
                self._rocks.del_cstorage(batch, contract_addr, slot)
            for k, v in snapshot.items():
                self._rocks.put_cstorage(batch, contract_addr, k,
                                         str(v).encode("ascii"))
            self._rocks.commit(batch, sync=True)
            self.update_contract_storage_root(contract_addr)
            return
        c = self._conn()
        c.execute("DELETE FROM contract_storage WHERE contract_addr=?",
                  (contract_addr,))
        for k, v in snapshot.items():
            c.execute(
                """INSERT INTO contract_storage (contract_addr,slot_key,slot_value)
                   VALUES (?,?,?)""",
                (contract_addr, k, v))
        c.commit()
        self.update_contract_storage_root(contract_addr)

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  VVM RECEIPTS                                                          ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def save_vvm_receipt(self, tx_id: str, block_idx: int, contract_addr: str,
                          gas_used: int, gas_limit: int, success: bool,
                          return_data: bytes, revert_reason: str,
                          logs: list, storage_delta: dict):
        if self._pgx_enabled:
            self._pg_exec(
                """INSERT INTO vvm_receipts
                       (tx_id, block_idx, contract_addr, gas_used, gas_limit,
                        success, return_data, revert_reason, logs, storage_delta)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                   ON CONFLICT (tx_id) DO UPDATE SET
                       block_idx=EXCLUDED.block_idx,
                       contract_addr=EXCLUDED.contract_addr,
                       gas_used=EXCLUDED.gas_used,
                       gas_limit=EXCLUDED.gas_limit,
                       success=EXCLUDED.success,
                       return_data=EXCLUDED.return_data,
                       revert_reason=EXCLUDED.revert_reason,
                       logs=EXCLUDED.logs,
                       storage_delta=EXCLUDED.storage_delta""",
                tx_id, int(block_idx), contract_addr, int(gas_used),
                int(gas_limit), bool(success), return_data.hex(),
                revert_reason, json.dumps(logs), json.dumps(storage_delta))
            return
        c = self._conn()
        c.execute(
            """INSERT OR REPLACE INTO vvm_receipts
                   (tx_id, block_idx, contract_addr, gas_used, gas_limit,
                    success, return_data, revert_reason, logs, storage_delta)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (tx_id, block_idx, contract_addr, gas_used, gas_limit,
             1 if success else 0, return_data.hex(),
             revert_reason, json.dumps(logs), json.dumps(storage_delta)))
        c.commit()
        self._maybe_checkpoint()

    def delete_vvm_receipts_for_block(self, block_idx: int) -> None:
        """Delete VVM receipts belonging to an orphaned canonical block."""
        if self._pgx_enabled:
            # vvm_receipts is canonical PGX data.  The auxiliary SQLite store is
            # intentionally a reduced shadow schema and does not own receipts.
            self._pg_exec(
                "DELETE FROM vvm_receipts WHERE block_idx=$1", int(block_idx))
            return
        c = self._conn()
        c.execute("DELETE FROM vvm_receipts WHERE block_idx=?", (int(block_idx),))
        c.commit()
        self._maybe_checkpoint()

    def get_vvm_receipt(self, tx_id: str) -> Optional[dict]:
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT * FROM vvm_receipts WHERE tx_id=$1", tx_id)
            if not row: return None
            d = dict(row)
            d["return_data"] = bytes.fromhex(d["return_data"]) if d["return_data"] else b""
            try: d["logs"] = json.loads(d["logs"])
            except Exception: d["logs"] = []
            try: d["storage_delta"] = json.loads(d["storage_delta"])
            except Exception: d["storage_delta"] = {}
            d["success"] = bool(d["success"])
            return d
        row = self._conn().execute(
            "SELECT * FROM vvm_receipts WHERE tx_id=?", (tx_id,)).fetchone()
        if not row: return None
        d = dict(row)
        d["return_data"] = bytes.fromhex(d["return_data"]) if d["return_data"] else b""
        d["logs"]          = json.loads(d["logs"])
        d["storage_delta"] = json.loads(d["storage_delta"])
        d["success"]       = bool(d["success"])
        return d

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  NODE META  (key-value; mirrored to aux-SQLite for external readers)   ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def get_meta(self, key: str, default=None):
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                "SELECT value FROM node_meta WHERE key=$1", key)
            return row["value"] if row else default
        row = self._conn().execute(
            "SELECT value FROM node_meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def get_cumulative_issued_sat(self) -> int:
        """
        AUDIT-FIX-16 (dead conservation check): running total of NEW coinbase
        issuance only (block subsidies) — deliberately excludes fee
        redistribution, which moves already-existing balance between
        addresses rather than creating supply. Backed by the meta
        key-value store, incremented once per block from
        Blockchain._distribute_rewards() at the point base_reward_sat is
        computed. Replaces the previous conservation check's reliance on
        `burns`/`issuance` tables that were never created on either
        backend (see the removed conservation_check()/assert_conservation()
        bodies for what this replaces).
        """
        v = self.get_meta("cumulative_issued_sat", "0")
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    def increment_cumulative_issued_sat(self, amount_sat: int) -> None:
        """AUDIT-FIX-16: add amount_sat (must be new issuance, not a
        transfer) to the running cumulative-issuance counter."""
        if amount_sat == 0:
            return
        self.set_meta("cumulative_issued_sat",
                      str(self.get_cumulative_issued_sat() + int(amount_sat)))

    def set_meta_batch(self, values: Dict[str, str]):
        """Atomically upsert a group of node metadata values.

        L2 persistence depends on the tree, checkpoint history, and batch id
        describing one coherent state.  A single transaction prevents a crash
        from leaving a mixed-version trio.
        """
        if not values:
            return
        if self._pgx_enabled:
            active = self._pgx_active_conn()
            async def _write(c):
                for key, value in values.items():
                    await c.execute(
                        """INSERT INTO node_meta (key, value) VALUES ($1, $2)
                           ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value""",
                        key, str(value))
            if active is not None:
                self._pg.run(_write(active))
            else:
                async def _tx():
                    async with self._pg._pool.acquire() as c:
                        async with c.transaction():
                            await _write(c)
                self._pg.run(_tx())

            def _mirror_batch():
                try:
                    with self._aux_lock:
                        c = self._conn()
                        c.execute("BEGIN")
                        for key, value in values.items():
                            c.execute(
                                "INSERT OR REPLACE INTO node_meta (key,value) VALUES (?,?)",
                                (key, str(value)))
                        c.commit()
                except Exception:
                    try:
                        self._conn().rollback()
                    except Exception:
                        pass
            self._pgx_after_commit(_mirror_batch)
            return
        c = self._conn()
        # When block application already owns the SQLite transaction, this
        # method must participate in that transaction instead of issuing a
        # nested BEGIN.  The outer block transaction remains responsible for
        # commit/rollback, preserving atomicity across L1 + L2 state.
        in_atomic_block = c.atomic_active()
        try:
            if not in_atomic_block:
                c.execute("BEGIN")
            for key, value in values.items():
                c.execute(
                    "INSERT OR REPLACE INTO node_meta (key,value) VALUES (?,?)",
                    (key, str(value)))
            if not in_atomic_block:
                c.commit()
        except Exception:
            if not in_atomic_block:
                c.rollback()
            raise

    def set_meta(self, key: str, value: str):
        if self._pgx_enabled:
            self._pg_exec(
                """INSERT INTO node_meta (key, value) VALUES ($1, $2)
                   ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value""",
                key, str(value))
            def _mirror():
                try:
                    with self._aux_lock:
                        self._conn().execute(
                            "INSERT OR REPLACE INTO node_meta (key,value) VALUES (?,?)",
                            (key, str(value)))
                        self._conn().commit()
                except Exception:
                    pass
            self._pgx_after_commit(_mirror)
            return
        self._conn().execute(
            "INSERT OR REPLACE INTO node_meta (key,value) VALUES (?,?)",
            (key, value))
        self._conn().commit()

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  PRUNING                                                               ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    PRUNE_TX_HISTORY_BLOCKS   = 10_000
    PRUNE_META_SIGNAL_KEEP    = 500
    PRUNE_BATCH_SIZE          = 500

    def prune_old_data(self, current_height: int) -> dict:
        if self.PRUNE_TX_HISTORY_BLOCKS <= 0:
            return {}
        deleted = {}
        cutoff_block = max(0, current_height - self.PRUNE_TX_HISTORY_BLOCKS)
        meta_cutoff  = max(0, current_height - max(
            self.PRUNE_META_SIGNAL_KEEP, Config.FORK_SIGNAL_WINDOW * 2))
        apply_cutoff = max(0, current_height - Config.GOVERNANCE_ROLLBACK_WINDOW * 3)

        if self._pgx_enabled:
            try:
                if cutoff_block > 0:
                    r = self._pg_exec(
                        """DELETE FROM transactions
                             WHERE ctid IN (
                                 SELECT ctid FROM transactions
                                  WHERE block_idx < $1 LIMIT $2)""",
                        int(cutoff_block), int(self.PRUNE_BATCH_SIZE))
                    try: deleted["transactions"] = int(r.split()[-1])
                    except Exception: pass
                if meta_cutoff > 0:
                    r = self._pg_exec(
                        """DELETE FROM node_meta
                            WHERE key LIKE 'proto_sig:%'
                              AND (SPLIT_PART(key,':',2))::bigint < $1""",
                        int(meta_cutoff))
                    try: deleted["node_meta_signals"] = int(r.split()[-1])
                    except Exception: pass
                if apply_cutoff > 0:
                    r = self._pg_exec(
                        """DELETE FROM node_meta
                            WHERE key LIKE 'block_apply:%'
                              AND (SPLIT_PART(key,':',2))::bigint < $1""",
                        int(apply_cutoff))
                    try: deleted["node_meta_apply"] = int(r.split()[-1])
                    except Exception: pass
            except Exception as e:
                log.debug("prune: PG error %s", e)
            if deleted:
                total = sum(deleted.values())
                try: metrics.inc("pruned_rows", float(total))
                except Exception: pass
            return deleted

        # legacy sqlite
        c = self._conn()
        if cutoff_block > 0:
            rows = c.execute(
                "SELECT tx_id FROM transactions WHERE block_idx < ? LIMIT ?",
                (cutoff_block, self.PRUNE_BATCH_SIZE)).fetchall()
            if rows:
                ids = [r["tx_id"] for r in rows]
                c.executemany("DELETE FROM transactions WHERE tx_id=?",
                              [(i,) for i in ids])
                c.commit(); deleted["transactions"] = len(ids)
        if meta_cutoff > 0:
            rows = c.execute(
                "SELECT key FROM node_meta WHERE key LIKE 'proto_sig:%' LIMIT ?",
                (self.PRUNE_BATCH_SIZE,)).fetchall()
            prunable = []
            for r in rows:
                try:
                    hh = int(r["key"].split(":")[1])
                    if hh < meta_cutoff: prunable.append(r["key"])
                except (IndexError, ValueError): pass
            if prunable:
                c.executemany("DELETE FROM node_meta WHERE key=?",
                              [(k,) for k in prunable])
                c.commit(); deleted["node_meta_signals"] = len(prunable)
        if apply_cutoff > 0:
            rows = c.execute(
                "SELECT key FROM node_meta WHERE key LIKE 'block_apply:%' LIMIT ?",
                (self.PRUNE_BATCH_SIZE,)).fetchall()
            prunable_apply = []
            for r in rows:
                try:
                    hh = int(r["key"].split(":")[1])
                    if hh < apply_cutoff: prunable_apply.append(r["key"])
                except (IndexError, ValueError): pass
            if prunable_apply:
                c.executemany("DELETE FROM node_meta WHERE key=?",
                              [(k,) for k in prunable_apply])
                c.commit(); deleted["node_meta_apply"] = len(prunable_apply)
        if deleted:
            total = sum(deleted.values())
            try: metrics.inc("pruned_rows", float(total))
            except Exception: pass
        return deleted

    def get_state_size_report(self) -> dict:
        if self._pgx_enabled:
            tables = ["transactions", "accounts", "mempool", "validator_votes",
                      "upgrade_proposals", "contract_accounts",
                      "vvm_receipts", "node_meta", "peers", "identities"]
            # Whitelist guard: tbl is always from the literal list above, but
            # validate explicitly so static analysers (and future edits) stay safe.
            _ALLOWED_PG = frozenset(tables)
            result = {}
            for tbl in tables:
                if tbl not in _ALLOWED_PG:  # pragma: no cover – belt-and-suspenders
                    result[tbl] = -1
                    continue
                try:
                    row = self._pg_fetchrow(f"SELECT COUNT(*) AS n FROM {tbl}")  # nosec B608
                    result[tbl] = int(row["n"]) if row else 0
                except Exception:
                    result[tbl] = -1
            # RocksDB block count
            result["blocks"] = max(0, self._rocks.tip_height() + 1)
            return result
        c = self._conn()
        tables = ["blocks", "transactions", "balances", "roles",
                  "mempool", "validator_votes", "account_nonces",
                  "upgrade_proposals", "contract_accounts", "contract_code",
                  "contract_storage", "contract_storage_tags", "vvm_receipts", "node_meta", "peers"]
        _ALLOWED_SQLITE = frozenset(tables)
        result = {}
        for tbl in tables:
            if tbl not in _ALLOWED_SQLITE:  # pragma: no cover – belt-and-suspenders
                result[tbl] = -1
                continue
            try:
                n = c.execute(f"SELECT COUNT(*) AS n FROM {tbl}").fetchone()["n"]  # nosec B608
                result[tbl] = n
            except Exception:
                result[tbl] = -1
        return result

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  UPGRADE PROPOSALS                                                     ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def save_upgrade_proposal(self, version: int, phase: str,
                               signal_start: int, signal_end: int,
                               lock_in_height: int, activation_height: int,
                               threshold: float, rollback_window: int,
                               disabled: bool = False):
        now = int(time.time())
        if self._pgx_enabled:
            existing = self._pg_fetchrow(
                "SELECT created_at FROM upgrade_proposals WHERE version=$1",
                int(version))
            created = int(existing["created_at"]) if existing else now
            self._pg_exec(
                """INSERT INTO upgrade_proposals
                       (version, phase, signal_start_height, signal_end_height,
                        lock_in_height, activation_height, threshold,
                        rollback_window, created_at, updated_at, disabled)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                   ON CONFLICT (version) DO UPDATE SET
                       phase=EXCLUDED.phase,
                       signal_start_height=EXCLUDED.signal_start_height,
                       signal_end_height=EXCLUDED.signal_end_height,
                       lock_in_height=EXCLUDED.lock_in_height,
                       activation_height=EXCLUDED.activation_height,
                       threshold=EXCLUDED.threshold,
                       rollback_window=EXCLUDED.rollback_window,
                       updated_at=EXCLUDED.updated_at,
                       disabled=EXCLUDED.disabled""",
                int(version), phase, int(signal_start), int(signal_end),
                int(lock_in_height), int(activation_height),
                float(threshold), int(rollback_window),
                created, now, bool(disabled))
            return
        c = self._conn()
        existing = c.execute(
            "SELECT created_at FROM upgrade_proposals WHERE version=?",
            (version,)).fetchone()
        created = existing["created_at"] if existing else now
        c.execute(
            """INSERT OR REPLACE INTO upgrade_proposals
                   (version, phase, signal_start_height, signal_end_height,
                    lock_in_height, activation_height, threshold,
                    rollback_window, created_at, updated_at, disabled)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (version, phase, signal_start, signal_end,
             lock_in_height, activation_height, threshold, rollback_window,
             created, now, 1 if disabled else 0))
        c.commit()

    def get_upgrade_proposal(self, version: int) -> Optional[dict]:
        if self._pgx_enabled:
            row = self._pg_fetchrow(
                """SELECT version, phase, signal_start_height, signal_end_height,
                          lock_in_height, activation_height, threshold,
                          rollback_window, created_at, updated_at,
                          (CASE WHEN disabled THEN 1 ELSE 0 END) AS disabled
                     FROM upgrade_proposals WHERE version=$1""",
                int(version))
            return dict(row) if row else None
        row = self._conn().execute(
            "SELECT * FROM upgrade_proposals WHERE version=?",
            (version,)).fetchone()
        return dict(row) if row else None

    def get_all_upgrade_proposals(self) -> List[dict]:
        if self._pgx_enabled:
            rows = self._pg_fetch(
                """SELECT version, phase, signal_start_height, signal_end_height,
                          lock_in_height, activation_height, threshold,
                          rollback_window, created_at, updated_at,
                          (CASE WHEN disabled THEN 1 ELSE 0 END) AS disabled
                     FROM upgrade_proposals ORDER BY version""")
            return [dict(r) for r in rows]
        rows = self._conn().execute(
            "SELECT * FROM upgrade_proposals ORDER BY version").fetchall()
        return [dict(r) for r in rows]

    def get_block_invalid_rate(self, from_height: int, window: int) -> float:
        total, failed = 0, 0
        for h in range(from_height, from_height + window):
            val = self.get_meta(f"block_apply:{h}")
            if val is None: continue
            total += 1
            if val == "fail": failed += 1
        return (failed / total) if total > 0 else 0.0

    def wipe_all_balances(self):
        """Delete every balance row (hard-reset & startup-guard use this).

        In pgx mode, this truncates the Postgres ``accounts`` table AND the
        aux-SQLite shadow so that raw-SQL RPC readers see an empty set.
        Call sites formerly did ``DELETE FROM balances`` via ``_conn()``; they
        should now use this method instead.
        """
        if self._pgx_enabled:
            try: self._pg_exec("TRUNCATE TABLE accounts")
            except Exception:
                try: self._pg_exec("DELETE FROM accounts")
                except Exception: pass
        try:
            with self._aux_lock:
                self._conn().execute("DELETE FROM balances")
                self._conn().commit()
        except Exception:
            pass

    def restore_snapshot_state(self, payload: dict) -> None:
        """Replace canonical state from a verified snapshot payload.

        The snapshot engine performs authentication before calling this method.
        This method is deliberately backend-aware so PGX snapshots never write
        consensus state to the auxiliary SQLite shadow database.
        """
        if not isinstance(payload, dict):
            raise ValueError("snapshot payload must be an object")

        balances = {
            str(a): int(v) for a, v in payload.get("balances", {}).items()
            if str(a)
        }
        if any(v < 0 for v in balances.values()):
            raise ValueError("snapshot contains a negative balance")

        nonces = {
            str(a): int(v) for a, v in payload.get("nonces", {}).items()
            if str(a)
        }
        if any(v < 0 for v in nonces.values()):
            raise ValueError("snapshot contains a negative nonce")

        contracts = payload.get("contracts", {}) or {}
        roles = payload.get("roles", {}) or {}
        claims = payload.get("name_claims", {}) or {}
        channels = payload.get("state_channels", {}) or {}
        contract_code = payload.get("contract_code", {}) or {}
        contract_storage = payload.get("contract_storage", {}) or {}
        contract_storage_tags = payload.get("contract_storage_tags", {}) or {}

        # Typed-storage metadata is state belonging to an existing contract.
        # Reject orphan tag entries instead of restoring them into RocksDB: an
        # attacker-supplied snapshot must not be able to plant hidden metadata
        # at an address which may only become a contract later.
        contract_addr_set = {str(a) for a in contracts}
        for addr in contract_storage_tags:
            if str(addr) not in contract_addr_set:
                raise ValueError(f"contract_storage_tags contains unknown contract {addr}")

        normalized_code = {}
        for code_hash, code_hex in contract_code.items():
            try:
                normalized_code[str(code_hash)] = bytes.fromhex(str(code_hex))
            except ValueError as exc:
                raise ValueError(
                    f"invalid contract bytecode for {str(code_hash)[:16]}"
                ) from exc

        # Never restore a contract account whose authenticated bytecode or
        # storage commitment cannot be reconstructed from the supplied state.
        for addr, ct in contracts.items():
            code_hash = str(ct.get("code_hash", ""))
            if code_hash:
                code = normalized_code.get(code_hash)
                if code is None:
                    raise ValueError(f"missing bytecode for contract {addr}")
                if __import__("hashlib").sha256(code).hexdigest() != code_hash:
                    raise ValueError(f"bytecode hash mismatch for contract {addr}")
            slots = contract_storage.get(addr, {})
            if not isinstance(slots, dict):
                raise ValueError(f"contract_storage[{addr}] must be an object")
            tags = contract_storage_tags.get(addr, {})
            if not isinstance(tags, dict):
                raise ValueError(f"contract_storage_tags[{addr}] must be an object")
            for _slot, _tag in tags.items():
                if not 1 <= int(_tag) <= 7:
                    raise ValueError(f"invalid storage type tag for {addr}:{_slot}")
            stored_root = str(ct.get("storage_root", ""))
            if stored_root:
                values = {str(k): str(v) for k, v in slots.items()}
                tag_map = {str(k): int(v) for k, v in tags.items()}
                ordered_keys = sorted(set(values) | set(tag_map), key=lambda x: x.encode("utf-8"))
                if not ordered_keys:
                    material = b"empty_storage"
                elif tag_map:
                    material = "\n".join(
                        f"{k}:{values.get(k, '0')}:{int(tag_map.get(k, 0))}"
                        for k in ordered_keys
                    ).encode("utf-8")
                else:
                    material = "\n".join(
                        f"{k}:{values.get(k, '0')}" for k in ordered_keys
                    ).encode("utf-8")
                computed_root = __import__("hashlib").sha256(material).hexdigest()
                if computed_root != stored_root:
                    raise ValueError(f"storage root mismatch for contract {addr}")

        if self._pgx_enabled:
            # Snapshot of all canonical SQL state is committed atomically in
            # PostgreSQL.  RocksDB stores contract bytecode/storage; its write
            # batch is prepared and committed immediately before the SQL
            # transaction.  The operation is idempotent, and a node never
            # reports snapshot success unless both stores completed.
            batch = self._rocks.new_batch()
            self._rocks.clear_all_contract_storage(batch)
            for code_hash, bytecode in normalized_code.items():
                self._rocks.put_contract_code(batch, code_hash, bytecode)
            for addr, slots in contract_storage.items():
                if not isinstance(slots, dict):
                    raise ValueError(f"contract_storage[{addr}] must be an object")
                for slot, value in slots.items():
                    self._rocks.put_cstorage(
                        batch, str(addr), str(slot), str(value).encode("ascii"))
            for addr, tags in contract_storage_tags.items():
                if not isinstance(tags, dict):
                    raise ValueError(f"contract_storage_tags[{addr}] must be an object")
                for slot, tag in tags.items():
                    self._rocks.put_cstorage_tag(batch, str(addr), str(slot), int(tag))
            self._rocks.commit(batch, sync=True)

            async def _restore_pg():
                async with self._pg._pool.acquire() as c:
                    async with c.transaction():
                        await c.execute("DELETE FROM accounts")
                        await c.execute("DELETE FROM validators")
                        await c.execute("DELETE FROM contract_accounts")
                        await c.execute("DELETE FROM name_claims")
                        await c.execute("DELETE FROM state_channels")

                        if balances:
                            await c.executemany(
                                "INSERT INTO accounts "
                                "(address,balance_sat) VALUES ($1,$2)",
                                [(a, v) for a, v in balances.items()])
                        if nonces:
                            await c.executemany(
                                "INSERT INTO accounts (address,nonce) "
                                "VALUES ($1,$2) "
                                "ON CONFLICT (address) DO UPDATE "
                                "SET nonce=EXCLUDED.nonce",
                                [(a, n) for a, n in nonces.items()])
                        if contracts:
                            await c.executemany(
                                "INSERT INTO contract_accounts "
                                "(address,code_hash,storage_root,nonce,creator,"
                                "created_at,destroyed,contract_name) "
                                "VALUES ($1,$2,$3,$4,$5,$6,FALSE,$7)",
                                [(
                                    str(a), ct.get("code_hash", ""),
                                    ct.get("storage_root", ""), int(ct.get("nonce", 0)),
                                    ct.get("creator", ""), int(ct.get("created_at", 0)),
                                    ct.get("name", ""),
                                ) for a, ct in contracts.items()])
                        if roles:
                            await c.executemany(
                                "INSERT INTO validators "
                                "(address,role,stake_sat,score,slashed,registered_at) "
                                "VALUES ($1,$2,$3,$4,$5,$6)",
                                [(
                                    str(a), r.get("role", ""),
                                    int(r.get("stake_sat", 0)),
                                    float(r.get("score", 1.0)),
                                    bool(int(r.get("slashed", 0))),
                                    int(r.get("registered_at", 0)),
                                ) for a, r in roles.items()])
                        if claims:
                            await c.executemany(
                                "INSERT INTO name_claims "
                                "(user_id,wallet_addr,pub_hex,registered_height,tx_id) "
                                "VALUES ($1,$2,$3,$4,$5)",
                                [(
                                    str(name), claim.get("wallet_addr", ""),
                                    claim.get("pub_hex", ""),
                                    int(claim.get("registered_height", 0)),
                                    claim.get("tx_id", ""),
                                ) for name, claim in claims.items()])
                        if channels:
                            await c.executemany(
                                "INSERT INTO state_channels "
                                "(channel_id,contract_addr,opener,counterparty,"
                                "total_deposit_sat,opener_deposit_sat,timeout_blocks,"
                                "open_height,status,dispute_seq,dispute_bal_opener,"
                                "dispute_bal_counter,dispute_height,closed_height) "
                                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
                                [(
                                    str(cid), str(ch.get("contract_addr", "")),
                                    str(ch.get("opener", "")), str(ch.get("counterparty", "")),
                                    int(ch.get("total_deposit_sat", 0)),
                                    int(ch.get("opener_deposit_sat", 0)),
                                    int(ch.get("timeout_blocks", 100)),
                                    int(ch.get("open_height", 0)),
                                    str(ch.get("status", "OPEN")),
                                    int(ch.get("dispute_seq", 0)),
                                    int(ch.get("dispute_bal_opener", 0)),
                                    int(ch.get("dispute_bal_counter", 0)),
                                    int(ch.get("dispute_height", 0)),
                                    int(ch.get("closed_height", 0)),
                                ) for cid, ch in channels.items()])
            self._pg.run(_restore_pg())

            # Refresh non-authoritative Redis balance cache after the canonical
            # account table was replaced.
            try:
                self._cache.clear_balance_cache()
                for address, sat in balances.items():
                    self._cache.cache_balance(address, sat)
            except Exception:
                pass
            return

        # Legacy SQLite: one transaction covers the complete state replacement.
        c = self._conn()
        with self._sqlite_api_lock:
            c.execute("BEGIN")
            try:
                for table in (
                    "balances", "account_nonces", "contract_accounts", "roles",
                    "name_claims", "state_channels", "contract_storage", "contract_storage_tags",
                ):
                    c.execute(f"DELETE FROM {table}")

                c.executemany(
                    "INSERT INTO balances (address,balance) VALUES (?,?)",
                    list(balances.items()))
                c.executemany(
                    "INSERT INTO account_nonces (address,nonce) VALUES (?,?)",
                    list(nonces.items()))
                c.executemany(
                    "INSERT INTO contract_accounts "
                    "(address,code_hash,storage_root,nonce,creator,created_at,"
                    "contract_name,destroyed) VALUES (?,?,?,?,?,?,?,0)",
                    [(
                        str(a), ct.get("code_hash", ""),
                        ct.get("storage_root", ""), int(ct.get("nonce", 0)),
                        ct.get("creator", ""), int(ct.get("created_at", 0)),
                        ct.get("name", ""),
                    ) for a, ct in contracts.items()])
                c.executemany(
                    "INSERT INTO roles "
                    "(address,role,stake,score,slashed,registered_at) "
                    "VALUES (?,?,?,?,?,?)",
                    [(
                        str(a), r.get("role", ""),
                        float(int(r.get("stake_sat", 0))) / Config.SATOSHI_PER_VSD,
                        float(r.get("score", 1.0)),
                        int(r.get("slashed", 0)),
                        int(r.get("registered_at", 0)),
                    ) for a, r in roles.items()])
                c.executemany(
                    "INSERT INTO name_claims "
                    "(user_id,wallet_addr,pub_hex,registered_height,tx_id) "
                    "VALUES (?,?,?,?,?)",
                    [(
                        str(name), claim.get("wallet_addr", ""),
                        claim.get("pub_hex", ""),
                        int(claim.get("registered_height", 0)),
                        claim.get("tx_id", ""),
                    ) for name, claim in claims.items()])
                c.executemany(
                    "INSERT INTO state_channels "
                    "(channel_id,contract_addr,opener,counterparty,total_deposit_sat,"
                    "opener_deposit_sat,timeout_blocks,open_height,status,dispute_seq,"
                    "dispute_bal_opener,dispute_bal_counter,dispute_height,closed_height) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [(
                        str(cid), str(ch.get("contract_addr", "")),
                        str(ch.get("opener", "")), str(ch.get("counterparty", "")),
                        int(ch.get("total_deposit_sat", 0)),
                        int(ch.get("opener_deposit_sat", 0)),
                        int(ch.get("timeout_blocks", 100)),
                        int(ch.get("open_height", 0)),
                        str(ch.get("status", "OPEN")),
                        int(ch.get("dispute_seq", 0)),
                        int(ch.get("dispute_bal_opener", 0)),
                        int(ch.get("dispute_bal_counter", 0)),
                        int(ch.get("dispute_height", 0)),
                        int(ch.get("closed_height", 0)),
                    ) for cid, ch in channels.items()])

                c.execute("DELETE FROM contract_code")
                c.executemany(
                    "INSERT INTO contract_code (code_hash,bytecode) VALUES (?,?)",
                    [(h, b.hex()) for h, b in normalized_code.items()])
                c.executemany(
                    "INSERT INTO contract_storage (contract_addr,slot_key,slot_value) "
                    "VALUES (?,?,?)",
                    [
                        (str(addr), str(slot), str(value))
                        for addr, slots in contract_storage.items()
                        for slot, value in (slots.items() if isinstance(slots, dict) else [])
                    ])
                c.executemany(
                    "INSERT INTO contract_storage_tags (contract_addr,slot_key,type_tag) "
                    "VALUES (?,?,?)",
                    [
                        (str(addr), str(slot), int(tag))
                        for addr, tags in contract_storage_tags.items()
                        for slot, tag in (tags.items() if isinstance(tags, dict) else [])
                    ])
                c.commit()
            except Exception:
                c.rollback()
                raise

    def record_block_apply_result(self, height: int, success: bool):
        self.set_meta(f"block_apply:{height}", "ok" if success else "fail")

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  ATOMIC BLOCK APPLICATION — snapshot / restore                         ║
    # ║                                                                        ║
    # ║  ``apply_block`` mutates state row-by-row (debit sender, credit        ║
    # ║  receiver, update nonce, distribute rewards...). If ANY step fails     ║
    # ║  halfway through, the block is rejected by the caller but the         ║
    # ║  mutations already performed are permanent — corrupting state.        ║
    # ║                                                                        ║
    # ║  These two primitives let the state engine wrap a block's full        ║
    # ║  application in a checkpoint:                                         ║
    # ║                                                                        ║
    # ║      snap = storage.snapshot_accounts(addresses)                      ║
    # ║      try:                                                             ║
    # ║          ... mutate balances / nonces ...                             ║
    # ║      except Exception:                                                ║
    # ║          storage.restore_accounts(snap)                               ║
    # ║                                                                        ║
    # ║  Only addresses touched by the block need snapshotting, keeping the   ║
    # ║  snapshot small (typically < 100 rows for a normal block).            ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def snapshot_accounts(self, addresses: Iterable[str]) -> dict:
        """Capture (balance_sat, nonce, ht_volume_sat) for each address.
        Returns a dict[address] -> (balance_sat, nonce, ht_volume_sat, existed).
        """
        addrs = list(set(a for a in addresses if a))
        snap: dict = {}
        if not addrs:
            return snap
        if self._pgx_enabled:
            rows = self._pg_fetch(
                """SELECT address, balance_sat, nonce, ht_volume_sat
                     FROM accounts WHERE address = ANY($1::text[])""",
                addrs)
            found = {r["address"]: r for r in rows}
            for a in addrs:
                if a in found:
                    r = found[a]
                    snap[a] = (int(r["balance_sat"]), int(r["nonce"]),
                               int(r["ht_volume_sat"]), True)
                else:
                    snap[a] = (0, 0, 0, False)
            return snap
        c = self._conn()
        for a in addrs:
            b = c.execute("SELECT balance FROM balances WHERE address=?",
                          (a,)).fetchone()
            n = c.execute("SELECT nonce FROM account_nonces WHERE address=?",
                          (a,)).fetchone()
            v = c.execute("SELECT volume FROM ht_volume WHERE address=?",
                          (a,)).fetchone()
            snap[a] = (int(b["balance"]) if b else 0,
                       int(n["nonce"])   if n else 0,
                       int(v["volume"])  if v else 0,
                       b is not None)
        return snap

    def restore_accounts(self, snap: dict) -> None:
        """Restore accounts to a captured snapshot (atomic per-backend)."""
        if not snap:
            return
        if self._pgx_enabled:
            rows = [(addr, bal, nonce, vol, existed)
                    for addr, (bal, nonce, vol, existed) in snap.items()]

            async def _write(c):
                for addr, bal, nonce, vol, existed in rows:
                    if existed:
                        await c.execute(
                            """UPDATE accounts SET
                                   balance_sat   = $2,
                                   nonce         = $3,
                                   ht_volume_sat = $4,
                                   updated_at    = now()
                                WHERE address = $1""",
                            addr, bal, nonce, vol)
                    else:
                        await c.execute(
                            "DELETE FROM accounts WHERE address=$1", addr)

            active = self._pgx_active_conn()
            try:
                if active is not None:
                    self._pg.run(_write(active))
                else:
                    async def _do():
                        async with self._pg._pool.acquire() as c:
                            async with c.transaction():
                                await _write(c)
                    self._pg.run(_do())
            except Exception as e:
                log.error("restore_accounts PG failed: %s", e)

            # Invalidate local cache immediately; shadow writes are deferred
            # until a surrounding block transaction commits.
            for addr in snap.keys():
                self._cache.invalidate_balance(addr)
                if snap[addr][3]:
                    self._pgx_after_commit(
                        self._mirror_balance_to_aux, addr, snap[addr][0])
                else:
                    def _delete_shadow(a=addr):
                        try:
                            with self._aux_lock:
                                self._conn().execute(
                                    "DELETE FROM balances WHERE address=?", (a,))
                                self._conn().commit()
                        except Exception:
                            pass
                    self._pgx_after_commit(_delete_shadow)
            return
        c = self._conn()
        for addr, (bal, nonce, vol, existed) in snap.items():
            if existed:
                c.execute(
                    "INSERT OR REPLACE INTO balances (address, balance) VALUES (?,?)",
                    (addr, bal))
                c.execute(
                    "INSERT OR REPLACE INTO account_nonces (address, nonce) VALUES (?,?)",
                    (addr, nonce))
                c.execute(
                    """INSERT OR REPLACE INTO ht_volume (address, volume, updated)
                       VALUES (?,?,?)""",
                    (addr, vol, int(time.time())))
            else:
                c.execute("DELETE FROM balances      WHERE address=?", (addr,))
                c.execute("DELETE FROM account_nonces WHERE address=?", (addr,))
                c.execute("DELETE FROM ht_volume     WHERE address=?", (addr,))
        c.commit()

    # ╔════════════════════════════════════════════════════════════════════════╗
    # ║  ROLE SNAPSHOT / RESTORE (v7.2.0)                                      ║
    # ║  Mirrors snapshot_accounts for the roles / validators table so that    ║
    # ║  apply_block can roll back on-chain REGISTER transactions along with   ║
    # ║  balance mutations when a block fails mid-application.                 ║
    # ╚════════════════════════════════════════════════════════════════════════╝
    def snapshot_roles(self, addresses) -> dict:
        """Capture the exact pre-block role state for each address.

        ``registered_at`` is included because it is consensus-visible metadata
        and must not be replaced with the rollback wall-clock time.
        """
        addrs = list(set(a for a in addresses if a))
        snap: dict = {}
        if not addrs:
            return snap
        if self._pgx_enabled:
            rows = self._pg_fetch(
                """SELECT address, role, stake_sat, score,
                          (CASE WHEN slashed THEN 1 ELSE 0 END) AS slashed,
                          registered_at
                     FROM validators WHERE address = ANY($1::text[])""",
                addrs)
            found = {r["address"]: r for r in rows}
            for a in addrs:
                if a in found:
                    r = found[a]
                    snap[a] = (r["role"], int(r["stake_sat"]),
                               float(r["score"]), int(r["slashed"]),
                               int(r["registered_at"] or 0), True)
                else:
                    snap[a] = (None, 0, 1.0, 0, 0, False)
            return snap
        c = self._conn()
        for a in addrs:
            r = c.execute("SELECT role, stake, score, slashed, registered_at FROM roles "
                          "WHERE address=?", (a,)).fetchone()
            if r:
                snap[a] = (r["role"], to_satoshi(float(r["stake"])),
                           float(r["score"]), int(r["slashed"]),
                           int(r["registered_at"] or 0), True)
            else:
                snap[a] = (None, 0, 1.0, 0, 0, False)
        return snap

    def restore_roles(self, snap: dict) -> None:
        """Restore the roles table to the captured snapshot."""
        if not snap:
            return
        if self._pgx_enabled:
            async def _write(c):
                for addr, item in snap.items():
                    role, stake_sat, score, slashed, registered_at, existed = item
                    if existed:
                        await c.execute(
                            """INSERT INTO validators
                                   (address, role, stake_sat, score, slashed, registered_at)
                               VALUES ($1,$2,$3,$4,$5,$6)
                               ON CONFLICT (address) DO UPDATE SET
                                   role=EXCLUDED.role,
                                   stake_sat=EXCLUDED.stake_sat,
                                   score=EXCLUDED.score,
                                   slashed=EXCLUDED.slashed,
                                   registered_at=EXCLUDED.registered_at""",
                            addr, role, int(stake_sat), float(score),
                            bool(slashed), int(registered_at))
                    else:
                        await c.execute(
                            "DELETE FROM validators WHERE address=$1", addr)
            try:
                active = self._pgx_active_conn()
                if active is not None:
                    self._pg.run(_write(active))
                else:
                    async def _do():
                        async with self._pg._pool.acquire() as c:
                            async with c.transaction():
                                await _write(c)
                    self._pg.run(_do())
            except Exception as e:
                log.error("restore_roles PG failed: %s", e)
            return
        c = self._conn()
        for addr, item in snap.items():
            if len(item) == 6:
                role, stake_sat, score, slashed, registered_at, existed = item
            else:
                role, stake_sat, score, slashed, existed = item
                registered_at = 0
            if existed:
                c.execute(
                    """INSERT OR REPLACE INTO roles
                           (address, role, stake, score, slashed, registered_at)
                       VALUES (?,?,?,?,?,?)""",
                    (addr, role, from_satoshi(int(stake_sat)),
                     float(score), int(slashed), int(registered_at)))
            else:
                c.execute("DELETE FROM roles WHERE address=?", (addr,))
        c.commit()

    # ── durable per-block REGISTER undo snapshots ───────────────────────────
    def record_block_role_snapshot(self, height: int, block_hash: str,
                                   snap: dict) -> None:
        """Persist the exact role pre-state needed to undo a block.

        This is intentionally stored in ``node_meta`` so it is covered by the
        same SQLite transaction as the block and state mutations.  In PGX the
        metadata is committed independently, which is acceptable because the
        snapshot is only an undo record and is never used to advance state.
        """
        payload = {
            "block_hash": str(block_hash),
            "roles": {
                str(addr): {
                    "role": item[0],
                    "stake_sat": int(item[1]),
                    "score": float(item[2]),
                    "slashed": int(item[3]),
                    "registered_at": int(item[4]) if len(item) == 6 else 0,
                    "existed": bool(item[5] if len(item) == 6 else item[4]),
                }
                for addr, item in snap.items()
            },
        }
        self.set_meta(f"block_role_undo:{int(height)}",
                      json.dumps(payload, sort_keys=True, separators=(",", ":")))

    def get_block_role_snapshot(self, height: int, block_hash: str) -> Optional[dict]:
        raw = self.get_meta(f"block_role_undo:{int(height)}")
        if not raw:
            return None
        try:
            payload = json.loads(raw)
            if str(payload.get("block_hash", "")) != str(block_hash):
                return None
            out = {}
            for addr, item in (payload.get("roles") or {}).items():
                out[str(addr)] = (
                    item.get("role"), int(item.get("stake_sat", 0)),
                    float(item.get("score", 1.0)), int(item.get("slashed", 0)),
                    int(item.get("registered_at", 0)),
                    bool(item.get("existed", False)),
                )
            return out
        except Exception:
            return None

    def delete_block_role_snapshot(self, height: int) -> None:
        key = f"block_role_undo:{int(height)}"
        if self._pgx_enabled:
            self._pg_exec("DELETE FROM node_meta WHERE key=$1", key)
            try:
                with self._aux_lock:
                    self._conn().execute("DELETE FROM node_meta WHERE key=?", (key,))
                    self._conn().commit()
            except Exception:
                pass
            return
        self._conn().execute("DELETE FROM node_meta WHERE key=?", (key,))
        self._conn().commit()
