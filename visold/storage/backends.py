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
"""visold.storage.backends


Origin: visold_vsd_.py L2926-2951, L2954-3147, L3150-3262, L3265-3310, L3313-3364
"""

import os
import struct
import threading
import asyncio as _asyncio
from typing import List, Optional

try:  # optional dependency: name may be undefined, exactly as in the monolith
    from visold.kernel.compat import _asyncpg
except ImportError:
    pass

try:  # optional dependency: name may be undefined, exactly as in the monolith
    from visold.kernel.compat import _msgpack
except ImportError:
    pass

try:  # optional dependency: name may be undefined, exactly as in the monolith
    from visold.kernel.compat import _redis
except ImportError:
    pass

try:  # optional dependency: name may be undefined, exactly as in the monolith
    from visold.kernel.compat import _rocksdb, _rocksdict
except ImportError:
    _rocksdb = None
    _rocksdict = None


# ── RocksDB key schema (big-endian numerics → prefix-scan in chain order) ──
_P_BLOCK     = b"b:"


_P_HEADER    = b"h:"


_P_BLOCKHASH = b"bh:"


_P_TX        = b"t:"


_P_STATE     = b"s:"


_P_MERKLE    = b"m:"


_P_CSTORAGE  = b"k:"
_P_CSTOR_TAG = b"kt:"


_P_CCODE     = b"c:"


_P_META      = b"M:"


_CF_DEFAULT  = "default"


_CF_BLOCKS   = "blocks"


_CF_STATE    = "state"


_META_CHAIN_TIP = "chain_tip"


_META_TIP_HASH  = "tip_hash"


def _u64(n: int) -> bytes: return struct.pack(">Q", n)


def _u32(n: int) -> bytes: return struct.pack(">I", n)


def _k_block(h):    return _P_BLOCK     + _u64(h)


def _k_header(h):   return _P_HEADER    + _u64(h)


def _k_blockhash(x):return _P_BLOCKHASH + x.encode("ascii")


def _k_tx(x):       return _P_TX        + x.encode("ascii")


def _k_state(a):    return _P_STATE     + a.encode("utf-8")


def _k_merkle(x):   return _P_MERKLE    + x.encode("ascii")


def _k_cstor(a,s):  return _P_CSTORAGE  + a.encode() + b":" + s.encode("ascii")
def _k_cstor_tag(a,s): return _P_CSTOR_TAG + a.encode() + b":" + s.encode("ascii")


def _k_ccode(x):    return _P_CCODE     + x.encode("ascii")


def _k_meta(n):     return _P_META      + n.encode("utf-8")


_PG_SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS accounts (
    address         TEXT        PRIMARY KEY,
    balance_sat     BIGINT      NOT NULL DEFAULT 0 CHECK (balance_sat >= 0),
    nonce           BIGINT      NOT NULL DEFAULT 0,
    ht_volume_sat   BIGINT      NOT NULL DEFAULT 0,
    updated_height  BIGINT      NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_accounts_balance   ON accounts (balance_sat DESC);
CREATE INDEX IF NOT EXISTS idx_accounts_updated_h ON accounts (updated_height);

CREATE TABLE IF NOT EXISTS transactions (
    tx_id        TEXT        PRIMARY KEY,
    block_idx    BIGINT      NOT NULL,
    tx_index     INT         NOT NULL DEFAULT 0,
    sender       TEXT        NOT NULL,
    receiver     TEXT        NOT NULL,
    amount_sat   BIGINT      NOT NULL,
    fee_sat      BIGINT      NOT NULL DEFAULT 0,
    nonce        BIGINT      NOT NULL DEFAULT 0,
    timestamp    BIGINT      NOT NULL,
    -- Persistence-only enum code. The original string tx_type is preserved
    -- verbatim inside data_json and is the consensus representation.
    tx_type      SMALLINT    NOT NULL DEFAULT 0,
    status       SMALLINT    NOT NULL DEFAULT 1,
    data_json    TEXT        NOT NULL DEFAULT '{}',
    memo         TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tx_sender    ON transactions (sender,   block_idx DESC);
CREATE INDEX IF NOT EXISTS idx_tx_receiver  ON transactions (receiver, block_idx DESC);
CREATE INDEX IF NOT EXISTS idx_tx_block_idx ON transactions (block_idx);
CREATE INDEX IF NOT EXISTS idx_tx_timestamp ON transactions (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_tx_memo_prefix ON transactions (memo text_pattern_ops)
    WHERE memo LIKE 'ORDER:%';

-- AUDIT-FIX-14b: permanent replay guard, deliberately separate from and
-- never pruned by prune_old_data() or RollingWindowPruner (both delete rows
-- from `transactions` above on their own retention windows — the shorter
-- of which defaults to 600 blocks). tx_exists() checking only `transactions`
-- made any expiry=0 transaction replayable once its row aged out; this
-- table has no retention window at all.
CREATE TABLE IF NOT EXISTS tx_replay_guard (
    tx_id TEXT PRIMARY KEY
);

CREATE UNLOGGED TABLE IF NOT EXISTS mempool (
    tx_id     TEXT   PRIMARY KEY,
    sender    TEXT   NOT NULL DEFAULT '',
    fee_sat   BIGINT NOT NULL,
    timestamp BIGINT NOT NULL,
    data_json TEXT   NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mempool_fee ON mempool (fee_sat DESC, timestamp ASC);

CREATE TABLE IF NOT EXISTS peers (
    peer_id      TEXT        PRIMARY KEY,
    ip           TEXT        NOT NULL,
    port         INT         NOT NULL CHECK (port > 0 AND port < 65536),
    last_seen    BIGINT      NOT NULL DEFAULT 0,
    reputation   DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    fail_count   INT         NOT NULL DEFAULT 0,
    blacklisted  BOOLEAN     NOT NULL DEFAULT FALSE,
    ban_score    INT         NOT NULL DEFAULT 0,
    tls_fp       TEXT        NOT NULL DEFAULT '',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_peers_last_seen  ON peers (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_peers_reputation ON peers (reputation DESC)
    WHERE blacklisted = FALSE;

CREATE TABLE IF NOT EXISTS validators (
    address       TEXT        PRIMARY KEY,
    role          TEXT        NOT NULL DEFAULT 'validator',
    stake_sat     BIGINT      NOT NULL DEFAULT 0,
    score         DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    slashed       BOOLEAN     NOT NULL DEFAULT FALSE,
    registered_at BIGINT      NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_validators_stake ON validators (stake_sat DESC)
    WHERE slashed = FALSE;

CREATE TABLE IF NOT EXISTS validator_votes (
    block_hash     TEXT        NOT NULL,
    validator_addr TEXT        NOT NULL,
    block_idx      BIGINT      NOT NULL DEFAULT 0,
    sig_hex        TEXT        NOT NULL,
    pub_hex        TEXT        NOT NULL,
    voted_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (block_hash, validator_addr)
);
CREATE INDEX IF NOT EXISTS idx_votes_block_idx ON validator_votes (block_idx);

CREATE TABLE IF NOT EXISTS identities (
    user_id     TEXT   PRIMARY KEY,
    peer_id     TEXT,
    wallet_addr TEXT,
    pub_hex     TEXT,
    multiaddrs  TEXT   NOT NULL DEFAULT '[]',
    last_seen   BIGINT NOT NULL DEFAULT 0
);

-- Canonical name ownership is populated only from confirmed blockchain blocks.
-- Network liveness and multiaddrs remain in identities and are never used for
-- ownership decisions.
CREATE TABLE IF NOT EXISTS name_claims (
    user_id          TEXT PRIMARY KEY,
    wallet_addr      TEXT NOT NULL,
    pub_hex          TEXT NOT NULL,
    registered_height BIGINT NOT NULL,
    tx_id            TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS upgrade_proposals (
    version             INT         PRIMARY KEY,
    phase               TEXT        NOT NULL DEFAULT 'DORMANT',
    signal_start_height BIGINT      NOT NULL DEFAULT 0,
    signal_end_height   BIGINT      NOT NULL DEFAULT 0,
    lock_in_height      BIGINT      NOT NULL DEFAULT 0,
    activation_height   BIGINT      NOT NULL DEFAULT 0,
    threshold           DOUBLE PRECISION NOT NULL DEFAULT 0.75,
    rollback_window     INT         NOT NULL DEFAULT 100,
    disabled            BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at          BIGINT      NOT NULL DEFAULT 0,
    updated_at          BIGINT      NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS contract_accounts (
    address      TEXT    PRIMARY KEY,
    code_hash    TEXT    NOT NULL DEFAULT '',
    storage_root TEXT    NOT NULL DEFAULT '',
    nonce        BIGINT  NOT NULL DEFAULT 0,
    creator      TEXT    NOT NULL DEFAULT '',
    created_at   BIGINT  NOT NULL DEFAULT 0,
    destroyed    BOOLEAN NOT NULL DEFAULT FALSE,
    -- SC-NAME-1: normalised name; empty string = legacy "unnamed" contract
    contract_name TEXT   NOT NULL DEFAULT ''
);

-- SC-NAME-1: Global name uniqueness index.
-- UNIQUE constraint enforces uniqueness at the DB layer as a safety net;
-- the authoritative uniqueness check is in _apply_vvm_tx() (consensus).
-- Partial index: only active (non-destroyed) contracts with a non-empty
-- name must be unique.  Two destroyed contracts can share a name (the
-- second may be re-registered after SELFDESTRUCT).
CREATE UNIQUE INDEX IF NOT EXISTS idx_contract_name_unique
    ON contract_accounts (contract_name)
    WHERE destroyed = FALSE AND contract_name != '';

CREATE TABLE IF NOT EXISTS vvm_receipts (
    tx_id         TEXT    PRIMARY KEY,
    block_idx     BIGINT  NOT NULL,
    contract_addr TEXT    NOT NULL DEFAULT '',
    gas_used      BIGINT  NOT NULL DEFAULT 0,
    gas_limit     BIGINT  NOT NULL DEFAULT 0,
    success       BOOLEAN NOT NULL DEFAULT TRUE,
    return_data   TEXT    NOT NULL DEFAULT '',
    revert_reason TEXT    NOT NULL DEFAULT '',
    logs          TEXT    NOT NULL DEFAULT '[]',
    storage_delta TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_vvm_receipts_block    ON vvm_receipts (block_idx);
CREATE INDEX IF NOT EXISTS idx_vvm_receipts_contract ON vvm_receipts (contract_addr);

-- AUDIT-FIX (Batch D, payment channel finding): state_channels was only
-- ever added to PGX-aux-sqlite and legacy-sqlite (see module changelog);
-- Postgres itself never had this table, so pgx-mode deployments had no
-- authoritative store for channel state even once the wrong-object /
-- missing self._conn() bug below is fixed. Added here to match
-- contract_accounts' pg-primary + aux-sqlite-shadow pattern.
CREATE TABLE IF NOT EXISTS state_channels (
    channel_id          TEXT    PRIMARY KEY,
    contract_addr        TEXT    NOT NULL DEFAULT '',
    opener               TEXT    NOT NULL,
    counterparty         TEXT    NOT NULL,
    total_deposit_sat    BIGINT  NOT NULL DEFAULT 0,
    opener_deposit_sat   BIGINT  NOT NULL DEFAULT 0,
    timeout_blocks       BIGINT  NOT NULL DEFAULT 100,
    open_height          BIGINT  NOT NULL DEFAULT 0,
    status               TEXT    NOT NULL DEFAULT 'OPEN',
    dispute_seq          BIGINT  NOT NULL DEFAULT 0,
    dispute_bal_opener   BIGINT  NOT NULL DEFAULT 0,
    dispute_bal_counter  BIGINT  NOT NULL DEFAULT 0,
    dispute_height       BIGINT  NOT NULL DEFAULT 0,
    closed_height        BIGINT  NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sc_opener       ON state_channels (opener);
CREATE INDEX IF NOT EXISTS idx_sc_counterparty ON state_channels (counterparty);
CREATE INDEX IF NOT EXISTS idx_sc_status       ON state_channels (status);

CREATE TABLE IF NOT EXISTS node_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class _RocksDictBatch:
    """Small adapter preserving the legacy batch.put((cf, key), value) API.

    The rest of Visold was written against python-rocksdb's tuple-form
    column-family API.  rocksdict uses WriteBatch.put(key, value, handle), so
    this wrapper translates the call shape without changing callers.
    """
    def __init__(self, module):
        self._module = module
        # The parent Rdict is opened with Options(raw_mode=True), and
        # rocksdict requires every WriteBatch consumed by that Rdict to carry
        # the same raw_mode flag.  Constructing the batch without it succeeds
        # locally but is rejected later by Rdict.write(), which means the first
        # consensus write fails at runtime.  Never silently fall back to a
        # non-raw batch: that would risk encoding the byte keys/values through
        # the wrong codec on older bindings.
        try:
            self._batch = module.WriteBatch(raw_mode=True)
        except TypeError as exc:
            raise RuntimeError(
                "PGX requires a rocksdict WriteBatch(raw_mode=True) compatible "
                "with the configured raw-mode Rdict"
            ) from exc

    def put(self, cf_key, value):
        cf, key = cf_key
        self._batch.put(key, value, cf)

    def delete(self, cf_key):
        cf, key = cf_key
        self._batch.delete(key, cf)


class _RocksBlockStore:
    """RocksDB wrapper for blocks, state, merkle, contract code/storage.

    Two Python bindings are supported:

    * legacy ``python-rocksdb`` when it is genuinely importable;
    * modern ``rocksdict`` (preferred on current Linux distributions).

    The consensus/storage API above this class is identical for both paths.
    """
    def __init__(self, path: str, cache_mb: int = 512, wbuf_mb: int = 128):
        self._write_lock = threading.RLock()
        os.makedirs(path, exist_ok=True)
        if _rocksdb is not None:
            self._impl = "python-rocksdb"
            self._init_python_rocksdb(path, cache_mb, wbuf_mb)
        elif _rocksdict is not None:
            self._impl = "rocksdict"
            self._init_rocksdict(path, cache_mb, wbuf_mb)
        else:
            raise RuntimeError(
                "PGX RocksDB backend unavailable: install rocksdict "
                "(preferred) or a compatible python-rocksdb binding"
            )

    # ── legacy python-rocksdb path ────────────────────────────────────────
    def _init_python_rocksdb(self, path: str, cache_mb: int, wbuf_mb: int):
        opts = _rocksdb.Options()
        opts.create_if_missing = True
        # Older python-rocksdb builds expose this attribute; newer builds may
        # not.  The column-family open itself below remains authoritative.
        if hasattr(opts, "create_missing_column_families"):
            opts.create_missing_column_families = True
        opts.max_open_files = 4096
        opts.write_buffer_size = wbuf_mb * 1024 * 1024
        opts.max_write_buffer_number = 4
        if hasattr(opts, "bytes_per_sync"):
            opts.bytes_per_sync = 4 * 1024 * 1024
        if hasattr(_rocksdb, "CompressionType"):
            opts.compression = _rocksdb.CompressionType.lz4_compression
        tf = None
        if all(hasattr(_rocksdb, x) for x in ("BlockBasedTableFactory", "LRUCache", "BloomFilterPolicy")):
            tf = _rocksdb.BlockBasedTableFactory(
                block_cache=_rocksdb.LRUCache(cache_mb * 1024 * 1024),
                filter_policy=_rocksdb.BloomFilterPolicy(10),
                block_size=16 * 1024,
            )
            opts.table_factory = tf
        cf_opts = {n: _rocksdb.ColumnFamilyOptions() for n in
                   (_CF_DEFAULT, _CF_BLOCKS, _CF_STATE)}
        for o in cf_opts.values():
            if tf is not None:
                o.table_factory = tf
            if hasattr(opts, "compression"):
                o.compression = opts.compression
        # Some python-rocksdb versions require the CF names as bytes; try the
        # native names first and retry with byte names only for that API error.
        try:
            self._db = _rocksdb.DB(path, opts, column_families=cf_opts)
            self._cf = {n: self._db.get_column_family(n) for n in cf_opts}
        except (TypeError, ValueError):
            cf_opts_b = {n.encode("ascii"): v for n, v in cf_opts.items()}
            self._db = _rocksdb.DB(path, opts, column_families=cf_opts_b)
            self._cf = {
                n: self._db.get_column_family(n.encode("ascii"))
                for n in cf_opts
            }

    # ── modern rocksdict path ─────────────────────────────────────────────
    def _init_rocksdict(self, path: str, cache_mb: int, wbuf_mb: int):
        Options = _rocksdict.Options
        options = Options(raw_mode=True)
        # These methods are part of rocksdict's public API.  Keep all byte
        # values in raw mode because Visold already msgpack-serializes values.
        options.create_if_missing(True)
        options.create_missing_column_families(True)
        options.set_write_buffer_size(wbuf_mb * 1024 * 1024)
        # Avoid hard-coding the large legacy cache factory here: rocksdict
        # manages the table/cache options itself and can safely reopen a DB
        # created by another RocksDB client.  Retain the existing cache limit
        # as a best-effort tuning knob where supported.
        if hasattr(options, "set_block_cache_size"):
            try:
                options.set_block_cache_size(cache_mb * 1024 * 1024)
            except Exception:
                pass
        # Rdict always creates the "default" column family.  Only pass the
        # additional families in the column_families mapping to avoid asking
        # RocksDB to recreate its mandatory default family.
        cf_options = {
            name: Options(raw_mode=True)
            for name in (_CF_BLOCKS, _CF_STATE)
        }
        for opt in cf_options.values():
            opt.create_if_missing(True)
        # Reusing the same on-disk DB is important after a restart.  For an
        # already-created RocksDB, let rocksdict load the database's own
        # persisted options/column-family descriptors rather than forcing a
        # potentially incompatible new Options object over an existing DB.
        current_manifest = os.path.join(path, "CURRENT")
        if os.path.exists(current_manifest) and hasattr(_rocksdict.Rdict, "list_cf"):
            self._db = _rocksdict.Rdict(path)
            existing = {
                x.decode("utf-8") if isinstance(x, bytes) else x
                for x in _rocksdict.Rdict.list_cf(path)
            }
            for name, cf_opt in cf_options.items():
                if name not in existing:
                    self._db.create_column_family(name, cf_opt)
        else:
            self._db = _rocksdict.Rdict(
                path,
                options=options,
                column_families=cf_options,
            )
        self._cf = {
            name: self._db.get_column_family(name)
            for name in (_CF_DEFAULT, _CF_BLOCKS, _CF_STATE)
        }
        self._cf_handle = {
            name: self._db.get_column_family_handle(name)
            for name in (_CF_DEFAULT, _CF_BLOCKS, _CF_STATE)
        }

    # ── common batch API ──────────────────────────────────────────────────
    def new_batch(self):
        if self._impl == "rocksdict":
            return _RocksDictBatch(_rocksdict)
        return _rocksdb.WriteBatch()

    @staticmethod
    def _configure_rocksdict_write_options(write_options, sync: bool):
        """Configure rocksdict WriteOptions across API generations.

        The installed rocksdict binding used by the PGX test environment
        exposes ``sync`` and ``disable_wal`` as boolean properties, while
        some older/newer wrappers expose setter methods instead.  Never call
        a boolean property as if it were a function.  This helper intentionally
        touches only per-write durability flags and leaves all other defaults
        unchanged.
        """
        setter = getattr(write_options, "set_sync", None)
        if callable(setter):
            setter(bool(sync))
        elif hasattr(write_options, "sync"):
            write_options.sync = bool(sync)
        elif sync:
            raise RuntimeError(
                "rocksdict WriteOptions exposes neither set_sync() nor sync")

        disable = getattr(write_options, "disable_wal", None)
        if callable(disable):
            disable(False)
        elif hasattr(write_options, "disable_wal"):
            # PGX consensus writes must remain WAL-backed.
            write_options.disable_wal = False
        else:
            raise RuntimeError(
                "rocksdict WriteOptions exposes neither disable_wal() "
                "nor disable_wal property")
        return write_options

    def commit(self, batch, sync: bool = True):
        with self._write_lock:
            if self._impl == "rocksdict":
                raw_batch = batch._batch
                # Prefer the binding's explicit per-DB write-options hook.
                # The helper above supports both method-style and property-
                # style WriteOptions APIs (the latter is used by the target
                # rocksdict build).
                if hasattr(_rocksdict, "WriteOptions") and hasattr(self._db, "set_write_options"):
                    wo = self._configure_rocksdict_write_options(
                        _rocksdict.WriteOptions(), sync)
                    self._db.set_write_options(wo)
                elif hasattr(_rocksdict, "WriteOptions"):
                    # Defensive compatibility for bindings that expose
                    # WriteOptions but not Rdict.set_write_options().
                    wo = self._configure_rocksdict_write_options(
                        _rocksdict.WriteOptions(), sync)
                    try:
                        self._db.write(raw_batch, wo)
                    except TypeError as exc:
                        raise RuntimeError(
                            "rocksdict binding cannot apply per-write "
                            "WriteOptions; refusing an unconfigured PGX write"
                        ) from exc
                else:
                    if sync:
                        raise RuntimeError(
                            "rocksdict WriteOptions unavailable for a "
                            "consensus-critical synchronous PGX write")
                    self._db.write(raw_batch)
                    return
                self._db.write(raw_batch)
                if sync and hasattr(self._db, "flush_wal"):
                    self._db.flush_wal(True)
                return
            wo = _rocksdb.WriteOptions()
            wo.sync = sync
            self._db.write(batch, wo)

    # ── common read helper ────────────────────────────────────────────────
    def _get(self, cf_name, key):
        cf = self._cf[cf_name]
        if hasattr(cf, "get"):
            return cf.get(key)
        try:
            return cf[key]
        except (KeyError, TypeError):
            return None

    def _iter_items(self, cf_name, from_key=None):
        cf = self._cf[cf_name]
        if self._impl == "rocksdict":
            return cf.items(from_key=from_key) if from_key is not None else cf.items()
        it = self._db.iterkeys(cf)
        if from_key is not None:
            it.seek(from_key)
        return ((k[1], self._db.get(k)) for k in it)

    # blocks / headers / hash index
    def put_block(self, batch, height, block_dict, header_dict, bhash):
        cf = self._cf_handle[_CF_BLOCKS] if self._impl == "rocksdict" else self._cf[_CF_BLOCKS]
        batch.put((cf, _k_block(height)),    _msgpack.packb(block_dict,  use_bin_type=True))
        batch.put((cf, _k_header(height)),   _msgpack.packb(header_dict, use_bin_type=True))
        batch.put((cf, _k_blockhash(bhash)), height.to_bytes(8, "big"))
    def get_block(self, height):
        v = self._get(_CF_BLOCKS, _k_block(height))
        return _msgpack.unpackb(v, raw=False) if v else None
    def get_header(self, height):
        v = self._get(_CF_BLOCKS, _k_header(height))
        return _msgpack.unpackb(v, raw=False) if v else None

    def clear_all_contract_storage(self, batch):
        """Delete every contract-storage key from the state column family.

        Snapshot restore must not leave unreachable storage behind: a future
        replay can legitimately recreate an old contract address, and stale
        slots from a post-snapshot state would then become visible.  Keeping
        the deletion in the same RocksDB batch makes the restore deterministic
        and avoids a window in which only some slots are cleared.
        """
        cf = self._cf_handle[_CF_STATE] if self._impl == "rocksdict" else self._cf[_CF_STATE]
        prefix = _P_CSTORAGE
        tag_prefix = _P_CSTOR_TAG
        # _iter_items normalises the rocksdict and legacy python-rocksdb
        # iterator shapes to raw (key,value) pairs.
        for key, _value in self._iter_items(_CF_STATE, prefix):
            if not key.startswith(prefix):
                break
            batch.delete((cf, key))
        for key, _value in self._iter_items(_CF_STATE, tag_prefix):
            if not key.startswith(tag_prefix):
                break
            batch.delete((cf, key))
    def get_block_by_hash(self, bhash):
        v = self._get(_CF_BLOCKS, _k_blockhash(bhash))
        return self.get_block(int.from_bytes(v, "big")) if v else None
    def delete_block(self, batch, height, bhash):
        cf = self._cf_handle[_CF_BLOCKS] if self._impl == "rocksdict" else self._cf[_CF_BLOCKS]
        batch.delete((cf, _k_block(height)))
        batch.delete((cf, _k_header(height)))
        if bhash:
            batch.delete((cf, _k_blockhash(bhash)))
    def iter_heights_desc(self, n: int) -> List[int]:
        """Return up to n most-recent heights."""
        tip = self.tip_height()
        if tip < 0: return []
        return list(range(max(0, tip - n + 1), tip + 1))
    def put_tx_loc(self, batch, txid, height, tx_index):
        cf = self._cf_handle[_CF_BLOCKS] if self._impl == "rocksdict" else self._cf[_CF_BLOCKS]
        batch.put((cf, _k_tx(txid)), _u64(height) + _u32(tx_index))

    def delete_tx_loc(self, batch, txid):
        """Delete the secondary tx_id -> (height,index) location index."""
        cf = self._cf_handle[_CF_BLOCKS] if self._impl == "rocksdict" else self._cf[_CF_BLOCKS]
        batch.delete((cf, _k_tx(txid)))

    def get_tx_loc(self, txid):
        v = self._get(_CF_BLOCKS, _k_tx(txid))
        if not v or len(v) != 12: return None
        return struct.unpack(">QI", v)

    # state / merkle / contracts
    def put_state(self, batch, addr, d):
        cf = self._cf_handle[_CF_STATE] if self._impl == "rocksdict" else self._cf[_CF_STATE]
        batch.put((cf, _k_state(addr)), _msgpack.packb(d, use_bin_type=True))
    def get_state(self, addr):
        v = self._get(_CF_STATE, _k_state(addr))
        return _msgpack.unpackb(v, raw=False) if v else None
    def put_contract_code(self, batch, code_hash, bytecode):
        cf = self._cf_handle[_CF_STATE] if self._impl == "rocksdict" else self._cf[_CF_STATE]
        batch.put((cf, _k_ccode(code_hash)), bytecode)
    def get_contract_code(self, code_hash):
        return self._get(_CF_STATE, _k_ccode(code_hash))
    def del_contract_code(self, batch, code_hash):
        cf = self._cf_handle[_CF_STATE] if self._impl == "rocksdict" else self._cf[_CF_STATE]
        batch.delete((cf, _k_ccode(code_hash)))
    def put_cstorage(self, batch, addr, slot, value_bytes):
        cf = self._cf_handle[_CF_STATE] if self._impl == "rocksdict" else self._cf[_CF_STATE]
        batch.put((cf, _k_cstor(addr, slot)), value_bytes)
    def del_cstorage(self, batch, addr, slot):
        cf = self._cf_handle[_CF_STATE] if self._impl == "rocksdict" else self._cf[_CF_STATE]
        batch.delete((cf, _k_cstor(addr, slot)))
    def get_cstorage(self, addr, slot):
        return self._get(_CF_STATE, _k_cstor(addr, slot))
    def put_cstorage_tag(self, batch, addr, slot, tag):
        cf = self._cf_handle[_CF_STATE] if self._impl == "rocksdict" else self._cf[_CF_STATE]
        batch.put((cf, _k_cstor_tag(addr, slot)), str(int(tag) & 0x07).encode("ascii"))
    def del_cstorage_tag(self, batch, addr, slot):
        cf = self._cf_handle[_CF_STATE] if self._impl == "rocksdict" else self._cf[_CF_STATE]
        batch.delete((cf, _k_cstor_tag(addr, slot)))
    def get_cstorage_tag(self, addr, slot):
        return self._get(_CF_STATE, _k_cstor_tag(addr, slot))
    def iter_cstorage_tags(self, addr: str):
        prefix = _P_CSTOR_TAG + addr.encode() + b":"
        out = []
        if self._impl == "rocksdict":
            for k, v in self._cf[_CF_STATE].items(from_key=prefix):
                if not k.startswith(prefix): break
                slot = k[len(prefix):].decode("ascii")
                out.append((slot, int(v.decode("ascii"))))
            return out
        it = self._db.iterkeys(self._cf[_CF_STATE]); it.seek(prefix)
        for k in it:
            if not k[1].startswith(prefix): break
            slot = k[1][len(prefix):].decode("ascii")
            v = self._db.get(k)
            out.append((slot, int(v.decode("ascii"))))
        return out
    def iter_cstorage(self, addr: str):
        """Yield (slot_key, slot_value_bytes) for all slots of a contract."""
        prefix = _P_CSTORAGE + addr.encode() + b":"
        out = []
        if self._impl == "rocksdict":
            # rocksdict's from_key seek gives a real ordered RocksDB iterator;
            # stop as soon as the prefix changes.
            for k, v in self._cf[_CF_STATE].items(from_key=prefix):
                if not k.startswith(prefix):
                    break
                slot = k[len(prefix):].decode("ascii")
                out.append((slot, v))
            return out
        it = self._db.iterkeys(self._cf[_CF_STATE]); it.seek(prefix)
        for k in it:
            if not k[1].startswith(prefix): break
            slot = k[1][len(prefix):].decode("ascii")
            v = self._db.get(k)
            out.append((slot, v))
        return out

    # meta
    def put_meta(self, batch, name, value_bytes):
        cf = self._cf_handle[_CF_DEFAULT] if self._impl == "rocksdict" else self._cf[_CF_DEFAULT]
        batch.put((cf, _k_meta(name)), value_bytes)

    def delete_meta(self, batch, name):
        cf = self._cf_handle[_CF_DEFAULT] if self._impl == "rocksdict" else self._cf[_CF_DEFAULT]
        batch.delete((cf, _k_meta(name)))

    def get_meta(self, name):
        return self._get(_CF_DEFAULT, _k_meta(name))
    def tip_height(self) -> int:
        v = self.get_meta(_META_CHAIN_TIP)
        return int.from_bytes(v, "big") if v else -1

    def close(self):
        with self._write_lock:
            if self._impl == "rocksdict":
                try:
                    if hasattr(self._db, "flush_wal"):
                        self._db.flush_wal(True)
                finally:
                    # CF handles/objects keep the DB alive in rocksdict, so
                    # drop them before the parent Rdict.
                    for obj in getattr(self, "_cf", {}).values():
                        try: obj.close()
                        except Exception: pass
                    self._cf.clear()
                    self._cf_handle.clear()
                    try: self._db.close()
                    except Exception: pass
                return
            try:
                self._db.flush_wal(True) if hasattr(self._db, "flush_wal") else None
            except Exception:
                pass
            try:
                self._db.close()
            except Exception:
                pass


class _PgStateDB:
    """asyncpg pool running on a dedicated background event loop so the
    existing sync P2P / consensus threads can call it without refactoring."""
    def __init__(self, dsn: str, min_size=4, max_size=32):
        self._dsn, self._min, self._max = dsn, min_size, max_size
        self._pool = None
        self._loop: Optional[_asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready  = threading.Event()
        self._start_error: Optional[str] = None

    def start(self):
        if self._thread: return
        self._thread = threading.Thread(target=self._run, name="pgstate-loop", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=15):
            raise RuntimeError("PgStateDB failed to start within 15s")
        if self._start_error:
            raise RuntimeError(f"PgStateDB init failed: {self._start_error}")

    def _run(self):
        self._loop = _asyncio.new_event_loop()
        _asyncio.set_event_loop(self._loop)
        async def _init():
            self._pool = await _asyncpg.create_pool(
                dsn=self._dsn, min_size=self._min, max_size=self._max,
                command_timeout=30, statement_cache_size=1024)
            async with self._pool.acquire() as c:
                await c.execute(_PG_SCHEMA_SQL)
        try:
            self._loop.run_until_complete(_init())
        except Exception as e:
            self._start_error = repr(e)
            self._ready.set()
            return
        self._ready.set()
        self._loop.run_forever()

    def close(self):
        if self._loop and self._pool:
            try: _asyncio.run_coroutine_threadsafe(self._pool.close(), self._loop).result(5)
            except Exception: pass
            self._loop.call_soon_threadsafe(self._loop.stop)

    def run(self, coro):
        return _asyncio.run_coroutine_threadsafe(coro, self._loop).result()


class _RedisCache:
    def __init__(self, url: str):
        self.r = None
        if not url:
            return
        try:
            pool = _redis.ConnectionPool.from_url(
                url, decode_responses=False, max_connections=64,
                socket_timeout=2, socket_connect_timeout=2)
            r = _redis.Redis(connection_pool=pool)
            r.ping()
            self.r = r
        except Exception:
            self.r = None
    def _safe(self, fn, *a, **kw):
        if self.r is None: return None
        try: return fn(*a, **kw)
        except Exception: return None
    def set_tip(self, height, bhash, publish: bool = True):
        if self.r is None: return
        self._safe(self.r.set, "vsd:height", height)
        self._safe(self.r.set, "vsd:tip_hash", bhash, ex=60)
        if publish:
            self._safe(self.r.publish, "vsd:ch:new_block", str(height))

    def clear_tip(self):
        """Clear the cached tip when the canonical chain has no stored tip."""
        if self.r is None: return
        self._safe(self.r.delete, "vsd:height", "vsd:tip_hash")
    def get_height(self):
        v = self._safe(self.r.get, "vsd:height") if self.r else None
        return int(v) if v else None
    def cache_balance(self, addr, sat):
        if self.r is None: return
        self._safe(self.r.set, f"vsd:bal:{addr}", str(sat), ex=30)
    def get_balance(self, addr):
        v = self._safe(self.r.get, f"vsd:bal:{addr}") if self.r else None
        return int(v) if v else None
    def invalidate_balance(self, addr):
        if self.r is None: return
        self._safe(self.r.delete, f"vsd:bal:{addr}")
    def clear_balance_cache(self):
        """Remove every cached account balance after a full-state restore."""
        if self.r is None:
            return
        try:
            keys = list(self.r.scan_iter(match="vsd:bal:*", count=500))
            if keys:
                self.r.delete(*keys)
        except Exception:
            # Redis is a non-authoritative cache.  A cache-clear failure must
            # never make an otherwise successful consensus-state restore fail.
            pass
    def mempool_add(self, tx_id, fee_sat, payload):
        if self.r is None: return
        p = self._safe(self.r.pipeline)
        if p is None: return
        try:
            p.zadd("vsd:mempool", {tx_id: fee_sat})
            p.set(f"vsd:mempool:tx:{tx_id}", payload, ex=3600)
            p.execute()
        except Exception: pass
    def mempool_remove(self, tx_ids: List[str]):
        if self.r is None or not tx_ids: return
        try:
            p = self.r.pipeline()
            p.zrem("vsd:mempool", *tx_ids)
            p.delete(*[f"vsd:mempool:tx:{t}" for t in tx_ids])
            p.execute()
        except Exception: pass
