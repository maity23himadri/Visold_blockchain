# PGX backend fix — 2026-10-05

This build fixes the PGX storage initialization path for modern Linux environments where `rocksdict` is available but the legacy `python-rocksdb` binding is not compatible with the installed RocksDB library.

## Supported RocksDB Python bindings

Preferred:

```bash
pip install rocksdict asyncpg redis msgpack
```

Legacy `python-rocksdb` remains supported when its API is genuinely available.

## Important backend-selection rule

`VISOLD_STORAGE=pgx` is now an explicit request. If PGX initialization fails, Visold raises an error instead of silently starting on SQLite. Automatic selection may still use SQLite only when no backend was explicitly selected.

## Native PGX test

Use a dedicated PostgreSQL database and Redis DB. Set at minimum:

```bash
export VISOLD_STORAGE=pgx
export VISOLD_PG_DSN='postgresql://...'
export VISOLD_REDIS_URL='redis://...'
export VISOLD_ROCKS_PATH='/isolated/path/rocks'
export VISOLD_DATA_DIR='/isolated/path/data'
```

Then run the existing full suite with SQLite explicitly for the reference backend, followed by the PGX-specific rollback and restart/multi-node harness:

```bash
VISOLD_STORAGE=sqlite python visold_vsd_.py --test
VISOLD_STORAGE=pgx python visold_vsd_.py --test
PYTHONPATH=. VISOLD_STORAGE=pgx python tests/test_vvm_rollback_regressions.py
```

The second and third commands must only be reported as PGX results when the logs show `Storage: PostgreSQL + rocksdict + Redis initialized` (or the legacy RocksDB equivalent).

## Follow-up fixes from 2026-10-05 PGX runtime test

Two runtime defects were corrected after the first native PGX pass:

1. `rocksdict.WriteOptions.disable_wal` / `sync` are handled as either callable setters or boolean properties, matching the installed binding without disabling WAL for consensus writes.
2. PostgreSQL `transactions.tx_type SMALLINT` now receives an explicit persistence-only code mapping for `transfer`, `deploy`, `call`, `register`, `rollup`, and `reward`. The original string transaction type remains unchanged in `data_json` and therefore is not altered in consensus hashing/signing/serialization. Unknown types fail closed instead of being silently remapped.
3. The PGX `rocksdict` batch adapter now constructs `WriteBatch(raw_mode=True)` to match the raw-mode `Rdict`. Bindings that cannot create a raw-mode batch are rejected explicitly rather than falling back to a potentially incompatible non-raw batch.
4. PGX rollback cleanup no longer deletes `vvm_receipts` through the auxiliary SQLite shadow database. VVM receipts are canonical in PostgreSQL and are not mirrored into that reduced aux schema. Auxiliary shadow cleanup is non-authoritative and cannot convert a successful canonical rollback into a false failure. Redis tip metadata is also rewound silently after a successful canonical block delete, without publishing a fake new-block event.

The supplied native PGX smoke test should now be rerun on the target `rocksdict` environment; full consensus/VVM/rollback equivalence is not claimed from this container because `rocksdict` is not installed here.

