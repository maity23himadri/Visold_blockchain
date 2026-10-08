"""Native PGX RocksDB adapter smoke test.

Run this on the target environment with rocksdict installed. It exercises the
same adapter used by Storage, including column families, atomic WriteBatch use,
seek-based contract storage iteration, and reopen persistence.
"""
from __future__ import annotations

import os
import shutil
import tempfile


def main() -> int:
    try:
        import rocksdict  # noqa: F401
    except Exception as exc:
        print(f"SKIP: rocksdict is not installed/importable: {exc}")
        return 2

    from visold.storage.backends import _RocksBlockStore

    root = tempfile.mkdtemp(prefix="visold-pgx-rocks-smoke-")
    path = os.path.join(root, "rocks")
    try:
        store = _RocksBlockStore(path, cache_mb=32, wbuf_mb=8)
        assert store._impl == "rocksdict", store._impl

        batch = store.new_batch()
        store.put_meta(batch, "chain_tip", (7).to_bytes(8, "big"))
        store.put_tx_loc(batch, "tx-test", 7, 2)
        store.put_cstorage(batch, "VSDc-test", "01", b"alpha")
        store.put_cstorage(batch, "VSDc-test", "02", b"beta")
        store.put_contract_code(batch, "code-test", b"6000")
        store.commit(batch, sync=True)

        assert store.tip_height() == 7
        assert store.get_tx_loc("tx-test") == (7, 2)
        assert store.get_cstorage("VSDc-test", "01") == b"alpha"
        assert store.iter_cstorage("VSDc-test") == [("01", b"alpha"), ("02", b"beta")]
        assert store.get_contract_code("code-test") == b"6000"
        store.close()

        # Reopen the same RocksDB and prove persisted data/CF metadata are
        # readable through the same adapter.
        store = _RocksBlockStore(path, cache_mb=32, wbuf_mb=8)
        assert store.tip_height() == 7
        assert store.get_tx_loc("tx-test") == (7, 2)
        assert store.iter_cstorage("VSDc-test") == [("01", b"alpha"), ("02", b"beta")]
        store.close()
        print("PGX RocksDB adapter native smoke: PASS")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
