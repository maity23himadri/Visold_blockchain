"""Regression checks for PGX binding/schema compatibility fixes.

These checks do not fake a successful PGX storage run.  They verify the
source-level compatibility rules that can be exercised without requiring the
native PostgreSQL/RocksDB services.
"""
from __future__ import annotations

from visold.ledger.transaction import Transaction
from visold.storage.backends import _RocksBlockStore, _RocksDictBatch
from visold.storage.storage import _pg_tx_type_code


class _PropertyStyleWriteOptions:
    """Matches the target rocksdict binding observed in the PGX report."""

    def __init__(self) -> None:
        self.disable_wal = True
        self.sync = False


class _MethodStyleWriteOptions:
    """Compatibility model for a method-style WriteOptions binding."""

    def __init__(self) -> None:
        self._disable_wal = True
        self._sync = False

    def disable_wal(self, value: bool) -> None:
        self._disable_wal = value

    def set_sync(self, value: bool) -> None:
        self._sync = value


class _RawModeWriteBatch:
    def __init__(self, raw_mode=False):
        self.raw_mode = raw_mode
        self.put_calls = []
        self.delete_calls = []

    def put(self, key, value, cf):
        self.put_calls.append((key, value, cf))

    def delete(self, key, cf):
        self.delete_calls.append((key, cf))


class _RawModeRocksdictModule:
    WriteBatch = _RawModeWriteBatch


class _LegacyWriteBatch:
    def __init__(self):
        pass


class _LegacyRocksdictModule:
    WriteBatch = _LegacyWriteBatch


def test_write_options_property_style() -> None:
    opts = _PropertyStyleWriteOptions()
    _RocksBlockStore._configure_rocksdict_write_options(opts, True)
    assert opts.disable_wal is False
    assert opts.sync is True


def test_write_options_method_style() -> None:
    opts = _MethodStyleWriteOptions()
    _RocksBlockStore._configure_rocksdict_write_options(opts, True)
    assert opts._disable_wal is False
    assert opts._sync is True


def test_pg_transaction_type_codes_are_explicit() -> None:
    expected = {
        Transaction.TYPE_TRANSFER: 0,
        Transaction.TYPE_DEPLOY: 1,
        Transaction.TYPE_CALL: 2,
        Transaction.TYPE_REGISTER: 3,
        Transaction.TYPE_ROLLUP: 4,
        "reward": 5,
    }
    for tx_type, code in expected.items():
        assert _pg_tx_type_code(tx_type) == code


def test_pg_transaction_type_unknown_fails_closed() -> None:
    try:
        _pg_tx_type_code("unknown-future-type")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown transaction type was silently remapped")


def test_rocksdict_batch_is_created_in_raw_mode() -> None:
    wrapper = _RocksDictBatch(_RawModeRocksdictModule)
    assert wrapper._batch.raw_mode is True


def test_rocksdict_store_new_batch_uses_raw_mode(monkeypatch) -> None:
    import visold.storage.backends as backends

    monkeypatch.setattr(backends, "_rocksdict", _RawModeRocksdictModule)
    store = _RocksBlockStore.__new__(_RocksBlockStore)
    store._impl = "rocksdict"
    batch = store.new_batch()
    assert batch._batch.raw_mode is True


def test_rocksdict_batch_rejects_bindings_without_raw_mode() -> None:
    try:
        _RocksDictBatch(_LegacyRocksdictModule)
    except RuntimeError as exc:
        assert "WriteBatch(raw_mode=True)" in str(exc)
    else:
        raise AssertionError("legacy non-raw WriteBatch was accepted by PGX")
