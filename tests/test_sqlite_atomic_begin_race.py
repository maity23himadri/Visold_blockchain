"""Regression tests for SQLite's ordinary-write / block-BEGIN race."""
import sqlite3
import threading
import time

from visold.storage.sqlite_serialized import (
    _SerializedSQLiteConnection,
    _SQLiteConnectionTransactionBusy,
)
from visold.storage.storage import Storage


def test_block_atomic_begin_waits_for_pending_ordinary_writer(monkeypatch):
    """Block BEGIN must yield the API lock so the implicit writer can commit."""
    api_lock = threading.RLock()
    raw = sqlite3.connect(":memory:", check_same_thread=False)
    raw.execute("CREATE TABLE items (value TEXT NOT NULL)")
    raw.commit()
    shared = _SerializedSQLiteConnection(raw, api_lock)

    class _StorageHarness:
        _pgx_enabled = False
        _sqlite_api_lock = api_lock

        @staticmethod
        def _conn():
            return shared

    harness = _StorageHarness()
    ordinary_write_ready = threading.Event()
    permit_ordinary_commit = threading.Event()
    block_begin_saw_pending_tx = threading.Event()
    errors = []

    original_begin_atomic = _SerializedSQLiteConnection.begin_atomic

    def observed_begin_atomic(self):
        try:
            return original_begin_atomic(self)
        except _SQLiteConnectionTransactionBusy:
            block_begin_saw_pending_tx.set()
            raise

    monkeypatch.setattr(
        _SerializedSQLiteConnection, "begin_atomic", observed_begin_atomic
    )

    def ordinary_writer():
        try:
            shared.execute("INSERT INTO items(value) VALUES ('ordinary')").close()
            ordinary_write_ready.set()
            if not permit_ordinary_commit.wait(3.0):
                raise AssertionError("test did not release the ordinary writer")
            shared.commit()
        except BaseException as exc:
            errors.append(exc)

    def block_writer():
        try:
            Storage.begin_sqlite_atomic_block(harness)
            try:
                shared.execute("INSERT INTO items(value) VALUES ('block')").close()
                Storage.commit_sqlite_atomic_block(harness)
            except BaseException:
                Storage.rollback_sqlite_atomic_block(harness)
                raise
        except BaseException as exc:
            errors.append(exc)

    ordinary_thread = threading.Thread(target=ordinary_writer, daemon=True)
    ordinary_thread.start()
    assert ordinary_write_ready.wait(2.0)

    block_thread = threading.Thread(target=block_writer, daemon=True)
    block_thread.start()
    try:
        assert block_begin_saw_pending_tx.wait(2.0), (
            "test failed to observe the pending transaction conflict"
        )
    finally:
        permit_ordinary_commit.set()

    ordinary_thread.join(timeout=2.0)
    block_thread.join(timeout=3.0)
    try:
        assert not ordinary_thread.is_alive()
        assert not block_thread.is_alive()
        assert errors == []
        rows = shared.execute("SELECT value FROM items ORDER BY rowid").fetchall()
        assert [row[0] for row in rows] == ["ordinary", "block"]
        assert raw.in_transaction is False
    finally:
        raw.close()
