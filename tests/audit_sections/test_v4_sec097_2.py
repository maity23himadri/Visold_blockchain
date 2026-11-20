"""Section 97 V4 Regression Tests: Storage Batch Proxy Atomicity and Error Handling."""

import os
import pytest

from visold.kernel.config import Config
from visold.state.batch_proxy import _StorageBatchProxy
from visold.storage.storage import Storage


def _make_sqlite_storage(tmp_path):
    db_path = str(tmp_path / "test_s97.db")
    orig_pgx = os.environ.get("VISOLD_STORAGE_BACKEND")
    os.environ["VISOLD_STORAGE_BACKEND"] = "sqlite"
    try:
        st = Storage(db_path)
    finally:
        if orig_pgx is None:
            os.environ.pop("VISOLD_STORAGE_BACKEND", None)
        else:
            os.environ["VISOLD_STORAGE_BACKEND"] = orig_pgx
    return st


def test_flush_block_batch_sqlite_rolls_back_on_error(tmp_path, monkeypatch):
    """Fixed: Storage._flush_block_batch() in SQLite mode rolls back on mid-batch
    failure when called outside begin_sqlite_atomic_block(), leaving in_transaction=False."""
    st = _make_sqlite_storage(tmp_path)
    monkeypatch.setattr(Config, "SQLITE_BUSY_TIMEOUT_MS", 100)
    try:
        proxy = _StorageBatchProxy(st)
        proxy.credit_sat("alice", 500_000_000)
        proxy._nonces["alice"] = "not_an_int"
        proxy._dirty_non.add("alice")

        with pytest.raises(ValueError):
            proxy.flush()

        assert st._conn()._conn.in_transaction is False

        st.begin_sqlite_atomic_block()
        st.rollback_sqlite_atomic_block()
    finally:
        st.close()


def test_restore_state_channel_journal_accounts_only_does_not_corrupt_state_channels(tmp_path):
    """Fixed: restore_state_channel_journal() does not treat an 'accounts'-only
    journal as a channel_id named 'accounts'."""
    st = _make_sqlite_storage(tmp_path)
    try:
        st.set_balance("alice", 1000)
        proxy = _StorageBatchProxy(st)
        proxy.debit_sat("alice", 400)
        assert proxy.get_balance_sat("alice") == 600

        journal = {"accounts": {"alice": (1000, 0, 0, True)}}
        proxy.restore_state_channel_journal(journal)

        assert proxy.get_balance_sat("alice") == 1000

        rows = st._conn().execute(
            "SELECT channel_id FROM state_channels WHERE channel_id='accounts'"
        ).fetchall()
        assert len(rows) == 0
    finally:
        st.close()
