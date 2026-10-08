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
"""visold.storage.sqlite_serialized

Original section: SECTION 6: STORAGE (SQLite — WAL mode + periodic checkpoint)

Origin: visold_vsd_.py L12776-12833, L12836-12902
"""

import sqlite3
import threading


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6: STORAGE (SQLite — WAL mode + periodic checkpoint)
# ─────────────────────────────────────────────────────────────────────────────
class _SerializedSQLiteCursor:
    """Serialize every operation on a cursor from a shared connection.

    ``sqlite3.Connection`` itself may be shared only when every operation on
    the connection and its cursors is serialized.  The production code keeps
    cursors alive across ``execute()`` and ``fetchone()/fetchall()`` calls, so
    serializing only ``Connection.execute`` is insufficient.  This adapter
    preserves the cursor API used by this file while protecting each cursor
    operation with the Storage-level re-entrant lock.
    """
    __slots__ = ("_cursor", "_lock")

    def __init__(self, cursor, lock: threading.RLock):
        self._cursor = cursor
        self._lock = lock

    def execute(self, *args, **kwargs):
        with self._lock:
            self._cursor.execute(*args, **kwargs)
        return self

    def executemany(self, *args, **kwargs):
        with self._lock:
            self._cursor.executemany(*args, **kwargs)
        return self

    def fetchone(self):
        with self._lock:
            return self._cursor.fetchone()

    def fetchmany(self, *args, **kwargs):
        with self._lock:
            return self._cursor.fetchmany(*args, **kwargs)

    def fetchall(self):
        with self._lock:
            return self._cursor.fetchall()

    def close(self):
        with self._lock:
            return self._cursor.close()

    def __iter__(self):
        # Iteration is kept under one lock for the full result stream.  This
        # prevents another thread from changing connection-level statement
        # state between successive rows.
        with self._lock:
            for row in self._cursor:
                yield row

    def __getattr__(self, name):
        attr = getattr(self._cursor, name)
        if callable(attr):
            def _locked(*args, **kwargs):
                with self._lock:
                    return attr(*args, **kwargs)
            return _locked
        return attr


class _SerializedSQLiteConnection:
    """Small compatibility wrapper for one SQLite connection shared by threads.

    The wrapper deliberately does not change SQL, transaction mode, WAL mode,
    busy timeout, row factories, or return values.  It only serializes calls
    that enter the underlying connection/cursor object.  ``RLock`` is required
    because existing Storage methods legitimately call ``execute`` and then
    ``commit`` while already inside a higher-level protected operation.
    """
    __slots__ = ("_conn", "_lock", "_atomic")

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock):
        self._conn = conn
        self._lock = lock
        self._atomic = False

    def execute(self, *args, **kwargs):
        with self._lock:
            return _SerializedSQLiteCursor(
                self._conn.execute(*args, **kwargs), self._lock)

    def executemany(self, *args, **kwargs):
        with self._lock:
            return _SerializedSQLiteCursor(
                self._conn.executemany(*args, **kwargs), self._lock)

    def executescript(self, *args, **kwargs):
        with self._lock:
            return _SerializedSQLiteCursor(
                self._conn.executescript(*args, **kwargs), self._lock)

    def cursor(self, *args, **kwargs):
        with self._lock:
            return _SerializedSQLiteCursor(
                self._conn.cursor(*args, **kwargs), self._lock)

    def atomic_active(self) -> bool:
        """Return whether the connection is inside a Storage-owned atomic block.

        This is intentionally distinct from ``sqlite3.Connection.in_transaction``:
        SQLite may also have an implicit transaction opened by an ordinary write,
        whereas Storage methods need to know specifically whether the enclosing
        block-application transaction owns commit/rollback.
        """
        with self._lock:
            return bool(self._atomic)

    def begin_atomic(self):
        """Begin an exclusive Storage-level SQLite transaction.

        The caller must already hold the shared Storage SQLite lock for the
        entire transaction.  While active, ordinary commit()/rollback() calls
        from Storage methods are suppressed; the owner uses commit_atomic() or
        rollback_atomic() to finish the transaction.
        """
        with self._lock:
            if self._atomic:
                raise RuntimeError("SQLite atomic transaction already active")
            if self._conn.in_transaction:
                raise RuntimeError("SQLite connection already has an active transaction")
            self._conn.execute("BEGIN IMMEDIATE")
            self._atomic = True

    def commit_atomic(self):
        with self._lock:
            if not self._atomic:
                raise RuntimeError("SQLite atomic transaction is not active")
            try:
                self._conn.commit()
            finally:
                self._atomic = False

    def rollback_atomic(self):
        with self._lock:
            if not self._atomic:
                return
            try:
                self._conn.rollback()
            finally:
                self._atomic = False

    def commit(self):
        with self._lock:
            if self._atomic:
                return None
            return self._conn.commit()

    def rollback(self):
        with self._lock:
            if self._atomic:
                return None
            return self._conn.rollback()

    def close(self):
        with self._lock:
            return self._conn.close()

    def __enter__(self):
        with self._lock:
            self._conn.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback_value):
        with self._lock:
            return self._conn.__exit__(exc_type, exc_value, traceback_value)

    def __getattr__(self, name):
        attr = getattr(self._conn, name)
        if callable(attr):
            def _locked(*args, **kwargs):
                with self._lock:
                    result = attr(*args, **kwargs)
                    if isinstance(result, sqlite3.Cursor):
                        return _SerializedSQLiteCursor(result, self._lock)
                    return result
            return _locked
        return attr
