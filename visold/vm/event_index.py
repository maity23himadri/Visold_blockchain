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
"""visold.vm.event_index

Original section: SECTION 7B1B: CONTRACT EVENT INDEX  (SC-FIX-8)

Defines: ContractEventIndex
Origin: visold_vsd_.py L21961-22091
"""

from typing import TYPE_CHECKING

from visold.kernel.logging_setup import log

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.storage.storage import Storage


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7B1B: CONTRACT EVENT INDEX  (SC-FIX-8)
#
# Provides efficient O(1) lookup of contract logs by:
#   • contract address  (all events emitted by a contract)
#   • topic[0]          (all events of a specific type across all contracts)
#   • block range       (events in a height range)
#
# The index is maintained atomically inside save_vvm_receipt() so it is
# always consistent with the receipt table. Reorg rollback clears the index
# for rolled-back blocks.
# ─────────────────────────────────────────────────────────────────────────────

class ContractEventIndex:
    """
    Queryable index for VVM contract event logs.

    Schema (SQLite auxiliary table):
        contract_event_index (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            block_idx    INTEGER NOT NULL,
            tx_id        TEXT    NOT NULL,
            contract     TEXT    NOT NULL,
            topic0       TEXT    NOT NULL DEFAULT '',
            topic1       TEXT    NOT NULL DEFAULT '',
            topic2       TEXT    NOT NULL DEFAULT '',
            log_data     TEXT    NOT NULL DEFAULT '',
            log_index    INTEGER NOT NULL DEFAULT 0
        )

    Indexes on (contract, block_idx), (topic0, block_idx).
    """

    _TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS contract_event_index (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            block_idx INTEGER NOT NULL,
            tx_id     TEXT    NOT NULL,
            contract  TEXT    NOT NULL,
            topic0    TEXT    NOT NULL DEFAULT '',
            topic1    TEXT    NOT NULL DEFAULT '',
            topic2    TEXT    NOT NULL DEFAULT '',
            log_data  TEXT    NOT NULL DEFAULT '',
            log_index INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS cei_contract_block
            ON contract_event_index(contract, block_idx);
        CREATE INDEX IF NOT EXISTS cei_topic0_block
            ON contract_event_index(topic0, block_idx);
        CREATE INDEX IF NOT EXISTS cei_block
            ON contract_event_index(block_idx);
    """

    def __init__(self, storage: 'Storage'):
        self._storage = storage
        self._ensure_table()

    def _ensure_table(self):
        try:
            c = self._storage._conn()
            c.executescript(self._TABLE_SQL)
            c.commit()
        except Exception as e:
            log.debug(f"ContractEventIndex: init error: {e}")

    def index_logs(self, tx_id: str, block_idx: int,
                   contract_addr: str, logs: list):
        """
        Index all log entries from a single VVM transaction.
        Called atomically from save_vvm_receipt().

        logs: list of dicts with keys 'address', 'topics', 'data'
        """
        if not logs:
            return
        try:
            c = self._storage._conn()
            for i, entry in enumerate(logs):
                addr    = entry.get("address", contract_addr)
                topics  = entry.get("topics", [])
                t0 = topics[0] if len(topics) > 0 else ""
                t1 = topics[1] if len(topics) > 1 else ""
                t2 = topics[2] if len(topics) > 2 else ""
                data    = entry.get("data", "")
                c.execute(
                    """INSERT INTO contract_event_index
                       (block_idx, tx_id, contract, topic0, topic1, topic2,
                        log_data, log_index)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (block_idx, tx_id, addr, t0, t1, t2, data, i)
                )
            c.commit()
        except Exception as e:
            log.debug(f"ContractEventIndex.index_logs error: {e}")

    def get_events_by_contract(self, contract: str,
                               from_block: int = 0,
                               to_block: int = 2**31) -> list:
        """Return all indexed log entries emitted by `contract`."""
        try:
            c = self._storage._conn()
            rows = c.execute(
                """SELECT block_idx, tx_id, topic0, topic1, topic2,
                          log_data, log_index
                   FROM contract_event_index
                   WHERE contract=? AND block_idx>=? AND block_idx<=?
                   ORDER BY block_idx, log_index""",
                (contract, from_block, to_block)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            log.debug(f"ContractEventIndex.get_events_by_contract error: {e}")
            return []

    def get_events_by_topic(self, topic0: str,
                            from_block: int = 0,
                            to_block: int = 2**31) -> list:
        """Return all indexed log entries with the given topic0."""
        try:
            c = self._storage._conn()
            rows = c.execute(
                """SELECT block_idx, tx_id, contract, topic0, topic1, topic2,
                          log_data, log_index
                   FROM contract_event_index
                   WHERE topic0=? AND block_idx>=? AND block_idx<=?
                   ORDER BY block_idx, log_index""",
                (topic0, from_block, to_block)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            log.debug(f"ContractEventIndex.get_events_by_topic error: {e}")
            return []

    def delete_block_events(self, block_idx: int):
        """Remove all event index entries for a rolled-back block."""
        try:
            c = self._storage._conn()
            c.execute(
                "DELETE FROM contract_event_index WHERE block_idx=?",
                (block_idx,)
            )
            c.commit()
        except Exception as e:
            log.debug(f"ContractEventIndex.delete_block_events error: {e}")
