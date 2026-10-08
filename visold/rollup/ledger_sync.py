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
"""visold.rollup.ledger_sync


Defines: sync_local_ledger
Origin: visold_vsd_.py L25065-25066, L25069-25119, L25122-25180, L25183-25227
"""

import json
import os
import threading

from visold.kernel.logging_setup import log
from visold.kernel.units import from_satoshi
from visold.rollup.batches import RollupSubmission


# ─────────────────────────────────────────────────────────────────────────────
# LOCAL TRANSACTION INDEXER  (vsd_personal_ledger)
# ─────────────────────────────────────────────────────────────────────────────
# Scans every block that is about to be pruned (or any block passed in) for
# transactions that involve OWNER_ADDRESS (as sender OR receiver) on both L1
# and L2 layers, and appends matching records to a local JSON file so they
# survive the 600-block rolling prune window.
#
# Design goals
# ────────────
#  • Zero overhead on the critical path — the heavy I/O work is dispatched to
#    a short-lived daemon thread so apply_block returns immediately.
#  • Idempotent — duplicate entries are skipped by Tx_Hash set-check inside
#    the file; safe to call on the same block multiple times (e.g. after a
#    crash+replay).
#  • Resilient — every failure path is caught; the main chain keeps running
#    regardless of ledger write failures (disk full, permission error, …).
#  • L1 + L2 aware — regular Transfer/Deploy/Call/Register L1 transactions
#    AND L2 transactions packed inside TYPE_ROLLUP submissions are both
#    indexed.
#
# Placed here (after RollupSubmission, before Sequencer) so that all
# referenced names — RollupSubmission, from_satoshi, threading, os, json,
# log — are already defined at module parse time with no forward references.
#
# Usage (inside your main block-loop or just before prune_async):
#
#     OWNER_ADDRESS = "VSD<your_address>"
#     sync_local_ledger(block, OWNER_ADDRESS)   # non-blocking
#
# The produced JSON file (vsd_personal_ledger.json) has this shape:
#
#   {
#     "owner":   "VSD<address>",
#     "entries": [
#       {
#         "Block_Height":         <int>,
#         "Tx_Hash":              "<hex>",
#         "Type":                 "L1" | "L2",
#         "Amount":               <float, VSD>,
#         "Timestamp":            <int, unix seconds>,
#         "Counterparty_Address": "<address>"
#       },
#       …
#     ]
#   }
# ─────────────────────────────────────────────────────────────────────────────

_LOCAL_LEDGER_PATH = "vsd_personal_ledger.json"


_LOCAL_LEDGER_LOCK = threading.Lock()   # serialises concurrent daemon writes


def _ledger_collect_entries(block, owner_address: str) -> list:
    """Pure extraction step — no I/O.  Returns a list of dicts for every
    L1 and L2 transaction in *block* that involves *owner_address*.

    Kept separate from the write step so it can be unit-tested without
    touching the filesystem.
    """
    owner = owner_address.strip()
    collected: list = []

    # ── L1 transactions ──────────────────────────────────────────────────────
    for tx in getattr(block, "transactions", ()):
        sender   = getattr(tx, "sender",   "") or ""
        receiver = getattr(tx, "receiver", "") or ""
        if sender == owner or receiver == owner:
            counterparty = receiver if sender == owner else sender
            collected.append({
                "Block_Height":         int(block.index),
                "Tx_Hash":              str(getattr(tx, "tx_id", "") or ""),
                "Type":                 "L1",
                "Amount":               float(getattr(tx, "amount", 0.0) or 0.0),
                "Timestamp":            int(getattr(tx, "timestamp", 0) or 0),
                "Counterparty_Address": counterparty,
            })

    # ── L2 transactions packed inside TYPE_ROLLUP submissions ────────────────
    for tx in getattr(block, "transactions", ()):
        if getattr(tx, "tx_type", "") != "rollup":
            continue
        try:
            submission = RollupSubmission.from_json(tx.data or "")
            l2_txs     = RollupSubmission.decompress_batch(submission.compressed_data)
        except Exception:
            # Corrupt / empty rollup payload — skip silently.
            continue
        for l2tx in l2_txs:
            l2_sender   = getattr(l2tx, "sender",   "") or ""
            l2_receiver = getattr(l2tx, "receiver", "") or ""
            if l2_sender == owner or l2_receiver == owner:
                counterparty = l2_receiver if l2_sender == owner else l2_sender
                amount_vsd   = from_satoshi(int(getattr(l2tx, "amount_sat", 0) or 0))
                collected.append({
                    "Block_Height":         int(block.index),
                    "Tx_Hash":              str(getattr(l2tx, "l2_tx_id", "") or ""),
                    "Type":                 "L2",
                    "Amount":               float(amount_vsd),
                    "Timestamp":            int(getattr(l2tx, "timestamp", 0) or 0),
                    "Counterparty_Address": counterparty,
                })

    return collected


def _ledger_write_worker(block_index: int, new_entries: list,
                         owner_address: str) -> None:
    """Thread-worker: merges *new_entries* into the JSON ledger file.

    Holds _LOCAL_LEDGER_LOCK for the duration of the read-modify-write so
    concurrent daemon threads for adjacent blocks cannot corrupt the file.
    All exceptions are swallowed — the caller (apply_block path) must never
    crash because of ledger I/O.
    """
    if not new_entries:
        return
    try:
        with _LOCAL_LEDGER_LOCK:
            # ── Load existing ledger (or start fresh) ──────────────────────
            ledger: dict = {"owner": owner_address, "entries": []}
            if os.path.exists(_LOCAL_LEDGER_PATH):
                try:
                    with open(_LOCAL_LEDGER_PATH, "r", encoding="utf-8") as fh:
                        ledger = json.load(fh)
                    if not isinstance(ledger, dict):
                        ledger = {"owner": owner_address, "entries": []}
                    if "entries" not in ledger or not isinstance(ledger["entries"], list):
                        ledger["entries"] = []
                except (json.JSONDecodeError, OSError):
                    # Corrupted file — reset to avoid poisoning the whole ledger.
                    ledger = {"owner": owner_address, "entries": []}

            # ── Deduplicate by Tx_Hash ──────────────────────────────────────
            existing_hashes: set = {
                e.get("Tx_Hash", "") for e in ledger["entries"]
                if isinstance(e, dict)
            }
            appended = 0
            for entry in new_entries:
                if entry.get("Tx_Hash", "") not in existing_hashes:
                    ledger["entries"].append(entry)
                    existing_hashes.add(entry["Tx_Hash"])
                    appended += 1

            if appended == 0:
                return   # nothing new — skip the write entirely

            # ── Persist atomically ─────────────────────────────────────────
            ledger["owner"] = owner_address
            tmp_path = _LOCAL_LEDGER_PATH + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(ledger, fh, indent=2, ensure_ascii=False)
            os.replace(tmp_path, _LOCAL_LEDGER_PATH)   # atomic on POSIX + Windows
            log.debug(
                "sync_local_ledger: block=%d archived %d new entry(ies) "
                "(total=%d) for owner=%s",
                block_index, appended, len(ledger["entries"]),
                owner_address[:16],
            )
    except Exception as exc:   # pragma: no cover
        # Swallow ALL errors — disk full, permissions, etc. — so the main
        # chain loop is never interrupted by ledger I/O problems.
        log.warning("sync_local_ledger: write failed (block=%d): %s",
                    block_index, exc)


def sync_local_ledger(block_data, owner_address: str) -> None:
    """Archive all transactions involving *owner_address* from *block_data*
    into ``vsd_personal_ledger.json`` before the block is pruned.

    This function is **non-blocking**: extraction runs inline (cheap, pure
    Python) and the file I/O is dispatched to a short-lived daemon thread,
    so ``apply_block`` is never delayed.

    Parameters
    ──────────
    block_data    : Block  — the Block object about to be pruned / processed.
    owner_address : str    — the VSD address whose transactions to archive
                             (checked as both sender and receiver).

    Call site (inside your main block-loop, just before prune_async):

        OWNER_ADDRESS = "VSD<your_address>"
        sync_local_ledger(block, OWNER_ADDRESS)
        self._rolling_pruner.prune_async(block.index)
    """
    if not owner_address or not owner_address.strip():
        return   # no owner configured — silently skip

    try:
        # Extraction is fast (pure iteration, no I/O) so it runs inline on
        # the apply_block thread.  This keeps the daemon thread's work minimal
        # (just file I/O) and avoids passing the entire Block object across
        # thread boundaries.
        new_entries = _ledger_collect_entries(block_data, owner_address)
    except Exception as exc:
        log.warning("sync_local_ledger: extraction failed (block=%s): %s",
                    getattr(block_data, "index", "?"), exc)
        return

    if not new_entries:
        return   # nothing to archive — don't even spawn a thread

    # Dispatch I/O to a daemon thread so apply_block returns immediately.
    t = threading.Thread(
        target=_ledger_write_worker,
        args=(getattr(block_data, "index", -1), new_entries, owner_address),
        daemon=True,
        name=f"ledger-writer-{getattr(block_data, 'index', 0)}",
    )
    t.start()
