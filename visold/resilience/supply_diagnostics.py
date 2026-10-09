"""Bounded, privacy-preserving supply tracing for diagnostic builds.

This module observes balance mutation requests and block-level supply totals.
It never changes balances, commits/rolls back database work, or logs raw account
addresses. Diagnostic logging failures are intentionally non-fatal.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from contextlib import nullcontext
from typing import Any, Dict, Optional

from visold.kernel.config import Config
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, L2_WITHDRAW_ADDRESS


_DIAGNOSTICS_BY_STORAGE_ID: Dict[int, "SupplyDiagnostics"] = {}


class SupplyDiagnostics:
    """Write bounded JSONL records for balance mutations and block totals."""

    # Two files, each capped at 256 KiB: maximum diagnostic storage ~512 KiB.
    MAX_FILE_BYTES = 256 * 1024
    FILE_NAME = "visold_supply_diagnostics.log"

    def __init__(self, storage: Any, blockchain: Any, data_dir: Optional[str] = None):
        self.storage = storage
        self.blockchain = blockchain
        self._write_lock = threading.Lock()
        self._log_errors = 0
        self.data_dir = data_dir or getattr(Config, "DATA_DIR", "") or os.getcwd()
        try:
            os.makedirs(self.data_dir, exist_ok=True)
        except Exception:
            self.data_dir = os.path.expanduser("~/.visold")
            os.makedirs(self.data_dir, exist_ok=True)
        self.path = os.path.join(self.data_dir, self.FILE_NAME)
        self.backup_path = self.path + ".1"
        self.emit("diagnostic_started", backend="postgresql" if getattr(storage, "_pgx_enabled", False) else "sqlite",
                  privacy="account identifiers are SHA-256 prefixes; no raw addresses or secrets")

    @staticmethod
    def account_id(address: Any) -> str:
        """Stable pseudonymous identifier; do not store the actual address."""
        return hashlib.sha256(str(address).encode("utf-8", "replace")).hexdigest()[:16]

    @staticmethod
    def caller_site(skip: int = 2) -> Dict[str, Any]:
        """Return a short source call-site label without locals or arguments."""
        try:
            frame = sys._getframe(skip)
            filename = frame.f_code.co_filename.replace("\\", "/")
            marker = "/visold/"
            if marker in filename:
                filename = "visold/" + filename.rsplit(marker, 1)[1]
            else:
                filename = os.path.basename(filename)
            return {"caller_file": filename, "caller_line": int(frame.f_lineno),
                    "caller_func": frame.f_code.co_name}
        except Exception:
            return {"caller_file": "?", "caller_line": 0, "caller_func": "?"}

    def emit(self, event: str, **fields: Any) -> None:
        """Append one JSONL record; tracing must never interrupt node work."""
        record = {
            "ts": round(time.time(), 6),
            "event": str(event),
            "pid": os.getpid(),
            "thread": threading.current_thread().name[:64],
        }
        record.update(fields)
        try:
            line = (json.dumps(record, separators=(",", ":"), sort_keys=True,
                                default=lambda obj: type(obj).__name__) + "\n").encode("utf-8")
            # All current records are deliberately small. Avoid storing an
            # oversized record if a future call site supplies an unexpectedly
            # large field.
            if len(line) > 8192:
                line = (json.dumps({"ts": record["ts"], "event": event,
                                    "pid": record["pid"], "thread": record["thread"],
                                    "record_dropped": "oversized"}, separators=(",", ":")) + "\n").encode()
            with self._write_lock:
                try:
                    current_size = os.path.getsize(self.path)
                except OSError:
                    current_size = 0
                if current_size + len(line) > self.MAX_FILE_BYTES:
                    try:
                        if os.path.exists(self.backup_path):
                            os.remove(self.backup_path)
                        if os.path.exists(self.path):
                            os.replace(self.path, self.backup_path)
                    except OSError:
                        # Truncate only the current log if rotation is blocked.
                        try:
                            with open(self.path, "wb"):
                                pass
                        except OSError:
                            return
                with open(self.path, "ab") as fh:
                    fh.write(line)
        except Exception:
            self._log_errors += 1
            # Deliberately no logging fallback: writing to stdout/stderr could
            # corrupt Visold's TUI and conceal the original issue.

    def balance_snapshot(self) -> Dict[str, Any]:
        """Read canonical held supply and calculate scheduled issuance."""
        try:
            excludes = (Config.BURN_ADDRESS, L2_BRIDGE_ADDRESS, L2_WITHDRAW_ADDRESS)
            if getattr(self.storage, "_pgx_enabled", False):
                rows = self.storage._pg_fetch(
                    "SELECT COALESCE(SUM(balance_sat),0) AS total FROM accounts "
                    "WHERE address NOT IN ($1,$2,$3)", list(excludes))
                held = int(rows[0]["total"]) if rows else 0
            else:
                row = self.storage._conn().execute(
                    "SELECT COALESCE(SUM(CAST(balance AS INTEGER)),0) AS total "
                    "FROM balances WHERE address NOT IN (?,?,?)", excludes).fetchone()
                held = int(row["total"])
            height = int(self.storage.chain_height())
            issued = self.expected_issuance_sat(height)
            return {
                "height": height,
                "held_sat": held,
                "issued_sat": issued,
                "excess_sat": held - issued,
                "scan_ok": True,
            }
        except Exception as exc:
            return {"scan_ok": False, "scan_error_type": type(exc).__name__}

    def expected_issuance_sat(self, height: int) -> int:
        """Sum rewards exactly by reward epochs (not a per-block O(height) scan)."""
        h = max(0, int(height))
        if h == 0:
            return 0
        epoch_size = int(Config.REWARD_DECAY_BLOCKS)
        if epoch_size <= 0:
            return sum(int(self.blockchain.compute_reward_sat(i)) for i in range(1, h + 1))
        issued = 0
        first = 1
        while first <= h:
            epoch = first // epoch_size
            end = min(h, (epoch + 1) * epoch_size - 1)
            if end < first:  # defensive progress guard for unusual config values
                end = first
            reward = int(self.blockchain.compute_reward_sat(first))
            issued += (end - first + 1) * reward
            first = end + 1
        return issued

    def trace_direct_mutation(self, operation: str, address: Any, amount_sat: Any,
                              result: Any = None, error: Optional[BaseException] = None,
                              **extra: Any) -> None:
        fields = {
            "operation": operation,
            "account_id": self.account_id(address),
            "amount_sat": _int_or_none(amount_sat),
            "result_type": type(result).__name__ if error is None else None,
            "result_bool": result if isinstance(result, bool) and error is None else None,
            "error_type": type(error).__name__ if error is not None else None,
        }
        fields.update(self.caller_site(skip=3))
        fields.update(extra)
        self.emit("balance_mutation", **fields)


def _int_or_none(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _install_batch_proxy_wrappers(diag: SupplyDiagnostics) -> None:
    """Instrument in-block writes, which bypass Storage.credit_sat/debit_sat."""
    try:
        from visold.state.batch_proxy import _StorageBatchProxy
    except Exception as exc:
        diag.emit("instrumentation_unavailable", component="batch_proxy",
                  error_type=type(exc).__name__)
        return

    for method_name, direction in (("credit_sat", 1), ("debit_sat", -1)):
        original = getattr(_StorageBatchProxy, method_name, None)
        marker = "_supply_diag_wrapped_" + method_name
        if original is None or getattr(original, marker, False):
            continue

        def make_wrapper(orig, name, sign):
            def wrapped(proxy, address, amount_sat, *args, **kwargs):
                runtime_diag = _DIAGNOSTICS_BY_STORAGE_ID.get(id(proxy._real), diag)
                amount = _int_or_none(amount_sat)
                had_value = address in proxy._balances
                before = proxy._balances.get(address)
                caller = runtime_diag.caller_site(skip=2)
                try:
                    result = orig(proxy, address, amount_sat, *args, **kwargs)
                except BaseException as exc:
                    runtime_diag.emit("batch_balance_mutation", operation=name,
                                      account_id=runtime_diag.account_id(address), amount_sat=amount,
                                      requested_delta_sat=(sign * amount if amount is not None else None),
                                      before_sat=before, after_sat=proxy._balances.get(address),
                                      result="raised", error_type=type(exc).__name__, **caller)
                    raise
                after = proxy._balances.get(address)
                if before is None and after is not None and amount is not None:
                    # If this call first touched the account, infer the state
                    # immediately before this operation from its successful delta.
                    if name == "credit_sat":
                        before = after - amount
                    elif result is True:
                        before = after + amount
                runtime_diag.emit("batch_balance_mutation", operation=name,
                                  account_id=runtime_diag.account_id(address), amount_sat=amount,
                                  requested_delta_sat=(sign * amount if amount is not None else None),
                                  before_sat=before, after_sat=after, account_preloaded=had_value,
                                  result_bool=result if isinstance(result, bool) else None,
                                  **caller)
                return result
            setattr(wrapped, marker, True)
            return wrapped

        setattr(_StorageBatchProxy, method_name,
                make_wrapper(original, method_name, direction))


def install_supply_diagnostics(storage: Any, blockchain: Any, data_dir: Optional[str] = None) -> SupplyDiagnostics:
    """Attach passive diagnostics to the live node after safety overlays install."""
    existing = getattr(blockchain, "_supply_diagnostics", None)
    if isinstance(existing, SupplyDiagnostics):
        return existing
    diag = SupplyDiagnostics(storage, blockchain, data_dir=data_dir)
    _DIAGNOSTICS_BY_STORAGE_ID[id(storage)] = diag
    setattr(blockchain, "_supply_diagnostics", diag)

    # Wrap write-through Storage methods after the hardening overlay, so this
    # observes their final guarded behavior rather than replacing those guards.
    for name in ("credit_sat", "debit_sat"):
        original = getattr(storage, name, None)
        if original is None or getattr(original, "_supply_diag_wrapped", False):
            continue

        def make_storage_amount_wrapper(orig, operation):
            def wrapped(address, amount_sat, *args, **kwargs):
                callsite = diag.caller_site(skip=2)
                try:
                    result = orig(address, amount_sat, *args, **kwargs)
                except BaseException as exc:
                    diag.trace_direct_mutation(operation, address, amount_sat,
                                               error=exc, **callsite)
                    raise
                diag.trace_direct_mutation(operation, address, amount_sat,
                                           result=result, **callsite)
                return result
            wrapped._supply_diag_wrapped = True
            return wrapped

        setattr(storage, name, make_storage_amount_wrapper(original, name))

    # Absolute setters and recovery paths can move balances without a credit()
    # call, so log their target balances without recording raw addresses.
    for name in ("set_balance", "restore_accounts", "wipe_all_balances", "_flush_block_batch"):
        original = getattr(storage, name, None)
        if original is None or getattr(original, "_supply_diag_wrapped", False):
            continue

        if name == "set_balance":
            def make_set_wrapper(orig):
                def wrapped(address, balance, *args, **kwargs):
                    try:
                        before = int(storage._get_balance_satoshi(address))
                    except Exception:
                        before = None
                    try:
                        result = orig(address, balance, *args, **kwargs)
                    except BaseException as exc:
                        diag.emit("storage_set_balance", account_id=diag.account_id(address),
                                  requested_value_sat=_int_or_none(balance), before_sat=before,
                                  result="raised", error_type=type(exc).__name__,
                                  **diag.caller_site(skip=2))
                        raise
                    try:
                        after = int(storage._get_balance_satoshi(address))
                    except Exception:
                        after = None
                    # This method treats an int as satoshi; floats are VSD.
                    if isinstance(balance, int):
                        target_sat = int(balance)
                    else:
                        try:
                            target_sat = int(round(float(balance) * Config.SATOSHI_PER_VSD))
                        except (TypeError, ValueError, OverflowError):
                            target_sat = None
                    diag.emit("storage_set_balance", account_id=diag.account_id(address),
                              requested_value_sat=target_sat, before_sat=before,
                              after_sat=after,
                              delta_sat=(after - before if after is not None and before is not None else None),
                              result="ok", **diag.caller_site(skip=2))
                    return result
                wrapped._supply_diag_wrapped = True
                return wrapped
            replacement = make_set_wrapper(original)
        elif name == "restore_accounts":
            def make_restore_wrapper(orig):
                def wrapped(snap, *args, **kwargs):
                    caller = diag.caller_site(skip=2)
                    try:
                        count = len(snap) if hasattr(snap, "__len__") else None
                        for addr, value in (snap.items() if hasattr(snap, "items") else []):
                            try:
                                target = int(value[0])
                                existed = bool(value[3]) if len(value) > 3 else None
                            except Exception:
                                target, existed = None, None
                            diag.emit("storage_restore_account", account_id=diag.account_id(addr),
                                      target_balance_sat=target, existed=existed, **caller)
                        result = orig(snap, *args, **kwargs)
                    except BaseException as exc:
                        diag.emit("storage_restore_accounts", count=count if "count" in locals() else None,
                                  result="raised", error_type=type(exc).__name__, **caller)
                        raise
                    diag.emit("storage_restore_accounts", count=count, result="ok", **caller)
                    return result
                wrapped._supply_diag_wrapped = True
                return wrapped
            replacement = make_restore_wrapper(original)
        elif name == "wipe_all_balances":
            def make_wipe_wrapper(orig):
                def wrapped(*args, **kwargs):
                    caller = diag.caller_site(skip=2)
                    diag.emit("storage_wipe_all_balances", phase="begin", **caller)
                    try:
                        result = orig(*args, **kwargs)
                    except BaseException as exc:
                        diag.emit("storage_wipe_all_balances", phase="error",
                                  error_type=type(exc).__name__, **caller)
                        raise
                    diag.emit("storage_wipe_all_balances", phase="complete", **caller)
                    return result
                wrapped._supply_diag_wrapped = True
                return wrapped
            replacement = make_wipe_wrapper(original)
        else:  # _flush_block_batch
            def make_flush_wrapper(orig):
                def wrapped(bal_updates, *args, **kwargs):
                    caller = diag.caller_site(skip=2)
                    try:
                        count = len(bal_updates)
                    except Exception:
                        count = None
                    diag.emit("storage_balance_batch", phase="begin", count=count, **caller)
                    try:
                        for addr, target in (bal_updates.items() if hasattr(bal_updates, "items") else []):
                            diag.emit("storage_balance_batch_account",
                                      account_id=diag.account_id(addr),
                                      target_balance_sat=_int_or_none(target), **caller)
                        result = orig(bal_updates, *args, **kwargs)
                    except BaseException as exc:
                        diag.emit("storage_balance_batch", phase="error", count=count,
                                  error_type=type(exc).__name__, **caller)
                        raise
                    diag.emit("storage_balance_batch", phase="complete", count=count, **caller)
                    return result
                wrapped._supply_diag_wrapped = True
                return wrapped
            replacement = make_flush_wrapper(original)
        setattr(storage, name, replacement)

    _install_batch_proxy_wrappers(diag)

    # One supply snapshot before and after each block application pinpoints the
    # first transition from conserved to over-issued supply. Hold the existing
    # RLock for consistency; the underlying implementation already uses it.
    original_apply = getattr(blockchain, "apply_block", None)
    if original_apply is not None and not getattr(original_apply, "_supply_diag_wrapped", False):
        def wrapped_apply_block(block, *args, **kwargs):
            callsite = diag.caller_site(skip=2)
            block_index = _int_or_none(getattr(block, "index", None))
            raw_hash = getattr(block, "hash", None)
            if callable(raw_hash):
                try:
                    raw_hash = raw_hash()
                except Exception:
                    raw_hash = None
            block_hash_id = hashlib.sha256(str(raw_hash).encode()).hexdigest()[:12] if raw_hash else None
            lock = getattr(blockchain, "_lock", None)
            context = lock if hasattr(lock, "__enter__") and hasattr(lock, "__exit__") else nullcontext()
            with context:
                before = diag.balance_snapshot()
                diag.emit("block_apply_started", block_index=block_index,
                          block_hash_id=block_hash_id, supply_before=before, **callsite)
                result = None
                error_type = None
                try:
                    result = original_apply(block, *args, **kwargs)
                    return result
                except BaseException as exc:
                    error_type = type(exc).__name__
                    raise
                finally:
                    after = diag.balance_snapshot()
                    diag.emit("block_apply_finished", block_index=block_index,
                              block_hash_id=block_hash_id,
                              result_bool=result if isinstance(result, bool) else None,
                              result_type=type(result).__name__ if error_type is None else None,
                              error_type=error_type,
                              held_delta_sat=(after.get("held_sat", 0) - before.get("held_sat", 0)
                                              if before.get("scan_ok") and after.get("scan_ok") else None),
                              issued_delta_sat=(after.get("issued_sat", 0) - before.get("issued_sat", 0)
                                                if before.get("scan_ok") and after.get("scan_ok") else None),
                              supply_before=before, supply_after=after, **callsite)
        wrapped_apply_block._supply_diag_wrapped = True
        blockchain.apply_block = wrapped_apply_block

    diag.emit("instrumentation_installed",
              methods=["Storage.credit_sat", "Storage.debit_sat", "Storage.set_balance",
                       "Storage.restore_accounts", "Storage.wipe_all_balances",
                       "Storage._flush_block_batch", "_StorageBatchProxy.credit_sat",
                       "_StorageBatchProxy.debit_sat", "Blockchain.apply_block"])
    return diag
