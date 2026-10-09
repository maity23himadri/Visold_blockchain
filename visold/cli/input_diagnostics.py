"""Bounded, privacy-preserving diagnostics for Visold CLI input stalls.

This module records input lifecycle/state only. It never records typed text or
secret material. It is intended for the diagnostic build, not as a general
application logger.
"""
from __future__ import annotations

import json
import os
import platform
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

_MAX_FILE_BYTES = 256 * 1024
_MAX_ROTATED_FILES = 1
_WATCHDOG_INTERVAL = 10.0
_STACK_DUMP_AFTER = 30.0
_STACK_DUMP_REPEAT = 60.0


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _safe_value(value: Any) -> Any:
    """Keep log fields small and JSON-compatible; never stringify unknown objects."""
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, str):
            return value[:200]
        return value
    if isinstance(value, dict):
        return {str(k)[:80]: _safe_value(v) for k, v in list(value.items())[:40]}
    if isinstance(value, (tuple, list)):
        return [_safe_value(v) for v in value[:40]]
    return type(value).__name__


class InputDiagnostics:
    """Small rotating JSONL log plus read-state watchdog."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._write_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._next_id = 1
        self._active: Dict[int, Dict[str, Any]] = {}
        self._rate_limit: Dict[str, Dict[str, Any]] = {}
        self._watchdog_started = False
        self._path = Path(path).expanduser() if path is not None else self._choose_path()
        self.event(
            "diagnostic_session_started",
            python=sys.version.split()[0],
            platform=platform.platform()[:180],
            cwd=os.getcwd()[:200],
            log_path=str(self._path)[:250],
            max_log_bytes=_MAX_FILE_BYTES,
            max_rotated_files=_MAX_ROTATED_FILES,
            typed_content_logging=False,
        )

    @staticmethod
    def _choose_path() -> Path:
        override = os.environ.get("VISOLD_INPUT_DIAG_PATH", "").strip()
        if override:
            return Path(override).expanduser()
        # Prefer the directory from which the user launches Visold: it is easy
        # to locate and share in Termux. Fall back to ~/.visold if not writable.
        return Path.cwd() / "visold_input_diagnostics.log"

    @property
    def path(self) -> Path:
        return self._path

    def _rotate_if_needed(self, incoming_size: int) -> None:
        try:
            current_size = self._path.stat().st_size if self._path.exists() else 0
        except OSError:
            current_size = 0
        if current_size + incoming_size <= _MAX_FILE_BYTES:
            return
        try:
            if _MAX_ROTATED_FILES:
                old = self._path.with_name(self._path.name + ".1")
                try:
                    old.unlink(missing_ok=True)
                except OSError:
                    pass
                if self._path.exists():
                    self._path.replace(old)
            else:
                self._path.write_bytes(b"")
        except OSError:
            try:
                self._path.write_bytes(b"")
            except OSError:
                pass

    def event(self, name: str, **fields: Any) -> None:
        record = {
            "time_utc": _utc_now(),
            "mono": round(time.monotonic(), 3),
            "pid": os.getpid(),
            "thread": threading.current_thread().name[:80],
            "event": str(name)[:80],
        }
        record.update({str(k)[:80]: _safe_value(v) for k, v in fields.items()})
        try:
            encoded = (json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
            # Prevent malformed/oversized diagnostics from dominating the file.
            if len(encoded) > 24 * 1024:
                record = {k: v for k, v in record.items() if k not in ("stacks", "stack")}
                record["record_truncated"] = True
                encoded = (json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
            with self._write_lock:
                try:
                    self._path.parent.mkdir(parents=True, exist_ok=True)
                    self._rotate_if_needed(len(encoded))
                    with self._path.open("ab") as handle:
                        handle.write(encoded)
                except OSError:
                    # Fall back to the private Termux home directory if the
                    # working directory is shared storage or no longer writable.
                    fallback = Path.home() / ".visold" / "visold_input_diagnostics.log"
                    try:
                        fallback.parent.mkdir(parents=True, exist_ok=True)
                        self._path = fallback
                        self._rotate_if_needed(len(encoded))
                        with self._path.open("ab") as handle:
                            handle.write(encoded)
                    except OSError:
                        # Diagnostics must never break the node or its input path.
                        pass
        except Exception:
            pass

    def event_rate_limited(
        self, name: str, rate_key: str, *, interval_s: float = 5.0, **fields: Any
    ) -> None:
        """Log repeated state changes at most once per interval, with a count."""
        now = time.monotonic()
        key = f"{name}:{rate_key}"
        with self._state_lock:
            entry = self._rate_limit.get(key)
            if entry is not None and now - entry["last_emit"] < interval_s:
                entry["suppressed"] += 1
                return
            suppressed = entry["suppressed"] if entry is not None else 0
            self._rate_limit[key] = {"last_emit": now, "suppressed": 0}
        self.event(name, suppressed_repeats=suppressed, **fields)

    def _begin_operation(self, kind: str, operation_type: str) -> int:
        with self._state_lock:
            operation_id = self._next_id
            self._next_id += 1
            now = time.monotonic()
            self._active[operation_id] = {
                "kind": kind,
                "operation_type": operation_type,
                "owner_thread": threading.get_ident(),
                "started": now,
                "state": "starting",
                "bytes_read": 0,
                "read_calls": 0,
                "polls": 0,
                "ready": 0,
                "enter_seen": False,
                "last_snapshot": 0.0,
            }
            if not self._watchdog_started:
                self._watchdog_started = True
                threading.Thread(
                    target=self._watchdog_loop,
                    name="visold-input-diag-watchdog",
                    daemon=True,
                ).start()
        event_name = "input_read_started" if operation_type == "read" else "ui_activity_started"
        self.event(event_name, operation_id=operation_id, kind=kind, operation_type=operation_type)
        return operation_id

    def begin_read(self, kind: str) -> int:
        return self._begin_operation(kind, "read")

    def begin_activity(self, kind: str) -> int:
        """Watch a potentially blocking UI action even when no prompt is active."""
        return self._begin_operation(kind, "activity")

    def update(self, read_id: Optional[int], **fields: Any) -> None:
        if read_id is None:
            return
        with self._state_lock:
            state = self._active.get(read_id)
            if state is not None:
                for key, value in fields.items():
                    state[key] = value

    def count_poll(self, read_id: Optional[int], *, ready: bool = False) -> None:
        if read_id is None:
            return
        with self._state_lock:
            state = self._active.get(read_id)
            if state is not None:
                state["polls"] += 1
                if ready:
                    state["ready"] += 1

    def bytes_received(self, read_id: Optional[int], chunk: bytes) -> None:
        if read_id is None:
            return
        with self._state_lock:
            state = self._active.get(read_id)
            if state is None:
                return
            state["read_calls"] += 1
            state["bytes_read"] += len(chunk)
            kind = state.get("kind", "line")
            calls = state["read_calls"]
            total = state["bytes_read"]
            has_enter = (10 in chunk) or (13 in chunk)
            has_edit = any(v in chunk for v in (8, 127, 21, 4, 27))
            if has_enter:
                state["enter_seen"] = True
        # Do not log characters, byte values, secret lengths, or actual text.
        if kind == "secret":
            if has_enter or has_edit or calls % 8 == 0:
                self.event("secret_input_activity", read_id=read_id,
                           chunk_received=True, enter_like=has_enter,
                           editing_control_seen=has_edit)
        elif has_enter or has_edit or calls % 8 == 0:
            self.event("input_bytes_received", read_id=read_id,
                       chunk_size=len(chunk), total_bytes=total,
                       contains_cr=(13 in chunk), contains_lf=(10 in chunk),
                       contains_edit_control=has_edit)

    def heartbeat(self, read_id: Optional[int], **fields: Any) -> None:
        if read_id is None:
            return
        with self._state_lock:
            state = self._active.get(read_id)
            if state is None:
                return
            kind = state.get("kind", "line")
            base = {
                "elapsed_s": round(time.monotonic() - state["started"], 1),
                "state": state.get("state"),
                "polls": state.get("polls", 0),
                "ready": state.get("ready", 0),
                "read_calls": state.get("read_calls", 0),
                "enter_seen": state.get("enter_seen", False),
            }
            if kind != "secret":
                base["bytes_read"] = state.get("bytes_read", 0)
            state["last_heartbeat"] = time.monotonic()
        base.update(fields)
        self.event("input_wait_heartbeat", read_id=read_id, kind=kind, **base)

    def _finish_operation(
        self, operation_id: Optional[int], status: str, operation_type: str, **fields: Any
    ) -> None:
        if operation_id is None:
            return
        with self._state_lock:
            state = self._active.pop(operation_id, None)
        data: Dict[str, Any] = {
            "operation_id": operation_id, "operation_type": operation_type, "status": status
        }
        if state:
            data.update({
                "kind": state.get("kind"),
                "elapsed_s": round(time.monotonic() - state["started"], 3),
            })
            if operation_type == "read":
                data.update({
                    "polls": state.get("polls", 0),
                    "ready": state.get("ready", 0),
                    "read_calls": state.get("read_calls", 0),
                    "enter_seen": state.get("enter_seen", False),
                })
                if state.get("kind") != "secret":
                    data["bytes_read"] = state.get("bytes_read", 0)
        data.update(fields)
        event_name = "input_read_finished" if operation_type == "read" else "ui_activity_finished"
        self.event(event_name, **data)

    def finish_read(self, read_id: Optional[int], status: str, **fields: Any) -> None:
        self._finish_operation(read_id, status, "read", **fields)

    def finish_activity(self, activity_id: Optional[int], status: str, **fields: Any) -> None:
        self._finish_operation(activity_id, status, "activity", **fields)

    def _watchdog_loop(self) -> None:
        while True:
            time.sleep(_WATCHDOG_INTERVAL)
            now = time.monotonic()
            snapshots = []
            with self._state_lock:
                active_reads_by_thread = {
                    state.get("owner_thread") for state in self._active.values()
                    if state.get("operation_type") == "read"
                }
                for operation_id, state in self._active.items():
                    age = now - state["started"]
                    last = state.get("last_snapshot", 0.0)
                    if age < _STACK_DUMP_AFTER or (last != 0.0 and now - last < _STACK_DUMP_REPEAT):
                        continue
                    # A nested read stack also contains its parent menu-dispatch
                    # frames, so don't write a duplicate parent snapshot.
                    if (state.get("operation_type") == "activity"
                            and state.get("owner_thread") in active_reads_by_thread):
                        continue
                    state["last_snapshot"] = now
                    snapshot = {
                        "operation_id": operation_id,
                        "operation_type": state.get("operation_type"),
                        "kind": state.get("kind"),
                        "age_s": round(age, 1),
                        "state": state.get("state"),
                    }
                    if state.get("operation_type") == "read":
                        snapshot.update({
                            "polls": state.get("polls", 0),
                            "ready": state.get("ready", 0),
                            "read_calls": state.get("read_calls", 0),
                            "enter_seen": state.get("enter_seen", False),
                        })
                        if state.get("kind") != "secret":
                            snapshot["bytes_read"] = state.get("bytes_read", 0)
                    snapshots.append(snapshot)
            for snapshot in snapshots:
                try:
                    frames = sys._current_frames()
                    stacks = {}
                    for thread in threading.enumerate():
                        frame = frames.get(thread.ident)
                        if frame is not None:
                            # Store frame locations, not locals; six frames per thread
                            # keep snapshots useful within the bounded log record size.
                            frames_text = traceback.format_stack(frame)[-6:]
                            key = f"{thread.name[:60]}#{thread.ident}"
                            stacks[key] = [line.strip()[-180:] for line in frames_text]
                    operation_type = snapshot.get("operation_type")
                    event_name = (
                        "input_watchdog_stack_snapshot" if operation_type == "read"
                        else "ui_activity_watchdog_stack_snapshot"
                    )
                    self.event(event_name, **snapshot, stacks=stacks)
                except Exception as exc:
                    self.event(
                        "input_watchdog_snapshot_error", operation_id=snapshot.get("operation_id"),
                        error_type=type(exc).__name__
                    )


INPUT_DIAG = InputDiagnostics()
