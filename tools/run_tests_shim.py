#!/usr/bin/env python3
"""Minimal pytest-compatible runner for the Visold ``tests/`` directory.

pytest is not installed in this sandbox and network access is disabled, so this
shim loads the test modules directly.  It implements the subset of pytest that
the Visold suites use:

  * module-level ``test_*`` functions, with the fixtures ``monkeypatch``,
    ``tmp_path``, ``capsys`` and ``caplog``;
  * ``unittest.TestCase`` classes (run through unittest).

Each test runs under a SIGALRM watchdog, so a deadlock is reported as a failure
instead of hanging the whole run.  Output is captured per test and printed only
for failures.  Any fixture name not listed above is reported as an error rather
than silently skipped.

Usage, from the Visold root directory:

    python3 tools/run_tests_shim.py                      # every tests/test_*.py
    python3 tools/run_tests_shim.py tests/test_x.py      # selected files
    python3 tools/run_tests_shim.py -k deadlock          # name filter
    python3 tools/run_tests_shim.py --timeout 120 --report out.json
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import importlib.util
import inspect
import io
import json
import logging
import os
import pathlib
import shutil
import signal
import sys
import tempfile
import time
import traceback
import unittest
from collections import namedtuple

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
NOTSET = object()
SUPPORTED_FIXTURES = ("monkeypatch", "tmp_path", "capsys", "caplog")

_CaptureResult = namedtuple("CaptureResult", ["out", "err"])


class _Timeout(BaseException):  # BaseException: broad "except Exception" in code under test must not swallow it
    pass


def _import_dotted(path: str):
    """Resolve 'pkg.mod.Class.attr' into (owner, attr) for string-form setattr."""
    parts = path.split(".")
    for i in range(len(parts) - 1, 0, -1):
        try:
            owner = importlib.import_module(".".join(parts[:i]))
        except ImportError:
            continue
        for part in parts[i:-1]:
            owner = getattr(owner, part)
        return owner, parts[-1]
    raise ImportError(f"cannot resolve {path!r}")


class _MonkeyPatch:
    """Subset of pytest.MonkeyPatch; every change is undone after the test."""

    def __init__(self):
        self._undo = []

    def setattr(self, target, name, value=NOTSET, raising=True):
        if isinstance(target, str):
            value = name
            target, name = _import_dotted(target)
        if raising and not hasattr(target, name):
            raise AttributeError(f"{target!r} has no attribute {name!r}")
        if inspect.isclass(target):
            old = target.__dict__.get(name, NOTSET)
        else:
            old = getattr(target, name, NOTSET)

        def restore(target=target, name=name, old=old):
            if old is NOTSET:
                if hasattr(target, name):
                    delattr(target, name)
            else:
                setattr(target, name, old)

        self._undo.append(restore)
        setattr(target, name, value)

    def delattr(self, target, name, raising=True):
        if not hasattr(target, name):
            if raising:
                raise AttributeError(f"{target!r} has no attribute {name!r}")
            return
        old = getattr(target, name)
        self._undo.append(lambda: setattr(target, name, old))
        delattr(target, name)

    def setitem(self, dic, name, value):
        had = name in dic
        old = dic.get(name)

        def restore():
            if had:
                dic[name] = old
            else:
                dic.pop(name, None)

        self._undo.append(restore)
        dic[name] = value

    def delitem(self, dic, name, raising=True):
        if name not in dic:
            if raising:
                raise KeyError(name)
            return
        old = dic[name]
        self._undo.append(lambda: dic.__setitem__(name, old))
        del dic[name]

    def setenv(self, name, value, prepend=None):
        value = str(value)
        if prepend and name in os.environ:
            value = value + prepend + os.environ[name]
        self.setitem(os.environ, name, value)

    def delenv(self, name, raising=True):
        self.delitem(os.environ, name, raising)

    def syspath_prepend(self, path):
        path = str(path)
        sys.path.insert(0, path)
        self._undo.append(lambda: sys.path.remove(path) if path in sys.path else None)

    def chdir(self, path):
        old = os.getcwd()
        os.chdir(path)
        self._undo.append(lambda: os.chdir(old))

    def undo(self):
        while self._undo:
            self._undo.pop()()


class _Capsys:
    """Reads what the test wrote to the per-test stdout/stderr buffers."""

    def __init__(self, out, err):
        self._out, self._err = out, err

    def readouterr(self):
        result = _CaptureResult(self._out.getvalue(), self._err.getvalue())
        for buf in (self._out, self._err):
            buf.seek(0)
            buf.truncate(0)
        return result


class _CaplogHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.NOTSET)
        self.records = []

    def emit(self, record):
        self.records.append(record)


class _Caplog:
    """Subset of pytest's caplog: text, records, messages, set_level, clear."""

    def __init__(self):
        self.handler = _CaplogHandler()
        self.handler.setFormatter(
            logging.Formatter("%(levelname)-8s %(name)s:%(filename)s:%(lineno)d %(message)s"))
        self._logger_levels = []

    def install(self):
        logging.getLogger().addHandler(self.handler)

    def uninstall(self):
        logging.getLogger().removeHandler(self.handler)
        for logger, level in reversed(self._logger_levels):
            logger.setLevel(level)

    @property
    def records(self):
        return self.handler.records

    @property
    def messages(self):
        return [r.getMessage() for r in self.handler.records]

    @property
    def text(self):
        return "\n".join(self.handler.format(r) for r in self.handler.records)

    def set_level(self, level, logger=None):
        target = logging.getLogger(logger)
        self._logger_levels.append((target, target.level))
        target.setLevel(level)

    def clear(self):
        self.handler.records.clear()


class _Fixtures:
    """Creates fixture objects lazily and tears them down after one test."""

    def __init__(self, out_buf, err_buf):
        self._out, self._err = out_buf, err_buf
        self._made = {}
        self._tmp_dirs = []

    def get(self, name):
        if name not in self._made:
            if name == "monkeypatch":
                self._made[name] = _MonkeyPatch()
            elif name == "tmp_path":
                path = pathlib.Path(tempfile.mkdtemp(prefix="vsd_shim_"))
                self._tmp_dirs.append(path)
                self._made[name] = path
            elif name == "capsys":
                self._made[name] = _Capsys(self._out, self._err)
            elif name == "caplog":
                cap = _Caplog()
                cap.install()
                self._made[name] = cap
            else:
                raise RuntimeError(f"unsupported fixture {name!r}")
        return self._made[name]

    def teardown(self):
        if "monkeypatch" in self._made:
            self._made["monkeypatch"].undo()
        if "caplog" in self._made:
            self._made["caplog"].uninstall()
        for path in self._tmp_dirs:
            shutil.rmtree(path, ignore_errors=True)


def _alarm(_signum, _frame):
    raise _Timeout("test exceeded the per-test watchdog")


def _load_module(path: pathlib.Path):
    name = "vsd_shim_" + path.stem
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _run_function(fn, timeout: int):
    """Run one module-level test function. Returns (status, detail)."""
    params = inspect.signature(fn).parameters
    unsupported = [p for p in params if p not in SUPPORTED_FIXTURES]
    if unsupported:
        return "ERROR", f"unsupported fixture(s) {unsupported} in {fn.__name__}"

    out_buf, err_buf = io.StringIO(), io.StringIO()
    fixtures = _Fixtures(out_buf, err_buf)
    previous_handler = signal.signal(signal.SIGALRM, _alarm)
    status, detail = "PASS", ""
    try:
        kwargs = {p: fixtures.get(p) for p in params}
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            signal.alarm(timeout)
            try:
                fn(**kwargs)
            finally:
                signal.alarm(0)
    except _Timeout as exc:
        status, detail = "ERROR", f"TIMEOUT after {timeout}s: {exc}"
    except AssertionError as exc:
        status = "FAIL"
        detail = "".join(traceback.format_exception(exc)).rstrip()
    except BaseException as exc:  # noqa: BLE001 - report every failure mode
        status = "ERROR"
        detail = "".join(traceback.format_exception(exc)).rstrip()
    finally:
        signal.signal(signal.SIGALRM, previous_handler)
        try:
            fixtures.teardown()
        except Exception:  # noqa: BLE001
            status = "ERROR"
            detail += "\nteardown failed:\n" + traceback.format_exc()
    captured = out_buf.getvalue() + err_buf.getvalue()
    if status != "PASS" and captured.strip():
        detail += "\n--- captured output ---\n" + captured.rstrip()
    return status, detail


def _run_unittest_class(cls, module_name: str, timeout: int, name_filter: str):
    results = []
    loader = unittest.TestLoader()
    for name in loader.getTestCaseNames(cls):
        test_id = f"{module_name}::{cls.__name__}::{name}"
        if name_filter and name_filter not in test_id:
            continue
        suite = unittest.TestSuite([cls(name)])
        previous_handler = signal.signal(signal.SIGALRM, _alarm)
        started = time.monotonic()
        result = unittest.TestResult()
        signal.alarm(timeout)
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                suite.run(result)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)
        elapsed = time.monotonic() - started
        if result.errors or result.failures:
            tb = "".join((result.errors or result.failures)[0][1])
            status = "FAIL" if result.failures else "ERROR"
            results.append((test_id, status, elapsed, tb))
        elif result.skipped:
            results.append((test_id, "SKIP", elapsed, result.skipped[0][1]))
        else:
            results.append((test_id, "PASS", elapsed, ""))
    return results


def collect_and_run(files, name_filter: str, timeout: int, on_record=None):
    records = []

    def emit(rec):
        records.append(rec)
        if on_record is not None:
            on_record(rec)

    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(TESTS))
    os.chdir(ROOT)
    for path in files:
        module_name = path.stem
        try:
            module = _load_module(path)
        except BaseException as exc:  # noqa: BLE001
            emit((f"{module_name}::<import>", "ERROR", 0.0,
                  "".join(traceback.format_exception(exc))))
            continue
        for attr_name, obj in vars(module).items():
            if inspect.isclass(obj) and issubclass(obj, unittest.TestCase) \
                    and obj.__module__ == module.__name__:
                for rec in _run_unittest_class(obj, module_name, timeout, name_filter):
                    emit(rec)
        for attr_name in sorted(vars(module)):
            obj = vars(module)[attr_name]
            if not (inspect.isfunction(obj) and obj.__module__ == module.__name__
                    and attr_name.startswith("test")):
                continue
            test_id = f"{module_name}::{attr_name}"
            if name_filter and name_filter not in test_id:
                continue
            started = time.monotonic()
            status, detail = _run_function(obj, timeout)
            emit((test_id, status, time.monotonic() - started, detail))
    return records


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("files", nargs="*", help="test files (default: tests/test_*.py)")
    parser.add_argument("-k", dest="name_filter", default="", help="substring filter on test id")
    parser.add_argument("--timeout", type=int, default=600, help="per-test watchdog in seconds")
    parser.add_argument("--report", default="", help="write JSON results to this path")
    parser.add_argument("-q", action="store_true", help="only print failures and the summary")
    args = parser.parse_args(argv)

    if args.files:
        files = [pathlib.Path(f).resolve() for f in args.files]
    else:
        files = sorted(TESTS.glob("test_*.py"))

    counts = {}

    def show(rec):
        test_id, status, elapsed, detail = rec
        counts[status] = counts.get(status, 0) + 1
        if status != "PASS" or not args.q:
            print(f"{status:5s} {elapsed:8.2f}s  {test_id}", flush=True)
        if status not in ("PASS", "SKIP") and detail:
            print(detail, flush=True)
            print("-" * 72, flush=True)

    started = time.monotonic()
    records = collect_and_run(files, args.name_filter, args.timeout, on_record=show)
    total = time.monotonic() - started
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no tests collected"
    print(f"\n== {len(records)} collected: {summary} in {total:.1f}s", flush=True)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump([{"id": t, "status": s, "seconds": round(e, 3), "detail": d}
                       for t, s, e, d in records], fh, indent=2)
    bad = counts.get("FAIL", 0) + counts.get("ERROR", 0)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
