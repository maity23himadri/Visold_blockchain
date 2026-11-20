"""V4 regression tests for Audit Section 010: Compat, Source Identity & LRUCache."""

import hashlib
import importlib
import importlib.util
import json
import os
import stat
import time

import pytest

from visold.kernel import compat, source_identity
from visold.kernel.lru_cache import LRUCache


def test_compat_cuda_and_opencl_false_when_missing(monkeypatch):
    """_CUDA_AVAILABLE and _OPENCL_AVAILABLE are False when importlib.util.find_spec() returns None."""
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    reloaded = importlib.reload(compat)
    try:
        assert reloaded._CUDA_AVAILABLE is False
        assert reloaded._OPENCL_AVAILABLE is False
    finally:
        monkeypatch.undo()
        importlib.reload(compat)


def test_source_identity_unreadable_file_returns_unknown(tmp_path):
    """compute_node_logic_hash() returns 'unknown' when a source file is unreadable instead of trusting manifest."""
    pkg = tmp_path / "visold"
    pkg.mkdir()
    good_py = pkg / "a.py"
    good_py.write_text("x = 1\n", encoding="utf-8")
    bad_py = pkg / "b.py"
    bad_py.write_text("y = 2\n", encoding="utf-8")

    blob = source_identity.package_source_blob(str(pkg))
    full_sha = hashlib.sha256(blob).hexdigest()
    manifest = {
        "algorithm": "visold-package-source-v1",
        "package_source_sha256": full_sha,
        "source_file_count": 2,
    }
    (pkg / "_build_identity.json").write_text(json.dumps(manifest), encoding="utf-8")

    if os.geteuid() == 0:
        bad_py.unlink()
        bad_py.symlink_to(tmp_path / "nonexistent_target.py")
    else:
        bad_py.chmod(0o000)

    try:
        with pytest.raises(OSError):
            source_identity.package_source_blob(str(pkg))

        result = source_identity.compute_node_logic_hash(str(pkg))
        assert result == "unknown"
    finally:
        if os.geteuid() != 0 and bad_py.exists():
            bad_py.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_lru_cache_sweep_expired_bounds_scanned_entries():
    """_sweep_expired(max_scan=64) scans at most max_scan entries on put() when entries are live."""
    cache = LRUCache(capacity=1000, ttl=3600.0)
    for i in range(500):
        cache.put(f"k{i}", i)

    scan_count = 0
    orig_is_expired = cache._is_expired

    def counting_is_expired(ts: float) -> bool:
        nonlocal scan_count
        scan_count += 1
        return orig_is_expired(ts)

    cache._is_expired = counting_is_expired
    cache.put("new_key", 999)

    assert scan_count <= 64


def test_lru_cache_ttl_uses_monotonic_time_across_wall_clock_step(monkeypatch):
    """LRUCache uses monotonic time so backward wall-clock steps do not bypass TTL expiry."""
    wall_now = [1000.0]
    mono_now = [5000.0]
    monkeypatch.setattr(time, "time", lambda: wall_now[0])
    monkeypatch.setattr(time, "monotonic", lambda: mono_now[0])

    cache = LRUCache(capacity=10, ttl=10.0)
    cache.put("msg1", "payload")

    mono_now[0] = 5015.0
    wall_now[0] = 995.0
    assert cache.get("msg1") is None
