"""Section 117 V4 Regression Tests: Panic Breaker, Hardened Core, Sentinel, Safety Invariants."""

import json
import types
import urllib.request
import pytest

from visold.kernel.config import Config
from visold.resilience.hardened_core import (
    SystemInvariantGate,
    TimestampAnomalyError,
)
from visold.resilience.safety_invariants import SafetyInvariantChecker
from visold.resilience.sentinel import SentinelNode


def test_safety_invariant_check_safety_detects_finality_conflict():
    """SafetyInvariantChecker._check_safety() detects two conflicting finalized blocks at the same height."""
    blk_a = types.SimpleNamespace(
        index=1, finalized=True, block_hash="a" * 64, prev_hash="0" * 64
    )
    blk_b = types.SimpleNamespace(
        index=1, finalized=True, block_hash="b" * 64, prev_hash="0" * 64
    )
    blk_0 = types.SimpleNamespace(
        index=0, finalized=True, block_hash="0" * 64, prev_hash="0" * 64
    )

    class _FakeStorage:
        blocks_by_height = {0: [blk_0], 1: [blk_a, blk_b]}

        def get_block(self, idx):
            items = self.blocks_by_height.get(idx, [])
            return items[0] if items else None

        def get_blocks_at_height(self, idx):
            return list(self.blocks_by_height.get(idx, []))

    checker = SafetyInvariantChecker(
        storage=_FakeStorage(),
        blockchain=types.SimpleNamespace(height=lambda: 1),
        network=types.SimpleNamespace(active_peer_count=lambda: []),
    )
    violations = []
    ok = checker._check_safety(violations, full_scan=True)
    assert ok is False
    assert len(violations) == 1
    assert "conflicting finality" in violations[0].lower()


def test_assert_timestamp_valid_nan_inf_raises_timestamp_anomaly_error():
    """SystemInvariantGate.assert_timestamp_valid() raises TimestampAnomalyError on NaN and Infinity."""
    with pytest.raises(TimestampAnomalyError):
        SystemInvariantGate.assert_timestamp_valid(float("nan"), "test")

    with pytest.raises(TimestampAnomalyError):
        SystemInvariantGate.assert_timestamp_valid(float("inf"), "test")


def test_sentinel_rpc_call_closes_http_response(tmp_path, monkeypatch):
    """SentinelNode._rpc_call() uses a context manager and closes the HTTPResponse after reading."""
    monkeypatch.setattr(Config, "DATA_DIR", str(tmp_path))
    (tmp_path / "rpc_token").write_text("tok123\n", encoding="utf-8")

    opened_resps = []

    class _FakeResp:
        def __init__(self):
            self.closed = False

        def read(self):
            return json.dumps({"jsonrpc": "2.0", "id": 1, "result": 42}).encode()

        def close(self):
            self.closed = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def _fake_urlopen(req, timeout=5):
        r = _FakeResp()
        opened_resps.append(r)
        return r

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    sentinel = SentinelNode(node=types.SimpleNamespace(storage=None))
    res = sentinel._rpc_call("getblockcount")
    assert res == 42
    assert len(opened_resps) == 1
    assert opened_resps[0].closed is True
