"""Regression tests for noisy warnings on legacy missing validator snapshots.

Logging is coalesced for one contiguous missing-snapshot episode only. The
consensus behavior must remain fail-closed: unavailable snapshots still defer
finalization and reject validator votes.
"""
from __future__ import annotations

import logging
import threading
from types import SimpleNamespace

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine


def _bare_chain() -> Blockchain:
    # The warning helpers use only the chain lock and their in-memory episode
    # state; constructing a full SQLite chain is unnecessary for this unit.
    chain = Blockchain.__new__(Blockchain)
    chain._lock = threading.RLock()
    chain._missing_validator_snapshot_episode = None
    return chain


def test_missing_snapshot_warning_is_emitted_once_across_multiple_heights(caplog):
    chain = _bare_chain()
    caplog.set_level(logging.WARNING)

    for height in (1921, 1922, 1923, 1924, 1925, 1925):
        chain._report_missing_validator_snapshot(
            SimpleNamespace(index=height),
            f"Block #{height} finalization deferred: eligible validator snapshot unavailable",
        )

    warnings = [
        record for record in caplog.records
        if "eligible validator snapshot unavailable" in record.getMessage()
    ]
    assert len(warnings) == 1
    assert "suppressing repeated warnings" in warnings[0].getMessage()
    episode = chain._missing_validator_snapshot_episode
    assert episode["heights"] == {1921, 1922, 1923, 1924, 1925}


def test_snapshot_recovery_ends_episode_and_allows_a_future_warning(caplog):
    chain = _bare_chain()
    caplog.set_level(logging.INFO)

    chain._report_missing_validator_snapshot(
        SimpleNamespace(index=1921), "Block #1921 finalization deferred: eligible validator snapshot unavailable"
    )
    chain._report_missing_validator_snapshot(
        SimpleNamespace(index=1922), "Block #1922 finalization deferred: eligible validator snapshot unavailable"
    )
    chain._note_validator_snapshot_available(SimpleNamespace(index=1923))
    chain._report_missing_validator_snapshot(
        SimpleNamespace(index=1924), "Block #1924 finalization deferred: eligible validator snapshot unavailable"
    )

    warnings = [
        record for record in caplog.records
        if record.levelno >= logging.WARNING
        and "eligible validator snapshot unavailable" in record.getMessage()
    ]
    assert len(warnings) == 2
    assert any("suppressed repeated missing-snapshot warnings for 2 block height(s) (1921..1922)" in record.getMessage()
               for record in caplog.records if record.levelno == logging.INFO)


def test_consensus_still_refuses_finalization_when_snapshot_is_missing(caplog):
    chain = _bare_chain()
    chain._is_canonical = lambda _block: True
    chain.get_validator_set_for_block = lambda _block: None
    engine = ConsensusEngine(chain, wallet=None)
    engine._is_canonical = lambda _block: True
    block = SimpleNamespace(index=1921, block_hash="hash-1921", finalized=False)

    caplog.set_level(logging.WARNING)
    result = engine.finalize_applied_block(block)
    assert result == (False, "eligible validator snapshot unavailable; refusing BFT vote")
    assert block.finalized is False
    assert "eligible validator snapshot unavailable" in caplog.text
