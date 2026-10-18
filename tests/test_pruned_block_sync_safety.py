"""Security regressions for pruned block serialization and sync handling.

These tests intentionally assert that a header-only record is clearly marked
and cannot enter the normal full-block validation/application path. They do not
claim to implement trustless snapshot bootstrap; that requires a protocol-level
state commitment upgrade.
"""
from __future__ import annotations

import pytest

from visold.ledger.block import Block


def _pruned_payload() -> dict:
    return {
        "version": 1,
        "protocol_version": 1,
        "index": 7,
        "prev_hash": "11" * 32,
        "timestamp": 1_800_000_000,
        "miner_address": "VSD-test-miner",
        "difficulty": 1.0,
        "nonce": 42,
        "vrf_proof": "",
        "vrf_output": "",
        "merkle_root": "22" * 32,  # retained historical commitment
        "state_root": "33" * 32,
        "block_hash": "44" * 32,
        "finalized": False,
        "validator_sigs": [],
        "transactions": [],
        "pruned": True,
    }


def test_pruned_marker_and_historical_merkle_root_survive_roundtrip():
    block = Block.from_dict(_pruned_payload())

    wire = block.to_dict()
    assert block.is_pruned is True
    assert wire["pruned"] is True
    assert wire["transactions"] == []
    assert wire["merkle_root"] == "22" * 32
    assert wire["block_hash"] == "44" * 32

    restored = Block.from_dict(wire)
    assert restored.is_pruned is True
    assert restored.to_dict()["pruned"] is True
    assert restored.merkle_root == "22" * 32


def test_pruned_block_never_passes_full_block_integrity_check():
    block = Block.from_dict(_pruned_payload())

    ok, reason = block.integrity_check()

    assert ok is False
    assert "pruned" in reason.lower()
    assert "transaction body" in reason.lower()


def test_pruned_flag_cannot_be_mutated_after_deserialization():
    block = Block.from_dict(_pruned_payload())

    with pytest.raises(AttributeError):
        block._pruned = False

    assert block.is_pruned is True


@pytest.mark.parametrize("bad_marker", ["true", "false", 1, 0, None, []])
def test_non_boolean_pruned_marker_is_rejected(bad_marker):
    payload = _pruned_payload()
    payload["pruned"] = bad_marker
    with pytest.raises(ValueError, match="pruned marker must be a boolean"):
        Block.from_dict(payload)


def test_pruned_payload_with_transaction_body_is_rejected():
    payload = _pruned_payload()
    payload["transactions"] = [{"tx_id": "fake"}]
    with pytest.raises(ValueError, match="must not include transaction bodies"):
        Block.from_dict(payload)


def test_pruned_payload_without_original_merkle_root_is_rejected():
    payload = _pruned_payload()
    payload["merkle_root"] = ""
    with pytest.raises(ValueError, match="preserve its original merkle_root"):
        Block.from_dict(payload)


def test_ordinary_full_block_does_not_gain_a_pruned_false_wire_field():
    payload = _pruned_payload()
    payload.pop("pruned")
    payload["index"] = 1
    payload["merkle_root"] = "55" * 32
    block = Block.from_dict(payload)

    assert block.is_pruned is False
    assert "pruned" not in block.to_dict()
