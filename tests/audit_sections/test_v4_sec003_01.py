"""V4 regression tests for Audit Section 003: Serialization & Round-Trip Integrity."""

import json
import os
import tempfile

import pytest

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.kernel.serialization import _serialize
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.rollup.batches import RollupSubmission
from visold.storage.storage import Storage


def test_genesis_block_roundtrip_preserves_expiry_and_integrity_check():
    """Loading the canonical genesis block via Block.from_dict()/Transaction.from_dict() preserves expiry=0 and passes integrity_check()."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(os.path.join(tmpdir, "visold.db"))
        bc = Blockchain(storage)
        genesis = bc.get_block(0)
        assert genesis is not None
        assert genesis.transactions[0].sender == Config.GENESIS_TX_SENDER
        assert genesis.transactions[0].expiry == 0

        ok, msg = genesis.integrity_check()
        assert ok is True, msg


def test_serialize_handles_sets_as_sorted_lists():
    """_serialize() serializes Python sets as sorted JSON lists rather than str()."""
    payload = {"tags": {3, 1, 2}}
    raw = _serialize(payload)
    parsed = json.loads(raw)

    assert parsed["tags"] == [1, 2, 3]


def test_block_from_dict_preserves_zero_timestamp_and_protocol_version():
    """Block.from_dict() preserves explicit timestamp=0 and protocol_version=0."""
    tx = Transaction(
        sender="COINBASE",
        receiver="VSD_MINER",
        amount=10.0,
        timestamp=1700000000,
        nonce=0,
        expiry=0,
    )
    blk = Block(
        index=1,
        prev_hash="0" * 64,
        transactions=[tx],
        miner_address="VSD_MINER",
        difficulty=5.15,
        timestamp=1700000000,
        nonce=1,
    )
    d = blk.to_dict()
    d["timestamp"] = 0
    d["protocol_version"] = 0

    reloaded = Block.from_dict(d)
    assert reloaded.timestamp == 0
    assert reloaded.protocol_version == 0


def test_rollup_submission_from_json_raises_value_error_on_non_dict_or_null_fields():
    """RollupSubmission.from_json() raises ValueError on non-dict JSON and null hex fields."""
    with pytest.raises(ValueError):
        RollupSubmission.from_json("[]")

    bad_null = json.dumps(
        {
            "kind": "rollup_submission_v1",
            "batch_id": 1,
            "previous_l2_root": "a" * 64,
            "new_l2_root": "b" * 64,
            "zk_proof": None,
            "compressed_data": "",
        }
    )
    with pytest.raises(ValueError):
        RollupSubmission.from_json(bad_null)
