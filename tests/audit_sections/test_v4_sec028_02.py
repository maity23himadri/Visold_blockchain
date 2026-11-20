"""V4 regression tests for Section 28 (Session 02): Block Header Structure, Hashing, and Field Integrity."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.consensus.difficulty import DifficultyEngine
from visold.crypto.hashing import hash_obj
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.bootstrap_sync import _canonical_header_dict
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _mine_valid_block(bc: Blockchain, miner: str | None = None, **overrides) -> Block:
    miner = miner or Wallet.generate().address
    tip = bc.get_block(0)
    idx = tip.index + 1
    diff = bc.get_difficulty()
    ts = max(int(tip.timestamp) + 1, 1700000000)
    reward_vsd = bc.compute_reward(idx)
    cb = Transaction.coinbase(miner, reward_vsd, block_height=idx)
    state_root = bc.dry_run_state_root([cb], miner, idx, ts, diff)
    kwargs = dict(
        index=idx,
        prev_hash=tip.block_hash,
        transactions=[cb],
        miner_address=miner,
        difficulty=diff,
        timestamp=ts,
        nonce=0,
        state_root=state_root,
    )
    kwargs.update(overrides)
    blk = Block(**kwargs)
    assert blk.mine() is True
    return blk


def test_canonical_genesis_passes_integrity_check_and_validate_block():
    """Canonical genesis block created by Blockchain._create_genesis() passes integrity_check() and validate_block()."""
    with tempfile.TemporaryDirectory() as tmp:
        storage = Storage(os.path.join(tmp, "chain.db"))
        bc = Blockchain(storage)
        genesis = bc.get_block(0)
        assert genesis is not None
        assert genesis.index == 0

        ok_int, msg_int = genesis.integrity_check()
        assert ok_int is True, msg_int

        ok_val, msg_val = bc.validate_block(genesis)
        assert ok_val is True, msg_val


def test_from_dict_preserves_version_and_falsy_header_fields():
    """Block.from_dict() preserves version=2, timestamp=0, protocol_version=0, and rejects empty block_hash."""
    cb = Transaction.coinbase("VSD_MINER", 50.0, block_height=1)
    blk = Block(
        index=1,
        prev_hash="a" * 64,
        transactions=[cb],
        miner_address="VSD_MINER",
        difficulty=0.001,
        timestamp=1700000000,
        nonce=16,
    )
    d = blk.to_dict()

    # 1) version=2 preserved
    d_ver2 = dict(d)
    d_ver2["version"] = 2
    d_ver2["block_hash"] = hash_obj(_canonical_header_dict(d_ver2))
    loaded_ver2 = Block.from_dict(d_ver2)
    assert loaded_ver2.version == 2
    assert loaded_ver2.compute_hash() == d_ver2["block_hash"]

    # 2) timestamp=0 preserved
    d_ts0 = dict(d)
    d_ts0["timestamp"] = 0
    d_ts0["block_hash"] = hash_obj(_canonical_header_dict(d_ts0))
    loaded_ts0 = Block.from_dict(d_ts0)
    assert loaded_ts0.timestamp == 0

    # 3) protocol_version=0 preserved
    d_pv0 = dict(d)
    d_pv0["protocol_version"] = 0
    d_pv0["block_hash"] = hash_obj(_canonical_header_dict(d_pv0))
    loaded_pv0 = Block.from_dict(d_pv0)
    assert loaded_pv0.protocol_version == 0

    # 4) Empty block_hash="" on non-pruned block rejected
    d_empty_hash = dict(d)
    d_empty_hash["block_hash"] = ""
    try:
        loaded_empty = Block.from_dict(d_empty_hash)
        ok_empty, _ = loaded_empty.integrity_check()
        assert ok_empty is False
    except (ValueError, TypeError):
        pass


def test_header_type_confusion_rejected_by_validation():
    """Non-canonical header field types are rejected or canonicalized consistently."""
    with tempfile.TemporaryDirectory() as tmp:
        storage = Storage(os.path.join(tmp, "chain.db"))
        bc = Blockchain(storage)
        tip = bc.get_block(0)
        diff = bc.get_difficulty()
        ts = max(int(tip.timestamp) + 1, 1700000000)
        cb = Transaction.coinbase("VSD_MINER", bc.compute_reward(1), block_height=1)
        state_root = bc.dry_run_state_root([cb], "VSD_MINER", 1, ts, diff)

        # Case A: str difficulty, float timestamp, negative nonce, negative protocol_version
        try:
            blk_weird = Block(
                index=1,
                prev_hash=tip.block_hash,
                transactions=[cb],
                miner_address="VSD_MINER",
                difficulty=str(diff),
                timestamp=float(ts) + 0.5,
                nonce=-42,
                protocol_version=-5,
                state_root=state_root,
            )
            target = DifficultyEngine.difficulty_to_target(float(diff))
            for _ in range(10000):
                h = blk_weird.compute_hash()
                if int(h, 16) <= target:
                    object.__setattr__(blk_weird, "block_hash", h)
                    break
                blk_weird.nonce -= 1
            blk_weird.seal()
            loaded = Block.from_dict(blk_weird.to_dict())
            ok_val, _ = bc.validate_block(loaded)
            if ok_val:
                assert hash_obj(_canonical_header_dict(blk_weird.to_dict())) == loaded.block_hash
        except (ValueError, TypeError):
            pass

        # Case B: bool index=True
        try:
            blk_bool_idx = Block(
                index=True,
                prev_hash=tip.block_hash,
                transactions=[cb],
                miner_address="VSD_MINER",
                difficulty=diff,
                timestamp=ts,
                nonce=0,
                state_root=state_root,
            )
            blk_bool_idx.mine()
            loaded_bool = Block.from_dict(blk_bool_idx.to_dict())
            ok_val_b, _ = bc.validate_block(loaded_bool)
            assert ok_val_b is False
        except (ValueError, TypeError):
            pass


def test_normal_mined_block_header_and_seal_immutability():
    """Verify normal mined block passes integrity_check, validate_block, seal immutability, and bootstrap parity."""
    with tempfile.TemporaryDirectory() as tmp:
        storage = Storage(os.path.join(tmp, "chain.db"))
        bc = Blockchain(storage)
        blk = _mine_valid_block(bc)

        ok_int, msg_int = blk.integrity_check()
        assert ok_int is True, msg_int

        ok_val, msg_val = bc.validate_block(blk)
        assert ok_val is True, msg_val

        assert hash_obj(_canonical_header_dict(blk.to_dict())) == blk.block_hash

        for field in ("index", "prev_hash", "merkle_root", "block_hash", "state_root", "difficulty"):
            with pytest.raises(AttributeError):
                setattr(blk, field, getattr(blk, field))
