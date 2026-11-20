"""V4 regression tests for Section 28 (Session 01): Block Size & Header Field Types."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.crypto.hashing import hash_obj
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.network.bootstrap_sync import _canonical_header_dict
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_chain(tmpdir: str):
    db_path = os.path.join(tmpdir, "chain.db")
    st = Storage(db_path)
    bc = Blockchain(st)
    return st, bc


def test_block_size_excludes_post_mining_validator_sigs():
    """Block.size() / validate_block() does not reject a valid block when post-mining validator_sigs are attached."""
    orig_max_size = Config.MAX_BLOCK_SIZE
    try:
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            _st1, bc1 = _make_chain(d1)
            _st2, bc2 = _make_chain(d2)
            miner = Wallet.generate()

            ce = ConsensusEngine(bc1, miner)
            candidate = ce.build_candidate_block(miner.address)
            object.__setattr__(candidate, "difficulty", 0.001)
            base_size = candidate.size()

            Config.MAX_BLOCK_SIZE = base_size + 32

            assert candidate.mine()
            bc2.get_difficulty = lambda: 0.001
            ok_pre, msg_pre = bc2.validate_block(candidate)
            assert ok_pre, f"Expected pre-vote mined block to validate, got: {msg_pre}"

            sig_entry = {
                "addr": miner.address,
                "pub": miner.pub_hex,
                "sig": "ab" * 64,
                "stake": 1000,
                "height": candidate.index,
                "block_hash": candidate.block_hash,
            }
            candidate.validator_sigs.append(sig_entry)
            candidate.finalized = True

            synced_block = Block.from_dict(candidate.to_dict())
            ok_int, msg_int = synced_block.integrity_check()
            assert ok_int, f"integrity_check should still pass: {msg_int}"

            ok_post, msg_post = bc2.validate_block(synced_block)
            assert ok_post is True, f"Expected post-vote block to validate: {msg_post}"
    finally:
        Config.MAX_BLOCK_SIZE = orig_max_size


def test_noncanonical_header_field_types_rejected_or_canonicalized():
    """Non-canonical header field types are either rejected or canonicalized so bootstrap_sync hash matches."""
    with tempfile.TemporaryDirectory() as d1:
        _st, bc = _make_chain(d1)
        miner = Wallet.generate()
        genesis = bc.storage.get_block(0)
        assert genesis is not None

        bc.get_difficulty = lambda: 0.001
        ce = ConsensusEngine(bc, miner)
        valid_cand = ce.build_candidate_block(miner.address)
        expected_diff = bc.get_difficulty()
        ts = float(valid_cand.timestamp)

        try:
            crafted = Block(
                index=1.0,
                prev_hash=genesis.block_hash,
                transactions=list(valid_cand.transactions),
                miner_address=miner.address,
                difficulty=str(expected_diff),
                timestamp=ts,
                nonce=0,
                state_root=valid_cand.state_root,
                protocol_version=float(Config.PROTOCOL_VERSION),
            )
            assert crafted.mine()
            reloaded = Block.from_dict(crafted.to_dict())
            ok_val, _ = bc.validate_block(reloaded)
            if ok_val:
                canonical_hash = hash_obj(_canonical_header_dict(reloaded.to_dict()))
                assert canonical_hash == reloaded.block_hash
        except (ValueError, TypeError):
            pass
