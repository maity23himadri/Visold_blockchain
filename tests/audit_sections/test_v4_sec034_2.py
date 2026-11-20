import tempfile
from pathlib import Path
import threading

import pytest

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.governance.engine import GovernanceEngine
from visold.governance.versioning import ProtocolVersionManager
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.storage.storage import Storage


def _make_block(
    index: int,
    prev_hash: str,
    difficulty: float = 1.0,
    timestamp: int = 1_700_000_000,
    finalized: bool = False,
    validator_sigs=None,
    block_hash: str | None = None,
) -> Block:
    blk = Block(
        index=index,
        prev_hash=prev_hash,
        transactions=[],
        miner_address="VSD_test_miner",
        difficulty=difficulty,
        timestamp=timestamp,
    )
    blk.finalized = finalized
    if validator_sigs is not None:
        blk.validator_sigs = list(validator_sigs)
    if block_hash is not None:
        blk.block_hash = block_hash
    return blk


class TestSection34ChainworkAndForkChoice:
    def test_cumulative_difficulty_exponential_work_and_bounds(self):
        bc = object.__new__(Blockchain)
        # 2 blocks at diff 5.0 => 2 * 2^20 = 2,097,152
        # 10 blocks at diff 4.0 => 10 * 2^16 = 655,360
        heavy_short = [_make_block(i, "0" * 64, difficulty=5.0, timestamp=i) for i in range(1, 3)]
        light_long = [_make_block(i, "0" * 64, difficulty=4.0, timestamp=i) for i in range(1, 11)]
        assert bc._cumulative_difficulty(heavy_short) > bc._cumulative_difficulty(light_long)

        # Invalid/non-finite difficulties are safely skipped
        bad_blk = _make_block(1, "0" * 64, difficulty=1.0, timestamp=1)
        bad_blk.difficulty = float("nan")
        assert bc._cumulative_difficulty([bad_blk]) == 0

        # MAX_DIFFICULTY remains finite
        max_blk = _make_block(1, "0" * 64, difficulty=Config.MAX_DIFFICULTY, timestamp=1)
        work = bc._cumulative_difficulty([max_blk])
        assert work.is_finite() and work > 0

    def test_find_common_ancestor_and_is_canonical(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(db_path=str(Path(tmp) / "chain.db"))
            try:
                b0 = _make_block(0, "0" * 64, timestamp=100, block_hash="a" * 64)
                b1 = _make_block(1, b0.block_hash, timestamp=110, block_hash="b" * 64)
                b2 = _make_block(2, b1.block_hash, timestamp=120, block_hash="c" * 64)
                for b in (b0, b1, b2):
                    storage.save_block(b)

                bc = object.__new__(Blockchain)
                bc.storage = storage

                fork_b2 = _make_block(2, b1.block_hash, timestamp=121, block_hash="d" * 64)
                assert bc._find_common_ancestor([b0, b1, fork_b2]) == 1
                assert bc._find_common_ancestor([fork_b2]) == -1

                ce = object.__new__(ConsensusEngine)
                ce.blockchain = bc
                assert ce._is_canonical(b2) is True
                assert ce._is_canonical(fork_b2) is False
            finally:
                storage.close()

    def test_accept_chain_overlap_and_non_contiguous_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(db_path=str(Path(tmp) / "bc.db"))
            try:
                b0 = _make_block(0, "0" * 64, timestamp=100, block_hash="a" * 64)
                storage.save_block(b0)

                bc = object.__new__(Blockchain)
                bc.storage = storage
                bc._lock = threading.RLock()
                bc.height = lambda: 0

                # Exact historical overlap returns True idempotently
                ok, msg = bc.accept_chain([b0])
                assert ok is True
                assert "Already have" in msg

                # Non-contiguous historical overlap is rejected
                b0_other = _make_block(0, "0" * 64, timestamp=100, block_hash="b" * 64)
                b2 = _make_block(2, "0" * 64, timestamp=120)
                ok_nc, msg_nc = bc.accept_chain([b0_other, b2])
                assert ok_nc is False
                assert "Non-contiguous" in msg_nc

                # Preflight requires a canonical anchor >= 0
                ok_pf, msg_pf = bc._preflight_peer_branch(-1, [b2])
                assert ok_pf is False
                assert "canonical anchor" in msg_pf
            finally:
                storage.close()

    def test_fork_choice_respects_tip_and_ancestry_on_same_height_fork(self):
        """
        V4 regression (FINDING-34-1):
        GovernanceEngine.fork_choice() inspects each tip's finality, justification,
        and cumulative PoW rather than falling through to hash tiebreak on same-height forks.
        """
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(db_path=str(Path(tmp) / "fork_same_h.db"))
            try:
                b0 = _make_block(0, "0" * 64, difficulty=1.0, timestamp=100, block_hash="1" * 64)
                b1 = _make_block(1, b0.block_hash, difficulty=1.0, timestamp=110, block_hash="2" * 64)
                tip_a = _make_block(
                    2,
                    b1.block_hash,
                    difficulty=1.0,
                    timestamp=120,
                    finalized=False,
                    validator_sigs=[],
                    block_hash="3" * 64,
                )
                for b in (b0, b1, tip_a):
                    storage.save_block(b)

                tip_b = _make_block(
                    2,
                    b1.block_hash,
                    difficulty=10.0,
                    timestamp=125,
                    finalized=True,
                    validator_sigs=[{"validator": "VSD_val_1", "sig": "aa"}],
                    block_hash="f" * 64,
                )

                gov = GovernanceEngine(storage, ProtocolVersionManager(storage))
                chosen = gov.fork_choice(storage, tip_a, tip_b)
                assert chosen.block_hash == tip_b.block_hash
            finally:
                storage.close()

    def test_fork_choice_evaluates_unapplied_higher_tip_properly(self):
        """
        V4 regression (FINDING-34-1, second trigger):
        When tip_b is at height H+1 and not yet stored as canonical at
        storage.get_block(H+1), fork_choice() properly credits its finality,
        justification, and PoW so tip_b wins over tip_a.
        """
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(db_path=str(Path(tmp) / "fork_higher_h.db"))
            try:
                b0 = _make_block(0, "0" * 64, difficulty=1.0, timestamp=100, block_hash="1" * 64)
                tip_a = _make_block(
                    1,
                    b0.block_hash,
                    difficulty=1.0,
                    timestamp=110,
                    finalized=False,
                    validator_sigs=[],
                    block_hash="2" * 64,
                )
                for b in (b0, tip_a):
                    storage.save_block(b)

                tip_b = _make_block(
                    2,
                    tip_a.block_hash,
                    difficulty=10.0,
                    timestamp=120,
                    finalized=True,
                    validator_sigs=[{"validator": "VSD_val_1", "sig": "bb"}],
                    block_hash="f" * 64,
                )

                gov = GovernanceEngine(storage, ProtocolVersionManager(storage))
                chosen = gov.fork_choice(storage, tip_a, tip_b)
                assert chosen.block_hash == tip_b.block_hash
            finally:
                storage.close()
