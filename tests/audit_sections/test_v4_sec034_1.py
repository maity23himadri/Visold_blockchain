"""
Audit verification tests for VISOLD Section 34:
Cumulative Chainwork and Fork-Choice Rules.
"""
from decimal import Decimal, localcontext
from pathlib import Path

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.governance.engine import GovernanceEngine
from visold.governance.versioning import ProtocolVersionManager
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.storage.storage import Storage


def _make_block(index: int, prev_hash: str, difficulty: float,
                timestamp: int, miner: str = "miner_a",
                finalized: bool = False, validator_sigs=None) -> Block:
    blk = Block(
        index=index,
        prev_hash=prev_hash,
        transactions=[],
        miner_address=miner,
        difficulty=difficulty,
        timestamp=timestamp,
    )
    blk.finalized = finalized
    if validator_sigs is not None:
        blk.validator_sigs = list(validator_sigs)
    blk.block_hash = blk.compute_hash()
    return blk


def _make_storage(tmp_path: Path) -> Storage:
    return Storage(db_path=str(tmp_path / "visold_test.db"))


# ── Clean-behavior checks ────────────────────────────────────────────────────

def test_cumulative_difficulty_exponential_and_sanitized():
    bc = object.__new__(Blockchain)
    b1 = _make_block(1, "0" * 64, 2.0, 100)
    b2 = _make_block(2, b1.block_hash, 3.0, 110)
    # 2^(4*2) + 2^(4*3) = 256 + 4096 = 4352
    assert bc._cumulative_difficulty([b1, b2]) == Decimal(4352)

    # Non-finite, negative, and above-MAX_DIFFICULTY values are sanitized
    b_nan = _make_block(3, b2.block_hash, float("nan"), 120)
    b_neg = _make_block(4, b_nan.block_hash, -5.0, 130)
    b_over = _make_block(5, b_neg.block_hash, Config.MAX_DIFFICULTY + 100.0, 140)
    work = bc._cumulative_difficulty([b_nan, b_neg, b_over])
    with localcontext() as ctx:
        ctx.prec = 80
        expected_over = Decimal(2) ** (
            Decimal(str(float(Config.MAX_DIFFICULTY))) * Decimal(4)
        )
        assert work == Decimal(1) + expected_over


def test_find_common_ancestor_stops_at_divergence(tmp_path):
    storage = _make_storage(tmp_path)
    b0 = _make_block(0, "0" * 64, 1.0, 1000)
    b1 = _make_block(1, b0.block_hash, 1.0, 1010)
    b2 = _make_block(2, b1.block_hash, 1.0, 1020)
    for b in (b0, b1, b2):
        storage.save_block(b)

    bc = object.__new__(Blockchain)
    bc.storage = storage

    b2_fork = _make_block(2, b1.block_hash, 1.0, 1025, miner="miner_b")
    assert bc._find_common_ancestor([b0, b1, b2_fork]) == 1

    b0_fork = _make_block(0, "0" * 64, 1.0, 1001, miner="miner_b")
    assert bc._find_common_ancestor([b0_fork, b1]) == -1


def test_consensus_engine_is_canonical(tmp_path):
    storage = _make_storage(tmp_path)
    b0 = _make_block(0, "0" * 64, 1.0, 1000)
    storage.save_block(b0)

    bc = object.__new__(Blockchain)
    bc.storage = storage
    ce = object.__new__(ConsensusEngine)
    ce.blockchain = bc

    b0_fork = _make_block(0, "0" * 64, 1.0, 1001, miner="miner_b")
    assert ce._is_canonical(b0) is True
    assert ce._is_canonical(b0_fork) is False


def test_accept_chain_rejects_empty_and_non_contiguous_fork(tmp_path):
    bc = Blockchain(_make_storage(tmp_path))
    ok, msg = bc.accept_chain([])
    assert not ok
    assert "Empty" in msg

    b0 = bc.storage.get_block(0)
    b2_fork = _make_block(2, b0.block_hash, 1.0, b0.timestamp + 20, miner="fork_m")
    b4_gap = _make_block(4, b2_fork.block_hash, 1.0, b0.timestamp + 40, miner="fork_m")
    ok, msg = bc.accept_chain([b2_fork, b4_gap])
    assert not ok
    assert "Non-contiguous" in msg


# ── V4 Regressions in GovernanceEngine.fork_choice() ─────────────────────────

def test_fork_choice_selects_winning_fork_tip_at_same_height(tmp_path):
    """
    V4 regression: GovernanceEngine.fork_choice() evaluates each tip's own
    finality, justification, and chainwork rather than reading canonical storage
    at height idx.
    """
    storage = _make_storage(tmp_path)
    gov = GovernanceEngine(storage, ProtocolVersionManager(storage))

    b0 = _make_block(0, "0" * 64, 1.0, 1000, finalized=True)
    storage.save_block(b0)

    tip_a = _make_block(
        1, b0.block_hash, 1.0, 1010, miner="canon_miner", finalized=False, validator_sigs=[]
    )
    tip_b = _make_block(
        1, b0.block_hash, 10.0, 1011, miner="fork_miner",
        finalized=True, validator_sigs=[{"addr": "V1", "sig": "00", "pub": "00"}],
    )
    if tip_a.block_hash > tip_b.block_hash:
        tip_a, tip_b = tip_b, tip_a
        tip_a.finalized = False
        tip_a.validator_sigs = []
        tip_a.difficulty = 1.0
        tip_b.finalized = True
        tip_b.validator_sigs = [{"addr": "V1", "sig": "00", "pub": "00"}]
        tip_b.difficulty = 10.0

    assert tip_a.block_hash < tip_b.block_hash
    storage.save_block(tip_a)

    chosen = gov.fork_choice(storage, tip_a, tip_b)
    assert chosen.block_hash == tip_b.block_hash


def test_fork_choice_selects_higher_finalized_fork_tip(tmp_path):
    """
    V4 regression: When tip_fork is at height h+1 above canonical tip h,
    fork_choice() properly credits its finality, justification, and work.
    """
    storage = _make_storage(tmp_path)
    gov = GovernanceEngine(storage, ProtocolVersionManager(storage))

    b0 = _make_block(0, "0" * 64, 1.0, 1000, finalized=False)
    b1 = _make_block(1, b0.block_hash, 1.0, 1010, finalized=False)
    storage.save_block(b0)
    storage.save_block(b1)

    b2_fork = _make_block(
        2, b1.block_hash, 8.0, 1020, miner="fork_miner",
        finalized=True, validator_sigs=[{"addr": "V1", "sig": "00", "pub": "00"}],
    )

    chosen = gov.fork_choice(storage, b1, b2_fork)
    assert chosen.block_hash == b2_fork.block_hash
