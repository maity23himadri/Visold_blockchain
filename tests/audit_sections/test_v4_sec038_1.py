"""Section 38 Audit: Validator Signature Thresholds and Quorum Calculations."""

import hashlib
import os

import pytest

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.crypto.ecc import sig_to_hex
from visold.kernel.units import bft_threshold_met
from visold.selfhealing.monitors import ValidatorMonitor
from visold.selfhealing.rollback import GovernanceRollbackVote
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_storage(tmp_path, name="chain.db"):
    return Storage(db_path=str(tmp_path / name))


def _sign_block(wallet: Wallet, block_hash: str) -> str:
    return sig_to_hex(wallet.sign(block_hash.encode("utf-8")))


def test_genesis_records_validator_snapshot_for_get_validators(tmp_path):
    """V4 regression: _create_genesis() records bft_validator_snapshot:0,
    so Storage.get_validators(), GovernanceRollbackVote.quorum_status(), and
    ValidatorMonitor.observe_block() work cleanly on a fresh genesis-only chain.
    """
    st = _make_storage(tmp_path)
    bc = Blockchain(st)
    assert bc.height() == 0

    genesis = st.get_block(0)
    assert st.get_block_validator_snapshot(0, genesis.block_hash) == []
    assert st.get_validators() == []

    vote = GovernanceRollbackVote(st, "prop-1", 1, {"reason": "test"})
    status = vote.quorum_status()
    assert status.get("error") is None
    assert status["reached"] is True

    monitor = ValidatorMonitor(st, bc)
    monitor.observe_block(genesis)


def test_bft_threshold_met_integer_boundaries():
    """Verify bft_threshold_met() integer cross-multiplication boundaries."""
    assert bft_threshold_met(0, 0) is False
    assert bft_threshold_met(100, 0) is False
    assert bft_threshold_met(100, -5) is False

    # Exactly 66.67% (666_700 / 1_000_000) passes; 1 satoshi below fails.
    assert bft_threshold_met(666_700, 1_000_000) is True
    assert bft_threshold_met(666_699, 1_000_000) is False

    # 3 equal-stake validators: 2/3 = 66.666...% < 66.67%, so 3/3 is required.
    assert bft_threshold_met(200, 300) is False
    assert bft_threshold_met(300, 300) is True

    # 4 equal-stake validators: 3/4 = 75% >= 66.67%.
    assert bft_threshold_met(200, 400) is False
    assert bft_threshold_met(300, 400) is True


def test_bft_quorum_min_validators_and_equivocation_exclusion(tmp_path):
    """Verify MIN_VALIDATORS_FOR_BFT gating, snapshot isolation, and
    equivocation exclusion in _maybe_finalize_by_bft() / add_validator_sig().
    """
    st = _make_storage(tmp_path)
    bc = Blockchain(st)
    miner = Wallet.generate()

    # Register 4 equal-stake validators directly before block 1.
    validators = [Wallet.generate() for _ in range(4)]
    for v in validators:
        st.set_role(v.address, "investor", 100.0)

    # Build, mine, and apply block 1.
    ce = ConsensusEngine(bc, miner)
    blk1 = ce.build_candidate_block(miner.address)
    assert blk1.mine()
    ok, msg = bc.apply_block(blk1)
    assert ok, msg

    # First record a vote from validators[0] for a different block hash at height 1.
    fake_hash = hashlib.sha256(b"competing-block-1").hexdigest()
    st.record_validator_vote(
        fake_hash,
        validators[0].address,
        _sign_block(validators[0], fake_hash),
        validators[0].pub_hex,
        block_idx=1,
    )

    # Now validators[0] tries to vote for canonical blk1: must be rejected as double-sign
    # and excluded from quorum.
    accepted_0 = bc.add_validator_sig(
        blk1.block_hash,
        validators[0].address,
        _sign_block(validators[0], blk1.block_hash),
        validators[0].pub_hex,
    )
    assert accepted_0 is False
    assert bc.storage.get_block(1).finalized is False

    # validators[1] and validators[2] vote (2/4 = 50% < 66.67%): not finalized yet.
    assert bc.add_validator_sig(
        blk1.block_hash,
        validators[1].address,
        _sign_block(validators[1], blk1.block_hash),
        validators[1].pub_hex,
    ) is True
    assert bc.add_validator_sig(
        blk1.block_hash,
        validators[2].address,
        _sign_block(validators[2], blk1.block_hash),
        validators[2].pub_hex,
    ) is True
    assert bc.storage.get_block(1).finalized is False

    # validators[3] votes (3/4 = 75% >= 66.67%): block 1 is BFT-finalized.
    assert bc.add_validator_sig(
        blk1.block_hash,
        validators[3].address,
        _sign_block(validators[3], blk1.block_hash),
        validators[3].pub_hex,
    ) is True
    assert bc.storage.get_block(1).finalized is True
