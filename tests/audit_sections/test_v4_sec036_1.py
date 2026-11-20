import os
import sys

import pytest


from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.consensus.difficulty import DifficultyEngine
from visold.crypto.ecc import sig_to_hex
from visold.governance.engine import GovernanceEngine
from visold.governance.versioning import ProtocolVersionManager
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_chain(tmp_path):
    db_path = os.path.join(str(tmp_path), "visold_s36.db")
    storage = Storage(db_path=db_path)
    bc = Blockchain(storage)
    return storage, bc


def _mine_next_block(bc: Blockchain, miner_wallet: Wallet) -> Block:
    ce = ConsensusEngine(bc, miner_wallet)
    blk = ce.build_candidate_block(miner_wallet.address)
    blk.mine()
    return blk


def _mine_fork_pair(tmp_path, miner_wallet: Wallet, validators_and_stakes):
    """Mine a 2-block fork from genesis in an isolated storage so it has higher work."""
    fork_dir = tmp_path / "fork_build"
    fork_dir.mkdir(exist_ok=True)
    _, fbc = _make_chain(fork_dir)
    _register_validators(fbc.storage, validators_and_stakes)
    b1 = _mine_next_block(fbc, miner_wallet)
    ok, msg = fbc.apply_block(b1)
    assert ok, msg
    b2 = _mine_next_block(fbc, miner_wallet)
    ok, msg = fbc.apply_block(b2)
    assert ok, msg
    return [b1, b2]


def _sign_block(wallet: Wallet, block_hash: str) -> dict:
    sig = wallet.sign(block_hash.encode("utf-8"))
    return {
        "addr": wallet.address,
        "sig": sig_to_hex(sig),
        "pub": wallet.pub_hex,
    }


def _register_validators(storage: Storage, wallets_and_stakes):
    for w, stake in wallets_and_stakes:
        storage.set_role(w.address, "investor", stake=stake)


@pytest.fixture(autouse=True)
def _fast_difficulty(monkeypatch):
    monkeypatch.setattr(Config, "MIN_DIFFICULTY", 0.01)
    monkeypatch.setattr(
        DifficultyEngine, "compute_next_difficulty",
        staticmethod(lambda *args, **kwargs: 0.01),
    )
    DifficultyEngine.invalidate_cache()


def test_init_and_recompute_highest_finalized_height(tmp_path):
    storage, bc = _make_chain(tmp_path)
    assert bc._highest_finalized_height == 0  # genesis is finalized

    miner = Wallet.generate()
    b1 = _mine_next_block(bc, miner)
    ok, msg = bc.apply_block(b1)
    assert ok, msg
    assert bc._highest_finalized_height == 0

    b1_stored = storage.get_block(1)
    b1_stored.finalized = True
    storage.save_block(b1_stored)

    # Simulate process restart against existing chain DB
    bc2 = Blockchain(storage)
    assert bc2._highest_finalized_height == 1


def test_reconcile_finality_after_failed_apply_restores_fence_and_flag(tmp_path):
    storage, bc = _make_chain(tmp_path)
    miner = Wallet.generate()
    bad = Block(
        index=1,
        prev_hash="0" * 64,
        transactions=[],
        difficulty=0.01,
        miner_address=miner.address,
        timestamp=1700000010,
        finalized=True,
    )
    bc._highest_finalized_height = 99  # simulate tentative bump before failure
    bc._reconcile_finality_after_failed_apply(bad, fallback_fence=0)
    assert bc._highest_finalized_height == 0
    assert bad.finalized is False


def test_bft_finalization_threshold_and_ineligible_vote_rejection(tmp_path):
    storage, bc = _make_chain(tmp_path)
    miner = Wallet.generate()
    v1, v2, v3, v4, outsider = [Wallet.generate() for _ in range(5)]
    _register_validators(storage, [(v1, 100.0), (v2, 100.0), (v3, 100.0), (v4, 100.0)])

    b1 = _mine_next_block(bc, miner)
    ok, msg = bc.apply_block(b1)
    assert ok, msg

    # Forged signature & outsider vote must be rejected
    assert bc.add_validator_sig(b1.block_hash, outsider.address, "00" * 64, outsider.pub_hex) is False
    bad_sig = _sign_block(v2, b1.block_hash)["sig"]
    assert bc.add_validator_sig(b1.block_hash, v1.address, bad_sig, v1.pub_hex) is False

    # 2 of 4 validators (50% < 66.67%) must NOT finalize
    for w in (v1, v2):
        s = _sign_block(w, b1.block_hash)
        assert bc.add_validator_sig(b1.block_hash, w.address, s["sig"], s["pub"]) is True
    assert storage.get_block(1).finalized is False
    assert bc._highest_finalized_height == 0

    # 3 of 4 validators (75% >= BFT_THRESHOLD_MILLIONTHS) MUST finalize
    s3 = _sign_block(v3, b1.block_hash)
    assert bc.add_validator_sig(b1.block_hash, v3.address, s3["sig"], s3["pub"]) is True
    assert storage.get_block(1).finalized is True
    assert bc._highest_finalized_height == 1


def test_conflicting_vote_equivocation_excluded_from_quorum(tmp_path):
    storage, bc = _make_chain(tmp_path)
    miner = Wallet.generate()
    v1, v2, v3, v4 = [Wallet.generate() for _ in range(4)]
    vals = [(v1, 100.0), (v2, 100.0), (v3, 100.0), (v4, 100.0)]
    _register_validators(storage, vals)

    b1a = _mine_next_block(bc, miner)
    ok, msg = bc.apply_block(b1a)
    assert ok, msg

    # v1 votes for b1a (25% < 66.67%, so b1a is NOT finalized)
    s1a = _sign_block(v1, b1a.block_hash)
    assert bc.add_validator_sig(b1a.block_hash, v1.address, s1a["sig"], s1a["pub"]) is True
    assert storage.get_block(1).finalized is False

    # Reorg height 1 to a longer competing branch [b1b, b2b]
    miner2 = Wallet.generate()
    fork_chain = _mine_fork_pair(tmp_path, miner2, vals)
    b1b = fork_chain[0]
    ok, msg = bc.reorg(fork_chain)
    assert ok, msg

    # Now v1 tries to vote for b1b as well (equivocation at height 1): must be rejected!
    s1b = _sign_block(v1, b1b.block_hash)
    assert bc.add_validator_sig(b1b.block_hash, v1.address, s1b["sig"], s1b["pub"]) is False

    # v2 and v3 vote for b1b (50% without v1); v1's conflicting vote must not count, so 1b cannot reach 66.67%!
    for w in (v2, v3):
        sw = _sign_block(w, b1b.block_hash)
        assert bc.add_validator_sig(b1b.block_hash, w.address, sw["sig"], sw["pub"]) is True
    assert storage.get_block(1).finalized is False

    # Embedded equivocating vote in _maybe_finalize_by_bft must also be excluded
    b1b_stored = storage.get_block(1)
    b1b_stored.validator_sigs = [s1b, _sign_block(v2, b1b.block_hash), _sign_block(v3, b1b.block_hash)]
    bc._maybe_finalize_by_bft(b1b_stored)
    assert storage.get_block(1).finalized is False


def test_depth_finality_bootstrap_vs_bft_fallback(tmp_path, monkeypatch):
    storage, bc = _make_chain(tmp_path)
    miner = Wallet.generate()
    monkeypatch.setattr(Config, "BOOTSTRAP_POW_FINALITY_DEPTH", 3)
    monkeypatch.setattr(Config, "POW_FINALITY_DEPTH", 2)
    monkeypatch.setattr(Config, "GOVERNANCE_FINALITY_TIMEOUT", 4)

    # No validators -> bootstrap depth (3)
    for _ in range(4):
        blk = _mine_next_block(bc, miner)
        ok, msg = bc.apply_block(blk)
        assert ok, msg
    assert storage.get_block(1).finalized is True
    assert storage.get_block(2).finalized is False
    assert bc._highest_finalized_height == 1


def test_consensus_engine_self_equivocation_guard_and_canonical_check(tmp_path):
    storage, bc = _make_chain(tmp_path)
    v1, v2, v3 = [Wallet.generate() for _ in range(3)]
    vals = [(v1, 100.0), (v2, 100.0), (v3, 100.0)]
    _register_validators(storage, vals)
    ce = ConsensusEngine(bc, v1)

    miner = Wallet.generate()
    b1a = _mine_next_block(bc, miner)

    # Non-canonical block must defer finalization and not cast a vote
    ok, msg = ce.validate_and_finalize(b1a)
    assert ok is True
    assert "deferred" in msg
    assert storage.get_validator_votes_at_height(1) == []

    # Apply b1a -> ce casts vote for b1a
    ok, msg = bc.apply_block(b1a)
    assert ok, msg
    ok, msg = ce.validate_and_finalize(b1a)
    assert ok is True
    assert len(storage.get_validator_votes_at_height(1)) == 1

    # Reorg to longer fork [b1b, b2b] (b1a not finalized) -> ce must withhold vote to avoid self-equivocation
    miner2 = Wallet.generate()
    fork_chain = _mine_fork_pair(tmp_path, miner2, vals)
    b1b = fork_chain[0]
    ok, msg = bc.reorg(fork_chain)
    assert ok, msg
    ok, msg = ce.validate_and_finalize(b1b)
    assert ok is True
    votes = storage.get_validator_votes_at_height(1)
    assert all(v["block_hash"] == b1a.block_hash for v in votes)


def test_governance_set_finality_source_ignores_wire_flag(tmp_path):
    storage, bc = _make_chain(tmp_path)
    proto = ProtocolVersionManager(storage)
    gov = GovernanceEngine(storage, proto)
    gov.set_finality_source(lambda: bc._highest_finalized_height)

    miner = Wallet.generate()
    b1 = _mine_next_block(bc, miner)
    ok, msg = bc.apply_block(b1)
    assert ok, msg
    # Wire block has finalized=True spoofed, but canonical fence is 0
    b1.finalized = True
    gov.on_block_applied(b1)
    assert gov._last_finalized_height == 0


def test_reorg_and_rollback_blocked_at_or_below_finalized_height(tmp_path):
    storage, bc = _make_chain(tmp_path)
    miner = Wallet.generate()
    v1, v2, v3 = [Wallet.generate() for _ in range(3)]
    vals = [(v1, 100.0), (v2, 100.0), (v3, 100.0)]
    _register_validators(storage, vals)

    b1 = _mine_next_block(bc, miner)
    ok, msg = bc.apply_block(b1)
    assert ok, msg
    for w in (v1, v2, v3):
        s = _sign_block(w, b1.block_hash)
        assert bc.add_validator_sig(b1.block_hash, w.address, s["sig"], s["pub"]) is True
    assert bc._highest_finalized_height == 1

    # Rollback below finalized height 1 must fail
    ok, msg = bc.rollback(0)
    assert ok is False
    assert "finalized" in msg.lower()

    # Reorg at fork_height=1 must fail
    fork_chain = _mine_fork_pair(tmp_path, Wallet.generate(), vals)
    ok, msg = bc.reorg(fork_chain)
    assert ok is False
    assert "finalized" in msg.lower()
