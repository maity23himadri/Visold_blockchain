"""Section 38 audit tests: Validator Signature Thresholds and Quorum Calculations."""
from __future__ import annotations

import os
import tempfile
import threading
import time

from visold.chain.blockchain import Blockchain
from visold.crypto.ecc import sig_to_hex
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _config_patch(**values):
    old = {key: getattr(Config, key) for key in values}
    for key, value in values.items():
        setattr(Config, key, value)
    return old


def _restore_config(old):
    for key, value in old.items():
        setattr(Config, key, value)


def _mine_block(bc: Blockchain, miner: Wallet, extra_txs=()) -> Block:
    height = bc.height() + 1
    coinbase = Transaction.coinbase(
        miner.address,
        bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD,
        height,
    )
    txs = [coinbase, *list(extra_txs)]
    root = bc.dry_run_state_root(txs, miner.address, height)
    prev = bc.latest_block()
    block = Block(
        index=height,
        prev_hash=prev.block_hash,
        transactions=txs,
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        timestamp=max(int(time.time()), int(prev.timestamp) + 1),
        state_root=root,
    )
    assert block.mine(), f"failed to mine test block #{height}"
    return block


def test_zero_stake_investor_excluded_from_snapshot_and_pow_finality_proceeds():
    """V4 regression (Finding 1a): Zero-stake investors are excluded from BFT snapshots,
    their votes are rejected, and bootstrap PoW depth finality proceeds normally.
    """
    old = _config_patch(
        MIN_DIFFICULTY=0.001,
        INITIAL_DIFFICULTY=0.001,
        MIN_VALIDATORS_FOR_BFT=3,
        POW_FINALITY_DEPTH=2,
        BOOTSTRAP_POW_FINALITY_DEPTH=2,
        GOVERNANCE_FINALITY_TIMEOUT=10,
    )
    try:
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(os.path.join(td, "zero-stake.db"))
            bc = Blockchain(storage)
            miner = Wallet.generate()
            zero_investors = [Wallet.generate() for _ in range(3)]
            for w in zero_investors:
                storage.set_role(w.address, "investor", 0.0)

            for _ in range(3):
                blk = _mine_block(bc, miner)
                ok, msg = bc.apply_block(blk)
                assert ok, msg

            b1 = storage.get_block(1)
            assert b1 is not None

            assert bc.emergency_operator_eligible(zero_investors[0].address) is False

            snap = bc.get_validator_set_for_block(b1)
            assert snap == []
            sig_hex = sig_to_hex(zero_investors[0].sign(b1.block_hash.encode("utf-8")))
            accepted = bc.add_validator_sig(
                b1.block_hash, zero_investors[0].address, sig_hex, zero_investors[0].pub_hex
            )
            assert accepted is False
            assert b1.finalized is True
    finally:
        _restore_config(old)


def test_zero_stake_investor_does_not_activate_bft_with_fewer_than_min_staked_validators():
    """V4 regression (Finding 1b): 2 staked validators + 1 zero-stake investor does NOT
    satisfy MIN_VALIDATORS_FOR_BFT=3, so BFT finalization does not trigger.
    """
    old = _config_patch(
        MIN_DIFFICULTY=0.001,
        INITIAL_DIFFICULTY=0.001,
        MIN_VALIDATORS_FOR_BFT=3,
        POW_FINALITY_DEPTH=50,
        BOOTSTRAP_POW_FINALITY_DEPTH=50,
    )
    try:
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(os.path.join(td, "two-staked-one-zero.db"))
            bc = Blockchain(storage)
            miner = Wallet.generate()
            v1, v2, v_zero = Wallet.generate(), Wallet.generate(), Wallet.generate()
            storage.set_role(v1.address, "investor", 201.0)
            storage.set_role(v2.address, "investor", 99.0)
            storage.set_role(v_zero.address, "investor", 0.0)

            blk = _mine_block(bc, miner)
            ok, msg = bc.apply_block(blk)
            assert ok, msg

            sig_hex = sig_to_hex(v1.sign(blk.block_hash.encode("utf-8")))
            assert bc.add_validator_sig(blk.block_hash, v1.address, sig_hex, v1.pub_hex) is True

            persisted = storage.get_block(blk.index)
            assert persisted is not None
            assert persisted.finalized is False
    finally:
        _restore_config(old)


def test_add_validator_sig_locked_concurrent_calls_preserve_votes_and_quorum():
    """V4 regression (Finding 2): Concurrent add_validator_sig() calls are serialized
    by self._lock so both signatures are preserved and BFT finalization succeeds.
    """
    old = _config_patch(
        MIN_DIFFICULTY=0.001,
        INITIAL_DIFFICULTY=0.001,
        MIN_VALIDATORS_FOR_BFT=3,
        POW_FINALITY_DEPTH=50,
        BOOTSTRAP_POW_FINALITY_DEPTH=50,
    )
    try:
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(os.path.join(td, "concurrent-votes.db"))
            bc = Blockchain(storage)
            miner = Wallet.generate()
            v1, v2, v3 = Wallet.generate(), Wallet.generate(), Wallet.generate()
            # v1=40%, v2=40%, v3=20% -> v1 + v2 = 80% >= 66.67%
            storage.set_role(v1.address, "investor", 40.0)
            storage.set_role(v2.address, "investor", 40.0)
            storage.set_role(v3.address, "investor", 20.0)

            blk = _mine_block(bc, miner)
            ok, msg = bc.apply_block(blk)
            assert ok, msg

            start_barrier = threading.Barrier(2, timeout=5.0)
            results = {}

            def cast(name, wallet):
                sig_hex = sig_to_hex(wallet.sign(blk.block_hash.encode("utf-8")))
                start_barrier.wait()
                results[name] = bc.add_validator_sig(
                    blk.block_hash, wallet.address, sig_hex, wallet.pub_hex
                )

            t1 = threading.Thread(target=cast, args=("v1", v1))
            t2 = threading.Thread(target=cast, args=("v2", v2))
            t1.start()
            t2.start()
            t1.join(timeout=10.0)
            t2.join(timeout=10.0)

            assert results == {"v1": True, "v2": True}

            persisted = storage.get_block(blk.index)
            assert persisted is not None
            votes = storage.get_validator_votes_at_height(blk.index)
            assert len(votes) == 2
            assert len(persisted.validator_sigs) == 2
            assert persisted.finalized is True
    finally:
        _restore_config(old)
