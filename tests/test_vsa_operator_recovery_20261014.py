"""Regression tests for the VSA-26 operator path: clearing a critical-recovery marker."""

from __future__ import annotations

import os
import tempfile

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _chain(td: str):
    st = Storage(os.path.join(td, "recovery.db"))
    return st, Blockchain(st)


def _coinbase_block(bc: Blockchain, miner: Wallet) -> Block:
    height = bc.height() + 1
    cb = Transaction.coinbase(
        miner.address, bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD, height)
    root = bc.dry_run_state_root([cb], miner.address, height)
    block = Block(
        index=height,
        prev_hash=bc.latest_block().block_hash,
        transactions=[cb],
        miner_address=miner.address,
        difficulty=bc.get_difficulty(),
        state_root=root,
    )
    assert block.mine(), "block failed to mine"
    return block


def test_marker_refuses_writes_until_the_matching_token_clears_it():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        block = _coinbase_block(bc, miner)

        bc._mark_critical_recovery("restoration of the old chain failed at height 3: injected")
        ok, msg = bc.apply_block(block)
        assert not ok and "operator recovery" in msg, msg

        token = bc.recovery_token()
        assert token and len(token) == 12
        ok, msg = bc.clear_critical_recovery("0" * 12)
        assert not ok and "does not match" in msg, msg
        assert bc.apply_block(block)[0] is False, "a mismatched token must not clear the marker"

        ok, msg = bc.clear_critical_recovery(token)
        assert ok, msg
        assert st.get_meta("chain_recovery_required") in (None, "")
        ok, msg = bc.apply_block(block)
        assert ok, f"writes must resume after an acknowledged clear: {msg}"
        assert bc.height() == block.index


def test_cleared_marker_stays_cleared_after_a_restart():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        bc._mark_critical_recovery("rollback of the old suffix failed: injected")
        assert bc.clear_critical_recovery(bc.recovery_token())[0] is True

        restarted = Blockchain(st)
        assert restarted._critical_recovery is None, "a restart re-armed a cleared marker"


def test_clearing_without_a_marker_is_refused():
    with tempfile.TemporaryDirectory() as td:
        _st, bc = _chain(td)
        assert bc.recovery_token() is None
        ok, msg = bc.clear_critical_recovery("anything")
        assert not ok and "no recovery marker" in msg, msg
