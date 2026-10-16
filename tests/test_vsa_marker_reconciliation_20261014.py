"""Regression tests for audit finding VSA-24: tip-marker reconciliation after a restart."""

from __future__ import annotations

import os
import tempfile

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _chain(td):
    st = Storage(os.path.join(td, "marker.db"))
    return st, Blockchain(st)


def _coinbase_block(bc, miner):
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


def _simulate_pre_fix_crash(st, height):
    """The state and block row are committed; the applied marker never was."""
    st._conn().execute("DELETE FROM node_meta WHERE key=?", (f"block_apply:{height}",))
    st._conn().commit()


def test_tip_without_marker_is_restored_when_its_state_matches():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        first = _coinbase_block(bc, miner)
        ok, msg = bc.apply_block(first)
        assert ok, msg
        _simulate_pre_fix_crash(st, first.index)

        restarted = Blockchain(st)
        second = _coinbase_block(restarted, miner)
        ok, msg = restarted.apply_block(second)

        assert ok, f"a consistent tip without its marker must not block writes: {msg}"
        assert st.get_meta(f"block_apply:{first.index}") == "ok", (
            "the tip's applied marker was not restored (VSA-24)")


def test_tip_without_marker_whose_state_does_not_match_fences_the_chain():
    with tempfile.TemporaryDirectory() as td:
        st, bc = _chain(td)
        miner = Wallet.generate()
        first = _coinbase_block(bc, miner)
        ok, msg = bc.apply_block(first)
        assert ok, msg
        _simulate_pre_fix_crash(st, first.index)
        st.credit_sat(miner.address, 1 * Config.SATOSHI_PER_VSD)   # state no longer matches the tip

        restarted = Blockchain(st)
        second = _coinbase_block(restarted, miner)
        ok, msg = restarted.apply_block(second)

        assert not ok and "operator recovery" in msg, (
            f"a mismatched tip must fence the chain (VSA-24): {msg}")
        assert restarted._critical_recovery
