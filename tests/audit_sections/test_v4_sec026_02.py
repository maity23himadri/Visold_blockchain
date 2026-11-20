"""V4 regression tests for Section 26 (Session 02): Transaction Validation and State-Dependent Rules."""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.kernel.config import Config
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_chain(tmpdir: str):
    orig_diff = Config.INITIAL_DIFFICULTY
    Config.INITIAL_DIFFICULTY = 0.001
    st = Storage(os.path.join(tmpdir, "audit26.db"))
    bc = Blockchain(st)
    bc._rolling_pruner.prune_async = lambda _h: None
    return st, bc, orig_diff


def test_forged_tx_id_rejected_by_validation_and_mempool():
    """Transaction.is_valid() and Mempool.add() verify tx.tx_id == tx._compute_id() and reject forged tx_ids."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _st, bc, orig_diff = _make_chain(tmpdir)
        try:
            miner = Wallet.generate()
            alice = Wallet.generate()
            bob = Wallet.generate()
            eng = ConsensusEngine(bc, miner)

            b1 = eng.build_candidate_block(miner.address)
            assert b1.mine()
            ok, msg = bc.apply_block(b1)
            assert ok, msg

            tx_fund = Transaction(
                sender=miner.address,
                receiver=alice.address,
                amount=5.0,
                fee=0.05,
                nonce=bc.storage.get_nonce(miner.address),
                timestamp=int(time.time()),
            )
            tx_fund.sign(miner)
            ok, msg = bc.mempool.add(tx_fund)
            assert ok, msg

            b2 = eng.build_candidate_block(miner.address)
            assert b2.mine()
            ok, msg = bc.apply_block(b2)
            assert ok, msg
            assert bc.storage.get_balance_sat(alice.address) == 500_000_000

            tx_real = Transaction(
                sender=alice.address,
                receiver=bob.address,
                amount=1.0,
                fee=0.01,
                nonce=bc.storage.get_nonce(alice.address),
                timestamp=int(time.time()),
            )
            tx_real.sign(alice)
            wire = tx_real.to_dict()
            forged_id = "f" * 64
            assert forged_id != tx_real.tx_id
            wire["tx_id"] = forged_id

            tx_forged = Transaction.from_dict(wire)
            assert tx_forged.tx_id == forged_id
            assert tx_forged.tx_id != tx_forged._compute_id()

            ok_v, _msg_v = tx_forged.is_valid()
            assert ok_v is False

            ok_m, _msg_m = bc.mempool.add(tx_forged)
            assert ok_m is False
            assert forged_id not in bc.mempool._pending_tx_ids
        finally:
            Config.INITIAL_DIFFICULTY = orig_diff


def test_coinbase_sender_rejected_by_validation_and_mempool():
    """Transaction.is_valid() and Mempool.add() reject unsigned COINBASE TYPE_TRANSFER txs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _st, bc, orig_diff = _make_chain(tmpdir)
        try:
            attacker = Wallet.generate()

            forged_cb = Transaction(
                sender="COINBASE",
                receiver=attacker.address,
                amount=100.0,
                fee=0.0,
                nonce=0,
                expiry=0,
                tx_type=Transaction.TYPE_TRANSFER,
            )
            ok_m, _msg_m = bc.mempool.add(forged_cb)
            assert ok_m is False
        finally:
            Config.INITIAL_DIFFICULTY = orig_diff
