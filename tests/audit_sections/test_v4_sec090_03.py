"""Section 90 V4 Regression Tests: L2 Balance Conservation and Settlement Consistency."""

import sys
from pathlib import Path

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.chain.blockchain import Blockchain
from visold.ledger.transaction import Transaction
from visold.rollup.l2_state import (
    L2_BRIDGE_ADDRESS,
    L2_WITHDRAW_ADDRESS,
    Layer2State,
)
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def test_l2_tx_to_sentinel_addresses_rejected(tmp_path):
    """V4 fix: L2Transaction.is_valid() and Layer2State.apply_l2_tx() reject
    protocol sentinel addresses as receiver so L2 funds cannot be stranded."""
    st = Storage(str(tmp_path / "l2_sentinel.db"))
    l2 = Layer2State(st)
    alice = Wallet.generate()
    deposit_sat = 500_000_000

    st.credit_sat(L2_BRIDGE_ADDRESS, deposit_sat)
    ok_d, msg_d = l2.L2_deposit(alice.address, deposit_sat, l1_height=1, l1_block_hash="a" * 64)
    assert ok_d, msg_d

    l2tx = alice.sign_l2_tx(receiver=L2_WITHDRAW_ADDRESS, amount_sat=200_000_000, nonce=0)
    ok_v, _ = l2tx.is_valid()
    assert not ok_v

    ok_a, _ = l2.apply_l2_tx(l2tx)
    assert not ok_a

    assert l2.get_balance_sat(L2_WITHDRAW_ADDRESS) == 0
    assert l2.get_balance_sat(alice.address) == deposit_sat
    assert st.get_balance_sat(L2_BRIDGE_ADDRESS) == deposit_sat


def test_dry_run_state_root_accepts_same_block_deposit_then_withdraw(tmp_path):
    """V4 fix: Blockchain.dry_run_state_root() accounts for earlier
    L2_BRIDGE_ADDRESS deposits in the same block when validating a subsequent
    L2_WITHDRAW_ADDRESS transaction."""
    st = Storage(str(tmp_path / "l2_dryrun.db"))
    bc = Blockchain(st)
    alice = Wallet.generate()
    miner = Wallet.generate()
    st.credit_sat(alice.address, 2_000_000_000)

    deposit_tx = Transaction(
        sender=alice.address,
        receiver=L2_BRIDGE_ADDRESS,
        amount=5.0,
        fee=0.005,
        nonce=0,
    )
    deposit_tx.sign(alice)

    withdraw_tx = Transaction(
        sender=alice.address,
        receiver=L2_WITHDRAW_ADDRESS,
        amount=5.0,
        fee=0.005,
        nonce=1,
    )
    withdraw_tx.sign(alice)

    cb = Transaction.coinbase(miner.address, bc.compute_reward(1), 1)

    state_root = bc.dry_run_state_root([cb, deposit_tx, withdraw_tx], miner.address, 1)
    assert isinstance(state_root, str) and len(state_root) == 64
