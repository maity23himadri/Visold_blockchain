"""V4 Regression Tests for Section 55: Reward Distribution and Beneficiary Eligibility."""
import json
import sys
import time
from pathlib import Path
import pytest

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.kernel.config import Config
from visold.wallet.wallet import Wallet
from visold.ledger.transaction import Transaction
from visold.ledger.block import Block
from visold.storage.storage import Storage
from visold.chain.blockchain import Blockchain
from visold.economics.rewards import RewardConfig, RewardError, validate_block_rewards
from visold.economics.monitor import EconomicMonitor


def _mine_block(bc: Blockchain, miner_addr: str, txs: list[Transaction]) -> Block:
    tip = bc.storage.get_block(bc.height())
    height = tip.index + 1
    diff = bc.get_difficulty()
    ts = max(int(time.time()), int(tip.timestamp) + 1)
    subsidy_vsd = bc.compute_reward(height)
    cb = Transaction.coinbase(miner_addr, subsidy_vsd, height)
    all_txs = [cb] + list(txs)
    state_root = bc.dry_run_state_root(
        all_txs, miner_addr, height, difficulty=diff, timestamp=ts
    )
    blk = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=all_txs,
        miner_address=miner_addr,
        difficulty=diff,
        timestamp=ts,
        state_root=state_root,
    )
    assert blk.mine()
    return blk


def test_cross_role_reentry_enforces_min_investor_stake(tmp_path, monkeypatch):
    """V4 Fix:
    Same-block REGISTER('none') followed by REGISTER('investor', 0.000001)
    cannot bypass MIN_INVESTOR_STAKE (200 VSD); validate_block() rejects it.
    """
    monkeypatch.setattr(Config, "MIN_DIFFICULTY", 1.0)
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 1.0)
    st = Storage(str(tmp_path / "audit_s55_fix1.db"))
    bc = Blockchain(st)

    alice = Wallet.generate()

    for _ in range(2):
        b = _mine_block(bc, alice.address, [])
        ok, msg = bc.validate_block(b)
        assert ok, msg
        ok, msg = bc.apply_block(b)
        assert ok, msg

    assert st.get_balance_sat(alice.address) == 2 * bc.compute_reward_sat(1)
    assert st.get_balance_sat(alice.address) < Config.MIN_INVESTOR_STAKE

    # Block 3: Alice registers as a miner with 10.0 VSD (MIN_MINER_STAKE).
    tx_reg_miner = Transaction(
        sender=alice.address,
        receiver="",
        amount=10.0,
        fee=0.00001,
        tx_type=Transaction.TYPE_REGISTER,
        memo="miner",
        nonce=st.get_nonce(alice.address),
        expiry=int(time.time()) + 3600,
    )
    tx_reg_miner.sign(alice)
    b3 = _mine_block(bc, alice.address, [tx_reg_miner])
    ok, msg = bc.validate_block(b3)
    assert ok, msg
    ok, msg = bc.apply_block(b3)
    assert ok, msg
    assert st.get_role(alice.address)["role"] == "miner"

    # Block 4: Attempt cross-role re-entry with below-minimum investor stake
    base_nonce = st.get_nonce(alice.address)
    tx_unstake = Transaction(
        sender=alice.address,
        receiver="",
        amount=0.0,
        fee=0.00001,
        tx_type=Transaction.TYPE_REGISTER,
        memo="none",
        nonce=base_nonce,
        expiry=int(time.time()) + 3600,
    )
    tx_unstake.sign(alice)

    tx_reg_investor = Transaction(
        sender=alice.address,
        receiver="",
        amount=0.000001,
        fee=0.00001,
        tx_type=Transaction.TYPE_REGISTER,
        memo="investor",
        nonce=base_nonce + 1,
        expiry=int(time.time()) + 3600,
    )
    tx_reg_investor.sign(alice)

    b4 = _mine_block(bc, alice.address, [tx_unstake, tx_reg_investor])
    ok, _msg = bc.validate_block(b4)
    assert not ok, "Cross-role re-entry below MIN_INVESTOR_STAKE must be rejected"
    assert st.get_role(alice.address)["role"] == "miner"


def test_validate_block_rewards_raises_reward_error_on_malformed_coinbase_payload():
    """V4 Fix:
    validate_block_rewards() raises RewardError on non-dict JSON or non-numeric
    subsidy/fees in coinbase payload.
    """
    class _FakeBlock:
        def __init__(self, txs, height=1):
            self.transactions = txs
            self.height = height
            self.index = height

    miner_addr = Wallet.generate().address

    cb_list = {
        "tx_type": RewardConfig.TX_TYPE_REWARD,
        "sender": RewardConfig.COINBASE_SENDER,
        "receiver": miner_addr,
        "amount": 100,
        "nonce": 1,
        "signature": "",
        "data": json.dumps([1, 2, 3]),
    }
    with pytest.raises(RewardError):
        validate_block_rewards(_FakeBlock([cb_list]), expected_subsidy=100, chain_tip_height=1)

    cb_bad_num = {
        "tx_type": RewardConfig.TX_TYPE_REWARD,
        "sender": RewardConfig.COINBASE_SENDER,
        "receiver": miner_addr,
        "amount": 100,
        "nonce": 1,
        "signature": "",
        "data": json.dumps({"subsidy": "not-an-int", "fees": 0}),
    }
    with pytest.raises(RewardError):
        validate_block_rewards(_FakeBlock([cb_bad_num]), expected_subsidy=100, chain_tip_height=1)


def test_section55_monitor_and_activity_credit_baseline(tmp_path):
    """Verify EconomicMonitor.record_block_rewards / record_reward baseline."""
    st = Storage(str(tmp_path / "audit_s55_base.db"))
    mon = EconomicMonitor(st)
    mon.record_block_rewards("VSDminerA", {"VSDminerA": 500_000_000, "VSDvalB": 350_000_000})
    mon.record_reward("VSDminerA", 1.5)
    assert len(mon._reward_log) == 2
    assert mon._reward_log[0][1] == {"VSDminerA": 500_000_000, "VSDvalB": 350_000_000}
    assert mon._reward_log[1][1] == {"VSDminerA": 150_000_000}
