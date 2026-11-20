"""V4 regression tests for Section 23 (Session 02): Transaction Nonce Management and Replay Protection."""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from visold.chain.blockchain import Blockchain
from visold.chain.roles import RoleManager
from visold.kernel.config import Config
from visold.kernel.units import VSD_GLOBAL_MARKET
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_wallet() -> Wallet:
    return Wallet.generate()


def _make_tx(
    wallet: Wallet,
    receiver: str,
    nonce: int,
    amount: float = 1.0,
    memo: str = "",
    expiry: int = 0,
) -> Transaction:
    fee = round(amount * Config.TX_FEE_RATE, 8)
    ts = int(time.time())
    tx = Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount=amount,
        fee=fee,
        timestamp=ts,
        memo=memo,
        nonce=nonce,
        expiry=expiry if expiry else ts + 3600,
    )
    tx.sign(wallet)
    return tx


def test_vsd_global_market_enforces_mempool_nonce_and_replay_guard(tmp_path):
    """Mempool.add() enforces nonce and replay_guard_exists() for VSD_GLOBAL_MARKET."""
    st = Storage(str(tmp_path / "db.sqlite"))
    mp = Mempool(st)
    w_alice = _make_wallet()
    st.set_nonce(w_alice.address, 0)

    # 1. Gapped VSD_GLOBAL_MARKET tx (nonce=999 > MAX_NONCE_GAP) is rejected
    gap_tx = _make_tx(w_alice, VSD_GLOBAL_MARKET, nonce=999, amount=1.0, memo="ORDER:1")
    ok, _msg = mp.add(gap_tx)
    assert ok is False

    # 2. Stale-nonce VSD_GLOBAL_MARKET tx is rejected
    st2 = Storage(str(tmp_path / "db2.sqlite"))
    mp2 = Mempool(st2)
    st2.set_nonce(w_alice.address, 5)
    stale_gm = _make_tx(w_alice, VSD_GLOBAL_MARKET, nonce=0, amount=1.0, memo="ORDER:stale")
    ok_stale, _ = mp2.add(stale_gm)
    assert ok_stale is False

    # 3. Pruned-tx replay is rejected via replay_guard_exists()
    pruned_gm = _make_tx(w_alice, VSD_GLOBAL_MARKET, nonce=5, amount=1.0, memo="ORDER:pruned")
    st2.record_applied_tx_id(pruned_gm.tx_id)
    assert st2.replay_guard_exists(pruned_gm.tx_id)
    assert not st2.tx_exists(pruned_gm.tx_id)
    ok_replay, _ = mp2.add(pruned_gm)
    assert ok_replay is False


def test_mempool_remove_preserves_shared_pending_nonce_or_prevents_duplicates(tmp_path):
    """Mempool prevents duplicate same-nonce txs from entering in the first place."""
    st = Storage(str(tmp_path / "db.sqlite"))
    mp = Mempool(st)
    w_alice = _make_wallet()
    st.credit_sat(w_alice.address, 100 * Config.SATOSHI_PER_VSD)
    st.set_nonce(w_alice.address, 0)

    tx_a = _make_tx(w_alice, VSD_GLOBAL_MARKET, nonce=0, amount=1.0, memo="ORDER:A")
    tx_b = _make_tx(w_alice, VSD_GLOBAL_MARKET, nonce=0, amount=1.0, memo="ORDER:B")
    assert mp.add(tx_a)[0] is True
    assert mp.add(tx_b)[0] is False


def test_caller_nonce_derivation_handles_pending_nonce_gap(tmp_path):
    """RoleManager._submit_role_tx() computes next available nonce cleanly even with pending nonce gap."""
    st = Storage(str(tmp_path / "db.sqlite"))
    bc = Blockchain(st)
    w_alice = _make_wallet()
    w_bob = _make_wallet()
    st.credit_sat(w_alice.address, 100 * Config.SATOSHI_PER_VSD)
    st.set_nonce(w_alice.address, 0)

    tx0 = _make_tx(w_alice, w_bob.address, nonce=0, amount=1.0)
    tx1 = _make_tx(w_alice, w_bob.address, nonce=1, amount=1.0)
    assert bc.mempool.add(tx0)[0]
    assert bc.mempool.add(tx1)[0]
    bc.mempool.remove(tx0.tx_id)

    engine = StateEngine(bc, bc._governance, st)
    engine.start()
    try:
        rm = RoleManager(st, w_alice, blockchain=bc, state_engine=engine)
        ok, msg = rm.register_miner(Config.MIN_MINER_STAKE / Config.SATOSHI_PER_VSD)
        assert ok is True, msg
    finally:
        engine.stop()


def test_transaction_is_valid_rejects_non_int_and_negative_nonces(tmp_path):
    """Transaction.is_valid() and Mempool.add() reject bool, float, negative, NaN, and huge nonces."""
    w_alice = _make_wallet()
    w_bob = _make_wallet()

    for bad_nonce in (False, 0.0, -1, float("nan"), 2**100):
        try:
            tx = Transaction(
                sender=w_alice.address,
                receiver=w_bob.address,
                amount=1.0,
                fee=round(1.0 * Config.TX_FEE_RATE, 8),
                nonce=bad_nonce,
            )
            tx.sign(w_alice)
            ok, _msg = tx.is_valid()
            assert ok is False, f"Expected is_valid() to reject {bad_nonce!r}"
        except (ValueError, TypeError):
            pass

    st = Storage(str(tmp_path / "db.sqlite"))
    mp = Mempool(st)
    tx_bool = Transaction(
        sender=w_alice.address,
        receiver=w_bob.address,
        amount=1.0,
        fee=round(1.0 * Config.TX_FEE_RATE, 8),
        nonce=False,
    )
    tx_bool.sign(w_alice)
    ok_mp, _msg_mp = mp.add(tx_bool)
    assert ok_mp is False
