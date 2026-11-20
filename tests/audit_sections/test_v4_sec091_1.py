"""
VISOLD V4 Regression Tests — Section 91: Mempool Transaction Admission and Validation
Converted from V3 audit PoCs to assert fixed V4 behavior.
"""

import pytest

from visold.kernel.config import Config
from visold.kernel.units import VSD_GLOBAL_MARKET, to_satoshi
from visold.wallet.wallet import Wallet
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.mempool.pool import Mempool
from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.state.engine import StateEngine


@pytest.fixture
def env(tmp_path):
    """Create an isolated Storage + Blockchain + Mempool + Wallet fixture."""
    db_path = str(tmp_path / "visold_test.db")
    storage = Storage(db_path)
    bc = Blockchain(storage)
    alice = Wallet.generate()
    bob = Wallet.generate()
    storage.credit_sat(alice.address, to_satoshi(1000.0))
    return {
        "storage": storage,
        "bc": bc,
        "mempool": bc.mempool,
        "alice": alice,
        "bob": bob,
    }


def test_v4_mempool_rejects_unauthenticated_coinbase(env):
    """
    Fixed: Mempool.add() and StateEngine._handle_new_tx() reject
    unauthenticated sender="COINBASE" transactions so they cannot poison blocks.
    """
    mempool: Mempool = env["mempool"]
    bc: Blockchain = env["bc"]
    alice: Wallet = env["alice"]

    fake_cb = Transaction(
        sender="COINBASE",
        receiver=alice.address,
        amount=500.0,
        fee=0.0,
        nonce=0,
        expiry=0,
        memo="forged-coinbase",
    )

    add_ok, add_msg = mempool.add(fake_cb)
    assert add_ok is False, f"Expected Mempool.add() to reject forged COINBASE, got: {add_msg}"
    assert mempool.size() == 0

    fake_cb_p2p = Transaction(
        sender="COINBASE",
        receiver=alice.address,
        amount=999.0,
        fee=0.0,
        nonce=0,
        expiry=0,
        memo="forged-coinbase-p2p",
    )
    engine = StateEngine(bc, None, env["storage"])
    p2p_ok, p2p_msg = engine._handle_new_tx({"tx": fake_cb_p2p.to_dict()}, source_peer="peer1:8333")
    assert p2p_ok is False, f"Expected _handle_new_tx() to reject forged COINBASE, got: {p2p_msg}"
    assert mempool.size() == 0

    ce = ConsensusEngine(bc, alice)
    candidate = ce.build_candidate_block(alice.address)
    coinbase_count = sum(1 for tx in candidate.transactions if tx.sender == "COINBASE")
    assert coinbase_count == 1, f"Expected exactly 1 COINBASE tx in candidate, got {coinbase_count}"


def test_v4_mempool_rejects_forged_tx_id(env):
    """
    Fixed: Transaction.is_valid() and Mempool.add() verify tx.tx_id == tx._compute_id()
    and reject tampered tx_ids.
    """
    mempool: Mempool = env["mempool"]
    alice: Wallet = env["alice"]
    bob: Wallet = env["bob"]

    tx = Transaction(
        sender=alice.address,
        receiver=bob.address,
        amount=10.0,
        fee=0.1,
        nonce=0,
    )
    tx.sign(alice)
    real_id = tx.tx_id
    forged_id = "deadbeef" * 8
    assert forged_id != real_id

    tx_dict = tx.to_dict()
    tx_dict["tx_id"] = forged_id
    tampered = Transaction.from_dict(tx_dict)

    assert tampered.tx_id == forged_id
    assert tampered.verify_signature() is True

    v_ok, v_msg = tampered.is_valid()
    assert v_ok is False, f"Expected is_valid() to reject forged tx_id, got: {v_msg}"

    add_ok, add_msg = mempool.add(tampered)
    assert add_ok is False, f"Expected Mempool.add() to reject forged tx_id, got: {add_msg}"
    assert mempool.size() == 0


def test_v4_mempool_rejects_zero_expiry_non_coinbase(env):
    """
    Fixed: Mempool.add() rejects non-coinbase transactions with expiry=0 when
    EXPIRY_REQUIRED_ACTIVATION_HEIGHT == 0, preventing unmineable nonce-blocking txs.
    """
    mempool: Mempool = env["mempool"]
    bc: Blockchain = env["bc"]
    alice: Wallet = env["alice"]
    bob: Wallet = env["bob"]

    assert Config.EXPIRY_REQUIRED_ACTIVATION_HEIGHT == 0

    tx0 = Transaction(
        sender=alice.address,
        receiver=bob.address,
        amount=5.0,
        fee=0.05,
        nonce=0,
        expiry=0,
    )
    tx0.expiry = 0
    tx0.sign(alice)
    assert tx0.expiry == 0

    add_ok, add_msg = mempool.add(tx0)
    assert add_ok is False, f"Expected Mempool.add() to reject expiry=0, got: {add_msg}"
    assert mempool.size() == 0

    # Honest nonce=0 tx with valid expiry is admitted and mineable
    tx_valid = Transaction(
        sender=alice.address,
        receiver=bob.address,
        amount=5.0,
        fee=0.05,
        nonce=0,
    )
    tx_valid.sign(alice)
    assert tx_valid.expiry > 0
    ok1, msg1 = mempool.add(tx_valid)
    assert ok1 is True, f"Expected valid nonce=0 to be admitted, got: {msg1}"

    ce = ConsensusEngine(bc, alice)
    candidate = ce.build_candidate_block(alice.address)
    cand_ids = {t.tx_id for t in candidate.transactions}
    assert tx0.tx_id not in cand_ids
    assert tx_valid.tx_id in cand_ids


def test_v4_mempool_enforces_nonce_check_for_vsd_global_market(env):
    """
    Fixed: Mempool.add() enforces nonce gap limits for VSD_GLOBAL_MARKET
    transactions just like normal transactions.
    """
    mempool: Mempool = env["mempool"]
    alice: Wallet = env["alice"]

    tx_gapped = Transaction(
        sender=alice.address,
        receiver=VSD_GLOBAL_MARKET,
        amount=1.0,
        fee=0.01,
        nonce=9999,
    )
    tx_gapped.sign(alice)

    ok_gap, msg_gap = mempool.add(tx_gapped)
    assert ok_gap is False, f"Expected Mempool.add() to reject gapped VSD_GLOBAL_MARKET nonce, got: {msg_gap}"
    assert "Nonce too far ahead" in msg_gap

    tx_normal_gap = Transaction(
        sender=alice.address,
        receiver=env["bob"].address,
        amount=1.0,
        fee=0.01,
        nonce=9999,
    )
    tx_normal_gap.sign(alice)
    ok_norm, msg_norm = mempool.add(tx_normal_gap)
    assert ok_norm is False
    assert "Nonce too far ahead" in msg_norm
