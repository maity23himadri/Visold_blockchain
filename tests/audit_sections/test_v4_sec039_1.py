import threading
import time
import pytest

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.consensus.difficulty import DifficultyEngine
from visold.consensus.mining_safety import MiningSafetyGuard
from visold.crypto.ecc import ecdsa_keygen, pub_to_hex
from visold.crypto.hashing import sha256
from visold.crypto.vrf import vrf_prove
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.vm.naming import derive_contract_address
from visold.node.security_gate import SecurityGate
from visold.resilience.hardened_core import (
    ImmediateAbort,
    InvariantViolation,
    SystemInvariantGate,
    TimestampAnomalyError,
    _HardenedSystemMode,
    _hc_panic_cb,
    apply_hardened_overlay,
)
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


@pytest.fixture(autouse=True)
def _fast_test_difficulty(monkeypatch):
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    monkeypatch.setattr(Config, "MIN_DIFFICULTY", 0.001)
    DifficultyEngine.invalidate_cache(from_height=0)
    yield
    DifficultyEngine.invalidate_cache(from_height=0)


def _make_wallet(tmp_path, name="miner"):
    priv, pub = ecdsa_keygen()
    return Wallet(priv, pub)


def _mine_block(bc: Blockchain, consensus: ConsensusEngine, wallet: Wallet) -> Block:
    latest = bc.latest_block()
    alpha = (latest.block_hash if latest else "genesis").encode()
    vrf_proof, vrf_beta = vrf_prove(wallet.priv, alpha)
    cand = consensus.build_candidate_block(
        wallet.address, vrf_proof.hex(), vrf_beta.hex()
    )
    cand.nonce = 0
    while not cand.validate_pow():
        cand.nonce += 1
    cand.block_hash = cand.compute_hash()
    cand.seal()
    return cand


def _reset_hc_cb():
    with _hc_panic_cb._mode_lock:
        _hc_panic_cb._mode = _HardenedSystemMode.NORMAL
        _hc_panic_cb._subsystems.clear()
        _hc_panic_cb._corruption_count = 0
        _hc_panic_cb._corruption_timestamps.clear()
        _hc_panic_cb._read_only_since = 0.0


def test_hardened_apply_block_accepts_defer_finality_kwarg(tmp_path):
    """
    V4 regression (Finding 1): apply_hardened_overlay() preserves the
    defer_finality keyword argument on blockchain.apply_block().
    """
    _reset_hc_cb()
    storage = Storage(str(tmp_path / "node.db"))
    bc = Blockchain(storage)
    wallet = _make_wallet(tmp_path)
    consensus = ConsensusEngine(bc, wallet)

    apply_hardened_overlay(bc, storage_instance=storage, start_ntp_clock=False)

    blk = _mine_block(bc, consensus, wallet)
    ok, msg = bc.apply_block(blk, defer_finality=True)
    assert ok is True, msg


def test_hardened_apply_block_supports_accept_chain_reorg(tmp_path):
    """
    V4 regression (Finding 1b): A hardened node reorganizes cleanly onto a
    longer peer fork via Blockchain.accept_chain() without TypeError.
    """
    _reset_hc_cb()
    storage_a = Storage(str(tmp_path / "node_a.db"))
    bc_a = Blockchain(storage_a)
    wallet_a = _make_wallet(tmp_path, "a")
    consensus_a = ConsensusEngine(bc_a, wallet_a)

    blk_a1 = _mine_block(bc_a, consensus_a, wallet_a)
    ok, msg = bc_a.apply_block(blk_a1)
    assert ok, msg

    storage_b = Storage(str(tmp_path / "node_b.db"))
    bc_b = Blockchain(storage_b)
    gen_a = bc_a.get_block(0)
    assert gen_a is not None
    storage_b.save_block(gen_a)
    wallet_b = _make_wallet(tmp_path, "b")
    consensus_b = ConsensusEngine(bc_b, wallet_b)
    blk_b1 = _mine_block(bc_b, consensus_b, wallet_b)
    ok1, msg1 = bc_b.apply_block(blk_b1)
    assert ok1, msg1
    blk_b2 = _mine_block(bc_b, consensus_b, wallet_b)
    ok2, msg2 = bc_b.apply_block(blk_b2)
    assert ok2, msg2

    apply_hardened_overlay(bc_a, storage_instance=storage_a, start_ntp_clock=False)

    reorg_ok, reorg_msg = bc_a.accept_chain([gen_a, blk_b1, blk_b2])
    assert reorg_ok is True, reorg_msg
    assert bc_a._critical_recovery is None
    assert bc_a.height() == 2


def test_candidate_precheck_excludes_call_to_nonexistent_contract(tmp_path):
    """
    V4 regression (Finding 2): build_candidate_block() excludes a CALL
    transaction targeting a non-existent contract so validate_block() passes.
    """
    _reset_hc_cb()
    storage = Storage(str(tmp_path / "call_bug.db"))
    bc = Blockchain(storage)
    wallet = _make_wallet(tmp_path)
    consensus = ConsensusEngine(bc, wallet)

    blk1 = _mine_block(bc, consensus, wallet)
    ok, msg = bc.apply_block(blk1)
    assert ok, msg

    missing_contract = derive_contract_address(wallet.address, 0, "a" * 64)
    call_tx = Transaction(
        sender=wallet.address,
        receiver=missing_contract,
        amount=0.0,
        fee=0.01,
        nonce=0,
        tx_type=Transaction.TYPE_CALL,
        data="deadbeef",
        gas_limit=50_000,
        gas_price=0.000001,
        expiry=int(time.time()) + 3600,
        pub_hex=wallet.pub_hex,
    )
    call_tx.sign(wallet)
    ok_mem, mem_msg = bc.mempool.add(call_tx)
    assert ok_mem, mem_msg

    cand = _mine_block(bc, consensus, wallet)
    assert not any(tx.tx_id == call_tx.tx_id for tx in cand.transactions)

    v_ok, v_msg = bc.validate_block(cand)
    assert v_ok is True, v_msg


def test_hardened_apply_block_rejects_nan_timestamp_cleanly(tmp_path):
    """
    V4 regression (Finding 3): Both validate_block() and hardened apply_block()
    reject a NaN timestamp cleanly with (False, reason) instead of raising ValueError.
    """
    _reset_hc_cb()
    storage = Storage(str(tmp_path / "nan_ts.db"))
    bc = Blockchain(storage)
    wallet = _make_wallet(tmp_path)
    consensus = ConsensusEngine(bc, wallet)

    blk = _mine_block(bc, consensus, wallet)
    blk.timestamp = float("nan")

    v_ok, v_msg = bc.validate_block(blk)
    assert not v_ok
    assert "integer" in v_msg.lower() or "finite" in v_msg.lower()

    apply_hardened_overlay(bc, storage_instance=storage, start_ntp_clock=False)
    h_ok, h_msg = bc.apply_block(blk)
    assert not h_ok
    assert h_msg


def test_verified_mining_safety_guard_and_security_gate(tmp_path, monkeypatch):
    """Verify core invariants of MiningSafetyGuard, SecurityGate, and SystemInvariantGate."""
    _reset_hc_cb()
    storage = Storage(str(tmp_path / "verify.db"))
    bc = Blockchain(storage)

    ok, msg = SecurityGate.verify_genesis_hash(storage, bc)
    assert ok, msg
    storage.set_meta("genesis_hash", "0" * 64)
    ok_bad, msg_bad = SecurityGate.verify_genesis_hash(storage, bc)
    assert not ok_bad
    assert "tampered" in msg_bad.lower()

    monkeypatch.setattr(Config, "MINING_SAFETY_ENABLED", True)
    monkeypatch.setattr(Config, "MINING_SYNC_REQUIRED_BEFORE_MINE", True)
    monkeypatch.setattr(Config, "MINING_SYNC_HEIGHT_TOLERANCE", 1)
    monkeypatch.setattr(Config, "MINING_SYNC_MAX_WAIT", 0.05)
    monkeypatch.setattr(Config, "MINING_SYNC_PROBE_INTERVAL", 0.01)
    monkeypatch.setattr(Config, "MINING_STALE_CANDIDATE_TIMEOUT", 0.02)

    guard = MiningSafetyGuard(bc, best_peer_height_fn=lambda: 5)
    stop_evt = threading.Event()
    proceed, why = guard.pre_mine_sync_check(stop_evt)
    assert not proceed
    assert "withheld" in why
    assert guard.sync_stalled is True

    guard.mining_started()
    time.sleep(0.03)
    assert guard.mining_should_abort() is True
    guard.mining_finished()
    assert guard.mining_should_abort() is False

    with pytest.raises(ImmediateAbort):
        SystemInvariantGate.assert_debit_safe("addr1", 100, 200, "test")
    with pytest.raises(InvariantViolation):
        SystemInvariantGate.assert_supply_cap(21_000_000 * 100_000_000 + 1, "test")
    with pytest.raises(TimestampAnomalyError):
        SystemInvariantGate.assert_timestamp_valid("not-a-ts", "test")
