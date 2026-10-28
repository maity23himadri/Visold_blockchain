from __future__ import annotations

import hashlib
import json
import os
import time
import zlib

import pytest

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.ledger.transaction import Transaction
from visold.network.bootstrap_sync import verify_bootstrap_header_chain
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


@pytest.fixture
def tiny_bootstrap_config(monkeypatch):
    DifficultyEngine.invalidate_cache()
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 2)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 3)
    monkeypatch.setattr(Config, "BOOTSTRAP_HEADER_PAGE_SIZE", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 100)
    monkeypatch.setattr(Config, "SNAPSHOT_KEEP", 2)
    yield
    DifficultyEngine.invalidate_cache()


def _mine_to(chain: Blockchain, miner: Wallet, height: int):
    chain._rolling_pruner.prune_async = lambda _height: None
    engine = ConsensusEngine(chain, miner)
    while chain.height() < height:
        block = engine.build_candidate_block(miner.address)
        assert block.mine(), f"PoW failed at {block.index}"
        ok, msg = chain.apply_block(block)
        assert ok, msg


def _source_chain(path: str):
    storage = Storage(path)
    chain = Blockchain(storage)
    miner = Wallet.generate()
    _mine_to(chain, miner, 5)
    entry = next(e for e in chain._snapshot_engine.get_manifest()
                 if int(e["height"]) == 4)
    blob = chain._snapshot_engine.get_snapshot_blob(4)
    headers = [chain.get_block(h).to_dict() for h in range(6)]
    ok, msg, verified, digest = verify_bootstrap_header_chain(
        headers, storage.get_meta("genesis_hash"), 4)
    assert ok, msg
    assert digest == entry["bootstrap_digest"]
    return storage, chain, miner, blob, verified, digest


def test_failed_bootstrap_restores_prior_state_headers_and_metadata(
    tmp_path, tiny_bootstrap_config, monkeypatch
):
    source_storage, source, miner, blob, verified, digest = _source_chain(
        str(tmp_path / "source.db"))
    target_path = str(tmp_path / "target.db")
    target_storage = Storage(target_path)
    target = Blockchain(target_storage)
    before_height = target.height()
    before_balance = target_storage.get_balance(miner.address)
    target_storage.set_meta("l2_history", "old-local-history")
    target_storage.set_meta("cumulative_issued_sat", "12345")

    original_set_meta = target_storage.set_meta
    injected = {"done": False}

    def fail_l2_history_once(key, value):
        if key == "l2_history" and not injected["done"]:
            injected["done"] = True
            raise OSError("injected l2_history persistence failure")
        return original_set_meta(key, value)

    monkeypatch.setattr(target_storage, "set_meta", fail_l2_history_once)
    ok, msg = target._snapshot_engine.restore_authenticated_bootstrap(
        blob, digest, verified)
    assert not ok
    assert "rolled back" in msg
    assert injected["done"]
    assert target.height() == before_height
    assert target_storage.get_balance(miner.address) == before_balance
    assert target.get_block(4) is None
    assert target_storage.get_meta("l2_history") == "old-local-history"
    assert target_storage.get_meta("cumulative_issued_sat") == "12345"
    assert not target_storage.get_meta("bootstrap_restore_in_progress")
    assert not target_storage.get_meta("bootstrap_restore_backup")


def test_interrupted_bootstrap_journal_recovers_on_engine_startup(
    tmp_path, tiny_bootstrap_config
):
    source_storage, source, miner, blob, verified, digest = _source_chain(
        str(tmp_path / "source2.db"))
    target_path = str(tmp_path / "target-restart.db")
    target_storage = Storage(target_path)
    target = Blockchain(target_storage)
    local_h = target.height()
    sig_start = max(0, 4 - int(Config.FORK_SIGNAL_WINDOW) - 1)
    journal = target._snapshot_engine._create_bootstrap_journal(local_h, 4, sig_start)

    # Simulate a process dying after installing only part of the header range.
    from visold.ledger.block import Block
    h = 1
    d = dict(verified[h])
    d["transactions"] = []
    d["pruned"] = True
    d["finalized"] = False
    d["validator_sigs"] = []
    target_storage.save_block(Block.from_dict(d))
    assert target_storage.get_meta("bootstrap_restore_in_progress") == "4"

    # Constructor performs the same durable recovery path used after a real crash.
    target2 = Blockchain(target_storage)
    assert target2.height() == local_h
    assert target_storage.get_block(1) is None
    assert not target_storage.get_meta("bootstrap_restore_in_progress")
    assert not target_storage.get_meta("bootstrap_restore_backup")
    assert target_storage.get_meta("chain_recovery_required") is None


def test_archive_write_failure_stops_before_pruning_eligible_transfer(
    tmp_path, tiny_bootstrap_config
):
    # This is an actual signed transfer in the canonical block, not a synthetic
    # transaction projection. Its recipient qualifies it for permanent history.
    path = str(tmp_path / "pruner.db")
    storage = Storage(path)
    chain = Blockchain(storage)
    sender = Wallet.generate()
    receiver = Wallet.generate()
    _mine_to(chain, sender, 1)

    tx = Transaction(
        sender=sender.address,
        receiver=receiver.address,
        amount=5.0,
        fee=0.05,
        nonce=storage.get_nonce(sender.address),
        timestamp=int(time.time()),
    )
    tx.sign(sender)
    admitted, msg = chain.mempool.add(tx)
    assert admitted, msg
    chain._rolling_pruner.prune_async = lambda _height: None
    candidate = ConsensusEngine(chain, sender).build_candidate_block(sender.address)
    assert candidate.mine()
    ok, msg = chain.apply_block(candidate)
    assert ok, msg
    containing_height = candidate.index
    assert any(item.tx_id == tx.tx_id for item in candidate.transactions)

    # Advance one block so maybe_prune's normal minimum-height condition passes.
    _mine_to(chain, sender, 3)
    storage.set_meta("own_address", receiver.address)
    storage.set_meta("rolling_prune_reconcile_version", "1")
    storage.set_meta("rolling_pruned_until", "0")
    chain._rolling_pruner._recoverability_aligned_cutoff = lambda _h: containing_height + 1

    c = storage._conn()
    c.execute(
        """CREATE TRIGGER fail_permanent_history_insert
           BEFORE INSERT ON permanent_history
           BEGIN SELECT RAISE(ABORT, 'injected required archive failure'); END"""
    )
    c.commit()

    processed = chain._rolling_pruner.maybe_prune(chain.height())
    block_after = chain.get_block(containing_height)
    assert processed < containing_height + 1
    assert block_after is not None and not block_after.is_pruned
    assert any(item.tx_id == tx.tx_id for item in block_after.transactions)
    assert c.execute(
        "SELECT COUNT(*) FROM transactions WHERE tx_id=?", (tx.tx_id,)
    ).fetchone()[0] == 1
    assert c.execute(
        "SELECT COUNT(*) FROM permanent_history WHERE tx_hash=?", (tx.tx_id,)
    ).fetchone()[0] == 0
    assert int(storage.get_meta("rolling_pruned_until") or 0) <= containing_height


def test_real_sqlite_l2_history_write_error_is_rolled_back_atomically(
    tmp_path, tiny_bootstrap_config
):
    source_storage, source, miner, blob, verified, digest = _source_chain(
        str(tmp_path / "source-trigger.db"))
    target_path = str(tmp_path / "target-trigger.db")
    storage = Storage(target_path)
    chain = Blockchain(storage)
    storage.set_meta("l2_history", "old-local-history")
    storage.set_meta("cumulative_issued_sat", "7654321")
    before_height = chain.height()
    before_balance = storage.get_balance(miner.address)

    c = storage._conn()
    c.execute(
        """CREATE TRIGGER fail_bootstrap_l2_history
           BEFORE INSERT ON node_meta
           WHEN NEW.key='l2_history' AND NEW.value <> 'old-local-history'
           BEGIN SELECT RAISE(ABORT, 'injected l2_history SQL write failure'); END"""
    )
    c.commit()

    ok, msg = chain._snapshot_engine.restore_authenticated_bootstrap(
        blob, digest, verified)
    assert not ok
    assert "rolled back" in msg
    assert chain.height() == before_height
    assert storage.get_balance(miner.address) == before_balance
    assert chain.get_block(4) is None
    assert storage.get_meta("l2_history") == "old-local-history"
    assert storage.get_meta("cumulative_issued_sat") == "7654321"
    assert not storage.get_meta("bootstrap_restore_in_progress")
    assert not storage.get_meta("bootstrap_restore_backup")


def test_failed_bootstrap_rollback_preserves_destroyed_contract_tombstones(
    tmp_path, tiny_bootstrap_config, monkeypatch
):
    source_storage, source, miner, blob, verified, digest = _source_chain(
        str(tmp_path / "source-tombstone.db"))
    path = str(tmp_path / "target-tombstone.db")
    storage = Storage(path)
    chain = Blockchain(storage)
    tombstone = "destroyed-contract-test-address"
    code = b"local historical bytecode"
    code_hash = hashlib.sha256(code).hexdigest()
    c = storage._conn()
    c.execute(
        """INSERT INTO contract_accounts
           (address,code_hash,storage_root,nonce,creator,created_at,contract_name,destroyed)
           VALUES (?,?,?,?,?,?,?,1)""",
        (tombstone, code_hash, "old-inactive-root", 7, "creator", 12, "old-name"),
    )
    c.execute("INSERT INTO contract_code (code_hash,bytecode) VALUES (?,?)",
              (code_hash, code.hex()))
    c.execute("INSERT INTO contract_storage (contract_addr,slot_key,slot_value) VALUES (?,?,?)",
              (tombstone, "slot-1", "42"))
    c.execute("INSERT INTO contract_storage_tags (contract_addr,slot_key,type_tag) VALUES (?,?,?)",
              (tombstone, "slot-1", 2))
    c.commit()

    original_set_meta = storage.set_meta
    def fail_l2_history(key, value):
        if key == "l2_history":
            raise OSError("injected post-state metadata failure")
        return original_set_meta(key, value)
    monkeypatch.setattr(storage, "set_meta", fail_l2_history)

    ok, msg = chain._snapshot_engine.restore_authenticated_bootstrap(blob, digest, verified)
    assert not ok and "rolled back" in msg
    row = c.execute(
        "SELECT code_hash,storage_root,nonce,destroyed FROM contract_accounts WHERE address=?",
        (tombstone,),
    ).fetchone()
    assert row is not None
    assert row["code_hash"] == code_hash
    assert row["storage_root"] == "old-inactive-root"
    assert row["nonce"] == 7
    assert row["destroyed"] == 1
    assert c.execute(
        "SELECT bytecode FROM contract_code WHERE code_hash=?", (code_hash,)
    ).fetchone()[0] == code.hex()
    assert c.execute(
        "SELECT slot_value FROM contract_storage WHERE contract_addr=? AND slot_key=?",
        (tombstone, "slot-1"),
    ).fetchone()[0] == "42"
    assert c.execute(
        "SELECT type_tag FROM contract_storage_tags WHERE contract_addr=? AND slot_key=?",
        (tombstone, "slot-1"),
    ).fetchone()[0] == 2
