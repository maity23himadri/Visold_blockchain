"""Regression coverage for October 2026 gossip/cache poisoning findings."""
from __future__ import annotations

import copy
import json
import os
import tempfile

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _chain(td: str, name: str) -> tuple[Storage, Blockchain]:
    storage = Storage(os.path.join(td, name))
    return storage, Blockchain(storage)


def _mine(bc: Blockchain, txs: list[Transaction], miner: str, height: int) -> Block:
    state_root = bc.dry_run_state_root(txs, miner, height)
    tip = bc.latest_block()
    block = Block(
        index=height,
        prev_hash=tip.block_hash,
        transactions=txs,
        miner_address=miner,
        difficulty=bc.get_difficulty(),
        state_root=state_root,
    )
    assert block.mine()
    return block


def _configure_fast_mining():
    return Config.MIN_DIFFICULTY, Config.INITIAL_DIFFICULTY


def test_mempool_verified_cache_does_not_skip_signature_for_same_txid_forgery():
    old_min, old_init = _configure_fast_mining()
    Config.MIN_DIFFICULTY = Config.INITIAL_DIFFICULTY = 0.001
    try:
        with tempfile.TemporaryDirectory() as td:
            st_a, a = _chain(td, "A.db")
            st_b, b = _chain(td, "B.db")
            assert a.latest_block().block_hash == b.latest_block().block_hash

            victim, miner = Wallet.generate(), Wallet.generate()
            for storage in (st_a, st_b):
                storage.credit_sat(victim.address, 50 * Config.SATOSHI_PER_VSD)

            genuine = Transaction(
                sender=victim.address,
                receiver=Wallet.generate().address,
                amount=1.0,
                fee=0.01,
                nonce=0,
                tx_type=Transaction.TYPE_TRANSFER,
            )
            genuine.sign(victim)
            added, reason = a.mempool.add(copy.deepcopy(genuine))
            assert added, reason
            assert a.mempool.is_verified(genuine.tx_id)
            assert a.mempool.is_verified(
                genuine.tx_id, tx=genuine,
                signing_payload=genuine.signing_bytes())

            forged = Transaction.from_dict(genuine.to_dict())
            forged.sig_hex = json.dumps([1, 1])
            assert forged.tx_id == genuine.tx_id
            assert not forged.verify_signature()
            assert not a.mempool.is_verified(
                forged.tx_id, tx=forged,
                signing_payload=forged.signing_bytes())

            coinbase = Transaction.coinbase(
                miner.address,
                a.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
                1,
            )
            block = _mine(a, [coinbase, forged], miner.address, 1)
            block_a = Block.from_dict(json.loads(json.dumps(block.to_dict())))
            block_b = Block.from_dict(json.loads(json.dumps(block.to_dict())))

            assert block_a.block_hash == block_b.block_hash
            assert a.validate_block(block_a)[0] is False
            assert b.validate_block(block_b)[0] is False
            assert a.apply_block(block_a)[0] is False
            assert b.apply_block(block_b)[0] is False
            assert a.height() == b.height() == 0
    finally:
        Config.MIN_DIFFICULTY, Config.INITIAL_DIFFICULTY = old_min, old_init


def test_exact_signature_cache_fast_path_preserves_valid_block_acceptance():
    old_min, old_init = _configure_fast_mining()
    Config.MIN_DIFFICULTY = Config.INITIAL_DIFFICULTY = 0.001
    try:
        with tempfile.TemporaryDirectory() as td:
            st_a, a = _chain(td, "valid-A.db")
            st_b, b = _chain(td, "valid-B.db")
            victim, miner = Wallet.generate(), Wallet.generate()
            for storage in (st_a, st_b):
                storage.credit_sat(victim.address, 50 * Config.SATOSHI_PER_VSD)

            tx = Transaction(
                sender=victim.address,
                receiver=Wallet.generate().address,
                amount=1.0,
                fee=0.01,
                nonce=0,
                tx_type=Transaction.TYPE_TRANSFER,
            )
            tx.sign(victim)
            added, reason = a.mempool.add(copy.deepcopy(tx))
            assert added, reason

            coinbase = Transaction.coinbase(
                miner.address,
                a.compute_reward_sat(1) / Config.SATOSHI_PER_VSD,
                1,
            )
            block = _mine(a, [coinbase, tx], miner.address, 1)
            wire = json.loads(json.dumps(block.to_dict()))
            block_a = Block.from_dict(wire)
            block_b = Block.from_dict(wire)

            assert a.validate_block(block_a) == (True, "OK")
            assert b.validate_block(block_b) == (True, "OK")
            assert a.apply_block(block_a)[0] is True
            assert b.apply_block(block_b)[0] is True
            assert a.height() == b.height() == 1
    finally:
        Config.MIN_DIFFICULTY, Config.INITIAL_DIFFICULTY = old_min, old_init
