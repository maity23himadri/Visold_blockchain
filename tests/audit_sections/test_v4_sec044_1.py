"""V4 regression tests for Section 44 (Session 03): GPU Mining Kernels and Hash Computation."""

from __future__ import annotations

import struct

from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mining.parallel_miner import GPU_KERNELS_VERIFIED, ParallelMiner
from visold.wallet.wallet import Wallet


def test_gpu_kernels_disabled_by_vsa29_guard():
    assert GPU_KERNELS_VERIFIED is False
    old_gpu = Config.MINING_GPU_ENABLED
    Config.MINING_GPU_ENABLED = True
    try:
        pm = ParallelMiner()
        backend = pm.initialize()
        assert backend == "cpu"
    finally:
        Config.MINING_GPU_ENABLED = old_gpu


def test_target_to_words_and_binary_header_layout():
    for diff in (0.0, 0.001, 1.5, 10.0, 64.0):
        target = DifficultyEngine.difficulty_to_target(diff)
        words = ParallelMiner._target_to_words(target)
        assert len(words) == 8
        reconstructed = b"".join(struct.pack(">I", w) for w in words)
        assert reconstructed == target.to_bytes(32, "big")

    miner = Wallet.generate()
    cb = Transaction.coinbase(miner.address, 50.0, 1)
    blk = Block(
        index=1,
        prev_hash="a" * 64,
        transactions=[cb],
        miner_address=miner.address,
        difficulty=0.001,
        state_root="b" * 64,
        vrf_proof="deadbeef",
    )
    pm = ParallelMiner()
    hdr = pm._build_binary_header(blk, nonce=0x0102030405060708)
    assert len(hdr) == ParallelMiner.HEADER_LEN == 136
    assert hdr[16:24] == struct.pack("<Q", 0x0102030405060708)


def test_json_verify_matches_block_validate_pow():
    miner = Wallet.generate()
    cb = Transaction.coinbase(miner.address, 50.0, 1)
    blk = Block(
        index=1,
        prev_hash="0" * 64,
        transactions=[cb],
        miner_address=miner.address,
        difficulty=0.001,
        state_root="c" * 64,
    )
    assert blk.mine()
    pm = ParallelMiner()

    blk_check = Block(
        index=blk.index,
        prev_hash=blk.prev_hash,
        transactions=list(blk.transactions),
        miner_address=blk.miner_address,
        difficulty=blk.difficulty,
        timestamp=blk.timestamp,
        state_root=blk.state_root,
    )
    assert pm._json_verify(blk_check, blk.nonce) is True
    assert blk_check.validate_pow() is True

    blk_bad = Block(
        index=blk.index,
        prev_hash=blk.prev_hash,
        transactions=list(blk.transactions),
        miner_address=blk.miner_address,
        difficulty=blk.difficulty,
        timestamp=blk.timestamp,
        nonce=blk.nonce,
        block_hash="f" * 64,
        state_root=blk.state_root,
    )
    assert blk_bad.validate_pow() is False
