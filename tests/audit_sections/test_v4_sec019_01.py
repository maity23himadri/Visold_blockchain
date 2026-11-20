"""Section 19 V4 Regression Tests: Parallel Signature Verification and Pool Recovery."""

import os
from pathlib import Path
import signal
import sys
import time

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.crypto.parallel_verify import (
    _PAR_SIG_THRESHOLD,
    _get_sig_pool,
    _par_verify_sig,
    shutdown_signature_pool,
)
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.mempool.pool import Mempool
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_signed_tx(wallet: Wallet, receiver: str, amount: float, nonce: int) -> Transaction:
    tx = Transaction(
        sender=wallet.address,
        receiver=receiver,
        amount=amount,
        fee=round(amount * 0.001, 8),
        timestamp=int(time.time()),
        nonce=nonce,
    )
    tx.sign(wallet)
    return tx


def _make_block(index: int, txs: list[Transaction], prev_hash: str = "0" * 64) -> Block:
    miner = txs[0].sender if txs else "VSD" + "1" * 30
    cb = Transaction(
        sender="COINBASE",
        receiver=miner,
        amount=50.0,
        fee=0.0,
        timestamp=int(time.time()),
        nonce=0,
    )
    blk = Block(
        index=index,
        transactions=[cb] + txs,
        prev_hash=prev_hash,
        miner_address=miner,
        timestamp=int(time.time()),
        difficulty=1,
    )
    blk.merkle_root = blk._merkle()
    blk.block_hash = blk.compute_hash()
    return blk


class TestSection19ConsistencyAndFixedRegressions:
    def teardown_method(self):
        shutdown_signature_pool(wait=True)

    def test_parallel_and_sequential_parity_for_valid_and_invalid_sigs(self):
        w1 = Wallet.generate()
        w2 = Wallet.generate()
        txs = [_make_signed_tx(w1, w2.address, 1.0, i) for i in range(_PAR_SIG_THRESHOLD)]
        blk = _make_block(1, txs)

        ok, msg = blk.integrity_check()
        assert ok, f"Expected valid block to pass integrity_check, got: {msg}"

        txs[2].sig_hex = txs[0].sig_hex
        ok_bad, _ = blk.integrity_check()
        assert not ok_bad
        assert not txs[2].verify_signature(block_height=1)
        assert not _par_verify_sig(
            txs[2].pub_hex, txs[2].sig_hex, txs[2].signing_bytes(1), txs[2].sender
        )

    def test_mempool_fingerprint_rejects_tampered_sig_with_same_txid(self, tmp_path):
        storage = Storage(str(tmp_path / "db.sqlite"))
        try:
            mempool = Mempool(storage)
            w1 = Wallet.generate()
            w2 = Wallet.generate()
            tx = _make_signed_tx(w1, w2.address, 1.0, 0)
            mempool._record_signature_verified(tx)

            payload = tx.signing_bytes(1)
            assert mempool.is_verified(tx.tx_id, tx=tx, signing_payload=payload)

            tampered = Transaction(
                sender=tx.sender,
                receiver=tx.receiver,
                amount=tx.amount,
                fee=tx.fee,
                timestamp=tx.timestamp,
                pub_hex=tx.pub_hex,
                sig_hex="[1, 2]",
                tx_id=tx.tx_id,
                memo=tx.memo,
                nonce=tx.nonce,
                expiry=tx.expiry,
            )
            assert not mempool.is_verified(tx.tx_id, tx=tampered, signing_payload=payload)
        finally:
            storage.close()

    def test_broken_sig_pool_recovers_automatically(self):
        """V4 fix for BUG-19-01: broken _SIG_POOL is detected and reset/recovered automatically."""
        w1 = Wallet.generate()
        w2 = Wallet.generate()
        txs = [_make_signed_tx(w1, w2.address, 1.0, i) for i in range(_PAR_SIG_THRESHOLD)]
        blk1 = _make_block(1, txs)

        ok, msg = blk1.integrity_check()
        assert ok, msg

        pool = _get_sig_pool()
        pids = list(pool._processes.keys())
        assert pids, "Expected active worker processes in _SIG_POOL"

        # Simulate unexpected worker death
        os.kill(pids[0], signal.SIGKILL)
        time.sleep(0.2)

        # Subsequent block integrity_check recovers cleanly instead of raising BrokenProcessPool
        blk2 = _make_block(2, [_make_signed_tx(w1, w2.address, 1.0, i) for i in range(_PAR_SIG_THRESHOLD)])
        ok2, msg2 = blk2.integrity_check()
        assert ok2, msg2
        assert _get_sig_pool() is not pool
