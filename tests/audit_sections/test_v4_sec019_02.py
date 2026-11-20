import hashlib
from pathlib import Path
import sys

V4_ROOT = Path(__file__).resolve().parents[2]
if str(V4_ROOT) not in sys.path:
    sys.path.insert(0, str(V4_ROOT))

from visold.crypto.ecc import ecdsa_keygen, ecdsa_sign, pub_to_address, pub_to_hex, sig_to_hex
from visold.crypto.parallel_verify import _par_verify_sig, _par_verify_sig_batch, shutdown_signature_pool
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction


def _make_signed_none_sender_tx(receiver: str, nonce: int, invalid_sig: bool = False) -> Transaction:
    priv, pub = ecdsa_keygen()
    tx = Transaction(
        sender=None,
        receiver=receiver,
        amount=1.0,
        fee=0.001,
        timestamp=1700000000 + nonce,
        nonce=nonce,
        expiry=1800000000,
    )
    tx.pub_hex = pub_to_hex(pub)
    if invalid_sig:
        tx.sig_hex = "[1, 2]"
    else:
        h = hashlib.sha256(tx.signing_bytes()).digest()
        tx.sig_hex = sig_to_hex(ecdsa_sign(priv, h))
    tx.tx_id = tx._compute_id()
    return tx


class TestSection19FixedRegressions:
    def teardown_method(self):
        shutdown_signature_pool(wait=True)

    def test_par_verify_sig_rejects_none_sender(self):
        """V4 fix: _par_verify_sig and _par_verify_sig_batch reject sender=None."""
        _, recipient_pub = ecdsa_keygen()
        receiver = pub_to_address(recipient_pub)
        tx = _make_signed_none_sender_tx(receiver=receiver, nonce=1, invalid_sig=False)

        assert tx.verify_signature() is False
        assert _par_verify_sig(
            tx.pub_hex,
            tx.sig_hex,
            tx.signing_bytes(),
            sender=tx.sender,
        ) is False

        assert _par_verify_sig_batch([
            (tx.pub_hex, tx.sig_hex, tx.signing_bytes(), tx.sender, None)
        ]) == 0

    def test_block_integrity_check_rejects_none_sender_sequential_and_parallel(self):
        """V4 fix: Block.integrity_check() rejects sender=None in both sequential and parallel paths."""
        _, recipient_pub = ecdsa_keygen()
        receiver = pub_to_address(recipient_pub)

        # Sequential path (< 4 non-coinbase txs)
        tx_seq = _make_signed_none_sender_tx(receiver=receiver, nonce=1, invalid_sig=False)
        cb = Transaction.coinbase(receiver, 50.0, block_height=1)
        blk_seq = Block(
            index=1,
            prev_hash="0" * 64,
            transactions=[cb, tx_seq],
            miner_address=receiver,
            difficulty=1,
            timestamp=1700000100,
        )
        verified_seq = set()
        ok_seq, _ = blk_seq.integrity_check(verified_txids=verified_seq)
        assert ok_seq is False
        assert tx_seq.tx_id not in verified_seq

        # Parallel path (>= 4 non-coinbase txs)
        txs_par = [_make_signed_none_sender_tx(receiver=receiver, nonce=i, invalid_sig=False) for i in range(1, 5)]
        blk_par = Block(
            index=1,
            prev_hash="0" * 64,
            transactions=[cb] + txs_par,
            miner_address=receiver,
            difficulty=1,
            timestamp=1700000100,
        )
        verified_par = set()
        ok_par, _ = blk_par.integrity_check(verified_txids=verified_par)
        assert ok_par is False
        for t in txs_par:
            assert t.tx_id not in verified_par

    def test_block_integrity_check_rejects_invalid_sig_with_none_sender_cleanly(self):
        """V4 fix: invalid sig with sender=None returns False cleanly without crashing with TypeError."""
        _, recipient_pub = ecdsa_keygen()
        receiver = pub_to_address(recipient_pub)
        cb = Transaction.coinbase(receiver, 50.0, block_height=1)

        tx_bad = _make_signed_none_sender_tx(receiver=receiver, nonce=1, invalid_sig=True)
        blk_seq = Block(
            index=1,
            prev_hash="0" * 64,
            transactions=[cb, tx_bad],
            miner_address=receiver,
            difficulty=1,
            timestamp=1700000100,
        )
        ok_seq, _ = blk_seq.integrity_check()
        assert ok_seq is False

        txs_bad_par = [_make_signed_none_sender_tx(receiver=receiver, nonce=i, invalid_sig=True) for i in range(1, 5)]
        blk_par = Block(
            index=1,
            prev_hash="0" * 64,
            transactions=[cb] + txs_bad_par,
            miner_address=receiver,
            difficulty=1,
            timestamp=1700000100,
        )
        ok_par, _ = blk_par.integrity_check()
        assert ok_par is False
