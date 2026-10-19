"""Regression tests for automatic authenticated recovery after pruned sync rejection.

The tests do not start real P2P nodes. They verify network dispatch, the
manifest trust boundary, and mempool reconciliation after an authenticated
snapshot jump. Cryptographic snapshot validation remains covered by
 test_pruning_authenticated_bootstrap.py.
"""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from visold.kernel.config import Config
from visold.network.p2p import (
    MSG_GET_SNAPSHOT_MANIFEST,
    MSG_SNAPSHOT_MANIFEST,
    P2PNetwork,
)


def _peer(peer_id="peer-stale"):
    return SimpleNamespace(
        peer_id=peer_id,
        connected=True,
        _pagination_active=threading.Event(),
        _sync_state_lock=threading.Lock(),
        _sync_last_reject_at=0.0,
        _snap_response_queue=None,
        _bootstrap_header_queue=None,
    )


def test_pruned_body_rejection_dispatches_authenticated_recovery_without_genesis_replay(monkeypatch):
    monkeypatch.setattr(Config, "SNAPSHOT_FAST_SYNC_ENABLED", True)
    net = P2PNetwork.__new__(P2PNetwork)
    net.blockchain = SimpleNamespace(height=lambda: 120, _snapshot_engine=object())
    net._sync_finish = lambda *_a, **_k: None
    legacy_calls = []
    net._sync_request = lambda *a, **k: legacy_calls.append((a, k)) or True
    called = threading.Event()
    finished = threading.Event()

    def recover(peer):
        try:
            assert peer.peer_id == "peer-stale"
            called.set()
            return True
        finally:
            finished.set()

    net._authenticated_pruned_recovery_from_peer = recover
    peer = _peer()

    net._on_chain_sync_result(
        peer,
        [SimpleNamespace(index=121)],
        False,
        "Block 121 is pruned/header-only; required historical block body is pruned",
        False,
        0,
        "request-pruned",
    )

    assert called.wait(2), "pruned rejection did not dispatch authenticated recovery"
    assert finished.wait(2), "recovery worker did not complete in the bounded test"
    assert legacy_calls == [], "must not retry the ineffective genesis 0..199 range"
    assert peer._authenticated_pruned_recovery_active is False


def test_pruned_recovery_requests_manifest_and_only_uses_ahead_committed_snapshot(monkeypatch):
    monkeypatch.setattr(Config, "SNAPSHOT_FAST_SYNC_ENABLED", True)
    peer = _peer()

    def send(message):
        if message.get("type") == MSG_GET_SNAPSHOT_MANIFEST:
            peer._snap_response_queue.put({
                "type": MSG_SNAPSHOT_MANIFEST,
                "manifest": [
                    {"height": 600, "bootstrap_digest": "d" * 64},
                    {"height": 1000, "bootstrap_digest": "e" * 64},
                ],
            })

    peer.send = send
    net = P2PNetwork.__new__(P2PNetwork)
    net.blockchain = SimpleNamespace(height=lambda: 120, _snapshot_engine=object())
    calls = []
    net._authenticated_bootstrap_from_manifest = (
        lambda *a, **k: calls.append((a, k)) or True
    )

    assert net._authenticated_pruned_recovery_from_peer(peer, manifest_timeout=1)
    assert len(calls) == 1
    assert calls[0][0][0] is peer
    assert [x["height"] for x in calls[0][0][1]] == [600, 1000]
    assert peer._snap_response_queue is None, "response queue must always be released"


def test_pruned_recovery_refuses_equal_height_or_uncommitted_snapshot(monkeypatch):
    monkeypatch.setattr(Config, "SNAPSHOT_FAST_SYNC_ENABLED", True)
    peer = _peer()

    def send(message):
        if message.get("type") == MSG_GET_SNAPSHOT_MANIFEST:
            peer._snap_response_queue.put({
                "type": MSG_SNAPSHOT_MANIFEST,
                "manifest": [
                    {"height": 120, "bootstrap_digest": "a" * 64},
                    {"height": 1000, "state_root": "b" * 64},
                ],
            })

    peer.send = send
    net = P2PNetwork.__new__(P2PNetwork)
    net.blockchain = SimpleNamespace(height=lambda: 120, _snapshot_engine=object())
    calls = []
    net._authenticated_bootstrap_from_manifest = lambda *a, **k: calls.append(a) or True

    assert not net._authenticated_pruned_recovery_from_peer(peer, manifest_timeout=1)
    assert calls == [], "equal-height or unsigned/uncommitted manifest must not trigger restore"
    assert peer._snap_response_queue is None


def test_snapshot_bootstrap_reconciles_confirmed_and_nonce_stale_mempool_entries():
    net = P2PNetwork.__new__(P2PNetwork)
    pending = [SimpleNamespace(tx_id="confirmed-1"),
               SimpleNamespace(tx_id="not-confirmed-1")]
    net.storage = SimpleNamespace(
        mempool_all=lambda: pending,
        existing_tx_ids=lambda ids: {"confirmed-1"} & set(ids),
    )
    calls = {"confirmed": [], "purged": 0}

    class Pool:
        def clear_confirmed(self, txids):
            calls["confirmed"].extend(txids)

        def purge_stale_nonces(self):
            calls["purged"] += 1
            return 1

    net.blockchain = SimpleNamespace(mempool=Pool())
    assert net._reconcile_mempool_after_authenticated_bootstrap() == (1, 1)
    assert calls == {"confirmed": ["confirmed-1"], "purged": 1}


def test_offline_receiver_reconnects_after_prune_restores_balance_mempool_and_receipt(
        tmp_path, monkeypatch):
    """Model the user's exact offline-mempool -> mined -> pruned -> reconnect flow."""
    import sqlite3
    import time
    from unittest.mock import patch

    from visold.chain.blockchain import Blockchain
    from visold.chain.consensus_engine import ConsensusEngine
    from visold.consensus.difficulty import DifficultyEngine
    from visold.kernel.config import Config
    from visold.ledger.block import Block
    from visold.ledger.transaction import Transaction
    from visold.network.p2p import (
        MSG_CHAIN,
        MSG_GET_CHAIN,
        MSG_GET_SNAPSHOT,
        MSG_GET_SNAPSHOT_MANIFEST,
        MSG_SNAPSHOT_DATA,
        MSG_SNAPSHOT_MANIFEST,
    )
    from visold.network.receipt_relay import ReceiptRelayManager
    from visold.storage.storage import Storage
    from visold.wallet.wallet import Wallet

    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 2)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 3)
    monkeypatch.setattr(Config, "BOOTSTRAP_HEADER_PAGE_SIZE", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 9)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 500)
    monkeypatch.setattr(Config, "SNAPSHOT_KEEP", 3)
    monkeypatch.setattr(Config, "SNAPSHOT_FAST_SYNC_ENABLED", True)
    monkeypatch.setattr(Config, "RECEIPT_RELAY_ENABLED", True)
    DifficultyEngine.invalidate_cache()

    with patch.object(Blockchain, "get_difficulty", return_value=0.0), \
         patch.object(DifficultyEngine, "_compute_uncached", return_value=0.0), \
         patch.object(DifficultyEngine, "validate_pow_target", return_value=True):
        source_path = str(tmp_path / "source-auto-recovery.db")
        source_st = Storage(source_path)
        source = Blockchain(source_st)
        source._rolling_pruner.prune_async = lambda _height: None
        sender = Wallet.generate()
        receiver = Wallet.generate()
        eng = ConsensusEngine(source, sender)
        stale_st = None
        relay_st = Storage(str(tmp_path / "relay-auto-recovery.db"))
        try:
            # Mine the common prefix through h=5.
            while source.height() < 5:
                block = eng.build_candidate_block(sender.address)
                assert block.mine()
                ok, why = source.apply_block(block)
                assert ok, why

            # Receiver B gets the signed transfer into its persistent mempool,
            # then goes offline before the sender mines it. Clone at exactly
            # that point so B's DB really contains the pending transaction.
            tx = Transaction(
                sender=sender.address, receiver=receiver.address,
                amount=5.0, fee=0.05,
                nonce=source_st.get_nonce(sender.address),
                timestamp=int(time.time()), expiry=2_000_000_000,
            )
            tx.sign(sender)
            accepted, why = source.mempool.add(tx)
            assert accepted, why
            stale_path = str(tmp_path / "receiver-offline.db")
            dst = sqlite3.connect(stale_path)
            try:
                source_st._conn().backup(dst)
            finally:
                dst.close()

            # Node 1 mines the previously pending tx while B is offline.
            block6 = eng.build_candidate_block(sender.address)
            assert any(item.tx_id == tx.tx_id for item in block6.transactions)
            assert block6.mine()
            ok, why = source.apply_block(block6)
            assert ok, why
            relay_builder = ReceiptRelayManager(source, relay_st, sender, "relay-builder")
            receipt = relay_builder.build_receipt(block6, tx)
            assert receipt is not None
            assert relay_builder.store_relay_receipt(receipt, 0)[0]

            # Advance beyond the pruned-body window and commit snapshot h=18.
            while source.height() < 20:
                block = eng.build_candidate_block(sender.address)
                assert block.mine()
                ok, why = source.apply_block(block)
                assert ok, why
            source._rolling_pruner._last_height = -1
            source._rolling_pruner.maybe_prune(source.height())
            assert source.get_block(6).is_pruned
            manifest = source._snapshot_engine.get_manifest()
            assert any(int(item["height"]) == 18 and item.get("bootstrap_digest")
                       for item in manifest)

            # Restart B from its persisted h=5 DB; it still has the now-confirmed
            # transaction in mempool, and its receiver balance has not been credited.
            stale_st = Storage(stale_path)
            stale = Blockchain(stale_st)
            stale._rolling_pruner.prune_async = lambda _height: None
            assert stale.height() == 5
            assert any(p.tx_id == tx.tx_id for p in stale_st.mempool_all())
            assert stale_st.get_balance_sat(receiver.address) == 0

            # The fake transport returns the real source manifest, real pruned
            # header records, and real authenticated snapshot bytes. Only the
            # socket is mocked; block/snapshot validation and restoration are real.
            class SourcePeer:
                peer_id = "source-peer"
                connected = True
                def __init__(self):
                    self._sync_state_lock = threading.Lock()
                    self._pagination_active = threading.Event()
                    self._snap_response_queue = None
                    self._bootstrap_header_queue = None
                def send(self, msg):
                    mtype = msg.get("type")
                    if mtype == MSG_GET_SNAPSHOT_MANIFEST:
                        self._snap_response_queue.put({
                            "type": MSG_SNAPSHOT_MANIFEST,
                            "manifest": source._snapshot_engine.get_manifest(),
                        })
                    elif mtype == MSG_GET_CHAIN:
                        start = int(msg["from_idx"])
                        end = min(int(msg["to_idx"]), source.height())
                        blocks = [source.get_block(h).to_dict()
                                  for h in range(start, end + 1)]
                        self._bootstrap_header_queue.put({
                            "type": MSG_CHAIN,
                            "blocks": blocks,
                            "request_id": msg.get("request_id"),
                        })
                    elif mtype == MSG_GET_SNAPSHOT:
                        height = int(msg["height"])
                        blob = source._snapshot_engine.get_snapshot_blob(height)
                        self._snap_response_queue.put({
                            "type": MSG_SNAPSHOT_DATA,
                            "height": height,
                            "data_hex": blob.hex() if blob else "",
                        })
                    else:
                        raise AssertionError(f"unexpected P2P message: {msg}")

            peer = SourcePeer()
            net = P2PNetwork.__new__(P2PNetwork)
            net.blockchain = stale
            net.storage = stale_st
            net._lock = threading.Lock()
            net._bootstrap_recovery_lock = threading.Lock()
            receipt_results = []
            target_relay = ReceiptRelayManager(stale, stale_st, receiver, "receiver")

            def query_receipt_mailbox():
                # Model a mailbox replica returning the real proof made before
                # source pruning; recipient validates it against the recovered
                # canonical header and writes its wallet receipt history.
                receipt_results.append(target_relay.deliver_to_local_wallet(receipt))

            net.query_receipt_mailbox = query_receipt_mailbox
            net._sync_finish = lambda *_args, **_kwargs: None

            def sync_following_blocks(_peer, start, end, **_kwargs):
                blocks = [Block.from_dict(source.get_block(h).to_dict())
                          for h in range(start, min(end, source.height()) + 1)]
                if blocks:
                    ok, why = stale.accept_chain(blocks)
                    assert ok, why
                return True

            net._sync_request = sync_following_blocks

            # Start from the real sync-rejection callback. It must dispatch the
            # authenticated recovery worker automatically; the socket itself is
            # mocked, but header verification, snapshot restore, mempool cleanup,
            # receipt proof validation, and post-snapshot block application are real.
            net._on_chain_sync_result(
                peer,
                [SimpleNamespace(index=6)],
                False,
                "Block 6 is pruned/header-only; required historical block body is pruned",
                False,
                0,
                "request-pruned-history",
            )
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if (not getattr(peer, "_authenticated_pruned_recovery_active", False)
                        and stale.height() == 20):
                    break
                time.sleep(0.01)
            assert not getattr(peer, "_authenticated_pruned_recovery_active", False), (
                "automatically dispatched recovery worker did not finish")

            # Recovery applied snapshot h=18 then validated full blocks 19 and 20.
            assert stale.height() == source.height() == 20
            assert stale.latest_block().block_hash == source.latest_block().block_hash
            assert stale.latest_block().state_root == source.latest_block().state_root
            assert stale_st.get_balance_sat(receiver.address) == source_st.get_balance_sat(receiver.address)
            assert stale_st.get_balance_sat(receiver.address) == 500_000_000

            # The pending tx that became canonical while B was offline must not
            # survive in mempool after the authenticated jump.
            assert all(item.tx_id != tx.tx_id for item in stale_st.mempool_all())
            assert stale.mempool.size() == 0

            # Receipt retrieval runs immediately after snapshot installation, once
            # its historical canonical header is available despite body pruning.
            assert receipt_results == [(True, "delivered")]
            history = stale_st.get_address_txs(receiver.address)
            hit = next(item for item in history if item.get("tx_id") == tx.tx_id)
            assert hit["sender"] == sender.address
            assert hit["receiver"] == receiver.address
            assert hit["amount"] == 5.0
            assert hit["_relay_receipt"] is True
        finally:
            if stale_st is not None:
                stale_st.close()
            relay_st.close()
            source_st.close()
            DifficultyEngine.invalidate_cache()
