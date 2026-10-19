"""End-to-end regression: recipient offline across tx mining + body pruning.

The scenario models B offline at X=5, a transfer created at X+3 (height 8),
confirmed at X+5 (height 10), then A advancing until block 10 is pruned. B
fast-forwards through an authenticated snapshot and recovers Balance History
through the proof-carrying VARR receipt mailbox.
"""
from __future__ import annotations

import contextlib
import io
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.kernel.lru_cache import LRUCache
from visold.ledger.transaction import Transaction
from visold.network.bootstrap_sync import verify_bootstrap_header_chain
from visold.network.kademlia import KademliaRouter
from visold.network.p2p import P2PNetwork
from visold.network.receipt_relay import ReceiptRelayManager
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet
from visold.cli.interactive import CLI


@pytest.fixture
def offline_tx_cfg(monkeypatch):
    DifficultyEngine.invalidate_cache()
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.001)
    # Freeze the DAA only inside this test: back-to-back test blocks have near-zero
    # wall-clock intervals and would otherwise rapidly increase difficulty. The
    # block PoW and bootstrap header verification still validate at this same target.
    monkeypatch.setattr(
        DifficultyEngine, "_compute_uncached",
        classmethod(lambda cls, storage, current_height: float(Config.INITIAL_DIFFICULTY)),
    )
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 2)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 3)
    monkeypatch.setattr(Config, "BOOTSTRAP_HEADER_PAGE_SIZE", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 100)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ARCHIVE_THRESHOLD", 100.0)
    monkeypatch.setattr(Config, "SNAPSHOT_KEEP", 3)
    monkeypatch.setattr(Config, "RECEIPT_RELAY_ENABLED", True)
    monkeypatch.setattr(Config, "RECEIPT_REPLICA_SLOTS", 1)
    yield
    DifficultyEngine.invalidate_cache()


def _mine_to(chain: Blockchain, miner: Wallet, height: int) -> None:
    # Tests trigger pruning synchronously and deterministically themselves.
    chain._rolling_pruner.prune_async = lambda _height: None
    engine = ConsensusEngine(chain, miner)
    while chain.height() < height:
        block = engine.build_candidate_block(miner.address)
        assert block.mine(), f"PoW failed at height {block.index}"
        ok, why = chain.apply_block(block)
        assert ok, f"block {block.index} rejected: {why}"


def _mine_one(chain: Blockchain, miner: Wallet):
    chain._rolling_pruner.prune_async = lambda _height: None
    block = ConsensusEngine(chain, miner).build_candidate_block(miner.address)
    assert block.mine(), f"PoW failed at height {block.index}"
    ok, why = chain.apply_block(block)
    assert ok, f"block {block.index} rejected: {why}"
    return block


class _Inbound:
    def __init__(self, peer_id):
        self.peer_id = peer_id
        self.connected = True


class _LinkPeer:
    def __init__(self, peer_id, remote, inbound_peer):
        self.peer_id = peer_id
        self.remote = remote
        self.inbound_peer = inbound_peer
        self.connected = True

    def send(self, msg):
        # Receipt path only; route PUT/QUERY/RESPONSE/ACK through the real handlers.
        from visold.kernel.messages import (
            MSG_RECEIPT_ACK, MSG_RECEIPT_PUT,
            MSG_RECEIPT_QUERY, MSG_RECEIPT_RESPONSE,
        )
        handlers = {
            MSG_RECEIPT_PUT: self.remote._handle_receipt_put,
            MSG_RECEIPT_QUERY: self.remote._handle_receipt_query,
            MSG_RECEIPT_RESPONSE: self.remote._handle_receipt_response,
            MSG_RECEIPT_ACK: self.remote._handle_receipt_ack,
        }
        handler = handlers.get(msg.get("type"))
        assert handler is not None, f"unexpected VARR message {msg.get('type')}"
        handler(self.inbound_peer, msg.copy())


def _network_shell(node_id, chain, storage, wallet):
    net = object.__new__(P2PNetwork)
    net.node_id = node_id
    net.blockchain = chain
    net.storage = storage
    net.wallet = wallet
    net.router = KademliaRouter(node_id)
    net.peers = {}
    net._lock = threading.Lock()
    net._receipt_relay = ReceiptRelayManager(chain, storage, wallet, node_id)
    net._receipt_ack_sent = LRUCache(8192, ttl=3600)
    net._receipt_repair_slot = 0
    return net


def _link(a, b):
    a.peers[b.node_id] = _LinkPeer(b.node_id, b, _Inbound(a.node_id))
    b.peers[a.node_id] = _LinkPeer(a.node_id, a, _Inbound(b.node_id))


def test_offline_recipient_gets_balance_and_history_after_snapshot_sync_and_pruning(
    tmp_path, offline_tx_cfg
):
    a_path = tmp_path / "node_a.db"
    b_path = tmp_path / "node_b_offline.db"
    relay_path = tmp_path / "custodian.db"
    a_storage = Storage(str(a_path))
    a_chain = Blockchain(a_storage)
    sender = Wallet.generate()
    receiver = Wallet.generate()
    b_storage = None
    relay_storage = Storage(str(relay_path))
    try:
        # X = 5. B's database is a consistent offline snapshot of A at height X.
        _mine_to(a_chain, sender, 5)
        backup_conn = sqlite3.connect(str(b_path))
        try:
            a_storage._conn().backup(backup_conn)
        finally:
            backup_conn.close()

        # A reaches X+3 (height 8); B is offline. A creates/registers A -> B.
        _mine_to(a_chain, sender, 8)
        tx = Transaction(
            sender=sender.address,
            receiver=receiver.address,
            amount=5.0,
            fee=0.05,
            nonce=a_storage.get_nonce(sender.address),
            timestamp=int(time.time()) - 5,
        )
        tx.sign(sender)
        admitted, admission_msg = a_chain.mempool.add(tx)
        assert admitted, f"transfer rejected from mempool: {admission_msg}"

        # The transaction remains pending through X+4 (height 9); then is mined
        # in X+5 (height 10). This models a delayed inclusion, not a failed tx.
        original_get_top = a_chain.mempool.get_top
        a_chain.mempool.get_top = lambda _limit: []
        try:
            _mine_one(a_chain, sender)  # height 9, deliberately excludes tx
        finally:
            a_chain.mempool.get_top = original_get_top
        block_10 = _mine_one(a_chain, sender)
        assert block_10.index == 10
        assert any(t.tx_id == tx.tx_id for t in block_10.transactions)

        # A publishes a proof-carrying receipt while the full transaction body
        # still exists. A nearby custodian stores it while B remains offline.
        key = ReceiptRelayManager.mailbox_key(receiver.address, 0)
        probe = KademliaRouter("probe")
        ids = [f"offline-receipt-node-{i}" for i in range(64)]
        ids.sort(key=lambda nid: probe._to_160bit_int(nid) ^ probe._to_160bit_int(key))
        custodian_id, source_id = ids[0], ids[-1]
        a_net = _network_shell(source_id, a_chain, a_storage, sender)
        relay_net = _network_shell(custodian_id, a_chain, relay_storage, Wallet.generate())
        _link(a_net, relay_net)
        published = a_net.publish_receipts_for_block(a_chain.get_block(10))
        assert published == 1
        stored = relay_net._receipt_relay.get_mailbox(receiver.address, 0)
        assert len(stored) == 1 and stored[0]["tx_id"] == tx.tx_id

        # Advance A until the transaction body is beyond the rolling window.
        _mine_to(a_chain, sender, 15)
        a_chain._rolling_pruner._last_height = -1
        a_chain._rolling_pruner.maybe_prune(a_chain.height())
        old = a_chain.get_block(10)
        assert old is not None and old.is_pruned
        assert old.transactions == ()
        assert a_storage._conn().execute(
            "SELECT COUNT(*) FROM transactions WHERE tx_id=?", (tx.tx_id,)
        ).fetchone()[0] == 0
        # Under the configured selective archive threshold, this small transfer
        # is absent from A's permanent-history table too; VARR is what preserves it.
        assert a_storage._conn().execute(
            "SELECT COUNT(*) FROM permanent_history WHERE tx_hash=?", (tx.tx_id,)
        ).fetchone()[0] == 0

        # B reconnects. It cannot replay pruned block bodies, so it authenticates
        # snapshot H=14 via the commitment in full block H+1=15.
        stale_storage = Storage(str(b_path))
        b_storage = stale_storage
        b_chain = Blockchain(stale_storage)
        assert b_chain.height() == 5
        manifest_entry = next(
            item for item in a_chain._snapshot_engine.get_manifest()
            if int(item["height"]) == 14
        )
        blob = a_chain._snapshot_engine.get_snapshot_blob(14)
        assert blob
        transport_headers = [a_chain.get_block(h).to_dict() for h in range(16)]
        ok, why, verified, committed = verify_bootstrap_header_chain(
            transport_headers, a_storage.get_meta("genesis_hash"), 14
        )
        assert ok, why
        assert committed == manifest_entry["bootstrap_digest"]
        ok, why = b_chain._snapshot_engine.restore_authenticated_bootstrap(
            blob, committed, verified
        )
        assert ok, why
        b_chain.layer2._try_restore_from_storage()
        block_15 = a_chain.get_block(15)
        assert block_15 is not None and not block_15.is_pruned
        ok, why = b_chain.apply_block(block_15)
        assert ok, why
        assert b_chain.height() == a_chain.height() == 15
        assert b_chain.latest_block().block_hash == a_chain.latest_block().block_hash
        assert b_chain.latest_block().state_root == a_chain.latest_block().state_root

        # Consensus balance is recovered from the authenticated snapshot, but
        # auxiliary wallet history is intentionally not inside that snapshot.
        assert stale_storage.get_balance(receiver.address) == pytest.approx(5.0)
        before_receipt = stale_storage.get_address_txs(receiver.address)
        assert not any(row.get("tx_id") == tx.tx_id for row in before_receipt)

        # B is now online and queries the same proof-backed mailbox. The actual
        # P2P query/response/delivery handlers verify the receipt against B's
        # canonical (header-only for h=10) chain and persist permanent history.
        # Simulate A's connection dropping while B was offline; the custodian
        # remains connected to the network and then to B.
        a_net.peers.clear()
        relay_net.peers.clear()
        b_net = _network_shell(ids[-2], b_chain, stale_storage, receiver)
        _link(b_net, relay_net)
        b_net._receipt_query_slot(0)

        assert stale_storage.get_balance(receiver.address) == pytest.approx(5.0)
        after_receipt = stale_storage.get_address_txs(receiver.address)
        matches = [row for row in after_receipt if row.get("tx_id") == tx.tx_id]
        assert len(matches) == 1
        assert matches[0]["sender"] == sender.address
        assert matches[0]["receiver"] == receiver.address
        assert matches[0]["amount"] == pytest.approx(5.0)
        assert matches[0]["block_idx"] == 10
        assert matches[0].get("_archived") is True
        assert matches[0].get("_relay_receipt") is True

        # Test the actual CLI Balance History output, not just the SQL row.
        cli = CLI.__new__(CLI)
        cli.node = SimpleNamespace(wallet=receiver, storage=stale_storage)
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            cli._balance_history()
        rendered = capture.getvalue()
        assert "Received" in rendered
        assert "+5.00000000" in rendered
        assert "#10" in rendered
    finally:
        if b_storage is not None:
            b_storage.close()
        relay_storage.close()
        a_storage.close()
