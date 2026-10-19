from __future__ import annotations

import copy
import threading
import time
from unittest.mock import patch

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.kernel.lru_cache import LRUCache
from visold.kernel.messages import MSG_RECEIPT_ACK, MSG_RECEIPT_PUT, MSG_RECEIPT_QUERY, MSG_RECEIPT_RESPONSE
from visold.kernel.units import from_satoshi
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.network.kademlia import KademliaRouter
from visold.network.p2p import P2PNetwork
from visold.network.receipt_relay import ReceiptRelayManager
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _chain(tmp_path, name):
    st = Storage(str(tmp_path / name))
    bc = Blockchain(st)
    bc._rolling_pruner.prune_async = lambda _h: None
    return st, bc


def _mine_block(bc, miner, ts, txs=None):
    h = bc.height() + 1
    cb = Transaction.coinbase(
        miner.address, bc.compute_reward_sat(h) / Config.SATOSHI_PER_VSD, h)
    all_txs = [cb] + list(txs or [])
    root = bc.dry_run_state_root(all_txs, miner.address, h)
    b = Block(
        index=h, prev_hash=bc.latest_block().block_hash,
        transactions=all_txs, miner_address=miner.address,
        difficulty=bc.get_difficulty(), timestamp=ts, state_root=root)
    assert b.mine()
    ok, msg = bc.apply_block(b)
    assert ok, msg
    return b


def _source_with_transfer(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 10)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 500)
    st, bc = _chain(tmp_path, "source_varr.db")
    d = Wallet.generate(); b_wallet = Wallet.generate()
    t0 = int(time.time()) + 3600
    for h in range(1, 8):
        _mine_block(bc, d, t0 + h * 60)
    tx = Transaction(
        sender=d.address, receiver=b_wallet.address, amount=5.0,
        fee=0.05, nonce=bc.storage.get_nonce(d.address),
        timestamp=t0 + 8 * 60)
    tx.sign(d)
    b8 = _mine_block(bc, d, t0 + 8 * 60, [tx])
    for h in range(9, 21):
        _mine_block(bc, d, t0 + h * 60)
    return st, bc, d, b_wallet, tx, b8


def test_receipt_survives_body_pruning_and_preserves_sender(tmp_path, monkeypatch):
    with patch.object(Blockchain, "get_difficulty", return_value=0.0):
        st, bc, _d, target, tx, b8 = _source_with_transfer(tmp_path, monkeypatch)
        try:
            mgr = ReceiptRelayManager(bc, st, target, "target")
            receipt = mgr.build_receipt(b8, tx)
            assert receipt is not None
            # Build the proof before pruning, then remove the full body exactly as production does.
            bc._rolling_pruner._last_height = -1
            bc._rolling_pruner.maybe_prune(bc.height())
            assert bc.height() == 20
            assert bc.get_block(8).is_pruned is True
            assert bc.get_block(8).transactions == ()

            ok, why = mgr.verify_receipt(receipt, require_canonical=True)
            assert ok, why
            ok, why = mgr.deliver_to_local_wallet(receipt)
            assert ok, why
            rows = mgr.local_wallet_receipts()
            hit = next(r for r in rows if r["receipt_id"] == receipt["receipt_id"])
            assert hit["sender"] == tx.sender
            assert hit["receiver"] == target.address
            assert int(hit["amount_sat"]) == 500_000_000
            assert hit["block_height"] == 8
            # A verified relay receipt must become a durable permanent-history
            # row as well as a local wallet proof. Balance History reads through
            # get_address_txs(), so it must surface exactly one archived row.
            archive_rows = st._conn().execute(
                "SELECT tx_hash, block_idx, sender, receiver, amount, tx_type, timestamp, metadata_json "
                "FROM permanent_history WHERE tx_hash=?", (tx.tx_id,)
            ).fetchall()
            assert len(archive_rows) == 1
            archive = archive_rows[0]
            assert archive["block_idx"] == 8
            assert archive["sender"] == tx.sender
            assert archive["receiver"] == target.address
            assert float(archive["amount"]) == 5.0
            import json
            meta = json.loads(archive["metadata_json"])
            assert meta["fee"] == 0.05
            assert meta["nonce"] == tx.nonce
            assert meta["_relay_receipt"] is True
            assert meta["history_source"] == "verified_varr_receipt"

            merged = st.get_address_txs(target.address)
            hits = [d for d in merged if d.get("tx_id") == tx.tx_id]
            assert len(hits) == 1
            recovered = hits[0]
            assert recovered["sender"] == tx.sender
            assert recovered["receiver"] == target.address
            assert recovered["amount"] == 5.0
            assert recovered["fee"] == 0.05
            assert recovered["block_idx"] == 8
            assert recovered.get("_archived") is True
            assert recovered.get("_relay_receipt") is True

            # Re-delivery is idempotent. A receiver-signed ACK may let the
            # temporary relay mailbox garbage-collect its copy, but the durable
            # wallet proof and Balance History archive must remain intact.
            ok, why = mgr.deliver_to_local_wallet(receipt)
            assert ok, why
            assert st._conn().execute(
                "SELECT COUNT(*) FROM wallet_receipts WHERE receipt_id=?",
                (receipt["receipt_id"],),
            ).fetchone()[0] == 1
            assert st._conn().execute(
                "SELECT COUNT(*) FROM permanent_history WHERE tx_hash=?",
                (tx.tx_id,),
            ).fetchone()[0] == 1
            ok, why = mgr.store_relay_receipt(receipt, 0)
            assert ok, why
            ack = mgr.make_ack(receipt["receipt_id"])
            ok, why = mgr.accept_ack(ack)
            assert ok, why
            monkeypatch.setattr(Config, "RECEIPT_ACK_GRACE_SECS", 0)
            assert mgr.gc_delivered() == 1
            assert st._conn().execute(
                "SELECT COUNT(*) FROM relay_receipts WHERE receipt_id=?",
                (receipt["receipt_id"],),
            ).fetchone()[0] == 0
            assert st._conn().execute(
                "SELECT COUNT(*) FROM wallet_receipts WHERE receipt_id=?",
                (receipt["receipt_id"],),
            ).fetchone()[0] == 1
            assert st._conn().execute(
                "SELECT COUNT(*) FROM permanent_history WHERE tx_hash=?",
                (tx.tx_id,),
            ).fetchone()[0] == 1
            final_history = [d for d in st.get_address_txs(target.address)
                             if d.get("tx_id") == tx.tx_id]
            assert len(final_history) == 1
            assert final_history[0]["amount"] == 5.0
        finally:
            st.close()


def test_receipt_tampering_and_forged_ack_are_rejected(tmp_path, monkeypatch):
    with patch.object(Blockchain, "get_difficulty", return_value=0.0):
        st, bc, _d, target, tx, b8 = _source_with_transfer(tmp_path, monkeypatch)
        try:
            mgr = ReceiptRelayManager(bc, st, target, "target")
            receipt = mgr.build_receipt(b8, tx)
            assert receipt
            forged = copy.deepcopy(receipt)
            # Change signed amount without possessing sender key.
            for item in forged["signed_fields"]:
                if item[0] == "amount_sat":
                    item[1] = "50000000000"
            # Even recomputing outer receipt_id cannot make inner tx signature/Merkle proof valid.
            base = dict(forged); base.pop("receipt_id")
            from visold.crypto.hashing import sha256
            import json
            forged["receipt_id"] = sha256(json.dumps(base, sort_keys=True, separators=(",", ":")).encode())
            ok, _ = mgr.verify_receipt(forged, require_canonical=True)
            assert not ok
            # Invalid proofs must never create either the durable wallet copy or
            # a permanent-history row.
            ok, _ = mgr.deliver_to_local_wallet(forged)
            assert not ok
            assert st._conn().execute(
                "SELECT COUNT(*) FROM wallet_receipts WHERE receipt_id=?",
                (receipt["receipt_id"],),
            ).fetchone()[0] == 0
            assert st._conn().execute(
                "SELECT COUNT(*) FROM permanent_history WHERE tx_hash=?",
                (tx.tx_id,),
            ).fetchone()[0] == 0

            assert mgr.store_relay_receipt(receipt, 0)[0]
            attacker = Wallet.generate()
            payload = f"VSD-VARR-ACK-V1|{Config.CHAIN_ID}|{target.address}|{receipt['receipt_id']}".encode()
            from visold.crypto.ecc import sig_to_hex
            bad_ack = {
                "domain": "VSD-VARR-ACK-V1", "version": 1,
                "chain_id": str(Config.CHAIN_ID), "receiver": target.address,
                "receipt_id": receipt["receipt_id"], "pub_hex": attacker.pub_hex,
                "sig_hex": sig_to_hex(attacker.sign(payload)),
            }
            ok, _ = mgr.accept_ack(bad_ack)
            assert not ok
            assert len(mgr.get_mailbox(target.address, 0)) == 1
        finally:
            st.close()


class _LinkPeer:
    def __init__(self, peer_id, remote, inbound_peer):
        self.peer_id = peer_id
        self.remote = remote
        self.inbound_peer = inbound_peer
        self.connected = True
    def send(self, msg):
        t = msg.get("type")
        if t == MSG_RECEIPT_PUT:
            self.remote._handle_receipt_put(self.inbound_peer, copy.deepcopy(msg))
        elif t == MSG_RECEIPT_QUERY:
            self.remote._handle_receipt_query(self.inbound_peer, copy.deepcopy(msg))
        elif t == MSG_RECEIPT_RESPONSE:
            self.remote._handle_receipt_response(self.inbound_peer, copy.deepcopy(msg))
        elif t == MSG_RECEIPT_ACK:
            self.remote._handle_receipt_ack(self.inbound_peer, copy.deepcopy(msg))
        else:
            raise AssertionError(t)


class _Inbound:
    def __init__(self, peer_id):
        self.peer_id = peer_id
        self.connected = True


def _net_shell(node_id, bc, st, wallet):
    n = object.__new__(P2PNetwork)
    n.node_id = node_id
    n.blockchain = bc
    n.storage = st
    n.wallet = wallet
    n.router = KademliaRouter(node_id)
    n.peers = {}
    n._lock = threading.Lock()
    n._receipt_relay = ReceiptRelayManager(bc, st, wallet, node_id)
    n._receipt_ack_sent = LRUCache(8192, ttl=3600)
    n._receipt_repair_slot = 0
    return n


def _link(a, b):
    # `a.peers[b]` sends into b with an inbound peer identity representing a.
    a.peers[b.node_id] = _LinkPeer(b.node_id, b, _Inbound(a.node_id))
    b.peers[a.node_id] = _LinkPeer(a.node_id, a, _Inbound(b.node_id))


def test_mailbox_query_routes_over_mesh_without_direct_target_custodian_link(tmp_path, monkeypatch):
    with patch.object(Blockchain, "get_difficulty", return_value=0.0):
        source_st, bc, _d, target, tx, b8 = _source_with_transfer(tmp_path, monkeypatch)
        stores=[]
        try:
            receipt = ReceiptRelayManager(bc, source_st, target, "builder").build_receipt(b8, tx)
            assert receipt
            slot=0
            key=ReceiptRelayManager.mailbox_key(target.address, slot)

            # Generate four IDs and assign them farthest→closest to the mailbox key.
            ids=[f"node-{i}" for i in range(4)]
            probe=KademliaRouter(ids[0])
            ids.sort(key=lambda nid: probe._to_160bit_int(nid) ^ probe._to_160bit_int(key))
            # Route deliberately starts with a *farther* hop: B is near the key
            # but its only neighbour X is far away; X then reaches Y and the
            # closest custodian R. Pure greedy routing would get stuck at B.
            R_id, B_id, Y_id, X_id = ids[0], ids[1], ids[2], ids[3]
            ids=[B_id, X_id, Y_id, R_id]
            wallets=[target, Wallet.generate(), Wallet.generate(), Wallet.generate()]
            nets=[]
            for i,nid in enumerate(ids):
                st=Storage(str(tmp_path / f"mesh_{i}.db")); stores.append(st)
                nets.append(_net_shell(nid, bc, st, wallets[i]))
            B,X,Y,R=nets
            _link(B,X); _link(X,Y); _link(Y,R)
            # B has no direct R connection by construction.
            assert R.node_id not in B.peers

            ok, why = R._receipt_relay.store_relay_receipt(receipt, slot)
            assert ok, why
            B._receipt_query_slot(slot)
            rows=B._receipt_relay.local_wallet_receipts()
            assert any(r["receipt_id"] == receipt["receipt_id"] for r in rows)
            hit=next(r for r in rows if r["receipt_id"] == receipt["receipt_id"])
            assert hit["sender"] == tx.sender
            assert hit["amount_sat"] == 500_000_000
        finally:
            for st in stores:
                st.close()
            source_st.close()

def test_surviving_custodian_repairs_replica_to_new_closer_node(tmp_path, monkeypatch):
    with patch.object(Blockchain, "get_difficulty", return_value=0.0):
        source_st, bc, _d, target, tx, b8 = _source_with_transfer(tmp_path, monkeypatch)
        stores=[]
        try:
            receipt=ReceiptRelayManager(bc, source_st, target, "builder").build_receipt(b8, tx)
            assert receipt
            slot=0; key=ReceiptRelayManager.mailbox_key(target.address, slot)
            probe=KademliaRouter("probe")
            candidates=[f"repair-{i}" for i in range(64)]
            candidates.sort(key=lambda nid: probe._to_160bit_int(nid) ^ probe._to_160bit_int(key))
            close_id, far_id=candidates[0], candidates[-1]
            far_st=Storage(str(tmp_path / "repair_far.db")); stores.append(far_st)
            close_st=Storage(str(tmp_path / "repair_close.db")); stores.append(close_st)
            far=_net_shell(far_id, bc, far_st, Wallet.generate())
            close=_net_shell(close_id, bc, close_st, Wallet.generate())
            assert far._receipt_relay.store_relay_receipt(receipt, slot)[0]
            _link(far, close)
            # Production maintenance invokes the same route operation periodically.
            far._receipt_route_put(receipt, slot)
            assert len(close._receipt_relay.get_mailbox(target.address, slot)) == 1
            # The repaired copy remains after the old holder disappears.
            far.peers.clear(); close.peers.clear()
            assert len(close._receipt_relay.get_mailbox(target.address, slot)) == 1
        finally:
            for st in stores: st.close()
            source_st.close()

def test_exact_offline_height5_tx_at8_pruned_to20_recovers_balance_and_sender_history(tmp_path, monkeypatch):
    import sqlite3
    from visold.chain.consensus_engine import ConsensusEngine
    from visold.consensus.difficulty import DifficultyEngine
    from visold.network.bootstrap_sync import verify_bootstrap_header_chain

    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 0.0)
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 2)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 3)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 9)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 500)
    monkeypatch.setattr(Config, "SNAPSHOT_KEEP", 3)

    with patch.object(Blockchain, "get_difficulty", return_value=0.0), \
         patch.object(DifficultyEngine, "_compute_uncached", return_value=0.0), \
         patch.object(DifficultyEngine, "validate_pow_target", return_value=True):
        source_st, source = _chain(tmp_path, "exact_source.db")
        d = Wallet.generate(); target = Wallet.generate()
        eng = ConsensusEngine(source, d)
        relay_st = Storage(str(tmp_path / "exact_relay.db"))
        stale_st = None
        try:
            while source.height() < 5:
                c=eng.build_candidate_block(d.address); assert c.mine(); assert source.apply_block(c)[0]

            # B goes offline here: clone exactly the canonical h=5 state.
            stale_path=str(tmp_path / "exact_stale.db")
            dst=sqlite3.connect(stale_path)
            try: source_st._conn().backup(dst)
            finally: dst.close()

            while source.height() < 7:
                c=eng.build_candidate_block(d.address); assert c.mine(); assert source.apply_block(c)[0]

            tx=Transaction(
                sender=d.address, receiver=target.address, amount=5.0, fee=0.05,
                nonce=source_st.get_nonce(d.address), timestamp=int(time.time()))
            tx.sign(d)
            ok,msg=source.mempool.add(tx); assert ok,msg
            b8=eng.build_candidate_block(d.address)
            assert any(t.tx_id == tx.tx_id for t in b8.transactions)
            assert b8.mine(); ok,msg=source.apply_block(b8); assert ok,msg

            # Temporary network custody begins while the body still exists.
            builder=ReceiptRelayManager(source, relay_st, d, "relay-builder")
            receipt=builder.build_receipt(b8, tx); assert receipt
            assert builder.store_relay_receipt(receipt, 0)[0]

            while source.height() < 20:
                c=eng.build_candidate_block(d.address); assert c.mine(); ok,msg=source.apply_block(c); assert ok,msg
            source._rolling_pruner._last_height=-1
            source._rolling_pruner.maybe_prune(source.height())
            assert source.height() == 20
            for h in range(6, 11):
                assert source.get_block(h).is_pruned is True, h

            # B fast-forwards over the missing bodies using the authenticated h=18 snapshot.
            headers=[source.get_block(h).to_dict() for h in range(0, 20)]  # through commitment block 19
            entry=next(e for e in source._snapshot_engine.get_manifest() if int(e["height"]) == 18)
            blob=source._snapshot_engine.get_snapshot_blob(18); assert blob
            ok,msg,verified,committed=verify_bootstrap_header_chain(
                headers, source_st.get_meta("genesis_hash"), 18)
            assert ok,msg; assert committed == entry["bootstrap_digest"]

            stale_st=Storage(stale_path); stale=Blockchain(stale_st)
            assert stale.height() == 5
            ok,msg=stale._snapshot_engine.restore_authenticated_bootstrap(blob, committed, verified)
            assert ok,msg; assert stale.height() == 18
            stale.layer2._try_restore_from_storage()
            for h in (19,20):
                ok,msg=stale.apply_block(source.get_block(h)); assert ok,msg
            assert stale.height() == 20
            assert stale_st.get_balance_sat(target.address) == 500_000_000

            # Receipt is independent of the pruned body and restores sender/history metadata.
            target_mgr=ReceiptRelayManager(stale, stale_st, target, "target")
            held=builder.get_mailbox(target.address, 0)
            assert len(held) == 1
            ok,msg=target_mgr.deliver_to_local_wallet(held[0]); assert ok,msg
            hist=stale_st.get_address_txs(target.address)
            recovered=next(x for x in hist if x.get("tx_id") == tx.tx_id)
            assert recovered["sender"] == d.address
            assert recovered["receiver"] == target.address
            assert recovered["amount"] == 5.0
            assert recovered["block_idx"] == 8
            assert recovered.get("_relay_receipt") is True
        finally:
            if stale_st is not None: stale_st.close()
            relay_st.close(); source_st.close()
