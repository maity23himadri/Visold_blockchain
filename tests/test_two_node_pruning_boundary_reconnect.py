"""Diagnostic two-database test for stale-peer prune-boundary behavior."""
from __future__ import annotations
import json, threading, time
from types import SimpleNamespace
from unittest.mock import patch

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.network.p2p import (
    P2PNetwork, MSG_GET_CHAIN, MSG_CHAIN, MSG_GET_SNAPSHOT,
    MSG_SNAPSHOT_DATA, MSG_GET_SNAPSHOT_MANIFEST, MSG_SNAPSHOT_MANIFEST,
)
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def mine_to(chain, miner, target):
    eng = ConsensusEngine(chain, miner)
    chain._rolling_pruner.prune_async = lambda _height: None
    while chain.height() < target:
        b = eng.build_candidate_block(miner.address)
        assert b.mine()
        ok, why = chain.apply_block(b)
        assert ok, why


def pruned_heights(chain):
    out = []
    for h in range(chain.height() + 1):
        b = chain.get_block(h)
        if b is not None and b.is_pruned:
            out.append(h)
    return out


def test_two_nodes_reconnect_after_A_prunes_and_compare_pruning_boundaries(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 2)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 1000)
    monkeypatch.setattr(Config, "BOOTSTRAP_HEADER_PAGE_SIZE", 2)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 9)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 500)
    monkeypatch.setattr(Config, "SNAPSHOT_KEEP", 3)
    monkeypatch.setattr(Config, "SNAPSHOT_FAST_SYNC_ENABLED", True)
    monkeypatch.setattr(Config, "RECEIPT_RELAY_ENABLED", False)
    DifficultyEngine.invalidate_cache()

    with patch.object(Blockchain, "get_difficulty", return_value=0.0), \
         patch.object(DifficultyEngine, "_compute_uncached", return_value=0.0), \
         patch.object(DifficultyEngine, "validate_pow_target", return_value=True):
        ast = Storage(str(tmp_path / "node_A.db")); A = Blockchain(ast)
        bst = Storage(str(tmp_path / "node_B.db")); B = Blockchain(bst)
        A._rolling_pruner.prune_async = lambda _height: None
        B._rolling_pruner.prune_async = lambda _height: None
        miner = Wallet.generate()
        try:
            # A mines; B connects and syncs the complete chain through h=10.
            mine_to(A, miner, 10)
            initial = [Block.from_dict(A.get_block(h).to_dict()) for h in range(0, 11)]
            ok, why = B.accept_chain(initial)
            assert ok, f"B initial sync rejected: {why}"
            assert B.height() == A.height() == 10
            assert B.latest_block().block_hash == A.latest_block().block_hash

            # B goes offline. Enable authenticated snapshot commitments for the
            # newly mined suffix, then A advances and prunes older block bodies.
            Config.BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT = 3
            mine_to(A, miner, 25)
            A._rolling_pruner._last_height = -1
            n = A._rolling_pruner.maybe_prune(A.height())
            assert n > 0, "A did not run pruning"
            assert A.height() == 25
            a_watermark_before = int(ast.get_meta("rolling_pruned_until") or 0)
            assert A.get_block(1).is_pruned

            # B reconnects. The normal chain-sync request needs block 11 whose
            # body is pruned, which must dispatch authenticated snapshot recovery.
            class SourcePeer:
                peer_id = "node-A-peer"
                connected = True
                def __init__(self):
                    self._sync_state_lock = threading.Lock()
                    self._pagination_active = threading.Event()
                    self._snap_response_queue = None
                    self._bootstrap_header_queue = None
                def send(self, msg):
                    typ = msg.get("type")
                    if typ == MSG_GET_SNAPSHOT_MANIFEST:
                        self._snap_response_queue.put({
                            "type": MSG_SNAPSHOT_MANIFEST,
                            "manifest": A._snapshot_engine.get_manifest(),
                        })
                    elif typ == MSG_GET_CHAIN:
                        start = int(msg["from_idx"]); end = min(int(msg["to_idx"]), A.height())
                        self._bootstrap_header_queue.put({
                            "type": MSG_CHAIN,
                            "blocks": [A.get_block(h).to_dict() for h in range(start, end + 1)],
                            "request_id": msg.get("request_id"),
                        })
                    elif typ == MSG_GET_SNAPSHOT:
                        h = int(msg["height"]); blob = A._snapshot_engine.get_snapshot_blob(h)
                        self._snap_response_queue.put({
                            "type": MSG_SNAPSHOT_DATA, "height": h,
                            "data_hex": blob.hex() if blob else "",
                        })
                    else:
                        raise AssertionError(f"unexpected P2P message {msg}")

            peer = SourcePeer()
            net = P2PNetwork.__new__(P2PNetwork)
            net.blockchain = B; net.storage = bst
            net._bootstrap_recovery_lock = threading.Lock()
            net._sync_finish = lambda *_a, **_k: None
            def sync_after_snapshot(_peer, start, end, **_kwargs):
                blocks = [Block.from_dict(A.get_block(h).to_dict())
                          for h in range(start, min(end, A.height()) + 1)]
                if blocks:
                    ok2, why2 = B.accept_chain(blocks)
                    assert ok2, why2
                return True
            net._sync_request = sync_after_snapshot
            net._on_chain_sync_result(
                peer, [SimpleNamespace(index=11)], False,
                "Block 11 is pruned/header-only; required historical block body is pruned",
                False, 0, "two-node-prune-reconnect")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if not getattr(peer, "_authenticated_pruned_recovery_active", False) and B.height() == 25:
                    break
                time.sleep(0.01)
            assert B.height() == A.height() == 25, f"B failed authenticated reconnect: B={B.height()} A={A.height()}"
            assert B.latest_block().block_hash == A.latest_block().block_hash
            assert B.latest_block().state_root == A.latest_block().state_root

            # Allow B's own local pruner to run at its recovered tip.
            B._rolling_pruner._last_height = -1
            b_pruned_now = B._rolling_pruner.maybe_prune(B.height())

            a_flags = pruned_heights(A)
            b_flags = pruned_heights(B)
            a_mark = int(ast.get_meta("rolling_pruned_until") or 0)
            b_mark = int(bst.get_meta("rolling_pruned_until") or 0)
            def database_stats(storage):
                conn = storage._conn()
                rows = conn.execute("SELECT idx, data_json FROM blocks ORDER BY idx").fetchall()
                flags = [int(idx) for idx, payload in rows if json.loads(payload).get("pruned") is True]
                tx_rows = conn.execute("SELECT block_idx, COUNT(*) FROM transactions GROUP BY block_idx ORDER BY block_idx").fetchall()
                header_rows = [int(r[0]) for r in conn.execute("SELECT idx FROM block_headers ORDER BY idx").fetchall()]
                return {"pruned_flagged_heights_in_blocks_table": flags,
                        "transaction_table_rows_by_height": [[int(h), int(n)] for h, n in tx_rows],
                        "block_headers_heights": header_rows}

            # Regression assertions: bootstrap must prune the old local prefix,
            # repair header indexes, and keep the watermark aligned to the actual
            # first retained full-body height. B legitimately lacks bodies for imported
            # snapshot-header heights 11..24, so its body retention can be more
            # aggressive than A, but both nodes must prune the old prefix through
            # a snapshot-aligned recoverability boundary at this final height.
            # For A, raw cutoff=16 but the newest committed snapshot strictly
            # below it is h=14, so the safe exclusive boundary is 15.
            assert a_flags == list(range(15))
            assert b_flags == list(range(25))
            assert a_mark == 15 and b_mark == 25
            assert b_pruned_now == 0
            assert [B.get_block(h).is_pruned for h in range(0, 11)] == [True] * 11
            b_headers = [int(r[0]) for r in bst._conn().execute(
                "SELECT idx FROM block_headers ORDER BY idx").fetchall()]
            assert b_headers == list(range(25)), b_headers
            a_headers = [int(r[0]) for r in ast._conn().execute(
                "SELECT idx FROM block_headers ORDER BY idx").fetchall()]
            assert a_headers == list(range(15)), a_headers

            print("RESULT", {
                "height_A": A.height(), "height_B": B.height(),
                "tip_hash_equal": A.latest_block().block_hash == B.latest_block().block_hash,
                "configured_window": Config.ROLLING_PRUNE_WINDOW,
                "A_pruned_blocks": a_flags,
                "B_pruned_blocks": b_flags,
                "A_first_pruned_flagged_block": min(a_flags) if a_flags else None,
                "B_first_pruned_flagged_block": min(b_flags) if b_flags else None,
                "A_contiguous_pruned_prefix_end": max(a_flags) if a_flags and a_flags == list(range(max(a_flags)+1)) else None,
                "B_contiguous_pruned_prefix_end": max(b_flags) if b_flags and b_flags == list(range(max(b_flags)+1)) else None,
                "A_rolling_pruned_until": a_mark,
                "B_rolling_pruned_until": b_mark,
                "A_pruned_blocks_this_pass": n,
                "B_pruned_blocks_this_pass_after_reconnect": b_pruned_now,
                "B_local_height_0_to_10_pruned_flags": [B.get_block(h).is_pruned for h in range(0,11)],
                "A_database_tables": database_stats(ast),
                "B_database_tables": database_stats(bst),
            })

            # Advance both nodes until A's rolling cutoff reaches B's more
            # aggressively pruned snapshot history. Their watermark must never
            # move backwards, and the body-retention boundary should converge.
            mine_to(A, miner, 35)
            A._rolling_pruner._last_height = -1
            A._rolling_pruner.maybe_prune(A.height())
            tail = [Block.from_dict(A.get_block(h).to_dict()) for h in range(26, 36)]
            ok, why = B.accept_chain(tail)
            assert ok, why
            assert B.height() == A.height() == 35
            assert B.latest_block().block_hash == A.latest_block().block_hash
            assert B.latest_block().state_root == A.latest_block().state_root
            B._rolling_pruner._last_height = -1
            B._rolling_pruner.maybe_prune(B.height())
            # tip=35 gives raw cutoff=26; snapshot h=24 is the last committed
            # anchor strictly below it, so both converge on safe boundary 25.
            assert ast.get_meta("rolling_pruned_until") == "25"
            assert bst.get_meta("rolling_pruned_until") == "25"
            assert [A.get_block(h).is_pruned for h in range(25)] == [True] * 25
            assert [B.get_block(h).is_pruned for h in range(25)] == [True] * 25
            assert [A.get_block(h).is_pruned for h in range(25, 36)] == [False] * 11
            assert [B.get_block(h).is_pruned for h in range(25, 36)] == [False] * 11
        finally:
            bst.close(); ast.close()
            DifficultyEngine.invalidate_cache()


def test_legacy_overstated_watermark_is_repaired_without_another_snapshot(tmp_path, monkeypatch):
    """An old bad DB must self-heal on its next pruning trigger, even if block 0 is pruned."""
    monkeypatch.setattr(Config, "BOOTSTRAP_SNAPSHOT_INTERVAL", 2)
    monkeypatch.setattr(Config, "BOOTSTRAP_COMMITMENT_ACTIVATION_HEIGHT", 3)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_ENABLED", True)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_WINDOW", 9)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_INTERVAL", 1)
    monkeypatch.setattr(Config, "ROLLING_PRUNE_BATCH", 4)
    DifficultyEngine.invalidate_cache()

    with patch.object(Blockchain, "get_difficulty", return_value=0.0), \
         patch.object(DifficultyEngine, "_compute_uncached", return_value=0.0), \
         patch.object(DifficultyEngine, "validate_pow_target", return_value=True):
        st = Storage(str(tmp_path / "legacy-bad-watermark.db"))
        chain = Blockchain(st)
        chain._rolling_pruner.prune_async = lambda _height: None
        miner = Wallet.generate()
        try:
            mine_to(chain, miner, 25)
            conn = st._conn()
            # Simulate the old bootstrap result: local heights 0..10 remain full;
            # imported heights 11..24 are header-only, but the watermark wrongly
            # claims the prefix through 23 has already been pruned. Height 25 is full.
            for h in range(11, 25):
                payload = chain.get_block(h).to_dict()
                payload["transactions"] = []
                payload["pruned"] = True
                conn.execute(
                    "UPDATE blocks SET data_json=? WHERE idx=?",
                    (json.dumps(payload, separators=(",", ":")), h),
                )
            conn.execute("DELETE FROM transactions WHERE block_idx BETWEEN 11 AND 24")
            conn.commit()
            st.set_meta("rolling_pruned_until", "24")
            st.set_meta("rolling_prune_reconcile_version", "")

            assert [chain.get_block(h).is_pruned for h in range(0, 11)] == [False] * 11
            assert st.get_meta("rolling_pruned_until") == "24"

            # Trigger normal pruning. The one-time reconciliation must ignore the
            # stale watermark, walk the actual stored markers, repair header rows,
            # and catch up through cutoff=16 in multiple bounded batches.
            chain._rolling_pruner._last_height = -1
            chain._rolling_pruner.maybe_prune(chain.height())

            assert chain.height() == 25
            assert [chain.get_block(h).is_pruned for h in range(0, 16)] == [True] * 16
            assert [chain.get_block(h).is_pruned for h in range(16, 25)] == [True] * 9
            assert not chain.get_block(25).is_pruned
            assert st.get_meta("rolling_pruned_until") == "25"
            headers = [int(r[0]) for r in conn.execute(
                "SELECT idx FROM block_headers ORDER BY idx").fetchall()]
            assert headers == list(range(25))
        finally:
            st.close()
            DifficultyEngine.invalidate_cache()
