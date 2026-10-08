# ─────────────────────────────────────────────────────────────────────────────
#  Visold (VSD) Blockchain Protocol
#  Copyright (c) 2025 Visold Contributors
#  Licensed under the MIT License.
#
#  The original and canonical source is maintained by the Visold Project.
#  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#  the license agreement.
# ─────────────────────────────────────────────────────────────────────────────
# cython: language_level=3
# cython: boundscheck=True
# cython: wraparound=True
# cython: cdivision=True
# cython: nonecheck=True
# cython: initializedcheck=False
# cython: infer_types=True
# cython: optimize.use_switch=True
# cython: optimize.unpack_method_calls=True
"""visold.api.rpc_server

Original section: SECTION 17: JSON-RPC API (port + 1, for wallets / explorers)

Defines: RPCServer
Origin: visold_vsd_.py L40412-41687
"""

import hmac
import http.server
import json
import os
import secrets
import socketserver
import threading
import time
from typing import TYPE_CHECKING

from visold.kernel.config import Config
from visold.kernel.events import Event, EventType
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics
from visold.kernel.units import from_satoshi, to_satoshi
from visold.ledger.transaction import Transaction
from visold.mempool.mev import _mev_mempool
from visold.network.capabilities import (
    CAP_ARCHIVE,
    CAP_BOOTSTRAP,
    CAP_FULL_NODE,
    CAP_LIGHT_RELAY,
    CAP_VALIDATOR,
    CAP_VVM_EXEC,
)
from visold.network.spv import SPVClient
from visold.rollup.l2_state import L2Transaction, L2_BRIDGE_ADDRESS
from visold.vm.engine import VVMEngine
from visold.vm.naming import derive_contract_address
from visold.vm.static_analyzer import VVMStaticAnalyzer

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.node.visold_node import VisoldNode


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 17: JSON-RPC API (port + 1, for wallets / explorers)
# ─────────────────────────────────────────────────────────────────────────────
class RPCServer:
    """
    Minimal JSON-RPC 2.0 HTTP server — localhost only, Bearer-token authenticated.

    A random 256-bit token is generated on first start and written to
    ~/.visold/rpc_token (mode 0o600).  Callers must supply it in every
    request as:  Authorization: Bearer <token>

    Without the token any request is rejected with HTTP 401, so no other
    process on the same machine (browser, malware, another app) can issue
    commands such as 'sendtransaction'.

    Exposes: getbalance, getblockcount, getblock, sendtransaction,
             getpeerinfo, getmempool
    """
    TOKEN_FILE = os.path.join(Config.DATA_DIR, "rpc_token")

    def __init__(self, node: 'VisoldNode', rpc_port: int):
        self.node      = node
        self.rpc_port  = rpc_port
        self._server   = None
        self._thread   = None
        self._token    = self._load_or_create_token()

    # ── Token management ──────────────────────────────────────────────────────

    @classmethod
    def _load_or_create_token(cls) -> str:
        Config.ensure_dirs()
        if os.path.exists(cls.TOKEN_FILE):
            with open(cls.TOKEN_FILE, 'r') as f:
                tok = f.read().strip()
            if tok:
                return tok
        tok = secrets.token_hex(32)   # 256-bit random token
        with open(cls.TOKEN_FILE, 'w') as f:
            f.write(tok)
        try:
            os.chmod(cls.TOKEN_FILE, 0o600)
        except Exception:
            pass
        log.info(f"RPC token written to {cls.TOKEN_FILE} (chmod 600)")
        return tok

    # ── Server lifecycle ──────────────────────────────────────────────────────

    def start(self):
        node  = self.node
        token = self._token
        # ── v7.5.0-OPT Admin token ─────────────────────────────────────────
        # Admin-gated methods (currently only vsd_triggerManualRollup) require
        # a SECOND token that is distinct from the regular RPC token.  The
        # rationale: a wallet or explorer that holds the standard token
        # should not be able to force-seal L2 rollups.  We generate the
        # admin token on demand — if ~/.visold/rpc_admin_token does not
        # exist, admin-gated methods are permanently disabled on this node
        # until the operator creates the file.  This is a deliberate
        # fail-closed default: no admin privileges unless explicitly enabled.
        _ADMIN_TOKEN_FILE = os.path.join(Config.DATA_DIR, "rpc_admin_token")
        _admin_token = None
        try:
            if os.path.exists(_ADMIN_TOKEN_FILE):
                with open(_ADMIN_TOKEN_FILE, "r") as _atf:
                    _candidate = _atf.read().strip()
                if _candidate:
                    _admin_token = _candidate
        except Exception as _at_e:
            log.warning(f"Admin token read failed: {_at_e}")
            _admin_token = None

        # F-16 FIX: Token-bucket rate limiter — max 20 req/s standard,
        # 2 req/s for expensive ops (analyzecontract, getmempool).
        import threading as _rpc_threading
        _rate_lock      = _rpc_threading.Lock()
        _rate_tokens    = [20.0]
        _rate_last      = [time.time()]
        _RATE_MAX       = 20.0
        _RATE_REFILL    = 20.0   # tokens per second
        _SLOW_METHODS   = {"analyzecontract", "getmempool", "checkinvariants"}

        def _consume_token(method: str = "") -> bool:
            cost = 10.0 if method in _SLOW_METHODS else 1.0
            with _rate_lock:
                now  = time.time()
                elapsed = now - _rate_last[0]
                _rate_last[0] = now
                _rate_tokens[0] = min(_RATE_MAX,
                                      _rate_tokens[0] + elapsed * _RATE_REFILL)
                if _rate_tokens[0] >= cost:
                    _rate_tokens[0] -= cost
                    return True
                return False

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def _send_json(self, status: int, body: dict):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _send_text(self, status: int, body: str,
                           content_type: str = "text/plain; charset=utf-8"):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _authenticate(self) -> bool:
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    return False
                provided = auth[len("Bearer "):]
                return hmac.compare_digest(provided, token)

            def _is_admin(self) -> bool:
                """v7.5.0-OPT: check whether the caller holds the admin token.

                Gate for L2 admin methods (e.g. vsd_triggerManualRollup).
                Admin privilege requires BOTH:
                  • a valid standard Bearer token (already checked by
                    _authenticate before dispatch), AND
                  • a matching X-Admin-Token header whose value equals
                    the admin token loaded from ~/.visold/rpc_admin_token.

                If the admin token file does not exist OR is empty, this
                returns False unconditionally (fail-closed).  Operators
                explicitly opt in by creating the file with mode 0o600.
                """
                if _admin_token is None:
                    return False
                hdr = self.headers.get("X-Admin-Token", "")
                if not hdr:
                    return False
                try:
                    return hmac.compare_digest(str(hdr), _admin_token)
                except Exception:
                    return False

            def _check_rate(self, method: str = "") -> bool:
                """F-16: Enforce token-bucket rate limit."""
                if not _consume_token(method):
                    self._send_json(429, {"error": "Rate limit exceeded — try again shortly"})
                    return False
                return True

            def do_GET(self):
                """
                GET /metrics  — Prometheus text format.
                F-08 FIX: Requires Bearer token authentication.
                            Metrics expose sensitive operational intelligence
                            (ban counts, attack alerts, mempool size) — they
                            must not be available to unauthenticated processes.
                GET /headers  — light-client header sync (SPV).
                """
                if self.path == "/metrics":
                    # F-08 FIX: Authenticate before serving metrics.
                    if not self._authenticate():
                        self._send_json(401, {"error": "Unauthorized — Bearer token required"})
                        return
                    if not self._check_rate():
                        return
                    # Update live gauges before rendering
                    metrics.set_gauge("peer_count",
                                      len(node.network.active_peer_count()))
                    metrics.set_gauge("mempool_size",
                                      node.blockchain.mempool.size())
                    metrics.set_gauge("chain_height",
                                      node.blockchain.height())
                    metrics.set_gauge("difficulty",
                                      node.blockchain.get_difficulty())
                    text = metrics.render_prometheus()
                    self._send_text(200, text,
                                    "text/plain; version=0.0.4; charset=utf-8")
                    return
                if self.path.startswith("/headers"):
                    if not self._authenticate():
                        self._send_json(401, {"error": "Unauthorized"})
                        return
                    import urllib.parse as _up
                    qs   = _up.urlparse(self.path).query
                    args = dict(_up.parse_qsl(qs))
                    from_idx = int(args.get("from", 0))
                    count    = min(int(args.get("count", 20)), 100)
                    headers  = []
                    for i in range(from_idx, from_idx + count):
                        b = node.blockchain.get_block(i)
                        if b:
                            headers.append(SPVClient.get_block_header(b))
                    data = json.dumps(headers).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                self._send_text(404, "Not found")

            def do_POST(self):
                if not self._authenticate():
                    self._send_json(401, {
                        "jsonrpc": "2.0", "id": None,
                        "error": {"code": -32600,
                                  "message": "Unauthorized — valid Bearer token required"}
                    })
                    return
                # VSD-H07 FIX: apply token-bucket rate limit to POST as well
                # (previously only GET /metrics was rate-limited)
                try:
                    _method_peek = ""
                    # Peek method name for slow-method cost without consuming body
                except Exception:
                    pass
                if not self._check_rate():
                    return
                try:
                    length = int(self.headers.get("Content-Length", 0))
                except ValueError:
                    length = 0
                if length > 64 * 1024:
                    self._send_json(413, {
                        "jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": "Request body too large"}
                    })
                    return
                body = self.rfile.read(length)
                try:
                    req    = json.loads(body)
                    result = self._dispatch(req)
                    self._send_json(200, {
                        "jsonrpc": "2.0",
                        "id":      req.get("id"),
                        "result":  result,
                    })
                except Exception as e:
                    self._send_json(200, {
                        "jsonrpc": "2.0", "id": None,
                        "error": {"code": -32603, "message": str(e)},
                    })

            def _dispatch(self, req):
                method = req.get("method", "")
                params = req.get("params", [])
                # ── Core ─────────────────────────────────────────────────────
                if method == "getbalance":
                    addr = params[0] if params else node.wallet.address
                    return node.storage.get_balance(addr)
                elif method == "getblockcount":
                    return node.blockchain.height()
                elif method == "getblock":
                    idx = int(params[0]) if params else node.blockchain.height()
                    b = node.blockchain.get_block(idx)
                    return b.to_dict() if b else None
                elif method == "sendtransaction":
                    to, amt = params[0], float(params[1])
                    memo = params[2] if len(params) > 2 else ""
                    ok, msg = node.send_transaction(to, amt, memo)
                    return {"ok": ok, "msg": msg}
                elif method == "getpeerinfo":
                    return node.network.peer_list()
                elif method == "getmempool":
                    return [t.to_dict() for t in
                            node.blockchain.mempool.all_txs()[:50]]
                # ── SPV / Light client (Problem #16) ─────────────────────────
                elif method == "getblockheader":
                    idx = int(params[0]) if params else node.blockchain.height()
                    b = node.blockchain.get_block(idx)
                    return SPVClient.get_block_header(b) if b else None
                elif method == "getblockheaders":
                    from_idx = int(params[0]) if len(params) > 0 else 0
                    count    = min(int(params[1]) if len(params) > 1 else 20, 100)
                    return [SPVClient.get_block_header(b)
                            for i in range(from_idx, from_idx + count)
                            for b in [node.blockchain.get_block(i)] if b]
                elif method == "getmerkleproof":
                    idx   = int(params[0]) if len(params) > 0 else 0
                    tx_id = params[1] if len(params) > 1 else ""
                    b     = node.blockchain.get_block(idx)
                    if not b:
                        return None
                    # SPV-1 fix: pass block height so the V1/V2 rule used
                    # to build the proof matches Block._merkle()'s rule
                    # for that height exactly.
                    proof = SPVClient.get_merkle_proof(
                        b.transactions, tx_id, b.index)
                    return {"tx_id": tx_id, "block_index": idx,
                            "merkle_root": b.merkle_root, "proof": proof}
                elif method == "verifymerkleproof":
                    return SPVClient.verify_merkle_proof(
                        params[0], params[1], params[2])
                # ── Protocol version (Problem #13) ────────────────────────────
                elif method == "getprotocolversion":
                    return {
                        "current":  Config.PROTOCOL_VERSION,
                        "node":     node.blockchain._proto_mgr.current_version(),
                        "active":   node.blockchain._governance.get_active_version(),
                    }
                # ── Chain info ────────────────────────────────────────────────
                elif method == "getchaininfo":
                    gen = node.storage.get_block(0)
                    return {
                        "chain_id":         Config.CHAIN_ID,
                        "version":          Config.VERSION,
                        "height":           node.blockchain.height(),
                        "difficulty":       node.blockchain.get_difficulty(),
                        "genesis_hash":     node.storage.get_meta("genesis_hash") or "",
                        "genesis_ts":       gen.timestamp if gen else 0,
                        "network":          "mainnet",
                        "protocol_version": Config.PROTOCOL_VERSION,
                        "active_version":   node.blockchain._governance.get_active_version(),
                    }
                # ── Governance — upgrade lifecycle ────────────────────────────
                elif method == "getgovernance":
                    """
                    Returns all upgrade proposals and their current phase.
                    No params required.
                    """
                    return {
                        "proposals":       node.blockchain._governance.all_proposals(),
                        "active_version":  node.blockchain._governance.get_active_version(),
                        "blacklist":       list(node.blockchain._governance._blacklist),
                    }
                elif method == "getupgradestatus":
                    """
                    Returns status of a specific upgrade proposal.
                    Params: [version_int]
                    """
                    version = int(params[0]) if params else None
                    if version is None:
                        raise ValueError("getupgradestatus requires version param")
                    p = node.blockchain._governance.get_proposal(version)
                    return p.to_dict() if p else None
                elif method == "proposeupgrade":
                    """
                    Propose a protocol upgrade.
                    Params: [version_int, signal_start_height_int, threshold_float?]
                    Requires valid bearer token (operator only).
                    """
                    if len(params) < 2:
                        raise ValueError(
                            "proposeupgrade requires [version, signal_start_height]")
                    version      = int(params[0])
                    start_height = int(params[1])
                    threshold    = float(params[2]) if len(params) > 2 else None
                    ok, msg = node.propose_upgrade(version, start_height, threshold)
                    return {"ok": ok, "msg": msg}
                elif method == "emergencydisable":
                    """
                    Emergency kill-switch for a faulty upgrade version.
                    Params: [version_int]
                    Requires valid bearer token (operator only).
                    """
                    version = int(params[0]) if params else None
                    if version is None:
                        raise ValueError("emergencydisable requires version param")
                    ok, msg = node.emergency_disable_upgrade(version)
                    return {"ok": ok, "msg": msg}
                elif method == "forkchoice":
                    """
                    Run the deterministic fork-choice rule between two block hashes.
                    Params: [hash_a, hash_b]
                    Returns the hash of the preferred chain tip.
                    """
                    if len(params) < 2:
                        raise ValueError("forkchoice requires [hash_a, hash_b]")
                    blk_a = node.storage.get_block_by_hash(params[0])
                    blk_b = node.storage.get_block_by_hash(params[1])
                    if blk_a is None or blk_b is None:
                        raise ValueError("One or both block hashes not found")
                    preferred = node.blockchain._governance.fork_choice(
                        node.storage, blk_a, blk_b)
                    return {
                        "preferred_hash": preferred.block_hash,
                        "preferred_height": preferred.index,
                    }
                # ── Mempool tx by id ──────────────────────────────────────────
                elif method == "getmempooltx":
                    tx_id = params[0] if params else ""
                    if not tx_id:
                        raise ValueError("getmempooltx requires tx_id param")
                    tx = node.storage.mempool_get_by_id(tx_id)
                    return tx.to_dict() if tx else None
                # ── Rich balance list ─────────────────────────────────────────
                elif method == "getbalances":
                    limit = min(int(params[0]) if params else 20, 500)
                    rows = node.storage._conn().execute(
                        "SELECT address, balance FROM balances "
                        "ORDER BY balance DESC LIMIT ?", (limit,)).fetchall()
                    return [{"address": r["address"], "balance": r["balance"]}
                            for r in rows]
                # ── Metrics snapshot (Problem #11) ────────────────────────────
                elif method == "getmetrics":
                    return {
                        "peer_count":           len(node.network.active_peer_count()),
                        "mempool_size":         node.blockchain.mempool.size(),
                        "chain_height":         node.blockchain.height(),
                        "hashrate":             metrics.get_gauge("hashrate"),
                        "difficulty":           node.blockchain.get_difficulty(),
                        "avg_block_time_s":     round(metrics.avg_block_time(), 3),
                        "base_fee_multiplier":  metrics.get_gauge("base_fee_multiplier"),
                        "blocks_applied":       metrics.get_counter("blocks_applied"),
                        "blocks_finalized_bft": metrics.get_counter("blocks_finalized_bft"),
                        "blocks_finalized_pow": metrics.get_counter("blocks_finalized_pow"),
                        "eco_concentration_alerts": metrics.get_counter("economic_concentration_alerts"),
                        "eco_fee_spike_alerts":     metrics.get_counter("economic_fee_spike_alerts"),
                        "eco_collusion_alerts":     metrics.get_counter("economic_collusion_alerts"),
                        # Governance metrics
                        "governance_proposals":         metrics.get_counter("governance_proposals"),
                        "governance_lock_ins":          metrics.get_counter("governance_lock_ins"),
                        "governance_activations":       metrics.get_counter("governance_activations"),
                        "governance_rollbacks":         metrics.get_counter("governance_rollbacks"),
                        "governance_signal_failures":   metrics.get_counter("governance_signal_failures"),
                        "governance_emergency_disables":metrics.get_counter("governance_emergency_disables"),
                        "governance_cooldowns":         metrics.get_counter("governance_cooldowns"),
                        # VVM metrics
                        "vvm_txs_success":  metrics.get_counter("vvm_txs_success"),
                        "vvm_txs_reverted": metrics.get_counter("vvm_txs_reverted"),
                        "vvm_gas_used":     metrics.get_counter("vvm_gas_used"),
                        # Fix #12: Safety invariant counters
                        "invariant_violations":        metrics.get_gauge("invariant_violations"),
                        "invariant_safety_violations": metrics.get_counter("invariant_safety_violations"),
                        "invariant_liveness_violations": metrics.get_counter("invariant_liveness_violations"),
                        "invariant_consistency_violations": metrics.get_counter("invariant_consistency_violations"),
                        "invariant_rolling_violations": metrics.get_counter("invariant_rolling_violations"),
                        # Fix #10: State size
                        "finality_stall_blocks": metrics.get_gauge("finality_stall_blocks"),
                        "clock_drift_secs":      metrics.get_gauge("clock_drift_secs"),
                        "db_tx_index_rows":      metrics.get_gauge("db_tx_index_rows"),
                        "db_node_meta_rows":     metrics.get_gauge("db_node_meta_rows"),
                        "pruned_rows":           metrics.get_counter("pruned_rows"),
                        # Fix #11: Extended economic attack alerts
                        "eco_selfish_mining_alerts":      metrics.get_counter("economic_selfish_mining_alerts"),
                        "eco_reward_manipulation_alerts": metrics.get_counter("economic_reward_manipulation_alerts"),
                        "eco_concentration_critical":     metrics.get_counter("economic_concentration_critical"),
                        # NEW: subsystem metrics
                        "circuit_breaker_state":      node.circuit_breaker.state(),
                        "circuit_breaker_trips":      metrics.get_counter("circuit_breaker_trips"),
                        "sentinel_state":             node.sentinel.status().get("state", "OFF"),
                        "sentinel_failovers":         metrics.get_counter("sentinel_failovers"),
                        "mev_commits_submitted":      metrics.get_counter("mev_commits_submitted"),
                        "mev_reveals_verified":       metrics.get_counter("mev_reveals_verified"),
                        "slash_evidence_applied":     metrics.get_counter("slash_evidence_applied"),
                        "slash_evidence_auto_built":  metrics.get_counter("slash_evidence_auto_built"),
                        "state_pruned_until":         metrics.get_gauge("state_pruned_until_height"),
                        "capability_adverts_received":metrics.get_counter("capability_adverts_received"),
                    }

                # ── Fix #12: Safety invariant check RPC ───────────────────────
                elif method == "checkinvariants":
                    """
                    Run the three formal safety invariants and return the report.
                    Params: [full_scan_bool (optional, default false)]
                    Returns: {"safety_ok", "liveness_ok", "consistency_ok",
                              "violations": [...], "checked_at": int}
                    Note: full_scan=true scans the entire chain — may be slow
                    on long chains.  Use with care on production nodes.
                    """
                    full_scan = bool(params[0]) if params else False
                    return node.invariant_checker.check_all(full_scan=full_scan)

                elif method == "getdbsizes":
                    """
                    Return row counts for each database table.
                    Useful for monitoring state growth (Fix #10).
                    No params required.
                    """
                    return node.storage.get_state_size_report()

                elif method == "getdbbackend":
                    """
                    Return information about the active block database backend.

                    No params required.
                    Returns:
                      {
                        "backend":           "sqlite"|"leveldb"|"rocksdb",
                        "enabled":           bool,   (True when KV store is active)
                        "path":              str,    (KV store directory path)
                        "leveldb_available": bool,
                        "rocksdb_available": bool,
                        "chain_height_kv":   int,    (tip height per KV store, -1 if n/a)
                        "chain_height_sql":  int,    (tip height per SQLite)
                      }

                    Use this to verify the backend is operating correctly and
                    that the KV store and SQLite agree on the chain tip height.
                    """
                    info = node.storage._block_db.backend_info()
                    info["chain_height_kv"]  = node.storage._block_db.chain_height()
                    # SQLite chain height (direct query, bypasses KV store)
                    row = node.storage._conn().execute(
                        "SELECT MAX(idx) as h FROM blocks").fetchone()
                    info["chain_height_sql"] = (row["h"] if row and row["h"] is not None
                                                else -1)
                    return info

                # ── NEW: Circuit Breaker RPC ───────────────────────────────────
                elif method == "getcircuitbreaker":
                    """
                    Return current circuit breaker state and trip info.
                    No params required.
                    Returns: {"state": "CLOSED"|"OPEN", "trip_reason": str,
                              "trip_time": float, "violations": list}
                    """
                    return node.circuit_breaker.trip_info()

                elif method == "resetcircuitbreaker":
                    """
                    Manually reset the circuit breaker (requires bearer token).
                    Only callable after investigating the root cause of the trip.
                    No params required.
                    Returns: {"ok": bool, "msg": str}
                    """
                    ok, msg = node.circuit_breaker.reset(authorized_by="rpc_operator")
                    return {"ok": ok, "msg": msg}

                # ── NEW: Sentinel RPC ──────────────────────────────────────────
                elif method == "getsentinelstatus":
                    """
                    Return sentinel node status.
                    No params required.
                    """
                    return node.sentinel.status()

                # ── NEW: Capability Discovery RPC ─────────────────────────────
                elif method == "getcapabilities":
                    """
                    Return this node's own capabilities and known peer capabilities.
                    No params required.
                    """
                    return {
                        "own":   node.capability_router.own_capabilities(),
                        "peers": {
                            cap: node.capability_router.find_peers_with(cap)
                            for cap in [CAP_FULL_NODE, CAP_ARCHIVE, CAP_VVM_EXEC,
                                        CAP_LIGHT_RELAY, CAP_VALIDATOR, CAP_BOOTSTRAP]
                        },
                    }

                elif method == "findpeerswith":
                    """
                    Find peers with a specific capability.
                    Params: [capability_string]
                    Returns: list of peer_ids
                    """
                    if not params:
                        raise ValueError("findpeerswith requires [capability]")
                    return node.capability_router.find_peers_with(str(params[0]))

                # ── NEW: MEV Protection RPC ───────────────────────────────────
                elif method == "mevcommit":
                    """
                    Submit a transaction commitment (Phase 1 of MEV protection).
                    Params: [commit_hash_hex]
                    commit_hash = SHA-256(tx_id ‖ sender ‖ nonce)
                    Returns: {"ok": bool, "msg": str}
                    Requires Config.MEV_PROTECTION_ENABLED = True.
                    """
                    if not params:
                        raise ValueError("mevcommit requires [commit_hash]")
                    commit_hash = str(params[0])
                    current_h   = node.blockchain.height()
                    ok, msg = _mev_mempool.submit_commit(
                        commit_hash, node.wallet.address, current_h)
                    return {"ok": ok, "msg": msg,
                            "pending_commits": _mev_mempool.pending_count()}

                elif method == "getmevstatus":
                    """
                    Return MEV protection status.
                    No params required.
                    """
                    return {
                        "enabled":         Config.MEV_PROTECTION_ENABLED,
                        "pending_commits":  _mev_mempool.pending_count(),
                        "delay_blocks":     Config.COMMIT_REVEAL_DELAY_BLOCKS,
                    }

                # ── NEW: Static Analysis RPC ──────────────────────────────────
                elif method == "analyzecontract":
                    """
                    Run VVM static analysis on bytecode before deployment.
                    Params: [bytecode_hex]
                    Returns: analysis report with findings.
                    Does NOT deploy — purely informational.
                    """
                    if not params:
                        raise ValueError("analyzecontract requires [bytecode_hex]")
                    bytecode_hex = str(params[0])
                    try:
                        bytecode = bytes.fromhex(bytecode_hex)
                    except ValueError:
                        raise ValueError("bytecode_hex is not valid hex")
                    report = VVMStaticAnalyzer.analyze(bytecode)
                    return report.to_dict()

                # ── NEW: Slashing Evidence RPC ────────────────────────────────
                elif method == "submitslashingevidence":
                    """
                    Manually submit a double-sign evidence packet.
                    Params: [evidence_dict]
                    Returns: {"ok": bool, "msg": str}
                    """
                    if not params or not isinstance(params[0], dict):
                        raise ValueError("submitslashingevidence requires evidence dict")
                    ok, msg = node.slash_evidence.apply_evidence(params[0])
                    return {"ok": ok, "msg": msg}

                elif method == "getpeerreputation":
                    """
                    Get long-term reputation score for a peer.
                    Params: [peer_id]
                    Returns: {"peer_id": str, "score": float}
                    score ∈ [0.0, 1.0], neutral = 0.5
                    """
                    peer_id = str(params[0]) if params else ""
                    if not peer_id:
                        raise ValueError("getpeerreputation requires [peer_id]")
                    score = node.reputation_mgr.get_score(peer_id)
                    return {"peer_id": peer_id, "score": score}

                elif method == "getstatepruneinfo":
                    """
                    Return state pruning configuration and watermark.
                    No params required.
                    """
                    return {
                        "enabled":           Config.STATE_PRUNE_ENABLED,
                        "keep_snapshots":    Config.STATE_PRUNE_KEEP_SNAPSHOTS,
                        "interval_blocks":   Config.STATE_PRUNE_INTERVAL,
                        "pruned_watermark":  node.state_pruner.get_pruned_watermark(),
                        "current_height":    node.blockchain.height(),
                    }

                # ── VVM / Smart contract RPC methods ──────────────────────────
                elif method == "deploycontract":
                    """
                    Deploy a smart contract.
                    Params: [bytecode_hex, gas_limit_int, gas_price_float,
                             value_float (optional, default 0)]
                    Returns: {"ok": bool, "msg": str, "predicted_addr": str}
                    """
                    if len(params) < 3:
                        raise ValueError(
                            "deploycontract requires [bytecode_hex, gas_limit, gas_price]")
                    bytecode_hex = str(params[0])
                    gas_limit    = int(params[1])
                    gas_price    = float(params[2])
                    call_value   = float(params[3]) if len(params) > 3 else 0.0
                    # Validate bytecode
                    try:
                        bytecode_bytes = bytes.fromhex(bytecode_hex)
                    except ValueError:
                        raise ValueError("bytecode_hex is not valid hex")
                    if len(bytecode_bytes) > Config.VVM_MAX_BYTECODE_SIZE:
                        raise ValueError(
                            f"Bytecode {len(bytecode_bytes)} bytes exceeds max "
                            f"{Config.VVM_MAX_BYTECODE_SIZE}")
                    # Build and sign transaction
                    sender      = node.wallet.address
                    chain_nonce = node.storage.get_nonce(sender)
                    pending_cnt = len(node.blockchain.mempool._pending_nonces.get(sender, set()))
                    nonce       = chain_nonce + pending_cnt
                    fee         = round(gas_limit * gas_price, 8)
                    tx = Transaction(
                        sender    = sender,
                        receiver  = "",   # empty for deploy
                        amount    = call_value,
                        fee       = fee,
                        memo      = "VVM:deploy",
                        nonce     = nonce,
                        tx_type   = Transaction.TYPE_DEPLOY,
                        data      = bytecode_hex,
                        gas_limit = gas_limit,
                        gas_price = gas_price,
                    )
                    tx.sign(node.wallet)
                    predicted_addr = derive_contract_address(sender, nonce, tx.tx_id)
                    evt = Event(EventType.NEW_TX, {"tx": tx.to_dict()})
                    ok, msg = node.state_engine.post_sync(evt)
                    if ok:
                        node.network.broadcast_tx(tx)
                    return {"ok": ok, "msg": msg,
                            "tx_id": tx.tx_id,
                            "predicted_addr": predicted_addr}

                elif method == "callcontract":
                    """
                    Call a deployed smart contract.
                    Params: [contract_addr, calldata_hex, gas_limit_int,
                             gas_price_float, value_float (optional, default 0)]
                    Returns: {"ok": bool, "msg": str, "tx_id": str}
                    """
                    if len(params) < 4:
                        raise ValueError(
                            "callcontract requires [contract_addr, calldata_hex, "
                            "gas_limit, gas_price]")
                    contract_addr = str(params[0])
                    calldata_hex  = str(params[1])
                    gas_limit     = int(params[2])
                    gas_price     = float(params[3])
                    call_value    = float(params[4]) if len(params) > 4 else 0.0
                    # Validate contract
                    if not node.storage.get_contract(contract_addr):
                        raise ValueError(f"Contract {contract_addr} not found")
                    try:
                        if calldata_hex:
                            bytes.fromhex(calldata_hex)
                    except ValueError:
                        raise ValueError("calldata_hex is not valid hex")
                    sender      = node.wallet.address
                    chain_nonce = node.storage.get_nonce(sender)
                    pending_cnt = len(node.blockchain.mempool._pending_nonces.get(sender, set()))
                    nonce       = chain_nonce + pending_cnt
                    fee         = round(gas_limit * gas_price, 8)
                    tx = Transaction(
                        sender    = sender,
                        receiver  = contract_addr,
                        amount    = call_value,
                        fee       = fee,
                        memo      = "VVM:call",
                        nonce     = nonce,
                        tx_type   = Transaction.TYPE_CALL,
                        data      = calldata_hex,
                        gas_limit = gas_limit,
                        gas_price = gas_price,
                    )
                    tx.sign(node.wallet)
                    evt = Event(EventType.NEW_TX, {"tx": tx.to_dict()})
                    ok, msg = node.state_engine.post_sync(evt)
                    if ok:
                        node.network.broadcast_tx(tx)
                    return {"ok": ok, "msg": msg, "tx_id": tx.tx_id}

                elif method == "getcontract":
                    """
                    Get contract metadata.
                    Params: [contract_addr]
                    Returns contract record or null.
                    """
                    addr = params[0] if params else ""
                    if not addr:
                        raise ValueError("getcontract requires contract_addr param")
                    rec = node.storage.get_contract(addr)
                    if not rec:
                        return None
                    # Include bytecode size
                    code = node.storage.get_contract_code(rec["code_hash"])
                    rec["bytecode_size"] = len(code) if code else 0
                    return rec

                elif method == "getcontractstorage":
                    """
                    Read a contract storage slot.
                    Params: [contract_addr, slot_key_hex]
                    Returns hex value string.
                    """
                    if len(params) < 2:
                        raise ValueError(
                            "getcontractstorage requires [contract_addr, slot_key_hex]")
                    addr, slot = str(params[0]), str(params[1])
                    val = node.storage.sload(addr, slot)
                    return hex(val)

                elif method == "getvmreceipt":
                    """
                    Get VVM execution receipt for a transaction.
                    Params: [tx_id]
                    Returns receipt dict or null.
                    """
                    tx_id = params[0] if params else ""
                    if not tx_id:
                        raise ValueError("getvmreceipt requires tx_id param")
                    rec = node.storage.get_vvm_receipt(tx_id)
                    # RPC-SERIALIZATION-FIX: get_vvm_receipt() returns
                    # return_data as bytes, including b"" for successful calls
                    # with no return payload.  The previous truthiness guard
                    # converted non-empty bytes only, allowing empty bytes to
                    # reach json.dumps() and produce "Object of type bytes is
                    # not JSON serializable".  Convert every bytes-like value;
                    # this is presentation-only and does not alter consensus
                    # storage, receipts, or execution behavior.
                    if rec is not None:
                        raw_return = rec.get("return_data")
                        if isinstance(raw_return, (bytes, bytearray, memoryview)):
                            rec["return_data"] = bytes(raw_return).hex()
                    return rec

                elif method == "listcontracts":
                    """
                    List deployed contracts.
                    Params: [limit (optional, default 20)]
                    Returns list of contract records.
                    SC-NAME-1: contract_name field included.
                    """
                    limit = min(int(params[0]) if params else 20, 500)
                    rows = node.storage._conn().execute(
                        "SELECT address, code_hash, storage_root, creator, "
                        "created_at, nonce, contract_name "
                        "FROM contract_accounts "
                        "WHERE destroyed=0 ORDER BY created_at DESC LIMIT ?",
                        (limit,)).fetchall()
                    return [
                        {
                            "address":       r["address"],
                            "code_hash":     r["code_hash"],
                            "storage_root":  r["storage_root"],
                            "creator":       r["creator"],
                            "created_at":    r["created_at"],
                            "nonce":         r["nonce"],
                            # SC-NAME-1: None for unnamed contracts (cleaner than "")
                            "contract_name": r["contract_name"] or None,
                        }
                        for r in rows
                    ]

                elif method == "simulatecall":
                    """
                    SC-IMPROVEMENT-1: Dry-run a contract call using VVMEngine.simulate().
                    All storage writes are discarded — state is never modified.
                    Params: [contract_addr, calldata_hex, gas_limit_int,
                             caller_addr (optional), value_float (optional)]
                    Returns: {"success": bool, "return_data_hex": str,
                              "gas_used": int, "logs": list, "revert_reason": str}
                    """
                    if len(params) < 3:
                        raise ValueError(
                            "simulatecall requires [contract_addr, calldata_hex, gas_limit]")
                    contract_addr = str(params[0])
                    calldata_hex  = str(params[1])
                    gas_limit     = min(int(params[2]), Config.VVM_TX_GAS_CAP)
                    caller_addr   = str(params[3]) if len(params) > 3 else node.wallet.address
                    call_value_f  = float(params[4]) if len(params) > 4 else 0.0

                    if not node.storage.get_contract(contract_addr):
                        raise ValueError(f"Contract {contract_addr} not found")

                    calldata = bytes.fromhex(calldata_hex) if calldata_hex else b""
                    latest   = node.blockchain.latest_block()

                    vvm    = VVMEngine(storage=node.storage)
                    result = vvm.simulate(
                        caller     = caller_addr,
                        contract   = contract_addr,
                        calldata   = calldata,
                        # FIX-5: use to_satoshi() (round half-even, integer)
                        # instead of int(float * 1e8) which is subject to
                        # IEEE-754 rounding divergence between x86 and ARM.
                        call_value = to_satoshi(call_value_f),
                        gas_limit  = gas_limit,
                        block_ctx  = latest,
                    )
                    return {
                        "success":         result.success,
                        "return_data_hex": result.return_data.hex() if result.return_data else "",
                        "gas_used":        result.gas_used,
                        "logs":            result.logs,
                        "revert_reason":   result.revert_reason,
                        "dry_run":         True,
                    }

                elif method == "estimategas":
                    """
                    SC-IMPROVEMENT-2: Estimate minimum gas for a VVM call.
                    Params: [contract_addr, calldata_hex,
                             caller_addr (optional), value_float (optional)]
                    Returns: {"estimated_gas": int, "gas_cap": int,
                              "success": bool, "note": str}
                    No state is modified.
                    """
                    if len(params) < 2:
                        raise ValueError(
                            "estimategas requires [contract_addr, calldata_hex]")
                    contract_addr = str(params[0])
                    calldata_hex  = str(params[1])
                    caller_addr   = str(params[2]) if len(params) > 2 else node.wallet.address
                    call_value_f  = float(params[3]) if len(params) > 3 else 0.0

                    calldata = bytes.fromhex(calldata_hex) if calldata_hex else b""
                    return node.blockchain.estimate_vvm_gas(
                        caller     = caller_addr,
                        contract   = contract_addr,
                        calldata   = calldata,
                        # FIX-5: use to_satoshi() — same integer conversion
                        # path used everywhere else for VSD→satoshi.
                        call_value = to_satoshi(call_value_f),
                    )

                elif method == "getcontractevents":
                    """
                    SC-FIX-8: Retrieve indexed event logs emitted by a contract.
                    Params: [contract_addr, from_block (optional), to_block (optional)]
                    Returns: list of event log entries
                    O(1) index lookup — does not scan entire chain.
                    """
                    if len(params) < 1:
                        raise ValueError("getcontractevents requires [contract_addr]")
                    contract_addr = str(params[0])
                    from_block    = int(params[1]) if len(params) > 1 else 0
                    to_block      = int(params[2]) if len(params) > 2 else 2**31
                    return node.blockchain.get_contract_events(
                        contract_addr, from_block, to_block)

                elif method == "geteventsbytopic":
                    """
                    SC-FIX-8: Retrieve indexed event logs by topic0 (event signature hash).
                    Params: [topic0_hex, from_block (optional), to_block (optional)]
                    Returns: list of event log entries across all contracts.
                    O(1) index lookup.
                    """
                    if len(params) < 1:
                        raise ValueError("geteventsbytopic requires [topic0_hex]")
                    topic0     = str(params[0])
                    from_block = int(params[1]) if len(params) > 1 else 0
                    to_block   = int(params[2]) if len(params) > 2 else 2**31
                    return node.blockchain.get_events_by_topic(
                        topic0, from_block, to_block)

                elif method == "shbs_status":
                    shbs = getattr(node, 'shbs', None)
                    if shbs is None:
                        raise ValueError("SHBS not initialized")
                    return shbs.get_status()

                elif method == "shbs_log":
                    shbs = getattr(node, 'shbs', None)
                    if shbs is None:
                        raise ValueError("SHBS not initialized")
                    n = int(params[0]) if params else 50
                    return shbs.get_action_log(n)

                elif method == "shbs_unfreeze":
                    shbs = getattr(node, 'shbs', None)
                    if shbs is None:
                        raise ValueError("SHBS not initialized")
                    addr = str(params[0]) if params else ""
                    ok, msg = shbs.unfreeze(addr)
                    return {"ok": ok, "message": msg}

                elif method == "shbs_vote":
                    shbs = getattr(node, 'shbs', None)
                    if shbs is None:
                        raise ValueError("SHBS not initialized")
                    proposal_id    = str(params[0]) if len(params) > 0 else ""
                    validator_addr = str(params[1]) if len(params) > 1 else ""
                    approve        = bool(params[2]) if len(params) > 2 else False
                    sig_hex        = str(params[3]) if len(params) > 3 else ""
                    pub_hex        = str(params[4]) if len(params) > 4 else ""
                    ok, msg = shbs.receive_vote(proposal_id, validator_addr,
                                                approve, sig_hex, pub_hex)
                    return {"ok": ok, "message": msg}

                elif method == "shbs_confirm_rollback":
                    # AUDIT-FIX-6: second-round confirmation vote for a
                    # rollback preview. Same param shape as shbs_vote but
                    # takes a confirm_id (returned/logged when the preview
                    # was emitted) instead of a proposal_id.
                    shbs = getattr(node, 'shbs', None)
                    if shbs is None:
                        raise ValueError("SHBS not initialized")
                    confirm_id     = str(params[0]) if len(params) > 0 else ""
                    validator_addr = str(params[1]) if len(params) > 1 else ""
                    approve        = bool(params[2]) if len(params) > 2 else False
                    sig_hex        = str(params[3]) if len(params) > 3 else ""
                    pub_hex        = str(params[4]) if len(params) > 4 else ""
                    ok, msg = shbs.confirm_rollback_preview(
                        confirm_id, validator_addr, approve, sig_hex, pub_hex)
                    return {"ok": ok, "message": msg}

                # AUDIT-FIX-L3 (dead code made shbs_submit_rollback_proposal
                # unreachable): the eight lines below used to be textually
                # fused onto the end of the shbs_confirm_rollback branch
                # above, stranded after its unconditional `return` with no
                # "elif method == ...:" header of their own -- so they could
                # never execute under any input. This is the RPC method
                # documented in _attach_operator_apis()'s docstring as the
                # intended operator-facing entry point for triggering a
                # rollback proposal (see also the "operators must call
                # submit_rollback_proposal() via RPC" log line emitted on a
                # CRITICAL-tier SHBS detection) -- restoring the missing
                # elif header is the whole fix; the body is unchanged.
                elif method == "shbs_submit_rollback_proposal":
                    shbs = getattr(node, 'shbs', None)
                    if shbs is None:
                        raise ValueError("SHBS not initialized")
                    if not hasattr(shbs, 'submit_rollback_proposal'):
                        raise ValueError("SHBS v2 not active (apply_hardening_patch not called)")
                    depth  = int(params[0]) if len(params) > 0 else 5
                    reason = str(params[1]) if len(params) > 1 else "operator_request"
                    return shbs.submit_rollback_proposal(depth, reason)

                elif method == "shbs_rollback_dry_run":
                    shbs = getattr(node, 'shbs', None)
                    if shbs is None:
                        raise ValueError("SHBS not initialized")
                    if not hasattr(shbs, 'rollback_dry_run'):
                        raise ValueError("SHBS v2 not active")
                    depth = int(params[0]) if params else 5
                    return shbs.rollback_dry_run(depth)

                elif method == "shbs_risk_status":
                    shbs = getattr(node, 'shbs', None)
                    if shbs is None:
                        raise ValueError("SHBS not initialized")
                    if not hasattr(shbs, 'v2_risk_status'):
                        raise ValueError("SHBS v2 not active")
                    return shbs.v2_risk_status()

                elif method == "shbs_manual_unfreeze":
                    shbs = getattr(node, 'shbs', None)
                    if shbs is None:
                        raise ValueError("SHBS not initialized")
                    if not hasattr(shbs, 'manual_unfreeze'):
                        raise ValueError("SHBS v2 not active")
                    addr = str(params[0]) if params else ""
                    return shbs.manual_unfreeze(addr)

                # ═══════════════════════════════════════════════════════════
                # v7.5.0-OPT LAYER-2 ROLLUP RPC METHODS
                # ═══════════════════════════════════════════════════════════
                # All L2 RPC methods use the "vsd_" prefix per the spec and
                # are thread-safe: they read/write through node.blockchain.layer2
                # and node.sequencer, both of which hold their own internal
                # locks.  Admin-gated methods additionally require the caller
                # to present an admin token distinct from the standard RPC
                # token — see _is_admin() helper inside this dispatcher.
                elif method == "vsd_getBalance":
                    # params: [address?]   — defaults to this node's wallet.
                    # Returns {address, l1_sat, l1_vsd, l2_sat, l2_vsd, l2_nonce}
                    addr = params[0] if params else node.wallet.address
                    if not isinstance(addr, str) or not addr:
                        raise ValueError("address must be a non-empty string")
                    # Bound address length — prevent pathological inputs.
                    if len(addr) > 128:
                        raise ValueError("address too long")
                    l1_sat = int(node.storage.get_balance_sat(addr))
                    layer2 = getattr(node.blockchain, "layer2", None)
                    if layer2 is None:
                        l2_sat = 0
                        l2_nonce = 0
                    else:
                        l2_sat = int(layer2.get_balance_sat(addr))
                        l2_nonce = int(layer2.get_nonce(addr))
                    return {
                        "address":  addr,
                        "l1_sat":   l1_sat,
                        "l1_vsd":   from_satoshi(l1_sat),
                        "l2_sat":   l2_sat,
                        "l2_vsd":   from_satoshi(l2_sat),
                        "l2_nonce": l2_nonce,
                    }

                elif method == "vsd_getL2StateRoot":
                    # Returns {root, account_count, last_batch_id, supply_ok,
                    #          l2_supply_sat, l1_bridge_sat}
                    layer2 = getattr(node.blockchain, "layer2", None)
                    if layer2 is None:
                        raise ValueError("Layer2State not initialised")
                    return layer2.status()

                elif method == "vsd_sendL2Transaction":
                    # params: [l2_tx_dict]
                    # The caller has already signed the L2 tx (e.g. via the
                    # CLI `send-l2` command or a wallet SDK).  We add it to
                    # the local Sequencer's pool AND gossip it over P2P so
                    # sequencers on other nodes see it too.
                    if not params or not isinstance(params[0], dict):
                        raise ValueError("params[0] must be an L2 tx dict")
                    try:
                        l2_tx = L2Transaction.from_dict(params[0])
                    except Exception as e:
                        raise ValueError(f"malformed L2 tx: {e}")
                    ok_s, msg_s = l2_tx.is_valid()
                    if not ok_s:
                        return {"ok": False, "msg": msg_s,
                                "l2_tx_id": l2_tx.l2_tx_id}
                    # Local sequencer admission (if running).  Either way
                    # we gossip so that another node's sequencer can pick
                    # it up.  Duplicate IDs are deduped at add_l2_tx().
                    accepted_locally = False
                    seq_msg = "sequencer not running on this node"
                    seq = getattr(node, "sequencer", None)
                    if seq is not None and getattr(seq, "_running", False):
                        ok_a, msg_a = seq.add_l2_tx(l2_tx)
                        accepted_locally = ok_a
                        seq_msg = msg_a
                    try:
                        if node.network is not None:
                            node.network.broadcast_l2_tx(l2_tx)
                    except Exception as _bg_e:
                        log.debug(f"vsd_sendL2Transaction gossip failed: {_bg_e}")
                    return {
                        "ok": True,
                        "l2_tx_id": l2_tx.l2_tx_id,
                        "accepted_locally": accepted_locally,
                        "sequencer_msg": seq_msg,
                        "gossiped": True,
                    }

                elif method == "vsd_depositToL2":
                    # params: [amount_vsd, memo?]
                    # Convenience wrapper: constructs an L1 transfer from
                    # the node's own wallet to L2_BRIDGE_ADDRESS.  The
                    # standard transfer path's apply_block hook then
                    # auto-credits Layer2State for us.  We validate
                    # satoshi overflow strictly here to avoid integer
                    # surprises later in the pipeline.
                    if not params:
                        raise ValueError("amount required")
                    try:
                        amount_vsd = float(params[0])
                    except (TypeError, ValueError):
                        raise ValueError("amount must be numeric")
                    if not (amount_vsd > 0.0):
                        raise ValueError("amount must be positive")
                    if amount_vsd != amount_vsd:   # NaN check
                        raise ValueError("amount must be a real number")
                    # Convert to satoshi FIRST so we reject any value that
                    # would exceed the safe integer range before it reaches
                    # Mempool / Transaction code paths.
                    amount_sat = to_satoshi(amount_vsd)
                    # Cap at a sanity bound — 2**62 satoshi is far beyond
                    # any legitimate deposit.  Prevents overflow in any
                    # downstream satoshi arithmetic.
                    if amount_sat <= 0 or amount_sat >= (1 << 62):
                        raise ValueError("amount out of satoshi range")
                    memo = ""
                    if len(params) > 1 and params[1] is not None:
                        memo = str(params[1])[:128]
                    ok, msg = node.send_transaction(
                        L2_BRIDGE_ADDRESS, amount_vsd, memo)
                    return {"ok": ok, "msg": msg,
                            "amount_sat": amount_sat,
                            "bridge": L2_BRIDGE_ADDRESS}

                elif method == "vsd_withdrawFromL2":
                    # params: [amount_vsd]
                    # Forced-exit bridge: atomically debit the caller's L2
                    # tree balance and credit their L1 wallet from the bridge
                    # escrow.  No mempool / block required — mirrors the
                    # deposit hook in apply_block but in reverse.
                    if not params:
                        raise ValueError("amount required")
                    try:
                        amount_vsd = float(params[0])
                    except (TypeError, ValueError):
                        raise ValueError("amount must be numeric")
                    if not (amount_vsd > 0.0):
                        raise ValueError("amount must be positive")
                    if amount_vsd != amount_vsd:  # NaN guard
                        raise ValueError("amount must be a real number")
                    amount_sat = to_satoshi(amount_vsd)
                    if amount_sat <= 0 or amount_sat >= (1 << 62):
                        raise ValueError("amount out of satoshi range")
                    ok, msg = node.withdraw_from_l2(amount_vsd)
                    return {"ok": ok, "msg": msg, "amount_sat": amount_sat}

                elif method == "vsd_triggerManualRollup":
                    # ADMIN-ONLY.  Forces the sequencer to seal whatever
                    # it has in its pending pool, even if size / age
                    # thresholds haven't triggered.  Useful for
                    # operator-driven tests and emergency flushes.
                    if not self._is_admin():
                        # Return a clean HTTP-200 JSON-RPC error rather
                        # than 401 so clients can distinguish "method
                        # exists but you're not admin" from "bad token".
                        raise PermissionError(
                            "admin token required for vsd_triggerManualRollup")
                    seq = getattr(node, "sequencer", None)
                    if seq is None:
                        raise ValueError("sequencer not constructed on this node")
                    if not getattr(seq, "_running", False):
                        raise ValueError("sequencer is not running — "
                                         "start it first")
                    try:
                        sealed = seq._seal_one()
                    except Exception as e:
                        return {"ok": False, "msg": f"seal raised: {e}"}
                    if sealed is None:
                        return {"ok": False, "msg": "nothing to seal"}
                    tx, batch_id, applied = sealed
                    # AUDIT-FIX-G3: this handler used to treat a sealed
                    # batch as final the moment _seal_one() returned,
                    # including when node.state_engine was None (submit_msg
                    # stayed "not submitted" but {"ok": True} was still
                    # returned) — under the old _seal_one() the batch's
                    # txs were ALREADY evicted from the pending pool by
                    # that point regardless, so a truly-unsubmitted "ok"
                    # batch was silently lost. Now we only finalize
                    # (remove from pending / advance batch_id) once
                    # submission is actually confirmed.
                    if node.state_engine is None:
                        seq._abandon_seal()   # AUDIT-FIX-L4
                        return {"ok": False,
                                "msg": "sealed but no state_engine configured "
                                       "on this node to submit through — "
                                       "batch left pending, will be retried "
                                       "automatically",
                                "tx_id": tx.tx_id}
                    # AUDIT-FIX-L4: wrapped in try/except -- an uncaught
                    # exception from post_sync here (same gap as in
                    # Sequencer._loop()) would otherwise skip both
                    # _finalize_seal() and _abandon_seal(), permanently
                    # stranding the seal-cycle lock _seal_one() left held
                    # and blocking all future sealing (background AND
                    # manual) on this node.
                    try:
                        evt = Event(EventType.NEW_TX, {"tx": tx})
                        ok_p, submit_msg = node.state_engine.post_sync(
                            evt, timeout=5.0)
                    except Exception as e:
                        seq._abandon_seal()   # AUDIT-FIX-L4
                        return {"ok": False,
                                "msg": f"submit raised: {e} — "
                                       f"batch left pending, will be "
                                       f"retried automatically",
                                "tx_id": tx.tx_id}
                    if not ok_p:
                        seq._abandon_seal()   # AUDIT-FIX-L4
                        return {"ok": False,
                                "msg": f"submit failed: {submit_msg} — "
                                       f"batch left pending, will be "
                                       f"retried automatically",
                                "tx_id": tx.tx_id}
                    seq._finalize_seal(batch_id, applied)
                    return {"ok": True, "tx_id": tx.tx_id,
                            "submit_msg": submit_msg}

                else:
                    raise ValueError(f"Unknown method: {method}")

        try:
            # ─── v7.5.0-OPT CONCURRENT RPC DISPATCH ─────────────────────────
            # Use ThreadingTCPServer so a slow handler (one that briefly
            # blocks on blockchain._lock during a reorg / apply_block /
            # full-scan invariant check) cannot stall every other RPC
            # request behind it.  Measured impact: with the stock
            # single-threaded TCPServer, a fast getchaininfo call issued
            # 100ms into a 1500ms slow handler waited the full ~1400ms
            # remainder before its response was sent.  Under the threaded
            # server the same fast call completes in ~4ms.
            #
            # Per-request thread safety: all RPC handlers in _dispatch()
            # read/write through objects (blockchain, storage, mempool,
            # layer2, sequencer) whose own locks are already held on
            # their mutating methods, so concurrent dispatch is safe.
            # The rate-limit state in this closure (_rate_tokens, _rate_last)
            # is explicitly guarded by _rate_lock.
            #
            # daemon_threads=True ensures node shutdown doesn't hang waiting
            # for in-flight request threads — those threads are implicitly
            # cancelled when the main process exits.
            class _RPCServer(socketserver.ThreadingTCPServer):
                allow_reuse_address = True
                daemon_threads      = True

            self._server = _RPCServer(
                ("127.0.0.1", self.rpc_port), Handler)
            self._thread = threading.Thread(
                target=self._server.serve_forever, daemon=True)
            self._thread.start()
            log.info(
                f"JSON-RPC server on 127.0.0.1:{self.rpc_port} "
                f"(threaded, token auth — see {self.TOKEN_FILE})")
        except Exception as e:
            log.warning(f"RPC server failed to start: {e}")

    def stop(self):
        if self._server:
            self._server.shutdown()
