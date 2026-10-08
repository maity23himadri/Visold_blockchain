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
"""visold.state.engine


Defines: StateEngine
Origin: visold_vsd_.py L7151-7987
"""

import queue
import threading
import time
import concurrent.futures as _futures
from typing import Any, Dict, List, Optional, TYPE_CHECKING, Tuple

from visold.kernel.config import Config
from visold.kernel.events import Event, EventType
from visold.kernel.logging_setup import log
from visold.kernel.messages import MSG_VALIDATOR_SIG
from visold.kernel.metrics import metrics
from visold.kernel.notifications import _push_block_notif
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.chain.blockchain import Blockchain
    from visold.governance.engine import GovernanceEngine
    from visold.network.p2p import P2PNetwork
    from visold.resilience.panic_breaker import PanicCircuitBreaker
    from visold.resilience.safety_invariants import SafetyInvariantChecker
    from visold.storage.state_pruner import StatePruner
    from visold.storage.storage import Storage


class StateEngine:
    """
    The SINGLE WRITER for all Visold chain state.

    ═══════════════════════════════════════════════════════════════════════════
    Architecture
    ────────────
    The StateEngine owns a bounded FIFO queue.  All subsystems that need to
    modify chain state (mining, networking, CLI, RPC) post Event objects to
    this queue.  A single background thread drains the queue and processes
    events one at a time.

    Because only ONE thread ever calls blockchain.apply_block(),
    blockchain.mempool.add(), or any other state-mutating method, there is:
      • No need for the Blockchain._lock in hot paths (it stays for safety)
      • No possible double-spend via concurrent validation
      • No partial state updates (validation and application are atomic)
      • Deterministic replay: the same event sequence → the same final state

    ═══════════════════════════════════════════════════════════════════════════
    Posting events
    ──────────────
    Non-blocking post (fire-and-forget):
        engine.post(Event(EventType.NEW_TX, {"tx": tx}))

    Blocking post (wait for result, used by CLI / RPC):
        ok, msg = engine.post_sync(Event(EventType.NEW_TX, {"tx": tx}))

    ═══════════════════════════════════════════════════════════════════════════
    Event handlers
    ──────────────
    NEW_TX        → mempool.add(tx); if ok, network.broadcast_tx(tx)
    NEW_BLOCK     → validate_block + apply_block; if ok, broadcast
    MINE_RESULT   → validate_block + apply_block; if ok, broadcast + finalize
    VALIDATOR_SIG → blockchain.add_validator_sig; if ok, broadcast
    CHAIN_SYNC    → blockchain.accept_chain
    TIMER         → mempool pruning, metrics update
    STOP          → set stop flag, drain remaining events

    ═══════════════════════════════════════════════════════════════════════════
    Back-pressure
    ─────────────
    The queue is bounded at STATE_ENGINE_QUEUE_SIZE.  Callers that post to a
    full queue will block (queue.Queue default behaviour).  Mining and network
    threads should use a non-blocking post with a timeout so they can detect
    a stuck StateEngine and log a warning without deadlocking.
    """

    def __init__(self, blockchain: 'Blockchain',
                 governance: 'GovernanceEngine',
                 storage: 'Storage'):
        self._blockchain  = blockchain
        self._governance  = governance
        self._storage     = storage
        self._network: Optional['P2PNetwork'] = None  # set after network starts
        self._queue: queue.Queue = queue.Queue(
            maxsize=Config.STATE_ENGINE_QUEUE_SIZE)
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._stop_evt = threading.Event()
        # Fix #12: invariant checker injected by VisoldNode after construction
        self._invariant_checker: Optional['SafetyInvariantChecker'] = None
        # NEW: Circuit breaker — injected by VisoldNode; gates write events
        self._circuit_breaker: Optional['PanicCircuitBreaker'] = None
        # _circuit_breaker_tripped mirrors circuit_breaker.is_open as a fast
        # local flag so post() can check it without acquiring the breaker lock.
        # Updated by set_circuit_breaker() and whenever the breaker trips.
        self._circuit_breaker_tripped: bool = False
        # NEW: State pruner — injected by VisoldNode; called from timer
        self._state_pruner: Optional['StatePruner'] = None
        # _node_ref — injected by VisoldNode so block hooks can reach the node
        self._node_ref: Optional[Any] = None
        # BFT-FIX: validator signatures can arrive before their block through
        # independent gossip queues. Keep a small, expiring buffer and replay
        # only after the canonical block is applied; invalid signatures are
        # never buffered and remain subject to immediate cryptographic checks.
        self._pending_validator_sigs: List[Tuple[float, dict, str]] = []
        self._pending_validator_sigs_lock = threading.Lock()
        self.MAX_PENDING_VALIDATOR_SIGS = 512
        self.PENDING_VALIDATOR_SIG_TTL = 30.0
        # ─────────────────────────────────────────────────────────────────────
        # v7.1.8 BUG-FIX (Bug 3): Orphan-block pool.
        #
        # Before: a block whose index was > my_tip + 1 was discarded after
        # firing a single MSG_GET_CHAIN gap-fetch.  If the gap-fetch response
        # didn't include that exact tip block (e.g. server's own tip moved,
        # MSG_CHAIN page boundary, or the response itself dropped at the
        # StateEngine high-water), the block was lost forever — the source
        # peer had it cached in _seen_msgs and would not re-gossip for an
        # hour.  The node would then sit one block behind the network until
        # the NEXT mined block triggered another gap-fetch.
        #
        # Fix (Bitcoin-core orphan-pool pattern): when we see a block whose
        # parent we don't have, stash it in self._orphans keyed by prev_hash.
        # After every successful apply_block, drain any orphans whose
        # prev_hash matches the just-applied block's hash and feed them back
        # through _handle_new_block.  This makes mid-sync tip blocks
        # self-healing without requiring peer cooperation.
        #
        # Capacity is bounded so a malicious peer cannot OOM us by flooding
        # bogus future blocks.  Entries expire by simple FIFO eviction.
        # ─────────────────────────────────────────────────────────────────────
        self._orphans: Dict[str, dict] = {}        # prev_hash -> block_dict
        self._orphan_order: List[str] = []         # FIFO eviction order
        self._orphans_lock = threading.Lock()
        self.MAX_ORPHANS = 256                     # bounded — DoS-resistant

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def set_network(self, network: 'P2PNetwork'):
        """Inject network reference after construction (avoids circular deps)."""
        self._network = network

    def start(self):
        """Start the single-writer background thread."""
        self._running = True
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="state-engine")
        self._thread.start()
        log.info("StateEngine started — single-writer mode active")

    def stop(self):
        """Graceful shutdown: drain the queue then stop."""
        self._running = False
        # Post a STOP event to unblock the queue.get() if it is waiting
        try:
            self._queue.put_nowait(Event(EventType.STOP, {}))
        except queue.Full:
            pass
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=10)

    # ── Post API ──────────────────────────────────────────────────────────────

    # High-water mark: when queue exceeds this fraction of capacity,
    # network events are dropped to protect P2P handler threads (F-10 fix).
    _QUEUE_HIGH_WATER = 0.80

    def post(self, event: Event, timeout: Optional[float] = None) -> bool:
        """
        Post an event to the queue.
        F-10 FIX: Network-sourced events (source_peer_id != "") use put_nowait()
        so that P2P handler threads are NEVER blocked waiting for queue space.
        A blocked P2P thread cannot send PONG keepalives, causing all honest
        peers to mark the node as disconnected — a cross-layer DoS.
        Local events (CLI/RPC, timeout=provided) may still block with a timeout.
        """
        if self._circuit_breaker and self._circuit_breaker.is_open:
            if event.etype not in (EventType.TIMER, EventType.STOP):
                return False  # breaker open — drop state-mutating events

        try:
            # Network events: always non-blocking (drop rather than stall P2P)
            if event.source_peer_id:
                qsize = self._queue.qsize()
                if qsize > self._queue.maxsize * self._QUEUE_HIGH_WATER:
                    log.warning(
                        f"StateEngine high-water: queue {qsize}/{self._queue.maxsize} "
                        f"— dropping network {event.etype.value} from {event.source_peer_id[:12]}")
                    return False
                self._queue.put_nowait(event)
                return True
            # Local events (CLI / RPC): block with optional timeout
            if timeout is not None:
                self._queue.put(event, timeout=timeout)
            else:
                self._queue.put(event)
            return True
        except queue.Full:
            log.warning(
                f"StateEngine queue full — dropped {event.etype.value} event")
            return False


    def post_sync(self, event: Event,
                  timeout: Optional[float] = None) -> Tuple[bool, str]:
        """
        Post an event and BLOCK until it is processed.
        Returns (ok, message) from the handler.
        Used by CLI and RPC for synchronous responses.

        If the StateEngine is not running (e.g. during test setup), falls back
        to direct synchronous execution.
        """
        if not self._running:
            # Fallback: direct execution for tests / pre-start scenarios
            return self._dispatch_direct(event)

        t = timeout if timeout is not None else Config.STATE_ENGINE_SYNC_TIMEOUT
        fut: _futures.Future = _futures.Future()
        event.future = fut
        if not self.post(event, timeout=t):
            return False, "StateEngine queue full — try again later"
        try:
            result = fut.result(timeout=t)
            return result
        except _futures.TimeoutError:
            return False, "StateEngine timeout — node may be under heavy load"
        except Exception as e:
            return False, f"StateEngine error: {e}"

    def _dispatch_direct(self, event: Event) -> Tuple[bool, str]:
        """Synchronous fallback for tests / pre-start scenarios."""
        try:
            return self._handle(event)
        except Exception as e:
            return False, str(e)

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _run(self):
        """
        Fixed StateEngine Event Loop
        """
        _last_seq: int = 0
        while self._running:
            try:
                # Poll the queue for new events (blocks, txs, etc.)
                event = self._queue.get(timeout=1.0)
            except queue.Empty:
                # This keeps the engine alive even when no events are happening
                self._handle_timer()
                continue

            if event.etype == EventType.STOP:
                break

            # Global ordering audit
            if event.global_seq <= _last_seq:
                log.warning(f"StateEngine: out-of-order event {event.global_seq}")
            _last_seq = event.global_seq

            try:
                result = self._handle(event)
            except Exception as exc:
                log.error(f"StateEngine error: {exc}", exc_info=True)
                result = (False, str(exc))
            finally:
                if event.future is not None and not event.future.done():
                    event.future.set_result(result)
                self._queue.task_done()

    def _handle(self, event: Event) -> Tuple[bool, str]:
        """Dispatch a single event. Called only from the engine thread."""
        et = event.etype
        pl = event.payload

        # ── Circuit breaker: gate state-mutating events ────────────────────
        # Read-only events (TIMER, STOP) bypass the circuit breaker.
        # Write events (NEW_TX, NEW_BLOCK, MINE_RESULT, VALIDATOR_SIG,
        # CHAIN_SYNC) are blocked when the breaker is OPEN.
        if self._circuit_breaker and self._circuit_breaker.is_open:
            write_events = {EventType.NEW_TX, EventType.NEW_BLOCK,
                            EventType.MINE_RESULT, EventType.VALIDATOR_SIG,
                            EventType.CHAIN_SYNC}
            if et in write_events:
                ok, reason = self._circuit_breaker.check_allows_write()
                return False, reason

        if et == EventType.NEW_TX:
            return self._handle_new_tx(pl, event.source_peer_id)

        elif et == EventType.NEW_BLOCK:
            return self._handle_new_block(pl, event.source_peer_id)

        elif et == EventType.MINE_RESULT:
            return self._handle_mine_result(pl)

        elif et == EventType.VALIDATOR_SIG:
            return self._handle_validator_sig(pl, event.source_peer_id)

        elif et == EventType.CHAIN_SYNC:
            return self._handle_chain_sync(pl, event.source_peer_id)

        elif et == EventType.TIMER:
            self._handle_timer()
            return True, "timer"

        elif et == EventType.STOP:
            return True, "stop"

        return False, f"Unknown event type: {et}"

    # ── Event handlers — all run on the engine thread, no concurrent writes ──

    def _handle_new_tx(self, payload: dict,
                       source_peer: str) -> Tuple[bool, str]:
        """
        Validate and add a transaction to the mempool.
        Source may be local (CLI/RPC) or remote (P2P).
        """
        try:
            tx_data = payload.get("tx")
            if tx_data is None:
                return False, "Missing tx in payload"
            # Accept pre-built Transaction objects or dict
            if isinstance(tx_data, dict):
                tx = Transaction.from_dict(tx_data)
            else:
                tx = tx_data  # already a Transaction

            ok, msg = self._blockchain.mempool.add(tx)
            if ok and self._network and not source_peer:
                # Only broadcast if transaction originated locally
                self._network.broadcast_tx(tx)
                metrics.inc("transactions_sent")
            elif ok and self._network and source_peer:
                # Relay to other peers (gossip), not back to sender
                msg_out = {"type": "TX", "tx": tx.to_dict(),
                           "ttl": Config.GOSSIP_TTL}
                self._network._gossip(msg_out, exclude=source_peer)
            return ok, msg
        except Exception as e:
            return False, f"new_tx error: {e}"

    # ── Orphan-pool helpers (v7.1.8 — Bug 3 fix) ──────────────────────────
    def _stash_orphan(self, block: 'Block', block_data: dict) -> None:
        """Buffer a block whose parent we don't have yet.  Bounded FIFO."""
        with self._orphans_lock:
            key = block.prev_hash
            if key in self._orphans:
                return                              # already stashed
            if len(self._orphan_order) >= self.MAX_ORPHANS:
                evict = self._orphan_order.pop(0)
                self._orphans.pop(evict, None)
            self._orphans[key] = block_data
            self._orphan_order.append(key)
        log.info(
            f"[ORPHAN] Stashed block #{block.index} "
            f"({block.block_hash[:12]}…) waiting for parent "
            f"{block.prev_hash[:12]}…  (pool size: {len(self._orphan_order)})")

    def _drain_orphans_for(self, parent_hash: str,
                           source_peer: str) -> None:
        """Re-process any orphans that chain (via prev_hash) from ``parent_hash``.

        AUDIT-FIX-J1: this previously called self._handle_new_block()
        recursively — once per link in the orphan chain — via plain Python
        function calls, not the event queue. That consumed Python stack
        frames per link with no matching sys.setrecursionlimit() override
        anywhere in this file (confirmed absent). A chain approaching
        MAX_ORPHANS (256) could reach the interpreter's default recursion
        limit; the resulting RecursionError was silently swallowed by
        _handle_new_block's own `except Exception`, permanently losing
        the orphan that was mid-flight (already popped from self._orphans
        before the failing call) and stranding every orphan deeper in the
        chain, since the block that would have unlocked them was gone.
        Rewritten as an explicit work-list processed in a single stack
        frame, so drain depth no longer depends on chain length.
        """
        pending: List[str] = [parent_hash]
        while pending:
            key = pending.pop()
            with self._orphans_lock:
                child_data = self._orphans.pop(key, None)
                if child_data is not None:
                    try:
                        self._orphan_order.remove(key)
                    except ValueError:
                        pass
            if child_data is None:
                continue
            log.info(
                f"[ORPHAN] Parent {key[:12]}… now applied — "
                f"replaying buffered child block")
            # _drain=False: this call must NOT itself recurse into
            # _drain_orphans_for — this loop already owns draining the
            # whole chain iteratively; queue the child's own hash below
            # instead so any orphans waiting on IT get picked up next.
            ok, _msg = self._handle_new_block(
                {"block": child_data}, source_peer, _drain=False)
            if ok:
                try:
                    child_block = Block.from_dict(child_data)
                    pending.append(child_block.block_hash)
                except Exception:
                    # child_data just round-tripped through
                    # _handle_new_block successfully, so this parse
                    # should not fail — but if it somehow does, there is
                    # nothing further to drain from this branch, not a
                    # reason to raise out of the drain loop.
                    pass

    def _handle_new_block(self, payload: dict,
                          source_peer: str,
                          _drain: bool = True) -> Tuple[bool, str]:
        """
        Validate and apply a block received from the network.
        On success, gossip to other peers.

        v7.1.8 changes (Bug 2 + Bug 3):
          • Blocks with index > tip+1 (or whose parent is genuinely missing)
            are now stashed in the orphan pool keyed by prev_hash, so they
            self-heal as soon as the missing parent arrives — no longer
            silently discarded.
          • If apply_block fails with "Previous block not found", we treat
            it as a transient gap (orphan) rather than a fatal validation
            failure, request the gap, and leave the block in the pool.

        AUDIT-FIX-J1: added the internal-only ``_drain`` parameter. It
        defaults to True for normal callers (the event dispatcher,
        _handle_mine_result). _drain_orphans_for's own iterative loop
        passes _drain=False when replaying a stashed orphan, so this
        method never triggers a nested drain of its own — see
        _drain_orphans_for for why that recursion was a bug.
        """
        try:
            block_data = payload.get("block")
            if block_data is None:
                return False, "Missing block in payload"
            if isinstance(block_data, dict):
                block = Block.from_dict(block_data)
                _block_dict_for_orphan = block_data
            else:
                block = block_data
                _block_dict_for_orphan = block.to_dict()

            # ── Gap detection ────────────────────────────────────────────────
            # If incoming block is more than 1 ahead of our tip, request the
            # missing range AND stash this block so it isn't lost if the
            # gap-fetch response doesn't include the tip.
            my_tip = self._blockchain.height()
            if block.index > my_tip + 1 and source_peer and self._network:
                with self._network._lock:
                    gap_peer = self._network.peers.get(source_peer)
                if gap_peer and gap_peer.connected:
                    self._network._sync_request(
                        gap_peer, my_tip + 1, block.index,
                        kind="gap", force=False)
                    log.debug(
                        f"Gap detected: our tip={my_tip}, incoming block "
                        f"#{block.index} — requested blocks "
                        f"{my_tip+1}..{block.index} from {source_peer[:12]}")
                # v7.1.8 Bug 3: stash so we don't lose the tip block if the
                # gap-fetch response is partial / dropped.
                self._stash_orphan(block, _block_dict_for_orphan)
                return False, (
                    f"Gap: missing blocks {my_tip+1}..{block.index-1}; "
                    f"requested from peer; tip block stashed")

            # SAME-HEIGHT FORK FIX: if this height already contains a
            # different hash, do not apply the candidate directly to live
            # state. Route the candidate plus its known parent through
            # accept_chain(), which performs common-ancestor detection,
            # cumulative-work comparison, finality checks, and reorg.
            _existing_at_height = self._storage.get_block(block.index)
            if (_existing_at_height is not None
                    and _existing_at_height.block_hash != block.block_hash):
                # A single stale candidate below our current tip cannot win
                # a fork choice; it is a harmless late relay, not an apply
                # failure. Same-height candidates still go through reorg.
                if block.index < self._blockchain.height():
                    self._storage.record_block_apply_result(block.index, True)
                    return True, "Stale conflicting block ignored; higher tip retained"
                _parent = self._storage.get_block(block.index - 1)
                if _parent is not None and _parent.block_hash == block.prev_hash:
                    _fork_ok, _fork_msg = self._blockchain.accept_chain([_parent, block])
                    # A same-height candidate can legitimately lose the
                    # cumulative-work/tip-hash fork choice. That is not a
                    # failed application and must not poison block_apply:*.
                    if (not _fork_ok
                            and not _fork_msg.startswith("Reorg apply block")):
                        _fork_ok = True
                        _fork_msg = (
                            "Fork candidate rejected by deterministic fork choice; "
                            f"local chain retained ({_fork_msg})")
                    self._storage.record_block_apply_result(block.index, _fork_ok)
                    return _fork_ok, _fork_msg
                return False, (
                    f"Conflicting block {block.index} has no matching local "
                    f"parent; request the peer chain for fork resolution")

            # Shadow validation (pre-activation compatibility check)
            warnings = self._governance.shadow_validate(block)
            for w in warnings:
                log.warning(w)

            ok, msg = self._blockchain.apply_block(block)
            self._storage.record_block_apply_result(block.index, ok)

            # ── v7.1.8 Bug 2 fix: treat "Previous block not found" as a gap
            # rather than a hard reject.  Stash in orphan pool and request
            # the immediate parent so the chain heals automatically.
            if (not ok) and msg and "Previous block not found" in msg:
                self._stash_orphan(block, _block_dict_for_orphan)
                if source_peer and self._network:
                    try:
                        with self._network._lock:
                            gp = self._network.peers.get(source_peer)
                        if gp and gp.connected:
                            self._network._sync_request(
                                gp, max(1, block.index - 1), block.index - 1,
                                kind="gap-backfill", force=False)
                    except Exception:
                        pass
                return False, f"Stashed as orphan: {msg}"

            if ok:
                # Drive governance state machine
                self._governance.on_block_applied(block)
                # BFT-FIX: received blocks must trigger this node's local
                # consensus step as well as relay. The mining path already
                # invokes validate_and_finalize(), but received blocks used to
                # stop after apply_block(), so investor nodes never voted.
                try:
                    _consensus_ref = getattr(
                        getattr(self, "_node_ref", None), "consensus", None)
                    if _consensus_ref is not None:
                        _consensus_ref.validate_and_finalize(block)
                except Exception as _bft_vote_err:
                    # Voting is additive; never turn a valid received block
                    # into a transport failure because a local vote failed.
                    log.warning(
                        f"Received-block BFT vote failed for #{block.index}: "
                        f"{_bft_vote_err}")
                # RELAY-FIX: loud logging + never drop relay silently
                if self._network:
                    try:
                        peer_count = len([p for pid, p in self._network.peers.items()
                                          if p.connected and pid != source_peer])
                        _src = source_peer[:12] if source_peer else "unknown"
                        log.info(f"[RELAY] Block #{block.index} from {_src} -> relaying to {peer_count} other peer(s)")
                        # v7.5.0: broadcast_block now emits MSG_CMPCTBLOCK so
                        # peers with full mempools reconstruct without re-download.
                        # exclude= is honoured inside broadcast_block → _gossip.
                        self._network.broadcast_block(block, exclude=source_peer)
                    except Exception as _re:
                        log.error(f"[RELAY] relay FAILED for #{block.index}: {_re}", exc_info=True)
                else:
                    log.error(f"[RELAY] _network is None - block #{block.index} NOT relayed!")
                # v7.1.8 Bug 3: drain any orphans that were waiting for THIS
                # block as their parent. AUDIT-FIX-J1: only do this for a
                # top-level call (_drain=True) — when _handle_new_block is
                # itself being invoked BY the drain loop to replay a
                # stashed orphan, _drain is False and the loop in
                # _drain_orphans_for handles chaining to further orphans
                # itself, iteratively.
                if _drain:
                    self._drain_orphans_for(block.block_hash, source_peer)
                self._drain_pending_validator_sigs()
                self._rebroadcast_block_validator_sigs(block, source_peer)
                # ── SHBS: anomaly detection on received block ─────────────────
                try:
                    _shbs = getattr(getattr(self, '_node_ref', None), 'shbs', None)
                    if _shbs is not None and _shbs._running:
                        _shbs.on_block_applied(block)
                except Exception as _shbs_hook_err:
                    log.debug(f"[SHBS] on_block_applied hook error: {_shbs_hook_err}")
            return ok, msg
        except Exception as e:
            return False, f"new_block error: {e}"

    def _handle_mine_result(self, payload: dict) -> Tuple[bool, str]:
        """
        Apply a locally-mined block.
        The mining thread posts this event; it never touches state directly.
        """
        try:
            block = payload.get("block")
            if block is None:
                return False, "Missing block in mine_result"

            _existing_at_height = self._storage.get_block(block.index)
            if (_existing_at_height is not None
                    and _existing_at_height.block_hash != block.block_hash):
                if block.index < self._blockchain.height():
                    ok, msg = True, "Stale conflicting mined block ignored; higher tip retained"
                else:
                    _parent = self._storage.get_block(block.index - 1)
                    if _parent is not None and _parent.block_hash == block.prev_hash:
                        ok, msg = self._blockchain.accept_chain([_parent, block])
                        if (not ok and not msg.startswith("Reorg apply block")):
                            ok = True
                            msg = (
                                "Fork candidate rejected by deterministic fork choice; "
                                f"local chain retained ({msg})")
                    else:
                        ok, msg = False, (
                            f"Conflicting mined block {block.index} has no matching "
                            f"local parent")
            else:
                ok, msg = self._blockchain.apply_block(block)
            self._storage.record_block_apply_result(block.index, ok)

            if ok:
                self._governance.on_block_applied(block)
                metrics.inc("blocks_mined")
                # BROADCAST-FIX: loud logging + guard against silent failure
                if self._network:
                    try:
                        peer_count = len([p for p in self._network.peers.values() if p.connected])
                        log.info(f"[BROADCAST] Mined block #{block.index} -> broadcasting to {peer_count} peer(s)")
                        self._network.broadcast_block(block)
                    except Exception as _be:
                        log.error(f"[BROADCAST] broadcast_block FAILED for #{block.index}: {_be}", exc_info=True)
                else:
                    log.error(f"[BROADCAST] _network is None - block #{block.index} NOT broadcast!")
                # ── LIVE-UI: push instant local-mine notification ──────────────
                _push_block_notif(block.index, block.miner_address, source="local")
                # Trigger BFT validator sig if this node is an investor
                consensus_ref = payload.get("consensus")
                if consensus_ref:
                    consensus_ref.validate_and_finalize(block)
                # v7.1.8 Bug 3: also drain orphans whose parent is the
                # block we just mined (handles the rare case of a peer
                # tip block arriving while we were finalising our own).
                self._drain_orphans_for(block.block_hash, "")
                # ── SHBS: anomaly detection on locally-mined block ───────────
                try:
                    _shbs = getattr(getattr(self, '_node_ref', None), 'shbs', None)
                    if _shbs is not None and _shbs._running:
                        _shbs.on_block_applied(block)
                except Exception as _shbs_mine_err:
                    log.debug(f"[SHBS] on_block_applied (mine) hook error: {_shbs_mine_err}")
            else:
                log.warning(f"Mine result rejected: {msg}")
            return ok, msg
        except Exception as e:
            return False, f"mine_result error: {e}"

    def _merge_incoming_validator_sigs(self, blocks: List['Block'],
                                        source_peer: str = "") -> None:
        """Merge validated signatures carried by overlapping sync blocks."""
        for incoming in blocks:
            canonical = self._storage.get_block_by_hash(incoming.block_hash)
            if canonical is None:
                continue
            for vote in getattr(incoming, "validator_sigs", []) or []:
                if not isinstance(vote, dict):
                    continue
                payload = {
                    "block_hash": incoming.block_hash,
                    "validator": vote.get("addr", vote.get("validator", "")),
                    "sig": vote.get("sig", ""),
                    "pub_hex": vote.get("pub", vote.get("pub_hex", "")),
                }
                if all(payload.values()):
                    self._handle_validator_sig(payload, source_peer)

    def _rebroadcast_block_validator_sigs(self, block: 'Block',
                                            exclude: str = "") -> None:
        """Relay stored validator records after a block becomes canonical."""
        if self._network is None:
            return
        canonical = self._storage.get_block_by_hash(block.block_hash)
        if canonical is None:
            return
        for vote in getattr(canonical, "validator_sigs", []) or []:
            if not isinstance(vote, dict):
                continue
            payload = {
                "type": MSG_VALIDATOR_SIG,
                "block_hash": canonical.block_hash,
                "validator": vote.get("addr", vote.get("validator", "")),
                "sig": vote.get("sig", ""),
                "pub_hex": vote.get("pub", vote.get("pub_hex", "")),
                "ttl": Config.GOSSIP_TTL,
            }
            if payload["validator"] and payload["sig"] and payload["pub_hex"]:
                self._network._gossip(payload, exclude=exclude or None)

    def _queue_pending_validator_sig(self, payload: dict,
                                      source_peer: str) -> None:
        """Buffer a vote whose canonical block has not arrived yet."""
        now = time.time()
        item = (now, dict(payload), source_peer or "")
        with self._pending_validator_sigs_lock:
            cutoff = now - self.PENDING_VALIDATOR_SIG_TTL
            self._pending_validator_sigs = [
                existing for existing in self._pending_validator_sigs
                if existing[0] >= cutoff
            ]
            key = (payload.get("block_hash", ""),
                   payload.get("validator", ""),
                   payload.get("sig", ""))
            if any((entry[1].get("block_hash", ""),
                    entry[1].get("validator", ""),
                    entry[1].get("sig", "")) == key
                   for entry in self._pending_validator_sigs):
                return
            if len(self._pending_validator_sigs) >= self.MAX_PENDING_VALIDATOR_SIGS:
                self._pending_validator_sigs.pop(0)
            self._pending_validator_sigs.append(item)

    def _drain_pending_validator_sigs(self) -> None:
        """Replay buffered votes whose blocks are now canonical."""
        now = time.time()
        with self._pending_validator_sigs_lock:
            pending = self._pending_validator_sigs
            self._pending_validator_sigs = []
        for created_at, payload, source_peer in pending:
            if now - created_at > self.PENDING_VALIDATOR_SIG_TTL:
                continue
            block_hash = payload.get("block_hash", "")
            if self._storage.get_block_by_hash(block_hash) is None:
                self._queue_pending_validator_sig(payload, source_peer)
                continue
            self._handle_validator_sig(payload, source_peer)

    def _handle_validator_sig(self, payload: dict,
                               source_peer: str) -> Tuple[bool, str]:
        """Record a BFT validator signature."""
        try:
            block_hash = payload.get("block_hash", "")
            block_present = self._storage.get_block_by_hash(block_hash) is not None
            ok = self._blockchain.add_validator_sig(
                block_hash,
                payload.get("validator", ""),
                payload.get("sig", ""),
                payload.get("pub_hex", ""),
            )
            if not ok and not block_present:
                self._queue_pending_validator_sig(payload, source_peer)
            if ok and self._network and source_peer:
                self._network._gossip(
                    dict(payload, type="VALIDATOR_SIG",
                         ttl=Config.GOSSIP_TTL),
                    exclude=source_peer)
            return ok, "ok" if ok else "sig rejected"
        except Exception as e:
            return False, f"validator_sig error: {e}"

    def _handle_chain_sync(self, payload: dict,
                            source_peer: str) -> Tuple[bool, str]:
        """Accept a sequence of blocks from a peer (sync or reorg)."""
        try:
            blocks_data = payload.get("blocks", [])
            if not blocks_data:
                return False, "Empty chain sync"
            blocks = [Block.from_dict(d) if isinstance(d, dict) else d
                      for d in blocks_data]
            ok, msg = self._blockchain.accept_chain(blocks)
            # An overlapping sync response can carry validator signatures for
            # blocks already present locally. Merge those records through the
            # normal cryptographic validator before the result is evaluated.
            self._merge_incoming_validator_sigs(blocks, source_peer)
            # AUDIT-FIX-15 (safety monitor blind spot): previously only
            # recorded on success (`if ok:`), so a rejected batch left every
            # height in it with NO recorded block_apply result at all —
            # Storage.get_block_invalid_rate() treats a missing record as
            # "not observed" and skips it entirely (neither numerator nor
            # denominator), not as a failure. GovernanceEngine's automatic
            # upgrade-rollback monitor consumes exactly that rate to decide
            # whether to auto-rollback a bad protocol upgrade — a node
            # syncing/catching up through the monitored window (arguably
            # the scenario that safety net most needs to cover) contributed
            # nothing to that decision whenever its batches failed. Record
            # every height in the batch with the batch's overall verdict:
            # not as precise as per-block granularity would be (accept_chain
            # returns one verdict for the whole batch, not per-block), but
            # far more accurate than recording nothing, and it closes the
            # actual blind spot.
            for block in blocks:
                self._storage.record_block_apply_result(block.index, ok)
            if ok:
                for block in blocks:
                    self._governance.on_block_applied(block)
                # BFT-FIX: chain-sync is another block-receipt path. A node
                # that catches up through sync must validate and, when it is
                # an investor, sign the canonical blocks just as it does for
                # direct block gossip. Without this hook, sync_chain() could
                # silently bypass validator voting.
                try:
                    _consensus_ref = getattr(
                        getattr(self, "_node_ref", None), "consensus", None)
                    if _consensus_ref is not None:
                        for block in blocks:
                            _consensus_ref.validate_and_finalize(block)
                    self._drain_pending_validator_sigs()
                    for _synced_block in blocks:
                        self._rebroadcast_block_validator_sigs(
                            _synced_block, source_peer)
                except Exception as _sync_bft_err:
                    log.warning(
                        f"Chain-sync BFT vote failed: {_sync_bft_err}")
            # AUDIT-FIX-2 (network sync stall): continue pagination from
            # this path too. This is the path that handles almost every
            # chain-sync batch in normal operation (StateEngine.post()
            # only fails when its queue is already >80% full), so without
            # this call the event-driven pagination system — next-page
            # request, sync watchdog, _pagination_active bookkeeping —
            # never actually ran; sync silently degraded to one page per
            # P2PNetwork._reconnect_loop heartbeat tick regardless of how
            # far behind the node was. _on_chain_sync_result() is the same
            # logic the synchronous fallback path uses, so both paths now
            # behave identically.
            if self._network is not None:
                peer = self._network.peers.get(source_peer)
                if peer is not None:
                    self._network._on_chain_sync_result(
                        peer, blocks, ok, msg,
                        payload.get("needs_next_page", False),
                        payload.get("next_page_from", 0),
                        payload.get("sync_request_id"))
            return ok, msg
        except Exception as e:
            return False, f"chain_sync error: {e}"

    def _handle_timer(self):
        """
        Periodic maintenance: mempool pruning, metrics snapshot, state pruning,
        and rolling safety invariant check.

        Fix #10 — State Growth: triggers Storage.prune_old_data() on every
        timer tick so that transaction index rows and stale node_meta entries
        are cleaned up incrementally without blocking the event loop.

        Fix #12 — Safety Invariants: runs a lightweight rolling invariant check
        on the last 200 blocks every timer tick.  Full scan only at startup.
        """
        try:
            # Prune expired mempool transactions
            with self._blockchain.mempool._lock:
                self._blockchain.mempool._purge_expired()
            # Refresh metrics
            metrics.set_gauge("mempool_size",
                              self._blockchain.mempool.size())
            metrics.set_gauge("chain_height", self._blockchain.height())
            # Fix #10: incremental state pruning
            current_height = self._blockchain.height()
            if current_height > 0:
                self._storage.prune_old_data(current_height)
            # NEW: State snapshot pruning (Merkle/Patricia)
            if self._state_pruner is not None:
                self._state_pruner.maybe_prune(current_height)
            # Fix #12: rolling safety invariant check
            if self._invariant_checker is not None:
                report = self._invariant_checker.rolling_check()
                # ── NEW: Auto-trip circuit breaker on repeated violations ──────
                if (report and self._circuit_breaker is not None
                        and isinstance(report, dict)):
                    for violation in report.get("violations", []):
                        self._circuit_breaker.record_violation(violation)
        except Exception as e:
            log.debug(f"StateEngine timer error: {e}")
