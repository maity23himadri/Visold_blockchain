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
"""visold.chain.sequencer


Defines: Sequencer
Origin: visold_vsd_.py L25231-25767
"""

import threading
import time
from typing import Dict, List, Optional, TYPE_CHECKING, Tuple

from visold.kernel.config import Config
from visold.kernel.events import Event, EventType
from visold.kernel.logging_setup import log
from visold.kernel.metrics import metrics
from visold.ledger.transaction import Transaction
from visold.rollup.batches import RollupBatch, RollupSubmission
from visold.rollup.l2_state import L2Transaction, L2_BRIDGE_ADDRESS
from visold.rollup.proofs import ProofRegistry, UnsafeBackendOnMainnetError

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.chain.blockchain import Blockchain
    from visold.network.p2p import P2PNetwork
    from visold.rollup.l2_state import Layer2State
    from visold.state.engine import StateEngine
    from visold.wallet.wallet import Wallet


# ─────────────────────────────────────────────────────────────────────────────
class Sequencer:
    """Background thread that collects L2 transactions and periodically
    seals them into a RollupBatch, generates a proof, builds an L1
    TYPE_ROLLUP transaction, and submits it to the main mempool.

    Operator model
    ──────────────
    A Sequencer is owned by ONE node.  On a production rollup there is
    typically a rotation or a permissioned set; here we allow any node
    to run one (disabled by default).  The sequencer's L1 wallet signs
    the outgoing TYPE_ROLLUP transaction — so the L1 settlement tx is
    gated by that signature, and the sequencer must hold enough L1 VSD
    to pay the submission fee.

    Thread safety
    ─────────────
    • `add_l2_tx` can be called from any thread (P2P, RPC, local wallet).
    • The batch-sealing step runs on a single internal thread.
    • All shared mutations are guarded by `_lock`.

    Invariants
    ──────────
    • Every sealed batch has batch_id strictly greater than the previous.
    • previous_l2_root of batch N equals new_l2_root of batch N-1 (for
      the sequencer's local view; other sequencers on the same network
      must coordinate via on-chain settlement order).
    • All balance math is integer satoshi.
    """

    def __init__(self, layer2: 'Layer2State', wallet: 'Wallet',
                 blockchain: 'Blockchain', network: Optional['P2PNetwork'] = None,
                 state_engine: Optional['StateEngine'] = None):
        self.layer2       = layer2
        self.wallet       = wallet
        self.blockchain   = blockchain
        self.network      = network
        self._state_engine = state_engine
        self._lock        = threading.Lock()
        self._pending:    List[L2Transaction] = []
        self._seen_ids:   set = set()
        self._next_batch_id: int = 0
        self._running     = False
        self._thread: Optional[threading.Thread] = None
        self._stop_evt    = threading.Event()
        # Dedup pending-tx IDs bounded so long-running sequencers don't
        # leak memory on replay attempts.
        self._SEEN_MAX    = 100_000
        # AUDIT-FIX-G2: per-tx count of consecutive failed apply_l2_tx
        # attempts at seal time, so a tx that can genuinely never apply
        # (e.g. a nonce below the sender's current one) is eventually
        # evicted instead of being retried forever — while a tx that
        # fails only for a transient, state-dependent reason (nonce
        # ordering, a balance check that will pass once an earlier tx
        # lands) survives long enough to succeed. Cleared on success
        # (_finalize_seal) or once a tx is evicted for exceeding the cap.
        self._fail_counts: Dict[str, int] = {}
        self._max_seal_attempts = getattr(Config, "L2_MAX_SEAL_ATTEMPTS", 10)
        # AUDIT-FIX-L4: guards a full seal -> submit -> finalize-or-abandon
        # cycle end-to-end, so _loop()'s background polling and an
        # RPC-triggered manual seal (or two manual seals) can never both be
        # "in flight" on the same uncommitted pending window / batch_id at
        # once. See _seal_one()/_finalize_seal()/_abandon_seal() docstrings.
        self._seal_cycle_lock = threading.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────
    def start(self) -> Tuple[bool, str]:
        if self._running:
            return False, "sequencer already running"
        # ── Production guard ─────────────────────────────────────────────
        # On mainnet, refuse to start with an unsafe proof backend.  This
        # is the LAST line of defence between a misconfigured deployment
        # and broken cryptographic guarantees.  ProofRegistry.get_configured
        # raises UnsafeBackendOnMainnetError if the configured backend is
        # dev/stub/hmac on mainnet — we surface that as a clean (False, msg)
        # so callers get a deterministic refusal instead of a crash.
        try:
            backend = ProofRegistry.get_configured()
        except UnsafeBackendOnMainnetError as e:
            log.error(f"[SEQUENCER] Refusing to start: {e}")
            return False, f"unsafe proof backend on mainnet: {e}"
        except Exception as e:
            log.error(f"[SEQUENCER] Backend lookup failed: {e}")
            return False, f"proof backend lookup failed: {e}"
        # Even outside mainnet, log a clear note about what backend is in
        # use so operators reviewing logs can see at a glance.
        try:
            log.info(f"[SEQUENCER] Proof backend at start: name={backend.name()} "
                     f"security={backend.security()} "
                     f"production_ready={backend.is_production_ready()}")
        except Exception:
            pass
        self._running = True
        self._stop_evt.clear()
        # Resume from layer2's last known batch_id so we don't collide on
        # restart with batches already on-chain.
        try:
            self._next_batch_id = max(0, int(self.layer2._last_batch_id) + 1)
        except Exception:
            self._next_batch_id = 0
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="sequencer")
        self._thread.start()
        log.info(f"[SEQUENCER] Started.  Next batch_id={self._next_batch_id}, "
                 f"backend={backend.name()}")
        return True, "OK"

    def stop(self) -> Tuple[bool, str]:
        self._running = False
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("[SEQUENCER] Stopped")
        return True, "OK"

    # ── Inbound L2 tx acceptance ─────────────────────────────────────────
    def add_l2_tx(self, tx: L2Transaction) -> Tuple[bool, str]:
        """Enqueue an L2 transaction for the next batch.

        Performs cheap up-front validation (structural + signature via
        tx.is_valid) so invalid entries never sit in the pool.  Balance /
        nonce ordering is NOT checked here — that happens inside
        Layer2State.apply_l2_tx at seal time, because the state may
        change between enqueue and seal.
        """
        if not self._running:
            return False, "sequencer not running"
        ok, msg = tx.is_valid()
        if not ok:
            return False, msg
        with self._lock:
            if tx.l2_tx_id in self._seen_ids:
                return False, "duplicate l2_tx_id"
            if len(self._pending) >= Config.L2_MAX_BATCH_SIZE * 4:
                # Overflow protection — cap the pending pool at 4× the
                # max batch size.
                return False, "sequencer pending pool full"
            self._pending.append(tx)
            if len(self._seen_ids) >= self._SEEN_MAX:
                # Cheap eviction — drop half the seen set.  A tx that was
                # seen long ago and is re-gossipped will now get a second
                # structural pass, which is cheap, and will then be
                # rejected for nonce mismatch at apply time.
                self._seen_ids = set(list(self._seen_ids)[self._SEEN_MAX // 2:])
            self._seen_ids.add(tx.l2_tx_id)
        metrics.inc("l2_txs_received")
        return True, "OK"

    # ── Batch sealing ─────────────────────────────────────────────────────
    def _should_seal(self) -> bool:
        with self._lock:
            if not self._pending:
                return False
            if len(self._pending) >= Config.L2_MAX_BATCH_SIZE:
                return True
            age = time.time() - self._pending[0].timestamp
            if age >= Config.L2_BATCH_MAX_AGE_SECS:
                return True
        return False

    def generate_batch_proof(self, batch: RollupBatch,
                             compressed_data: bytes) -> bytes:
        """Produce a proof that `batch.prev_root` transitions to
        `batch.new_root` when the contents of `compressed_data` are
        applied in order.

        Delegates to the currently configured IProofBackend.  The
        returned bytes are opaque to the caller — only the backend's
        own verify() method knows how to interpret them.

        For the simulated backend this returns an HMAC tag, NOT a zero-
        knowledge proof.  See SimulatedProofBackend docstring.
        """
        backend = ProofRegistry.get_configured()
        batch_h = RollupSubmission.batch_hash(compressed_data)
        return backend.prove(batch.prev_root, batch.new_root, batch_h, b"")

    def _seal_one(self) -> Optional[Tuple['Transaction', int, List[L2Transaction]]]:
        """Seal the current pending txs into a batch and return
        (l1_tx, batch_id, applied_l2_txs).

        AUDIT-FIX-G3: the caller MUST call _finalize_seal(batch_id,
        applied_l2_txs) once it has confirmed l1_tx was actually accepted
        (mempool admission or broadcast) — and must NOT call it if
        submission failed. Only then are the sealed txs removed from the
        pending pool and the batch counter advanced. This makes a failed
        submission a no-op (the same batch is retried next cycle) instead
        of a silent, permanent loss of the sealed batch. See
        _finalize_seal()'s docstring and _loop() for the reference usage.

        AUDIT-FIX-L4: acquires self._seal_cycle_lock for the duration of
        this seal attempt. If a seal cycle is already in flight (from
        _loop() or a concurrent vsd_triggerManualRollup RPC call), this
        returns None immediately instead of racing -- without this guard,
        _seal_one() reads self._pending/self._next_batch_id but does not
        mutate them until a later, separate _finalize_seal() call, so a
        second concurrent _seal_one() could read the identical window and
        batch_id and produce a duplicate, independently-signed batch. On
        every path that returns without a result the caller can act on,
        the lock is released before returning. On the success path (the
        final `return l1_tx, batch_id, applied`), the lock is DELIBERATELY
        left held — the caller now owns it and MUST release it by calling
        either _finalize_seal() (after confirming submission succeeded) or
        _abandon_seal() (if it will not finalize, for any reason,
        including an exception). Failing to do so will permanently block
        all future sealing on this node.

        Returns None if there is nothing to seal or sealing failed."""
        if not self._seal_cycle_lock.acquire(blocking=False):
            return None
        try:
            with self._lock:
                if not self._pending:
                    self._seal_cycle_lock.release()
                    return None
                # Take up to MAX_BATCH_SIZE in FIFO order.
                take_n  = min(len(self._pending), Config.L2_MAX_BATCH_SIZE)
                to_seal = self._pending[:take_n]
                # We don't pop yet — only on success do we remove these.

            # Capture the prev root BEFORE we apply anything.  If the layer2
            # state is mutated between here and the apply calls below (e.g.,
            # a concurrent deposit lands) we may have a prev_root that no
            # longer matches the on-disk state.  To keep this deterministic
            # we take the layer2 lock for the whole seal path.
            #
            # L2-2 FIX (sequencer self-rejects own batch): the previous
            # implementation called layer2.apply_l2_tx(tx) inside the lock,
            # which permanently mutated the live tree.  Once the L1
            # TYPE_ROLLUP transaction we built here was eventually mined into
            # a block, the SAME node's apply_block would call
            # _apply_rollup_tx, observe that current layer2 root no longer
            # matched submission.previous_l2_root (because we had already
            # advanced past prev_root in this seal), and REJECT its own
            # block.  Other nodes (whose layer2 was still at prev_root)
            # would accept the block — splitting the chain at the sequencer.
            #
            # The fix is to take a snapshot, apply the txs against the live
            # tree to MEASURE the new root, then restore the snapshot.  When
            # _apply_rollup_tx eventually runs on our own block, layer2 is
            # still at prev_root, the stateful check passes, and re-execution
            # advances the tree exactly as it does on every other node.
            # Symmetric: same code path runs everywhere.
            batch_id  = self._next_batch_id
            with self.layer2._lock:
                prev_root = self.layer2._tree.root()
                # Take a snapshot of every account before any mutation so we
                # can restore to exactly prev_root regardless of which txs
                # apply successfully.
                seal_snap = self.layer2._tree.snapshot()
                batch = RollupBatch(batch_id, prev_root)
                applied: List[L2Transaction] = []
                failed_ids: set = set()
                for tx in to_seal:
                    ok, msg = self.layer2.apply_l2_tx(tx)
                    if not ok:
                        log.debug(f"[SEQUENCER] tx {tx.l2_tx_id[:12]} did not "
                                  f"apply this round: {msg}")
                        failed_ids.add(tx.l2_tx_id)
                        continue
                    batch.add_tx(tx)
                    applied.append(tx)

                # AUDIT-FIX-G2 (silent, permanent loss of valid pending L2 txs):
                # The old code, whenever EVERY tx in `to_seal` failed
                # apply_l2_tx, unconditionally dropped the entire `to_seal`
                # window from self._pending — including txs that failed only
                # for transient, state-dependent reasons (nonce ordering from
                # out-of-order P2P delivery, a balance check that will pass
                # once an earlier tx lands): exactly the same failure reasons
                # the partial-success case already correctly retained for
                # retry. That asymmetry silently discarded valid, already-
                # accepted (add_l2_tx returned True) user transfers with no
                # error ever surfacing to the sender.
                #
                # Fix: every failed tx is treated the same regardless of
                # whether other txs in the same window succeeded — it stays
                # in self._pending for retry, bounded by a small per-tx
                # attempt counter so a tx that can truly never apply (e.g. a
                # stale nonce lower than the sender's current one) doesn't
                # sit in the pool forever and eventually starve add_l2_tx's
                # pending-pool cap.
                if failed_ids:
                    with self._lock:
                        dead_ids = set()
                        for tx_id in failed_ids:
                            n = self._fail_counts.get(tx_id, 0) + 1
                            self._fail_counts[tx_id] = n
                            if n >= self._max_seal_attempts:
                                dead_ids.add(tx_id)
                        if dead_ids:
                            log.warning(
                                f"[SEQUENCER] dropping {len(dead_ids)} tx(s) "
                                f"after {self._max_seal_attempts} failed seal "
                                f"attempts: {[i[:12] for i in dead_ids]}")
                            self._pending = [t for t in self._pending
                                             if t.l2_tx_id not in dead_ids]
                            for tx_id in dead_ids:
                                self._fail_counts.pop(tx_id, None)

                if not batch.txs:
                    # Nothing applied this round — restore (defensive no-op:
                    # a failed apply_l2_tx never mutates the tree) and stop.
                    # Anything that survived the dead_ids eviction above (i.e.
                    # everything still under the attempt cap) stays in
                    # self._pending for the next cycle.
                    self.layer2._tree.restore(seal_snap)
                    self._seal_cycle_lock.release()
                    return None
                batch.new_root = self.layer2._tree.root()
                batch.sealed   = True
                # Critical: restore the live tree to prev_root.  The new_root
                # we just computed is now ONLY persisted inside batch.new_root
                # and the L1 TYPE_ROLLUP tx we are about to build.  Once that
                # L1 tx is mined and apply_block runs _apply_rollup_tx on this
                # node, the txs will be re-executed against the (still-prev)
                # tree and the live tree will advance to new_root deterministically.
                self.layer2._tree.restore(seal_snap)

            # Compression + proof — can be done without the layer2 lock since
            # it only reads the frozen batch contents.
            compressed = RollupSubmission.compress_batch(batch.txs)
            if len(compressed) > RollupSubmission.MAX_COMPRESSED_BYTES:
                log.error(f"[SEQUENCER] batch {batch_id} compressed to "
                          f"{len(compressed)} bytes > cap; abandoning batch")
                # L2-2 FIX side-effect: the live tree was already restored to
                # prev_root inside the seal lock above, so there is nothing
                # to roll back here — we simply abandon this batch.  The
                # consumed pending entries get re-queued by NOT popping them
                # below.
                self._seal_cycle_lock.release()
                return None

            proof_bytes = self.generate_batch_proof(batch, compressed)
            backend     = ProofRegistry.get_configured()
            submission  = RollupSubmission(
                batch_id         = batch_id,
                previous_l2_root = prev_root,
                new_l2_root      = batch.new_root,
                zk_proof         = proof_bytes,
                compressed_data  = compressed,
                backend          = backend.name(),
                backend_security = backend.security(),
            )

            # Wrap in an L1 TYPE_ROLLUP Transaction.  amount is 0 (no VSD is
            # transferred by the submission itself — deposits/withdrawals are
            # a separate, explicit mechanism).  Fee equals the standard fee
            # math on amount=0, which is 0 — the sequencer pays gas via a
            # minimum L1 economic cost we set below.
            #
            # NOTE: per Mempool.add() rules, tx.fee MUST match
            # tx.compute_fee_sat().  For amount=0 that is also 0.  We set
            # fee=0.0 explicitly.
            l1_chain_nonce = self.blockchain.storage.get_nonce(self.wallet.address)
            l1_tx = Transaction(
                sender    = self.wallet.address,
                receiver  = L2_BRIDGE_ADDRESS,
                amount    = 0.0,
                fee       = 0.0,
                timestamp = int(time.time()),
                pub_hex   = self.wallet.pub_hex,
                tx_type   = Transaction.TYPE_ROLLUP,
                data      = submission.to_json(),
                nonce     = l1_chain_nonce,
            )
            l1_tx.sign(self.wallet)  # type: ignore[attr-defined]

            # AUDIT-FIX-G3 (silent loss of a sealed-but-unsubmitted batch):
            # This used to remove `applied` from self._pending and advance
            # self._next_batch_id HERE — unconditionally, before the caller
            # had any confirmation that l1_tx was actually accepted anywhere.
            # If mempool submission then failed (rejected, timed out, mempool
            # full), the batch's L2 txs were already gone from self._pending
            # (never retried) and the batch_id was already burned — a
            # silent, permanent loss of a fully-valid, already-sealed batch.
            # (Layer2State itself was never corrupted — the tree was already
            # restored to prev_root above — but the transfers inside the
            # batch just vanished.)
            #
            # Fix: do NOT mutate self._pending / self._next_batch_id here.
            # Sealing succeeded (the batch/proof/l1_tx are valid); whether
            # it's actually SUBMITTED is the caller's concern. The caller
            # must call _finalize_seal(batch_id, applied) itself, and only
            # after confirming submission succeeded — see its docstring and
            # _loop(). On submission failure the caller simply does nothing,
            # so this exact (batch_id, to_seal window) is retried next cycle.
            metrics.inc("l2_batches_sealed")
            metrics.set_gauge("l2_last_sealed_batch", batch_id)
            log.info(f"[SEQUENCER] Sealed batch {batch_id}: "
                     f"{len(applied)} txs, compressed={len(compressed)} B, "
                     f"prev={prev_root[:12]}, new={batch.new_root[:12]}, "
                     f"backend={backend.name()}")
            # AUDIT-FIX-L4: lock intentionally still held -- caller now owns
            # it and must release via _finalize_seal() or _abandon_seal().
            return l1_tx, batch_id, applied
        except Exception:
            self._seal_cycle_lock.release()
            raise

    def _finalize_seal(self, batch_id: int,
                       applied: List[L2Transaction]) -> None:
        """AUDIT-FIX-G3: commit a successfully-SUBMITTED seal — remove its
        txs from the pending pool and advance the batch counter.

        Callers of _seal_one() MUST call this once, and only once, after
        confirming the returned l1_tx was actually accepted (mempool
        admission via StateEngine.post_sync, or a successful
        network.broadcast_tx). If submission failed, do NOT call this —
        leaving self._pending / self._next_batch_id untouched means the
        same batch is naturally retried on the next seal cycle.

        AUDIT-FIX-L4: releases self._seal_cycle_lock, which _seal_one()
        left held for the caller. Always call this or _abandon_seal()
        exactly once per successful _seal_one() call.
        """
        try:
            with self._lock:
                consumed = {t.l2_tx_id for t in applied}
                self._pending = [t for t in self._pending
                                 if t.l2_tx_id not in consumed]
                for tx_id in consumed:
                    self._fail_counts.pop(tx_id, None)
            self._next_batch_id = batch_id + 1
        finally:
            self._seal_cycle_lock.release()

    def _abandon_seal(self) -> None:
        """AUDIT-FIX-L4: call this instead of _finalize_seal() when a
        _seal_one() result will NOT be submitted/finalized (e.g. submission
        failed or raised), to release the seal-cycle guard WITHOUT mutating
        _pending / _next_batch_id — leaving the same batch to be retried
        on the next seal attempt, exactly as before this fix."""
        try:
            self._seal_cycle_lock.release()
        except RuntimeError:
            log.debug("[SEQUENCER] _abandon_seal called with lock not held")

    def _restore_layer2_to(self, target_root: str) -> None:
        """Conservative recovery if seal math fails past the apply step.

        Walks the layer2 history backwards for a snapshot matching
        target_root.  If none is found, logs loudly but leaves state in
        place — operator intervention needed.
        """
        try:
            with self.layer2._lock:
                for entry in reversed(self.layer2._history):
                    if entry.get("l2_root") == target_root:
                        self.layer2._tree.restore(entry["snapshot"])
                        return
            log.error(
                f"[SEQUENCER] could not restore L2 tree to root "
                f"{target_root[:16]} — no matching snapshot")
        except Exception as e:
            log.error(f"[SEQUENCER] restore failed: {e}")

    # ── Main loop ─────────────────────────────────────────────────────────
    def _loop(self):
        _POLL_SECS = 1.0
        while self._running:
            if self._stop_evt.wait(timeout=_POLL_SECS):
                break
            try:
                if self._should_seal():
                    sealed = self._seal_one()
                    if sealed is not None:
                        tx, batch_id, applied = sealed
                        # AUDIT-FIX-G3: only commit (pending-pool removal +
                        # batch_id advance, via _finalize_seal) once we
                        # know the L1 tx was actually accepted somewhere.
                        # On failure we do nothing: self._pending and
                        # self._next_batch_id stay untouched, so the exact
                        # same batch is reattempted on the next cycle
                        # instead of being silently lost.
                        submitted = False
                        if self._state_engine is not None:
                            # Submit via StateEngine so the normal mempool admit
                            # path runs (dedup, nonce tracking, rate limit).
                            # AUDIT-FIX-L4: wrapped in try/except -- an
                            # uncaught exception here would previously
                            # propagate straight to this loop's outer
                            # except-and-log below without ever reaching
                            # _finalize_seal() or _abandon_seal(),
                            # permanently stranding the seal-cycle lock
                            # _seal_one() left held and blocking all future
                            # sealing on this node.
                            try:
                                ev = Event(EventType.NEW_TX, {"tx": tx})
                                ok, msg = self._state_engine.post_sync(ev, timeout=5.0)
                                if ok:
                                    submitted = True
                                else:
                                    log.warning(
                                        f"[SEQUENCER] batch {batch_id} submit to "
                                        f"mempool failed: {msg} — will retry "
                                        f"next cycle")
                            except Exception as e:
                                log.warning(
                                    f"[SEQUENCER] batch {batch_id} submit to "
                                    f"mempool raised: {e} — will retry "
                                    f"next cycle")
                        elif self.network is not None:
                            # Fallback — direct broadcast.  Caller should have
                            # injected a state_engine though.
                            try:
                                self.network.broadcast_tx(tx)
                                submitted = True
                            except Exception as e:
                                log.warning(
                                    f"[SEQUENCER] batch {batch_id} broadcast "
                                    f"failed: {e} — will retry next cycle")
                        else:
                            log.warning(
                                f"[SEQUENCER] batch {batch_id} sealed but no "
                                f"state_engine or network configured to "
                                f"submit through — will retry next cycle")
                        if submitted:
                            self._finalize_seal(batch_id, applied)
                        else:
                            self._abandon_seal()   # AUDIT-FIX-L4
            except Exception as e:
                log.error(f"[SEQUENCER] loop error: {e}")

    # ── Diagnostics ───────────────────────────────────────────────────────
    def status(self) -> dict:
        with self._lock:
            pending_n = len(self._pending)
            oldest_age = (time.time() - self._pending[0].timestamp
                          if self._pending else 0.0)
        return {
            "running":         self._running,
            "pending":         pending_n,
            "oldest_tx_age":   oldest_age,
            "next_batch_id":   self._next_batch_id,
            "backend":         ProofRegistry.get_configured().name(),
            "backend_security": ProofRegistry.get_configured().security(),
        }
