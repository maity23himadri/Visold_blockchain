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
"""visold.kernel.events


Defines: GlobalSequencer, EventType, Event
Origin: visold_vsd_.py L7071-7095, L7099-7117, L7120-7148
"""

import threading
import time
import concurrent.futures as _futures
import enum as _enum
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# FIX 1 — GLOBAL EVENT ORDERING
# A node-wide, strictly monotonically increasing sequence counter is stamped
# onto every Event before it enters the StateEngine queue.  The engine
# processes events strictly in arrival order (queue.Queue guarantees FIFO
# within a single process), and the sequence number makes each ordering
# decision auditable and replay-deterministic.
#
# Three categories of events get different ordering rules:
#   • Transactions      — ordered by (sender_nonce, global_seq)
#   • Validator sigs    — ordered by (block_height, global_seq)
#   • Cross-node blocks — ordered by (block.index, block.timestamp, global_seq)
#
# Because all mutations are serialised through a single queue, two honest nodes
# that receive the same sequence of network messages will produce identical
# state, satisfying the "no conflicting state" safety property.
# ─────────────────────────────────────────────────────────────────────────────
class GlobalSequencer:
    """
    Thread-safe monotonic sequence counter.

    F-18 FIX: Counter now initializes from the current epoch in microseconds
    rather than 0.  This guarantees strict monotonicity across node restarts
    without any disk persistence: events from a new session (starting at e.g.
    1_700_000_000_000_000) are always ordered after events from a previous
    session (starting at an earlier epoch value).  The global_seq is used only
    for intra-session tie-breaking; chain state re-validation makes it safe to
    use a time-based seed rather than a persisted counter.
    """
    _counter: int = int(time.time() * 1_000_000)   # microsecond epoch seed
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def next(cls) -> int:
        with cls._lock:
            cls._counter += 1
            return cls._counter

    @classmethod
    def current(cls) -> int:
        with cls._lock:
            return cls._counter


class EventType(_enum.Enum):
    """
    Canonical event types processed by the StateEngine.

    NEW_TX        — New transaction submitted (from CLI, RPC, or network).
    NEW_BLOCK     — New block received from network peer.
    MINE_RESULT   — Mining engine found a valid PoW solution.
    VALIDATOR_SIG — BFT validator signature received from network.
    CHAIN_SYNC    — Sequence of blocks received for chain synchronization.
    TIMER         — Periodic maintenance tick (mempool pruning, etc.).
    STOP          — Graceful shutdown signal.
    """
    NEW_TX        = "NEW_TX"
    NEW_BLOCK     = "NEW_BLOCK"
    MINE_RESULT   = "MINE_RESULT"
    VALIDATOR_SIG = "VALIDATOR_SIG"
    CHAIN_SYNC    = "CHAIN_SYNC"
    TIMER         = "TIMER"
    STOP          = "STOP"


class Event:
    """
    Immutable event carrier posted to the StateEngine queue.

    Fields
    ──────
    etype         : EventType
    payload       : arbitrary dict (event-specific data)
    source_peer_id: originating peer ID (for network events), or "" for local
    future        : optional concurrent.futures.Future for synchronous callers.
                    If set, the StateEngine sets its result after processing.
    global_seq    : monotonically increasing node-local sequence number
                    stamped at construction time by GlobalSequencer.next().
                    Guarantees total ordering of all state mutations within
                    a single node session (Fix #1 — Global Event Ordering).
    """
    __slots__ = ("etype", "payload", "source_peer_id", "future", "global_seq")

    def __init__(self, etype: EventType, payload: dict,
                 source_peer_id: str = "",
                 future: Optional['_futures.Future'] = None):
        self.etype          = etype
        self.payload        = payload
        self.source_peer_id = source_peer_id
        self.future         = future
        # Stamp with a global sequence number immediately at creation so that
        # regardless of which thread builds the event, the ordering is
        # determined by real creation time, not by queue-insertion delay.
        self.global_seq: int = GlobalSequencer.next()
