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
"""visold.kernel.messages

Original section: SECTION 13: P2P NETWORK (TCP + Gossip + Kademlia + PEX + Auto-Peer)

Origin: visold_vsd_.py L31223-31241, L31249-31256, L31263, L31275, L31298
"""




# ─────────────────────────────────────────────────────────────────────────────
# SECTION 13: P2P NETWORK (TCP + Gossip + Kademlia + PEX + Auto-Peer)
# ─────────────────────────────────────────────────────────────────────────────
MSG_HELLO       = "HELLO"


MSG_VERIFY      = "VERIFY"


MSG_ACCEPT      = "ACCEPT"


MSG_REJECT      = "REJECT"


MSG_POW_CHALLENGE = "POW_CHALLENGE"  # CRIT-01: server-issued PoW challenge before HELLO


MSG_GET_PEERS   = "GET_PEERS"


MSG_PEERS       = "PEERS"


MSG_TX          = "TX"


MSG_BLOCK       = "BLOCK"


MSG_GET_BLOCK   = "GET_BLOCK"


MSG_GET_CHAIN   = "GET_CHAIN"


MSG_CHAIN       = "CHAIN"


MSG_PING        = "PING"


MSG_PONG        = "PONG"


MSG_VALIDATOR_SIG = "VALIDATOR_SIG"


MSG_ALERT       = "INVALID_NODE_ALERT"


MSG_IDENTITY    = "IDENTITY"


MSG_RESOLVE     = "RESOLVE"


MSG_RESOLVE_RESP= "RESOLVE_RESP"


# ── v7.5.0 Compact-Block protocol (BIP-152-inspired) ─────────────────────────
# MSG_CMPCTBLOCK  : broadcast header + short-IDs instead of full transactions.
# MSG_GETBLOCKTXN : receiver asks for specific missing full transactions.
# MSG_BLOCKTXN    : sender replies with the requested full transactions.
# All three are point-to-point (never flood-gossiped) so they join
# _GOSSIP_DEDUP_SKIP.  Dedup of the reconstructed block is done via
# the canonical block_hash key ("BLOCK", bh) — same path as MSG_BLOCK.
MSG_CMPCTBLOCK  = "CMPCTBLOCK"


MSG_GETBLOCKTXN = "GETBLOCKTXN"


MSG_BLOCKTXN    = "BLOCKTXN"


# ── v7.5.0 Parallel Block Downloader messages ─────────────────────────────────
MSG_GET_BLOCK_MANIFEST = "GET_BLOCK_MANIFEST"


MSG_BLOCK_MANIFEST     = "BLOCK_MANIFEST"


MSG_GET_BLOCK_CHUNK    = "GET_BLOCK_CHUNK"


MSG_BLOCK_CHUNK_DATA   = "BLOCK_CHUNK_DATA"


# ── v7.5.0-OPT L2 ROLLUP GOSSIP ─────────────────────────────────────────────
# MSG_L2TX : a lightweight L2Transaction broadcast to the network, destined
#            for a sequencer's pending pool.  Routed at PRI_BULK in the
#            outbound priority queue so a surge of L2 traffic CANNOT starve
#            MSG_BLOCK / MSG_CMPCTBLOCK propagation — the chain tip always
#            moves forward even if L2 sync is lagging.
MSG_L2TX        = "L2TX"


# ── HASHRATE OPTIMIZATION (v7.6.0) ────────────────────────────────────────────
# Periodic broadcast of a miner's *actual* (unthrottled) hashrate.  Every
# node maintains a registry { peer_id -> (actual_hashrate, last_seen_ts) }
# which the local HashrateGovernor consults to compute its individual
# optimized-hashrate cap.  This is metadata only — it does NOT affect block
# validation, PoW target, difficulty, or consensus in any way.  The
# message is point-to-point in spirit but gossiped network-wide so every
# miner converges on a similar view of the global actual-hashrate
# distribution.  Stale reports (older than HASHRATE_PEER_TTL seconds) are
# evicted on read, so no central cleanup is needed.
MSG_HASHRATE_REPORT = "HASHRATE_REPORT"


# ── RATE DEFECTION AUDIT (v7.7.0) ────────────────────────────────────────────
# Cryptographically-anchored statistical evidence that a miner consistently
# produced blocks faster than the throttle allowed.  Unlike the double-sign
# evidence in MSG_SLASH_EVIDENCE, this is statistical, not cryptographic —
# receivers MUST independently re-audit from their own block history before
# applying any slash.  Verifiers refuse to apply a slash unless their local
# audit independently confirms the claim within RATE_AUDIT_VERIFY_TOLERANCE.
#
# Payload schema:
#   {
#     "type":          "RATE_DEFECTION_EVIDENCE",
#     "miner":         "VSD...",
#     "window_start":  int,           # first block index in audit window
#     "window_end":    int,           # last block index in audit window
#     "expected_wins": float,
#     "actual_wins":   int,
#     "ratio":         float,         # actual / expected
#     "consecutive":   int,           # how many consecutive flagged windows
#     "submitted_by":  "VSD...",
#     "ts":            int,
#   }
MSG_RATE_DEFECTION_EVIDENCE = "RATE_DEFECTION_EVIDENCE"
