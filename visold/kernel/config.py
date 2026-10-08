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
"""visold.kernel.config

Original section: SECTION 1: CONFIGURATION

Defines: Config
Origin: visold_vsd_.py L3819-4897
"""

import json
import os
import re
from typing import Dict


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1: CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
class Config:
    # Coin
    COIN_NAME           = "Visold"
    COIN_SYMBOL         = "VSD"
    VERSION             = "11.0.0.0"

    # Chain identity — included in every transaction's signing bytes.
    # Changing this value creates an incompatible fork.  Testnet nodes must
    # use a different CHAIN_ID (e.g. "vsd-testnet-1") so that testnet
    # transactions cannot be replayed on mainnet and vice versa.
    CHAIN_ID            = "vsd-mainnet-1"

    # ── Genesis block constants (network-wide protocol constants) ─────────────
    # These values MUST be byte-for-byte identical on every node that joins
    # this chain. Changing any of them creates an incompatible fork because
    # the resulting genesis block hash will differ and validate_block() will
    # reject the foreign genesis as "Forged or wrong-chain genesis".
    #
    # GENESIS_TIMESTAMP : 1224720000  →  2008-10-23 00:00:00 UTC
    #                     (the publication date of the Bitcoin whitepaper —
    #                      a symbolic anchor for a peer-to-peer cash system)
    # GENESIS_NONCE     : protocol sentinel (genesis is not mined)
    # GENESIS_MINER     : symbolic miner address for the genesis coinbase
    # GENESIS_TX_SENDER : symbolic sender for the genesis coinbase tx
    # GENESIS_TX_AMOUNT : satoshi amount minted at genesis (0 = no premine)
    # GENESIS_TX_NONCE  : per-sender nonce of the genesis tx (always 0)
    # GENESIS_TX_EXPIRY : 0 = no expiry (genesis tx never expires)
    # GENESIS_TX_MEMO   : fixed memo string included in the tx_id hash
    GENESIS_TIMESTAMP   = 1224720000
    GENESIS_NONCE       = 42
    GENESIS_MINER       = "VSD_GENESIS"
    GENESIS_TX_SENDER   = "VSD_GENESIS_SENDER"
    GENESIS_TX_AMOUNT   = 0
    GENESIS_TX_NONCE    = 0
    GENESIS_TX_EXPIRY   = 0
    GENESIS_TX_MEMO     = "coinbase:0"
    # Optional pinned genesis hash. Once you have run a fresh node ONCE with
    # the deterministic genesis code below and observed the printed
    # "[GENESIS] Hash: <hex>" line, paste that hex string here. Every future
    # node start-up will then verify that the locally-computed genesis hash
    # equals this pin. If they differ, the node refuses to start instead of
    # silently forking the network. Leave as "" to skip the check (dev mode).
    GENESIS_HASH_PIN    = ""

    # ── F-01 FIX: Integer Financial Units (satoshi model) ─────────────────────
    # All VSD amounts are stored and computed as integers (satoshi units).
    # 1 VSD = 100_000_000 satoshi  (10^8, matching Bitcoin's model).
    # This eliminates float non-determinism that would cause consensus splits
    # between nodes on different hardware architectures.
    SATOSHI_PER_VSD     = 100_000_000        # 10^8 atomic units per coin

    # Block / Mining  (all amounts in satoshi)
    INITIAL_REWARD      = 1_000_000_000      # 10.0 VSD in satoshi
    MIN_REWARD          =    10_000_000      #  0.1 VSD in satoshi
    REWARD_DECAY_BLOCKS = 20000
    # AUDIT-FIX (Batch D): REWARD_DECAY_RATE is kept only as a human-readable
    # display value. compute_reward_sat() no longer computes
    # REWARD_DECAY_RATE ** n -- float ** int in CPython is routed to the
    # platform's C library pow(), which is not guaranteed byte-identical
    # across libm implementations (glibc/musl/macOS/Bionic) for the same
    # input. This is exactly the risk class SEC-FIX M-05 eliminated for
    # difficulty-to-target conversion, applied here too since the reward is
    # computed on every block, not just at retarget boundaries.
    # REWARD_DECAY_NUM/DEN express the identical 0.99 decay factor as an
    # exact rational (99/100) so compute_reward_sat can use pure Python
    # big-integer exponentiation (int ** int is exact
    # exponentiation-by-squaring, never routed through any platform's
    # floating-point pow()) -- portable and byte-identical on every
    # interpreter. If this ever changes, update REWARD_DECAY_RATE (display)
    # and REWARD_DECAY_NUM/DEN (consensus math) together.
    REWARD_DECAY_RATE   = 0.99               # display only -- see note above
    REWARD_DECAY_NUM    = 99                 # decay factor numerator
    REWARD_DECAY_DEN    = 100                # decay factor denominator
    TARGET_BLOCK_TIME   = 60           # seconds
    INITIAL_DIFFICULTY  = 5.15    # fractional hex-zero difficulty — very easy bootstrap start
    # SEC-FIX H-04 (Bootstrap PoW Strength)
    # ────────────────────────────────────
    # Raised from 2.0 → 4.0 hex-zero bits.  At 2.0 the target was ~2^248,
    # which a single phone CPU could sustain at the 60 s target rate —
    # making a 51% rewrite of an early chain trivially cheap.  At 4.0 the
    # target is ~2^240, which requires real (modest) hashpower to maintain
    # the schedule.  4.0 is still well below INITIAL_DIFFICULTY=5.15 so the
    # LWMA controller can always come back down if hashrate drops.
    MIN_DIFFICULTY      = 4.0    # hard floor; raised in v7.5.1 (see SEC-FIX H-04)
    # F-19 FIX: keep the consensus ceiling strictly below the 256-bit SHA-256
    # boundary.  D=64 maps to target 0 (no ordinary SHA-256 digest can satisfy
    # H <= 0), which would make the chain permanently unmineable.  D=63 is the
    # highest integer difficulty with a non-zero target (target=16 with the
    # protocol's canonical target conversion), so the DAA can never enter the
    # unreachable zero-target state.
    MAX_DIFFICULTY      = 63.0

    # VVM DIFFICULTY is exposed on the integer-only VM stack as fixed-point
    # micro-units.  The consensus block field remains the protocol's float
    # difficulty; the opcode representation is therefore:
    #     vm_value = round(difficulty * VVM_DIFFICULTY_SCALE)
    # A 1e6 scale preserves substantially more precision than the difficulty
    # controller normally needs while remaining comfortably inside uint256.
    VVM_DIFFICULTY_SCALE = 1_000_000

    # ─────────────────────────────────────────────────────────────────────────
    # Dynamic Difficulty Adjustment (DAA)  —  LWMA-1 (Linearly-Weighted
    # Moving Average) with WORK-ADJUSTED solve times.
    #
    # Why LWMA (and why the previous hybrid macro+micro engine was replaced):
    #
    #   The previous engine combined a Bitcoin-style rolling span ratio
    #   (macro) with an Ethereum-style per-block nudge (micro) and an extra
    #   10 % relative smoothing cap.  In a chain whose difficulty changes
    #   every block, that design has a hidden feedback loop:
    #
    #     • the "macro" ratio compares total span of the last N blocks to
    #       N × TARGET, but those N blocks were mined under *different*
    #       difficulties — so the ratio does not correctly reflect the
    #       current hashrate, only the average effort across a changing D.
    #     • as D rises, the window slowly fills with blocks that took real
    #       wall-clock time; the ratio eventually flips from "too fast" to
    #       "too slow" even though hashrate is unchanged, which pulls D
    #       back down, which makes blocks instant again, which pulls D up.
    #       This is exactly the 4→2→5 oscillation the user reported.
    #
    #   LWMA fixes this by normalising every solve time by the difficulty
    #   that was in force when that block was mined.  The controller then
    #   reasons in units of "expected work per second", which is invariant
    #   under difficulty changes and therefore has no feedback loop.
    #
    # Tuning (TARGET_BLOCK_TIME = 60 s):
    DIFF_LWMA_WINDOW       = 20          # N — averaging window in blocks.
                                         # Tuned down from 45 → 20 in v7.6.0
                                         # so the difficulty engine locks onto
                                         # the real network hashrate within
                                         # ~10 blocks instead of ~25.  Combined
                                         # with HashrateGovernor activation,
                                         # this dramatically reduces the
                                         # bootstrap-phase block-time variance
                                         # operators were seeing (1 s ↔ 2.5 min
                                         # spreads at low difficulty).  Zcash
                                         # uses 17, Monero 60-90; 20 is the
                                         # responsiveness/smoothness sweet spot
                                         # for a 60 s target with a tight band.
    DIFF_LWMA_MAX_TS_STEP  = 360         # 6 × TARGET_BLOCK_TIME.  Per-block
                                         # solve-time clamp — prevents a single
                                         # forged timestamp from poisoning the
                                         # average.  Bounded below by 1 s
                                         # (never zero; see algorithm).
    DIFF_LWMA_MIN_TS_STEP  = 1           # lower clamp on per-block solve time.
    DIFF_LWMA_MAX_SWING    = 1.5         # max multiplicative change vs parent
                                         # difficulty per block.  At D (hex
                                         # zeros) this is +log2(1.5)/4 ≈ +0.146
                                         # and −0.146 hex-units — a hard
                                         # anti-jump guardrail that still
                                         # permits full recovery within ~15
                                         # blocks from any shock.
    DIFF_BOOTSTRAP_BLOCKS  = 3           # keep INITIAL_DIFFICULTY for the first
                                         # N blocks after genesis so we have at
                                         # least one real parent→child interval
                                         # before the DAA runs.  Tuned down from
                                         # 10 → 3 in v7.6.0 so the difficulty
                                         # adjuster engages almost immediately
                                         # after genesis.  This was a deliberate
                                         # change paired with the LWMA window
                                         # shrink (45 → 20): together they cut
                                         # the bootstrap-variance window by
                                         # ~3× and let the HashrateGovernor see
                                         # a representative difficulty value
                                         # within ~10 blocks of network start.
                                         # (The old value of 3×window held D
                                         # fixed for 60 blocks — that was what
                                         # *caused* the giant "catch-up" surge
                                         # at height 60 which then had to be
                                         # unwound, producing oscillation.
                                         # LWMA responds immediately and correctly
                                         # from block 2, so no grace window is
                                         # needed beyond a tiny sanity gap.)

    # ── Legacy names kept as aliases so any external code / comments that
    #    reference them still evaluate; they are NOT used by the new DAA.
    DIFF_MACRO_WINDOW      = DIFF_LWMA_WINDOW
    DIFF_MACRO_CLAMP       = 4.0
    DIFF_MICRO_STEP        = 0.0         # micro layer removed
    DIFF_MAX_RELATIVE_STEP = 0.50        # only used now as a final hard cap
    DIFF_MIN_ABS_STEP      = 0.000001

    # MTP timestamp validation (unchanged — independent of DAA math)
    DIFF_MTP_WINDOW        = 11          # Median Time Past: median of last N timestamps
    DIFF_MAX_FUTURE_DRIFT  = 7200        # max seconds a timestamp may lead local clock

    # Block size (bytes)
    # SEC-FIX M-03 (Block Size Floor)
    # ───────────────────────────────
    # Pre-fix MIN_BLOCK_SIZE == MAX_BLOCK_SIZE which froze the dynamic
    # block-size throttle and the comment claimed "0.25 KB" — wrong by 4
    # orders of magnitude.  MIN now properly sits an order of magnitude
    # below MAX so the dynamic throttle has room to operate.  Both values
    # are ADVISORY for candidate building (see get_dynamic_block_size);
    # consensus enforcement is via MAX_BLOCK_SIZE in validate_block.
    MIN_BLOCK_SIZE      = 1_048_576     # 1 MiB minimum candidate cap
    MAX_BLOCK_SIZE      = 4_096_000     # ~3.9 MiB consensus cap
    BLOCK_SIZE_UP       = 0.10
    BLOCK_SIZE_DOWN     = 0.05

    # ─────────────────────────────────────────────────────────────────────
    # LAYER-2 ROLLUP (see SECTION 7E)
    # ─────────────────────────────────────────────────────────────────────
    # How many past confirmed L2 roots to retain for reorg rollback.
    L2_ROOT_HISTORY_DEPTH = 128
    # Maximum L2 transactions packed into a single rollup batch.
    L2_MAX_BATCH_SIZE     = 2048
    # Soft target for batch age (seconds) — sequencer seals a batch after
    # this many seconds even if it hasn't hit L2_MAX_BATCH_SIZE.
    L2_BATCH_MAX_AGE_SECS = 30
    # Named proof backend.  The name must match a registered IProofBackend.
    # Shipped backends:
    #   "local-dev"        — HMAC, NOT a SNARK.  Refused on mainnet.  (Default.)
    #   "simulated"        — Legacy alias of "local-dev".  Same restrictions.
    #   "snark-subprocess" — Stub.  Becomes usable once an operator supplies
    #                        a prover/verifier binary (see
    #                        SubprocessSNARKBackend docstring) and sets
    #                        VISOLD_SNARK_AUDITED=1.
    # On mainnet (VISOLD_NETWORK=mainnet) the registry refuses to return any
    # backend whose security() string contains dev/test/stub/hmac tokens or
    # whose is_production_ready() returns False.  Sequencer.start() refuses
    # to start in that case.
    # SEC-FIX C-01 (Safe-By-Default L2 Proof Backend)
    # ────────────────────────────────────────────────
    # Default changed from "local-dev" → "no-backend-configured" in v7.5.1.
    # The previous default silently selected LocalDevBackend (an HMAC, not a
    # real proof) on every non-mainnet deployment.  The new default does NOT
    # match any registered backend, so ProofRegistry.get_configured() will
    # log a loud warning and fall through to LocalDevBackend ONLY on dev /
    # testnet (where it's still useful for tests).  On mainnet it raises
    # UnsafeBackendOnMainnetError exactly as before.  Operators who want L2
    # rollups in production MUST explicitly register a real IProofBackend
    # implementation and set this constant to its name() — e.g. the audited
    # SubprocessSNARKBackend wrapper around a Groth16 / PLONK prover.
    L2_PROOF_BACKEND      = "no-backend-configured"

    # Fees (in satoshi)
    TX_FEE_RATE         = 0.01          # 1% from receiver side (applied to satoshi amount)
    # SEC-FIX M-06 (Mempool Dust Floor — Acceptance Policy Only)
    # ──────────────────────────────────────────────────────────
    # Absolute satoshi floor for transactions admitted to the mempool.
    # This is a NODE-LOCAL acceptance policy — it does NOT change the
    # consensus fee formula in Transaction.compute_fee_sat().  A block
    # mined elsewhere that contains a sub-floor tx remains consensus-valid
    # so the chain cannot fork on a policy disagreement.  But each node's
    # mempool refuses such txs at admission time, which kills the cheap
    # mempool-flooding vector where 0.0001-amount txs carry 0.000001 fees.
    # 1 000 satoshi ≈ 0.00001 VSD per transaction — still negligible for
    # honest users, but enough that an attacker cannot send millions of
    # spam txs for free.
    MIN_TX_FEE_SAT      = 1_000

    # ─────────────────────────────────────────────────────────────────────
    # REWARD SPLIT (v7.1.12 — Option B: clean V2-only)
    # ─────────────────────────────────────────────────────────────────────
    # Distribution applied to (base_reward + tx_fees) on every block:
    #   • 20% → block proposer (the miner who solved PoW)
    #   • 45% → all active miners ∝ hashrate score
    #   • 35% → all active validators ∝ stake
    #   • If NO validators are registered: their 35% rolls into the
    #     all-miners pool → miners share 80% total.
    #
    # No explicit burn.  The integer-division dust (typically 0-2 sat
    # per block) is sent to BURN_ADDRESS so the supply conservation
    # invariant (sum of all credits == base_reward + fees) holds exactly.
    #
    # ⚠️  This is a CONSENSUS RULE.  Changing any of these values forks
    # every chain that has ever applied a block.  Because this binary
    # ships in development-mode where every node operator wipes their
    # database before running, we deploy the new rules from genesis with
    # no activation-height machinery.  If you ever need to change rewards
    # AFTER the chain has gone public, do not edit these constants —
    # implement an activation-height upgrade so historical blocks still
    # validate under their original rules.
    REWARD_CREATOR        = 0.20   # 20% block proposer
    REWARD_ALL_MINERS     = 0.45   # 45% all active miners ∝ hashrate
    REWARD_ALL_VALIDATORS = 0.35   # 35% all validators ∝ stake (else→miners)
    # Consensus-safe miner activity weighting.  Only canonical PoW blocks in
    # this fixed historical window contribute; local H/s and peer reports are
    # deliberately excluded because they are not consensus-deterministic.
    MINER_ACTIVITY_WINDOW = 100   # blocks; recent PoW contribution window
    # Sum: 1.00 — no explicit burn; rounding dust still goes to BURN_ADDRESS.

    # Burn address — coins sent here are irrecoverable
    BURN_ADDRESS        = "VSD_BURN_000000000000000000000000"

    # PoS / staking  (all amounts in satoshi)
    MIN_INVESTOR_STAKE  = 20_000_000_000   # 200.0 VSD in satoshi
    MIN_MINER_STAKE     =    1_000_000_000   #   10.0 VSD in satoshi
    SLASH_RATE          = 0.10             # 10% slash for malicious vote
    # F-01 FIX: BFT threshold as integer millionths to avoid float comparison
    # 2/3 majority = 666_700 / 1_000_000.  Use integer arithmetic:
    # approved_stake_millionths * 1_000_000 >= BFT_THRESHOLD_MILLIONTHS * total
    BFT_THRESHOLD_MILLIONTHS = 666_700     # 66.67% expressed as millionths
    BFT_THRESHOLD       = 0.6667           # kept for legacy display only

    # ─────────────────────────────────────────────────────────────────────────
    # HASHRATE OPTIMIZATION (Optimized vs Actual Hashrate)
    # ─────────────────────────────────────────────────────────────────────────
    # Two hashrate values are tracked per node:
    #   • actual_hashrate    — the raw, unthrottled hashing speed of the miner.
    #                          This is what the hardware can physically produce.
    #   • optimized_hashrate — the locally-applied per-miner cap that keeps
    #                          the network's *aggregate* hashrate close to the
    #                          theoretical hashrate required to mine each
    #                          block in TARGET_BLOCK_TIME ± TARGET_BLOCK_TIME_TOLERANCE.
    #
    # Required network hashrate is the inverse of the difficulty equation:
    #     each hash has probability 2^(-4·D) of solving, so the expected
    #     number of hashes to mine one block is 2^(4·D).  To mine that block
    #     in TARGET_BLOCK_TIME seconds, the network needs:
    #         H_required = 2^(4·D) / TARGET_BLOCK_TIME      (hashes per second)
    #
    # Each miner's individual cap is computed from the network total and its
    # share of the observed actual-hashrate distribution, with a smoothing
    # exponent that gives weaker miners "almost the same" opportunity:
    #     share_i = actual_i ^ HASHRATE_SHARE_EXPONENT
    #     limit_i = H_required × share_i / Σ share_j
    #
    # The cap is enforced LOCALLY by sleeping between hash batches.  It is
    # NOT a consensus rule — block validation, PoW, difficulty, MTP, and
    # state_root checks are unchanged on every node.  Reward distribution
    # also uses the existing miner-score field (proportional to actual
    # hashrate over time), so reward fairness follows real hardware power
    # while the *race speed* is throttled to keep the chain on schedule.
    # ─────────────────────────────────────────────────────────────────────────
    HASHRATE_OPTIMIZATION_ENABLED = True   # master switch
    TARGET_BLOCK_TIME_TOLERANCE   = 5      # seconds — 60 ± 5 s acceptance band
    HASHRATE_SHARE_EXPONENT       = 0.5    # 1.0 = pure proportional, 0.0 = perfectly equal,
                                            # 0.5 = sqrt-weighted (almost-same opportunity)
    HASHRATE_REPORT_INTERVAL      = 5      # seconds between actual-hashrate
                                            # broadcasts.  Tuned down from
                                            # 30 → 5 in v7.6.0 so a freshly-
                                            # connected miner's first report
                                            # reaches the network within a few
                                            # seconds, letting the governor
                                            # activate during early blocks
                                            # instead of waiting 30 s for the
                                            # first peer-rate sample.  Bandwidth
                                            # cost is negligible (~150 B per
                                            # peer per 5 s = 30 B/s/peer).
    HASHRATE_PEER_TTL             = 300    # seconds before a peer's hashrate report is
                                            # considered stale and dropped from the registry
    # ── v7.6.4 Decay-on-silence ──────────────────────────────────────────────
    # When a peer's reports stop arriving (paused miner, hung process, etc.)
    # but its TCP connection remains alive, the simple TTL would let its
    # claimed hashrate inflate the network total for HASHRATE_PEER_TTL
    # seconds.  Decay-on-silence solves this gracefully:
    #
    #   age ≤ HASHRATE_FRESH_SECS            → use the report value as-is
    #   HASHRATE_FRESH_SECS < age ≤ TTL      → linearly decay toward zero
    #   age > TTL                            → drop the report entirely
    #
    # Defaults are tuned to absorb 6× the report interval before any decay
    # starts (30 s vs 5 s reports), then ramp down over the next 60 s.  A
    # genuinely-paused miner stops contributing within ~90 s; a healthy miner
    # whose report is briefly delayed by network jitter sees no change.
    HASHRATE_FRESH_SECS           = 30     # age (s) below which report is taken at face
    HASHRATE_DECAY_SECS           = 60     # additional age (s) over which report decays
                                            # to zero.  Total drop-out at
                                            # HASHRATE_FRESH_SECS + HASHRATE_DECAY_SECS = 90s.
    HASHRATE_MIN_FLOOR            = 1.0    # H/s — minimum cap so a miner is never starved
    HASHRATE_THROTTLE_BATCH_SIZE  = 1024   # nonces hashed per throttle pause
    HASHRATE_HEADROOM_FACTOR      = 1.00   # multiplier on H_required when computing
                                            # the budget.  v7.6.3 — set to 1.00.
                                            # Earlier versions used 1.10 thinking
                                            # "10% headroom absorbs variance"; in
                                            # practice this caused a SYSTEMATIC
                                            # undershoot of TARGET_BLOCK_TIME.
                                            # Math: in equilibrium the difficulty
                                            # engine adjusts D until expected
                                            # solve time at the cap == TARGET.
                                            # If cap = required × 1.10, then
                                            # equilibrium settles at TARGET / 1.10
                                            # = 54.5s (for a 60s target), not
                                            # 60s.  Setting headroom to 1.00 lets
                                            # the difficulty engine and the
                                            # throttle converge at the actual
                                            # target.  Variance is handled by
                                            # the LWMA window itself, which is
                                            # already designed for it.

    # ─────────────────────────────────────────────────────────────────────────
    # MINING SAFETY GUARD — robustness during bootstrap, reconnect, and stalls.
    # ─────────────────────────────────────────────────────────────────────────
    # Four scenarios this guard addresses:
    #   1. The local node has been offline for a long time, comes back, and
    #      the chain tip is far ahead.  Mining on a stale tip would produce
    #      blocks that the network rejects.  The guard requires that the
    #      node is "synced" (highest known peer height ≤ local + tolerance)
    #      before mining starts.
    #   2. A reconnecting node finds peers whose chain height is so far
    #      ahead that block-by-block sync would take forever.  In this case
    #      the guard triggers fast-sync (snapshot) instead.
    #   3. A block download stalls during live mining (peer unresponsive).
    #      The guard times out the request and rotates to another peer.
    #   4. Mining runs for a very long time without finding a block (e.g.
    #      stale candidate, difficulty mismatch).  The guard cancels the
    #      current attempt and rebuilds the candidate against the latest
    #      tip.  This prevents the miner from wasting cycles on an outdated
    #      header.
    # All checks here are LOCAL-ONLY — no consensus rules are altered.
    # ─────────────────────────────────────────────────────────────────────────
    MINING_SAFETY_ENABLED              = True
    MINING_SYNC_REQUIRED_BEFORE_MINE   = True
    MINING_SYNC_HEIGHT_TOLERANCE       = 3        # blocks of slack vs best known peer
    MINING_FAR_BEHIND_THRESHOLD        = 200      # blocks behind ⇒ trigger fast-sync first
    MINING_STALE_CANDIDATE_TIMEOUT     = 240      # 4× target — mining-no-progress watchdog
    MINING_BLOCK_DOWNLOAD_TIMEOUT      = 30       # seconds before retrying GET_BLOCK from another peer
    MINING_SYNC_PROBE_INTERVAL         = 5        # seconds between sync-status checks while waiting
    MINING_SYNC_MAX_WAIT               = 600      # absolute cap on pre-mine sync wait (seconds)

    # Slashing: nothing-at-stake detection window
    SLASH_WINDOW        = 10            # check last N blocks for double-sign

    # ─────────────────────────────────────────────────────────────────────────
    # RATE DEFECTION AUDIT (v7.7.0)
    # ─────────────────────────────────────────────────────────────────────────
    # Statistical detection of miners that ignore the local hashrate throttle
    # and produce blocks faster than their share-of-the-budget should allow.
    # This is the consensus-level enforcement layer that complements the
    # local-only HashrateGovernor (which is honor-system).
    #
    # Detection math
    # ──────────────
    # Over a rolling window of W blocks, for each miner with share ≥ MIN_AUDIT_SHARE:
    #     expected_wins = W × (their_cap / total_cap)
    #     actual_wins   = blocks they actually mined in the window
    #     ratio         = actual_wins / expected_wins
    # If ratio > THRESHOLD over CONSECUTIVE windows, they are slashed.
    #
    # Conservative tuning
    # ───────────────────
    # A miner with 10% expected share over W=500 blocks wins 50 ± 7 blocks
    # naturally (binomial, 1σ).  THRESHOLD=2.0 means 100 wins to flag, which
    # is ~7σ above the mean.  Probability of an honest miner false-positiving
    # in a single window: < 1 in 10^11.  Requiring 3 consecutive flagged
    # windows pushes false-positive rate to effectively zero.
    #
    # Sustained-defection detection time
    # ──────────────────────────────────
    # 3 windows × 500 blocks × 60 s = ~25 hours to slash a defector.  Faster
    # detection requires either smaller windows (more variance, more false
    # positives) or higher thresholds (less sensitivity).  25 h is the
    # right tradeoff for "frictionless to honest miners."
    #
    # Observe-only initial deployment
    # ───────────────────────────────
    # AUTO_SLASH_RATE_DEFECTION starts False.  In observe mode the audit
    # runs every cycle, logs would-be-slashed addresses, and broadcasts
    # advisory evidence — but no actual slashing fires.  Operators run the
    # network for several weeks in observe mode, verify no false positives
    # in the logs, then flip the flag to True via config and a coordinated
    # network restart.  This is the only way to safely tune statistical
    # thresholds against real-world data.
    AUTO_SLASH_RATE_DEFECTION       = False    # initial deployment: observe only
    RATE_AUDIT_WINDOW               = 500      # blocks per audit window
    RATE_AUDIT_CADENCE              = 50       # run audit every N blocks
    RATE_AUDIT_THRESHOLD            = 2.0      # ratio above which a miner is flagged
    RATE_AUDIT_CONSECUTIVE          = 3        # consecutive flagged windows to slash
    RATE_AUDIT_MIN_SHARE            = 0.03     # 3% minimum share to be auditable
    RATE_AUDIT_VERIFY_TOLERANCE     = 0.10     # 10% slack in independent verification
    RATE_AUDIT_OFFENSE_DECAY_BLOCKS = 10000    # offense counter halves every N blocks

    # Slashing schedule for rate defection (multiplicative on stake/score):
    #   1st offense: 5%
    #   2nd offense: 25%
    #   3rd offense: 75%
    #   4th+ offense: permanent ban (entry added to RATE_DEFECTION_BANS)
    RATE_SLASH_SCHEDULE = [0.05, 0.25, 0.75]    # >3 → ban

    # Finality: PoW-only confirmation depth (when no investors registered)
    # SEC-FIX H-04 (Bootstrap Finality Depth)
    # ───────────────────────────────────────
    # Steady-state finality stays at 6 confirmations.  Until the validator
    # set has reached MIN_VALIDATORS_FOR_BFT, _maybe_finalize_by_depth uses
    # BOOTSTRAP_POW_FINALITY_DEPTH instead — a much deeper confirmation
    # depth — because the chain is exposed to a 51% rewrite attack while
    # PoW is the sole finality source AND validators have not yet staked.
    POW_FINALITY_DEPTH            = 6   # 6 confirmations — steady state
    BOOTSTRAP_POW_FINALITY_DEPTH  = 20  # used while validators < MIN_VALIDATORS_FOR_BFT

    # F-09 FIX: Minimum validators required before BFT mode is considered active
    MIN_VALIDATORS_FOR_BFT = 3          # require at least 3 validators for BFT finality

    # HT (High Transactor) — amounts in satoshi
    HT_VOLUME_THRESHOLD = 100_000_000_000  # 1000.0 VSD in satoshi
    HT_WINDOW_BLOCKS    = 100

    # Network
    DEFAULT_PORT        = 8338
    # ── Outbound Port Enforcement ────────────────────────────────────────────
    # FORCE_OUTBOUND_DEST_PORT = False (fixed default).
    #
    # The advertised port from Peer Exchange / DNS seeds is used as-is.
    # This is correct for IPv6 peers (which are publicly routable and always
    # advertise their real listen port) and for IPv4 peers that have proper
    # port-forwarding configured.
    #
    # For IPv4 peers behind CGNAT, _connect_with_fallback() tries the
    # advertised port first and then automatically retries on DEFAULT_PORT
    # if the first attempt fails — giving the best of both worlds without
    # silently overriding every operator-specified non-standard port.
    #
    # Set to True only if every node in your private test network listens
    # on DEFAULT_PORT and you want to hard-enforce that invariant.
    FORCE_OUTBOUND_DEST_PORT = False

    # Dual-stack bind: '::' listens on all IPv4 AND IPv6 interfaces when
    # IPV6_V6ONLY is cleared to 0.  '::1' is the IPv6 loopback address.
    BIND_ADDRESS        = "::"          # replaces 0.0.0.0 — dual-stack
    LOOPBACK_ADDRESS    = "::1"         # replaces 127.0.0.1 for self-checks
    MAX_PEERS           = 30
    # SEC-FIX H-03 (Sybil Resistance — Peer Hashcash)
    # ───────────────────────────────────────────────
    # MAJOR-09: hashcash PoW for initial peer connections.
    # Connecting nodes must find a nonce such that
    #   SHA-256(challenge || nonce_hex) starts with PEER_POW_DIFFICULTY zero bits.
    #
    # Lowered from 22 → 19 bits in v11.0.0.  Cost analysis:
    #   16 bits → ~65k    hashes (~5 ms on a phone)        — cheap to spam
    #   19 bits → ~524k   hashes (~0.04–0.1 s on a phone)  — fast + meaningful
    #   22 bits → ~4.2M   hashes (~0.3–1 s on a phone)     — was too slow
    # 19 bits keeps connect latency under 100 ms for honest peers while
    # making Sybil identity generation ~512× more expensive than 16 bits.
    # Sybil attack with 1000 fake peers still needs ~512 M hashes — expensive.
    #
    # Adaptive boost: when the per-IP / per-subnet incoming-connection rate
    # spikes (network treats it as an attack) PEER_POW_DIFFICULTY_ADAPTIVE
    # is added on top.  See PeerConnection.choose_peer_pow_difficulty().
    PEER_POW_DIFFICULTY            = 19
    PEER_POW_DIFFICULTY_ADAPTIVE   = 4    # +bits when burst detected
    PEER_POW_BURST_RATE_PER_MIN    = 30   # connects/min from one /24 (or /48 v6)
                                          # before adaptive boost kicks in
    MIN_PEERS           = 3    # BUG-FIX: was 15 — caused constant reconnect
                               # hammering on small networks with only 1-2 real
                               # peers, producing the CONNECTING→FAILED→CONNECTING
                               # cycle visible in the dashboard.
    PEER_STORAGE        = 1000
    GOSSIP_TTL          = 8
    PEER_TIMEOUT        = 15           # seconds
    PEER_MAX_FAIL       = 3
    PEER_DECAY_SECS     = 3600
    PEX_INTERVAL        = 60
    RECONNECT_INTERVAL  = 30
    KAD_K               = 20            # k-bucket size
    KAD_BITS            = 160

    # DoS / Bandwidth protection
    MAX_MESSAGE_SIZE    = 1_073_741_824 # 1 GB — was 16 MB which was too small
                                        # for 200-block MSG_CHAIN sync responses
                                        # (~8 KB/block × 200 = ~1.6 MB typical,
                                        # up to ~12 MB with full transactions).
                                        # Old value caused large syncs to trigger
                                        # "oversized frame" bans, permanently
                                        # disconnecting peers mid-sync.
    MAX_PEER_BANDWIDTH  = 10_485_760    # 10 MB/s per peer (bytes/sec)
    PEER_BAN_SCORE_THRESHOLD = 100      # ban peer when ban score reaches this
    PEER_SCORE_INVALID_MSG   = 10       # ban points for each invalid message
    PEER_SCORE_OVERSIZED_MSG = 50       # ban points for oversized message
    PEER_SCORE_SYNC_TIMEOUT  = 5        # ban points for zombie-peer sync timeout
                                        # (v7.0.1.0): light penalty — timeout may
                                        # be caused by a flaky link, not malice.
                                        # Repeated timeouts from the same peer
                                        # accumulate and eventually trigger a ban.
    PEER_SCORE_RATE_LIMIT_HARD = 20     # v7.1.0: ban points for >2× msg-rate
                                        # overshoot.  100/20 = 5 hard breaches
    # An application frame is newline-delimited JSON.  A peer is allowed to
    # stream a frame over multiple TCP segments, but an unterminated frame must
    # have both a byte and an absolute-age bound.  This is intentionally much
    # smaller than MAX_MESSAGE_SIZE: complete legacy messages retain the larger
    # compatibility ceiling, while a malicious peer cannot reserve hundreds of
    # megabytes simply by never sending the final '\n'.
    MAX_PARTIAL_FRAME_BYTES = int(os.environ.get(
        "VISOLD_MAX_PARTIAL_FRAME_BYTES", str(32 * 1024 * 1024)))
    MAX_PARTIAL_FRAME_AGE_SECS = float(os.environ.get(
        "VISOLD_MAX_PARTIAL_FRAME_AGE_SECS", "120"))
    MAX_FORK_SYNC_BLOCKS = int(os.environ.get(
        "VISOLD_MAX_FORK_SYNC_BLOCKS", "10000"))
    MAX_FORK_SYNC_BYTES = int(os.environ.get(
        "VISOLD_MAX_FORK_SYNC_BYTES", str(64 * 1024 * 1024)))
                                        # before auto-blacklist.
    PEER_SCORE_DECAY_INTERVAL = 600     # seconds before ban score decays by half

    # Chain sync watchdog (v7.0.1.0 — Bug 3 fix)
    # If a page request (MSG_GET_CHAIN) from _apply_chain_direct() is not
    # answered within this many seconds, the peer is considered zombie and
    # the request is re-issued to an alternate connected peer.
    CHAIN_SYNC_TIMEOUT_SECS = 30        # seconds before sync watchdog fires

    # SQLite busy timeout (v7.0.1.0 — Bug 1 fix)
    # WAL mode allows only one writer at a time.  Without a busy_timeout,
    # a second connection that tries to commit while another is mid-write
    # receives an immediate OperationalError: database is locked.  Setting
    # this to 5000 ms gives SQLite up to 5 s to retry internally, handling
    # all transient lock contention between the networking threads (save_peer,
    # add_ban_score, mark_peer_fail) and the block-apply threads (save_block).
    SQLITE_BUSY_TIMEOUT_MS  = 5000 
    MSG_GET_BLOCK_MANIFEST = "GET_BLOCK_MANIFEST"
    MSG_BLOCK_MANIFEST     = "BLOCK_MANIFEST"
    MSG_GET_BLOCK_CHUNK    = "GET_BLOCK_CHUNK"
    MSG_BLOCK_CHUNK_DATA   = "BLOCK_CHUNK_DATA"

     # milliseconds

    # TLS
    TLS_ENABLED         = True          # wrap all P2P sockets with TLS
    TLS_CERT_FILE       = ""            # set at runtime (in DATA_DIR)
    TLS_KEY_FILE        = ""            # set at runtime (in DATA_DIR)
    TLS_CERT_VALIDITY_DAYS = 90         # VSD-H06 FIX: 90-day rotation (was 10 years)
    # SEC-FIX M-01 (TLS First-Joiner Pinning)
    # ────────────────────────────────────────
    # Operator-pinned bootstrap fingerprints distributed out-of-band (e.g.
    # printed in release notes, signed in a release announcement, or
    # embedded in this file by the network operator).  Format:
    #     { "ip-or-host": "sha256-cert-fingerprint-hex", ... }
    # When non-empty, TLSManager preloads these into _ip_fp_store at startup
    # so the very first TLS connection from a fresh node is authenticated
    # against the operator's pin instead of TOFU-trusting whatever cert is
    # presented.  Empty by default — networks that don't ship pins fall back
    # to plain TOFU exactly as before.
    TLS_BOOTSTRAP_FINGERPRINTS: Dict[str, str] = {}

    # Transaction
    TX_DEFAULT_EXPIRY_SECS = 3600       # 1 hour expiry if not set
    TX_MAX_EXPIRY_SECS     = 86400      # 24 hours max

    # Protocol versioning / fork signaling
    PROTOCOL_VERSION       = 1          # current protocol version
    FORK_SIGNAL_WINDOW     = 100        # blocks to count signaling over
    FORK_SIGNAL_THRESHOLD  = 0.75       # 75% miners must signal for soft fork

    # ── Consensus resource/economic hardening activations ───────────────────
    # Fresh chains use 0 so the secure rules apply from genesis.  A live chain
    # that already contains pre-fix history must coordinate a future height
    # across miners/validators before enabling these rules, preventing a node
    # upgrade from retroactively rejecting already-finalized blocks.
    ROLE_STAKE_MIN_ACTIVATION_HEIGHT: int = 0
    VVM_BLOCK_GAS_LIMIT_ACTIVATION_HEIGHT: int = 0

    # ── v7.1.17 TX-ID V2 ACTIVATION HEIGHT ───────────────────────────────────
    # Blocks at height >= this value use the V2 tx_id rule: sha256(full data)
    # instead of data[:64].  Blocks below this height keep the V1 rule so that
    # historical merkle_roots and block_hashes remain valid and every existing
    # chain can upgrade without a database wipe.
    #
    # Set to 0 if this is a FRESH chain with no existing history (all blocks
    # will use the secure V2 rule from genesis).
    # Set to a future block height on any LIVE chain so that nodes have time to
    # upgrade before the activation height is reached.
    #
    # Why this is safe:
    #   • V1 blocks (height < activation): _compute_id uses data[:64] — identical
    #     to the pre-fix behaviour; all stored merkle_roots stay valid.
    #   • V2 blocks (height >= activation): _compute_id uses sha256(full data);
    #     collision-resistance is fully restored.
    #   • Both Mempool.add() and Block.integrity_check() pass the block height to
    #     _compute_id so they always apply the correct rule for that block.
    TXID_V2_ACTIVATION_HEIGHT = 0  # change to a future height on live chains

    # SEC-FIX H-01 (Merkle Duplicate-Leaf Hardening)
    # ──────────────────────────────────────────────
    # Activation height for the v2 Merkle rule.  Below this height the
    # legacy CVE-2012-2459-style construction (duplicate the last hash on
    # odd levels) is used so historical block_hashes remain valid.  At and
    # above this height the secure rule is used: odd-level loners are
    # promoted with a domain-separator tag, eliminating the
    # same-root-different-txs collision class entirely.
    #
    # Set to 0 on FRESH chains (recommended) so all blocks use the secure
    # rule from genesis.  Set to a future height on LIVE chains.
    MERKLE_V2_ACTIVATION_HEIGHT = 0

    # SEC-FIX H-02 (Truncated tx_id Hardening)
    # ────────────────────────────────────────
    # When False (default for fresh chains), the legacy V1 tx_id rule
    # (data[:64] truncation) is REJECTED outright at _compute_id time —
    # callers must pass a block_height that resolves to the V2 rule.  Set
    # this to True only on LIVE chains that already have V1-mined history
    # to validate; new chains should leave it False so the truncated rule
    # is unreachable in practice.
    TXID_V1_LEGACY_ENABLED = False

    # SEC-FIX H-03 (Ambiguous Transaction Encoding)
    # Canonical V3 signing/tx-id encoding uses explicit field boundaries and
    # canonical integer economic values. New transactions always use V3.
    # Historical pre-V3 blocks may be revalidated only while both the explicit
    # legacy switch is enabled and their height is below this activation gate.
    # Fresh chains keep the secure defaults below and therefore never accept
    # the ambiguous pre-V3 format.
    TXID_CANONICAL_V3_ACTIVATION_HEIGHT = 0
    TXID_CANONICAL_V2_LEGACY_ENABLED = False

    # SC-NAME-1 ── Contract naming activation & limits ─────────────────────────
    # Set CONTRACT_NAMING_ACTIVATION_HEIGHT = 0 for fresh chains.
    # Live chains: pick a future block height and coordinate the upgrade.
    CONTRACT_NAMING_ACTIVATION_HEIGHT: int = 0
    VVM_CONTRACT_NAME_MAX_LEN: int         = 64

    # AUDIT-FIX-11 ── Strict nonce-sequencing activation ────────────────────────
    # Set NONCE_STRICT_ACTIVATION_HEIGHT = 0 for fresh chains, so the check is
    # active from genesis. Live chains with existing history: pick a future
    # block height and coordinate the upgrade, in case any already-accepted
    # historical block relied on the previously-lenient nonce handling (a gap
    # or a reused nonce that happened to be silently accepted). Below this
    # height, validate_block skips the strict nonce check entirely, matching
    # pre-fix behavior for re-validation of old blocks during a resync.
    NONCE_STRICT_ACTIVATION_HEIGHT: int    = 0

    # AUDIT-FIX-14 ── expiry=0 required for ordinary transactions ──────────────
    # expiry == 0 means "never expires" (Transaction.is_expired()), correct
    # and intentional for COINBASE/genesis but never validated as REQUIRED to
    # be non-zero for ordinary user transactions. Combined with pruning
    # (Storage.prune_old_data / RollingWindowPruner) deleting old rows from
    # the `transactions` table that tx_exists() depends on for replay
    # protection, an expiry=0 transaction becomes replayable indefinitely
    # once its row is pruned — see AUDIT-FIX-14's permanent replay-guard
    # table for the other half of this fix. Set to 0 for fresh chains.
    EXPIRY_REQUIRED_ACTIVATION_HEIGHT: int = 0

    # ── State Engine (Concurrency) ────────────────────────────────────────────
    # Maximum number of events in the StateEngine queue before back-pressure
    # is applied (callers block on post()).  4096 gives ample headroom even
    # under heavy load while bounding memory use.
    STATE_ENGINE_QUEUE_SIZE   = 4096
    # Seconds to wait for a synchronous event result before timeout
    STATE_ENGINE_SYNC_TIMEOUT = 30.0

    # ── Governance / Upgrade Lifecycle ───────────────────────────────────────
    # Number of blocks after lock-in before the new rules activate.
    # Gives nodes time to upgrade software before enforcement.
    GOVERNANCE_ACTIVATION_DELAY  = 100
    # Blocks after activation to watch for failure before rollback window closes
    GOVERNANCE_ROLLBACK_WINDOW   = 100
    # If invalid_block_rate exceeds this fraction in the rollback window, revert
    GOVERNANCE_ROLLBACK_INVALID_RATE = 0.20
    # Blocks without BFT finality that trigger a rollback
    GOVERNANCE_FINALITY_TIMEOUT  = 20
    # Lock-in delay: once threshold is hit at height H, lock-in is at H+1
    # and activation is at H+1+ACTIVATION_DELAY.  This is deterministic so
    # all nodes compute the same activation_height without coordination.

    # Economic security
    REWARD_CONCENTRATION_ALERT = 0.40   # alert if >40% rewards go to one address
    COLLUSION_SIG_OVERLAP      = 0.80   # alert if >80% of sigs come from same group

    # ── Solo Mining Mode ──────────────────────────────────────────────────────
    # When True, ALL economic attack alerts (reward concentration, selfish
    # mining) are fully suppressed regardless of peer count or miner diversity.
    # Use this when you are intentionally the sole miner on a live network and
    # do not want any false-positive attack alerts.  When False (default), the
    # refined bootstrap guard (unique_miners_in_last_100_blocks < 2) controls
    # suppression automatically so alerts only fire when competition exists.
    # Override via environment variable: VISOLD_SOLO_MINING_MODE=1
    SOLO_MINING_MODE = os.environ.get("VISOLD_SOLO_MINING_MODE", "0") == "1"

    # DHT / Identity
    DHT_TTL             = 86400         # 1 day
    LRU_CACHE_SIZE      = 512

    # Storage
    DATA_DIR            = os.environ.get("VISOLD_DATA_DIR",
                            os.path.expanduser("~/.visold"))
    DB_PATH             = ""            # set in ensure_dirs()
    PEERS_FILE          = ""
    WALLET_FILE         = ""
    KEYSTORE_FILE       = ""
    SIG_FILE            = ""
    KEY_FILE            = ""
    GENESIS_HASH_FILE   = ""

    # ── Database Backend Selection ────────────────────────────────────────────
    # When the blockchain grows to millions of blocks, SQLite block storage
    # becomes a bottleneck (large data_json BLOBs, sequential scans).
    # Switch to a high-performance key-value database for block data:
    #
    #   "sqlite"   — default; no extra install needed
    #   "leveldb"  — fast reads/writes; install: pip install plyvel
    #   "rocksdb"  — higher write throughput + compression; install: pip install rocksdict (PGX) or python-rocksdb (legacy)
    #
    # Override via environment variable: VISOLD_DB_BACKEND=leveldb
    # SQLite is always used for relational data (balances, roles, peers, etc.)
    # Only block storage (data_json) moves to the KV backend.
    DB_BACKEND          = os.environ.get("VISOLD_DB_BACKEND", "sqlite")
    LEVELDB_PATH        = ""            # set in ensure_dirs()
    ROCKSDB_PATH        = ""            # set in ensure_dirs()

    # Seed nodes (bootstrap — hardcoded fallback)
    # F-06 FIX: Multiple geographically diverse seeds; no single point of failure.
    # Static seed addresses remain opt-in through VISOLD_SEED_PEERS or config.
    SEED_PEERS = []

    # DNS Seeds — queried immediately at startup and periodically thereafter.
    # The previous V2 file left this list empty, so a fresh node never attempted
    # the DuckDNS bootstrap path.  The DuckDNS hostname is dual-stack: DNSSeeder
    # uses getaddrinfo(AF_UNSPEC), registers IPv6 results first, and P2PNetwork
    # dials them with AF_INET6.  Override with VISOLD_DNS_SEEDS or config.json.
    _DEFAULT_DNS_SEEDS = "visoldcrypto2026.duckdns.org"
    DNS_SEEDS = [s.strip() for s in os.environ.get(
        "VISOLD_DNS_SEEDS", _DEFAULT_DNS_SEEDS).split(",") if s.strip()]
    DNS_SEED_PORT = int(os.environ.get("VISOLD_DNS_SEED_PORT", str(DEFAULT_PORT)))
    DNS_SEED_INTERVAL = int(os.environ.get("VISOLD_DNS_SEED_INTERVAL", "600"))


    # UPnP NAT traversal
    UPNP_ENABLED         = True
    UPNP_LEASE_SECONDS   = 3600
    UPNP_RENEW_INTERVAL  = 3500

    # ── Fix #8: Time / Synchronization ───────────────────────────────────────
    # The consensus layer uses block timestamps for difficulty adjustment and
    # finality timeout detection.  Clock skew across nodes can cause:
    #   • False timestamp rejections (MTP check), degrading liveness
    #   • Artificially inflated or deflated block intervals, causing
    #     difficulty oscillation
    #
    # Controls:
    #   CLOCK_MAX_DRIFT_SECS   — maximum observed peer timestamp divergence
    #     before a warning is emitted.  Blocks within ±DIFF_MAX_FUTURE_DRIFT
    #     are always accepted; this is the tighter "warn" threshold.
    #   CLOCK_PEER_SAMPLE_SIZE — number of recent peer timestamps to collect
    #     for network time estimation.
    #   CLOCK_UPDATE_INTERVAL  — how often (seconds) the network clock
    #     estimate is refreshed from peer timestamps.
    CLOCK_MAX_DRIFT_SECS   = 30    # warn if node clock drifts > 30s from median
    CLOCK_PEER_SAMPLE_SIZE = 16    # peer timestamps kept for median estimate
    CLOCK_UPDATE_INTERVAL  = 60    # seconds between network clock updates

    # ── ICE / NAT traversal (STUN + UDP hole punching + TURN relay) ───────────
    ICE_ENABLED          = True
    # Primary STUN server (Google public STUN — RFC 5389)
    STUN_SERVERS         = [
        ("stun.l.google.com",  19302),
        ("stun1.l.google.com", 19302),
        ("stun.cloudflare.com", 3478),
    ]
    # UDP hole punching
    ICE_HOLE_PUNCH_ATTEMPTS  = 10
    ICE_HOLE_PUNCH_INTERVAL  = 0.25   # seconds between each send burst
    ICE_HOLE_PUNCH_TIMEOUT   = 8.0    # total seconds to wait for response
    ICE_KEEPALIVE_INTERVAL   = 15     # seconds between UDP keepalive pings
    # TURN relay fallback
    TURN_ENABLED         = True
    AUTO_RELAY           = True       # auto-start relay_server.py if needed
    RELAY_PORT_OFFSET    = 2          # relay listens on node_port + 2
    NODE_STATUS_FILE     = ""         # set at runtime in DATA_DIR
    # ICE candidate priority weights (higher = preferred)
    ICE_PRIORITY_HOST    = 126
    ICE_PRIORITY_SRFLX   = 100
    ICE_PRIORITY_RELAY   = 0

    # Mempool
    MEMPOOL_MAX         = 5000

    # VRF
    VRF_SEED_LEN        = 32

    # WAL checkpoint frequency (pages)
    WAL_CHECKPOINT_PAGES = 1000

    # JSON-RPC
    RPC_PORT_OFFSET     = 1            # node_port + 1

    # Logging
    LOG_FORMAT          = os.environ.get("VISOLD_LOG_FORMAT", "text")  # "text" or "json"

    # ── VVM (Visold Virtual Machine) ──────────────────────────────────────────
    # Maximum gas allowed per contract execution call or deploy
    VVM_BLOCK_GAS_LIMIT    = 10_000_000_000  # max total gas per block for all VVM txs (1000x)
    VVM_TX_GAS_CAP         = 5_000_000_000  # hard cap per single transaction (1000x)
    VVM_MIN_GAS_PRICE      = 0.000_000_01   # min gas price in VSD (10^-8)
    VVM_MAX_CALL_DEPTH     = 1024           # max contract-to-contract call depth
    VVM_MAX_MEMORY_BYTES   = 1_048_576      # 1 MB hard memory cap per frame
    VVM_MAX_STACK_DEPTH    = 1024           # EVM-compatible stack depth limit
    VVM_MAX_BYTECODE_SIZE  = 24_576         # 24 KB max deployed bytecode (EIP-170)
    VVM_DEPLOY_GAS_BASE    = 32_000         # base gas for CREATE/DEPLOY
    VVM_GAS_PER_BYTE_CODE  = 200            # gas per byte of deployed bytecode

    # ── P2P Message Compression ───────────────────────────────────────────────
    # Compresses P2P frames above COMPRESS_THRESHOLD bytes using zstd (preferred)
    # or zlib (stdlib fallback).  Reduces bandwidth at high transaction volumes.
    COMPRESSION_ENABLED   = True
    COMPRESS_THRESHOLD    = 512    # bytes — only compress frames above this size
    COMPRESS_MAGIC        = b'\xc0\xde'  # 2-byte magic prefix identifies compressed frames

    # ── Peer Reputation Score Persistence ────────────────────────────────────
    # Long-term reputation score tracks "good behavior" over months.
    # Used to prioritize high-quality peers during network congestion.
    REPUTATION_DECAY_FACTOR       = 0.99   # per-hour decay toward neutral
    REPUTATION_GOOD_BLOCK_BONUS   = 0.05   # bonus per valid block propagated quickly
    REPUTATION_GOOD_TX_BONUS      = 0.005  # bonus per valid tx forwarded
    REPUTATION_FAST_BLOCK_SECS    = 5.0    # block received within N seconds = "fast"
    REPUTATION_PERSIST_INTERVAL   = 600    # persist reputation to DB every N seconds

    # ── DiscV5-style Capability Topic Discovery ───────────────────────────────
    # Nodes advertise capabilities in HELLO; peers with matching capabilities
    # are preferred for specific query types (archive data, VVM execution, etc.)
    NODE_CAPABILITIES = os.environ.get(
        "VISOLD_CAPABILITIES", "full_node,vvm").split(",")
    CAPABILITY_DISCOVERY_INTERVAL = 120   # seconds between capability refreshes

    # ── State Tree Pruning ────────────────────────────────────────────────────
    # Prunes historical state snapshots (account balances/contract storage) that
    # are no longer needed to verify the current chain tip.
    STATE_PRUNE_ENABLED        = os.environ.get("VISOLD_STATE_PRUNE", "0") == "1"
    STATE_PRUNE_KEEP_SNAPSHOTS = 128   # keep last N state snapshots
    STATE_PRUNE_INTERVAL       = 1000  # prune every N blocks

    # ── Rolling Window Pruning (v7.4.0) ──────────────────────────────────────
    # Standard nodes only keep full block bodies + transactions for the last
    # PRUNE_WINDOW blocks.  Older data is pruned from the DB; only the slim
    # block header row (hash, prev_hash, merkle_root, state_root, timestamp,
    # difficulty, nonce) is retained for cryptographic chain integrity.
    # Set ROLLING_PRUNE_ENABLED=1 env var to activate.
    ROLLING_PRUNE_ENABLED      = os.environ.get("VISOLD_ROLLING_PRUNE", "1") == "1"
    ROLLING_PRUNE_WINDOW       = int(os.environ.get("VISOLD_PRUNE_WINDOW", "600"))
    ROLLING_PRUNE_INTERVAL     = 50    # check every N new blocks (low overhead)
    ROLLING_PRUNE_BATCH        = 100   # max blocks pruned per pass
    # Selective Archive: transactions with amount >= this value (float VSD)
    # are preserved in permanent_history before pruning.
    # Default: 100 VSD.  Override: VISOLD_ARCHIVE_THRESHOLD=<float_vsd>
    ROLLING_PRUNE_ARCHIVE_THRESHOLD = float(
        os.environ.get("VISOLD_ARCHIVE_THRESHOLD", "100.0")
    )

    # ── State Snapshot Engine (v7.4.0) ────────────────────────────────────────
    # At every SNAPSHOT_INTERVAL blocks, a full compressed binary snapshot of
    # the account/contract state is serialised and stored in node_meta.
    # New nodes can fast-sync by downloading the latest snapshot instead of
    # replaying the entire chain from genesis.
    SNAPSHOT_ENABLED           = os.environ.get("VISOLD_SNAPSHOT", "1") == "1"
    SNAPSHOT_INTERVAL          = int(os.environ.get("VISOLD_SNAPSHOT_INTERVAL", "600"))
    SNAPSHOT_KEEP              = int(os.environ.get("VISOLD_SNAPSHOT_KEEP", "3"))
    SNAPSHOT_FAST_SYNC_ENABLED = os.environ.get("VISOLD_FAST_SYNC", "1") == "1"
    SNAPSHOT_FAST_SYNC_MIN_HEIGHT = 600   # only attempt fast-sync on chains >= this height
    CAP_SNAPSHOT               = "snapshot"  # capability advertised by snapshot-serving nodes

    # ── Parallel Multi-Peer Snapshot Sync (v7.5.0) ───────────────────────────
    SNAPSHOT_CHUNK_SIZE         = int(os.environ.get("VISOLD_CHUNK_SIZE",    str(1 * 1024 * 1024)))  # 1 MB
    SNAPSHOT_MAX_PARALLEL_PEERS = int(os.environ.get("VISOLD_SYNC_PEERS",    "8"))
    SNAPSHOT_CHUNK_TIMEOUT      = int(os.environ.get("VISOLD_CHUNK_TIMEOUT", "30"))  # seconds/chunk
    SNAPSHOT_CHUNK_MAX_RETRIES  = int(os.environ.get("VISOLD_CHUNK_RETRIES", "3"))
    # A snapshot is a state shortcut, not a trust anchor.  Only restore one
    # when the receiver can bind it to a block header already present in its
    # own canonical chain/header store.  A fresh node therefore falls back to
    # ordinary block sync instead of accepting a peer-supplied state root.
    SNAPSHOT_REQUIRE_LOCAL_ANCHOR = os.environ.get(
        "VISOLD_SNAPSHOT_REQUIRE_LOCAL_ANCHOR", "1") == "1"
    SNAPSHOT_MAX_UNCOMPRESSED_BYTES = int(os.environ.get(
        "VISOLD_SNAPSHOT_MAX_UNCOMPRESSED_BYTES", str(256 * 1024 * 1024)))

    # ── MEV Protection (Commit-Reveal) ────────────────────────────────────────
    # When enabled, transactions are committed as a hash first, then revealed
    # after COMMIT_REVEAL_DELAY_BLOCKS blocks.  Prevents front-running.
    MEV_PROTECTION_ENABLED      = os.environ.get("VISOLD_MEV_PROTECT", "0") == "1"
    COMMIT_REVEAL_DELAY_BLOCKS  = 3    # VSD-M05 FIX: 3-block delay (was 1) to prevent miner front-running

    # ── Automated Slashing Evidence ───────────────────────────────────────────
    # When a double-sign is detected, automatically submit evidence to the network
    # to trigger slashing without manual operator intervention.
    AUTO_SLASH_EVIDENCE = True   # auto-broadcast double-sign proofs

    # ── Sentinel / High-Availability ─────────────────────────────────────────
    # Sentinel mode: backup node monitors primary and auto-takes-over on failure.
    SENTINEL_MODE          = os.environ.get("VISOLD_SENTINEL", "0") == "1"
    SENTINEL_PRIMARY_HOST  = os.environ.get("VISOLD_PRIMARY_HOST", "127.0.0.1")
    SENTINEL_PRIMARY_PORT  = int(os.environ.get("VISOLD_PRIMARY_PORT", "8338"))
    SENTINEL_CHECK_INTERVAL = 15   # seconds between primary health-checks
    SENTINEL_FAILOVER_AFTER = 3    # consecutive failures before failover

    # ── Panic Circuit Breaker ─────────────────────────────────────────────────
    # Automatically puts node into "Read-Only" mode if a critical consistency
    # error is detected — preventing spread of corrupted data.
    CIRCUIT_BREAKER_ENABLED    = True
    CIRCUIT_BREAKER_VIOLATIONS = 2   # trigger after N safety violations

    # ── Peer Trust / Identity Verification ────────────────────────────────────
    # Set of logic-hash strings considered "Known Good" besides our own.
    # Add prior-version hashes here to allow graceful rolling upgrades:
    # nodes running the old version are flagged TRUST_LEVEL_LOW only if
    # their hash is completely absent from this set.
    # Populated/extended at runtime via ensure_dirs(); empty by default.
    KNOWN_GOOD_LOGIC_HASHES: set = set()
    # Bandwidth throttle for TRUST_LEVEL_LOW peers.
    # They may send at most this many bytes of TX/block data per 60-second
    # window.  Legitimate old-version nodes will stay well under the limit;
    # only flood-attack nodes will hit it and receive a ban-score penalty.
    UNTRUSTED_TX_RATE_LIMIT_BYTES = 1_048_576   # 1 MB per 60-second window

    # ── Soft Ban: Consecutive Failure Escalation (v6.0.0) ────────────────────────
    # Solves the "Scrutiny Tax" CPU-exhaustion attack: a TRUST_LEVEL_LOW peer
    # that sends consecutive invalid TX / BLOCK messages is escalated through
    # three strike levels instead of just accumulating a ban score:
    #
    #   Strike 1 → WARNING log (single alert, connection kept open)
    #   Strike 2 → Throttling: SOFT_BAN_THROTTLE_DELAY_SECS sleep is injected
    #              before every subsequent MSG_TX / MSG_BLOCK from this peer,
    #              capping the rate at which the node spends CPU re-validating
    #              their garbage while still giving them a chance to recover.
    #   Strike 3 → BANNED: peer_id blacklisted in DB + IP recorded in node_meta
    #              with a 24-hour expiry; both inbound and outbound connections
    #              from that IP are refused for SOFT_BAN_BAN_DURATION_SECS.
    #
    # The consecutive counter resets to 0 whenever the peer sends a *valid*
    # MSG_TX or MSG_BLOCK (passes Full Audit Mode without rejection), so a
    # legitimate experimental fork that occasionally misbehaves is not banned.
    SOFT_BAN_THROTTLE_DELAY_SECS = 2.0    # seconds of sleep per message at strike 2
    SOFT_BAN_BAN_DURATION_SECS   = 86400  # 24-hour IP ban at strike 3

    # ── Outbound connection fail cooldown ─────────────────────────────────────
    # If an IP fails this many consecutive outbound attempts (no handshake),
    # the reconnect loop skips it for OUTBOUND_FAIL_COOLDOWN_SECS before
    # retrying.  Counter resets to 0 on the first successful connection.
    # Not persistent — resets on node restart.  Not a permanent ban.
    OUTBOUND_FAIL_LIMIT         = 5
    OUTBOUND_FAIL_COOLDOWN_SECS = 300    # 5 minutes

    # ── Parallel Mining ───────────────────────────────────────────────────────
    # CPU: spawn one mining thread per logical CPU core by default.
    # hashlib.sha256() releases Python's GIL, so threads genuinely run in
    # parallel across cores.  Override with VISOLD_MINING_THREADS env-var.
    MINING_THREADS: int = max(1, int(
        os.environ.get("VISOLD_MINING_THREADS", str(os.cpu_count() or 4))
    ))

    # GPU: set VISOLD_MINING_GPU=1 to enable CUDA or OpenCL acceleration.
    # The system auto-detects CUDA first, then OpenCL, then falls back to CPU.
    # VISOLD_GPU_DEVICE selects which GPU to use (0 = first device).
    # VISOLD_GPU_BATCH controls how many nonces each GPU kernel launch tests
    # simultaneously (default 2^20 = ~1 million).  Larger batches improve GPU
    # utilisation but increase latency between host-side stop checks.
    MINING_GPU_ENABLED: bool = os.environ.get("VISOLD_MINING_GPU", "0") == "1"
    MINING_GPU_DEVICE:  int  = int(os.environ.get("VISOLD_GPU_DEVICE", "0"))
    MINING_GPU_BATCH:   int  = int(os.environ.get("VISOLD_GPU_BATCH",
                                                   str(1 << 20)))  # 1 M nonces

    # AI suggestion stub
    AI_TIPS = [
        "Stake more VSD to increase validator rewards.",
        "High transaction volume qualifies you for HT rewards.",
        "Consistent uptime improves your peer reputation score.",
        "Difficulty is auto-adjusting — stay online for best results.",
        "Use 'balance_history' to track your earning trends.",
    ]

    @classmethod
    def ensure_dirs(cls):
        # Allow env-var override for port
        port_env = os.environ.get("VISOLD_PORT")
        if port_env:
            try:
                cls.DEFAULT_PORT = int(port_env)
            except ValueError:
                pass

        os.makedirs(cls.DATA_DIR, exist_ok=True)
        cls.DB_PATH           = os.path.join(cls.DATA_DIR, "visold.db")
        cls.PEERS_FILE        = os.path.join(cls.DATA_DIR, "peers.json")
        cls.WALLET_FILE       = os.path.join(cls.DATA_DIR, "wallet.json")
        cls.KEYSTORE_FILE     = os.path.join(cls.DATA_DIR, "keystore.json")
        cls.SIG_FILE          = os.path.join(cls.DATA_DIR, "signature.sig")
        cls.KEY_FILE          = os.path.join(cls.DATA_DIR, "public_key.key")
        cls.GENESIS_HASH_FILE = os.path.join(cls.DATA_DIR, "genesis.hash")
        cls.TLS_CERT_FILE     = os.path.join(cls.DATA_DIR, ".node_tls_cert.pem")
        cls.TLS_KEY_FILE      = os.path.join(cls.DATA_DIR, ".node_tls_key.pem")
        cls.LEVELDB_PATH      = os.path.join(cls.DATA_DIR, "blocks_leveldb")
        cls.ROCKSDB_PATH      = os.path.join(cls.DATA_DIR, "blocks_rocksdb")
        cls.NODE_STATUS_FILE  = os.path.join(cls.DATA_DIR, ".node_status.json")

        # Optional JSON config file override (F-14 FIX: validated ranges)
        cfg_file = os.path.join(cls.DATA_DIR, "config.json")
        if os.path.exists(cfg_file):
            try:
                with open(cfg_file) as f:
                    cfg = json.load(f)
                import logging as _cfglog
                _cl = _cfglog.getLogger("VISOLD.config")

                if "port" in cfg:
                    p = int(cfg["port"])
                    if 1024 <= p <= 65535:
                        cls.DEFAULT_PORT = p
                    else:
                        _cl.warning(f"config.json: port {p} out of range [1024,65535] — ignored")

                if "max_peers" in cfg:
                    mp = int(cfg["max_peers"])
                    if 5 <= mp <= 500:
                        cls.MAX_PEERS = mp
                    else:
                        _cl.warning(f"config.json: max_peers {mp} out of range [5,500] — ignored")

                # F-14 FIX: TLS cannot be disabled via config file (requires code change)
                if "tls" in cfg and not bool(cfg["tls"]):
                    _cl.warning("config.json: disabling TLS via config is not permitted "
                                "(security requirement). Ignoring tls=false.")

                if "log_format" in cfg:
                    lf = str(cfg["log_format"])
                    if lf in ("text", "json"):
                        cls.LOG_FORMAT = lf
                    else:
                        _cl.warning(f"config.json: unknown log_format '{lf}' — ignored")

                if "dns_seeds" in cfg:
                    _hostname_re = re.compile(
                        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
                    valid_seeds = [s for s in list(cfg["dns_seeds"])
                                   if isinstance(s, str) and _hostname_re.match(s)]
                    if valid_seeds:
                        cls.DNS_SEEDS = valid_seeds
                    else:
                        _cl.warning("config.json: dns_seeds contains no valid hostnames — ignored")

                if "bind_address" in cfg:
                    cls.BIND_ADDRESS = str(cfg["bind_address"])
                if "loopback" in cfg:
                    cls.LOOPBACK_ADDRESS = str(cfg["loopback"])
            except Exception as e:
                import logging as _cfglog2
                _cfglog2.getLogger("VISOLD.config").warning(
                    f"config.json parse error: {e} — all config.json values ignored")


        # ENV-var peer injection
        env_peers = os.environ.get("VISOLD_PEERS", "")
        if env_peers:
            for p in env_peers.split(","):
                p = p.strip()
                if p and p not in cls.SEED_PEERS:
                    cls.SEED_PEERS.append(p)
