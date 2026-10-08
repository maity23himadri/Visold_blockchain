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
"""visold.selfhealing.docs_text


Origin: visold_vsd_.py L52983-53075, L53082-53225, L53232-53333
"""




# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION GUIDE (copy-paste blocks for main file)
# ─────────────────────────────────────────────────────────────────────────────

INTEGRATION_GUIDE = """
═══════════════════════════════════════════════════════════════════
VISOLD SHBS INTEGRATION GUIDE
───────────────────────────────────────────────────────────────────

STEP 1 — Import at the top of VisoldNode.__init__ (or in the file):

    from visold_self_healing import (
        SelfHealingSystem, patch_storage
    )

STEP 2 — In VisoldNode.__init__, AFTER all subsystems are built:

    # Patch storage with SHBS helper methods
    patch_storage(self.storage)

    # Build SHBS (no threads started yet)
    self.shbs = SelfHealingSystem(
        blockchain=self.blockchain,
        storage=self.storage,
        state_engine=self.state_engine,
        p2p=self.p2p,
        governance=self.governance,   # optional
    )

STEP 3 — In VisoldNode.start() or where StateEngine is started:

    self.shbs.start()   # installs StateEngine hook + starts monitoring

STEP 4 — In StateEngine._handle_new_block, after apply_block:

    # Existing code:
    ok, msg = self._blockchain.apply_block(block)
    if ok:
        # ... existing gossip / notification code ...

        # ADD THIS:
        node = getattr(self, '_node_ref', None)
        if node and hasattr(node, 'shbs'):
            node.shbs.on_block_applied(block)

    NOTE: Set self._node_ref = node in StateEngine after construction,
    or pass shbs directly: self._shbs = node.shbs

STEP 5 — In StateEngine._handle_mine_result, same pattern:

    if ok:
        node = getattr(self, '_node_ref', None)
        if node and hasattr(node, 'shbs'):
            node.shbs.on_block_applied(block)

STEP 6 — Add RPC handlers to existing RPC server:

    elif method == "shbs_status":
        return self._node.shbs.get_status()
    elif method == "shbs_log":
        n = params.get("n", 50)
        return self._node.shbs.get_action_log(n)
    elif method == "shbs_unfreeze":
        addr = params.get("address", "")
        ok, msg = self._node.shbs.unfreeze(addr)
        return {"ok": ok, "message": msg}
    elif method == "shbs_vote":
        ok, msg = self._node.shbs.receive_vote(
            params["proposal_id"], params["validator"],
            params["approve"], params.get("sig", ""),
            params.get("pub", "")
        )
        return {"ok": ok, "message": msg}
    elif method == "shbs_confirm_rollback":
        # AUDIT-FIX-6: second-round confirmation vote for a rollback
        # preview (only meaningful once v2 hardening is active).
        ok, msg = self._node.shbs.confirm_rollback_preview(
            params["confirm_id"], params["validator"],
            params["approve"], params.get("sig", ""),
            params.get("pub", "")
        )
        return {"ok": ok, "message": msg}

ZERO MODIFICATIONS REQUIRED TO:
  ✓ P2P wire protocol / message types (alerts use existing _gossip)
  ✓ Block/Transaction validation logic
  ✓ state_root computation
  ✓ VVMEngine execution
  ✓ Consensus rules (PoW+PoS hybrid)
  ✓ Database schema (aux table only)
  ✓ Reward distribution
  ✓ PanicCircuitBreaker (used read-only; .trip() is existing API)
  ✓ SlashingEvidenceProtocol (triggered via storage.slash_validator)
  ✓ GovernanceEngine upgrade voting (completely separate)

═══════════════════════════════════════════════════════════════════
"""


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO SIMULATION: DeFi Hack
# ─────────────────────────────────────────────────────────────────────────────

"""
═══════════════════════════════════════════════════════════════════════════
EXAMPLE SCENARIO: DeFi Reentrancy Hack + System Response
───────────────────────────────────────────────────────────────────────────

SETUP:
  • Chain: 500 blocks, 3 validators (Alice, Bob, Carol), 100k VSD in a
    DeFi lending contract at VSDcLEND00...
  • Attacker deploys a malicious contract VSDcATTACK... at block 501
  • Attack begins at block 502

ATTACK SEQUENCE:
  Block 502, tx 1: Attacker deposits 100 VSD into lending contract
  Block 502, tx 2: Attacker calls withdraw(). Contract sends ETH before
                   updating balance (reentrancy). Attacker's fallback re-
                   calls withdraw() 50 times in a loop.
  Estimated drain: 99,900 VSD (near-total contract balance)

───────────────────────────────────────────────────────────────────────────
SHBS RESPONSE TIMELINE:

T+0.0s  Block 502 applied by StateEngine._handle_new_block
        shbs.on_block_applied(block_502) called

T+0.1s  Layer 1 — Monitoring:
          tx_monitor.observe_block(502):
            → FUND_DRAIN detected: 99,900 VSD (99.9% of balance)
              confidence=0.75, kind=FUND_DRAIN, z_score=8.4
          gas_monitor.observe_block(502):
            → GAS_SPIKE: gas_used=9,850,000 (z=7.2 against baseline)
          reentrancy_detector.observe_block(502):
            → REENTRANCY_PATTERN: SSTORE[3] before CALL[7] in VSDcLEND
              confidence=0.70

T+0.2s  Layer 2 — ADE:
          3 anomaly reports produced
          Deduplication: only 3 unique (kind, addr) pairs — all pass

T+0.3s  Layer 3 — Decision Engine (FUND_DRAIN first, highest priority):
          _classify(FUND_DRAIN, amount=99900, confidence=0.75):
            → amount > 100_000? NO (99,900 < 100,000) → HIGH not CRITICAL
            → confidence 0.75 >= HIGH_CONFIDENCE (0.60)? YES
            → Severity = HIGH
            → actions = ["log", "freeze_account", "alert_validators"]
            → attacker_ev = 99900 * 0.90 = 89,910 VSD
            → validator_ev = 99900 * 0.05 / 3 = 1,665 VSD each
            → suppress? NO (confidence 0.75 ≥ HIGH threshold 0.60)

          _classify(REENTRANCY_PATTERN, confidence=0.70):
            → confidence ≥ HIGH_CONFIDENCE? YES
            → check contract_balance (evidence missing — default 0) < 50k → HIGH
            → Severity = HIGH
            → actions = ["log", "freeze_contract", "alert_validators"]

T+0.4s  Layer 4 — HAL execution (FUND_DRAIN decision):
          action "log"           → HealingActionLog records event
          action "freeze_account" → FreezeRegistry.freeze(VSDcATTACK, 600s)
            [WARN] FROZEN: VSDcATTACK... for 600s
          action "alert_validators" → P2P _gossip(SHBS_ALERT) to all peers

T+0.45s  HAL execution (REENTRANCY decision):
          action "freeze_contract" → FreezeRegistry.freeze(VSDcLEND, 600s)
            [WARN] FROZEN: VSDcLEND... for 600s

T+0.5s  StateEngine hook active:
          → Any TX from VSDcATTACK is now rejected: "SHBS: sender frozen"
          → Any TX to/from VSDcLEND is now rejected: "SHBS: receiver frozen"
          → Attacker cannot drain remaining balance

T+0.6s  Block 503: attacker attempts second withdrawal
          StateEngine._handle_new_tx called
          se_hook: FreezeRegistry.is_frozen(VSDcATTACK) = TRUE
          → return False, "SHBS: sender account frozen during anomaly response"
          Attack effectively stopped.

T+60s   Validators Alice, Bob, Carol receive SHBS_ALERT via P2P
          They examine the evidence and call RPC shbs_vote:
            Alice: shbs_vote(proposal_id, approve=True)
            Bob:   shbs_vote(proposal_id, approve=True)
            Carol: shbs_vote(proposal_id, approve=True)

T+60s+  NOTE: In this scenario HAL classified as HIGH (not CRITICAL) because
          drain < 100k VSD threshold → no automatic rollback was initiated.

          IF the drain had been > 100k VSD (CRITICAL):
            GovernanceRollbackVote.quorum_status() = reached (3/3 validators)
            RollbackExecutor.execute(target=501, flagged={VSDcATTACK})
              → _rollback_block(502) → state restored to block 501
              → 99,900 VSD restored to VSDcLEND
              → safe txs (non-attacker) replayed into mempool

T+600s  Freeze expires automatically (10 minutes)
          Operators can extend via: shbs_unfreeze(VSDcLEND) → manual review

RESULT:
  • Attack contained at block 502
  • No funds drained from block 503 onward
  • Validators alerted; governance vote possible for block 502 rollback
  • Zero modifications to P2P, VVM, or state_root computation
  • Full audit trail in shbs_action_log table

───────────────────────────────────────────────────────────────────────────

TRADE-OFFS AND FAILURE CASES:
───────────────────────────────────────────────────────────────────────────

TRADE-OFF 1: Baseline warm-up period
  Statistical detectors require BASELINE_WINDOW (200) blocks before firing.
  Fresh chains: only rule-based detection is active for the first 200 blocks.
  Mitigation: lower BASELINE_WINDOW for testnets; keep high for mainnet.

TRADE-OFF 2: Freeze duration vs. service continuity
  A 10-minute freeze on a high-traffic DeFi contract causes ~60 missed blocks.
  Mitigation: operators can call shbs_unfreeze after manual review.

TRADE-OFF 3: Rollback quorum timeout
  If validators are offline when a CRITICAL event fires, quorum may not be
  reached within the 30-second window → rollback does not execute.
  Mitigation: increase VOTE_WINDOW_SECS; add SentinelNode validator redundancy.

TRADE-OFF 4: False positive chain freezes
  PanicCircuitBreaker.trip() halts all state mutations. If a supply
  conservation check fires falsely, the chain enters read-only mode.
  Mitigation: SUPPLY_CONSERVATION_MONITOR only runs every 50 blocks with
  a 5% tolerance margin; requires significant drift before triggering.

FAILURE CASE 1: Attacker drains in a single tx under the 30% drain threshold
  The FUND_DRAIN rule fires at >30% per-sender balance reduction.
  An attacker who drains exactly 29% per block evades the rule for 4 blocks.
  Mitigation: Statistical baseline catches cumulative TPS/gas anomalies.

FAILURE CASE 2: Validator majority is attacker-controlled
  If ≥ 2/3 validators are malicious, the quorum vote would approve attacker
  transactions. This is a fundamental Byzantine fault tolerance limit (BFT
  requires <1/3 Byzantine nodes). SHBS cannot defend against this without
  external intervention. Mitigation: decentralise validator set.

FAILURE CASE 3: StateEngine hook bypassed by direct _apply methods
  If code calls blockchain.apply_block() directly (not through StateEngine),
  the hook does not fire. Mitigation: audit all apply_block call sites;
  the hook covers the two canonical paths (_handle_new_block, _handle_mine_result).

═══════════════════════════════════════════════════════════════════════════
"""


# ─────────────────────────────────────────────────────────────────────────────
# TEXTUAL ARCHITECTURE DIAGRAM
# ─────────────────────────────────────────────────────────────────────────────

ARCHITECTURE_DIAGRAM = """
╔══════════════════════════════════════════════════════════════════════╗
║           VISOLD SELF-HEALING BLOCKCHAIN SYSTEM — DATA FLOW         ║
╚══════════════════════════════════════════════════════════════════════╝

 ┌──────────────────────────────────────────────────────────────────┐
 │                     EXTERNAL WORLD                               │
 │   Transactions ──► P2P Network ──► StateEngine ──► Blockchain   │
 └──────────────────────────────┬───────────────────────────────────┘
                                │ on_block_applied(block) [read-only]
                                ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  LAYER 1: CONTINUOUS MONITORING                                  │
 │                                                                  │
 │  TransactionMonitor          GasMonitor        ValidatorMonitor  │
 │  ├─ TPS (ring buffer)        ├─ gas/tx          ├─ sig history  │
 │  ├─ drain ratio              ├─ exhaustion      ├─ inactivity   │
 │  └─ sender flood count       └─ spike (z-score) └─ double-sign  │
 │                                                                  │
 │  ReentrancyDetector          SupplyConservationMonitor           │
 │  └─ SSTORE before CALL       └─ Welford sum check (every 50 blk)│
 │                                                                  │
 │  MonitorBus ──► MetricsRingBuffer ──► BaselineTracker (Welford) │
 └──────────────────────────────┬───────────────────────────────────┘
                                │ AnomalyReport (typed, immutable)
                                ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  LAYER 2: ANOMALY DETECTION ENGINE                               │
 │                                                                  │
 │  RuleEngine                 StatEngine           PatternEngine   │
 │  (hard thresholds:          (z-score vs           (SSTORE-CALL   │
 │   TPS, drain %, flood)       EWMA baseline)        pattern)      │
 │                                                                  │
 │  Deduplication (30s window, O(1) hash map)                       │
 │  ──► List[AnomalyReport] ──► Listener callbacks                 │
 └──────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  LAYER 3: DECISION ENGINE (Deterministic — no ML)                │
 │                                                                  │
 │  ┌─────────────────────────────────────────────────────────┐    │
 │  │  Severity Classifier                                    │    │
 │  │  CRITICAL: double_sign, drain>100k, supply_inflation    │    │
 │  │  HIGH:     drain>10k, reentrancy, extreme TPS, inactiv. │    │
 │  │  MEDIUM:   TPS/gas z>3.5, flood, gas exhaustion         │    │
 │  │  LOW:      circular_trade, low-conf collusion           │    │
 │  └─────────────────────────────────────────────────────────┘    │
 │                                                                  │
 │  GameTheoryModel: attacker_ev, validator_ev (per anomaly kind)   │
 │  FalsePositiveSuppressor: confidence gate + attacker_ev floor    │
 │                                                                  │
 │  ──► SeverityDecision (severity, action_tags, rationale)        │
 └──────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  LAYER 4: SELF-HEALING ACTION LAYER (HAL)                        │
 │                                                                  │
 │  LOW  ──► HealingActionLog.record()                             │
 │           (log + increase monitoring cadence)                    │
 │                                                                  │
 │  MED  ──► RateLimiter.limit(addr)        [3 tx/60s]            │
 │       ──► ValidatorAlerter._gossip(SHBS_ALERT)                  │
 │                                                                  │
 │  HIGH ──► FreezeRegistry.freeze(addr, 600s)                     │
 │       ──► ValidatorAlerter.alert()                              │
 │       ──► (DOUBLE_SIGN) → storage.slash_validator()             │
 │                                                                  │
 │  CRIT ──► GovernanceRollbackVote (2/3 quorum, 30s window)       │
 │       ──► PanicCircuitBreaker.trip() [if "freeze_chain"]        │
 │       ──► RollbackExecutor.execute(target, flagged, replay)     │
 └──────────────────────────────┬───────────────────────────────────┘
                                │
              ┌─────────────────┴──────────────────┐
              ▼                                    ▼
 ┌────────────────────────┐         ┌──────────────────────────────┐
 │  StateEngine Hook      │         │  RollbackExecutor            │
 │  (instance monkey-     │         │  ├─ SnapshotStore (50 blks)  │
 │   patch on _handle_tx) │         │  ├─ blockchain._rollback_blk │
 │  ├─ FreezeRegistry     │         │  │  (existing method, loop)  │
 │  └─ RateLimiter        │         │  └─ safe_tx replay into pool │
 └────────────────────────┘         └──────────────────────────────┘

 ┌──────────────────────────────────────────────────────────────────┐
 │  GOVERNANCE LAYER                                                │
 │  GovernanceRollbackVote: proposal_id, depth, evidence           │
 │  Quorum: ≥ 2/3 active validators OR auto-approve if none        │
 │  Fast-track: 3/3 validators skip 30s window                     │
 │  Vote input: P2P MSG_SHBS_VOTE or RPC shbs_vote                 │
 └──────────────────────────────────────────────────────────────────┘

 ┌──────────────────────────────────────────────────────────────────┐
 │  SAFETY CONSTRAINTS                                              │
 │  • Rollback capped at 50 blocks (SnapshotStore.MAX_SNAPSHOTS)   │
 │  • Freeze auto-expires in 10min (no permanent DoS)              │
 │  • Suppress gate: CRITICAL needs ≥80% confidence                │
 │  • Attacker EV floor: CRITICAL needs attacker_ev > 1000 VSD     │
 │  • Solo-node auto-approve (no validators registered)            │
 │  • Stats anomalies suppressed during warm-up (200 blocks)       │
 └──────────────────────────────────────────────────────────────────┘
"""
