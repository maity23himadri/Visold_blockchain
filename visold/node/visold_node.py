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
"""visold.node.visold_node

Original section: SECTION 18: NODE — FULL NODE ORCHESTRATOR

Defines: VisoldNode, UserAccount
Origin: visold_vsd_.py L43643-44543, L44548-44851
"""

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sys
import threading
import time
from typing import List, Optional, Tuple

from visold.api.rpc_server import RPCServer
from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine
from visold.chain.roles import RoleManager
from visold.chain.sequencer import Sequencer
from visold.consensus.difficulty import DifficultyEngine
from visold.consensus.rate_defection import RateDefectionAuditor
from visold.consensus.slashing import SlashingEvidenceProtocol
from visold.crypto.hashing import sha256
from visold.identity.names import IdentitySystem
from visold.kernel.config import Config
from visold.kernel.events import Event, EventType
from visold.kernel.logging_setup import log
from visold.kernel.netutil import _write_node_status
from visold.kernel.units import VSD_GLOBAL_MARKET, from_satoshi, to_satoshi
from visold.ledger.transaction import Transaction
from visold.mempool.mev import (build_commitment_tx, core_transfer, load_flight,
                               new_salt, protection_default)
from visold.mining.engine import MiningEngine
from visold.network.capabilities import CapabilityRouter
from visold.network.p2p import P2PNetwork
from visold.network.reputation import PeerReputationManager
from visold.node.security_gate import SecurityGate
from visold.resilience.hardened_core import apply_hardened_overlay
from visold.resilience.panic_breaker import PanicCircuitBreaker
from visold.resilience.safety_invariants import SafetyInvariantChecker
from visold.resilience.sentinel import SentinelNode
from visold.resilience.supply_diagnostics import install_supply_diagnostics
from visold.rollup.l2_state import L2_BRIDGE_ADDRESS, L2_WITHDRAW_ADDRESS
from visold.selfhealing.hardening.patches import apply_hardening_patch
from visold.selfhealing.orchestrator import SelfHealingSystem
from visold.selfhealing.storage_patch import _patch_storage_for_shbs
from visold.state.engine import StateEngine
from visold.storage.state_pruner import StatePruner
from visold.storage.storage import Storage
from visold.wallet.hd import _WALLET_DERIV_VERSION, derive_wallet_from_secret
from visold.wallet.wallet import Wallet


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 18: NODE — FULL NODE ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────
class VisoldNode:
    """
    Full node orchestrator: blockchain + StateEngine + P2P + mining +
    governance + identity + roles + RPC.

    Wiring order (avoids circular dependencies):
      1. Storage, Blockchain (owns GovernanceEngine internally)
      2. StateEngine (needs Blockchain + GovernanceEngine)
      3. P2PNetwork (needs Blockchain, gets StateEngine injected)
      4. MiningEngine (needs Blockchain + ConsensusEngine, gets StateEngine injected)
      5. StateEngine.set_network() (wires network back into engine)
      6. RPCServer (needs node reference for all of the above)
    """

    def __init__(self, port: Optional[int] = None):
        self._shutdown_lock = threading.Lock()
        self._shutdown_started = False
        self._shutdown_complete = False
        self._startup_timers: list = []
        # Serialises updates to the local incoming-transfer inbox.  Inbox data
        # lives in node_meta (not consensus state) and must never affect blocks.
        self._incoming_transfer_lock = threading.RLock()
        # Load config before selecting the default listen port. A default argument
        # bound to Config.DEFAULT_PORT at import time would ignore config.json.
        Config.ensure_dirs()
        if port is None:
            port = int(Config.DEFAULT_PORT)
        else:
            port = int(port)

        ok, msg = SecurityGate.verify_startup()
        if not ok:
            log.critical(f"SECURITY GATE FAILED: {msg}")
            sys.exit(1)

        self.wallet = self._load_or_create_wallet()

        self.storage    = Storage(Config.DB_PATH)
        self.blockchain = Blockchain(self.storage)

        ok, gmsg = SecurityGate.verify_genesis_hash(self.storage, self.blockchain)
        if not ok:
            log.critical(gmsg)
            sys.exit(1)

        # ── Hybrid difficulty system activation ───────────────────────────────
        DifficultyEngine.invalidate_cache(from_height=0)

        self.consensus = ConsensusEngine(self.blockchain, self.wallet)
        self.node_id   = sha256(self.wallet.pub_hex.encode())

        # ── StateEngine — created before network and mining ────────────────────
        # It references blockchain._governance which is already constructed
        # inside Blockchain.__init__.
        self.state_engine = StateEngine(
            blockchain  = self.blockchain,
            governance  = self.blockchain._governance,
            storage     = self.storage,
        )
        self.state_engine._mev_wallet = self.wallet

        # ── Network — StateEngine injected after construction ──────────────────
        self.network = P2PNetwork(
            self.blockchain, self.wallet, self.storage,
            port=port, node_id=self.node_id)
        self.consensus.set_network(self.network)
        self.network.set_state_engine(self.state_engine)

        # ── Wire network back into StateEngine ────────────────────────────────
        self.state_engine.set_network(self.network)
        # ── v7.5.0-OPT Wire network into Blockchain for latency-aware sizing ──
        #    Purely advisory — Blockchain consults network.latency_tracker only
        #    inside get_dynamic_block_size(), which does not affect consensus.
        self.blockchain.set_network(self.network)
        # ── SHBS: wire node reference so block hooks can reach shbs ──
        self.state_engine._node_ref = self

        # ── v7.5.0-OPT LAYER-2 SEQUENCER ─────────────────────────────────
        # Constructed opt-in — the sequencer thread is NOT started here.
        # Operators start it via a CLI / RPC command (Sequencer.start()).
        # The object exists so any node can receive and relay L2 txs;
        # only the node(s) where .start() has been called will seal
        # batches and submit rollup transactions to the L1 mempool.
        #
        # NOTE: the shipped ProofRegistry default backend is
        # SimulatedProofBackend — HMAC-based, explicitly NOT a
        # zero-knowledge proof.  See SECTION 7E-3 docstring.  Production
        # deployments MUST register and select a real SNARK backend
        # before starting the sequencer.
        self.sequencer: Optional[Sequencer] = None
        try:
            self.sequencer = Sequencer(
                layer2       = self.blockchain.layer2,
                wallet       = self.wallet,
                blockchain   = self.blockchain,
                network      = self.network,
                state_engine = self.state_engine,
            )
            # Let P2P route inbound L2 txs into the sequencer's pool.
            self.network.set_sequencer(self.sequencer)
        except Exception as _seq_e:
            # Sequencer construction failure must never prevent node boot —
            # L2 is a secondary subsystem, L1 consensus is primary.
            log.error(f"[L2] Sequencer init failed (L2 disabled): {_seq_e}")
            self.sequencer = None

        # ── Mining — StateEngine injected after construction ──────────────────
        self.mining = MiningEngine(
            self.blockchain, self.consensus,
            self.network, self.wallet, self.storage,
            state_engine=self.state_engine)
        # ── v7.6.0 Wire mining engine into network so MSG_HASHRATE_REPORT
        # handler can find the local HashrateGovernor.  Investor-only nodes
        # never construct a MiningEngine, in which case _mining_engine_ref
        # stays None and the handler is a no-op for inbound reports.
        try:
            self.network.set_mining_engine(self.mining)
        except Exception:
            pass

        self.roles    = RoleManager(
            self.storage, self.wallet,
            blockchain=self.blockchain,
            state_engine=self.state_engine)
        self.identity = IdentitySystem(
            self.storage, self.network, self.wallet,
            blockchain=self.blockchain, state_engine=self.state_engine)
        # P2PNetwork may choose a nearby free port in Auto mode. The node, RPC,
        # status file, identity advertisement, and UI must all use the actual
        # listener port, not the originally requested base port.
        self.port     = int(self.network.port)

        rpc_port  = self.port + Config.RPC_PORT_OFFSET
        self.rpc  = RPCServer(self, rpc_port)

        # ── Fix #12: Safety Invariant Checker ────────────────────────────────
        # Instantiated last (needs storage, blockchain, and network).
        # Wired into StateEngine for periodic rolling checks (via timer tick)
        # and into the RPC server for on-demand operator invocation.
        self.invariant_checker = SafetyInvariantChecker(
            storage    = self.storage,
            blockchain = self.blockchain,
            network    = self.network,
        )
        # Inject into StateEngine so the timer tick can call rolling_check()
        self.state_engine._invariant_checker = self.invariant_checker

        # ── NEW: Panic Circuit Breaker ────────────────────────────────────────
        # Automatically trips to Read-Only mode on critical safety violations.
        # Inject mining + state_engine references after both are constructed.
        self.circuit_breaker = PanicCircuitBreaker(
            mining_engine=self.mining,
            state_engine=self.state_engine,
        )
        # Wire circuit breaker into invariant checker for automatic tripping
        self.invariant_checker._circuit_breaker = self.circuit_breaker
        # Wire circuit breaker into StateEngine for write-gating
        self.state_engine._circuit_breaker = self.circuit_breaker

        # ── NEW: Peer Reputation Manager ─────────────────────────────────────
        # Long-term "good behavior" tracking for quality peer prioritization.
        self.reputation_mgr = PeerReputationManager(self.storage)
        self.network._reputation_mgr = self.reputation_mgr

        # ── NEW: DiscV5 Capability Router ────────────────────────────────────
        # Topic-based peer discovery; nodes advertise and query capabilities.
        self.capability_router = CapabilityRouter(self.storage)
        self.network._capability_router = self.capability_router
        # Store own address in node_meta so CapabilityRouter can check role
        self.storage.set_meta("own_address", self.wallet.address)

        # ── NEW: State Pruner (Merkle/Patricia snapshots) ─────────────────────
        # Prunes historical state snapshots to bound DB growth.
        self.state_pruner = StatePruner(self.storage, self.blockchain)
        self.state_engine._state_pruner = self.state_pruner

        # ── NEW: Slashing Evidence Protocol ──────────────────────────────────
        # Auto-broadcasts double-sign proofs to trigger network-wide slashing.
        self.slash_evidence = SlashingEvidenceProtocol(
            self.storage, self.blockchain)
        self.blockchain._slash_evidence = self.slash_evidence
        self.network._slash_evidence    = self.slash_evidence


        # ── v7.7.0: Rate Defection Auditor ───────────────────────────────────
        # Statistical detection of miners ignoring the hashrate throttle.
        # Runs every RATE_AUDIT_CADENCE blocks, broadcasts evidence on flag.
        # Default deployment is OBSERVE-ONLY (Config.AUTO_SLASH_RATE_DEFECTION
        # is False).  Operators flip the flag to True after weeks of testnet
        # observation confirms no false positives.
        self.rate_auditor = RateDefectionAuditor(self.storage, self.blockchain)
        # Wire it into the blockchain (so apply_block can trigger an audit
        # cycle), into the network (so the inbound message handler can find
        # it), and into the mining engine (so mining-engine code paths can
        # access offense/ban state if needed).
        self.blockchain._rate_auditor = self.rate_auditor
        self.network._rate_auditor    = self.rate_auditor
        try:
            self.mining._rate_auditor = self.rate_auditor
        except Exception:
            pass

        # ── NEW: Sentinel Node (High-Availability) ────────────────────────────
        # Monitors primary node; auto-failover for validator duties.
        self.sentinel = SentinelNode(self)

        # ── INTEGRATED: Self-Healing Blockchain System (SHBS) v2.0.0 ──────────
        # Non-invasive anomaly detection + staged healing actions.
        # ZERO modifications to consensus, state_root, P2P wire protocol or VVM.
        # Must be last in __init__ so all subsystems are available.
        self.shbs: Optional['SelfHealingSystem'] = None
        try:
            _shbs_storage = self.storage
            _patch_storage_for_shbs(_shbs_storage)
            self.shbs = SelfHealingSystem(
                blockchain   = self.blockchain,
                storage      = _shbs_storage,
                state_engine = self.state_engine,
                p2p          = self.network,
                governance   = self.blockchain._governance,
                data_dir     = Config.DATA_DIR,
            )
        except Exception as _shbs_err:
            log.error(f"[SHBS] Instantiation error (non-fatal): {_shbs_err}")
            self.shbs = None

        # ── HARDENED CORE OVERLAY ─────────────────────────────────────────────
        # Six orthogonal safety layers applied LAST — after all subsystems are
        # constructed and wired:
        #   1. _HardenedCBSingleton  — NORMAL/READ_ONLY/SAFE_SHUTDOWN state machine
        #   2. SystemInvariantGate   — pre-condition checks before every write
        #   3. AtomicStateTransition — Prepare → Verify → Commit pattern
        #   4. _NTPClock             — NTP-median deterministic clock
        #   5. ResourceCap           — recursion guard + memory ceiling + timeout
        #   6. GracefulDegradation   — secondary component isolation
        # All patches are instance-level — zero class-level mutations.
        try:
            apply_hardened_overlay(
                blockchain_instance  = self.blockchain,
                storage_instance     = self.storage,
                vvm_engine_instance  = getattr(self.blockchain, '_vvm_engine', None),
                event_index_instance = getattr(self.blockchain, '_event_index', None),
                start_ntp_clock      = True,
            )
            self.hardened_overlay_active = True
            log.info("[VisoldNode] Hardened core overlay applied successfully.")
        except Exception as _hco_err:
            # AUDIT-FIX-10: escalated from log.error("...non-fatal...") to
            # log.critical + a persistent, queryable status flag. The most
            # severe single consequence of running without this overlay
            # (unauthorized minting via a negative debit_sat/credit_sat
            # amount) is now independently guarded at the base Storage
            # layer regardless of overlay state -- see the AUDIT-FIX-10
            # guards on Storage.debit_sat/credit_sat and
            # _StorageBatchProxy.debit_sat/credit_sat. Given that, crashing
            # the entire node over a failed add-on safety layer would trade
            # network liveness for a marginal safety gain; instead this
            # fails loudly and stays inspectable (self.hardened_overlay_active)
            # rather than fully silently, without refusing to start.
            self.hardened_overlay_active = False
            log.critical(
                f"[VisoldNode] Hardened core overlay FAILED to apply — "
                f"running WITHOUT: NTP-median clock, atomic prepare/verify/"
                f"commit wrapping, resource caps, graceful degradation, and "
                f"the overlay's own pre-condition invariant checks (the "
                f"base-layer negative-amount guard on debit_sat/credit_sat "
                f"is still active independently of this). "
                f"Error: {_hco_err}")

        # Diagnostic-build only: observe every supported balance mutation and
        # compare held supply with scheduled issuance around each block apply.
        # The observer never repairs state and its own failures are non-fatal.
        try:
            self._supply_diagnostics = install_supply_diagnostics(
                self.storage, self.blockchain)
        except Exception as _supply_diag_err:
            self._supply_diagnostics = None
            log.warning("[SupplyDiagnostics] Instrumentation unavailable (%s)",
                        type(_supply_diag_err).__name__)

    def _load_or_create_wallet(self) -> 'Wallet':
        # Prefer encrypted keystore; fall back to plaintext wallet only for
        # backward-compatibility migration.
        #
        # v7.5.x: If account.json declares wallet_derivation == v1-hkdf
        # AND a keystore exists, sanity-check that the keystore's address
        # matches the address declared in account.json.  A mismatch means
        # the keystore is stale (old random wallet from pre-v7.5.x code)
        # while account.json was written by a newer recover() — refuse to
        # start with the wrong wallet rather than silently signing tx with
        # keys that don't own the user's funds.
        _account_data = None
        try:
            if os.path.exists(UserAccount.ACCOUNTS_FILE):
                with open(UserAccount.ACCOUNTS_FILE) as _af:
                    _account_data = json.load(_af)
        except Exception as _ae:
            log.warning(f"Could not read account.json: {_ae}")

        _expected_addr = ""
        _is_v1_hkdf    = False
        if _account_data:
            if _account_data.get("wallet_derivation") == _WALLET_DERIV_VERSION:
                _is_v1_hkdf    = True
                _expected_addr = _account_data.get("wallet_addr", "") or ""

        if os.path.exists(Config.KEYSTORE_FILE):
            machine_secret = self._get_or_create_machine_secret()
            try:
                w = Wallet.load_keystore(Config.KEYSTORE_FILE, machine_secret)
            except Exception as e:
                log.critical(f"Cannot decrypt keystore: {e}")
                if _is_v1_hkdf:
                    log.critical(
                        "  Hint: this account was created with deterministic "
                        "wallet derivation.  You can recover by deleting "
                        f"{Config.KEYSTORE_FILE} and {UserAccount.ACCOUNTS_FILE} "
                        "then choosing 'Restore my existing account' on next start."
                    )
                sys.exit(1)
            # v7.5.x sanity check: prevent stale-keystore drift.
            if (_is_v1_hkdf and _expected_addr
                    and w.address != _expected_addr):
                log.critical(
                    "Keystore wallet address does not match account.json "
                    f"declared address.\n"
                    f"  keystore: {w.address}\n"
                    f"  account : {_expected_addr}\n"
                    f"This usually means the keystore predates a successful "
                    f"deterministic recovery on this device.  To fix: delete "
                    f"{Config.KEYSTORE_FILE} (NOT account.json) and run the "
                    f"node again — the keystore will be regenerated on the "
                    f"next launch using the secret stored at recover() time."
                )
                sys.exit(1)
            return w

        if os.path.exists(Config.WALLET_FILE):
            log.warning("Migrating plaintext wallet to encrypted keystore…")
            w = Wallet.load(Config.WALLET_FILE)
            machine_secret = self._get_or_create_machine_secret()
            w.save_keystore(Config.KEYSTORE_FILE, machine_secret)
            try:
                os.remove(Config.WALLET_FILE)
                log.info("Plaintext wallet file removed after migration.")
            except Exception:
                pass
            return w

        # No keystore present.  If the user has a v1-hkdf account.json the
        # keystore is supposed to have been written by register() / recover().
        # Refusing to silently mint a new random wallet here is the only way
        # to protect the user from spending tx with keys that don't own their
        # funds.  Direct them through the recovery flow.
        if _is_v1_hkdf and _expected_addr:
            log.critical(
                "Account.json indicates a deterministic wallet "
                f"({_expected_addr}) but no keystore was found on disk.  "
                f"To rebuild the keystore on this device, delete "
                f"{UserAccount.ACCOUNTS_FILE} and choose 'Restore my "
                f"existing account' on the next start, providing your "
                f"User ID + Secret Key.  The node refuses to generate a "
                f"random replacement wallet because that would silently "
                f"hide your real funds."
            )
            sys.exit(1)

        # Brand new wallet (legacy path: no account.json yet, fresh node).
        # Note: when account.json IS present (with no v1-hkdf flag) this
        # branch is taken too — that preserves the legacy random-wallet
        # behaviour for accounts created before deterministic derivation.
        w = Wallet.generate()
        machine_secret = self._get_or_create_machine_secret()
        w.save_keystore(Config.KEYSTORE_FILE, machine_secret)
        log.info(f"New wallet created and encrypted: {w.address}")
        return w

    @staticmethod
    def _get_or_create_machine_secret() -> str:
        """Return (or create) the machine-local secret used to encrypt the keystore.

        MAJOR-08 SECURITY NOTE:
        The secret is stored as a plaintext hex string in ~/.visold/.node_secret.
        chmod(0o600) limits access to the owning Unix user but does NOT protect
        against: root, backup tools, cloud-sync agents (Dropbox, Google Drive,
        iCloud), or Android content-provider leaks on non-rooted devices.

        Hardening recommendations (in order of increasing strength):
          1. NEVER sync ~/.visold/ to cloud storage.
          2. On Linux/macOS: use the `keyring` library to store the secret in
             the OS keychain (Keychain on macOS, libsecret/KWallet on Linux).
          3. On hardware with a TPM: derive the secret via TPM2_CreatePrimary so
             it never leaves the secure enclave in plaintext.
          4. On Android (Termux): consider Android Keystore via a JNI shim for
             hardware-backed key derivation.

        Until one of the above is implemented, the threat model for the machine
        secret is: protection against other unprivileged Unix users, but NOT
        against root, backup tools, or cloud sync.
        """
        secret_path = os.path.join(Config.DATA_DIR, ".node_secret")
        if os.path.exists(secret_path):
            with open(secret_path, 'r') as f:
                return f.read().strip()
        secret = secrets.token_hex(32)
        with open(secret_path, 'w') as f:
            f.write(secret)
        try:
            os.chmod(secret_path, 0o600)
        except Exception:
            pass
        log.warning(
            "SECURITY: Machine secret written to %s (chmod 600). "
            "Do NOT sync ~/.visold/ to cloud storage — see _get_or_create_machine_secret() "
            "for hardening options (OS keychain, TPM).",
            secret_path
        )
        return secret

    def _check_legacy_stake_balance_shortfall(self) -> None:
        """Diagnose a possible old stake-debit shortfall without crediting funds.

        Balance totals are not sufficient proof of which account was modified
        by an earlier bug.  This method intentionally has no write operations.
        """
        try:
            height = self.blockchain.height()
            if height <= 0:
                return
            total_issued_sat = sum(
                self.blockchain.compute_reward_sat(h)
                for h in range(1, height + 1)
            )
            total_balances_sat = self.storage.sum_all_balances_satoshi()
            total_staked_sat = self.storage.sum_all_staked_satoshi()
            shortfall_sat = total_issued_sat - total_balances_sat
            if 0 < shortfall_sat <= total_staked_sat:
                log.critical(
                    "[StakeOverDebitRepair] Possible legacy stake-related "
                    "balance shortfall: %.8f VSD (active stake %.8f VSD). "
                    "No automatic credit was applied: aggregate totals do not "
                    "prove the cause or the affected accounts. Back up this "
                    "database and rebuild balances by replaying the verified "
                    "canonical chain or restore a known-good backup.",
                    shortfall_sat / Config.SATOSHI_PER_VSD,
                    total_staked_sat / Config.SATOSHI_PER_VSD,
                )
        except Exception as exc:
            log.warning(
                "Legacy stake-balance diagnostic failed (no balances changed): %s",
                exc,
            )

    def start(self):
        # Start StateEngine FIRST — it must be running before network and mining
        self.state_engine.start()
        self.network.start()
        self.rpc.start()

        # ── Write node status file so Explorer always finds live ports ─────────
        # ICE gather runs in background; relay_port may update after _init_relay.
        # We write an initial status immediately and refresh once ICE is ready.
        _rpc_port   = self.port + Config.RPC_PORT_OFFSET
        _relay_port = self.port + Config.RELAY_PORT_OFFSET  # default fallback
        _write_node_status(self.port, _rpc_port, _relay_port)

        def _refresh_status_after_ice():
            """Wait for ICE gather to finish, then rewrite with actual relay port."""
            try:
                ice = getattr(self.network, "_ice", None)
                if ice is not None:
                    ice._ready.wait(timeout=15.0)
                    actual_relay = ice._relay_port
                    _write_node_status(self.port, _rpc_port, actual_relay)
                    log.info(
                        f"Node status updated: p2p={self.port} "
                        f"rpc={_rpc_port} relay={actual_relay}"
                    )
            except Exception as exc:
                log.debug(f"Node status refresh error (non-fatal): {exc}")

        threading.Thread(
            target=_refresh_status_after_ice,
            daemon=True,
            name="node-status-writer",
        ).start()

        user_id = self.storage.get_meta("user_id")
        if user_id:
            self.identity.register(user_id, "127.0.0.1", self.port)

        # ── NEW: Start Sentinel (High-Availability) ───────────────────────────
        self.sentinel.start()

        # ── SHBS: Apply hardening, THEN start monitoring ───────────────────────
        # AUDIT-FIX-7 (non-atomic patch + startup race): previously this
        # called self.shbs.start() — which installs the StateEngine hook and
        # begins live anomaly-detection processing — BEFORE
        # apply_hardening_patch() ran. Anything CRITICAL detected in that
        # window (or during the window while apply_hardening_patch() is
        # still working through its four sequential patch calls) would run
        # through the fully-automatic, ungated v1 pipeline: v1
        # DecisionEngine._classify() emits "rollback" in action_tags for
        # several CRITICAL cases, and v1 HealingActionLayer._dispatch_action()
        # unconditionally acts on it — no SafeActionValidator, no multi-signal
        # confirmation, no economic simulation, no rate limiting, no dynamic
        # depth cap (those are all v2-only). GovernanceRollbackVote.quorum_status()
        # also auto-approves when zero validators are registered, so a
        # solo-node/bootstrap deployment had no protection at all during
        # this window.
        #
        # Fix: patch FIRST (before any monitoring is live), and if hardening
        # fails partway through, do NOT start SHBS at all — a half-patched
        # safety system (some of ade/decision_eng/hal/rollback_exec hardened,
        # others still v1) is more dangerous than no automated response,
        # since it looks active in logs/RPC status while enforcing an
        # inconsistent mix of protections. Fail closed instead.
        try:
            if self.shbs is not None:
                _shbs_v2_components = apply_hardening_patch(self.shbs)
                self.shbs.start()
                log.info(
                    "[SHBS] Self-Healing System v2.0.0 active — "
                    "anomaly detection, staged response, rollback governance enabled."
                )
                # AUDIT-FIX-8: give the miner's candidate-block builder a
                # read-only reference to the freeze registry so a frozen
                # sender's transactions are excluded from blocks THIS node
                # proposes (see ConsensusEngine.build_candidate_block).
                # This is purely a local mining-policy choice — it must
                # NEVER be consulted during apply_block/validate_block,
                # since freeze state differs per node and isn't part of
                # consensus; making it consensus-relevant would let nodes
                # with different freeze state disagree on block validity.
                _consensus_ref = getattr(self, "consensus", None)
                if _consensus_ref is not None:
                    _consensus_ref._freeze_registry = self.shbs.freeze_reg
        except Exception as _shbs_start_err:
            log.critical(
                f"[SHBS] Hardening/start FAILED — Self-Healing System "
                f"DISABLED for this session (node operation continues "
                f"normally, but automated anomaly detection/response will "
                f"NOT run until restarted): {_shbs_start_err}")
            try:
                if self.shbs is not None:
                    self.shbs.stop()
            except Exception:
                pass

        # ── NEW: Broadcast own capabilities via DiscV5 router ────────────────
        try:
            self.capability_router.update_own_capabilities(self.storage)
            adv = self.capability_router.build_adv_message()
            _capability_timer = threading.Timer(
                5.0,
                lambda: self.network._gossip(adv) if self.network._running else None
            )
            _capability_timer.daemon = True
            self._startup_timers.append(_capability_timer)
            _capability_timer.start()
            log.info(f"Capability discovery: advertising "
                     f"{self.capability_router.own_capabilities()}")
        except Exception as e:
            log.debug(f"Capability advertisement error (non-fatal): {e}")

        # ── NEW (v7.1.5): Broadcast Genesis block like any other block ────────
        # Genesis is created synchronously inside Blockchain.__init__, long
        # before the network exists, so _create_genesis() itself cannot
        # broadcast.  We schedule a delayed one-shot broadcast here — after
        # self.network.start() and after initial peer connections have had a
        # few seconds to establish.  The receiver side is protected by the
        # genesis-idempotency short-circuit in Blockchain.apply_block(), so
        # a peer that already has matching genesis simply relays once and
        # stops (via _seen_msgs LRU dedup).  A peer that somehow lacks
        # genesis will persist the received block — the GENESIS_* constants
        # make the construction deterministic, so block_hash is guaranteed
        # to match what that peer would have computed locally.
        try:
            _genesis_timer = threading.Timer(
                5.0,
                lambda: self.network.broadcast_genesis()
                if self.network._running else None
            )
            _genesis_timer.daemon = True
            self._startup_timers.append(_genesis_timer)
            _genesis_timer.start()
        except Exception as e:
            log.debug(f"Genesis broadcast schedule error (non-fatal): {e}")

        # ── BUG-FIX (v6.9.9.5): Startup balance/height consistency guard ────────
        # Detect and repair the state where chain_height == 0 but balance > 0.
        # This happens when the blocks DB is wiped (or a fresh node syncs) but
        # the SQLite balances table retains rows from a previous session.
        # The chain is authoritative: at height 0 all balances MUST be zero.
        # We wipe only the wallet's own address here (targeted, safe); a full
        # balances wipe happens inside _hard_reset_to() during chain sync.
        #
        # BUG-FIX (v6.9.9.6): Two corrections to the original StartupGuard:
        #
        # 1. Condition was `_startup_height == 0`.  blockchain.height() returns 0
        #    when ONLY the genesis block exists (index 0), and -1 when the chain
        #    store is completely empty.  Both states mean "no mined blocks" and
        #    both require the same orphan wipe.  Changed to `_startup_height <= 0`.
        #
        # 2. The original guard only checked the wallet's own address for an
        #    orphaned balance.  If the previous session had distributed rewards to
        #    other addresses (miners, investors, fee recipients), those rows also
        #    survive a partial DB wipe and would remain invisible to a single-
        #    address check.  Changed to a SUM over the entire balances table so
        #    any non-zero total triggers the wipe — consistent with _hard_reset_to()
        #    which already does DELETE FROM balances unconditionally.
        try:
            _startup_height = self.blockchain.height()
            if _startup_height <= 0:
                # AUDIT-FIX-O1a: this used to read self.storage._conn() directly,
                # on the theory that it "works against the authoritative backend
                # ... because set_balance / credit_sat mirror the aux-SQLite
                # shadow." That mirror is best-effort -- every mirror write is
                # wrapped in `except Exception: pass` (see
                # _mirror_balance_to_aux) with no retry or alert -- so in pgx
                # mode this was reading a shadow copy that can silently drift
                # from Postgres, not the primary itself. A real orphan in
                # Postgres with a stale/empty shadow would never trip this
                # guard; a stale nonzero shadow next to a clean Postgres would
                # trip it and wipe_all_balances() would truncate real Postgres
                # data. sum_all_balances_satoshi() is already correctly
                # backend-aware -- use it instead.
                _total_orphaned_sat = self.storage.sum_all_balances_satoshi()
                if _total_orphaned_sat > 0:
                    _total_orphaned_vsd = _total_orphaned_sat / Config.SATOSHI_PER_VSD
                    log.warning(
                        f"[StartupGuard] Orphaned balance rows detected at chain "
                        f"height {_startup_height}: total={_total_orphaned_vsd:.8f} VSD. "
                        f"These rows are NOT backed by any mined block. "
                        f"Wiping all balance rows now — they will be rebuilt "
                        f"correctly once this node syncs blocks from a peer.")
                    self.storage.wipe_all_balances()
                    log.info(
                        "[StartupGuard] All balance rows wiped. "
                        "Node will rebuild balances from chain after peer sync.")
        except Exception as _sg_err:
            log.warning(f"[StartupGuard] Non-fatal startup guard error: {_sg_err}")

        # ── Legacy stake-debit recovery: diagnose only, never auto-mint ───────
        # The prior heuristic credited every active stake whenever the total
        # shortfall was merely <= total stake.  That does not prove that the
        # legacy bug ran, nor that the shortfall equals the amount it debited.
        # It can therefore create an over-issued balance.  We now report the
        # possible legacy condition without changing balances; recovery must be
        # performed from a verified canonical-chain replay or known-good backup.
        self._check_legacy_stake_balance_shortfall()

        # ── Fix #12: Run full safety invariant check at startup ───────────────
        # A full scan (all blocks) happens once here; subsequent periodic checks
        # are rolling (last 200 blocks) via the StateEngine timer tick.
        try:
            report = self.invariant_checker.check_all(full_scan=True)
            if report["violations"]:
                log.critical(
                    f"STARTUP INVARIANT VIOLATIONS DETECTED "
                    f"({len(report['violations'])} violation(s)):")
                for v in report["violations"]:
                    log.critical(f"  • {v}")
                log.critical(
                    "Node is running with invariant violations. "
                    "Investigate before proceeding.")
                # ── NEW: Trip circuit breaker on startup violations ────────────
                if len(report["violations"]) >= Config.CIRCUIT_BREAKER_VIOLATIONS:
                    for viol in report["violations"]:
                        self.circuit_breaker.record_violation(viol)
            else:
                log.info(
                    f"Safety invariants verified OK at startup "
                    f"(safety={report['safety_ok']}, "
                    f"liveness={report['liveness_ok']}, "
                    f"consistency={report['consistency_ok']})")
        except Exception as e:
            log.warning(f"Startup invariant check error (non-fatal): {e}")

        log.info(f"Visold node started | addr={self.wallet.address} "
                 f"| StateEngine active"
                 f"| compression={'ON' if Config.COMPRESSION_ENABLED else 'OFF'}"
                 f"| sentinel={'STANDBY' if Config.SENTINEL_MODE else 'OFF'}"
                 f"| mev_protect={'ON' if protection_default(self.storage) else 'OFF'}")

    def stop(self):
        """Idempotent, best-effort shutdown of every node-owned resource.

        A failure in one optional subsystem must not short-circuit cleanup of
        listeners, worker processes, state engine, or persistent databases.
        This is also safe to call from the CLI's finalizer after menu option 0.
        """
        with self._shutdown_lock:
            if self._shutdown_complete or self._shutdown_started:
                return
            self._shutdown_started = True
            failures = []

            def _stop_component(label, fn):
                if not callable(fn):
                    return
                try:
                    fn()
                except BaseException as exc:
                    failures.append((label, exc))
                    try:
                        log.error("Shutdown component %s failed: %s", label, exc)
                    except Exception:
                        pass

            # Cancel delayed startup broadcasts before shutting down their target
            # network. Non-daemon Timer threads used to keep Termux sessions alive
            # for up to five seconds after menu option 0.
            for timer in list(getattr(self, "_startup_timers", [])):
                try:
                    timer.cancel()
                    if timer is not threading.current_thread() and timer.is_alive():
                        timer.join(timeout=0.5)
                except Exception as exc:
                    failures.append(("startup timer", exc))
            getattr(self, "_startup_timers", []).clear()

            # Stop producers first so no new work should be added while the
            # network and state-processing components are being closed.
            mining = getattr(self, "mining", None)
            _stop_component("mining", getattr(mining, "stop", None))
            sequencer = getattr(self, "sequencer", None)
            _stop_component("sequencer", getattr(sequencer, "stop", None))
            _stop_component("P2P network", getattr(getattr(self, "network", None), "stop", None))
            _stop_component("JSON-RPC", getattr(getattr(self, "rpc", None), "stop", None))
            _stop_component("sentinel", getattr(getattr(self, "sentinel", None), "stop", None))
            _stop_component("self-healing system", getattr(getattr(self, "shbs", None), "stop", None))
            _stop_component("circuit breaker", getattr(getattr(self, "circuit_breaker", None), "stop", None))

            # StateEngine is stopped after network producers are closed; it can
            # process/finish work already queued before the STOP event.
            _stop_component("state engine", getattr(getattr(self, "state_engine", None), "stop", None))

            # Reap lazy signature-verification worker processes explicitly; they
            # otherwise can make a mobile Python session remain busy at exit.
            try:
                from visold.crypto.parallel_verify import shutdown_signature_pool
                _stop_component("signature worker pool", shutdown_signature_pool)
            except Exception as exc:
                failures.append(("signature worker pool", exc))

            storage = getattr(self, "storage", None)
            block_db = getattr(storage, "_block_db", None) if storage is not None else None
            _stop_component("block database", getattr(block_db, "close", None))
            _stop_component("storage backends", getattr(storage, "close", None))

            self._shutdown_complete = True
            if failures:
                log.warning("Node shutdown completed with %d cleanup warning(s)", len(failures))
            else:
                log.info("Node stopped cleanly")


    # ── Local incoming-transfer inbox (non-consensus UI metadata) ────────────
    _INCOMING_TRANSFER_MAX_ENTRIES = 500

    def _incoming_transfer_meta_key(self) -> str:
        """Wallet-scoped metadata key so inboxes never bleed across wallets."""
        return "incoming_transfers_v1:" + sha256(
            str(self.wallet.address).encode("utf-8"))[:24]

    def _load_incoming_transfer_inbox_unlocked(self) -> dict:
        """Load and defensively normalise the small, local-only transfer inbox.

        Called while ``_incoming_transfer_lock`` is held.  Only a bounded
        history is retained; ``total_count`` is cumulative and survives trim.
        The inbox is presentation metadata only and is never read by consensus.
        """
        empty = {"version": 1, "total_count": 0, "entries": []}
        try:
            raw = self.storage.get_meta(self._incoming_transfer_meta_key(), "")
            if not raw:
                return empty
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get("version") != 1:
                return empty
            raw_entries = data.get("entries", [])
            if not isinstance(raw_entries, list):
                raw_entries = []
            entries = []
            for item in raw_entries[-self._INCOMING_TRANSFER_MAX_ENTRIES:]:
                if not isinstance(item, dict):
                    continue
                tx_id = item.get("tx_id")
                sender = item.get("sender")
                try:
                    amount_sat = int(item.get("amount_sat"))
                    timestamp = int(item.get("timestamp", 0))
                    received_at = int(item.get("received_at", timestamp))
                except (TypeError, ValueError, OverflowError):
                    continue
                if (not isinstance(tx_id, str) or not tx_id or len(tx_id) > 128
                        or not isinstance(sender, str) or not sender
                        or len(sender) > 256 or amount_sat <= 0):
                    continue
                name = item.get("sender_name", "")
                if not isinstance(name, str):
                    name = ""
                entries.append({
                    "tx_id": tx_id,
                    "sender": sender,
                    "sender_name": name[:64],
                    "amount_sat": amount_sat,
                    "timestamp": max(0, timestamp),
                    "received_at": max(0, received_at),
                })
            try:
                total_count = max(0, int(data.get("total_count", 0)))
            except (TypeError, ValueError, OverflowError):
                total_count = 0
            return {
                "version": 1,
                "total_count": max(total_count, len(entries)),
                "entries": entries,
            }
        except Exception as exc:
            # A damaged UI inbox must never stop node startup or TX processing.
            log.warning("Incoming-transfer inbox could not be read: %s", exc)
            return empty

    def get_incoming_transfer_inbox(self) -> dict:
        """Return a defensive snapshot of the wallet's local transfer inbox."""
        with self._incoming_transfer_lock:
            data = self._load_incoming_transfer_inbox_unlocked()
            return {
                "version": 1,
                "total_count": int(data["total_count"]),
                "entries": [dict(item) for item in data["entries"]],
            }

    def get_incoming_transfer_total(self) -> int:
        """Cumulative count of distinct incoming transfers recorded locally."""
        return int(self.get_incoming_transfer_inbox()["total_count"])

    def record_incoming_transfer(self, tx: Transaction) -> bool:
        """Record one admitted transfer addressed to this wallet.

        This is called by StateEngine *only after* ``mempool.add`` succeeds for
        a remote transaction.  It intentionally does not claim confirmation.
        Duplicate tx IDs do not increment the count or emit a second alert.
        """
        try:
            if not isinstance(tx, Transaction):
                return False
            own_address = str(self.wallet.address)
            sender = str(getattr(tx, "sender", "") or "")
            receiver = str(getattr(tx, "receiver", "") or "")
            if (getattr(tx, "tx_type", None) != Transaction.TYPE_TRANSFER
                    or receiver != own_address or not sender or len(sender) > 256
                    or sender == own_address or sender == "COINBASE"):
                return False
            amount_sat = int(to_satoshi(getattr(tx, "amount", 0.0)))
            tx_id = str(getattr(tx, "tx_id", "") or "")
            if amount_sat <= 0 or not tx_id or len(tx_id) > 128:
                return False
            try:
                timestamp = max(0, int(getattr(tx, "timestamp", 0) or 0))
            except (TypeError, ValueError, OverflowError):
                timestamp = 0
            received_at = int(time.time())

            # Name display must come from a confirmed ownership claim, not the
            # mutable peer-directory cache. Otherwise an attacker could make a
            # different address appear to belong to a familiar registered name.
            sender_name = ""
            try:
                candidate = self.storage.get_uid_by_wallet(sender)
                if isinstance(candidate, str):
                    candidate = candidate.strip().casefold()
                    if re.fullmatch(
                            r"(?:[a-z0-9_.-]{3,32}|[a-z0-9_]{3,32}#[0-9a-f]{10})",
                            candidate):
                        claim = self.storage.resolve_name_claim(candidate)
                        if (claim and str(claim.get("wallet_addr", "")) == sender):
                            sender_name = candidate
            except Exception:
                # Unknown names are normal; the address remains the safe fallback.
                sender_name = ""

            with self._incoming_transfer_lock:
                data = self._load_incoming_transfer_inbox_unlocked()
                entries = data["entries"]
                if any(item.get("tx_id") == tx_id for item in entries):
                    return False
                entries.append({
                    "tx_id": tx_id,
                    "sender": sender,
                    "sender_name": sender_name,
                    "amount_sat": amount_sat,
                    "timestamp": timestamp,
                    "received_at": received_at,
                })
                entries = entries[-self._INCOMING_TRANSFER_MAX_ENTRIES:]
                total_count = max(0, int(data["total_count"])) + 1
                payload = {
                    "version": 1,
                    "total_count": total_count,
                    "entries": entries,
                }
                self.storage.set_meta(
                    self._incoming_transfer_meta_key(),
                    json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
                )

            # The activity message is an attention cue, not proof of payment.
            try:
                from visold.kernel.notifications import _push_incoming_transfer_notif
                label = sender_name or sender
                _push_incoming_transfer_notif(label, sender, amount_sat / 100_000_000)
            except Exception:
                pass
            return True
        except Exception as exc:
            # Failure of a local UI feature must not reject/undo an otherwise
            # valid network transaction or break StateEngine's relay path.
            log.warning("Could not record incoming-transfer notification: %s", exc)
            return False

    def send_transaction(self, to_user_or_addr: str, amount: float,
                         memo: str = "", protected=None) -> Tuple[bool, str]:
        if not amount > 0:
            return False, "Amount must be positive"
        if load_flight(self.storage) is not None:
            return False, ("A protected transfer is still in progress. Wait until it "
                           "is broadcast, then send again.")
        # Broadcast order: empty recipient → VSD_GLOBAL_MARKET
        addr: str
        if not to_user_or_addr or to_user_or_addr == VSD_GLOBAL_MARKET:
            addr = VSD_GLOBAL_MARKET
        elif not to_user_or_addr.startswith("VSD"):
            _resolved = self.identity.get_wallet_address(to_user_or_addr)
            if not _resolved:
                return False, f"Cannot resolve '{to_user_or_addr}'"
            addr = _resolved
        else:
            addr = to_user_or_addr

        sender = self.wallet.address
        bal    = self.storage.get_balance(sender)
        fee    = round(amount * Config.TX_FEE_RATE, 8)

        # v7.1.10-hotfix3: honour stake lock.  Stake is tracked in the role
        # table and NOT debited from ``balances`` (because that would cause
        # consensus divergence — see register_miner).  Enforce the lock
        # here by subtracting the staked amount from spendable balance.
        staked_vsd = 0.0
        try:
            role = self.storage.get_role(sender)
            if role and role.get("role") in ("miner", "investor"):
                staked_vsd = float(role.get("stake", 0.0))
        except Exception:
            pass
        # v7.2.x FIX: also subtract anything this sender already has
        # queued in the mempool (REGISTER stake + pending transfer
        # amounts + pending fees).  Without this, a user who sent 5 VSD
        # a moment ago (still pending) could send the same 5 VSD again
        # because the balance row hasn't been debited yet.
        pending_reg_vsd  = 0.0
        pending_xfer_vsd = 0.0
        pending_fee_vsd  = 0.0
        try:
            p_reg_sat, p_xfer_sat, p_fee_sat = \
                self.blockchain.mempool.pending_outflow_sat(sender)
            pending_reg_vsd  = from_satoshi(p_reg_sat)
            pending_xfer_vsd = from_satoshi(p_xfer_sat)
            pending_fee_vsd  = from_satoshi(p_fee_sat)
        except Exception:
            pass
        spendable = round(
            bal - staked_vsd
                - pending_reg_vsd - pending_xfer_vsd - pending_fee_vsd, 8)
        if spendable < round(amount + fee, 8):
            detail_bits = []
            if staked_vsd > 0:
                detail_bits.append(f"{staked_vsd:.8f} staked")
            if pending_reg_vsd > 0:
                detail_bits.append(
                    f"{pending_reg_vsd:.8f} pending-REGISTER")
            if pending_xfer_vsd > 0:
                detail_bits.append(
                    f"{pending_xfer_vsd:.8f} pending-transfer")
            if pending_fee_vsd > 0:
                detail_bits.append(
                    f"{pending_fee_vsd:.8f} pending-fees")
            if detail_bits:
                return False, (
                    f"Insufficient spendable balance: "
                    f"{max(0.0, spendable):.8f} VSD free "
                    f"({bal:.8f} total; " + ", ".join(detail_bits) +
                    f"; need {amount+fee:.8f} incl. {fee:.8f} fee)")
            return False, (f"Insufficient balance: {bal:.8f} VSD "
                           f"(need {amount+fee:.8f} incl. {fee:.8f} fee)")

        # ── Auto-derive correct nonce ──────────────────────────────────────────
        chain_nonce   = self.storage.get_nonce(sender)
        pending_count = len(self.blockchain.mempool._pending_nonces.get(sender, set()))
        nonce         = chain_nonce + pending_count

        # ── MEV protection: the commitment goes on-chain first; the transfer follows ──
        use_protection = (protection_default(self.storage) if protected is None
                          else bool(protected))
        if use_protection:
            commit_fee = from_satoshi(int(getattr(Config, "MIN_TX_FEE_SAT", 1000)))
            if spendable < round(amount + fee + commit_fee, 8):
                return False, (f"Insufficient spendable balance: a protected transfer needs "
                               f"{amount + fee + commit_fee:.8f} VSD, including the "
                               f"{commit_fee:.8f} VSD commitment fee")
            ts = int(time.time())
            salt = new_salt()
            core = core_transfer(sender, addr, amount, fee, memo, nonce + 1, ts)
            commit_tx = build_commitment_tx(self.wallet, nonce + 1, ts, core.mev_commitment(salt))
            return self.state_engine.post_sync(Event(EventType.NEW_TX, {
                "tx": commit_tx,
                "mev_flight": {
                    "core": {"receiver": addr, "amount_sat": to_satoshi(amount),
                             "fee_sat": to_satoshi(fee), "memo": memo,
                             "nonce": nonce + 1, "timestamp": ts},
                    "salt": salt,
                },
            }))

        # BUG-FIX: fee was computed above but never forwarded to Transaction,
        # leaving tx.fee=0.0.  Mempool.add() enforces tx.fee >= amount*MIN_FEE_RATE
        # (which is always > 0 for any positive amount), so every tx built here
        # was unconditionally rejected with "Fee too low: 0.00000000 VSD".
        tx = Transaction(
            sender   = sender,
            receiver = addr,
            amount   = amount,
            fee      = fee,
            memo     = memo,
            nonce    = nonce,
        )
        tx.sign(self.wallet)

        # ── Route through StateEngine (single-writer) ──────────────────────────
        # CLI/RPC send_transaction uses post_sync() for synchronous feedback.
        evt = Event(EventType.NEW_TX, {"tx": tx.to_dict()})
        return self.state_engine.post_sync(evt)

    def withdraw_from_l2(self, amount_vsd: float) -> Tuple[bool, str]:
        """Submit an L2→L1 withdrawal settlement transaction.

        ``tx.amount`` is the gross amount removed from L2/bridge escrow.  The
        normal transfer fee is deducted from those released funds, so mining
        credits ``amount - fee`` to the user's L1 wallet.  The user therefore
        does not need to pre-fund the withdrawal amount on L1.
        """
        if not math.isfinite(amount_vsd) or amount_vsd <= 0:
            return False, "amount must be a positive finite number"
        try:
            amount_sat = to_satoshi(amount_vsd)
        except Exception as e:
            return False, f"amount conversion failed: {e}"
        if amount_sat <= 0 or amount_sat >= (1 << 62):
            return False, "amount out of satoshi range"

        layer2 = getattr(self.blockchain, "layer2", None)
        if layer2 is None:
            return False, "L2 subsystem not initialised on this node"
        sender = self.wallet.address
        if layer2.get_balance_sat(sender) < amount_sat:
            return False, "Insufficient L2 balance for withdrawal"
        if self.storage.get_balance_sat(L2_BRIDGE_ADDRESS) < amount_sat:
            return False, "Bridge escrow too low; supply invariant violation"

        fee = round(amount_vsd * Config.TX_FEE_RATE, 8)
        fee_sat = to_satoshi(fee)
        if fee_sat > amount_sat:
            return False, "withdrawal amount is too small to cover its fee"

        chain_nonce = self.storage.get_nonce(sender)
        pending_count = len(self.blockchain.mempool._pending_nonces.get(sender, set()))
        nonce = chain_nonce + pending_count
        tx = Transaction(
            sender=sender, receiver=L2_WITHDRAW_ADDRESS,
            amount=amount_vsd, fee=fee, memo="L2_WITHDRAW", nonce=nonce)
        tx.sign(self.wallet)
        ok, msg = self.state_engine.post_sync(
            Event(EventType.NEW_TX, {"tx": tx.to_dict()}))
        if not ok:
            return False, msg
        return True, (f"Withdrawal submitted: gross {amount_vsd:.8f} VSD; "
                      f"{from_satoshi(amount_sat - fee_sat):.8f} VSD will be "
                      f"credited to L1 after the {fee:.8f} VSD fee when mined.")

    def add_peer_manual(self, ip: str, port: int) -> Tuple[bool, str]:
        # ── Optional Port Override ────────────────────────────────────────────
        # FORCE_OUTBOUND_DEST_PORT defaults to False so the operator-supplied
        # port is always respected.  Only override when explicitly enabled
        # (private test networks) — and log a visible warning so the operator
        # knows their intended port was changed.
        if Config.FORCE_OUTBOUND_DEST_PORT and port != Config.DEFAULT_PORT:
            log.warning(
                f"[PortEnforce] Manual peer add: overriding port {port} → "
                f"{Config.DEFAULT_PORT} for {ip} "
                f"(FORCE_OUTBOUND_DEST_PORT=True; set False in config to allow "
                f"custom ports)")
            port = Config.DEFAULT_PORT
        ok = self.network.connect_to(ip, port)
        return (True, f"Connected to {ip}:{port}") if ok else (False, "Connection failed")

    # ── Governance convenience API ─────────────────────────────────────────────

    def propose_upgrade(self, version: int, signal_start_height: int,
                        threshold: Optional[float] = None) -> Tuple[bool, str]:
        """
        Announce a protocol upgrade proposal.
        Delegates to GovernanceEngine.propose_upgrade().
        """
        return self.blockchain._governance.propose_upgrade(
            version             = version,
            signal_start_height = signal_start_height,
            threshold           = threshold,
        )

    def emergency_disable_upgrade(self, version: int) -> Tuple[bool, str]:
        """BUG-12: cast this node's signed emergency-disable vote and gossip it.

        Only a validator wallet at the chain tip may vote.  The disable runs once
        EMERGENCY_DISABLE_QUORUM distinct validators have voted, wherever their
        votes were cast.
        """
        if not self.blockchain.emergency_operator_eligible(self.wallet.address):
            return False, ("This node's wallet is not a validator at the chain tip. "
                           "Only validator operators can cast emergency-disable votes.")
        gov = self.blockchain._governance
        try:
            vote = gov.sign_emergency_vote(self.wallet, version)
        except RuntimeError as exc:
            return False, str(exc)
        accepted, disabled, msg = gov.record_emergency_vote(
            vote, is_eligible=self.blockchain.emergency_operator_eligible)
        network = getattr(self, "network", None)
        if accepted and network is not None:
            network.broadcast_emergency_vote(vote)
        return disabled, msg

    def governance_status(self) -> List[dict]:
        """Return all upgrade proposals and their current phase."""
        return self.blockchain._governance.all_proposals()


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 19: USER ACCOUNT SYSTEM
# ─────────────────────────────────────────────────────────────────────────────
class UserAccount:
    ACCOUNTS_FILE = os.path.join(Config.DATA_DIR, "account.json")

    @classmethod
    def is_registered(cls) -> bool:
        return os.path.exists(cls.ACCOUNTS_FILE)

    # ── VSD-H02 FIX: scrypt key-derivation helpers ───────────────────────────
    @staticmethod
    def _hash_secret(secret: str, salt: Optional[bytes] = None) -> Tuple[str, str, str]:
        """Derive a salted hash from secret.

        Tries scrypt with progressively lower memory costs so the function
        works on resource-constrained devices (Termux, low-RAM VMs, etc.).
        Falls back to PBKDF2-HMAC-SHA256 if scrypt is unavailable or all
        memory budgets are exceeded.

        Returns (salt_hex, hash_hex, kdf_string) where kdf_string encodes
        the exact parameters used — callers MUST store it so _verify_secret
        can reproduce the same derivation.
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        # Try scrypt with decreasing n (memory cost): 32 MB → 16 MB → 8 MB →
        # 4 MB → 2 MB.  Each halving of n halves peak RAM while keeping the
        # work-factor reduction modest.
        for n in (32768, 16384, 8192, 4096, 2048):
            try:
                dk = hashlib.scrypt(
                    secret.strip().encode(), salt=salt,
                    n=n, r=8, p=1, dklen=32)
                return salt.hex(), dk.hex(), f"scrypt-n{n}-r8-p1"
            except (ValueError, OSError):
                continue
        # Ultimate fallback: PBKDF2-HMAC-SHA256 with 260 000 iterations.
        # No scrypt-style memory requirement; secure for account credentials.
        dk = hashlib.pbkdf2_hmac(
            'sha256', secret.strip().encode(), salt, 260_000)
        return salt.hex(), dk.hex(), "pbkdf2-sha256-i260000"

    @staticmethod
    def _verify_secret(secret: str, salt_hex: str, hash_hex: str,
                       kdf: str = "scrypt-n32768-r8-p1") -> bool:
        """Constant-time verification of secret using stored kdf parameters.

        The kdf string (stored in account.json) tells us exactly which
        algorithm and parameters were used at registration time, so
        verification always uses the same derivation even if the defaults
        change in a future version.
        """
        import re as _re
        salt = bytes.fromhex(salt_hex)
        if kdf.startswith("scrypt-"):
            m = _re.match(r'scrypt-n(\d+)-r(\d+)-p(\d+)', kdf)
            n, r, p = (int(m.group(1)), int(m.group(2)), int(m.group(3))) \
                      if m else (32768, 8, 1)
            try:
                dk = hashlib.scrypt(
                    secret.strip().encode(), salt=salt,
                    n=n, r=r, p=p, dklen=32)
                return hmac.compare_digest(dk.hex(), hash_hex)
            except (ValueError, OSError):
                return False
        elif kdf.startswith("pbkdf2-sha256"):
            m = _re.match(r'pbkdf2-sha256-i(\d+)', kdf)
            iterations = int(m.group(1)) if m else 260_000
            dk = hashlib.pbkdf2_hmac(
                'sha256', secret.strip().encode(), salt, iterations)
            return hmac.compare_digest(dk.hex(), hash_hex)
        else:
            # Legacy plain SHA-256 (accounts created before VSD-H02)
            legacy = hashlib.sha256(secret.strip().encode()).hexdigest()
            return hmac.compare_digest(legacy, hash_hex)

    @classmethod
    def register(cls, username: str) -> Tuple[bool, str, str]:
        """Create a brand-new account and persist it locally.

        v7.5.x — DETERMINISTIC WALLET DERIVATION:
          The wallet's secp256k1 private key is now derived deterministically
          from (secret, user_id) using HKDF-SHA256 (see derive_wallet_priv).
          This means User ID + Secret Key is sufficient to fully reconstruct
          the wallet on any other device — no keystore.json copy required.
          The encrypted keystore is also written here so the freshly-created
          node boots straight into the correct wallet without re-deriving.
        """
        Config.ensure_dirs()
        unique              = secrets.token_hex(5)
        user_id             = f"{username}#{unique}"
        secret              = secrets.token_hex(16)
        salt_hex, hash_h, kdf_str = cls._hash_secret(secret)
        # ── Derive the wallet from (secret, user_id) and persist keystore ──
        # We do this BEFORE writing account.json so that if keystore creation
        # fails (rare: disk full, permission error) we never leave the user
        # with an account.json whose wallet doesn't actually exist on disk.
        wallet_addr = ""
        try:
            wallet = derive_wallet_from_secret(secret, user_id)
            wallet_addr = wallet.address
            # Encrypt under the machine secret so other unprivileged users
            # on this device can't read the priv key.  Recovery on a NEW
            # device just re-derives from (secret, user_id) — no need to
            # transport the keystore file.
            machine_secret = VisoldNode._get_or_create_machine_secret()
            wallet.save_keystore(Config.KEYSTORE_FILE, machine_secret)
        except Exception as _ke:
            return False, f"Failed to create keystore: {_ke}", ""
        data = {
            "user_id":            user_id,
            "secret_h":           hash_h,
            "secret_salt":        salt_hex,
            "kdf":                kdf_str,
            "username":           username,
            "created_at":         int(time.time()),
            # v7.5.x: marks the wallet as deterministically derivable from
            # (secret, user_id).  Old accounts without this flag remain
            # readable on their original device but cannot be recovered
            # cross-device — see _load_or_create_wallet for the legacy path.
            "wallet_derivation":  _WALLET_DERIV_VERSION,
            "wallet_addr":        wallet_addr,
        }
        with open(cls.ACCOUNTS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        return True, user_id, secret

    @classmethod
    def recover(cls, user_id: str, secret: str,
                confirmed_address: str = "") -> Tuple[bool, str]:
        """Restore an existing account on this device using User ID + Secret Key.

        F-15 FIX: The caller should derive and display the wallet address from
        the supplied secret, then ask the user to confirm it matches the address
        they expect BEFORE calling this method.  The `confirmed_address` param
        documents that the caller performed this check.  If confirmed_address is
        empty the recovery still proceeds but a warning is logged, because the
        network is fully decentralised and has no server to verify against.

        If the user enters a wrong secret the derived wallet address will not
        match their expected address — that mismatch is the user's signal to abort.

        Format expected:  user_id  →  USERNAME#<10 hex chars>
                          secret   →  32 hex chars  (as shown at account creation)
        """
        Config.ensure_dirs()
        # ── Basic format guards ────────────────────────────────────────────────
        if not re.match(r'^[a-zA-Z0-9_]{3,32}#[0-9a-f]{10}$', user_id):
            return False, (
                "Invalid User ID format.\n"
                "  Expected: USERNAME#<10 hex chars>  (e.g. HIMADRI#d43e705790)"
            )
        # MAJOR-07 FIX: Enforce the canonical 32 hex-char secret format that
        # register() always produces (secrets.token_hex(16) = 32 hex chars).
        # Accepting any 8-char string silently derived a weaker key and the
        # resulting wallet address silently mismatched the original.
        _secret_stripped = secret.strip()
        if not re.match(r'^[0-9a-fA-F]{32}$', _secret_stripped):
            _len = len(_secret_stripped)
            if _len < 32:
                return False, (
                    f"Secret key too short ({_len} chars) — "
                    "the full key is exactly 32 hex characters as shown at "
                    "account creation.  Check for truncation or missing characters."
                )
            else:
                return False, (
                    f"Secret key has invalid format ({_len} chars) — "
                    "expected exactly 32 hexadecimal characters (0–9, a–f).  "
                    "Check for extra spaces, line-breaks, or non-hex characters."
                )

        if not confirmed_address:
            log.warning(
                "[Recovery] No address confirmation provided — the user should "
                "verify the derived wallet address matches their expected address "
                "before proceeding.  Use _recover_account() which performs this check.")

        # ── Guard: don't silently overwrite a *different* account ──────────────
        if cls.is_registered():
            existing = cls.get_user_id()
            if existing != user_id:
                return False, (
                    f"Another account ({existing}) is already saved on this "
                    "device.\n"
                    "  Delete the data/account.json file first if you want to "
                    "switch accounts."
                )
            # Same user_id → allow re-import (updates stored secret hash)

        username                  = user_id.split("#")[0]
        salt_hex, hash_h, kdf_str = cls._hash_secret(secret)

        # ── v7.5.x: deterministic wallet recovery ─────────────────────────
        # Derive the wallet from (secret, user_id).  This is THE step that
        # makes "User ID + Secret Key" a complete recovery on a fresh
        # device — without it the node would later boot up with a
        # freshly-generated random wallet that has no connection to the
        # user's actual on-chain funds.
        #
        # AUDIT-FIX-N3: derive_wallet_from_secret() is a pure function (no
        # disk I/O) — previously the keystore was written to disk here,
        # immediately after deriving, BEFORE the confirmed_address sanity
        # check below. That made the check's own comment ("we refuse
        # rather than silently writing a wallet that the user did not
        # see") not actually true, since by the time it ran the write had
        # already happened, with no backup of whatever keystore existed
        # before this call. Deriving first and deferring the actual write
        # (further below) until after the check passes makes the refusal
        # real.
        wallet_addr_derived = ""
        try:
            _wallet = derive_wallet_from_secret(_secret_stripped, user_id)
            wallet_addr_derived = _wallet.address
        except Exception as _ke:
            return False, f"Failed to rebuild wallet from secret: {_ke}"

        # ── Sanity check against the address the caller previewed ────────
        # If the caller (CLI) showed the user a derived address and the user
        # confirmed it, that confirmed_address MUST match what we just
        # derived.  Any mismatch indicates a code-version inconsistency
        # between the preview path and this method — we refuse rather than
        # silently writing a wallet that the user did not see.
        if confirmed_address and confirmed_address != wallet_addr_derived:
            return False, (
                "Internal mismatch between previewed and derived wallet "
                "address — refusing to write keystore.  This indicates a "
                "version inconsistency; please update and retry.")

        # AUDIT-FIX-N3: only now, after the check above has passed, do we
        # touch disk. Overwrite any pre-existing keystore.  If a stale
        # random keystore is present from a previous fresh-device run,
        # replacing it is exactly what we want — the user came here
        # precisely to get the correct wallet back on this machine.
        try:
            machine_secret = VisoldNode._get_or_create_machine_secret()
            _wallet.save_keystore(Config.KEYSTORE_FILE, machine_secret)
        except Exception as _ke:
            return False, f"Failed to write keystore: {_ke}"

        data = {
            "user_id":            user_id,
            "secret_h":           hash_h,
            "secret_salt":        salt_hex,
            "kdf":                kdf_str,
            "username":           username,
            "created_at":         int(time.time()),
            "recovered_at":       int(time.time()),
            "address_confirmed":  bool(confirmed_address),
            "wallet_derivation":  _WALLET_DERIV_VERSION,
            "wallet_addr":        wallet_addr_derived,
        }
        with open(cls.ACCOUNTS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        return True, (
            f"Account restored successfully.  Wallet {wallet_addr_derived[:16]}... "
            f"is now active on this device.")

    @classmethod
    def login(cls, user_id: str, secret: str) -> Tuple[bool, str]:
        if not cls.is_registered():
            return False, "Not registered"
        with open(cls.ACCOUNTS_FILE) as f:
            data = json.load(f)
        if data["user_id"] != user_id:
            return False, "Invalid user_id"

        stored_salt = data.get("secret_salt")
        if stored_salt:
            # Modern account: scrypt or PBKDF2 hash stored with explicit salt.
            kdf = data.get("kdf", "scrypt-n32768-r8-p1")
            if not cls._verify_secret(secret, stored_salt, data["secret_h"], kdf):
                return False, "Invalid secret key"
        else:
            # ── Legacy account (pre-VSD-H02): bare SHA-256, no salt ──────────
            # Verify using the original (weak) hash for backward compatibility,
            # then IMMEDIATELY re-derive with the strongest available KDF and
            # overwrite account.json.  After this first successful login the
            # bare-SHA-256 credential no longer exists on disk.
            legacy_h = hashlib.sha256(secret.strip().encode()).hexdigest()
            if not hmac.compare_digest(data.get("secret_h", ""), legacy_h):
                return False, "Invalid secret key"
            # Transparent migration: re-hash with scrypt/Argon2id and persist.
            try:
                salt_hex, hash_h, kdf_str = cls._hash_secret(secret)
                data["secret_h"]    = hash_h
                data["secret_salt"] = salt_hex
                data["kdf"]         = kdf_str
                data["kdf_migrated_at"] = int(time.time())
                with open(cls.ACCOUNTS_FILE, 'w') as _f:
                    json.dump(data, _f, indent=2)
                log.info(
                    "KDF-MIGRATE: legacy SHA-256 credential upgraded to %s "
                    "for account %s", kdf_str, user_id)
            except Exception as _me:
                # Migration failure is non-fatal: login still succeeds.
                # The account remains on bare SHA-256 until the next login.
                log.warning("KDF-MIGRATE: failed to upgrade credential: %s", _me)

        return True, "Login successful"

    @classmethod
    def get_user_id(cls) -> Optional[str]:
        if not cls.is_registered(): return None
        with open(cls.ACCOUNTS_FILE) as f:
            return json.load(f).get("user_id")
