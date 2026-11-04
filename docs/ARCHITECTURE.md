# Visold - Architecture (modular edition)

*126 modules, 22 bounded contexts, 79,613 lines (excluding package `__init__.py` files).*

## 1. The idea in one paragraph

The former 55,370-line `visold_vsd_.py` is now a package, `visold/`, organised by **bounded context** (domain), not by technical type. Every context sits on a **layer**; a module should import only from its own context or from a **lower** layer (see the dependency rule below). This keeps import cycles out of module-level code, and each context can be read, tested and changed on its own. `visold_vsd_.py` is kept as the entry point and a flat-namespace facade, so `python visold_vsd_.py ...` and `from visold_vsd_ import Blockchain` still work. It contains no implementation and loads no legacy code.

## 2. Layers and contexts (bottom to top)

| Layer | Context | Purpose | Modules | Lines |
|---:|---|---|---:|---:|
| L0 | `kernel` | Shared kernel: configuration, optional-dependency detection, logging, metrics, clock, units, network helpers, protocol message ids, events, LRU cache, bounded-decompression helpers. Depends on nothing else in the package. | 14 | 3,446 |
| L1 | `crypto` | Cryptographic primitives: secp256k1 ECDSA, VRF, hashing, Base58, mnemonic, encrypted keystore, parallel signature verification. | 7 | 1,433 |
| L1 | `economics` | Economic security monitoring and reward / coinbase rules. | 2 | 761 |
| L1 | `governance` | Protocol versioning and upgrade governance. | 2 | 1,198 |
| L2 | `consensus` | Consensus rules that do not need chain state: difficulty, hashrate governor, mining safety, rate-defection auditor, authenticated hashrate reports, slashing evidence. | 6 | 2,449 |
| L2 | `rollup` | Layer-2 rollup core: compact codecs, L2 state, proof backends, batches, local ledger sync. | 5 | 2,481 |
| L2 | `selfhealing` | Self-Healing Blockchain System (SHBS): monitors, anomaly detection, decisions, healing, rollback, plus the hardening overlay. | 15 | 5,537 |
| L3 | `resilience` | Runtime resilience: panic circuit breaker, hardened core overlay, sentinel, safety invariants, supply diagnostics. | 5 | 2,569 |
| L3 | `vm` | Visold Virtual Machine (VVM): opcodes, frames, engine, ABI, assembler, precompiles, static analyzer, contract naming/addressing. | 9 | 4,956 |
| L3 | `wallet` | Wallet entities: key-holding wallet and HD derivation. | 2 | 337 |
| L4 | `ledger` | Ledger entities: Transaction, Block and canonical address-shape validation. | 3 | 1,555 |
| L5 | `state` | State engine (single-writer, event-driven) and storage batch proxy. | 2 | 1,592 |
| L5 | `storage` | Persistence: SQLite/RocksDB/PostgreSQL/Redis adapters, block database, pruners, snapshots. | 7 | 9,825 |
| L6 | `mempool` | Pending-transaction pool and MEV protection (commit-reveal). | 2 | 1,473 |
| L7 | `chain` | Chain services: Blockchain (chain management, reorg), role manager, consensus engine, L2 sequencer. | 4 | 8,734 |
| L8 | `network` | P2P networking: TCP/UDP transports, NAT traversal, discovery, TLS, reputation, adaptive topology policy, authenticated bootstrap helpers, port settings, receipt relay, SPV light client. | 25 | 18,222 |
| L9 | `api` | JSON-RPC server for wallets and explorers. | 1 | 1,473 |
| L9 | `identity` | Decentralized name service. | 1 | 180 |
| L9 | `mining` | Mining: workers, GPU kernels, parallel miner, auto-mining engine. | 4 | 2,149 |
| L9 | `testing` | Embedded test suites and verification harnesses. | 3 | 1,490 |
| L10 | `node` | Node composition root: VisoldNode, user accounts, security gate. | 2 | 1,639 |
| L11 | `cli` | Interfaces: interactive terminal UI, argparse CLI handler, entry point (main), input diagnostics. | 5 | 6,114 |

**Dependency rule:** `visold.<context>.*` may import `visold.<same context>.*` and any context on a lower layer, never a higher one. Module-level imports follow this rule with two exceptions in the current tree: `governance.engine` imports `crypto.ecc` (same layer) and `rollup.l2_state` imports the small address-validation helper `ledger.addressing` (a higher layer). A number of imports inside function bodies or under `TYPE_CHECKING` also point upward; they are used to avoid load-time import cycles. When adding code, prefer the rule above and pass dependencies in as parameters.

## 3. Where does X live?

| Name | Module |
|---|---|
| `Config` | `visold.kernel.config` |
| `Transaction` | `visold.ledger.transaction` |
| `Block` | `visold.ledger.block` |
| `Wallet` | `visold.wallet.wallet` |
| `Blockchain` | `visold.chain.blockchain` |
| `ConsensusEngine` | `visold.chain.consensus_engine` |
| `RoleManager` | `visold.chain.roles` |
| `Sequencer` | `visold.chain.sequencer` |
| `DifficultyEngine` | `visold.consensus.difficulty` |
| `Storage` | `visold.storage.storage` |
| `BlockDatabase` | `visold.storage.block_database` |
| `StateSnapshotEngine` | `visold.storage.snapshot` |
| `Mempool` | `visold.mempool.pool` |
| `check_reveal`, `build_reveal_tx`, `build_commitment_tx` | `visold.mempool.mev` |
| `StateEngine` | `visold.state.engine` |
| `VVMEngine` | `visold.vm.engine` |
| `VVMAssembler` | `visold.vm.assembler` |
| `Layer2State` | `visold.rollup.l2_state` |
| `ProofRegistry` | `visold.rollup.proofs` |
| `GovernanceEngine` | `visold.governance.engine` |
| `P2PNetwork` | `visold.network.p2p` |
| `UDPTransport` | `visold.network.udp.transport` |
| `TLSManager` | `visold.network.tls` |
| `ICEManager` | `visold.network.nat.ice` |
| `SPVClient` | `visold.network.spv` |
| `ParallelMiner` | `visold.mining.parallel_miner` |
| `MiningEngine` | `visold.mining.engine` |
| `RPCServer` | `visold.api.rpc_server` |
| `IdentitySystem` | `visold.identity.names` |
| `VisoldNode` | `visold.node.visold_node` |
| `UserAccount` | `visold.node.visold_node` |
| `SecurityGate` | `visold.node.security_gate` |
| `SentinelNode` | `visold.resilience.sentinel` |
| `CLI` | `visold.cli.interactive` |
| `CLIHandler` | `visold.cli.handler` |
| `main` | `visold.cli.entry` |
| `TestSuite` | `visold.testing.suite` |
| `HardenedVerificationSuite` | `visold.testing.hardened_verification` |
| `RiskScoringEngine` | `visold.selfhealing.hardening.risk` |

Everything else: `grep -rn "^class Name\|^def name" visold/` or see the module index below.

## 4. Module index

`Origin` = line range in the original monolith (for tracing and diffing against an old copy); modules marked "added after the split" have no counterpart in the monolith. `Lines` are current line counts.

### `kernel` (layer L0)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `kernel.clock` | 254 | L5671-5883, L5887 | `NetworkClock` |
| `kernel.compat` | 281 | L2885-2890, L2911-2922, L3389-3393, L3398-3402, L3406-3410, L3413-3418, L3425-3430, L3435-3440, L3448-3483, L3489-3524, L3534-3538 | - |
| `kernel.compression_utils` | 64 | — (added after the split) | `DecompressedSizeLimitError`, `bounded_zlib_decompress`() |
| `kernel.config` | 1362 | L3819-4897 | `Config` |
| `kernel.events` | 127 | L7071-7095, L7099-7117, L7120-7148 | `GlobalSequencer`, `EventType`, `Event` |
| `kernel.logging_setup` | 172 | L3595-3606, L3629, L3736-3769, L3772-3785, L3788-3793, L3796-3814 | - |
| `kernel.lru_cache` | 110 | L31143-31218 | `LRUCache` |
| `kernel.messages` | 183 | L31223-31241, L31249-31256, L31263, L31275, L31298 | - |
| `kernel.metrics` | 115 | L5586-5661, L5665 | `MetricsCollector` |
| `kernel.netutil` | 301 | L4980-5219 | - |
| `kernel.notifications` | 178 | L3636, L3641, L3653-3690, L3693-3711, L3714-3733 | - |
| `kernel.serialization` | 50 | L3374-3385 | - |
| `kernel.source_identity` | 136 | L3579-3583 | `package_source_blob()` |
| `kernel.units` | 113 | L4900, L4907-4973 | `to_satoshi()`, `from_satoshi()`, `gas_fee_to_sat()`, `bft_threshold_met()`, `conservation_check()` |

### `crypto` (layer L1)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `crypto.base58` | 63 | L10328-10354 | `b58encode()`, `b58decode()` |
| `crypto.ecc` | 388 | L10364-10403, L10408-10449, L10452-10477, L10480-10484 | `ECPoint`, `ecdsa_keygen()`, `ecdsa_sign()`, `ecdsa_verify()`, `pub_to_bytes()`, `pub_from_bytes()`, `pub_to_hex()` +4 more |
| `crypto.hashing` | 46 | L10771-10781, L10842-10843 | `sha256()`, `sha256d()`, `hash_obj()` |
| `crypto.keystore` | 233 | L3545-3549, L10846-10920, L10923-11004 | `keystore_encrypt()`, `keystore_decrypt()` |
| `crypto.mnemonic` | 234 | L11008-11171, L11174-11206 | `mnemonic_from_priv()`, `priv_from_mnemonic()` |
| `crypto.parallel_verify` | 152 | L6757-6771, L6774-6795, L6801 | - |
| `crypto.vrf` | 317 | L10514, L10517-10518, L10523-10559, L10564-10567, L10570-10586, L10589-10591, L10596-10617, L10622-10633, L10638-10691, L10696-10768 | `vrf_prove()`, `vrf_verify()` |

### `economics` (layer L1)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `economics.monitor` | 330 | L7993-8287 | `EconomicMonitor` |
| `economics.rewards` | 431 | L49242-49274, L49277-49279, L49283-49332, L49335-49371, L49375-49412, L49415-49423, L49427-49520, L49524-49550, L49554-49580 | `RewardConfig`, `RewardError`, `Coinbase`, `build_coinbase()`, `compute_tx_fee()`, `sum_block_fees()`, `validate_block_rewards()` +1 more |

### `governance` (layer L1)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `governance.engine` | 1060 | L5983-5997, L6000-6078, L6081-6732 | `UpgradePhase`, `UpgradeProposal`, `GovernanceEngine` |
| `governance.versioning` | 138 | L5900-5975 | `ProtocolVersionManager` |

### `consensus` (layer L2)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `consensus.difficulty` | 730 | L8493-9127 | `DifficultyEngine` |
| `consensus.hashrate_governor` | 416 | L9163-9512 | `HashrateGovernor` |
| `consensus.hashrate_reports` | 101 | — (added after the split) | `hashrate_report_payload`(), `hashrate_report_signing_bytes`(), `sign_hashrate_report`(), `verify_hashrate_report`() |
| `consensus.mining_safety` | 322 | L9548-9765 | `MiningSafetyGuard` |
| `consensus.rate_defection` | 600 | L9823-10320 | `RateDefectionAuditor` |
| `consensus.slashing` | 280 | L19002-19195 | `SlashingEvidenceProtocol` |

### `rollup` (layer L2)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `rollup.batches` | 223 | L24854-24887, L24891-25014 | `RollupBatch`, `RollupSubmission` |
| `rollup.compact_codec` | 207 | L23312-23348, L23351-23371, L23374-23402, L23405-23437 | `l2_sig_compact()`, `l2_sig_expand()`, `l2_pub_compact()`, `l2_pub_expand()` |
| `rollup.l2_state` | 970 | L23441-23576, L23580-23602, L23606-23707, L23725, L23735, L23738-24090 | `L2Transaction`, `L2Account`, `L2StateTree`, `Layer2State` |
| `rollup.ledger_sync` | 306 | L25065-25066, L25069-25119, L25122-25180, L25183-25227 | `sync_local_ledger()` |
| `rollup.proofs` | 775 | L24166-24172, L24175-24176, L24184-24186, L24189-24217, L24221-24224, L24227-24229, L24233-24293, L24297-24441, L24449-24459, L24463-24692, L24696-24806, L24812-24823 | `ProofBackendError`, `UnsafeBackendOnMainnetError`, `IProofBackend`, `LocalDevBackend`, `SimulatedProofBackend`, `SubprocessSNARKBackend`, `ProofRegistry` |

### `selfhealing` (layer L2)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `selfhealing.decision` | 308 | L51101-51175, L51178-51371 | `GameTheoryModel`, `DecisionEngine` |
| `selfhealing.detection` | 178 | L50962-51017, L51020-51094 | `StatisticalDetector`, `AnomalyDetectionEngine` |
| `selfhealing.docs_text` | 382 | L52983-53075, L53082-53225, L53232-53333 | - |
| `selfhealing.hardening.failure_analysis` | 129 | L55103-55199 | - |
| `selfhealing.hardening.operator_api` | 160 | L54967-55096 | - |
| `selfhealing.hardening.patches` | 1057 | L53958-54100, L54103-54159, L54166-54242, L54245-54327, L54330-54353, L54360-54609, L54612-54702, L54705-54752, L54759-54855, L54858-54881, L54888-54964 | `patch_decision_engine()`, `SafeActionValidator`, `patch_healing_action_layer()`, `patch_rollback_executor()`, `patch_anomaly_detection_engine()`, `apply_hardening_patch()` |
| `selfhealing.hardening.risk` | 638 | L53353-53396, L53401-53410, L53413-53546, L53551-53597, L53602-53716, L53721-53735, L53738-53796, L53804-53911, L53916-53951 | `RiskScore`, `SignalRecord`, `MultiSignalConfirmationWindow`, `AnomalyFrequencyTracker`, `EconomicImpactSimulator`, `RollbackPreview`, `RollbackAbuseGuard` +2 more |
| `selfhealing.healing` | 598 | L51830-51902, L51905-51951, L51954-52022, L52025-52069, L52072-52384 | `HealingActionLog`, `RateLimiter`, `FreezeRegistry`, `ValidatorAlerter`, `HealingActionLayer` |
| `selfhealing.model` | 269 | L50161-50212, L50215-50297, L50304-50326, L50329-50339, L50342-50372, L50375-50384 | `MetricsRingBuffer`, `BaselineTracker`, `AnomalyKind`, `Severity`, `AnomalyReport`, `SeverityDecision` |
| `selfhealing.monitors` | 611 | L50391-50458, L50461-50596, L50599-50696, L50699-50850, L50853-50955 | `MonitorBus`, `TransactionMonitor`, `GasMonitor`, `ValidatorMonitor`, `ReentrancyPatternDetector` |
| `selfhealing.orchestrator` | 332 | L52592-52866 | `SelfHealingSystem` |
| `selfhealing.rollback` | 451 | L51378-51418, L51421-51460, L51463-51516, L51519-51628, L51631-51823 | `BlockSnapshot`, `SnapshotStore`, `GovernanceRollbackVote`, `RollbackExecutor` |
| `selfhealing.state_hook` | 114 | L52506-52585 | `StateEngineHook` |
| `selfhealing.storage_patch` | 147 | L52873-52875, L52884-52914, L52917-52938, L52941-52953, L52956-52976, L53344-53346 | `patch_storage()` |
| `selfhealing.supply_monitor` | 163 | L52391-52499 | `SupplyConservationMonitor` |

### `resilience` (layer L3)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `resilience.hardened_core` | 1163 | L41881-41895, L41900-41901, L41904-41907, L41910-41929, L41932-41940, L41946-42128, L42131, L42134-42201, L42204, L42207-42348, L42351, L42354-42437, L42440-42547, L42550-42593, L42596-42718, L42721-42744, L42747-42753, L42756-42763, L42766-42775, L42778-42878 | `HardenedBaseError`, `ImmediateAbort`, `InvariantViolation`, `StateRootMismatch`, `ConservationViolation`, `TimestampAnomalyError`, `RecursionLimitExceeded` +5 more |
| `resilience.panic_breaker` | 216 | L41695-41860 | `PanicCircuitBreaker` |
| `resilience.safety_invariants` | 465 | L43252-43637 | `SafetyInvariantChecker` |
| `resilience.sentinel` | 297 | L42998-43246 | `SentinelNode` |
| `resilience.supply_diagnostics` | 428 | — (added after the split) | `SupplyDiagnostics`, `install_supply_diagnostics`() |

### `vm` (layer L3)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `vm.abi` | 209 | L21782-21877, L21880-21945 | `VVMABIEncoder`, `VVMABIDecoder` |
| `vm.assembler` | 531 | L22142-22156, L22159-22593 | `AssemblyResult`, `VVMAssembler` |
| `vm.engine` | 2040 | L20099-20101, L20106-20153, L20156-20170, L20174-21757 | `VVMEngine` |
| `vm.event_index` | 178 | L21961-22091 | `ContractEventIndex` |
| `vm.frame` | 587 | L19690-19720, L19723-20056, L20060-20092 | `VVMResult` |
| `vm.naming` | 94 | L10786-10804, L10809, L10812-10840, L21761-21764 | `normalize_contract_name()`, `validate_contract_name()`, `derive_contract_address()` |
| `vm.opcodes` | 544 | L19206-19607, L19611-19670, L19673-19676, L19681, L19684-19687 | `Op` |
| `vm.precompiles` | 383 | L22603-22896 | `VVMPrecompiles` |
| `vm.static_analyzer` | 390 | L22904-23257 | `VVMStaticAnalyzer` |

### `wallet` (layer L3)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `wallet.hd` | 129 | L11242-11243, L11246-11248, L11251-11261, L11264-11292, L11295-11302 | `derive_wallet_priv()`, `derive_wallet_from_secret()` |
| `wallet.wallet` | 208 | L11308-11418 | `Wallet` |

### `ledger` (layer L4)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `ledger.addressing` | 46 | — (added after the split) | `is_canonical_wallet_address`(), `is_canonical_contract_address`(), `is_valid_protocol_address`() |
| `ledger.block` | 672 | L11912-12425 | `Block` |
| `ledger.transaction` | 837 | L11423-11907 | `Transaction` |

### `state` (layer L5)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `state.batch_proxy` | 343 | L6821-7052 | - |
| `state.engine` | 1249 | L7151-7987 | `StateEngine` |

### `storage` (layer L5)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `storage.backends` | 872 | L2926-2951, L2954-3147, L3150-3262, L3265-3310, L3313-3364 | - |
| `storage.block_database` | 423 | L12430-12770 | `BlockDatabase` |
| `storage.rolling_window_pruner` | 899 | L16635-17017 | `RollingWindowPruner` |
| `storage.snapshot` | 1430 | L17268-17758 | `StateSnapshotEngine` |
| `storage.sqlite_serialized` | 230 | L12776-12833, L12836-12902 | - |
| `storage.state_pruner` | 138 | L16498-16593 | `StatePruner` |
| `storage.storage` | 5833 | L12905-16212 | `Storage` |

### `mempool` (layer L6)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `mempool.mev` | 356 | L18874-18990, L18994 | `check_reveal`, `build_reveal_tx`, `build_commitment_tx` |
| `mempool.pool` | 1117 | L17919-17998, L18001-18866 | `Mempool` |

### `chain` (layer L7)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `chain.blockchain` | 7310 | L25780-30470 | `Blockchain` |
| `chain.consensus_engine` | 516 | L30668-30996 | `ConsensusEngine` |
| `chain.roles` | 239 | L30475-30663 | `RoleManager` |
| `chain.sequencer` | 669 | L25231-25767 | `Sequencer` |

### `network` (layer L8)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `network.block_download` | 290 | L17043-17266 | `ParallelBlockDownloader` |
| `network.bootstrap_sync` | 212 | — (added after the split) | `verify_bootstrap_header_chain`() |
| `network.capabilities` | 233 | L16602-16604, L16607-16610, L16613-16616, L16619-16624, L17761-17894 | `CapabilityRouter` |
| `network.compression` | 182 | L16223-16349 | `CompressionEngine` |
| `network.dns_seeder` | 215 | L33348-33448 | `DNSSeeder` |
| `network.kademlia` | 176 | L31001-31138 | `KBucket`, `KademliaRouter` |
| `network.message_logger` | 226 | L31653-31809, L31815-31822 | `P2PMessageLogger` |
| `network.nat.hole_punch` | 238 | L32334-32535 | `UDPHolePuncher` |
| `network.nat.ice` | 576 | L32837-32852, L32855-32878, L32882-33338 | `ICEManager` |
| `network.nat.relay` | 332 | L32538-32832 | `RelayBridge` |
| `network.nat.stun` | 223 | L32151-32184, L32187-32331 | `ICECandidate`, `STUNClient` |
| `network.nat.upnp` | 356 | L31828-32141 | `UPnPManager` |
| `network.p2p` | 10394 | L33451-38510 | `P2PNetwork` |
| `network.peer_connection` | 974 | L31300-31628 | `PeerConnection` |
| `network.port_settings` | 221 | — (added after the split) | `validate_p2p_port`(), `probe_port_plan`(), `load_saved_port_settings`(), `save_port_settings`() |
| `network.receipt_relay` | 481 | — (added after the split) | `ReceiptRelayManager` |
| `network.reputation` | 176 | L16357-16490 | `PeerReputationManager` |
| `network.spv` | 235 | L8293-8488 | `SPVClient` |
| `network.tls` | 461 | L5224-5579 | `TLSManager` |
| `network.topology_policy` | 345 | — (added after the split) | `topology_signed_payload`(), `topology_signing_bytes`(), `verify_topology_report`(), `rank_topology_candidates`(), `topology_component_view_diagnostic`(), `topology_component_view`(), `topology_component_digest`() +3 more |
| `network.udp.latency` | 127 | L2468-2547 | `LatencyTracker` |
| `network.udp.reliability` | 283 | L1986-2076, L2080-2193 | - |
| `network.udp.session` | 346 | L2197-2426 | `UDPSession` |
| `network.udp.transport` | 654 | L2551-2674, L2690-2878 | `UDPTransport`, `UDPPeerConnection` |
| `network.udp.wire` | 266 | L1914-1930, L1939-1940, L1943-1948, L1952-1956, L1959-1973, L1976-1982, L2430-2433, L2436-2448, L2677-2686 | - |

### `api` (layer L9)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `api.rpc_server` | 1473 | L40412-41687 | `RPCServer` |

### `identity` (layer L9)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `identity.names` | 180 | L40275-40407 | `IdentitySystem` |

### `mining` (layer L9)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `mining.engine` | 835 | L39548-40211 | `MiningEngine` |
| `mining.gpu_kernels` | 286 | L38799-38957, L38961-39054 | - |
| `mining.parallel_miner` | 659 | L39057-39542 | `ParallelMiner` |
| `mining.workers` | 369 | L38545-38582, L38587-38729, L38737-38794 | - |

### `testing` (layer L9)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `testing.hardened_verification` | 152 | L42882-42990 | `HardenedVerificationSuite` |
| `testing.sc_name_tests` | 182 | L55208-55356 | - |
| `testing.suite` | 1156 | L48573-49195 | `TestSuite` |

### `node` (layer L10)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `node.security_gate` | 104 | L40216-40270 | `SecurityGate` |
| `node.visold_node` | 1535 | L43643-44543, L44548-44851 | `VisoldNode`, `UserAccount` |

### `cli` (layer L11)

| Module | Lines | Origin | Main definitions |
|---|---:|---|---|
| `cli.entry` | 186 | L50039-50135 | `main()` |
| `cli.handler` | 491 | L49620-50033 | `CLIHandler` |
| `cli.input_diagnostics` | 358 | — (added after the split) | `InputDiagnostics` |
| `cli.interactive` | 4956 | L44937-48568 | `CLI` |
| `cli.terminal` | 123 | L44864-44907, L44911-44935 | `clr()`, `bold()` |
## 5. Working with the package

- **Add code** to the context that owns the concept. If it needs something from a higher layer, that is a design signal: pass it in as a parameter, or move the shared piece down.
- **New module / context**: create the file and import what you need with absolute imports (`from visold.kernel.config import Config`). For a new context, decide its layer first and update the tables in this document.
- **Never** import `visold_vsd_` from inside the package; it is the entry/facade only.
- **Optional dependencies** (numpy, RocksDB, PostgreSQL, Redis, zstd, ...) are detected once in `visold.kernel.compat`; import the flags/modules from there.
- **Logging** is configured once, on first import of `visold.kernel.logging_setup`; use `from visold.kernel.logging_setup import log`.
- **Build identity**: `visold/kernel/source_identity.py` hashes every `.py` file in `visold/`, and nodes compare that hash in the handshake. Changing any package source file changes the fingerprint stored in `visold/_build_identity.json`.

## 6. Entry point

`visold_vsd_.py` adds its own folder to `sys.path`, imports the public names of every module (historical flat namespace, in the original definition order), then runs the original `__main__` blocks unchanged (`--verify-hardened`, `--test-sc-name-1`, otherwise `visold.cli.entry.main()`). Keep `visold_vsd_.py` and the `visold/` folder side by side.

## Authenticated bootstrap backpressure contract (2026-10-24)

Pruned-node bootstrap separates **state acquisition** from **state authentication**. A candidate snapshot is not trusted merely because a peer advertises it: the receiver verifies the canonical header chain through the snapshot commitment boundary, including the existing consensus/header checks, before installing snapshot state.

Header acquisition uses paginated `GET_CHAIN` requests. Per-peer message quotas are part of the network DoS boundary and are not disabled for bootstrap traffic. When the `GET_CHAIN` bucket is full, the serving peer returns a correlated chain `busy` response containing `retry_after_ms`. The requester preserves the page/request identity, waits for the advertised reopening interval, and retries that same page. This provides explicit transport backpressure instead of an ambiguous timeout.

The retry accounting is page-local, so the number of pages can grow with chain height without exhausting a single chain-wide retry counter. Global message limits, per-type limits, DB-scan concurrency limits, request-ID routing, header/PoW checks, and snapshot commitment verification remain independent safety layers.
