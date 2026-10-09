# ─────────────────────────────────────────────────────────────────────────────
#  Visold (VSD) Blockchain Protocol
#  Copyright (c) 2025 Visold Contributors
#  Licensed under the MIT License.
#
#  The original and canonical source is maintained by the Visold Project.
#  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#  the license agreement.
# ─────────────────────────────────────────────────────────────────────────────

"""Visold (VSD) - entry point and compatibility facade (strangler-fig).

The implementation now lives in the ``visold`` package (see docs/ARCHITECTURE.md).
This file keeps the historical entry point (``python visold_vsd_.py ...``) and the
historical flat namespace (``from visold_vsd_ import Blockchain``) working.
It contains no implementation code and loads no legacy source.
"""
import os
import sys


def _find_root():
    """folder that contains the visold/ package: next to this file, else next to argv[0], else the cwd"""
    cands = []
    try:
        cands.append(os.path.dirname(os.path.abspath(__file__)))
    except NameError:  # exec()-style launchers do not define __file__
        pass
    if sys.argv and sys.argv[0]:
        cands.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    cands.append(os.getcwd())
    for c in cands:
        if os.path.isfile(os.path.join(c, "visold", "__init__.py")):
            return c
    return cands[0]


_HERE = _find_root()
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# noqa: F401 - re-exported for backward compatibility
from visold.network.udp.wire import (
    _F_ACK,
    _F_FEC,
    _F_FRAG,
    _F_HB,
    _F_LAST,
    _F_NACK,
    _UDP_CWND_INIT,
    _UDP_CWND_MAX,
    _UDP_FEC_GROUP,
    _UDP_FRAG_MAX,
    _UDP_FRAG_MAX_PER_GROUP,
    _UDP_FRAG_TTL,
    _UDP_HB_INTERVAL,
    _UDP_HB_TIMEOUT,
    _UDP_HDR_FMT,
    _UDP_HDR_LEN,
    _UDP_MAGIC,
    _UDP_MAX_RETRIES,
    _UDP_MTU,
    _UDP_PAYLOAD_MAX,
    _UDP_RTO_INIT,
    _UDP_RTO_MAX,
    _UDP_RTO_MIN,
    _UDP_WINDOW_SLEEP,
    _udp_compress,
    _udp_decompress,
    _udp_normalize_addr,
    _udp_pack,
    _udp_unpack,
    _xor_bytes,
)
# noqa: F401 - re-exported for backward compatibility
from visold.network.udp.reliability import _UDPReassembler, _UDPWindow
# noqa: F401 - re-exported for backward compatibility
from visold.network.udp.session import UDPSession
# noqa: F401 - re-exported for backward compatibility
from visold.network.udp.latency import LatencyTracker
# noqa: F401 - re-exported for backward compatibility
from visold.network.udp.transport import UDPPeerConnection, UDPTransport
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.compat import (
    Cipher,
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
    PBKDF2HMAC,
    SECP256K1,
    _ARGON2_AVAILABLE,
    _CRYPTO_LIB,
    _CUDA_AVAILABLE,
    _CYTHON_COMPILED,
    _InvalidSignature,
    _LEVELDB_AVAILABLE,
    _NTPLIB_AVAILABLE,
    _NUMPY_AVAILABLE,
    _NameOID,
    _OPENCL_AVAILABLE,
    _PGX_AVAILABLE,
    _PGX_IMPORT_ERROR,
    _ROCKSDB_AVAILABLE,
    _STORAGE_BACKEND,
    _ZSTD_AVAILABLE,
    _ec,
    _hashes,
    _np,
    _ntplib,
    _x509,
    algorithms,
    cython,
    decode_dss_signature,
    default_backend,
    derive_private_key,
    encode_dss_signature,
    generate_private_key,
    modes,
    serialization,
)
# noqa: F401 - re-exported for backward compatibility
from visold.storage.backends import (
    _CF_BLOCKS,
    _CF_DEFAULT,
    _CF_STATE,
    _META_CHAIN_TIP,
    _META_TIP_HASH,
    _PG_SCHEMA_SQL,
    _P_BLOCK,
    _P_BLOCKHASH,
    _P_CCODE,
    _P_CSTORAGE,
    _P_HEADER,
    _P_MERKLE,
    _P_META,
    _P_STATE,
    _P_TX,
    _PgStateDB,
    _RedisCache,
    _RocksBlockStore,
    _k_block,
    _k_blockhash,
    _k_ccode,
    _k_cstor,
    _k_header,
    _k_merkle,
    _k_meta,
    _k_state,
    _k_tx,
    _u32,
    _u64,
)
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.serialization import _SafeJSONEncoder, _serialize
# noqa: F401 - re-exported for backward compatibility
from visold.crypto.keystore import (
    _ARGON2_HASH_LEN,
    _ARGON2_KDF_TAG,
    _ARGON2_MEMORY_COST,
    _ARGON2_PARALLELISM,
    _ARGON2_TIME_COST,
    _derive_key,
    _pkcs7_pad,
    _pkcs7_unpad,
    keystore_decrypt,
    keystore_encrypt,
)
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.source_identity import _NODE_LOGIC_HASH
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.logging_setup import (
    _QueueHandler,
    _StructuredFormatter,
    _flush_log_queue,
    _log_format,
    _log_queue,
    _queue_handler,
    log,
    root_logger,
)
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.notifications import (
    _notify_buf,
    _notify_buf_lock,
    _pa_push,
    _peer_activity_buf,
    _peer_activity_lock,
    _push_block_notif,
    _push_peer_notif,
    _push_sync_request_notif,
)
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.config import Config
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.units import (
    VSD_GLOBAL_MARKET,
    bft_threshold_met,
    conservation_check,
    from_satoshi,
    gas_fee_to_sat,
    to_satoshi,
)
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.netutil import (
    _create_connection_dual_stack,
    _create_dual_stack_server_socket,
    _format_peer_addr,
    _is_ipv6_address,
    _normalize_ip,
    _parse_peer_addr,
    _write_node_status,
)
# noqa: F401 - re-exported for backward compatibility
from visold.network.tls import TLSManager
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.metrics import MetricsCollector, metrics
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.clock import NetworkClock, network_clock
# noqa: F401 - re-exported for backward compatibility
from visold.governance.versioning import ProtocolVersionManager
# noqa: F401 - re-exported for backward compatibility
from visold.governance.engine import GovernanceEngine, UpgradePhase, UpgradeProposal
# noqa: F401 - re-exported for backward compatibility
from visold.crypto.parallel_verify import (
    _PAR_SIG_THRESHOLD,
    _SIG_POOL,
    _SIG_POOL_LOCK,
    _get_sig_pool,
    _par_verify_sig,
)
# noqa: F401 - re-exported for backward compatibility
from visold.state.batch_proxy import _StorageBatchProxy
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.events import Event, EventType, GlobalSequencer
# noqa: F401 - re-exported for backward compatibility
from visold.state.engine import StateEngine
# noqa: F401 - re-exported for backward compatibility
from visold.economics.monitor import EconomicMonitor
# noqa: F401 - re-exported for backward compatibility
from visold.network.spv import SPVClient
# noqa: F401 - re-exported for backward compatibility
from visold.consensus.difficulty import DifficultyEngine
# noqa: F401 - re-exported for backward compatibility
from visold.consensus.hashrate_governor import HashrateGovernor
# noqa: F401 - re-exported for backward compatibility
from visold.consensus.mining_safety import MiningSafetyGuard
# noqa: F401 - re-exported for backward compatibility
from visold.consensus.rate_defection import RateDefectionAuditor
# noqa: F401 - re-exported for backward compatibility
from visold.crypto.base58 import B58_ALPHABET, b58decode, b58encode
# noqa: F401 - re-exported for backward compatibility
from visold.crypto.ecc import (
    ECPoint,
    G,
    _crypto_key_to_pub_point,
    _priv_int_to_crypto_key,
    ecdsa_keygen,
    ecdsa_sign,
    ecdsa_verify,
    pub_from_bytes,
    pub_from_hex,
    pub_to_address,
    pub_to_bytes,
    pub_to_hex,
    sig_from_hex,
    sig_to_hex,
)
# noqa: F401 - re-exported for backward compatibility
from visold.crypto.vrf import (
    _SECP256K1_N,
    _SECP256K1_P,
    _VRF_SUITE,
    _rfc6979_nonce,
    _secp256k1_hash_to_curve,
    _vrf_challenge,
    _vrf_point_to_bytes,
    _vrf_scalar_mul_G,
    _vrf_scalar_mul_point,
    vrf_prove,
    vrf_verify,
)
# noqa: F401 - re-exported for backward compatibility
from visold.crypto.hashing import hash_obj, sha256, sha256d
# noqa: F401 - re-exported for backward compatibility
from visold.vm.naming import (
    _CONTRACT_NAME_RE,
    derive_contract_address,
    normalize_contract_name,
    validate_contract_name,
)
# noqa: F401 - re-exported for backward compatibility
from visold.crypto.mnemonic import _MNEMONIC_WORDS, mnemonic_from_priv, priv_from_mnemonic
# noqa: F401 - re-exported for backward compatibility
from visold.wallet.hd import (
    _WALLET_DERIV_SALT,
    _WALLET_DERIV_VERSION,
    _hkdf_expand,
    _hkdf_extract,
    derive_wallet_from_secret,
    derive_wallet_priv,
)
# noqa: F401 - re-exported for backward compatibility
from visold.wallet.wallet import Wallet
# noqa: F401 - re-exported for backward compatibility
from visold.ledger.transaction import Transaction
# noqa: F401 - re-exported for backward compatibility
from visold.ledger.block import Block
# noqa: F401 - re-exported for backward compatibility
from visold.storage.block_database import BlockDatabase
# noqa: F401 - re-exported for backward compatibility
from visold.storage.sqlite_serialized import (
    _SerializedSQLiteConnection,
    _SerializedSQLiteCursor,
)
# noqa: F401 - re-exported for backward compatibility
from visold.storage.storage import Storage
# noqa: F401 - re-exported for backward compatibility
from visold.network.compression import CompressionEngine
# noqa: F401 - re-exported for backward compatibility
from visold.network.reputation import PeerReputationManager
# noqa: F401 - re-exported for backward compatibility
from visold.storage.state_pruner import StatePruner
# noqa: F401 - re-exported for backward compatibility
from visold.network.capabilities import (
    CAP_ARCHIVE,
    CAP_BOOTSTRAP,
    CAP_FULL_NODE,
    CAP_LIGHT_RELAY,
    CAP_VALIDATOR,
    CAP_VVM_EXEC,
    CapabilityRouter,
    MSG_CAPABILITY_ADV,
    MSG_CAPABILITY_QUERY,
    MSG_CAPABILITY_RESPONSE,
    MSG_CHUNK_DATA,
    MSG_CHUNK_MANIFEST,
    MSG_GET_CHUNK,
    MSG_GET_CHUNK_MANIFEST,
    MSG_GET_SNAPSHOT,
    MSG_GET_SNAPSHOT_MANIFEST,
    MSG_SNAPSHOT_DATA,
    MSG_SNAPSHOT_MANIFEST,
)
# noqa: F401 - re-exported for backward compatibility
from visold.storage.rolling_window_pruner import RollingWindowPruner
# noqa: F401 - re-exported for backward compatibility
from visold.network.block_download import ParallelBlockDownloader
# noqa: F401 - re-exported for backward compatibility
from visold.storage.snapshot import StateSnapshotEngine
# noqa: F401 - re-exported for backward compatibility
from visold.mempool.pool import Mempool, _MempoolHeap
# noqa: F401 - re-exported for backward compatibility
from visold.mempool.mev import CommitRevealMempool, _mev_mempool
# noqa: F401 - re-exported for backward compatibility
from visold.consensus.slashing import SlashingEvidenceProtocol
# noqa: F401 - re-exported for backward compatibility
from visold.vm.opcodes import (
    Op,
    _GAS,
    _GAS_REFUND_DENOMINATOR,
    _SSTORE_CLEAR_GAS,
    _SSTORE_REFUND,
    _SSTORE_RESET_GAS,
    _SSTORE_SET_GAS,
    _mem_expansion_cost,
)
# noqa: F401 - re-exported for backward compatibility
from visold.vm.frame import VVMResult, _ReentrancyGuard, _VMFrame
# noqa: F401 - re-exported for backward compatibility
from visold.vm.engine import (
    VVMEngine,
    _chan_recover_address,
    _chan_state_msg,
    _gas_price_to_sat,
)
# noqa: F401 - re-exported for backward compatibility
from visold.vm.abi import VVMABIDecoder, VVMABIEncoder
# noqa: F401 - re-exported for backward compatibility
from visold.vm.event_index import ContractEventIndex
# noqa: F401 - re-exported for backward compatibility
from visold.vm.assembler import AssemblyResult, VVMAssembler
# noqa: F401 - re-exported for backward compatibility
from visold.vm.precompiles import VVMPrecompiles
# noqa: F401 - re-exported for backward compatibility
from visold.vm.static_analyzer import VVMStaticAnalyzer
# noqa: F401 - re-exported for backward compatibility
from visold.rollup.compact_codec import (
    l2_pub_compact,
    l2_pub_expand,
    l2_sig_compact,
    l2_sig_expand,
)
# noqa: F401 - re-exported for backward compatibility
from visold.rollup.l2_state import (
    L2Account,
    L2StateTree,
    L2Transaction,
    L2_BRIDGE_ADDRESS,
    L2_WITHDRAW_ADDRESS,
    Layer2State,
)
# noqa: F401 - re-exported for backward compatibility
from visold.rollup.proofs import (
    IProofBackend,
    LocalDevBackend,
    ProofBackendError,
    ProofRegistry,
    SimulatedProofBackend,
    SubprocessSNARKBackend,
    UnsafeBackendOnMainnetError,
    _UNSAFE_SECURITY_TOKENS,
    _is_mainnet,
    _is_unsafe_backend,
    _visold_network,
)
# noqa: F401 - re-exported for backward compatibility
from visold.rollup.batches import RollupBatch, RollupSubmission
# noqa: F401 - re-exported for backward compatibility
from visold.rollup.ledger_sync import (
    _LOCAL_LEDGER_LOCK,
    _LOCAL_LEDGER_PATH,
    _ledger_collect_entries,
    _ledger_write_worker,
    sync_local_ledger,
)
# noqa: F401 - re-exported for backward compatibility
from visold.chain.sequencer import Sequencer
# noqa: F401 - re-exported for backward compatibility
from visold.chain.blockchain import Blockchain
# noqa: F401 - re-exported for backward compatibility
from visold.chain.roles import RoleManager
# noqa: F401 - re-exported for backward compatibility
from visold.chain.consensus_engine import ConsensusEngine
# noqa: F401 - re-exported for backward compatibility
from visold.network.kademlia import KBucket, KademliaRouter
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.lru_cache import LRUCache
# noqa: F401 - re-exported for backward compatibility
from visold.kernel.messages import (
    MSG_ACCEPT,
    MSG_ALERT,
    MSG_BLOCK,
    MSG_BLOCKTXN,
    MSG_BLOCK_CHUNK_DATA,
    MSG_BLOCK_MANIFEST,
    MSG_CHAIN,
    MSG_CMPCTBLOCK,
    MSG_GETBLOCKTXN,
    MSG_GET_BLOCK,
    MSG_GET_BLOCK_CHUNK,
    MSG_GET_BLOCK_MANIFEST,
    MSG_GET_CHAIN,
    MSG_GET_PEERS,
    MSG_HASHRATE_REPORT,
    MSG_HELLO,
    MSG_IDENTITY,
    MSG_L2TX,
    MSG_PEERS,
    MSG_PING,
    MSG_PONG,
    MSG_POW_CHALLENGE,
    MSG_RATE_DEFECTION_EVIDENCE,
    MSG_REJECT,
    MSG_RESOLVE,
    MSG_RESOLVE_RESP,
    MSG_TX,
    MSG_VALIDATOR_SIG,
    MSG_VERIFY,
)
# noqa: F401 - re-exported for backward compatibility
from visold.network.peer_connection import PeerConnection
# noqa: F401 - re-exported for backward compatibility
from visold.network.message_logger import P2PMessageLogger
# noqa: F401 - re-exported for backward compatibility
from visold.network.nat.upnp import UPnPManager
# noqa: F401 - re-exported for backward compatibility
from visold.network.nat.stun import ICECandidate, STUNClient
# noqa: F401 - re-exported for backward compatibility
from visold.network.nat.hole_punch import UDPHolePuncher
# noqa: F401 - re-exported for backward compatibility
from visold.network.nat.relay import RelayBridge
# noqa: F401 - re-exported for backward compatibility
from visold.network.nat.ice import ICEManager, _pow_check, _pow_solve
# noqa: F401 - re-exported for backward compatibility
from visold.network.dns_seeder import DNSSeeder
# noqa: F401 - re-exported for backward compatibility
from visold.network.p2p import P2PNetwork
# noqa: F401 - re-exported for backward compatibility
from visold.mining.workers import _build_mine_template, _cpu_mine_thread, _cy_mine_worker
# noqa: F401 - re-exported for backward compatibility
from visold.mining.gpu_kernels import _CUDA_SHA256_KERNEL, _OPENCL_SHA256_KERNEL
# noqa: F401 - re-exported for backward compatibility
from visold.mining.parallel_miner import ParallelMiner
# noqa: F401 - re-exported for backward compatibility
from visold.mining.engine import MiningEngine
# noqa: F401 - re-exported for backward compatibility
from visold.node.security_gate import SecurityGate
# noqa: F401 - re-exported for backward compatibility
from visold.identity.names import IdentitySystem
# noqa: F401 - re-exported for backward compatibility
from visold.api.rpc_server import RPCServer
# noqa: F401 - re-exported for backward compatibility
from visold.resilience.panic_breaker import PanicCircuitBreaker
# noqa: F401 - re-exported for backward compatibility
from visold.resilience.hardened_core import (
    AtomicStateTransition,
    ConservationViolation,
    GracefulDegradation,
    HardenedBaseError,
    ImmediateAbort,
    InvariantViolation,
    RecursionLimitExceeded,
    ResourceCap,
    StateRootMismatch,
    SystemInvariantGate,
    TimestampAnomalyError,
    _HCCircuitBreakerRecord,
    _HC_CB_FAILURE_THRESHOLD,
    _HC_CB_HALF_OPEN_DELAY_SEC,
    _HC_CORRUPTION_TRIP_COUNT,
    _HC_CORRUPTION_WINDOW_SEC,
    _HC_MAX_BALANCE_SAT,
    _HC_MAX_BLOCK_TX_COUNT,
    _HC_MAX_HEAP_MB,
    _HC_MAX_RECURSION_DEPTH,
    _HC_MAX_SATOSHI_SUPPLY,
    _HC_MAX_TIMESTAMP_DRIFT_SEC,
    _HC_MIN_TIMESTAMP_UNIX,
    _HC_NTP_MAX_DRIFT_SEC,
    _HC_NTP_REFRESH_INTERVAL,
    _HC_NTP_SAMPLE_COUNT,
    _HC_NTP_SERVERS,
    _HC_OP_TIMEOUT_SEC,
    _HardenedCBSingleton,
    _HardenedSystemMode,
    _NTPClock,
    _hc_inv,
    _hc_ntp_clock,
    _hc_panic_cb,
    _make_degraded_event_index_save,
    _make_hardened_apply_block,
    _make_hardened_credit_sat,
    _make_hardened_debit_sat,
    _make_hardened_vvm_internal_call,
    apply_hardened_overlay,
)
# noqa: F401 - re-exported for backward compatibility
from visold.testing.hardened_verification import HardenedVerificationSuite
# noqa: F401 - re-exported for backward compatibility
from visold.resilience.sentinel import SentinelNode
# noqa: F401 - re-exported for backward compatibility
from visold.resilience.safety_invariants import SafetyInvariantChecker
# noqa: F401 - re-exported for backward compatibility
from visold.node.visold_node import UserAccount, VisoldNode
# noqa: F401 - re-exported for backward compatibility
from visold.cli.terminal import (
    BLUE,
    BOLD,
    CYAN,
    DIM,
    GREEN,
    MAGENTA,
    RED,
    RESET,
    WHITE,
    YELLOW,
    _ANSI_OK,
    _WIN_VT_ENABLED,
    _enable_windows_ansi,
    _stdout_is_tty,
    bold,
    clr,
)
# noqa: F401 - re-exported for backward compatibility
from visold.cli.interactive import CLI
# noqa: F401 - re-exported for backward compatibility
from visold.testing.suite import TestSuite
# noqa: F401 - re-exported for backward compatibility
from visold.economics.rewards import (
    Coinbase,
    RewardConfig,
    RewardError,
    _decode_coinbase_data,
    _g,
    _is_coinbase_like,
    _tx_amount,
    _tx_id,
    _tx_inputs,
    _tx_nonce,
    _tx_outputs,
    _tx_receiver,
    _tx_sender,
    _tx_signature,
    assert_inputs_mature,
    build_coinbase,
    compute_tx_fee,
    sum_block_fees,
    validate_block_rewards,
)
# noqa: F401 - re-exported for backward compatibility
from visold.cli.handler import CLIHandler
# noqa: F401 - re-exported for backward compatibility
from visold.cli.entry import main
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.model import (
    AnomalyKind,
    AnomalyReport,
    BaselineTracker,
    MetricsRingBuffer,
    Severity,
    SeverityDecision,
)
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.monitors import (
    GasMonitor,
    MonitorBus,
    ReentrancyPatternDetector,
    TransactionMonitor,
    ValidatorMonitor,
)
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.detection import AnomalyDetectionEngine, StatisticalDetector
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.decision import DecisionEngine, GameTheoryModel
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.rollback import (
    BlockSnapshot,
    GovernanceRollbackVote,
    RollbackExecutor,
    SnapshotStore,
    _verify_shbs_validator_signature,
)
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.healing import (
    FreezeRegistry,
    HealingActionLayer,
    HealingActionLog,
    RateLimiter,
    ValidatorAlerter,
)
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.supply_monitor import SupplyConservationMonitor
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.state_hook import StateEngineHook
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.orchestrator import SelfHealingSystem
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.storage_patch import (
    _fmt_time,
    _patch_storage_for_shbs,
    _storage_get_total_supply_sat,
    _storage_get_vvm_receipts_for_block,
    _storage_slash_validator,
    patch_storage,
)
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.docs_text import ARCHITECTURE_DIAGRAM, INTEGRATION_GUIDE
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.hardening.risk import (
    AnomalyFrequencyTracker,
    EconomicImpactSimulator,
    HardenedDecision,
    MultiSignalConfirmationWindow,
    RiskScore,
    RiskScoringEngine,
    RollbackAbuseGuard,
    RollbackPreview,
    SignalRecord,
)
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.hardening.patches import (
    SafeActionValidator,
    _build_action_tags,
    _dry_run_preview,
    _notify_governance_required,
    _stat_sample_interval,
    _verify_post_rollback,
    apply_hardening_patch,
    patch_anomaly_detection_engine,
    patch_decision_engine,
    patch_healing_action_layer,
    patch_rollback_executor,
)
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.hardening.operator_api import _attach_operator_apis
# noqa: F401 - re-exported for backward compatibility
from visold.selfhealing.hardening.failure_analysis import FAILURE_CASE_ANALYSIS
# noqa: F401 - re-exported for backward compatibility
from visold.testing.sc_name_tests import _sc_name_1_run_tests

# conditionally defined names (optional dependencies): exported only if they exist, as before
try:
    from visold.kernel.compat import _Argon2Type  # noqa: F401
except ImportError:
    pass
try:
    from visold.kernel.compat import _CythonShim  # noqa: F401
except ImportError:
    pass
try:
    from visold.kernel.compat import _asyncpg  # noqa: F401
except ImportError:
    pass
try:
    from visold.rollup.proofs import _dev_backend  # noqa: F401
except ImportError:
    pass
try:
    from visold.kernel.compat import _il_util  # noqa: F401
except ImportError:
    pass
try:
    from visold.rollup.proofs import _legacy_alias  # noqa: F401
except ImportError:
    pass
try:
    from visold.kernel.compat import _msgpack  # noqa: F401
except ImportError:
    pass
try:
    from visold.network.message_logger import _p2p_log_env  # noqa: F401
except ImportError:
    pass
try:
    from visold.kernel.compat import _plyvel  # noqa: F401
except ImportError:
    pass
try:
    from visold.kernel.compat import _redis  # noqa: F401
except ImportError:
    pass
try:
    from visold.kernel.compat import _rocksdb  # noqa: F401
except ImportError:
    pass
try:
    from visold.kernel.compat import _zstd_mod  # noqa: F401
except ImportError:
    pass
try:
    from visold.kernel.compat import hash_secret_raw  # noqa: F401
except ImportError:
    pass


# Dispatch only the requested mode on direct execution.  Printing the large
# architecture/integration documents unconditionally before `main()` polluted
# the TUI and made --help/--version unusable as clean, beginner-friendly entry
# points.  Developers can still request the documents explicitly.
if __name__ == "__main__":
    import sys as _sys_main
    if "--architecture" in _sys_main.argv:
        print(ARCHITECTURE_DIAGRAM)
        print(INTEGRATION_GUIDE)
        _sys_main.exit(0)
    elif "--verify-hardened" in _sys_main.argv:
        _suite = HardenedVerificationSuite()
        _ok = _suite.run()
        _sys_main.exit(0 if _ok else 1)
    elif "--test-sc-name-1" in _sys_main.argv:
        _sc_name_1_run_tests()
    else:
        main()
