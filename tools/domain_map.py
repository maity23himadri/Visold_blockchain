"""
domain_map.py - the architecture blueprint (v2).

BOUNDARIES: (first_line, "context/module")  -- every non-import unit whose first
source line is >= first_line and < the next boundary goes to that module.
Line numbers refer to the ORIGINAL monolith (visold_vsd_.py, 55,370 lines).
Special: top-level `if __name__ == "__main__":` units -> ENTRY (the thin facade),
         unit 0 (module docstring)                  -> DOCS.
"""
BOUNDARIES = [
    # ── network: UDP transport ─────────────────────────────────────────────
    (1858, "network/udp/wire"), (1986, "network/udp/reliability"), (2197, "network/udp/session"),
    (2430, "network/udp/wire"), (2468, "network/udp/latency"), (2551, "network/udp/transport"),
    (2677, "network/udp/wire"), (2690, "network/udp/transport"),
    # ── kernel + optional dependencies + storage backends ─────────────────
    (2882, "kernel/compat"),
    (2923, "storage/backends"),            # RocksDB key schema + PG schema + Rocks/Pg/Redis adapters
    (3366, "kernel/serialization"),
    (3387, "kernel/compat"),
    (3539, "crypto/keystore"),             # _ARGON2_* KDF parameters
    (3551, "kernel/source_identity"),
    (3585, "kernel/logging_setup"),
    (3630, "kernel/notifications"),
    (3734, "kernel/logging_setup"),
    (3816, "kernel/config"),
    (4898, "kernel/units"),
    (4975, "kernel/netutil"),
    (5222, "network/tls"),
    (5584, "kernel/metrics"),
    (5667, "kernel/clock"),
    (5898, "governance/versioning"),
    (5979, "governance/engine"),           # UpgradePhase/UpgradeProposal + GovernanceEngine
    (6736, "crypto/parallel_verify"),
    (6803, "state/batch_proxy"),
    (7053, "kernel/events"),
    (7149, "state/engine"),
    (7989, "economics/monitor"),
    (8289, "network/spv"),
    (8491, "consensus/difficulty"),
    (9129, "consensus/hashrate_governor"),
    (9514, "consensus/mining_safety"),
    (9767, "consensus/rate_defection"),
    # ── cryptography / wallet ─────────────────────────────────────────────
    (10322, "crypto/base58"), (10360, "crypto/ecc"), (10486, "crypto/vrf"),
    (10770, "crypto/hashing"),
    (10785, "vm/naming"),
    (10841, "crypto/hashing"),
    (10845, "crypto/keystore"),
    (11006, "crypto/mnemonic"),
    (11208, "wallet/hd"),
    (11304, "wallet/wallet"),
    # ── ledger / storage ──────────────────────────────────────────────────
    (11419, "ledger/transaction"), (11908, "ledger/block"),
    (12426, "storage/block_database"), (12772, "storage/sqlite_serialized"), (12903, "storage/storage"),
    (16216, "network/compression"), (16351, "network/reputation"),
    (16492, "storage/state_pruner"),
    (16595, "network/capabilities"),
    (16626, "storage/rolling_window_pruner"),
    (17019, "network/block_download"),
    (17266, "storage/snapshot"),
    (17759, "network/capabilities"),
    (17896, "mempool/pool"),               # _MempoolHeap + Mempool
    (18868, "mempool/mev"),
    (18996, "consensus/slashing"),
    # ── VVM ───────────────────────────────────────────────────────────────
    (19197, "vm/opcodes"), (19688, "vm/frame"), (20058, "vm/frame"), (20095, "vm/engine"),
    (21759, "vm/naming"), (21766, "vm/abi"), (21947, "vm/event_index"),
    (22140, "vm/assembler"), (22597, "vm/precompiles"), (22900, "vm/static_analyzer"),
    # ── Layer-2 rollup ────────────────────────────────────────────────────
    (23259, "rollup/compact_codec"), (23439, "rollup/l2_state"), (24098, "rollup/proofs"),
    (24826, "rollup/batches"), (25061, "rollup/ledger_sync"),
    # ── chain services ────────────────────────────────────────────────────
    (25229, "chain/sequencer"), (25776, "chain/blockchain"),
    (30471, "chain/roles"), (30664, "chain/consensus_engine"),
    # ── network ───────────────────────────────────────────────────────────
    (30997, "network/kademlia"),
    (31139, "kernel/lru_cache"),
    (31219, "kernel/messages"),
    (31300, "network/peer_connection"), (31631, "network/message_logger"),
    (31826, "network/nat/upnp"), (32147, "network/nat/stun"), (32330, "network/nat/hole_punch"),
    (32534, "network/nat/relay"), (32833, "network/nat/ice"),
    (33346, "network/dns_seeder"), (33449, "network/p2p"),
    # ── mining ────────────────────────────────────────────────────────────
    (38512, "mining/workers"), (38797, "mining/gpu_kernels"), (39055, "mining/parallel_miner"),
    (39546, "mining/engine"),
    # ── node-level services, identity, api, resilience ───────────────────
    (40214, "node/security_gate"),
    (40273, "identity/names"),
    (40410, "api/rpc_server"),
    (41691, "resilience/panic_breaker"),
    (41864, "resilience/hardened_core"),
    (42880, "testing/hardened_verification"),
    (42994, "resilience/sentinel"),
    (43250, "resilience/safety_invariants"),
    (43641, "node/visold_node"),           # VisoldNode + UserAccount (mutually dependent)
    (44546, "node/visold_node"),
    # ── interface / testing ───────────────────────────────────────────────
    (44854, "cli/terminal"), (44937, "cli/interactive"),
    (48571, "testing/suite"),
    (49199, "economics/rewards"),
    (49584, "cli/handler"), (50037, "cli/entry"),
    # ── self-healing (SHBS) + hardening overlay ──────────────────────────
    (50153, "selfhealing/model"), (50300, "selfhealing/model"),
    (50388, "selfhealing/monitors"), (50959, "selfhealing/detection"), (51098, "selfhealing/decision"),
    (51375, "selfhealing/rollback"), (51463, "selfhealing/rollback"),
    (51827, "selfhealing/healing"), (52388, "selfhealing/supply_monitor"),
    (52503, "selfhealing/state_hook"), (52589, "selfhealing/orchestrator"),
    (52871, "selfhealing/storage_patch"),
    (52981, "selfhealing/docs_text"),
    (53341, "selfhealing/storage_patch"),
    (53350, "selfhealing/hardening/risk"),
    (53956, "selfhealing/hardening/patches"),
    (54965, "selfhealing/hardening/operator_api"),
    (55101, "selfhealing/hardening/failure_analysis"),
    (55206, "testing/sc_name_tests"),
]
OVERRIDES = {}

CONTEXT_DOCS = {
    "kernel": "Shared kernel: configuration, optional-dependency detection, logging, metrics, clock, units,\nnetwork helpers, protocol message ids, events, LRU cache.  Depends on nothing else in the package.",
    "crypto": "Cryptographic primitives: secp256k1 ECDSA, VRF, hashing, Base58, mnemonic, encrypted keystore,\nparallel signature verification.",
    "consensus": "Consensus rules that do not need chain state: difficulty, hashrate governor, mining safety,\nrate-defection auditor, slashing evidence.",
    "rollup": "Layer-2 rollup core: compact codecs, L2 state, proof backends, batches, local ledger sync.",
    "vm": "Visold Virtual Machine (VVM): opcodes, frames, engine, ABI, assembler, precompiles, static analyzer,\ncontract naming/addressing.",
    "wallet": "Wallet entities: key-holding wallet and HD derivation.",
    "ledger": "Ledger entities: Transaction and Block.",
    "storage": "Persistence: SQLite/RocksDB/PostgreSQL/Redis adapters, block database, pruners, snapshots.",
    "mempool": "Pending-transaction pool and MEV protection (commit-reveal).",
    "state": "State engine (single-writer, event-driven) and storage batch proxy.",
    "governance": "Protocol versioning and upgrade governance.",
    "economics": "Economic security monitoring and reward / coinbase rules.",
    "chain": "Chain services: Blockchain (chain management, reorg), role manager, consensus engine, L2 sequencer.",
    "network": "P2P networking: TCP/UDP transports, NAT traversal, discovery, TLS, reputation, SPV light client.",
    "mining": "Mining: workers, GPU kernels, parallel miner, auto-mining engine.",
    "identity": "Decentralized name service.",
    "api": "JSON-RPC server for wallets and explorers.",
    "resilience": "Runtime resilience: panic circuit breaker, hardened core overlay, sentinel, safety invariants.",
    "selfhealing": "Self-Healing Blockchain System (SHBS): monitors, anomaly detection, decisions, healing, rollback,\nplus the hardening overlay.",
    "node": "Node composition root: VisoldNode, user accounts, security gate.",
    "cli": "Interfaces: interactive terminal UI, argparse CLI handler, entry point (main).",
    "testing": "Embedded test suites and verification harnesses.",
}
