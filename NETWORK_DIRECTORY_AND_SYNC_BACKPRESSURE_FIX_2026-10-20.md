# Visold Network Directory and Sync Backpressure Fix

Date: 2026-10-20
Base: `Visold_SATURATION_SEED_UNBOUNDED_TARGET_FIX.zip`

## User-visible changes

- F4 / Nodes view now displays exact peer IP and port, connection direction, height, identity/user ID, and VSD address for direct peers.
- Menu option `29 — Network-wide Node Directory` browses locally known nodes from live peers, paginated PEX gossip, DHT/router entries, DNS/bootstrap discoveries and the durable peer cache. It shows endpoint, user ID, chain height, source/status, VSD address and node ID.
- Directory search supports registered name, advertised user ID, VSD address, IP, port and node ID. Selecting an entry or entering `c IP:port` attempts a manual connection.
- PEX directory pages are capped at 100 records, the local cache is capped at 5,000 entries, and stale records expire. A decentralized PEX cache is eventually consistent: a node cannot guarantee every currently-online node worldwide is known immediately, and an endpoint behind NAT/CGNAT may not accept inbound manual connections.
- A name is labelled as a registered name only when the local canonical on-chain name claim resolves and its wallet address exactly matches the advertised VSD address. Account IDs in `name#suffix` form are also resolved against the bare-name claim. Unverified PEX advertisements never override an authenticated endpoint.

## Sync-load and fork-safety behavior

- The handshake advertises `chain_height` and `chain_tip_hash`. If local and remote height and tip hash are identical, the node skips the costly full-history initial replay. If the hashes differ, or a compatible peer does not advertise a tip hash, the conservative sync/fork-check path remains available.
- Tip hash is only a scheduling hint. It is not used to accept blocks, choose a fork, validate work, or override state-root/chain validation. Existing block acceptance, authenticated bootstrap, and consensus/fork-choice logic are unchanged.
- Automatic full sync uses one global local sync gate. Periodic sync heartbeat chooses one peer at a time instead of broadcasting chain requests to every peer. The periodic overlap audit remains bounded and rotates peers.
- Chain serving is limited to four concurrent chain-scan requests per process; each response is capped at 200 blocks. Busy servers return an explicitly correlated, retryable busy response instead of doing unlimited DB scans. Ordinary sync retries are bounded; authenticated bootstrap retries its own busy response by matching `request_id`, so busy backpressure is not misinterpreted as chain data or a fork.
- Existing per-peer `GET_CHAIN` rate limit remains active. These controls limit concurrency and retry amplification; they do not guarantee zero load on a seed with unlimited peers.

## Seed discovery note

Clients still automatically discover seed/bootstrap endpoints through the existing DNS/bootstrap discovery path; they do **not** need `VISOLD_SEED_NODE=1` just to find a seed. `VISOLD_SEED_NODE=1` (or `"seed_node": true`) is only for the operator intentionally running that process as the designated seed, to advertise its seed role and activate the seed-only peer policy.

## Verification performed

- Python compile check: passed.
- Main targeted directory/mesh/port/shutdown/logic-hash/security/sync-gate batch: **69 passed**.
- Pruned block sync safety: **12 passed**.
- Authenticated pruned reconnect bootstrap: **5 passed**.
- Same-height pruned reconnect sync: **5 passed**.
- Pruning authenticated bootstrap: **8 passed**.
- Same-height bootstrap recovery dispatch: **4 passed**.
- UDP peer recovery regressions: **4 passed**.
- Two-node pruning-boundary reconnect: **2 passed**.
- Total across those selected runs: **109 tests passed**. A combined run of the slower bootstrap set exceeded the command timeout; the files were rerun separately and passed.
- Build source hash in `visold/_build_identity.json` matches the current 149 Python source files.
- The archive has not been tested as a live six-node Android/Termux network in this environment. Please verify both sides' peer lists and actual chain-height convergence on-device. Older APK instances do not inherit this Python source patch until rebuilt/replaced.
