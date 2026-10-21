# Peer-height poisoning fix — 2026-10-21

## Confirmed source-level problems addressed

1. `MSG_BLOCK` raised `peer.chain_height` from an incoming block's unvalidated `index` before the StateEngine accepted the event. This was removed.
2. `MSG_CMPCTBLOCK` raised the same field from an unvalidated header index. This was removed.
3. A `MSG_CHAIN` response updated persistent peer height from its `server_height` and block indexes before the batch had passed chain validation. This persistent mutation was removed; response-local `server_height` remains available for pagination decisions.
4. `MSG_TX` could update peer height and tip hash from incidental message fields, even though transaction gossip is not a chain-tip verification path. That metadata update was removed.
5. Mining safety consumed the raw peer-advertised height, so a fabricated claim could make a node believe it was behind. Peer metadata now separates advertised height from verified progress; mining safety uses only `verified_chain_height` and rechecks the proof hash against local canonical storage.
6. PEX could forward an advertised peer height for another node. PEX output now sends `chain_height: -1` (unknown) and does not relay third-party height claims. A joining node learns its own peer's advertised height directly during its handshake.

## Verified-height rule

A peer gains verified-height credit only after a block or sync batch is accepted and the supplied block hash matches the locally stored canonical block at the same index. The highest such height stores its proof hash. If a reorg replaces that canonical block, the height is invalidated on the next mining-safety read.

## Files changed

- `visold/network/p2p.py`
- `visold/network/peer_connection.py`
- `visold/network/udp/transport.py`
- `visold/mining/engine.py`
- `visold/state/engine.py`
- `tests/test_peer_height_poisoning_regressions_20261021.py`

## Tests and limits

- `python -m py_compile` on the modified modules and new regression test: passed.
- Focused regression and related P2P/sync/pruning suite: **61 passed**.
- A full `pytest -q` run exceeded the available 120-second execution window after printing 56 progress dots; it is not reported as a pass.
- No live three-node network exploit/recovery run was performed in this sandbox. The tested evidence is unit/regression-level, not a claim of end-to-end multi-node verification.

## Design note

Unverified height advertisements still exist as sync-discovery hints on a directly connected peer for compatibility, but are not evidence for mining safety and are not forwarded via PEX. This blocks the identified fake-height poisoning path without confusing a peer's claim with the local canonical chain height.
