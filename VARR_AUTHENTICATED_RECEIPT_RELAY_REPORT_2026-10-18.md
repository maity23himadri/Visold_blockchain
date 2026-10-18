# Visold VARR Authenticated Receipt Relay — Implementation Report

Date: 2026-10-18
Base: Visold_5_pruning_authenticated_bootstrap_stale_sync_fix

## Goal
Preserve compact wallet transaction provenance across global block-body pruning without retaining full historical transaction bodies on every node. An offline target wallet can later recover an authenticated receipt through the peer mesh; after receipt delivery, a receiver-signed ACK makes relay copies eligible for garbage collection.

## Protocol summary

VARR (Visold Authenticated Relay Receipts) is a non-consensus metadata layer. It never changes balances or makes an invalid block valid.

For every confirmed non-coinbase transaction with a receiver, a compact receipt contains:
- protocol domain/version and chain id
- block height, canonical block hash, Merkle root
- transaction id
- canonical signed transaction fields (large transaction data is represented by its committed data_hash)
- original public key and transaction signature
- Merkle inclusion proof
- receipt id = SHA-256 of canonical receipt content

A receiving/relay node verifies the transaction id, sender/public-key binding, transaction signature, Merkle proof, and the referenced canonical local block header before accepting the receipt.

## Temporary distributed mailbox

Each receiver has 12 deterministic mailbox slots. Each slot derives an XOR routing key from chain id, receiver address and slot number. PUT/QUERY/ACK messages route over the existing peer mesh; the target does not need a direct connection to the current custodian.

Routing prefers strictly closer XOR peers. Sparse/tree meshes can have local minima, so a tightly bounded non-greedy fallback can explore an unvisited farther hop. The current local minimum still stores/responds/ACKs while the fallback is explored. A visited path, global hop cap, fallback-hop cap, message rate limits and fanout bounds limit loops/amplification.

## Dynamic repair

Relay storage is not tied permanently to 12 fixed nodes. Surviving custodians periodically republish one deterministic slot. Across maintenance passes, a surviving copy can repopulate the current live placement set when topology changes or previous custodians disappear.

No distributed system can recover a receipt if every existing copy and every source capable of republishing it disappear simultaneously before delivery. Replication and repair reduce this availability risk; they cannot make it mathematically impossible.

## Receiver ACK and deletion

After the target wallet receives and independently verifies a receipt, it signs a domain-separated ACK containing the chain id, receiver and receipt id. Custodians verify that the ACK public key owns the receipt receiver address and verify the signature. Only then is a relay copy marked delivered. A grace interval is retained before garbage collection so ACK propagation and duplicate delivery remain robust.

A forged ACK from another wallet cannot delete the receipt.

## Wallet history

Delivered receipts are stored only in the target node's local wallet_receipts table and merged into the existing address-history query with txid de-duplication. Consequently, after the original block body has been pruned, the wallet can still show sender, receiver, amount, tx type and block height from the authenticated receipt.

This does not recreate the full historical transaction payload and does not enlarge global consensus state.

## Exact requested scenario verified

Regression test:
- Node B is copied/offline at height 5.
- Node D sends B exactly 5 VSD in block 8.
- Source/network advances to height 20.
- Blocks 6, 7, 8, 9 and 10 are all body-pruned.
- B performs the authenticated stale-node snapshot fast-forward.
- B reaches height 20 with exactly 5 VSD from consensus state.
- B later receives the temporary VARR receipt over the relay layer.
- B's wallet history reports D as sender, B as receiver, 5 VSD, block 8.

PASS.

## Security tests verified

The VARR test suite currently covers:
1. Receipt remains verifiable using a retained canonical header after the full block body is pruned.
2. Signed sender/amount provenance is retained in the target wallet.
3. Receipt field tampering is rejected even if an attacker recomputes the outer receipt id.
4. Forged receiver ACK is rejected and does not delete custody.
5. Mailbox query succeeds through a multi-hop mesh without a direct target-to-custodian connection, including a route whose first hop is farther in XOR distance.
6. A surviving custodian repairs a replica to a newly available closer node.
7. Exact height-5/offline -> tx-at-8 -> pruned-6..10 -> source-height-20 -> snapshot catch-up -> sender/history recovery scenario.

Latest VARR suite result: 5 passed, 0 failed.

Post-routing-change peer security + sync-gate regressions: 18 passed, 0 failed.

Previously rerun independently on this implementation branch:
- pruning block-sync safety: 12 passed
- pruned resync integration: 1 passed
- authenticated pruning bootstrap: 6 passed
- peer security: 13 passed
- sync gate: 5 passed
- block application: 9 passed

The complete repository currently collects 262 tests. A complete 262/262 run was not certified in this execution environment because the long full-suite invocation did not complete; no full-suite pass is claimed.

## Storage tables

Non-consensus SQLite tables added with CREATE TABLE IF NOT EXISTS:
- relay_receipts
- relay_receipt_acks
- wallet_receipts

The same auxiliary schema is created for normal SQLite and the PGX auxiliary SQLite path.

## Default configuration

- VISOLD_RECEIPT_RELAY=1
- RECEIPT_REPLICA_SLOTS=12
- RECEIPT_ROUTE_HOPS=24
- RECEIPT_ROUTE_FANOUT=2
- RECEIPT_ROUTE_FALLBACK_HOPS=6
- RECEIPT_QUERY_LIMIT=128
- RECEIPT_MAX_BYTES=16384
- RECEIPT_REPAIR_INTERVAL_SECS=60
- RECEIPT_ACK_GRACE_SECS=300
- VISOLD_RECEIPT_MAX_AGE_BLOCKS=0 by default

MAX_AGE_BLOCKS=0 intentionally means an undelivered receipt does not expire merely because the receiver is offline, matching the requested delivery-until-ACK semantics. The trade-off is that permanently abandoned receiver addresses can cause relay storage to grow. Operators can configure a finite maximum age if bounded storage is more important than indefinite offline delivery.

## Trust boundary

Relay peers are untrusted. They may withhold or delete their own copies, but they cannot alter a receipt into another valid transaction or forge receiver delivery authorization without breaking the transaction signature/Merkle/canonical-header verification or receiver ACK signature. Consensus state correctness remains provided by normal block validation and the authenticated snapshot mechanism; VARR only restores wallet provenance metadata.
