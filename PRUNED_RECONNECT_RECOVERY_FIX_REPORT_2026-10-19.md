# Visold 10 — Authenticated Recovery After Pruned-Block Sync Rejection

Date: 2026-10-19

## Summary

Fixed the integration gap where a non-zero-height node received a `pruned/header-only` rejection during normal chain sync and then retried the ineffective genesis range `0..199`, instead of activating the existing authenticated snapshot recovery mechanism.

### Production changes

- `visold/network/p2p.py`
  - Detects explicit pruned-block-body rejection reasons in `_on_chain_sync_result()`.
  - Starts a throttled, per-peer authenticated recovery worker and does not repeat the known-ineffective genesis replay for that rejection.
  - Makes the peer-connect auto-sync loop yield while authenticated recovery is active, avoiding concurrent legacy requests racing bootstrap.
  - Adds `_authenticated_pruned_recovery_from_peer()`, which requests a snapshot manifest and only attempts a committed snapshot strictly ahead of local height. It uses the existing `verify_bootstrap_header_chain` / `_authenticated_bootstrap_from_manifest` trust path, not the legacy unauthenticated equal-height restore path.
  - Serializes snapshot installation with the existing checkpoint-recovery lock and protects the peer's snapshot response queue.
  - After restore, removes persisted mempool entries already present in the canonical transaction/replay indexes and purges stale nonces.
  - Triggers receipt mailbox retrieval immediately after canonical header records are installed, so receipts for pruned transaction bodies can be verified against retained Merkle roots.

- `tests/test_pruning_authenticated_bootstrap.py`
  - Corrected a flaky replay-guard assertion: it previously selected any replay ID from the source at height 5 even though the snapshot represented height 4. The test now selects an ID from the exact authenticated snapshot payload.

- `tests/test_pruned_reconnect_authenticated_bootstrap.py`
  - New tests for rejection dispatch, manifest eligibility, refusal of equal-height/uncommitted snapshots, mempool reconciliation, and an end-to-end offline-receiver recovery scenario.

## End-to-end regression scenario

The regression test uses real Visold `Blockchain`, SQLite `Storage`, block validation/application, pruning, authenticated header verification, snapshot restore, mempool reconciliation, and receipt proof verification. Only the P2P transport is mocked; no real nodes or live network are started.

The receiver's database contains a signed transfer in its persisted mempool at height 5. The source mines that transfer, advances to height 20, and prunes the transfer's block body. The test then invokes the actual sync-rejection callback for the stale receiver.

Assertions passing:

- Recovery is triggered automatically from the pruned-body rejection callback.
- The receiver advances to height 20 using an authenticated snapshot at height 18 and validated full blocks 19–20.
- Canonical tip hash and state root match the source.
- Receiver balance matches the source and equals 5 VSD.
- The now-confirmed transaction is removed from the receiver's persisted and in-memory mempool.
- Receipt mailbox retrieval is triggered after restoring the canonical header; the real receipt proof is verified and receiver history is persisted. The receipt delivery itself is supplied by a test mailbox stub; separate existing tests cover mesh mailbox routing.

## Verification results

`python -m compileall -q visold tests` completed successfully.

The following targeted test groups passed when run separately:

- Recovery-dispatch, authenticated-bootstrap, pruning, receipt-relay, sync-gate, sync-import, economic-monitor and balance-history regression groups: **49 passed total across the two grouped runs**.
- Additional overlapping confirmation run (`test_pruned_reconnect_authenticated_bootstrap.py` plus `test_sync_import_optimizations.py`): **11 passed**.

One attempt to run the full selected group in a single pytest process timed out; the sync-import tests emit a Python multiprocessing `fork()` warning because the process is multithreaded. The relevant groups passed in separate runs. The entire repository test suite was not run, so this report does not claim a full-suite pass.

## Security properties retained

- `accept_chain()` still rejects pruned/header-only blocks; it was not weakened.
- The snapshot must carry a bootstrap commitment digest.
- The header chain from the local genesis trust anchor through the snapshot commitment block is independently verified.
- The snapshot digest and commitment must match.
- The local chain must be an exact canonical prefix of the verified chain before snapshot state is replaced.
- If there is no suitable authenticated snapshot, recovery fails closed and logs the failure instead of accepting a peer's unverified state.
