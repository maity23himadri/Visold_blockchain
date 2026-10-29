# Visold V4 Bugfix Progress — Batch 8 — 2026-10-29

## Scope

Baseline: `Visold_V4_Batch7_Fixed.zip`.

This batch re-verified and fixed BUG-39, BUG-40, BUG-41, BUG-42, BUG-43, BUG-44, and BUG-46. It also reran all prior batch regressions to detect garbage/incomplete earlier fixes.

## Dispositions

| Bug | Disposition | Root cause | Fix | Verification |
|---|---|---|---|---|
| BUG-39 | Confirmed, fixed | `_addr_to_int()` excluded every address beginning `VSDc` from EOA Base58 decoding, so a valid wallet whose payload starts with `c` was text-encoded instead of ABI uint160. | Exact canonical contract shape (`VSDc` + 36 hex chars) is checked first; otherwise any valid `VSD` Base58 payload decoding to 20 bytes is encoded as EOA, including `VSDc...` wallets. | Batch-8 targeted regression baseline FAIL / patched PASS. |
| BUG-40 | Confirmed, fixed | `BLOCKHASH` explicitly returned zero for height 0 even when block 0 existed and was inside the 256-block window. | Removed the special `n == 0` rejection; current/future and >256-old heights still return zero. | Real VVM opcode execution: baseline FAIL / patched PASS. |
| BUG-41 | Confirmed, fixed | Reassembly accepted offsets above an already-declared LAST and count-based completion could be poisoned by out-of-range fragments. | Once LAST is known, offsets above it are rejected; when LAST arrives, previously received offsets above it are pruned. Completion remains O(1): under the enforced unique/non-negative/in-range invariant, `len(frags) == last_off + 1` is mathematically equivalent to exact containment. | Two ordering/poison cases baseline FAIL / patched PASS. |
| BUG-42 | Confirmed, fixed | Receiver limit was 2,048 fragments (~2.84 MB), while configured P2P messages can be up to 32 MiB; dropped high offsets were ACKed unconditionally. | Fragment limit now covers zlib worst-case compressed size for `Config.MAX_MESSAGE_SIZE` while remaining inside the 16-bit wire offset. Unrepresentable fragments are not ACKed. Outbound send refuses a message exceeding the representable configured limit instead of silently wrapping/dropping. | 3.1 MB incompressible production compression/reassembly test baseline FAIL / patched PASS; no-ACK test baseline FAIL / patched PASS. |
| BUG-43 | Confirmed, fixed | `StateEngine._handle_mine_result()` converted stale/lost mined candidates into `ok=True`, then ran governance, metrics, broadcast, orphan-drain and SHBS post-apply actions. | `ok=True` now requires the candidate itself to be canonical at its height. Stale or fork-choice-losing candidates return not-applied, skip `block_apply` poisoning, and skip all post-apply work. | Stale mined-candidate regression baseline FAIL / patched PASS. |
| BUG-44 | Confirmed, fixed | Personal ledger was append/dedup-by-txid only; rollback did not remove orphan entries, and reinclusion retained the orphan height. Async writer could race rollback. | Entries now include `Block_Hash`. `_rollback_block()` synchronously invalidates the block in the local ledger. The same lock and invalidated-block set prevent a delayed writer from resurrecting an orphan. Re-inclusion under a different block hash records the new height. Legacy entries without `Block_Hash` are removed by height as a migration fallback. | Orphan removal + delayed-writer + reinclusion regression baseline FAIL / patched PASS. |
| BUG-46 | Confirmed, fixed | RPC hardcoded `ok: true` / `gossiped: true` regardless of local sequencer admission or peer fanout. | `broadcast_l2_tx()` returns scheduled/attempted gossip target count. RPC reports `gossiped` from that count and `ok` only if admitted locally or scheduled to at least one connected gossip peer. Adds `gossip_targets` and `gossip_msg`. | Real localhost RPC with no sequencer and no network peers: baseline incorrectly returned true; patched returns false. |

## Important engineering choices

### BUG-41: no O(n^2) completion scan

A first-pass implementation used `all(off in frags for off in range(last_off + 1))`. That is correct but would turn large UDP reassembly into an O(n^2) path because completeness is checked on every fragment. It was rejected before packaging. The final implementation instead enforces the stronger invariant that every retained offset is unique, non-negative, and <= LAST once LAST is known. Under that invariant, count equality is exact containment and stays O(1).

### BUG-42: support the configured message size, not an arbitrary larger attack surface

The wire offset is 16-bit, but simply raising the limit to 65,536 fragments would increase per-group memory exposure unnecessarily. The final cap is derived from the configured 32 MiB maximum message size plus zlib worst-case expansion, bounded by the wire maximum. This supports every protocol-accepted message without silently broadening the accepted message domain beyond configuration.

### BUG-43: “node stayed healthy” is not “candidate applied”

The fix deliberately separates fork-choice rejection from successful application. A stale local candidate is not a successful block application just because the canonical chain remains healthy.

### BUG-44: asynchronous writer race

Removing an already-written orphan entry alone was insufficient: the daemon ledger writer could still append it after rollback. The invalidated block-hash set is checked while holding the same ledger file lock, closing that race. Reapplying/restoring the same block hash clears its invalidation before scheduling a new canonical write.

## Exact verification commands and results

### Batch-8 targeted suite

Patched tree:

```text
PYTHONPATH=. pytest -q tests/test_bugfix_batch8_20261029.py
9 passed in 0.76s
```

Untouched Batch-7 baseline, same test file:

```text
PYTHONPATH=. pytest -q tests/test_bugfix_batch8_20261029.py
9 failed
```

The baseline failures correspond to BUG-39/40/41/42/43/44/46 plus two strengthened BUG-42 production-path checks.

### Cumulative previous-fix regression suite

```text
PYTHONPATH=. pytest -q tests/test_bugfix_batch{1,2,3,4,5,6,7,8}_20261029.py
67 passed in 11.77s
```

Earlier run before the final UDP O(1) refinement:

```text
67 passed in 9.18s
```

### UDP adjacent suites

```text
PYTHONPATH=. pytest -q \
  tests/test_udp_security_fixes_20261006.py \
  tests/test_udp_peer_recovery_regressions_20261007.py \
  tests/test_udp_receiver_self_heal_20261027.py \
  tests/test_udp_stale_reconnect_regression_20261027.py
18 passed in 0.15s
```

Earlier expanded UDP + RPC adjacent run:

```text
28 passed in 4.84s
```

### Mining / audit / consensus adjacent suites

```text
PYTHONPATH=. pytest -q \
  tests/test_liveness_mining_regression_fix_20261027.py \
  tests/test_vsa_mining_lifecycle_20261014.py \
  tests/test_audit_fixes.py \
  tests/test_confirmed_bug_fixes.py \
  tests/test_consensus_security_fixes.py
37 passed in 5.90s
```

### Compilation

```text
python -m compileall -q visold tests
PASS
```

## Timeouts / unresolved test-runner issues

No new timeout occurred in Batch-8 verification. Previously documented grouped/order-dependent VVM/reorg suite termination issues remain historical known test-runner concerns; they were not reclassified as passes here.

## Cumulative status after Batch 8

Verified fixed:

BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-19, BUG-20, BUG-21, BUG-22, BUG-23, BUG-25, BUG-26, BUG-27, BUG-28, BUG-29, BUG-30, BUG-31, BUG-32, BUG-33, BUG-34, BUG-35, BUG-36, BUG-37, BUG-38, BUG-39, BUG-40, BUG-41, BUG-42, BUG-43, BUG-44, BUG-45, BUG-46.

Total: **43 / 46**.

Remaining findings:

- **BUG-12 — emergency-disable quorum:** requires an authenticated cross-node governance vote design. Reducing quorum to one would be an unsafe fake fix.
- **BUG-18 — legacy state-root hash fallback:** requires deciding the exact legacy compatibility boundary. The network will restart from scratch, which may justify removing legacy behavior, but this must be verified against block format/version code and tests before changing consensus hashing.
- **BUG-24 — CALLCODE semantics:** requires an explicit VM specification decision. If Ethereum-compatible CALLCODE is intended, implement it independently; if Visold intentionally does not support it, reject the opcode rather than silently aliasing DELEGATECALL.

## Remaining risks / limitations

1. This work verifies the 46 audited findings, not the entire codebase. The supplied final audit itself states that other persistence/networking/ABI/resilience/governance areas were not comprehensively covered.
2. UDP now supports configured maximum messages, which necessarily permits larger per-message reassembly than the old 2,048-fragment cap. The bound remains tied to `Config.MAX_MESSAGE_SIZE` and the 16-bit wire format; broader per-peer aggregate-memory hardening is a separate DoS-hardening topic, not part of BUG-42.
3. `gossiped: true` means delivery was synchronously attempted (one peer) or scheduled (parallel fanout) to one or more eligible connected peers. It is not an end-to-end remote acknowledgement; the response now reports `gossip_targets` explicitly so this distinction is visible.
4. The personal ledger remains a local, non-consensus JSON history feature. Its I/O failures are intentionally non-fatal to chain operation.
