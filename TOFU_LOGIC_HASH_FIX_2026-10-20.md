# Visold: TOFU Endpoint Pinning + Logic Hash Fix (2026-10-20)

## What was wrong

### 1. TLS TOFU fingerprint cache was keyed by IP only

The outbound connection path stored a certificate fingerprint under `ip`. This is ambiguous when several Visold nodes share one IPv6/IPv4 address but listen on different ports. One node could overwrite another node's in-memory observation, creating the misleading `[TOFU] Cert fingerprint changed` warning.

The old code also changed the IP pin before the application-layer identity challenge completed.

### 2. Empty source tree was advertised as a valid logic hash

`package_source_blob()` can return `b""` in a bytecode-only/stripped package. Hashing this produces `e3b0c442...` (SHA-256 of empty bytes), which misleadingly looks like a real source identity. This explains the `ours=e3b0c442...` side of the supplied log; the peer's `31f...` hash was not proof of consensus corruption.

## What changed

- TLS endpoint cache keys now include both host and port (for IPv6: `[address]:port`). Two Visold instances on one address no longer collide in this cache.
- The candidate TLS certificate fingerprint is captured first, not pinned immediately. The remote's advertised fingerprint must match the actual TLS certificate when advertised, then the ECDSA challenge and durable peer-ID TLS pin checks run before the endpoint cache is updated.
- Operator-provided bootstrap certificate pins are strict: exact endpoint pins take precedence, legacy IP-only entries remain wildcard pins, and a mismatch is rejected rather than silently overwritten.
- The logic hash is computed from the ordered package source when source is present. A bundled `visold/_build_identity.json` supplies the same build fingerprint for bytecode-only deployments. An incomplete package returns `unknown`; it never advertises the SHA-256 empty-tree digest as a valid fingerprint.
- The manifest is a compatibility fingerprint, not a signed build-attestation or proof that a binary matches the source. Consensus/block validation remains the security boundary.

## Expected rollout behavior

All nodes that should have identical software logic must be updated from the same fixed release. This source change necessarily changes the logic fingerprint. An old node may therefore temporarily show a logic-hash mismatch and be classified as lower trust until it is updated or its old hash is deliberately listed in `KNOWN_GOOD_LOGIC_HASHES`. Do not add a hash to that list unless you intentionally trust that build.

TLS certificate/key files should remain persistent for each node's data directory. The durable peer-ID certificate pin still rejects an unexpected certificate change for the same peer identity. For operator-configured bootstrap pins with colocated nodes, prefer endpoint keys such as `[2001:db8::1]:8338`; IP-only pins intentionally apply to all ports on that IP.

## Verification

- 10 focused regression tests cover IPv4/IPv6 endpoint separation, endpoint vs IP bootstrap pin precedence, package hash consistency, bytecode-only manifest fallback, missing-manifest behavior, partial source trees, and sourceless `__pycache__` path resolution.
- 80 tests passed across targeted networking/security and pruning/reconnect regression groups.
- Python compilation and ZIP integrity checks passed.
- A full `pytest -q` run was attempted but exceeded the 120-second execution limit. Therefore the full repository suite is not claimed as passing.
- Tests run locally/in-process; a live multi-node TCP/UDP test on the user's Android/Termux network remains necessary.

## Interpretation of the supplied block-serving log

The `served 178` line for blocks `601-800` is consistent with a serving node at height 778 (`778 - 601 + 1 = 178`) if the returned blocks were contiguous. After the user's clarification, this is not treated as one of the two faults fixed here. The two fixes target the TOFU warning and the empty/mismatched logic hash.
