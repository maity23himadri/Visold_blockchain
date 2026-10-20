# Visold Network & Ports Feature Report — 2026-10-20

## Implemented

- Added interactive TUI menu option **28 — Network & Ports**.
- Added persistent `auto` and `manual` P2P-port modes in each node data directory's `config.json`.
- Added port validation and preflight checks for the P2P TCP listener, P2P UDP listener, and local JSON-RPC port (`P2P + 1`). Port range: 1024–65533.
- Manual mode binds only the requested P2P port and fails clearly if the required listener/RPC port plan is unavailable. Auto mode retains scan-to-bind behavior and checks the RPC offset before selecting a listener port.
- Fixed node orchestration so if Auto mode binds a different actual P2P port, the RPC server, node status, and node identity metadata follow the actual port rather than the originally requested base port.
- Protected the ICE relay's port scan from taking the local JSON-RPC port; the relay keeps its scan-to-bind behavior.
- Added status output for actual P2P TCP/UDP ports, local-only RPC endpoint, relay endpoint/state, local IP list, STUN-observed UDP mapping, UPnP status, connected-peer count, current port/mode, and saved next-start port/mode.
- Added multi-instance guidance and honest NAT caveats in the TUI and `docs/NETWORK_PORTS.md`.
- Refreshed `visold/_build_identity.json` to match the edited package source tree.

## Usage

1. Start Visold and choose **28 — Network & Ports**.
2. Choose `1` to change the next-start port/mode.
3. Enter a P2P port in `1024–65533` and select `auto` or `manual`.
4. Exit Visold cleanly and restart it. Reopen menu 28 to inspect the actual bound port and current IP/mapping information.
5. If multiple local instances run on the same device, use a unique `VISOLD_DATA_DIR` for every instance as well as a distinct free P2P port. Different ports alone do not separate databases or wallets.

## NAT / firewall limitation

The feature preserves the existing UPnP, STUN, UDP hole-punching, and ICE relay paths. These are best-effort connectivity mechanisms, **not a guarantee of bypassing every firewall or CGNAT**. A STUN-mapped address is not proof of inbound reachability. Restrictive/symmetric NAT may require a relay endpoint that is reachable from the peers; the code cannot create public reachability where the network does not provide it. JSON-RPC remains local-only.

## Validation

- Python syntax compilation passed for changed modules.
- **82 targeted tests passed**, covering port validation/persistence, manual exact-port binding, Auto RPC-port conflict handling, actual P2P/RPC port wiring, menu visibility and terminal rendering, peer/security regressions, UDP recovery, startup safety, and the existing source-identity manifest test.
- A full `pytest -q` run was attempted but did not complete within the 200-second execution limit. It was therefore not counted as passing; no specific failure was reported before the timeout. The targeted test group completed successfully.
