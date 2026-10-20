# Network & Ports (Menu 28)

Visold now has a **Network & Ports** screen in the interactive TUI. Open the main menu and enter `28` to inspect the live network endpoints or save a P2P port preference for the next start.

## Port modes

- **Auto** (default) starts from the configured P2P port and scans nearby ports if needed. A candidate is accepted only when its P2P TCP and UDP listeners can bind and the associated local JSON-RPC port is available.
- **Manual** tries exactly the selected P2P port. It does not silently move to a different port. If the TCP/UDP listener or required RPC port is unavailable at startup, Visold reports a startup error so the operator can choose another port.

Choose an integer from **1024–65533**. Visold uses the selected P2P port for both TCP and UDP. The JSON-RPC port is the P2P port **+1** and remains local-only on `127.0.0.1`. The optional ICE relay chooses a free TCP port near the P2P port and skips the local RPC port.

A P2P port can be free while the **complete port plan is not**. For example, P2P `8338` needs both TCP/UDP `8338` and local JSON-RPC TCP `127.0.0.1:8339`. If TCP `8339` is already occupied, Manual mode correctly refuses the plan; Auto mode skips it and selects another candidate whose TCP/UDP and paired RPC ports can bind. Checking only `8338` does not test the required `8339` RPC port. Startup logs now identify skipped candidate port plans and the actual selected P2P/RPC pair. Port availability checks are best-effort and can still race if another process starts between preflight and bind.

Port choices are written to the active data directory's `config.json`. They apply **after a clean node shutdown and restart**; the running node is not rebound live. After restarting, open menu `28` again to see the actual bound ports, because Auto mode may have selected a nearby port.

## IP and reachability information

The screen displays the local IP addresses detected by the node, the P2P TCP/UDP listeners, the local JSON-RPC endpoint, the ICE relay endpoint/state, connected-peer count, any STUN-observed UDP mapping, and UPnP mapping status when available.

A STUN result is only an observed UDP mapping; it is **not proof** that peers can connect inbound to that endpoint. UPnP, IPv6 reachability, and UDP hole punching can help, but all are network-dependent and best-effort. Software cannot guarantee traversal through every firewall or CGNAT/symmetric-NAT configuration. When direct connectivity is blocked, a relay endpoint that is publicly reachable by the relevant peers may be needed; a relay running behind the same restrictive NAT does not automatically become reachable.

JSON-RPC intentionally remains local-only. Do not expose it to the public internet merely to make P2P connectivity work.

## Running several nodes on one Android device

Changing ports alone does **not** create independent node instances. Each simultaneous local node must use its own `VISOLD_DATA_DIR` so that its database, wallet, peers, configuration, and node status files do not overlap. For example, in separate Termux sessions:

```bash
VISOLD_DATA_DIR="$HOME/.visold-node-a" python visold_vsd_.py
```

```bash
VISOLD_DATA_DIR="$HOME/.visold-node-b" python visold_vsd_.py
```

Configure and restart each instance separately. Choose different free Manual P2P ports on the same device, and avoid overlapping the related RPC/relay port ranges. Back up each wallet/keystore before experimenting. On separate physical devices, using the same default P2P port is normal; port numbers are local to each device.
