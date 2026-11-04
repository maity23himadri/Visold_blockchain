# Visold (VSD)

<p align="center"><img src="docs/visold-logo.png" alt="Visold logo" width="160"></p>

Visold is a proof-of-work blockchain node written in Python. It includes peer-to-peer networking, a wallet, a small smart-contract virtual machine, and a layer-2 rollup module.

Software version: 11.0.0.0 · Network: Testnet · Chain ID: `vsd-testnet-1`

> **Network status:** Visold is currently operating as a testnet; mainnet has not launched. Testnet software is expected to change, so treat it accordingly.

## Verification status

The codebase has been tested in several ways, and fixes found along the way were accompanied by regression tests in `tests/` (109 test modules):

- **Automated tests:** unit, integration and regression tests across consensus, networking, storage and pruning, the virtual machine, the rollup module, the RPC server and the terminal UI.
- **Real multi-node and multi-device testing:** the node has been run as real multi-node and multi-device setups, not only inside the test suite. Problems found this way were fixed and then covered by new regression tests.
- **Repeated audit-and-fix cycles:** the code has been reviewed continuously, including AI-assisted audits, with each confirmed finding fixed.
- **External audit:** a formal audit by an outside security firm has not been done yet.

Dated validation records from earlier development snapshots are cited in the whitepaper (section 18.5).

## Running

```sh
python visold_vsd_.py                 # interactive node (terminal UI)
python visold_vsd_.py --test          # embedded test suite
python visold_vsd_.py --cli --help    # command-line wallet and node tools
python visold_vsd_.py --version
```

Keep `visold_vsd_.py` and the `visold/` folder side by side.

Optional, faster signature checks (the built-in implementation is always the fallback):

```sh
pip install -r requirements-crypto-accelerated.txt
```

## Project layout

| Path | Contents |
|---|---|
| `visold_vsd_.py` | Entry point |
| `visold/` | Implementation, split into bounded contexts (kernel, crypto, ledger, chain, consensus, network, storage, mempool, vm, rollup, wallet, api, cli, and others) |
| `tests/` | Test suite (run with `pytest tests/`) |
| `scripts/visold-termux.sh` | Optional `tmux` session helper for Android/Termux |
| `docs/` | Whitepaper, architecture map, network ports, crypto notes, Android guide, license |

## Android / Termux

The terminal UI works in Termux and adapts to narrow screens. For setup, background use, and the `tmux` helper, see [`docs/ANDROID_TERMUX_GUIDE.md`](docs/ANDROID_TERMUX_GUIDE.md):

```sh
bash scripts/visold-termux.sh start
bash scripts/visold-termux.sh attach
bash scripts/visold-termux.sh status
bash scripts/visold-termux.sh stop
```

Android power management can stop background processes, so measure reliability on your own device.

## Documentation

- [Technical whitepaper v1.3](docs/Visold_Technical_Whitepaper_v1.3.pdf) (also available as [Word document](docs/Visold_Technical_Whitepaper_v1.3.docx)). It describes an earlier snapshot of the code; see the note inside it.
- [Architecture](docs/ARCHITECTURE.md)
- [Network ports](docs/NETWORK_PORTS.md)
- [Crypto acceleration](docs/CRYPTO_ACCELERATION.md)

## License

See [`docs/LICENSE.txt`](docs/LICENSE.txt).
