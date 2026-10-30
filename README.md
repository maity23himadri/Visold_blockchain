# Visold (VSD)

Visold is a proof-of-work blockchain node written in Python. It includes peer-to-peer networking, a wallet, a small smart-contract virtual machine, and a layer-2 rollup module.

Software version: 11.0.0.0 · Network: Testnet · Chain ID: `vsd-testnet-1`

> **Network status:** Visold is currently operating as a testnet; mainnet has not launched. This is development software, has not been independently audited, and should not be used to hold real value.

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

- [Whitepaper (DOCX)](docs/Visold_Technical_Whitepaper_v1.2.docx) (also available as [PDF](docs/Visold_Technical_Whitepaper_v1.2.pdf))
- [Architecture](docs/ARCHITECTURE.md)
- [Network ports](docs/NETWORK_PORTS.md)
- [Crypto acceleration](docs/CRYPTO_ACCELERATION.md)

## License

See [`docs/LICENSE.txt`](docs/LICENSE.txt).
