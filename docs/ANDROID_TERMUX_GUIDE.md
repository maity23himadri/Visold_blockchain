# Visold on Android / Termux

This guide keeps Visold's existing Python node and terminal UI. It does not replace
or alter consensus, wallet, networking, or database behavior.

## First launch

1. Install Termux from a trusted distribution source.
2. Install Python and tmux:

   ```sh
   pkg update
   pkg install python tmux
   ```

3. Copy/extract the complete Visold folder to a directory you can write to. Keep
   `visold_vsd_.py` beside the `visold/` package.
4. Install the Python dependencies documented for this Visold build.
5. From the Visold directory, check the entry point and start the UI:

   ```sh
   python visold_vsd_.py --help
   python visold_vsd_.py --version
   python visold_vsd_.py
   ```

   The first run may ask you to create or import a local account. Protect the
   wallet/keystore and recovery material; never upload these files to support chats.

## Android-friendly background sessions

A terminal app's process and Android's power management still control whether a
node remains alive. The included `scripts/visold-termux.sh` keeps the interactive
TUI attached to a named `tmux` pseudo-terminal, so you can detach and return to it.
It is **not** a headless daemon and does not guarantee persistence if Android or
an OEM kills Termux.

```sh
bash scripts/visold-termux.sh start
bash scripts/visold-termux.sh attach
# Detach without stopping Visold: press Ctrl+B, then D
bash scripts/visold-termux.sh status
bash scripts/visold-termux.sh stop
```

The helper tries `termux-wake-lock` when that command exists. For full Termux API
support, install the matching Termux:API application/package from the same trusted
source as Termux. A wake lock can increase battery use; release it when Visold is
not needed in the background. Do not assume `tmux` prevents Android from killing
an application process.

## TUI usage and clipboard

- Enter a menu number or letter, then press Enter. `H` shows keyboard/clipboard tips.
- `B` detaches the interface only when running inside `tmux`; the node session stays
  alive. Outside `tmux`, use the helper's `start` command first.
- Switch tabs with F1–F5 or type `t1`–`t5`; aliases include `:dash`, `:wallet`,
  `:mining`, `:nodes`, and `:activity`.
- The terminal emulator owns text selection and clipboard behavior. Long-press
  gestures, Ctrl+Shift+C/V, and paste handling vary by emulator and keyboard.
  Visold uses normal line input (`input()`), so pasted text is accepted as input;
  never paste recovery secrets into a command prompt you do not trust.
- `python visold_vsd_.py --help` lists the supported launch modes.

## Current limitations

- This is a Termux-based distribution guide, not an APK installer.
- Background operation is best-effort and subject to Android/OEM lifecycle rules.
- Termux keyboard shortcuts and copy/paste must be verified on each supported
  terminal emulator/device combination.
- Benchmark the actual phone before advertising Termux-equivalent rendering speed.
